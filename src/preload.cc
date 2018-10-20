// SPDX-License-Identifier: LGPL-3.0-only
#include <queue>
#include <unordered_map>
#include <variant>
#include <memory>
#include <mutex>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/un.h>

#ifndef WRAP_SYM
#define WRAP_SYM(x) x
#endif

#include "rules.hh"
#include "realcalls.hh"
#include "socket.hh"

typedef std::shared_ptr<Socket> SocketInfoPtr;

struct SocketChildren {
    SocketInfoPtr parent;
};

static std::mutex g_sockinfo_mutex;
static std::mutex g_rules_mutex;

static std::shared_ptr<const std::vector<Rule>> g_rules = nullptr;

typedef std::variant<SocketInfoPtr, SocketChildren> SocketEntry;
static std::unordered_map<int, SocketEntry> g_active_sockets;

static void init_rules(void)
{
    if (g_rules != nullptr)
        return;

    std::optional<std::vector<Rule>> rules;
    const char *rule_source;

    if ((rule_source = getenv("__IP2UNIX_RULES")) != nullptr) {
        rules = parse_rules(std::string(rule_source), false);
    } else if ((rule_source = getenv("IP2UNIX_RULE_FILE")) != nullptr) {
        rules = parse_rules(std::string(rule_source), true);
    } else {
        fputs("FATAL: Unable to find __IP2UNIX_RULES or IP2UNIX_RULE_FILE!\n",
              stderr);
        _exit(EXIT_FAILURE);
    }

    if (!rules)
        _exit(EXIT_FAILURE);

    g_rules = std::make_shared<std::vector<Rule>>(rules.value());
}

static inline std::optional<SocketEntry> get_active_socket(int fd)
{
    auto found = g_active_sockets.find(fd);
    if (found == g_active_sockets.end())
        return std::nullopt;
    return found->second;
}

static inline SocketInfoPtr get_parent(SocketEntry &se)
{
    if (std::holds_alternative<SocketInfoPtr>(se))
        return std::get<SocketInfoPtr>(se);
    else
        return std::get<SocketChildren>(se).parent;
}

static inline bool is_children(SocketEntry &se)
{
    return std::holds_alternative<SocketChildren>(se);
}

static inline int real_bind_connect(RuleDir dir, int fd,
                                    const struct sockaddr *addr,
                                    socklen_t addrlen)
{
    switch (dir) {
        case RuleDir::INCOMING:
            return real::bind(fd, addr, addrlen);
        case RuleDir::OUTGOING:
            return real::connect(fd, addr, addrlen);
    }
    return -1;
}

int WRAP_SYM(socket)(int domain, int type, int protocol)
{
    int fd = real::socket(domain, type, protocol);
    if (fd != -1 && (domain == AF_INET || domain == AF_INET6)) {
        g_sockinfo_mutex.lock();
        g_active_sockets[fd] =
            std::make_shared<Socket>(Socket(fd, domain, type, protocol));
        g_sockinfo_mutex.unlock();
    }
    return fd;
}

/*
 * We override setsockopt() so that we can gather all the socket options that
 * are set for the socket file descriptor in question.
 */
int WRAP_SYM(setsockopt)(int sockfd, int level, int optname,
                         const void *optval, socklen_t optlen)
{
    g_sockinfo_mutex.lock();
    auto si = get_active_socket(sockfd);
    /* Only cache socket options for SOL_SOCKET, no IPPROTO_TCP etc... */
    if (si && level == SOL_SOCKET) {
        auto parent = get_parent(si.value());
        int ret = parent->setsockopt(level, optname, optval, optlen);
        g_sockinfo_mutex.unlock();
        return ret;
    }

    g_sockinfo_mutex.unlock();
    return real::setsockopt(sockfd, level, optname, optval, optlen);
}

#ifdef SOCKET_ACTIVATION
/*
 * For systemd socket activation, we need to make sure the program doesn't run
 * listen on the socket, as this is already done by systemd.
 */
int WRAP_SYM(listen)(int sockfd, int backlog)
{
    g_sockinfo_mutex.lock();

    int ret;

    auto found = g_active_sockets.find(sockfd);
    if (found == g_active_sockets.end()) {
        ret = real::listen(sockfd, backlog);
    } else {
        auto parent = get_parent(found->second);
        ret = parent->listen(backlog);
    }
    g_sockinfo_mutex.unlock();
    return ret;
}
#endif

/*
 * Handle both bind() and connect() depending on the value of "dir".
 */
static inline int handle_bind_connect(RuleDir dir, int fd,
                                      const struct sockaddr *addr,
                                      socklen_t addrlen)
{
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
        return real_bind_connect(dir, fd, addr, addrlen);

    g_sockinfo_mutex.lock();

    /* No socket() call was made prior to this, so simply execute the original
     * syscall, which will probably fail anyway  - in this case it's not our
     * fault.
     */
    auto found = g_active_sockets.find(fd);
    if (found == g_active_sockets.end()) {
        g_sockinfo_mutex.unlock();
        return real_bind_connect(dir, fd, addr, addrlen);
    }

    SocketInfoPtr si = get_parent(found->second);
    SockAddr inaddr(addr);

    g_rules_mutex.lock();

    init_rules();

    for (auto &rule : *g_rules) {
        if (rule.direction != dir)
            continue;

        if (!si->match_rule(inaddr, rule))
            continue;

#ifdef SOCKET_ACTIVATION
        // TODO: refactor!
        if (rule.socket_activation) {
            int ret = si->bind_connect(inaddr, rule);
            g_rules_mutex.unlock();
            g_sockinfo_mutex.unlock();
            return ret;
        }
#endif
        if (!rule.socket_path)
            continue;

        int ret = si->bind_connect(inaddr, rule);
        g_rules_mutex.unlock();
        g_sockinfo_mutex.unlock();
        return ret;
    }

    g_rules_mutex.unlock();
    g_sockinfo_mutex.unlock();
    return real_bind_connect(dir, fd, addr, addrlen);
}

int WRAP_SYM(bind)(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    return handle_bind_connect(RuleDir::INCOMING, fd, addr, addrlen);
}

int WRAP_SYM(connect)(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    return handle_bind_connect(RuleDir::OUTGOING, fd, addr, addrlen);
}

static void set_peername(struct sockaddr *addr, socklen_t *addrlen)
{
    struct sockaddr_in dummy;
    dummy.sin_family = AF_INET;
    // FIXME: Fake this with a cached value!
    dummy.sin_addr.s_addr = inet_addr("127.0.0.1");
    // TODO: Rotate this!
    dummy.sin_port = htons(65530);
    memcpy(addr, &dummy, sizeof dummy);
    *addrlen = sizeof dummy;
}

static int handle_accept(int fd, struct sockaddr *addr, socklen_t *addrlen,
                         int flags)
{
    int accfd = real::accept4(fd, addr, addrlen, flags);
    if (accfd > 0) {
        g_sockinfo_mutex.lock();
        auto si = get_active_socket(fd);
        if (si) {
            SocketChildren newchild;
            newchild.parent = get_parent(si.value());
            g_active_sockets[accfd] = newchild;
            set_peername(addr, addrlen);
        }
        g_sockinfo_mutex.unlock();
    }
    return accfd;
}

int WRAP_SYM(accept)(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return handle_accept(fd, addr, addrlen, 0);
}

int WRAP_SYM(accept4)(int fd, struct sockaddr *addr, socklen_t *addrlen,
                      int flags)
{
    return handle_accept(fd, addr, addrlen, flags);
}

int WRAP_SYM(getpeername)(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    g_sockinfo_mutex.lock();
    auto found = get_active_socket(fd);
    if (found) {
        auto si = get_parent(found.value());
        int ret = si->getpeername(addr, addrlen);
        g_sockinfo_mutex.unlock();
        return ret;
    }
    g_sockinfo_mutex.unlock();
    return real::getpeername(fd, addr, addrlen);
}

int WRAP_SYM(getsockname)(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    g_sockinfo_mutex.lock();
    auto found = get_active_socket(fd);
    if (found) {
        auto si = get_parent(found.value());
        int ret = si->getsockname(addr, addrlen);
        g_sockinfo_mutex.unlock();
        return ret;
    }
    g_sockinfo_mutex.unlock();
    return real::getsockname(fd, addr, addrlen);
}

int WRAP_SYM(close)(int fd)
{
    g_sockinfo_mutex.lock();
    auto found = get_active_socket(fd);
    if (!found || is_children(found.value())) {
        g_sockinfo_mutex.unlock();
        return real::close(fd);
    } else {
        auto si = get_parent(found.value());
#ifdef SOCKET_ACTIVATION
        if (si->rule && si->rule.value()->socket_activation) {
            g_active_sockets.erase(fd);
            g_sockinfo_mutex.unlock();
            return 0;
        }
#endif
        int ret = real::close(fd);

        if (si->rule) {
            auto rule = si->rule.value();
            if (si->sockpath && rule->direction == RuleDir::INCOMING)
                unlink(si->sockpath.value().c_str());
        }
        g_active_sockets.erase(fd);
        g_sockinfo_mutex.unlock();
        return ret;
    }
}
