// SPDX-License-Identifier: LGPL-3.0-only
#include <climits>
#include <csignal>
#include <cstring>
#include <forward_list>
#include <queue>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <memory>
#include <mutex>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef SOCKET_ACTIVATION
#include <systemd/sd-daemon.h>
#endif

#ifndef WRAP_SYM
#define WRAP_SYM(x) x
#endif

#include "rules.hh"

struct SockoptEntry {
    int level;
    int optname;
    std::vector<uint8_t> optval;
};

struct SocketInfo {
    int socktype;
    int protocol;
    std::string sockpath;
    struct in_addr addr;
    in_port_t port;
    std::optional<const UdsmapRule*> rule;
    std::queue<SockoptEntry> sockopts;
};

typedef std::shared_ptr<SocketInfo> SocketInfoPtr;

struct SocketChildren {
    SocketInfoPtr parent;
};

/* FIXME: This only covers critical sections involved with writes! */
static std::mutex g_mutex;

static std::shared_ptr<const std::vector<UdsmapRule>> g_rules = nullptr;

typedef std::variant<SocketInfoPtr, SocketChildren> SocketEntry;
static std::unordered_map<int, SocketEntry> g_active_sockets;

static void init_rules(void)
{
    if (g_rules != nullptr)
        return;

    char *rule_file = getenv("IP2UNIX_RULE_FILE");

    if (rule_file == nullptr) {
        fputs("FATAL: Unable to find IP2UNIX_RULE_FILE!\n", stderr);
        _exit(EXIT_FAILURE);
    }

    std::optional<std::vector<UdsmapRule>> rules = parse_rules(rule_file);
    if (!rules) _exit(EXIT_FAILURE);

    g_mutex.lock();
    g_rules = std::make_shared<std::vector<UdsmapRule>>(rules.value());
    g_mutex.unlock();
}

/* This namespace is here so that we can autogenerate and call wrappers for C
 * library functions in a convenient way. For example to call the wrapper for
 * close we can just use real::close(fd).
 */
namespace real {
    template <typename Sig, typename Sym>
    struct DlsymFun
    {
        Sig fptr = nullptr;

        template <typename ... Args>
        auto operator()(Args ... args) -> decltype(fptr(args ...))
        {
            if (fptr == nullptr)
                fptr = reinterpret_cast<Sig>(dlsym(RTLD_NEXT, Sym::fname));
            return fptr(args ...);
        }
    };

#define DLSYM_FUN(name) \
    struct name##_fun_t : public DlsymFun<decltype(&::name), name##_fun_t> { \
        static constexpr const char *fname = #name; \
    } name

    DLSYM_FUN(socket);
    DLSYM_FUN(setsockopt);
    DLSYM_FUN(bind);
    DLSYM_FUN(connect);
#ifdef SOCKET_ACTIVATION
    DLSYM_FUN(listen);
#endif
    DLSYM_FUN(accept);
    DLSYM_FUN(accept4);
    DLSYM_FUN(getpeername);
    DLSYM_FUN(getsockname);
    DLSYM_FUN(close);
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

#ifdef SOCKET_ACTIVATION
static inline bool is_socket_activated(int fd)
{
    auto found = g_active_sockets.find(fd);
    if (found == g_active_sockets.end())
        return false;
    std::optional<const UdsmapRule*> rule = get_parent(found->second)->rule;
    return rule && rule.value()->socket_activation;
}
#endif

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

static bool match_sockaddr_in(const struct sockaddr_in *addr,
                              UdsmapRule rule)
{
    /* Use max size of INET6 address, because INET is shorter anyway. */
    char buf[INET6_ADDRSTRLEN];
    bool match = true;

    if (rule.address &&
        inet_ntop(addr->sin_family, &addr->sin_addr, buf,
                  sizeof(buf)) != nullptr) {
        if (std::string(buf) != rule.address.value())
            match = false;
    }

    if (rule.port && ntohs(addr->sin_port) != rule.port.value())
        match = false;

    return match;
}

static bool match_sotype(int type, UdsmapRule rule)
{
    if (!rule.type)
        return true;

    switch (type) {
        case SOCK_STREAM:
            return rule.type.value() == RuleIpType::TCP;
        case SOCK_DGRAM:
            return rule.type.value() == RuleIpType::UDP;
    }

    return false;
}

int WRAP_SYM(socket)(int domain, int type, int protocol)
{
    int fd = real::socket(domain, type, protocol);
    if (domain == AF_INET || domain == AF_INET6) {
        SocketInfo si;
        si.socktype = type;
        si.protocol = protocol;
        memset(&si.addr, 0, sizeof(struct in_addr));
        memset(&si.port, 0, sizeof(in_port_t));
        g_mutex.lock();
        g_active_sockets[fd] = std::make_shared<SocketInfo>(si);
        g_mutex.unlock();
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
    auto si = get_active_socket(sockfd);
    /* Only cache socket options for SOL_SOCKET, no IPPROTO_TCP etc... */
    if (si && level == SOL_SOCKET) {
        std::vector<uint8_t> valcopy((uint8_t*)optval,
                                     (uint8_t*)optval + optlen);
        SockoptEntry entry{level, optname, valcopy};
        auto parent = get_parent(si.value());
        g_mutex.lock();
        parent->sockopts.push(entry);
        g_mutex.unlock();
    }

    return real::setsockopt(sockfd, level, optname, optval, optlen);
}

/*
 * Set all the socket options and file descriptor flags from old_sockfd to
 * new_sockfd.
 */
static bool set_cached_sockopts(int old_sockfd, int new_sockfd)
{
    int fdflags, fdstatus;

    if ((fdflags = fcntl(old_sockfd, F_GETFD)) == -1) {
        perror("fcntl(F_GETFD)");
        return false;
    }

    if ((fdstatus = fcntl(old_sockfd, F_GETFL)) == -1) {
        perror("fcntl(F_GETFL)");
        return false;
    }

    if (fcntl(new_sockfd, F_SETFD, fdflags) == -1) {
        perror("fcntl(F_SETFD)");
        return false;
    }

    if (fcntl(new_sockfd, F_SETFL, fdstatus) == -1) {
        perror("fcntl(F_SETFL)");
        return false;
    }

    auto si = get_active_socket(old_sockfd);
    if (si) {
        auto sockinfo = get_parent(si.value());
        while (!sockinfo->sockopts.empty()) {
            auto entry = sockinfo->sockopts.front();
            if (real::setsockopt(new_sockfd, entry.level, entry.optname,
                                 entry.optval.data(),
                                 entry.optval.size()) == -1) {
                perror("setsockopt");
                return false;
            }
            g_mutex.lock();
            sockinfo->sockopts.pop();
            g_mutex.unlock();
        }
    }

    return true;
}

/*
 * Turn the given socket file descriptor into a UNIX Domain socket by creating
 * a new socket and setting all the socket options and file descriptor flags
 * from the old socket.
 *
 * The socket options are read from sockopt_cache, which is gathered from the
 * override of the setsockopt() function above.
 */
static bool sock_make_unix(int old_sockfd)
{
    int sockfd;

    g_mutex.lock();
    int socktype = get_parent(g_active_sockets[old_sockfd])->socktype;
    g_mutex.unlock();

    if ((sockfd = real::socket(AF_UNIX, socktype, 0)) == -1) {
        perror("socket(AF_UNIX)");
        return false;
    }

    if (!set_cached_sockopts(old_sockfd, sockfd)) {
        real::close(sockfd);
        return false;
    }

    if (dup2(sockfd, old_sockfd) == -1) {
        perror("dup2");
        real::close(sockfd);
        return false;
    }

    return true;
}

#ifdef SOCKET_ACTIVATION
/*
 * Get a systemd socket file descriptor for the given rule either via name if
 * fd_name is set or just the next file descriptor available.
 */
static int get_systemd_fd_for_rule(UdsmapRule rule)
{
    static std::unordered_map<std::string, int> names;
    static std::queue<int> fds;
    static bool fetch_done = false;

    if (!fetch_done) {
        char **raw_names = nullptr;
        int count = sd_listen_fds_with_names(1, &raw_names);
        if (count < 0) {
            fprintf(stderr, "FATAL: Unable to get systemd sockets: %s\n",
                    strerror(errno));
            std::abort();
        } else if (count == 0) {
            fputs("FATAL: Needed at least one systemd socket file descriptor,"
                  " but found zero.\n", stderr);
            std::abort();
        }
        for (int i = 0; i < count; ++i) {
            std::string name = raw_names[i];
            if (name.empty() || name == "unknown" || name == "stored")
                fds.push(SD_LISTEN_FDS_START + i);
            else
                names[name] = SD_LISTEN_FDS_START + i;
        }
        if (raw_names != nullptr)
            free(raw_names);
        fetch_done = true;
    }

    if (rule.fd_name) {
        auto found = names.find(rule.fd_name.value());
        if (found == names.end()) {
            fprintf(stderr, "FATAL: Can't get systemd socket for '%s'.\n",
                    rule.fd_name.value().c_str());
            std::abort();
        }
        return found->second;
    } else if (fds.empty()) {
        fputs("FATAL: Ran out of systemd sockets to assign\n", stderr);
        std::abort();
    }

    int fd = fds.front();
    fds.pop();
    return fd;
}

/*
 * For systemd socket activation, we need to make sure the program doesn't run
 * listen on the socket, as this is already done by systemd.
 */
int WRAP_SYM(listen)(int sockfd, int backlog)
{
    if (is_socket_activated(sockfd))
        return 0;
    else
        return real::listen(sockfd, backlog);
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

    init_rules();

    for (auto &rule : *g_rules) {
        if (rule.direction != dir)
            continue;

        if (!match_sockaddr_in((struct sockaddr_in*)addr, rule))
            continue;

        auto found = g_active_sockets.find(fd);
        if (found == g_active_sockets.end())
            continue;

        SocketInfoPtr si = get_parent(found->second);

        if (!match_sotype(si->socktype, rule))
            continue;

#ifdef SOCKET_ACTIVATION
        if (rule.socket_activation) {
            int newfd = get_systemd_fd_for_rule(rule);

            if (!set_cached_sockopts(fd, newfd))
                return -1;

            if (dup2(newfd, fd) == -1) {
                perror("dup2");
                return -1;
            }

            struct sockaddr_in *inaddr = (struct sockaddr_in *)addr;
            memcpy(&si->addr, &inaddr->sin_addr, sizeof(struct in_addr));
            memcpy(&si->port, &inaddr->sin_port, sizeof(in_port_t));

            g_mutex.lock();
            si->rule = &rule;
            g_mutex.unlock();
            return 0;
        }
#endif
        if (!rule.socket_path)
            continue;

        if (!sock_make_unix(fd))
            continue;

        struct sockaddr_un ua;
        memset(&ua, 0, sizeof ua);
        ua.sun_family = AF_UNIX;
        strcpy(ua.sun_path, rule.socket_path.value().c_str());

        int ret = real_bind_connect(dir, fd, (struct sockaddr*)&ua, sizeof ua);
        if (ret == 0) {
            struct sockaddr_in *inaddr = (struct sockaddr_in *)addr;
            memcpy(&si->addr, &inaddr->sin_addr, sizeof(struct in_addr));
            memcpy(&si->port, &inaddr->sin_port, sizeof(in_port_t));
            g_mutex.lock();
            si->rule = &rule;
            g_mutex.unlock();
        }
        return ret;
    }

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
        auto si = get_active_socket(fd);
        if (si) {
            SocketChildren newchild;
            newchild.parent = get_parent(si.value());
            g_mutex.lock();
            g_active_sockets[accfd] = newchild;
            g_mutex.unlock();
            set_peername(addr, addrlen);
        }
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
    auto found = get_active_socket(fd);
    if (found) {
        set_peername(addr, addrlen);
        return 0;
    }
    return real::getpeername(fd, addr, addrlen);
}

int WRAP_SYM(getsockname)(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    auto found = get_active_socket(fd);
    if (found) {
        auto si = get_parent(found.value());

        struct sockaddr_in inaddr;
        inaddr.sin_family = AF_INET;
        memcpy(&inaddr.sin_addr, &si->addr, sizeof(struct in_addr));
        memcpy(&inaddr.sin_port, &si->port, sizeof(in_port_t));
        memcpy(addr, &inaddr, sizeof inaddr);
        *addrlen = sizeof inaddr;
        return 0;
    }
    return real::getsockname(fd, addr, addrlen);
}

int WRAP_SYM(close)(int fd)
{
    auto found = get_active_socket(fd);
    if (!found || is_children(found.value())) {
        return real::close(fd);
    } else {
        auto si = get_parent(found.value());
#ifdef SOCKET_ACTIVATION
        if (si->rule && si->rule.value()->socket_activation) {
            g_mutex.lock();
            g_active_sockets.erase(fd);
            g_mutex.unlock();
            return 0;
        }
#endif
        int ret = real::close(fd);

        if (si->rule) {
            auto rule = si->rule.value();
            std::optional<std::string> sockpath = rule->socket_path;
            if (sockpath && rule->direction == RuleDir::INCOMING)
                unlink(sockpath.value().c_str());
        }
        g_mutex.lock();
        g_active_sockets.erase(fd);
        g_mutex.unlock();
        return ret;
    }
}
