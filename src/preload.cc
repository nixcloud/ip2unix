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

static std::mutex g_rules_mutex;

static std::shared_ptr<const std::vector<Rule>> g_rules = nullptr;

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
    if (fd != -1 && (domain == AF_INET || domain == AF_INET6))
        Socket::create(fd, domain, type, protocol);
    return fd;
}

/*
 * We override setsockopt() so that we can gather all the socket options that
 * are set for the socket file descriptor in question.
 */
int WRAP_SYM(setsockopt)(int sockfd, int level, int optname,
                         const void *optval, socklen_t optlen)
{
    /* Only cache socket options for SOL_SOCKET, no IPPROTO_TCP etc... */
    if (level != SOL_SOCKET)
        return real::setsockopt(sockfd, level, optname, optval, optlen);

    return Socket::when<int>(sockfd, [&](Socket::Ptr sock) {
        return sock->setsockopt(level, optname, optval, optlen);
    }, [&]() {
        return real::setsockopt(sockfd, level, optname, optval, optlen);
    });
}

#ifdef SOCKET_ACTIVATION
/*
 * For systemd socket activation, we need to make sure the program doesn't run
 * listen on the socket, as this is already done by systemd.
 */
int WRAP_SYM(listen)(int sockfd, int backlog)
{
    return Socket::when<int>(sockfd, [&](Socket::Ptr sock) {
        return sock->listen(backlog);
    }, [&]() {
        return real::listen(sockfd, backlog);
    });
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

    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        SockAddr inaddr(addr);

        std::scoped_lock<std::mutex> lock(g_rules_mutex);

        init_rules();

        for (auto &rule : *g_rules) {
            if (rule.direction != dir)
                continue;

            if (!sock->match_rule(inaddr, rule))
                continue;

#ifdef SOCKET_ACTIVATION
            if (rule.socket_activation)
                return sock->bind_connect(inaddr, rule);
#endif
            if (!rule.socket_path)
                continue;

            return sock->bind_connect(inaddr, rule);
        }

        return real_bind_connect(dir, fd, addr, addrlen);
    }, [&]() {
        return real_bind_connect(dir, fd, addr, addrlen);
    });
}

int WRAP_SYM(bind)(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    return handle_bind_connect(RuleDir::INCOMING, fd, addr, addrlen);
}

int WRAP_SYM(connect)(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    return handle_bind_connect(RuleDir::OUTGOING, fd, addr, addrlen);
}

static int handle_accept(int fd, struct sockaddr *addr, socklen_t *addrlen,
                         int flags)
{
    int accfd = real::accept4(fd, addr, addrlen, flags);
    if (accfd > 0) {
        Socket::when(fd, [&](Socket::Ptr sock) {
            sock->accept(fd, addr, addrlen);
        });
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
    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        return sock->getpeername(addr, addrlen);
    }, [&]() {
        return real::getpeername(fd, addr, addrlen);
    });
}

int WRAP_SYM(getsockname)(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        return sock->getsockname(addr, addrlen);
    }, [&]() {
        return real::getsockname(fd, addr, addrlen);
    });
}

int WRAP_SYM(close)(int fd)
{
    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        return sock->close();
    }, [&]() {
        return real::close(fd);
    });
}
