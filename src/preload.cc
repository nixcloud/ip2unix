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

extern "C" int WRAP_SYM(socket)(int domain, int type, int protocol)
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
extern "C" int WRAP_SYM(setsockopt)(int sockfd, int level, int optname,
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

extern "C" int WRAP_SYM(ioctl)(int fd, unsigned long request, void *arg)
{
    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        return sock->ioctl(request, arg);
    }, [&]() {
        return real::ioctl(fd, request, arg);
    });
}

#ifdef SOCKET_ACTIVATION
/*
 * For systemd socket activation, we need to make sure the program doesn't run
 * listen on the socket, as this is already done by systemd.
 */
extern "C" int WRAP_SYM(listen)(int sockfd, int backlog)
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
template <typename SockFun, typename RealFun>
static inline int bind_connect(SockFun &&sockfun, RealFun &&realfun,
                               RuleDir dir, int fd,
                               const struct sockaddr *addr, socklen_t addrlen)
{
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
        return std::invoke(realfun, fd, addr, addrlen);

    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        SockAddr inaddr(addr);

        std::scoped_lock<std::mutex> lock(g_rules_mutex);

        init_rules();

        for (auto &rule : *g_rules) {
            if (rule.direction != dir)
                continue;

            if (rule.type && sock->type != rule.type)
                continue;

            if (rule.address && inaddr.get_host() != rule.address)
                continue;

            if (rule.port && inaddr.get_port() != rule.port)
                continue;

#ifdef SOCKET_ACTIVATION
            if (rule.socket_activation) {
                int newfd = get_systemd_fd_for_rule(rule);
                return sock->activate(inaddr, newfd);
            }
#endif
            if (!rule.socket_path)
                continue;

            return std::invoke(sockfun, sock, inaddr,
                               rule.socket_path.value());
        }

        return std::invoke(realfun, fd, addr, addrlen);
    }, [&]() {
        return std::invoke(realfun, fd, addr, addrlen);
    });
}

extern "C" int WRAP_SYM(bind)(int fd, const struct sockaddr *addr,
                              socklen_t addrlen)
{
    return bind_connect(&Socket::bind, real::bind, RuleDir::INCOMING,
                        fd, addr, addrlen);
}

extern "C" int WRAP_SYM(connect)(int fd, const struct sockaddr *addr,
                                 socklen_t addrlen)
{
    return bind_connect(&Socket::connect, real::connect, RuleDir::OUTGOING,
                        fd, addr, addrlen);
}

static int handle_accept(int fd, struct sockaddr *addr, socklen_t *addrlen,
                         int flags)
{
    int accfd = real::accept4(fd, addr, addrlen, flags);
    if (accfd > 0) {
        return Socket::when<int>(fd, [&](Socket::Ptr sock) {
            int ret = sock->accept(fd, addr, addrlen);
            return ret == 0 ? accfd : ret;
        }, [&]() { return accfd; });
    }
    return accfd;
}

extern "C" int WRAP_SYM(accept)(int fd, struct sockaddr *addr,
                                socklen_t *addrlen)
{
    return handle_accept(fd, addr, addrlen, 0);
}

extern "C" int WRAP_SYM(accept4)(int fd, struct sockaddr *addr,
                                 socklen_t *addrlen, int flags)
{
    return handle_accept(fd, addr, addrlen, flags);
}

extern "C" int WRAP_SYM(getpeername)(int fd, struct sockaddr *addr,
                                     socklen_t *addrlen)
{
    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        return sock->getpeername(addr, addrlen);
    }, [&]() {
        return real::getpeername(fd, addr, addrlen);
    });
}

extern "C" int WRAP_SYM(getsockname)(int fd, struct sockaddr *addr,
                                     socklen_t *addrlen)
{
    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        return sock->getsockname(addr, addrlen);
    }, [&]() {
        return real::getsockname(fd, addr, addrlen);
    });
}

extern "C" int WRAP_SYM(close)(int fd)
{
    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        return sock->close();
    }, [&]() {
        return real::close(fd);
    });
}
