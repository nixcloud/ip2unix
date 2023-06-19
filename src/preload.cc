// SPDX-License-Identifier: LGPL-3.0-only
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <memory>
#include <mutex>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#ifndef WRAP_SYM
#define WRAP_SYM(x) ip2unix_wrap_##x
#endif
#ifndef EXPORT_SYM
#define EXPORT_SYM(x) x
#endif

#include "rules.hh"
#include "realcalls.hh"
#include "socket.hh"
#include "logging.hh"
#include "serial.hh"
#include "sockaddr.hh"

#ifdef SYSTEMD_SUPPORT
#include "systemd.hh"
#endif

static std::mutex g_rules_mutex;

static std::shared_ptr<const std::vector<Rule>> g_rules = nullptr;

using RuleMatch = std::optional<std::pair<size_t, const Rule>>;

static void init_rules(void)
{
    if (g_rules != nullptr)
        return;

    std::optional<std::vector<Rule>> rules;
    const char *rule_source;

    if ((rule_source = getenv("__IP2UNIX_RULES")) != nullptr) {
        rules.emplace();
        MaybeError err = deserialise(std::string(rule_source), &*rules);
        if (err) {
            LOG(FATAL) << "Unable to decode __IP2UNIX_RULES: " << *err;
            _exit(EXIT_FAILURE);
        }
    } else if ((rule_source = getenv("IP2UNIX_RULE_FILE")) != nullptr) {
        std::cerr << "The use of the IP2UNIX_RULE_FILE environment"
                     " variable is deprecated and will be removed in"
                     " ip2unix version 3.0." << std::endl;
        rules = parse_rules(std::string(rule_source), true);
    } else {
        LOG(FATAL) << "Unable to find __IP2UNIX_RULES!";
        _exit(EXIT_FAILURE);
    }

    if (!rules)
        _exit(EXIT_FAILURE);

#ifdef SYSTEMD_SUPPORT
    for (const Rule &rule : *rules) {
        if (!rule.socket_activation)
            continue;

        Systemd::init(*rules);
        break;
    }
#endif

    g_rules = std::make_shared<std::vector<Rule>>(rules.value());
}

extern "C" const char *EXPORT_SYM(__ip2unix__)(void)
{
    return VERSION;
}

extern "C" int WRAP_SYM(socket)(int domain, int type, int protocol)
{
    TRACE_CALL("socket", domain, type, protocol);

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
    TRACE_CALL("setsockopt", sockfd, level, optname, optval, optlen);

    return Socket::when<int>(sockfd, [&](Socket::Ptr sock) {
        if (sock->rewrite_peer_address)
            return sock->setsockopt(level, optname, optval, optlen);
        else
            return real::setsockopt(sockfd, level, optname, optval, optlen);
    }, [&]() {
        return real::setsockopt(sockfd, level, optname, optval, optlen);
    });
}

extern "C" int WRAP_SYM(ioctl)(int fd, unsigned long request, void *arg)
{
    TRACE_CALL("ioctl", fd, request, arg);

    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        if (sock->rewrite_peer_address)
            return sock->ioctl(request, arg);
        else
            return real::ioctl(fd, request, arg);
    }, [&]() {
        return real::ioctl(fd, request, arg);
    });
}

#ifdef HAS_EPOLL
extern "C" int WRAP_SYM(epoll_ctl)(int epfd, int op, int fd,
                                   struct epoll_event *event)
{
    TRACE_CALL("epoll", epfd, op, fd, event);

    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        if (sock->rewrite_peer_address)
            return sock->epoll_ctl(epfd, op, event);
        else
            return real::epoll_ctl(epfd, op, fd, event);
    }, [&]() {
        return real::epoll_ctl(epfd, op, fd, event);
    });
}
#endif

#ifdef SYSTEMD_SUPPORT
/*
 * For systemd socket activation, we need to make sure the program doesn't run
 * listen on the socket, as this is already done by systemd.
 */
extern "C" int WRAP_SYM(listen)(int sockfd, int backlog)
{
    TRACE_CALL("listen", sockfd, backlog);
    return Socket::when<int>(sockfd, [&](Socket::Ptr sock) {
        return sock->listen(backlog);
    }, [&]() {
        return real::listen(sockfd, backlog);
    });
}
#endif

static RuleMatch match_rule(const SockAddr &addr, const Socket::Ptr sock,
                            const RuleDir dir)
{
    init_rules();

    size_t rulepos = 0;
    for (
        std::vector<Rule>::const_iterator it = g_rules->begin();
        it != g_rules->end();
        ++it, ++rulepos
    ) {
        const Rule &rule = *it;

        if (rule.direction && rule.direction != dir)
            continue;

        if (rule.type && sock->type != rule.type)
            continue;

        if (rule.address && addr.get_host() != rule.address)
            continue;

        if (rule.port) {
            std::optional<uint16_t> addrport = addr.get_port();
            if (addrport && rule.port_end) {
                if (rule.port.value() > addrport.value())
                    continue;
                if (rule.port_end < addrport.value())
                    continue;
            } else if (addrport != rule.port)
                continue;
        }

        if (rule.ignore)
            return std::nullopt;

#ifdef SYSTEMD_SUPPORT
        if (rule.socket_activation)
            return std::make_pair(rulepos, rule);
#endif
        if (!rule.socket_path && !rule.reject && !rule.blackhole)
            continue;

        return std::make_pair(rulepos, rule);
    }

    return std::nullopt;
}

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

        if (dir == RuleDir::OUTGOING) {
            /* If we already got something from a recvfrom or recvmsg, we
             * should have a mapping already and thus don't want to match
             * against a rule as we did this already in recv{from,msg} and the
             * destination address we get here doesn't necessarily match the
             * rule.
             */
            std::optional<int> pmap_ret = sock->connect_peermap(inaddr);
            if (pmap_ret) return pmap_ret.value();
        }

        std::scoped_lock<std::mutex> lock(g_rules_mutex);

        RuleMatch rule = match_rule(inaddr, sock, dir);

        if (!rule) {
            LOG(DEBUG) << "Socket " << fd << " doesn't match any rule or "
                       << "is explicitly ignored, unregistering.";
            sock->unregister();
            return std::invoke(realfun, fd, addr, addrlen);
        }

        if (rule->second.reject) {
            errno = rule->second.reject_errno.value_or(EACCES);
            return -1;
        }

        if (rule->second.blackhole) {
            sock->blackhole();
            return std::invoke(sockfun, sock, inaddr, "");
        }

#ifdef SYSTEMD_SUPPORT
        if (rule->second.socket_activation) {
            std::optional<Systemd::FdInfo> fdinfo =
                Systemd::acquire_fdinfo_for_rulepos(rule->first);
            if (fdinfo) {
                return sock->activate(inaddr, fdinfo->fd, fdinfo->is_inet);
            } else {
                LOG(WARNING) << "Systemd file descriptor queue empty, "
                             << "blackholing socket with fd " << fd << '.';
                sock->blackhole();
                return std::invoke(sockfun, sock, inaddr, "");
            }
        }
#endif

        return std::invoke(sockfun, sock, inaddr, *rule->second.socket_path);
    }, [&]() {
        return std::invoke(realfun, fd, addr, addrlen);
    });
}

extern "C" int WRAP_SYM(bind)(int fd, const struct sockaddr *addr,
                              socklen_t addrlen)
{
    TRACE_CALL("bind", fd, addr, addrlen);
    return bind_connect(&Socket::bind, real::bind, RuleDir::INCOMING,
                        fd, addr, addrlen);
}

extern "C" int WRAP_SYM(connect)(int fd, const struct sockaddr *addr,
                                 socklen_t addrlen)
{
    TRACE_CALL("connect", fd, addr, addrlen);
    return bind_connect(&Socket::connect, real::connect, RuleDir::OUTGOING,
                        fd, addr, addrlen);
}

static int handle_accept(int fd, struct sockaddr *addr, socklen_t *addrlen,
                         int flags)
{
    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        if (sock->rewrite_peer_address) {
            int accfd = real::accept4(fd, nullptr, nullptr, flags);
            if (accfd > 0)
                return sock->accept(accfd, addr, addrlen);
            else
                return accfd;
        } else {
            return real::accept4(fd, addr, addrlen, flags);
        }
    }, [&]() {
        return real::accept4(fd, addr, addrlen, flags);
    });
}

extern "C" int WRAP_SYM(accept)(int fd, struct sockaddr *addr,
                                socklen_t *addrlen)
{
    TRACE_CALL("accept", fd, addr, addrlen);
    return handle_accept(fd, addr, addrlen, 0);
}

extern "C" int WRAP_SYM(accept4)(int fd, struct sockaddr *addr,
                                 socklen_t *addrlen, int flags)
{
    TRACE_CALL("accept4", fd, addr, addrlen, flags);
    return handle_accept(fd, addr, addrlen, flags);
}

extern "C" int WRAP_SYM(getpeername)(int fd, struct sockaddr *addr,
                                     socklen_t *addrlen)
{
    TRACE_CALL("getpeername", fd, addr, addrlen);

    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        if (sock->rewrite_peer_address)
            return sock->getpeername(addr, addrlen);
        else
            return real::getpeername(fd, addr, addrlen);
    }, [&]() {
        return real::getpeername(fd, addr, addrlen);
    });
}

extern "C" int WRAP_SYM(getsockname)(int fd, struct sockaddr *addr,
                                     socklen_t *addrlen)
{
    TRACE_CALL("getsockname", fd, addr, addrlen);

    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        if (sock->rewrite_peer_address)
            return sock->getsockname(addr, addrlen);
        else
            return real::getsockname(fd, addr, addrlen);
    }, [&]() {
        return real::getsockname(fd, addr, addrlen);
    });
}

extern "C" ssize_t WRAP_SYM(recvfrom)(int fd, void *buf, size_t len, int flags,
                                      struct sockaddr *addr,
                                      socklen_t *addrlen)
{
    TRACE_CALL("recvfrom", fd, buf, len, flags, addr, addrlen);

    if (addr == nullptr)
        return real::recvfrom(fd, buf, len, flags, addr, addrlen);

    return Socket::when<ssize_t>(fd, [&](Socket::Ptr sock) {
        if (!sock->rewrite_peer_address)
            return real::recvfrom(fd, buf, len, flags, addr, addrlen);

        SockAddr recvaddr;
        recvaddr.ss_family = AF_UNIX;
        sockaddr *tmpaddr = recvaddr.cast();
        socklen_t tmplen = recvaddr.size();
        ssize_t ret = real::recvfrom(fd, buf, len, flags, tmpaddr, &tmplen);
        if (sock->rewrite_src(recvaddr, addr, addrlen)) {
            return ret;
        } else {
            errno = EINVAL;
            return static_cast<ssize_t>(-1);
        }
    }, [&]() {
        return real::recvfrom(fd, buf, len, flags, addr, addrlen);
    });
}

extern "C" ssize_t WRAP_SYM(recvmsg)(int fd, struct msghdr *msg, int flags)
{
    TRACE_CALL("recvmsg", fd, msg, flags);

    if (msg->msg_name == nullptr)
        return real::recvmsg(fd, msg, flags);

    return Socket::when<ssize_t>(fd, [&](Socket::Ptr sock) {
        if (!sock->rewrite_peer_address)
            return real::recvmsg(fd, msg, flags);

        SockAddr recvaddr;
        recvaddr.ss_family = AF_UNIX;

        msghdr msgcopy;
        memcpy(&msgcopy, msg, sizeof(msghdr));
        msgcopy.msg_name = &recvaddr;
        msgcopy.msg_namelen = recvaddr.size();

        ssize_t ret = real::recvmsg(fd, &msgcopy, flags);

        msgcopy.msg_name = msg->msg_name;
        msgcopy.msg_namelen = msg->msg_namelen;

        sockaddr *addr = reinterpret_cast<sockaddr*>(msgcopy.msg_name);
        if (sock->rewrite_src(recvaddr, addr, &msgcopy.msg_namelen)) {
            memcpy(msg, &msgcopy, sizeof(msghdr));
            return ret;
        } else {
            errno = EINVAL;
            return static_cast<ssize_t>(-1);
        }
    }, [&]() {
        return real::recvmsg(fd, msg, flags);
    });
}

extern "C" ssize_t WRAP_SYM(sendto)(int fd, const void *buf, size_t len,
                                    int flags, const struct sockaddr *addr,
                                    socklen_t addrlen)
{
    TRACE_CALL("sendto", fd, buf, len, flags, addr, addrlen);

    if (addr == nullptr)
        return real::sendto(fd, buf, len, flags, addr, addrlen);

    return Socket::when<ssize_t>(fd, [&](Socket::Ptr sock) {
        if (!sock->rewrite_peer_address)
            return real::sendto(fd, buf, len, flags, addr, addrlen);

        SockAddr addrcopy(addr);

        // XXX: Make all of this DRY!
        std::optional<SockAddr> newdest = sock->rewrite_dest_peermap(addrcopy);
        if (!newdest) {
            std::scoped_lock<std::mutex> lock(g_rules_mutex);

            RuleMatch rule = match_rule(addrcopy, sock, RuleDir::OUTGOING);

            if (!rule || !rule->second.socket_path)
                return real::sendto(fd, buf, len, flags, addr, addrlen);

            if (rule->second.reject) {
                errno = rule->second.reject_errno.value_or(EACCES);
                return static_cast<ssize_t>(-1);
            }

            newdest = sock->rewrite_dest(addrcopy, *rule->second.socket_path);
        }

        if (newdest) {
            sockaddr *ptr = reinterpret_cast<sockaddr*>(&newdest.value());
            return real::sendto(fd, buf, len, flags, ptr,
                                newdest.value().size());
        } else {
            return real::sendto(fd, buf, len, flags, nullptr,
                                static_cast<socklen_t>(0));
        }
    }, [&]() {
        return real::sendto(fd, buf, len, flags, addr, addrlen);
    });
}

extern "C" ssize_t WRAP_SYM(sendmsg)(int fd, const struct msghdr *msg,
                                     int flags)
{
    TRACE_CALL("sendmsg", fd, msg, flags);

    if (msg->msg_name == nullptr)
        return real::sendmsg(fd, msg, flags);

    return Socket::when<ssize_t>(fd, [&](Socket::Ptr sock) {
        if (!sock->rewrite_peer_address)
            return real::sendmsg(fd, msg, flags);

        SockAddr addrcopy(reinterpret_cast<const sockaddr*>(msg->msg_name));

        // XXX: Make all of this DRY!
        std::optional<SockAddr> newdest = sock->rewrite_dest_peermap(addrcopy);
        if (!newdest) {
            std::scoped_lock<std::mutex> lock(g_rules_mutex);

            RuleMatch rule = match_rule(addrcopy, sock, RuleDir::OUTGOING);

            if (!rule || !rule->second.socket_path)
                return real::sendmsg(fd, msg, flags);

            if (rule->second.reject) {
                errno = rule->second.reject_errno.value_or(EACCES);
                return static_cast<ssize_t>(-1);
            }

            newdest = sock->rewrite_dest(addrcopy, *rule->second.socket_path);
        }

        msghdr newmsg;
        memcpy(&newmsg, msg, sizeof(msghdr));
        if (newdest) {
            void *ptr = reinterpret_cast<void*>(&newdest.value());
            newmsg.msg_name = ptr;
            newmsg.msg_namelen = newdest.value().size();
        } else {
            newmsg.msg_name = nullptr;
            newmsg.msg_namelen = 0;
        }
        return real::sendmsg(fd, &newmsg, flags);
    }, [&]() {
        return real::sendmsg(fd, msg, flags);
    });
}

extern "C" int WRAP_SYM(dup)(int oldfd)
{
    TRACE_CALL("dup", oldfd);

    return Socket::when<int>(oldfd, [&](Socket::Ptr sock) {
        return sock->dup();
    }, [&]() {
        return real::dup(oldfd);
    });
}

static int handle_dup3(int oldfd, int newfd, int flags)
{
    if (oldfd == newfd)
        return real::dup3(oldfd, newfd, flags);

    return Socket::when<int>(oldfd, [&](Socket::Ptr sock) {
        return sock->dup(newfd, flags);
    }, [&]() {
        return real::dup3(oldfd, newfd, flags);
    });
}

extern "C" int WRAP_SYM(dup2)(int oldfd, int newfd)
{
    TRACE_CALL("dup2", oldfd, newfd);
    return handle_dup3(oldfd, newfd, 0);
}

extern "C" int WRAP_SYM(dup3)(int oldfd, int newfd, int flags)
{
    TRACE_CALL("dup3", oldfd, newfd, flags);
    return handle_dup3(oldfd, newfd, flags);
}

extern "C" int WRAP_SYM(close)(int fd)
{
    TRACE_CALL("close", fd);

#ifdef SYSTEMD_SUPPORT
    {
        std::scoped_lock<std::mutex> lock(g_rules_mutex);
        init_rules();
        if (Systemd::has_fd(fd)) {
            LOG(DEBUG) << "Prevented socket fd " << fd << " from being closed,"
                       << " because it's a file descriptor passed by systemd.";
            return 0;
        }
    }
#endif

    return Socket::when<int>(fd, [&](Socket::Ptr sock) {
        return sock->close();
    }, [&]() {
        return real::close(fd);
    });
}
