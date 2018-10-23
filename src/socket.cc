// SPDX-License-Identifier: LGPL-3.0-only
#include <cstring>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "socket.hh"
#include "realcalls.hh"
#include "rules.hh"

std::optional<Socket::Ptr> Socket::find(int fd)
{
    decltype(Socket::active)::const_iterator found = Socket::active.find(fd);
    if (found == Socket::active.end())
        return std::nullopt;
    return found->second;
}

Socket::Ptr Socket::create(int fd, int domain, int type, int protocol)
{
    std::scoped_lock<std::mutex> lock(Socket::active_mutex);
    Socket::Ptr sock = std::shared_ptr<Socket>(new Socket(fd, domain, type,
                                                          protocol));
    return Socket::active[fd] = sock->getptr();
}

static inline SocketType get_sotype(const int type)
{
    switch (type & (SOCK_STREAM | SOCK_DGRAM)) {
        case SOCK_STREAM:
            return SocketType::TCP;
        case SOCK_DGRAM:
            return SocketType::UDP;
        default:
            return SocketType::INVALID;
    }
}

std::mutex Socket::active_mutex;
std::unordered_map<int, Socket::Ptr> Socket::active;

Socket::Socket(int fd, int domain, int type, int protocol)
    : fd(fd)
    , domain(domain)
    , type(get_sotype(type))
    , typearg(type)
    , protocol(protocol)
    , binding()
    , sockopts()
{
}

Socket::~Socket()
{
    if (this->rule && this->sockpath) {
        auto rule = this->rule.value();
        if (rule->direction == RuleDir::INCOMING)
            unlink(this->sockpath.value().c_str());
    }
}

Socket::Ptr Socket::getptr(void)
{
    return this->shared_from_this();
}

int Socket::setsockopt(int level, int optname, const void *optval,
                       socklen_t optlen)
{
    std::vector<uint8_t> valcopy((uint8_t*)optval,
                                 (uint8_t*)optval + optlen);
    SockoptEntry entry{level, optname, valcopy};

    int ret = real::setsockopt(this->fd, level, optname, optval, optlen);

    /* Only add the socket option to the queue if the setsockopt() has
     * succeeded, otherwise we risk a fatal error while replaying them on
     * our end.
     */
    if (ret == 0)
        this->sockopts.push(entry);
    return ret;
}

#ifdef SOCKET_ACTIVATION
int Socket::listen(int backlog)
{
    if (this->rule && this->rule.value()->socket_activation)
        return 0;

    return real::listen(this->fd, backlog);
}
#endif

/*
 * Set all the socket options and file descriptor flags from old_sockfd to
 * new_sockfd.
 */
bool Socket::apply_sockopts(int new_sockfd)
{
    int fdflags, fdstatus;

    if ((fdflags = fcntl(this->fd, F_GETFD)) == -1) {
        perror("fcntl(F_GETFD)");
        return false;
    }

    if ((fdstatus = fcntl(this->fd, F_GETFL)) == -1) {
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

    while (!this->sockopts.empty()) {
        auto entry = this->sockopts.front();
        if (real::setsockopt(new_sockfd, entry.level, entry.optname,
                             entry.optval.data(),
                             entry.optval.size()) == -1) {
            perror("setsockopt");
            return false;
        }
        this->sockopts.pop();
    }

    return true;
}

/*
 * Replace placeholders such as %p or %a accordingly in the socket path.
 */
std::string Socket::format_sockpath(const std::string &sockpath,
                                    const SockAddr &addr) const
{
    std::string out = "";
    size_t sockpath_len = sockpath.size();

    for (size_t i = 0; i < sockpath_len; ++i) {
        if (sockpath[i] == '%' && i + 1 < sockpath_len) {
            switch (sockpath[i + 1]) {
                case '%': out += '%'; i++; continue;
                case 'a': out += addr.get_host().value_or("unknown"); i++;
                          continue;
                case 'p': out += addr.get_port_str().value_or("unknown"); i++;
                          continue;
                case 't':
                    switch (this->type) {
                        case SocketType::TCP: out += "tcp"; break;
                        case SocketType::UDP: out += "udp"; break;
                        default: out += "unknown"; break;
                    }
                    i++;
                    continue;
            }
        }
        out += sockpath[i];
    }

    return out;
}

/*
 * Turn the given socket file descriptor into a UNIX Domain socket by creating
 * a new socket and setting all the socket options and file descriptor flags
 * from the old socket.
 *
 * The socket options are read from sockopt_cache, which is gathered from the
 * override of the setsockopt() function above.
 */
bool Socket::make_unix(void)
{
    int newfd;

    if (this->is_unix)
        return true;

    if ((newfd = real::socket(AF_UNIX, this->typearg, 0)) == -1) {
        perror("socket(AF_UNIX)");
        return false;
    }

    if (!this->apply_sockopts(newfd)) {
        real::close(newfd);
        return false;
    }

    if (dup2(newfd, this->fd) == -1) {
        perror("dup2");
        real::close(newfd);
        return false;
    }

    this->is_unix = true;
    return true;
}

// FIXME: Get rid of rule!
int Socket::bind_connect(const SockAddr &addr, const Rule &rule)
{
#ifdef SOCKET_ACTIVATION
    if (rule.socket_activation) {
        // FIXME: Deduplicate!
        if (this->is_unix)
            return 0;

        // XXX: This shouldn't be here!
        int newfd = get_systemd_fd_for_rule(rule);

        if (!this->apply_sockopts(newfd))
            return -1;

        if (dup2(newfd, fd) == -1) {
            perror("dup2");
            return -1;
        }

        this->binding = addr;
        this->rule = &rule;
        this->is_unix = true;
        return 0;
    }
#endif

    if (!this->make_unix())
        return -1;

    // XXX: .value() -> dangerous!
    std::string sockpath =
        this->format_sockpath(rule.socket_path.value(), addr);

    struct sockaddr_un ua;
    memset(&ua, 0, sizeof ua);
    ua.sun_family = AF_UNIX;
    strncpy(ua.sun_path, sockpath.c_str(), sizeof(ua.sun_path) - 1);

    int ret;

    switch (rule.direction) {
        case RuleDir::INCOMING:
            ret = real::bind(this->fd, (struct sockaddr*)&ua, sizeof ua);
            break;
        case RuleDir::OUTGOING:
            ret = real::connect(this->fd, (struct sockaddr*)&ua, sizeof ua);
            break;
        default:
            // FIXME!
            return 0;
    }

    if (ret == 0) {
        this->binding = addr;
        this->sockpath = sockpath;
        this->rule = &rule;
    }

    return ret;
}

/* TODO!
int Socket::bind(const struct sockaddr *addr, socklen_t addrlen)
{
    return handle_bind_connect(addr, addrlen);
}

int Socket::connect(const struct sockaddr *addr, socklen_t addrlen)
{
    return handle_bind_connect(addr, addrlen);
}
*/

/*
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
*/

void Socket::accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    Socket::Ptr sock = std::shared_ptr<Socket>(new Socket(fd, this->domain,
                                                          this->typearg,
                                                          this->protocol));
    sock->parent = this->getptr();
    Socket::active[fd] = sock->getptr();

    std::optional<SockAddr> sa = SockAddr::create("127.0.0.1", 65530);
    sa.value_or(SockAddr()).apply_addr(addr, addrlen);
}

int Socket::getpeername(struct sockaddr *addr, socklen_t *addrlen)
{
    std::optional<SockAddr> sa = SockAddr::create("127.0.0.1", 65530);
    sa.value_or(SockAddr()).apply_addr(addr, addrlen);
    return 0;
}

int Socket::getsockname(struct sockaddr *addr, socklen_t *addrlen)
{
    this->binding.value_or(SockAddr()).apply_addr(addr, addrlen);
    return 0;
}

int Socket::close(void)
{
#ifdef SOCKET_ACTIVATION
    if (this->rule && this->rule.value()->socket_activation) {
        Socket::active.erase(this->fd);
        return 0;
    }
#endif
    int ret = real::close(fd);

    if (this->rule) {
        auto rule = this->rule.value();
        if (this->sockpath && rule->direction == RuleDir::INCOMING)
            unlink(this->sockpath.value().c_str());
    }

    Socket::active.erase(this->fd);
    return ret;
}

bool Socket::match_rule(const SockAddr &addr, const Rule &rule) const
{
    if (rule.type && this->type != rule.type)
        return false;

    if (rule.address && addr.get_host() != rule.address)
        return false;

    if (rule.port && addr.get_port() != rule.port)
        return false;

    return true;
}
