// SPDX-License-Identifier: LGPL-3.0-only
#include <cstring>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "socket.hh"
#include "realcalls.hh"

std::optional<Socket::Ptr> Socket::find(int fd)
{
    using itype = decltype(Socket::registry)::const_iterator;
    itype found = Socket::registry.find(fd);
    if (found == Socket::registry.end())
        return std::nullopt;
    return found->second;
}

Socket::Ptr Socket::create(int fd, int domain, int type, int protocol)
{
    std::scoped_lock<std::mutex> lock(Socket::registry_mutex);
    Socket::Ptr sock = std::shared_ptr<Socket>(new Socket(fd, domain, type,
                                                          protocol));
    return Socket::registry[fd] = sock->getptr();
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

std::mutex Socket::registry_mutex;
std::unordered_map<int, Socket::Ptr> Socket::registry;

Socket::Socket(int fd, int domain, int type, int protocol)
    : type(get_sotype(type))
    , fd(fd)
    , domain(domain)
    , typearg(type)
    , protocol(protocol)
    , activated(false)
    , bound(false)
    , binding()
    , connection()
    , sockpath()
    , sockopts()
    , ports()
{
}

Socket::~Socket()
{
    /* NOTE: Do not close the socket file descriptor here, because if an
     * application checks the return code of close() it might raise errors.
     *
     * We can however unlink() the socket path, because the application thinks
     * it's an AF_INET/AF_INET6 socket so it won't know about that path.
     */
    if (this->sockpath && this->bound && !this->activated)
        unlink(this->sockpath.value().c_str());
}

Socket::Ptr Socket::getptr(void)
{
    return this->shared_from_this();
}

int Socket::setsockopt(int level, int optname, const void *optval,
                       socklen_t optlen)
{
    int ret = real::setsockopt(this->fd, level, optname, optval, optlen);

    /* Only add the socket option to the queue if the setsockopt() has
     * succeeded, otherwise we risk a fatal error while replaying them on
     * our end.
     */
    if (ret == 0)
        this->sockopts.cache_sockopt(level, optname, optval, optlen);
    return ret;
}

int Socket::ioctl(unsigned long request, const void *arg)
{
    int ret = real::ioctl(this->fd, request, arg);

    /* Only add the arguments to the queue if the ioctl() has succeeded,
     * otherwise we risk a fatal error while replaying them on our end.
     */
    if (ret == 0)
        this->sockopts.cache_ioctl(request, arg);
    return ret;
}

#ifdef SOCKET_ACTIVATION
int Socket::listen(int backlog)
{
    if (this->activated)
        return 0;

    return real::listen(this->fd, backlog);
}
#endif

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
bool Socket::make_unix(int fd)
{
    int newfd;

    if (this->is_unix)
        return true;

    if (fd != -1) {
        newfd = fd;
    } else if ((newfd = real::socket(AF_UNIX, this->typearg, 0)) == -1) {
        perror("socket(AF_UNIX)");
        return false;
    }

    if (!this->sockopts.replay(this->fd, newfd)) {
        if (fd == -1) real::close(newfd);
        return false;
    }

    if (dup2(newfd, this->fd) == -1) {
        perror("dup2");
        if (fd == -1) real::close(newfd);
        return false;
    }

    this->is_unix = true;
    return true;
}

#ifdef SOCKET_ACTIVATION
int Socket::activate(const SockAddr &addr, int fd)
{
    if (!this->make_unix(fd))
        return -1;

    this->bound = true;
    this->binding = addr;
    this->activated = true;
    return 0;
}
#endif

int Socket::bind(const SockAddr &addr, const std::string &path)
{
    if (!this->make_unix())
        return -1;

    std::string sockpath = this->format_sockpath(path, addr);

    struct sockaddr_un ua;
    memset(&ua, 0, sizeof ua);
    ua.sun_family = AF_UNIX;
    strncpy(ua.sun_path, sockpath.c_str(), sizeof(ua.sun_path) - 1);

    int ret = real::bind(this->fd, (struct sockaddr*)&ua, sizeof ua);
    if (ret == 0) {
        std::optional<uint16_t> port = addr.get_port();
        if (port) this->ports.reserve(port.value());
        this->bound = true;
        this->binding = addr;
        this->sockpath = sockpath;
    }
    return ret;
}

int Socket::connect(const SockAddr &addr, const std::string &path)
{
    if (!this->make_unix())
        return -1;

    std::string sockpath = this->format_sockpath(path, addr);

    struct sockaddr_un ua;
    memset(&ua, 0, sizeof ua);
    ua.sun_family = AF_UNIX;
    strncpy(ua.sun_path, sockpath.c_str(), sizeof(ua.sun_path) - 1);

    int ret = real::connect(this->fd, (struct sockaddr*)&ua, sizeof ua);
    if (ret == 0) {
        uint16_t port = this->ports.reserve();
        this->binding = SockAddr::create("127.0.0.1", port);
        this->connection = addr;
        this->sockpath = sockpath;
    }
    return ret;
}

int Socket::accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    Socket::Ptr sock = std::shared_ptr<Socket>(new Socket(fd, this->domain,
                                                          this->typearg,
                                                          this->protocol));
    sock->parent = this->getptr();

    uint16_t sport = this->ports.acquire();
    std::optional<SockAddr> sa = SockAddr::create("127.0.0.1", sport);
    sock->ports.reserve(sport);

    uint16_t cport = sock->ports.acquire(); //    vvvvvvvvv - XXX!
    std::optional<SockAddr> ca = SockAddr::create("0.0.0.1", cport);

    if (sa && ca) {
        sock->binding = sa;
        sock->connection = ca;
        sa.value().apply_addr(addr, addrlen);
        Socket::registry[fd] = sock->getptr();
        return 0;
    } else {
        sock->close();
        errno = EPROTO;
        return -1;
    }
}

int Socket::getpeername(struct sockaddr *addr, socklen_t *addrlen)
{
    if (this->connection) {
        this->connection.value().apply_addr(addr, addrlen);
        return 0;
    } else {
        errno = EFAULT;
        return -1;
    }
}

int Socket::getsockname(struct sockaddr *addr, socklen_t *addrlen)
{
    if (this->binding) {
        this->binding.value().apply_addr(addr, addrlen);
        return 0;
    } else {
        errno = EFAULT;
        return -1;
    }
}

int Socket::close(void)
{
    int ret;

    if (this->activated) {
        ret = 0;
    } else {
        ret = real::close(this->fd);

        if (this->sockpath && this->bound)
            unlink(this->sockpath.value().c_str());
    }

    Socket::registry.erase(this->fd);
    return ret;
}
