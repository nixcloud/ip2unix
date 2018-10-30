// SPDX-License-Identifier: LGPL-3.0-only
#include <cstring>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "socket.hh"
#include "realcalls.hh"
#include "blackhole.hh"

std::optional<Socket::Ptr> Socket::find(int fd)
{
    using itype = decltype(Socket::registry)::const_iterator;
    itype found = Socket::registry.find(fd);
    if (found == Socket::registry.end())
        return std::nullopt;
    return found->second;
}

bool Socket::has_sockpath(const std::string &path)
{
    using itype = decltype(Socket::sockpath_registry)::const_iterator;
    itype found = Socket::sockpath_registry.find(path);
    return found != Socket::sockpath_registry.end();
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
std::unordered_set<std::string> Socket::sockpath_registry;

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
    if (this->sockpath && this->bound && !this->activated) {
        int old_errno = errno;
        unlink(this->sockpath.value().c_str());
        errno = old_errno;
    }
}

Socket::Ptr Socket::getptr(void)
{
    return this->shared_from_this();
}

void Socket::blackhole(void)
{
    this->is_blackhole = true;
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

    SockAddr newaddr = addr.copy();

    std::optional<uint16_t> port = newaddr.get_port();

    // Special case: Bind to port 0 uses a random port from the
    // ephemeral port range.
    if (port && port.value() == 0) {
        uint16_t anyport = this->ports.acquire();
        newaddr.set_port(anyport);
        port = anyport;
    }

    std::string sockpath = this->format_sockpath(path, newaddr);

    int ret;

    struct sockaddr_un ua;
    memset(&ua, 0, sizeof ua);
    ua.sun_family = AF_UNIX;

    // Another special case: If we already have a socket which binds to the
    // exact same path, let's blackhole the current socket.
    if (this->is_blackhole || Socket::has_sockpath(sockpath)) {
        BlackHole bh;
        std::optional<std::string> bh_path = bh.get_path();
        if (!bh_path) return -1;

        strncpy(ua.sun_path, bh_path.value().c_str(), sizeof(ua.sun_path) - 1);
        ret = real::bind(this->fd, (struct sockaddr*)&ua, sizeof ua);
        if (ret == 0)
            this->is_blackhole = true;
    } else {
        strncpy(ua.sun_path, sockpath.c_str(), sizeof(ua.sun_path) - 1);
        ret = real::bind(this->fd, (struct sockaddr*)&ua, sizeof ua);
        if (ret == 0) {
            Socket::sockpath_registry.insert(sockpath);
            this->sockpath = sockpath;
        }
    }

    if (ret == 0) {
        if (port) this->ports.reserve(port.value());
        this->bound = true;
        this->binding = newaddr;
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

    std::optional<uint16_t> remote_port = addr.get_port();
    if (!remote_port) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    int ret = real::connect(this->fd, (struct sockaddr*)&ua, sizeof ua);
    if (ret == 0) {
        if (!this->binding) {
            SockAddr local;
            local.ss_family = this->domain;

            if (addr.is_loopback()) {
                if (!local.set_host(addr)) {
                    errno = EADDRNOTAVAIL;
                    return -1;
                }
            } else {
                ucred local_cred;
                local_cred.uid = getuid();
                local_cred.gid = getgid();
                local_cred.pid = getpid();

                // Our local sockaddr, which we only need if we didn't have a
                // bind() before our connect.
                if (!local.set_host(local_cred)) {
                    errno = EADDRNOTAVAIL;
                    return -1;
                }
            }

            uint16_t local_port = this->ports.acquire();
            this->ports.reserve(remote_port.value());

            if (!local.set_port(local_port)) {
                errno = EADDRNOTAVAIL;
                return -1;
            }

            this->binding = local;
        }
        this->connection = addr;
        this->sockpath = sockpath;
    }
    return ret;
}

int Socket::accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (!this->binding) {
        errno = EINVAL;
        return -1;
    }

    SockAddr binding = this->binding.value().copy();
    std::optional<uint16_t> local_port = binding.get_port();
    if (!local_port) {
        errno = EINVAL;
        return -1;
    }

    SockAddr peer;
    peer.ss_family = this->domain;

    if (this->binding.value().is_loopback()) {
        if (!peer.set_host(this->binding.value())) {
            errno = EADDRNOTAVAIL;
            return -1;
        }
    } else {
        // We use SO_PEERCRED to get uid, gid and pid in order to generate
        // unique IP addresses.
        ucred peercred;
        socklen_t len = sizeof peercred;

        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peercred, &len) == -1)
            return -1;

        if (!peer.set_host(peercred)) {
            errno = EINVAL;
            return -1;
        }
    }

    // This is going to be used later when getpeername() is invoked.
    uint16_t peer_port = this->ports.acquire();
    if (!peer.set_port(peer_port)) {
        errno = EINVAL;
        return -1;
    }

    Socket::Ptr sock = std::shared_ptr<Socket>(
        new Socket(fd, this->domain, this->typearg, this->protocol)
    );
    sock->ports.reserve(local_port.value());
    sock->binding = binding;
    sock->connection = peer;
    peer.apply_addr(addr, addrlen);
    Socket::registry[fd] = sock->getptr();
    return fd;
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

        if (this->sockpath && this->bound && !this->is_blackhole) {
            int old_errno = errno;
            unlink(this->sockpath.value().c_str());
            errno = old_errno;
            Socket::sockpath_registry.erase(this->sockpath.value());
            this->sockpath = std::nullopt;
        }
    }

    Socket::registry.erase(this->fd);
    return ret;
}
