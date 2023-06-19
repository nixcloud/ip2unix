// SPDX-License-Identifier: LGPL-3.0-only
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <type_traits>
#include <utility>

#include "socket.hh"
#include "realcalls.hh"
#include "logging.hh"
#include "blackhole.hh"
#include "types.hh"

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
    Socket::registry[fd] = sock->getptr();
    LOG(INFO) << "Registered socket with fd " << fd << ", domain " << domain
              << ", type " << type << " and protocol " << protocol << '.';
    return Socket::registry[fd];
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

Socket::Socket(int sfd, int sdomain, int stype, int sproto)
    : type(get_sotype(stype))
    , rewrite_peer_address(true)
    , fd(sfd)
    , domain(sdomain)
    , typearg(stype)
    , protocol(sproto)
    , activated(false)
    , binding()
    , connection()
    , unlink_sockpath()
    , sockopts()
    , ports()
    , peermap()
    , revpeermap()
    , blackhole_ref(std::nullopt)
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
    if (this->unlink_sockpath) {
        int old_errno = errno;
        unlink(this->unlink_sockpath.value().c_str());
        errno = old_errno;
    }
}

Socket::Ptr Socket::getptr(void)
{
    return this->shared_from_this();
}

void Socket::blackhole(void)
{
    if (this->is_blackhole)
        return;
    LOG(INFO) << "Socket with fd " << this->fd << " blackholed.";
    this->is_blackhole = true;
}

int Socket::setsockopt(int level, int optname, const void *optval,
                       socklen_t optlen)
{
    if (this->is_unix && level != SOL_SOCKET) {
        LOG(DEBUG) << "Prevented calling setsockopt on fd " << this->fd
                   << " with incompatible level " << level << '.';
        return 0;
    }

    int ret = real::setsockopt(this->fd, level, optname, optval, optlen);
    if (ret != 0)
        return ret;

    /* Only add the socket option to the queue if the setsockopt() has
     * succeeded (and it's using SOL_SOCKET level), otherwise we risk a fatal
     * error while replaying them on our end.
     */
    if (!this->is_unix && level == SOL_SOCKET) {
        if (optname == SO_REUSEADDR && *static_cast<const int*>(optval) > 0)
            this->reuse_addr = true;

        this->sockopts.cache_sockopt(level, optname, optval, optlen);
    }

    return ret;
}

int Socket::ioctl(unsigned long request, const void *arg)
{
    int ret = real::ioctl(this->fd, request, arg);
    if (ret != 0)
        return ret;

    /* Only add the arguments to the queue if the ioctl() has succeeded,
     * otherwise we risk a fatal error while replaying them on our end.
     */
    if (!this->is_unix)
        this->sockopts.cache_ioctl(request, arg);

    return ret;
}

#ifdef HAS_EPOLL
int Socket::epoll_ctl(int epfd, int op, struct epoll_event *event)
{
    int ret = real::epoll_ctl(epfd, op, this->fd, event);
    if (ret != 0)
        return ret;

    if (!this->is_unix)
        this->sockopts.cache_epoll_ctl(epfd, op, event);

    return ret;
}
#endif

#ifdef SYSTEMD_SUPPORT
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
std::string Socket::format_sockpath(const std::string &path,
                                    const SockAddr &addr) const
{
    std::string out = "";
    size_t path_len = path.size();

    for (size_t i = 0; i < path_len; ++i) {
        if (path[i] == '%' && i + 1 < path_len) {
            switch (path[i + 1]) {
                case '%': out += '%'; i++; continue;
                case 'a': out += addr.get_host().value_or("unknown"); i++;
                          continue;
                case 'p': out += addr.get_port_str().value_or("unknown"); i++;
                          continue;
                case 't':
                    switch (this->type) {
                        case SocketType::TCP:     out += "tcp"; break;
                        case SocketType::UDP:     out += "udp"; break;
                        case SocketType::INVALID: out += "unknown"; break;
                    }
                    i++;
                    continue;
            }
        }
        out += path[i];
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
bool Socket::make_unix(int oldfd)
{
    int newfd;
    int old_errno = errno;

    if (this->is_unix)
        return true;

    if (oldfd != -1) {
        newfd = oldfd;
        LOG(INFO) << "Re-using socket with fd " << newfd << '.';
    } else {
        if ((newfd = real::socket(AF_UNIX, this->typearg, 0)) == -1) {
            LOG(ERROR) << "Unable to create new Unix socket with type "
                       << this->typearg << ": " << strerror(errno);
            errno = old_errno;
            return false;
        }
        LOG(INFO) << "Created new Unix socket with fd " << newfd << '.';
    }

    if (!this->sockopts.replay(this->fd, newfd)) {
        LOG(ERROR) << "Unable to replay socket options from fd " << this->fd
                   << " to fd " << newfd << '.';
        real::close(newfd);
        errno = old_errno;
        return false;
    }

    if (real::dup2(newfd, this->fd) == -1) {
        LOG(ERROR) << "Unable to replace socket fd " << this->fd
                   << " by socket with fd " << newfd << ": "
                   << strerror(errno);
        real::close(newfd);
        errno = old_errno;
        return false;
    }

    real::close(newfd);

    LOG(INFO) << "Replaced socket fd " << this->fd << " by socket with fd "
              << newfd << '.';

    errno = old_errno;
    this->is_unix = true;
    return true;
}

/* We need to use this for Socket::connect but also for Socket::rewrite_dest
 * because both create an implicit binding.
 */
bool Socket::create_binding(const SockAddr &addr)
{
    SockAddr local;
    local.ss_family = this->domain;

    if (addr.is_loopback()) {
        if (!local.set_host(addr))
            return false;
    } else {
        ucred local_cred;
        local_cred.uid = getuid();
        local_cred.gid = getgid();
        local_cred.pid = getpid();

        // Our local sockaddr, which we only need if we didn't have a
        // bind() before our connect.
        if (!local.set_host(local_cred))
            return false;
    }

    if (!local.set_port(this->ports.acquire()))
        return false;

    this->binding = local;
    return true;
}

#ifdef SYSTEMD_SUPPORT
int Socket::activate(const SockAddr &addr, int filedes, bool is_inet)
{
    if (is_inet) {
        LOG(DEBUG) << "Passed systemd socket file descriptor " << filedes
                   << " corresponds to an an inet socket, turning off peer"
                   << " address rewriting.";
        this->rewrite_peer_address = false;
    }

    if (!this->make_unix(filedes))
        return -1;

    this->binding = addr;
    this->activated = true;
    LOG(INFO) << "Socket fd " << this->fd
              << " marked for systemd socket activation.";
    return 0;
}
#endif

#define DO_USOCK_OR_FAIL(path, error_block) \
    std::optional<SockAddr> maybe_dest = SockAddr::unix(path); \
    if (!maybe_dest) error_block \
    SockAddr dest = maybe_dest.value()

#define USOCK_OR_FAIL(path, ret) \
    DO_USOCK_OR_FAIL(path, return ret;)

#define USOCK_OR_EFAULT(path) \
    DO_USOCK_OR_FAIL(path, { errno = EFAULT; return -1; })

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

    std::string newpath = this->format_sockpath(path, newaddr);

    int ret;

    // Another special case: If we already have a socket which binds to the
    // exact same path, let's blackhole the current socket.
    if (this->is_blackhole || Socket::has_sockpath(newpath)) {
        BlackHole bh;
        std::optional<std::string> bh_path = bh.get_path();
        if (!bh_path) return -1;

        USOCK_OR_EFAULT(bh_path.value());
        ret = real::bind(this->fd, dest.cast(), dest.size());
        if (ret == 0)
            this->blackhole();
    } else {
        if (this->reuse_addr)
            unlink(newpath.c_str());
        USOCK_OR_EFAULT(newpath);
        ret = real::bind(this->fd, dest.cast(), dest.size());
        if (ret == 0) {
            Socket::sockpath_registry.insert(newpath);
            this->unlink_sockpath = newpath;
        }
    }

    if (ret == 0) {
        if (port) this->ports.reserve(port.value());
        this->binding = newaddr;
    }
    return ret;
}

std::optional<int> Socket::connect_peermap(const SockAddr &addr)
{
    if (this->type == SocketType::UDP) {
        auto found = this->peermap.find(addr);
        if (found != this->peermap.end()) {
            USOCK_OR_EFAULT(found->second);
            int ret = real::connect(this->fd, dest.cast(), dest.size());
            if (ret != 0)
                return ret;
            this->connection = addr;
            return ret;
        }
    }
    return std::nullopt;
}

int Socket::connect(const SockAddr &addr, const std::string &path)
{
    if (this->type == SocketType::UDP && !this->binding) {
        /* If we connect without prior binding on a datagram socket, we need to
         * create an implicit binding first, so the peer is able to recognise
         * us.
         */
        std::optional<SockAddr> maybe_dest = this->rewrite_dest(addr, path);
        if (!maybe_dest) {
            errno = EADDRNOTAVAIL;
            return -1;
        }
        SockAddr dest = maybe_dest.value();
        int ret = real::connect(this->fd, dest.cast(), dest.size());
        if (ret == 0)
            this->connection = addr;
        return ret;
    }

    std::string new_sockpath = this->format_sockpath(path, addr);
    USOCK_OR_EFAULT(new_sockpath);

    if (!this->make_unix())
        return -1;

    std::optional<uint16_t> remote_port = addr.get_port();
    if (!remote_port) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    int ret = real::connect(this->fd, dest.cast(), dest.size());
    if (ret != 0)
        return ret;

    if (!this->binding) {
        if (!this->create_binding(addr)) {
            errno = EADDRNOTAVAIL;
            return -1;
        }
        this->ports.reserve(remote_port.value());
    }

    this->connection = addr;
    return ret;
}

int Socket::accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (!this->binding) {
        errno = EINVAL;
        return -1;
    }

    SockAddr local_addr = this->binding.value().copy();
    std::optional<uint16_t> local_port = local_addr.get_port();
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

        if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &peercred, &len) == -1)
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
        new Socket(sockfd, this->domain, this->typearg, this->protocol)
    );
    sock->ports.reserve(local_port.value());
    sock->binding = local_addr;
    sock->connection = peer;
    sock->is_unix = true;
    peer.apply_addr(addr, addrlen);
    Socket::registry[sockfd] = sock->getptr();
    LOG(INFO) << "Accepted socket fd " << sockfd
              << " registered as a children of socket fd "
              << this->fd << '.';
    return sockfd;
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

/* Apply source address to pointers from recvfrom/recvmsg. */
bool Socket::rewrite_src(const SockAddr &real_addr, struct sockaddr *addr,
                         socklen_t *addrlen)
{
    if (!this->binding)
        return true;

    std::optional<std::string> path = real_addr.get_sockpath();
    if (!path)
        return true;

    auto found = this->revpeermap.find(path.value());
    if (found != this->revpeermap.end()) {
        found->second.apply_addr(addr, addrlen);
        return true;
    }

    SockAddr peer;
    peer.ss_family = this->domain;

    peer.set_port(this->ports.acquire());

    if (this->binding.value().is_loopback()) {
        if (!peer.set_host(this->binding.value()))
            return false;
    } else {
        if (!peer.set_random_host())
            return false;
    }

    this->peermap[peer] = path.value();
    this->revpeermap[path.value()] = peer;

    peer.apply_addr(addr, addrlen);
    return true;
}

std::optional<SockAddr>
Socket::rewrite_dest_peermap(const SockAddr &addr) const
{
    auto found = this->peermap.find(addr);
    if (found != this->peermap.end()) {
        USOCK_OR_FAIL(found->second, std::nullopt);
        return dest;
    }
    return std::nullopt;
}

/* Rewrite address provided by sendto/sendmsg. */
std::optional<SockAddr> Socket::rewrite_dest(const SockAddr &addr,
                                             const std::string &path)
{
    if (this->type != SocketType::UDP)
        return std::nullopt;

    std::optional<SockAddr> destpath =
        SockAddr::unix(this->format_sockpath(path, addr));

    if (!destpath)
        return std::nullopt;

    if (!this->make_unix())
        return std::nullopt;

    /* In order to be able to distinguish the current peer on the remote side
     * we need to have a binding on our side. Otherwise all the remote side
     * will get is a null pointer of the peer address and there is no way to
     * find out anything about the peer, not even using SO_PEERCRED as we're
     * using datagrams.
     */
    if (!this->binding) {
        std::unique_ptr<BlackHole> bh = std::make_unique<BlackHole>();
        std::optional<std::string> bh_path = bh->get_path();
        if (!bh_path) return std::nullopt;

        USOCK_OR_FAIL(bh_path.value(), std::nullopt);
        int ret = real::bind(this->fd, dest.cast(), dest.size());
        if (ret != 0) return std::nullopt;

        if (!this->create_binding(addr))
            return std::nullopt;

        this->blackhole();

        /* Persist the blackhole, because the remote might want to connect() or
         * send additional packets.
         */
        this->blackhole_ref = std::move(bh);
    }

    return destpath;
}

int Socket::dup(void)
{
    int newfd = real::dup(this->fd);
    if (newfd != -1) {
        LOG(INFO) << "Duplicated socket fd " << this->fd
                  << " to " << newfd << '.';
        Socket::registry[newfd] = this->getptr();
    }
    return newfd;
}

int Socket::dup(int newfd, int flags)
{
    std::optional<Socket::Ptr> existing = Socket::find(newfd);
    if (existing)
        existing.value()->close();

    int ret = real::dup3(this->fd, newfd, flags);
    if (ret != -1) {
        LOG(INFO) << "Duplicated socket fd " << this->fd
                  << " to " << newfd << '.';
        Socket::registry[ret] = this->getptr();
    }

    return ret;
}

int Socket::close(void)
{
    int ret;

    if (this->activated) {
        LOG(INFO) << "Not closing socket fd " << this->fd
                  << " because it's a systemd socket.";
        ret = 0;
    } else {
        LOG(INFO) << "Closing socket fd " << this->fd << '.';
        ret = real::close(this->fd);

        if (this->unlink_sockpath) {
            int old_errno = errno;
            LOG(INFO) << "Unlinking socket path '" << *this->unlink_sockpath
                      << "'.";
            unlink(this->unlink_sockpath.value().c_str());
            errno = old_errno;
            Socket::sockpath_registry.erase(this->unlink_sockpath.value());
            this->unlink_sockpath = std::nullopt;
        }
    }

    Socket::registry.erase(this->fd);
    LOG(INFO) << "Socket fd " << this->fd << " unregistered.";
    return ret;
}

void Socket::unregister(void)
{
    LOG(DEBUG) << "Unregistering socket fd " << this->fd << '.';
    Socket::registry.erase(this->fd);
}
