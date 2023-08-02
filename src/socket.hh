// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKET_HH
#define IP2UNIX_SOCKET_HH

#include <sys/socket.h>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <unordered_map>
#include <unordered_set>

#include "types.hh"
#include "sockaddr.hh"
#include "sockopts.hh"
#include "dynports.hh"
#include "blackhole.hh"

enum class SocketType;
struct BlackHole;

struct Socket : std::enable_shared_from_this<Socket>
{
    using Ptr = std::shared_ptr<Socket>;

    ~Socket();
    const SocketType type;
    bool rewrite_peer_address;

    /* If we find a socket in Socket::registry, call the first function,
     * otherwise call the second function (providing default value).
     */
    template<typename T>
    static T when(int fd, std::function<T(Ptr)> f, std::function<T(void)> d) {
        std::unique_lock<std::mutex> lock(Socket::registry_mutex);
        std::optional<Ptr> sock = Socket::find(fd);
        if (sock) {
            return f(sock.value());
        } else {
            lock.unlock();
            return d();
        }
    }

    /* Same as the previous function, but without a default value. */
    static void when(int fd, std::function<void(Ptr)> f) {
        std::scoped_lock<std::mutex> lock(Socket::registry_mutex);
        std::optional<Ptr> sock = Socket::find(fd);
        if (sock) f(sock.value());
    }

    /* Construct the socket and register it in Socket::registry. */
    static std::shared_ptr<Socket> create(int, int, int, int);

    void blackhole(void);

    int setsockopt(int, int, const void*, socklen_t);
    int ioctl(unsigned long, const void*);
#ifdef HAS_EPOLL
    int epoll_ctl(int, int, struct epoll_event*);
#endif

    int listen(int);
#ifdef SYSTEMD_SUPPORT
    int activate(const SockAddr&, int, bool);
#endif
    int bind(const SockAddr&, const std::string&);
    std::optional<int> connect_peermap(const SockAddr&);
    int connect(const SockAddr&, const std::string&);

    int accept(int, sockaddr*, socklen_t*);
    int getsockname(sockaddr*, socklen_t*);
    int getpeername(sockaddr*, socklen_t*);

    bool rewrite_src(const SockAddr&, sockaddr*, socklen_t*);
    std::optional<SockAddr> rewrite_dest_peermap(const SockAddr&) const;
    std::optional<SockAddr> rewrite_dest(const SockAddr&, const std::string&);

    int dup(void);
    int dup(int, int);
    int close(void);
    void unregister(void);

    private:
        const int fd;
        const int domain;
        const int typearg;
        const int protocol;

        bool activated;
        std::optional<SockAddr> binding;
        std::optional<SockAddr> connection;
        std::optional<std::string> unlink_sockpath;

        SockOpts sockopts;
        DynPorts ports;

        /* This is used for recvfrom/recvmsg to generate random remote peers
         * and look them up either in the next recvfrom/recvmsg or in a
         * connect().
         */
        std::unordered_map<SockAddr, std::string> peermap;
        std::unordered_map<std::string, SockAddr> revpeermap;

        /* Constructor and reference getter. */
        Socket(int, int, int, int);
        Ptr getptr(void);

        /* Mutex to prevent race conditions during Socket::registry lookup. */
        static std::mutex registry_mutex;

        /* Find a registered socket in Socket::registry. */
        static std::optional<Ptr> find(int);

        /* Check if a socket path is registered. */
        static bool has_sockpath(const std::string&);

        /* All INET/INET6 sockets are registered here. */
        static std::unordered_map<int, Ptr> registry;

        /* Mapping from bound socket paths to sockets. */
        static std::unordered_set<std::string> sockpath_registry;

        /* Whether the socket has been converted to an AF_UNIX socket. */
        bool is_unix = false;

        /* Set if this socket is bound to an unlinked socket path. */
        bool is_blackhole = false;

        /* If true, the socket file should be unlinked before to bind. */
        bool reuse_addr = false;

        /* We need this if we need ta persist a blackhole path for a while. */
        std::optional<std::unique_ptr<BlackHole>> blackhole_ref;

        /* Various helper functions. */
        bool apply_sockopts(int);
        bool make_unix(int = -1);
        bool create_binding(const SockAddr&);

        std::string format_sockpath(const std::string&, const SockAddr&) const;
};

#endif
