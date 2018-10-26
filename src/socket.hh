// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKET_HH
#define IP2UNIX_SOCKET_HH

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <unordered_map>

#include "types.hh"
#include "sockaddr.hh"
#include "sockopts.hh"
#include "dynports.hh"

struct Socket : std::enable_shared_from_this<Socket>
{
    using Ptr = std::shared_ptr<Socket>;

    ~Socket();
    const SocketType type;

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

    int setsockopt(int, int, const void*, socklen_t);
    int ioctl(unsigned long, const void*);

    int listen(int);
#ifdef SOCKET_ACTIVATION
    int activate(const SockAddr&, int fd);
#endif
    int bind(const SockAddr&, const std::string&);
    int connect(const SockAddr&, const std::string&);

    int accept(int, sockaddr*, socklen_t*);
    int getsockname(sockaddr*, socklen_t*);
    int getpeername(sockaddr*, socklen_t*);
    int close(void);

    private:
        const int fd;
        const int domain;
        const int typearg;
        const int protocol;

        bool activated;
        bool bound;
        std::optional<SockAddr> binding;
        std::optional<SockAddr> connection;
        std::optional<std::string> sockpath;

        SockOpts sockopts;
        DynPorts ports;

        /* Constructor and reference getter. */
        Socket(int, int, int, int);
        Ptr getptr(void);

        /* Mutex to prevent race conditions during Socket::registry lookup. */
        static std::mutex registry_mutex;

        /* Find a registered socket in Socket::registry. */
        static std::optional<Ptr> find(int);

        /* All INET/INET6 sockets are registered here. */
        static std::unordered_map<int, Ptr> registry;

        /* Whether the socket has been converted to an AF_UNIX socket. */
        bool is_unix = false;

        /* Various helper functions. */
        bool apply_sockopts(int);
        bool make_unix(int = -1);

        std::string format_sockpath(const std::string&, const SockAddr&) const;
};

#endif
