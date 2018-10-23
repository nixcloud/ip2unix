// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKET_HH
#define IP2UNIX_SOCKET_HH

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <unordered_map>

#include <netinet/in.h>

#include "types.hh"
#include "sockaddr.hh"

// Forward decl
class Rule;

// FIXME
struct SockoptEntry {
    int level;
    int optname;
    std::vector<uint8_t> optval;
};

struct Socket : std::enable_shared_from_this<Socket>
{
    using Ptr = std::shared_ptr<Socket>;

    ~Socket();

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

    bool match_rule(const SockAddr&, const Rule&) const;

    int setsockopt(int, int, const void*, socklen_t);

    int listen(int);
    int bind_connect(const SockAddr&, const Rule &rule);

    void accept(int, sockaddr*, socklen_t*);
    int getsockname(sockaddr*, socklen_t*);
    int getpeername(sockaddr*, socklen_t*);
    int close(void);

    private:
        const int fd;
        const int domain;
        const SocketType type;
        const int typearg;
        const int protocol;

        std::optional<SockAddr> binding;
        std::queue<SockoptEntry> sockopts;

        /* Constructor and reference getter. */
        Socket(int, int, int, int);
        Ptr getptr(void);

        // XXX: Get rid of this...
        std::optional<const Rule*> rule = std::nullopt;
        std::optional<std::string> sockpath = std::nullopt;

        /* Mutex to prevent race conditions during Socket::registry lookup. */
        static std::mutex registry_mutex;

        /* Find a registered socket in Socket::registry. */
        static std::optional<Ptr> find(int);

        /* All INET/INET6 sockets are registered here. */
        static std::unordered_map<int, Ptr> registry;

        /* Whether the socket has been converted to an AF_UNIX socket. */
        bool is_unix = false;

        /* The parent once we got another socket via accept(). */
        std::optional<Ptr> parent;

        // helpers... TODO!
        bool apply_sockopts(int);
        bool make_unix(int = -1);

        void bind_sockaddr(const SockAddr*);

        std::string format_sockpath(const std::string&, const SockAddr&) const;
};

#endif
