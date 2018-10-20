// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKET_HH
#define IP2UNIX_SOCKET_HH

#include <optional>
#include <queue>

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

class Socket
{
    const int fd;
    const int domain;
    const SocketType type;
    const int typearg;
    const int protocol;

    std::optional<SockAddr> binding;
    std::queue<SockoptEntry> sockopts;

    // Whether the socket has already been converted to an AF_UNIX socket.
    bool is_unix = false;

    // helpers... TODO!
    bool apply_sockopts(int);
    bool make_unix();

    void bind_sockaddr(const SockAddr*);

    std::string format_sockpath(const std::string&, const SockAddr&) const;

    public:
        Socket(int, int, int, int);

        bool match_rule(const SockAddr&, const Rule&) const;

        // XXX: Make private!
        std::optional<const Rule*> rule = std::nullopt;
        std::optional<std::string> sockpath = std::nullopt;
        // !XXX

        int setsockopt(int, int, const void*, socklen_t);

        int listen(int);

        int bind_connect(const SockAddr&, const Rule &rule);
        /*
        int bind(const struct sockaddr*, socklen_t);
        int connect(const struct sockaddr *, socklen_t);
        */

        int getsockname(sockaddr*, socklen_t*);
        int getpeername(struct sockaddr*, socklen_t*);
        /*
        int accept4(struct sockaddr*, socklen_t*, int);
        */
        int close(void);
};

#endif
