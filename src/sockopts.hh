// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKOPT_HH
#define IP2UNIX_SOCKOPT_HH

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/socket.h>
#include <queue>
#include <variant>
#include <optional>
#include <vector>

#ifdef HAS_EPOLL
#include <sys/epoll.h>
#endif

class SockOpts
{
    struct EntrySockopt {
        int level;
        int optname;
        std::vector<uint8_t> optval;
    };

    struct EntryIoctl {
        unsigned long request;
        std::vector<uint8_t> arg;
    };

#ifdef HAS_EPOLL
    struct EntryEpollCtl {
        int epfd;
        int op;
        std::optional<epoll_event> event;
    };
#endif

    std::queue<std::variant<
        EntrySockopt,
        EntryIoctl
#ifdef HAS_EPOLL
        , EntryEpollCtl
#endif
    >> entries;

    public:
        SockOpts();

        void cache_sockopt(int, int, const void*, socklen_t);
        void cache_ioctl(unsigned long, const void*);
#ifdef HAS_EPOLL
        void cache_epoll_ctl(int, int, struct epoll_event*);
#endif

        bool replay(int, int);
};

#endif
