// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKOPT_HH
#define IP2UNIX_SOCKOPT_HH

#include <queue>
#include <variant>

#include <arpa/inet.h>

class SockOpts
{
    struct EntrySockopt {
        int level;
        int optname;
        std::vector<uint8_t> optval;
    };

    struct EntryIoctl {
        unsigned long request;
        // TODO: std::vector<...> args;
    };

    std::queue<std::variant<EntrySockopt, EntryIoctl>> entries;

    public:
        SockOpts();

        void cache_sockopt(int, int, const void*, socklen_t);
        void cache_ioctl(unsigned long, ...);

        bool replay(int, int);
};

#endif
