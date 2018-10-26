// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_DYNPORTS_HH
#define IP2UNIX_DYNPORTS_HH

#include <cstdint>
#include <unordered_set>

struct DynPorts
{
    DynPorts();
    uint16_t acquire(void);
    uint16_t reserve(uint16_t = 0);

    private:
        std::unordered_set<uint16_t> reserved;
        uint16_t current;
        uint16_t offset;

        uint16_t rotate_port(uint16_t, uint16_t) const;
};

#endif
