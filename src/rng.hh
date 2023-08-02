// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_RANDOMIZER_HH
#define IP2UNIX_RANDOMIZER_HH

#include <random>
#include <algorithm>

extern std::default_random_engine __generator;

/* A random generator for integer ranges which is very weak but faster than
 * using /dev/urandom or /dev/random and it's only used for port number and
 * address assignment, so we don't care whether it's well seeded.
 */
struct RNG
{
    template <class T>
    static T get(const T &from, const T &to) {
        std::uniform_int_distribution<T> dist(from, to);
        return dist(__generator);
    }
};

#endif
