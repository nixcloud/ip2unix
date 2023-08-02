// SPDX-License-Identifier: LGPL-3.0-only
#include <unistd.h>
#include <stdint.h>
#include <chrono>

#include "rng.hh"

static std::default_random_engine initalize_generator(void)
{
    auto now = std::chrono::system_clock::now();
    uint64_t seed = static_cast<uint64_t>(now.time_since_epoch().count())
                  ^ static_cast<uint64_t>(getpid());
    std::default_random_engine gen(seed);
    return gen;
}

std::default_random_engine __generator = initalize_generator();
