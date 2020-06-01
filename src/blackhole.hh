// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_BLACKHOLE_HH
#define IP2UNIX_BLACKHOLE_HH

#include <optional>
#include <string>

struct BlackHole
{
    BlackHole();
    ~BlackHole();

    inline const std::optional<std::string> get_path() const {
        return this->filepath;
    }

    private:
        std::optional<std::string> tmpdir;
        std::optional<std::string> filepath;
};

#endif
