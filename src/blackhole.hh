// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_BLACKHOLE_HH
#define IP2UNIX_BLACKHOLE_HH

#include "socketpath.hh"

#include <optional>
#include <string>

struct BlackHole
{
    BlackHole();
    ~BlackHole();

    inline std::optional<SocketPath> get_path() const {
        if (!this->filepath) return std::nullopt;
        return SocketPath(SocketPath::Type::FILESYSTEM, *this->filepath);
    }

    private:
        std::optional<std::string> tmpdir;
        std::optional<std::string> filepath;
};

#endif
