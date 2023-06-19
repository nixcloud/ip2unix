// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SYSTEMD_HH
#define IP2UNIX_SYSTEMD_HH

#include <stddef.h>
#include <optional>
#include <vector>

#include "rules.hh"

struct Rule;

namespace Systemd {
    struct FdInfo {
        int fd;
        bool is_inet;
    };

    void init(const std::vector<Rule>&);
    std::optional<FdInfo> acquire_fdinfo_for_rulepos(size_t);
    bool has_fd(int);
}

#endif
