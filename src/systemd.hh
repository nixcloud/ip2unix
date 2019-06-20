// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SYSTEMD_HH
#define IP2UNIX_SYSTEMD_HH

#include "rules.hh"

namespace Systemd {
    using FdInfo = std::pair<int, bool>;

    void init(const std::vector<Rule>&);
    std::optional<std::pair<int, bool>> acquire_fdinfo_for_rulepos(size_t);
    bool has_fd(int);
}

#endif
