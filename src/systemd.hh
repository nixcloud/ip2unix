// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SYSTEMD_HH
#define IP2UNIX_SYSTEMD_HH

#include "rules.hh"

namespace Systemd {
    void init(const std::vector<Rule>&);
    std::optional<int> acquire_fd_for_rulepos(size_t);
    bool has_fd(int);
}

#endif
