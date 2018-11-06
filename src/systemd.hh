// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SYSTEMD_HH
#define IP2UNIX_SYSTEMD_HH

namespace Systemd {
    void init(void);
    std::optional<int> get_fd_for_rule(const Rule&);
    bool has_fd(int);
}

#endif
