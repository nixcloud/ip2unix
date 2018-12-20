// SPDX-License-Identifier: LGPL-3.0-only
#include <cstring>
#include <unordered_map>
#include <queue>

#include <systemd/sd-daemon.h>

#include "rules.hh"
#include "systemd.hh"
#include "logging.hh"

static std::unordered_map<std::string, int> names;
static std::queue<int> fds;
static int fd_count;

void Systemd::init(void)
{
    static bool fetch_done = false;

    if (!fetch_done) {
        char **raw_names = nullptr;
#ifdef NO_FDNAMES
        fd_count = sd_listen_fds(1);
#else
        fd_count = sd_listen_fds_with_names(1, &raw_names);
#endif
        if (fd_count < 0) {
            LOG(FATAL) << "Unable to get systemd sockets: " << strerror(errno);
            std::abort();
        } else if (fd_count == 0) {
            LOG(FATAL) << "Needed at least one systemd socket file descriptor,"
                       << " but found zero.";
            std::abort();
        }
        for (int i = 0; i < fd_count; ++i) {
#ifdef NO_FDNAMES
            fds.push(SD_LISTEN_FDS_START + i);
#else
            std::string name = raw_names[i];
            if (name.empty() || name == "unknown" || name == "stored")
                fds.push(SD_LISTEN_FDS_START + i);
            else
                names[name] = SD_LISTEN_FDS_START + i;
#endif
        }
        if (raw_names != nullptr)
            free(raw_names);
        fetch_done = true;
    }
}

/*
 * Get a systemd socket file descriptor for the given rule either via name if
 * fd_name is set or just the next file descriptor available.
 */
std::optional<int> Systemd::get_fd_for_rule(const Rule &rule)
{
#ifndef NO_FDNAMES
    if (rule.fd_name) {
        auto found = names.find(rule.fd_name.value());
        if (found == names.end()) {
            LOG(FATAL) << "Can't get systemd socket for '"
                       << rule.fd_name.value() << "'.";
            std::abort();
        }
        return found->second;
    }
#else
    std::ignore = rule;
#endif
    if (fds.empty())
        return std::nullopt;

    int fd = fds.front();
    fds.pop();
    return fd;
}

/* Check whether the given file descriptor is passed by systemd. */
bool Systemd::has_fd(int fd)
{
    return fd >= SD_LISTEN_FDS_START && fd < SD_LISTEN_FDS_START + fd_count;
}
