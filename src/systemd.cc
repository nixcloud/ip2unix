// SPDX-License-Identifier: LGPL-3.0-only
#include <cstring>
#include <unordered_map>
#include <queue>

#include "rules.hh"
#include "systemd.hh"
#include "logging.hh"

#define SD_LISTEN_FDS_START 3

static std::unordered_map<std::string, int> names;
static std::queue<int> fds;
static int fd_count = 0;

void Systemd::init(void)
{
    static bool fetch_done = false;

    if (!fetch_done) {
        const char *listen_fds = getenv("LISTEN_FDS");

        if (listen_fds == nullptr) {
            LOG(FATAL) << "No LISTEN_FDS environment variable set, but"
                       << " systemd socket activation is used in rules.";
            std::abort();
        }

        if (*listen_fds < '0' || *listen_fds > '9') {
            LOG(FATAL) << "Invalid value '" << listen_fds << "' for LISTEN_FDS"
                       << " environment variable.";
            std::abort();
        }

        if ((fd_count = atoi(listen_fds)) == 0) {
            LOG(FATAL) << "Needed at least one systemd socket file descriptor,"
                       << " but found zero.";
            std::abort();
        }

        LOG(INFO) << "Number of systemd file descriptors found in LISTEN_FDS: "
                  << fd_count;

        const char *listen_fdnames = getenv("LISTEN_FDNAMES");

        for (int i = 0; i < fd_count; ++i) {
            if (listen_fdnames != nullptr) {
                const char *delim = strchr(listen_fdnames, ':');
                std::string name;
                if (delim == nullptr) {
                    name = listen_fdnames;
                } else {
                    using lentype = std::string::size_type;
                    lentype len = static_cast<lentype>(delim - listen_fdnames);
                    name = std::string(listen_fdnames, len);
                    listen_fdnames = delim + 1;
                }
                LOG(DEBUG) << "Got systemd file descriptor named '" << name
                           << "' (" << SD_LISTEN_FDS_START + i << ").";
                names[name] = SD_LISTEN_FDS_START + i;
            }

            fds.push(SD_LISTEN_FDS_START + i);
        }

        fetch_done = true;
        LOG(DEBUG) << "Finished getting systemd file descriptors.";
    }
}

/*
 * Get a systemd socket file descriptor for the given rule either via name if
 * fd_name is set or just the next file descriptor available.
 */
std::optional<int> Systemd::get_fd_for_rule(const Rule &rule)
{
    if (rule.fd_name) {
        auto found = names.find(rule.fd_name.value());
        if (found == names.end()) {
            LOG(FATAL) << "Can't get systemd socket for '"
                       << rule.fd_name.value() << "'.";
            std::abort();
        }
        return found->second;
    }

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
