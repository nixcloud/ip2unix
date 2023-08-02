// SPDX-License-Identifier: LGPL-3.0-only
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <algorithm>
#include <cstdlib>
#include <string>
#include <utility>

#include "rules.hh"
#include "systemd.hh"
#include "logging.hh"
#include "serial.hh"

#define SD_LISTEN_FDS_START 3

static std::unordered_map<size_t, Systemd::FdInfo> fdmap;
static std::deque<Systemd::FdInfo> fdinfos;
static std::unordered_set<int> all_fds;

/* Fetch a colon-separated environment variable and split it into a vector. */
static std::vector<std::string> get_env_vector(const char *name)
{
    const char *ptr;
    std::vector<std::string> result;

    const char *value = getenv(name);

    if (value == nullptr || *value == '\0')
        return result;

    LOG(DEBUG) << "Splitting value of " << name << ": " << value;

    while ((ptr = strchr(value, ':')) != nullptr) {
        using lentype = std::string::size_type;
        lentype len = static_cast<lentype>(ptr - value);
        std::string elem(value, len);
        LOG(DEBUG) << "Got element '" << elem << "' from " << name << '.';
        result.push_back(std::string(value, len));
        value = ptr + 1;
    }

    LOG(DEBUG) << "Got last element '" << value << "' from " << name << '.';
    result.push_back(std::string(value));
    return result;
}

static std::string join(const std::string &delim,
                        const std::vector<std::string> &chunks)
{
    std::string result;

    for (const std::string &chunk : chunks) {
        if (!result.empty())
            result += delim;
        result += chunk;
    }

    return result;
}

/*
 * Check whether the given socket file descriptor is an inet socket.
 *
 * This is important later, because we want to make sure that socket functions
 * will only fake/alter peer addresses if the socket is AF_UNIX.
 */
static bool socket_is_inet(int fd)
{
    int sotype;
    bool result = true;
    socklen_t len = sizeof(int);

    int old_errno = errno;
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &sotype, &len) == -1)
        LOG(WARNING) << "Unable to determine socket type from file descriptor "
                     << fd << " passed by systemd: " << strerror(errno);
    else
        result = sotype == AF_INET || sotype == AF_INET6;
    errno = old_errno;

    return result;
}

/*
 * Update the bookkeeping environment variables needed to associate systemd
 * socket file descriptors to rules.
 */
static void update_env(void)
{
    int ret;

    std::string fdval = serialise(fdinfos);

    LOG(DEBUG) << "Setting __IP2UNIX_SYSTEMD_FDS to '"
               << fdval << "'.";

    ret = setenv("__IP2UNIX_SYSTEMD_FDS", fdval.c_str(), 1);
    if (ret == -1) {
        LOG(FATAL) << "Unable to set __IP2UNIX_SYSTEMD_FDS: "
                   << strerror(errno);
        std::abort();
    }

    std::string fdmapval = serialise(fdmap);
    LOG(DEBUG) << "Setting __IP2UNIX_SYSTEMD_FDMAP to '"
               << fdmapval << "'.";

    ret = setenv("__IP2UNIX_SYSTEMD_FDMAP", fdmapval.c_str(), 1);
    if (ret == -1) {
        LOG(FATAL) << "Unable to set __IP2UNIX_SYSTEMD_FDMAP: "
                   << strerror(errno);
        std::abort();
    }
}

/*
 * Reinitialises the data structures from previous values written by
 * update_env().
 */
static bool init_from_env(void)
{
    MaybeError err;
    const char *fds_raw = getenv("__IP2UNIX_SYSTEMD_FDS");
    const char *fdmap_raw = getenv("__IP2UNIX_SYSTEMD_FDMAP");

    if (fds_raw == nullptr || fdmap_raw == nullptr)
        return false;

    if ((err = deserialise(std::string(fds_raw), &fdinfos))) {
        LOG(FATAL) << "Unable to deserialise __IP2UNIX_SYSTEMD_FDS: "
                   << *err;
        std::abort();
    }

    if ((err = deserialise(std::string(fdmap_raw), &fdmap))) {
        LOG(FATAL) << "Unable to deserialise __IP2UNIX_SYSTEMD_FDMAP: "
                   << *err;
        std::abort();
    }

    LOG(INFO) << "Reinitialising systemd file descriptors from internal"
              << " __IP2UNIX_SYSTEMD_FD* variables.";

    for (const std::pair<const size_t, Systemd::FdInfo> &item : fdmap) {
        LOG(DEBUG) << "Got systemd file descriptor " << item.second.fd
                   << " connected to rule #" << item.first << '.';
        all_fds.insert(item.second.fd);
    }

    for (const Systemd::FdInfo &fdinfo : fdinfos) {
        LOG(DEBUG) << "Got systemd file descriptor " << fdinfo.fd << '.';
        all_fds.insert(fdinfo.fd);
    }

    return true;
}

void Systemd::init(const std::vector<Rule> &rules)
{
    static bool fetch_done = false;

    if (!fetch_done) {
        if (init_from_env()) {
            fetch_done = true;
            return;
        }

        size_t fd_count;
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

        if ((fd_count = strtoul(listen_fds, nullptr, 10)) == 0) {
            LOG(FATAL) << "Needed at least one systemd socket file descriptor,"
                       << " but found zero.";
            std::abort();
        }

        LOG(INFO) << "Number of systemd file descriptors found in LISTEN_FDS: "
                  << fd_count;

        std::vector<std::string> fdnames = get_env_vector("LISTEN_FDNAMES");
        size_t fdnames_size = fdnames.size();

        if (fdnames_size > 0 && fdnames_size != fd_count) {
            LOG(WARNING) << "Mismatch between " << fdnames_size
                         << " element(s) in LISTEN_FDNAMES ("
                         << join(", ", fdnames) << ") and " << fd_count
                         << " LISTEN_FDS.";
        }

        std::unordered_set<int> avail_fds;
        for (size_t i = 0; i < fd_count; ++i) {
            int fd = SD_LISTEN_FDS_START + i;
            avail_fds.insert(fd);
            all_fds.insert(fd);
        }

        size_t rulepos = 0;
        for (const Rule &rule : rules) {
            if (!rule.socket_activation || !rule.fd_name) {
                rulepos++;
                continue;
            }

            size_t elems = std::min(fdnames_size, fd_count);
            for (size_t i = 0; i < elems; ++i) {
                int fd = SD_LISTEN_FDS_START + i;

                if (fdnames[i] == *rule.fd_name) {
                    bool is_inet = socket_is_inet(fd);
                    LOG(DEBUG) << "Matched systemd "
                               << (is_inet ? "inet" : "unix")
                               << " file descriptor name '"
                               << fdnames[i] << "' (fd " << fd << ")"
                               << " with rule #" << rulepos << '.';
                    Systemd::FdInfo fdinfo = { fd, is_inet };
                    fdmap[rulepos] = fdinfo;
                    avail_fds.erase(fd);
                    continue;
                }
            }

            rulepos++;
        }

        for (const int &fd : avail_fds) {
            bool is_inet = socket_is_inet(fd);
            LOG(DEBUG) << "Adding unnamed systemd "
                       << (is_inet ? "inet" : "unix")
                       << " file descriptor "
                       << fd << " to pool.";
            Systemd::FdInfo fdinfo = { fd, is_inet };
            fdinfos.push_front(fdinfo);
        }

        update_env();

        if (unsetenv("LISTEN_FDNAMES") == -1) {
            LOG(FATAL) << "Unable to unset LISTEN_FDNAMES: "
                       << strerror(errno);
            std::abort();
        }

        if (unsetenv("LISTEN_FDS") == -1) {
            LOG(FATAL) << "Unable to unset LISTEN_FDS: "
                       << strerror(errno);
            std::abort();
        }

        fetch_done = true;
        LOG(DEBUG) << "Finished getting systemd file descriptors.";
    }
}

/* Remove the file descriptor and set the FD_CLOEXEC flag. */
static void remove_fd(int fd)
{
    int old_flags, flags;

    LOG(INFO) << "Disassociating systemd file descriptor " << fd << ".";

    all_fds.erase(fd);
    update_env();

    int old_errno = errno;

    if ((old_flags = fcntl(fd, F_GETFD, 0)) == -1) {
        LOG(WARNING) << "Can't query flags for fd " << fd
                     << ": " << strerror(errno);
        old_flags = 0;
    }

    if (old_flags == (flags = old_flags | FD_CLOEXEC)) {
        errno = old_errno;
        return;
    }

    LOG(DEBUG) << "Setting new flags " << flags << " on fd " << fd
               << ", previos flags were " << old_flags << '.';

    if (fcntl(fd, F_SETFD, flags) == -1) {
        LOG(WARNING) << "Unable to set FD_CLOEXEC flag for fd " << fd
                     << ": " << strerror(errno);
    }

    errno = old_errno;
}

/*
 * Get a systemd socket file descriptor for the given rule either via name if
 * fd_name is set or just the next file descriptor available.
 */
std::optional<Systemd::FdInfo>
    Systemd::acquire_fdinfo_for_rulepos(size_t rulepos)
{
    using itype = decltype(fdmap)::const_iterator;
    itype found = fdmap.find(rulepos);

    if (found != fdmap.end()) {
        Systemd::FdInfo fdinfo = found->second;
        fdmap.erase(found);
        remove_fd(fdinfo.fd);
        return fdinfo;
    }

    if (fdinfos.empty())
        return std::nullopt;

    FdInfo fdinfo = fdinfos.front();
    fdinfos.pop_front();
    remove_fd(fdinfo.fd);
    return fdinfo;
}

/* Check whether the given file descriptor is passed by systemd. */
bool Systemd::has_fd(int fd)
{
    return all_fds.find(fd) != all_fds.end();
}
