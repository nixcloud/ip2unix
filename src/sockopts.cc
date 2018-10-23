// SPDX-License-Identifier: LGPL-3.0-only
#include <cstdio>
#include <fcntl.h>

#include "realcalls.hh"
#include "sockopts.hh"

SockOpts::SockOpts() : entries() {}

void SockOpts::cache_sockopt(int lvl, int name, const void *val, socklen_t len)
{
    std::vector<uint8_t> valcopy((uint8_t*)val,
                                 (uint8_t*)val + len);
    SockOpts::EntrySockopt entry{lvl, name, valcopy};
    this->entries.push(entry);
}

void cache_ioctl(unsigned long request, ...)
{
}

/*
 * Set all the socket options and file descriptor flags from old_sockfd to
 * new_sockfd.
 */
bool SockOpts::replay(int old_sockfd, int new_sockfd)
{
    struct replay_entry {
        replay_entry(int fd) : fd(fd) {}

        bool operator()(const SockOpts::EntrySockopt &entry)
        {
            if (real::setsockopt(this->fd, entry.level, entry.optname,
                                 entry.optval.data(),
                                 entry.optval.size()) == -1) {
                perror("setsockopt");
                return false;
            }

            return true;
        }

        bool operator()(const SockOpts::EntryIoctl &entry)
        {
            return true;
        }

        private: int fd;
    };

    int fdflags, fdstatus;

    if ((fdflags = fcntl(old_sockfd, F_GETFD)) == -1) {
        perror("fcntl(F_GETFD)");
        return false;
    }

    if ((fdstatus = fcntl(old_sockfd, F_GETFL)) == -1) {
        perror("fcntl(F_GETFL)");
        return false;
    }

    if (fcntl(new_sockfd, F_SETFD, fdflags) == -1) {
        perror("fcntl(F_SETFD)");
        return false;
    }

    if (fcntl(new_sockfd, F_SETFL, fdstatus) == -1) {
        perror("fcntl(F_SETFL)");
        return false;
    }

    while (!this->entries.empty()) {
        auto current = this->entries.front();

        if (!std::visit(replay_entry(new_sockfd), current))
            return false;

        this->entries.pop();
    }

    return true;
}
