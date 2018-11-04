// SPDX-License-Identifier: LGPL-3.0-only
#include <cstdio>
#include <fcntl.h>
#include <sys/ioctl.h>

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

void SockOpts::cache_ioctl(unsigned long request, const void *arg)
{
    size_t len;

    switch (request) {
        case SIOCSPGRP: len = sizeof(pid_t); break;
        case FIOASYNC: len = sizeof(int); break;
        default: return;
    }

    std::vector<uint8_t> argcopy((uint8_t*)arg,
                                 (uint8_t*)arg + len);
    SockOpts::EntryIoctl entry{request, argcopy};
    this->entries.push(entry);
}

static bool copy_fd_owner(int old_sockfd, int new_sockfd)
{
    f_owner_ex owner;

    if (fcntl(old_sockfd, F_GETOWN_EX, &owner) == -1) {
        perror("fcntl(F_GETOWN_EX)");
        return false;
    }

    if (fcntl(new_sockfd, F_SETOWN_EX, &owner) == -1) {
        perror("fcntl(F_SETOWN_EX)");
        return false;
    }

    return true;
}

static bool copy_fcntl(int old_sockfd, int new_sockfd, int get, int set)
{
    int value;

    if ((value = fcntl(old_sockfd, get)) == -1) {
        perror("fcntl");
        return false;
    }

    if (fcntl(new_sockfd, set, value) == -1) {
        perror("fcntl");
        return false;
    }

    return true;
}

/*
 * Set all the socket options and file descriptor flags from old_sockfd to
 * new_sockfd.
 */
bool SockOpts::replay(int old_sockfd, int new_sockfd)
{
    struct replay_entry {
        replay_entry(int filedes) : fd(filedes) {}

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
            if (real::ioctl(this->fd, entry.request, entry.arg.data()) == -1) {
                perror("ioctl");
                return false;
            }

            return true;
        }

        private: int fd;
    };

    if (!copy_fcntl(old_sockfd, new_sockfd, F_GETFD, F_SETFD))
        return false;
    if (!copy_fcntl(old_sockfd, new_sockfd, F_GETFL, F_SETFL))
        return false;
    if (!copy_fcntl(old_sockfd, new_sockfd, F_GETSIG, F_SETSIG))
        return false;
    if (!copy_fd_owner(old_sockfd, new_sockfd))
        return false;

    while (!this->entries.empty()) {
        auto current = this->entries.front();

        if (!std::visit(replay_entry(new_sockfd), current))
            return false;

        this->entries.pop();
    }

    return true;
}
