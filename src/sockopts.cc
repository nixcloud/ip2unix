// SPDX-License-Identifier: LGPL-3.0-only
#include <fcntl.h>
#include <sys/ioctl.h>
#include <asm/sockios.h>
#include <errno.h>
#include <cstdio>
#include <cstring>

#include "realcalls.hh"
#include "sockopts.hh"
#include "logging.hh"

SockOpts::SockOpts() : entries() {}

void SockOpts::cache_sockopt(int lvl, int name, const void *val, socklen_t len)
{
    const uint8_t *value = reinterpret_cast<const uint8_t*>(val);
    std::vector<uint8_t> valcopy(value, value + len);
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

    const uint8_t *ioarg = reinterpret_cast<const uint8_t*>(arg);
    std::vector<uint8_t> argcopy(ioarg, ioarg + len);
    SockOpts::EntryIoctl entry{request, argcopy};
    this->entries.push(entry);
}

#ifdef HAS_EPOLL
void SockOpts::cache_epoll_ctl(int epfd, int op, struct epoll_event *event)
{
    std::optional<epoll_event> eventcopy;
    if (event != nullptr)
        eventcopy = *event;

    SockOpts::EntryEpollCtl entry{epfd, op, eventcopy};
    this->entries.push(entry);
}
#endif

static bool copy_fd_owner(int old_sockfd, int new_sockfd)
{
    f_owner_ex owner;

    if (fcntl(old_sockfd, F_GETOWN_EX, &owner) == -1) {
        LOG(ERROR) << "Failure to get owner settings of socket fd "
                   << old_sockfd << ": " << strerror(errno);
        return false;
    }

    if (fcntl(new_sockfd, F_SETOWN_EX, &owner) == -1) {
        LOG(ERROR) << "Failure to set owner settings on socket fd "
                   << new_sockfd << ": " << strerror(errno);
        return false;
    }

    return true;
}

static bool copy_fcntl(int old_sockfd, int new_sockfd, int get, int set)
{
    int value;

    if ((value = fcntl(old_sockfd, get)) == -1) {
        LOG(ERROR) << "Failure getting fcntl options from socket fd "
                   << old_sockfd << ": " << strerror(errno);
        return false;
    }

    if (fcntl(new_sockfd, set, value) == -1) {
        LOG(ERROR) << "Failure setting fcntl options for socket fd "
                   << new_sockfd << ": " << strerror(errno);
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
                LOG(WARNING) << "Failure replaying socket option "
                             << entry.optname << " with level "
                             << entry.level << " on socket fd " << this->fd
                             << ": " << strerror(errno);
                return false;
            }

            return true;
        }

        bool operator()(const SockOpts::EntryIoctl &entry)
        {
            if (real::ioctl(this->fd, entry.request, entry.arg.data()) == -1) {
                LOG(WARNING) << "Failure replaying ioctl "
                             << entry.request << " on socket fd " << this->fd
                             << ": " << strerror(errno);
                return false;
            }

            return true;
        }

#ifdef HAS_EPOLL
        bool operator()(const SockOpts::EntryEpollCtl &entry)
        {
            epoll_event *event = nullptr;

            if (entry.event)
                event = const_cast<epoll_event*>(&*entry.event);

            if (real::epoll_ctl(entry.epfd, entry.op, this->fd, event) == -1) {
                LOG(WARNING) << "Failure replaying epoll_ctl using fd "
                             << entry.epfd << " on socket fd " << this->fd
                             << " with operation " << entry.op
                             << ": " << strerror(errno);
                return false;
            }

            return true;
        }
#endif

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
