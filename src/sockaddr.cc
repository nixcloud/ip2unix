// SPDX-License-Identifier: LGPL-3.0-only
#include <cstring>
#include <stdexcept>
#include <optional>

#include <arpa/inet.h>

#include "sockaddr.hh"

SockAddr::SockAddr()
{
    memset(this, 0, sizeof(sockaddr_storage));
}

SockAddr::SockAddr(const sockaddr *addr)
    : SockAddr()
{
    memcpy(this, addr, sizeof(sockaddr_storage));
}

std::optional<SockAddr> SockAddr::create(const std::string &addr,
                                         uint16_t port,
                                         sa_family_t family)
{
    SockAddr sa;
    if (family != AF_INET && family != AF_INET6)
        return std::nullopt;
    sa.ss_family = family;
    if (!sa.set_host(addr))
        return std::nullopt;
    if (!sa.set_port(port))
        return std::nullopt;

    return sa;
}

std::optional<std::string> SockAddr::get_host(void) const
{
    if (this->ss_family == AF_INET) {
        const sockaddr_in *addr = reinterpret_cast<const sockaddr_in*>(this);
        char buf[INET_ADDRSTRLEN];

        if (inet_ntop(addr->sin_family, &addr->sin_addr, buf,
                      INET_ADDRSTRLEN) != nullptr)
            return std::string(buf);
    } else if (this->ss_family == AF_INET6) {
        const sockaddr_in6 *addr = reinterpret_cast<const sockaddr_in6*>(this);
        char buf[INET6_ADDRSTRLEN];

        if (inet_ntop(addr->sin6_family, &addr->sin6_addr, buf,
                      INET6_ADDRSTRLEN) != nullptr)
            return std::string(buf);
    }

    return std::nullopt;
}

bool SockAddr::set_host(const std::string &host)
{
    if (this->ss_family == AF_INET) {
        sockaddr_in *addr = reinterpret_cast<struct sockaddr_in*>(this);
        if (inet_pton(AF_INET, host.c_str(), &addr->sin_addr.s_addr) != 1)
            return false;
    } else if (this->ss_family == AF_INET6) {
        sockaddr_in6 *addr = reinterpret_cast<struct sockaddr_in6*>(this);
        if (inet_pton(AF_INET6, host.c_str(), &addr->sin6_addr.s6_addr) != 1)
            return false;
    } else {
        return false;
    }

    return true;
}

std::optional<uint16_t> SockAddr::get_port(void) const
{
    if (this->ss_family == AF_INET)
        return htons(reinterpret_cast<const sockaddr_in*>(this)->sin_port);
    else if (this->ss_family == AF_INET6)
        return htons(reinterpret_cast<const sockaddr_in6*>(this)->sin6_port);
    else
        return std::nullopt;
}

bool SockAddr::set_port(uint16_t port)
{
    if (this->ss_family == AF_INET)
        reinterpret_cast<sockaddr_in*>(this)->sin_port = htons(port);
    else if(this->ss_family == AF_INET6)
        reinterpret_cast<sockaddr_in6*>(this)->sin6_port = htons(port);
    else
        return false;

    return true;
}

void SockAddr::apply_addr(struct sockaddr *addr, socklen_t *addrlen) const
{
    if (this->ss_family == AF_INET)
        *addrlen = sizeof(sockaddr_in);
    else if (this->ss_family == AF_INET)
        *addrlen = sizeof(sockaddr_in6);
    else
        return;

    memcpy(addr, this, *addrlen);
}
