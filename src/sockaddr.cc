// SPDX-License-Identifier: LGPL-3.0-only
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <optional>
#include <sstream>
#include <algorithm>
#include <iterator>

#include "sockaddr.hh"
#include "rng.hh"

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

std::optional<SockAddr> SockAddr::unix(const std::string &path)
{
    struct sockaddr_un ua;
    memset(&ua, 0, sizeof ua);
    ua.sun_family = AF_UNIX;
    if (path.size() >= sizeof(ua.sun_path))
        return std::nullopt;

    strncpy(ua.sun_path, path.c_str(), sizeof(ua.sun_path) - 1);
    return SockAddr(reinterpret_cast<const sockaddr*>(&ua));
}

SockAddr SockAddr::copy() const
{
    SockAddr sa(reinterpret_cast<const sockaddr*>(this));
    return sa;
}

std::optional<std::string> SockAddr::get_host(void) const
{
    if (this->ss_family == AF_INET) {
        const sockaddr_in *addr = this->cast4();
        char buf[INET_ADDRSTRLEN];

        if (inet_ntop(addr->sin_family, &addr->sin_addr, buf,
                      INET_ADDRSTRLEN) != nullptr)
            return std::string(buf);
    } else if (this->ss_family == AF_INET6) {
        const sockaddr_in6 *addr = this->cast6();
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
        sockaddr_in *addr = this->cast4();
        if (inet_pton(AF_INET, host.c_str(), &addr->sin_addr.s_addr) != 1)
            return false;
    } else if (this->ss_family == AF_INET6) {
        sockaddr_in6 *addr = this->cast6();
        if (inet_pton(AF_INET6, host.c_str(), &addr->sin6_addr.s6_addr) != 1)
            return false;
    } else {
        return false;
    }

    return true;
}

bool SockAddr::set_host(const SockAddr &other)
{
    if (this->ss_family == AF_INET && other.ss_family == AF_INET) {
        memcpy(&this->cast4()->sin_addr, &other.cast4()->sin_addr,
               sizeof(in_addr));
        return true;
    } else if (this->ss_family == AF_INET6 && other.ss_family == AF_INET6) {
        memcpy(&this->cast6()->sin6_addr, &other.cast6()->sin6_addr,
               sizeof(in6_addr));
        return true;
    } else {
        return false;
    }
}

bool SockAddr::set_host(const ucred &peercred)
{
    if (this->ss_family == AF_INET) {
        this->cast4()->sin_addr.s_addr =
            htonl(static_cast<uint32_t>(peercred.pid));
        return true;
    } else if (this->ss_family == AF_INET6) {
        sockaddr_in6 *addr = this->cast6();
        addr->sin6_addr.s6_addr[0] = 0xfe;
        addr->sin6_addr.s6_addr[1] = 0x80;
        addr->sin6_addr.s6_addr[2] = 0x00;
        addr->sin6_addr.s6_addr[3] = 0x00;
        uint32_t part = htonl(static_cast<uint32_t>(peercred.uid));
        memcpy(addr->sin6_addr.s6_addr + 4, &part, 4);
        part = htonl(static_cast<uint32_t>(peercred.gid));
        memcpy(addr->sin6_addr.s6_addr + 8, &part, 4);
        part = htonl(static_cast<uint32_t>(peercred.pid));
        memcpy(addr->sin6_addr.s6_addr + 12, &part, 4);
        return true;
    }
    return false;
}

bool SockAddr::set_random_host(void)
{
    if (this->ss_family == AF_INET) {
        this->cast4()->sin_addr.s_addr =
            htonl(RNG::get<uint32_t>(0, 0x00ffffff));
        return true;
    } else if (this->ss_family == AF_INET6) {
        sockaddr_in6 *addr = this->cast6();
        addr->sin6_addr.s6_addr[0] = 0xfe;
        addr->sin6_addr.s6_addr[1] = 0x80;
        addr->sin6_addr.s6_addr[2] = 0x00;
        addr->sin6_addr.s6_addr[3] = 0x00;
        memset(addr->sin6_addr.s6_addr + 4, 0, 8);
        uint32_t randsuf = htonl(RNG::get<uint32_t>(0, 0xffffffff));
        memcpy(addr->sin6_addr.s6_addr + 12, &randsuf, 4);
        return true;
    }

    return false;
}

std::optional<std::string> SockAddr::get_sockpath(void) const
{
    if (this->ss_family == AF_UNIX) {
        return std::string(this->cast_un()->sun_path);
    }

    return std::nullopt;
}

std::optional<uint16_t> SockAddr::get_port(void) const
{
    if (this->ss_family == AF_INET)
        return ntohs(this->cast4()->sin_port);
    else if (this->ss_family == AF_INET6)
        return ntohs(this->cast6()->sin6_port);
    else
        return std::nullopt;
}

bool SockAddr::set_port(uint16_t port)
{
    if (this->ss_family == AF_INET)
        this->cast4()->sin_port = htons(port);
    else if(this->ss_family == AF_INET6)
        this->cast6()->sin6_port = htons(port);
    else
        return false;

    return true;
}

bool SockAddr::is_loopback(void) const
{
    if (this->ss_family == AF_INET) {
        return (ntohl(this->cast4()->sin_addr.s_addr) & 0xff000000)
               >> 24 == 127;
    } else if (this->ss_family == AF_INET6) {
        return IN6_IS_ADDR_LOOPBACK(&this->cast6()->sin6_addr);
    } else {
        return false;
    }
}

void SockAddr::apply_addr(struct sockaddr *addr, socklen_t *addrlen) const
{
    if (addr == nullptr || addrlen == nullptr)
        return;

    *addrlen = this->size();
    memcpy(addr, this, *addrlen);
}

socklen_t SockAddr::size() const
{
    if (this->ss_family == AF_INET)
        return sizeof(sockaddr_in);
    else if (this->ss_family == AF_INET6)
        return sizeof(sockaddr_in6);
    else if (this->ss_family == AF_UNIX)
        return sizeof(sockaddr_un);
    else
        return sizeof(sockaddr_storage);
}

bool SockAddr::operator==(const SockAddr &other) const
{
    if (this->ss_family != other.ss_family)
        return false;

    if (this->ss_family == AF_INET) {
        const sockaddr_in *addr = this->cast4();
        const sockaddr_in *othr = other.cast4();
        return addr->sin_port == othr->sin_port
            && addr->sin_addr.s_addr == othr->sin_addr.s_addr;
    } else if (this->ss_family == AF_INET6) {
        const sockaddr_in6 *addr = this->cast6();
        const sockaddr_in6 *othr = other.cast6();
        if (!std::equal(std::begin(addr->sin6_addr.s6_addr),
                        std::end(addr->sin6_addr.s6_addr),
                        std::begin(othr->sin6_addr.s6_addr)))
            return false;
        return addr->sin6_port == othr->sin6_port;
    } else if (this->ss_family == AF_UNIX) {
        const sockaddr_un *addr = this->cast_un();
        const sockaddr_un *othr = other.cast_un();
        return std::string(addr->sun_path) == std::string(othr->sun_path);
    }

    return false;
}

std::size_t SockAddr::get_hash(void) const
{
    // XXX: This function is pretty slow and dumb, but at least accurate.
    std::ostringstream hashprep;
    hashprep << this->ss_family;

    if (this->ss_family == AF_INET) {
        const sockaddr_in *addr = this->cast4();
        hashprep << '|' << addr->sin_port;
        hashprep << '|' << addr->sin_addr.s_addr;
    } else if (this->ss_family == AF_INET6) {
        const sockaddr_in6 *addr = this->cast6();
        hashprep << '|' << addr->sin6_port;
        hashprep << '|';
        for (const unsigned char &comp : addr->sin6_addr.s6_addr)
            hashprep << comp;
    } else if (this->ss_family == AF_UNIX) {
        const sockaddr_un *addr = this->cast_un();
        hashprep << '|' << std::string(addr->sun_path);
    }

    return std::hash<std::string>{}(hashprep.str());
}
