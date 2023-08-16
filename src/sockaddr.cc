// SPDX-License-Identifier: LGPL-3.0-only
#include "sockaddr.hh"

#include "rng.hh"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <optional>
#include <sstream>

#include <arpa/inet.h>
#include <netinet/in.h>

static inline socklen_t family2size(sa_family_t family) {
    switch (family) {
        case AF_INET: return sizeof(sockaddr_in);
        case AF_INET6: return sizeof(sockaddr_in6);
        case AF_UNIX: return sizeof(sockaddr_un);
        default: return sizeof(sockaddr_storage);
    }
}

SockAddr::SockAddr()
    : inner({})
    , inner_size(sizeof(sockaddr_storage))
{
}

SockAddr::SockAddr(const sockaddr *addr)
    : inner({})
    , inner_size(family2size(addr->sa_family))
{
    memcpy(&this->inner, addr, this->inner_size);
}

void SockAddr::set_family(sa_family_t family)
{
    this->inner.ss_family = family;
    this->inner_size = family2size(family);
}

std::optional<SockAddr> SockAddr::unix(const SocketPath &path)
{
    struct sockaddr_un ua;
    memset(&ua, 0, sizeof ua);
    ua.sun_family = AF_UNIX;

    if (path.value.size() >= sizeof(ua.sun_path))
        return std::nullopt;

    switch (path.type) {
        case SocketPath::Type::FILESYSTEM:
            strncpy(ua.sun_path, path.value.c_str(), sizeof(ua.sun_path) - 1);
            return SockAddr(reinterpret_cast<const sockaddr*>(&ua));
#ifdef ABSTRACT_SUPPORT
        case SocketPath::Type::ABSTRACT:
            ua.sun_path[0] = '\0';
            memcpy(ua.sun_path + 1, path.value.c_str(), path.value.size());

            SockAddr sa(reinterpret_cast<const sockaddr*>(&ua));
            sa.inner_size = sizeof(sa_family_t) + path.value.size() + 1;
            return sa;
#endif
    }

    return std::nullopt;
}

SockAddr SockAddr::copy() const
{
    SockAddr sa(reinterpret_cast<const sockaddr*>(&this->inner));
    sa.inner_size = this->inner_size;
    return sa;
}

std::optional<std::string> SockAddr::get_host(void) const
{
    if (this->is_inet4()) {
        const sockaddr_in *addr = this->cast4();
        char buf[INET_ADDRSTRLEN];

        if (inet_ntop(addr->sin_family, &addr->sin_addr, buf,
                      INET_ADDRSTRLEN) != nullptr)
            return std::string(buf);
    } else if (this->is_inet6()) {
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
    if (this->is_inet4()) {
        sockaddr_in *addr = this->cast4();
        if (inet_pton(AF_INET, host.c_str(), &addr->sin_addr.s_addr) != 1)
            return false;
    } else if (this->is_inet6()) {
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
    if (this->is_inet4() && other.is_inet4()) {
        memcpy(&this->cast4()->sin_addr, &other.cast4()->sin_addr,
               sizeof(in_addr));
        return true;
    }

    if (this->is_inet6() && other.is_inet6()) {
        memcpy(&this->cast6()->sin6_addr, &other.cast6()->sin6_addr,
               sizeof(in6_addr));
        return true;
    }

    return false;
}

bool SockAddr::set_host(const ucred &peercred)
{
    if (this->is_inet4()) {
        this->cast4()->sin_addr.s_addr =
            htonl(static_cast<uint32_t>(peercred.pid));
        return true;
    }

    if (this->is_inet6()) {
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
    if (this->is_inet4()) {
        this->cast4()->sin_addr.s_addr =
            htonl(RNG::get<uint32_t>(0, 0x00ffffff));
        return true;
    }

    if (this->is_inet6()) {
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

std::optional<SocketPath> SockAddr::get_sockpath(void) const
{
    if (this->is_unix()) {
        return SocketPath(
            SocketPath::Type::FILESYSTEM,
            std::string(this->cast_un()->sun_path)
        );
    }

    return std::nullopt;
}

std::optional<uint16_t> SockAddr::get_port(void) const
{
    if (this->is_inet4())
        return ntohs(this->cast4()->sin_port);
    if (this->is_inet6())
        return ntohs(this->cast6()->sin6_port);
    return std::nullopt;
}

bool SockAddr::set_port(uint16_t port)
{
    if (this->is_inet4())
        this->cast4()->sin_port = htons(port);
    else if (this->is_inet6())
        this->cast6()->sin6_port = htons(port);
    else
        return false;

    return true;
}

bool SockAddr::is_loopback(void) const
{
    if (this->is_inet4()) {
        return (ntohl(this->cast4()->sin_addr.s_addr) & 0xff000000)
               >> 24 == 127;
    }

    if (this->is_inet6())
        return IN6_IS_ADDR_LOOPBACK(&this->cast6()->sin6_addr);

    return false;
}

void SockAddr::apply_addr(struct sockaddr *addr, socklen_t *addrlen) const
{
    if (addr == nullptr || addrlen == nullptr)
        return;

    *addrlen = this->size();
    memcpy(addr, &this->inner, *addrlen);
}

bool SockAddr::operator==(const SockAddr &other) const
{
    if (this->inner.ss_family != other.inner.ss_family)
        return false;

    if (this->is_inet4()) {
        const sockaddr_in *addr = this->cast4();
        const sockaddr_in *othr = other.cast4();
        return addr->sin_port == othr->sin_port
            && addr->sin_addr.s_addr == othr->sin_addr.s_addr;
    }

    if (this->is_inet6()) {
        const sockaddr_in6 *addr = this->cast6();
        const sockaddr_in6 *othr = other.cast6();
        if (!std::equal(std::begin(addr->sin6_addr.s6_addr),
                        std::end(addr->sin6_addr.s6_addr),
                        std::begin(othr->sin6_addr.s6_addr)))
            return false;
        return addr->sin6_port == othr->sin6_port;
    }

    if (this->is_unix()) {
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
    hashprep << this->inner.ss_family;

    if (this->is_inet4()) {
        const sockaddr_in *addr = this->cast4();
        hashprep << '|' << addr->sin_port;
        hashprep << '|' << addr->sin_addr.s_addr;
    } else if (this->is_inet6()) {
        const sockaddr_in6 *addr = this->cast6();
        hashprep << '|' << addr->sin6_port;
        hashprep << '|';
        for (const unsigned char &comp : addr->sin6_addr.s6_addr)
            hashprep << comp;
    } else if (this->is_unix()) {
        const sockaddr_un *addr = this->cast_un();
        hashprep << '|' << std::string(addr->sun_path);
    }

    return std::hash<std::string>{}(hashprep.str());
}
