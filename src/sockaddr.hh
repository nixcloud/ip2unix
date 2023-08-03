// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKETADDR_HH
#define IP2UNIX_SOCKETADDR_HH

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>

struct sockaddr_in6;
struct sockaddr_in;

struct SockAddr
{
    SockAddr();
    SockAddr(const sockaddr*);

    static std::optional<SockAddr> unix(const std::string&);

    SockAddr copy(void) const;

    std::optional<std::string> get_host(void) const;
    bool set_host(const std::string&);
    bool set_host(const ucred&);
    bool set_host(const SockAddr&);

    bool set_random_host(void);

    std::optional<std::string> get_sockpath(void) const;

    std::optional<uint16_t> get_port(void) const;
    bool set_port(uint16_t);

    bool is_loopback(void) const;

    void apply_addr(struct sockaddr*, socklen_t*) const;

    inline socklen_t size() const {
        return this->inner_size;
    }

    inline std::optional<std::string> get_port_str(void) const {
        auto port = this->get_port();
        if (port)
            return std::to_string(port.value());
        return std::nullopt;
    }

    bool operator==(const SockAddr &other) const;
    std::size_t get_hash(void) const;

    void set_family(sa_family_t family);

    inline bool is_inet4(void) const {
        return this->inner.ss_family == AF_INET;
    }

    inline bool is_inet6(void) const {
        return this->inner.ss_family == AF_INET6;
    }

    inline bool is_unix(void) const {
        return this->inner.ss_family == AF_UNIX;
    }

    inline sockaddr *cast(void) {
        return reinterpret_cast<sockaddr*>(&this->inner);
    }

    inline const sockaddr *cast(void) const {
        return reinterpret_cast<const sockaddr*>(&this->inner);
    }

    private:
        sockaddr_storage inner;
        socklen_t inner_size;

        inline sockaddr_in *cast4(void) {
            return reinterpret_cast<sockaddr_in*>(&this->inner);
        }

        inline const sockaddr_in *cast4(void) const {
            return reinterpret_cast<const sockaddr_in*>(&this->inner);
        }

        inline sockaddr_in6 *cast6(void) {
            return reinterpret_cast<sockaddr_in6*>(&this->inner);
        }

        inline const sockaddr_in6 *cast6(void) const
        {
            return reinterpret_cast<const sockaddr_in6*>(&this->inner);
        }

        inline sockaddr_un *cast_un(void) {
            return reinterpret_cast<sockaddr_un*>(&this->inner);
        }

        inline const sockaddr_un *cast_un(void) const
        {
            return reinterpret_cast<const sockaddr_un*>(&this->inner);
        }
};

namespace std {
    template<> struct hash<SockAddr> {
        std::size_t operator()(const SockAddr &addr) const {
            return addr.get_hash();
        }
    };
}

#endif
