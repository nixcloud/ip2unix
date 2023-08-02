// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKETADDR_HH
#define IP2UNIX_SOCKETADDR_HH
#include <netinet/in.h>
#include <sys/un.h>
#include <stdint.h>
#include <sys/socket.h>
#include <optional>
#include <string>
#include <variant>
#include <cstddef>
#include <utility>

struct sockaddr_in6;
struct sockaddr_in;

struct SockAddr : public sockaddr_storage
{
    SockAddr();
    SockAddr(const sockaddr*);

    static std::optional<SockAddr> create(const std::string&, uint16_t,
                                          sa_family_t = AF_INET);

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
    socklen_t size() const;

    inline std::optional<std::string> get_port_str(void) const {
        auto port = this->get_port();
        if (port)
            return std::to_string(port.value());
        return std::nullopt;
    }

    bool operator==(const SockAddr &other) const;
    std::size_t get_hash(void) const;

    inline sockaddr *cast(void) {
        return reinterpret_cast<sockaddr*>(this);
    }

    inline const sockaddr *cast(void) const {
        return reinterpret_cast<const sockaddr*>(this);
    }

    private:
        inline sockaddr_in *cast4(void) {
            return reinterpret_cast<sockaddr_in*>(this);
        }

        inline const sockaddr_in *cast4(void) const {
            return reinterpret_cast<const sockaddr_in*>(this);
        }

        inline sockaddr_in6 *cast6(void) {
            return reinterpret_cast<sockaddr_in6*>(this);
        }

        inline const sockaddr_in6 *cast6(void) const
        {
            return reinterpret_cast<const sockaddr_in6*>(this);
        }

        inline sockaddr_un *cast_un(void) {
            return reinterpret_cast<sockaddr_un*>(this);
        }

        inline const sockaddr_un *cast_un(void) const
        {
            return reinterpret_cast<const sockaddr_un*>(this);
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
