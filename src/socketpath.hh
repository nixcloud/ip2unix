// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SOCKPATH_HH
#define IP2UNIX_SOCKPATH_HH

#include <string>

struct SocketPath {
    enum class Type { ABSTRACT, FILESYSTEM };

    inline SocketPath() : type(Type::FILESYSTEM), value() {}
    inline SocketPath(Type t, const std::string &v) : type(t), value(v) {}

    inline bool operator==(const SocketPath &other) const {
        return this->type == other.type && this->value == other.value;
    }

    inline bool operator!=(const SocketPath &other) const {
        return this->type != other.type || this->value != other.value;
    }

    inline bool is_real_file() const {
        return this->type == Type::FILESYSTEM;
    }

    Type type;
    std::string value;
};

namespace std {
    template<> struct hash<SocketPath> {
        std::size_t operator()(const SocketPath &addr) const {
            return std::hash<std::string>()(addr.value); // TODO
        }
    };
}

#endif
