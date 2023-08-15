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
            std::size_t hashval = std::hash<std::string>()(addr.value);
            switch (addr.type) {
                case SocketPath::Type::ABSTRACT:
                    hashval = ~hashval;
                    break;
                case SocketPath::Type::FILESYSTEM:
                    break;
            }
            return hashval;
        }
    };
}

#endif
