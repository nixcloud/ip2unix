// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_LOGGING_HH
#define IP2UNIX_LOGGING_HH

#include <optional>
#include <sstream>

/* A small helper so that we always get the basename of the file at compile
 * time instead of determining it at runtime.
 */
constexpr std::string_view just_filename(const char *path) {
    std::string_view tmp(path);
    std::string::size_type last_slash = tmp.rfind('/');
    if (last_slash == std::string::npos)
        return tmp;
    else
        return tmp.substr(last_slash + 1);
}

#define LOG(level) Logger(Verbosity::level, just_filename(__FILE__), \
                          __LINE__, __func__, #level)

enum class Verbosity { FATAL = 0, ERROR, WARNING, INFO, DEBUG, TRACE };

class Logger
{
    std::optional<std::ostringstream> logbuf;

    public:
        Logger(Verbosity, const std::string_view&, int, const char*,
               const char*);
        ~Logger();

        template <typename T>
        Logger &operator<<(T const &val) {
            if (this->logbuf)
                this->logbuf.value() << val;
            return *this;
        }
};

#endif
