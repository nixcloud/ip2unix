// SPDX-License-Identifier: LGPL-3.0-only
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <iostream>

#include "logging.hh"

static std::optional<Verbosity> current_verbosity;

#ifdef SYSTEMD_SUPPORT
static bool is_systemd;

//                            FATAL, ERROR, WARNING, INFO, DEBUG, TRACE
static const int sysdlvl[] = {2,     3,     4,       6,    7,     7};
#endif

Logger::Logger(Verbosity verbosity, const std::string_view &file, int line,
               const char *fun, const char *label)
    : logbuf(std::nullopt)
{
    if (!current_verbosity) {
        const char *env = getenv("__IP2UNIX_VERBOSITY");
        if (env != nullptr && *env >= '0' && *env <= '9')
            current_verbosity = static_cast<Verbosity>(atoi(env));
        else
            current_verbosity = Verbosity::FATAL;

#ifdef SYSTEMD_SUPPORT
        int old_errno = errno;
        struct stat st;
        is_systemd = fstat(STDERR_FILENO, &st) == 0 && S_ISSOCK(st.st_mode);
        errno = old_errno;
#endif
    }

    if (verbosity <= current_verbosity.value()) {
        this->logbuf.emplace();
#ifdef SYSTEMD_SUPPORT
        if (is_systemd) {
            *this->logbuf << '<' << sysdlvl[static_cast<int>(verbosity)]
                          << ">ip2unix:";
            if (current_verbosity.value() >= Verbosity::DEBUG)
                *this->logbuf << file << ':' << line << ':' << fun;
            *this->logbuf << ' ';
            return;
        }
#endif

        *this->logbuf << "ip2unix";

        if (current_verbosity.value() >= Verbosity::DEBUG) {
            *this->logbuf << '[' << getpid() << "] ";
            *this->logbuf << file << ':' << line << ':' << fun;
        }

        *this->logbuf << ' ' << label << ": ";
    }
}

Logger::~Logger()
{
    if (this->logbuf) {
        *this->logbuf << std::endl;
        std::cerr << this->logbuf->str();
    }
}
