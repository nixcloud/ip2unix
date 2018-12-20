// SPDX-License-Identifier: LGPL-3.0-only
#include <iostream>

#include <unistd.h>

#include "logging.hh"

static std::optional<Verbosity> current_verbosity;

Logger::Logger(Verbosity verbosity, const std::string_view &file, int line,
               const char *fun, const char *label)
    : logbuf(std::nullopt)
{
    if (!current_verbosity) {
        const char *env = getenv("__IP2UNIX_VERBOSITY");
        if (env != NULL && *env >= '0' && *env <= '9')
            current_verbosity = static_cast<Verbosity>(atoi(env));
        else
            current_verbosity = Verbosity::FATAL;
    }

    if (verbosity <= current_verbosity.value()) {
        this->logbuf.emplace();
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
