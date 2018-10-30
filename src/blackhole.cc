// SPDX-License-Identifier: LGPL-3.0-only
#include <cstring>
#include <unistd.h>

#include "blackhole.hh"

BlackHole::BlackHole()
    : tmpdir(std::nullopt)
    , filepath(std::nullopt)
{
    static const char *tempdir = nullptr;

    if (tempdir == nullptr) {
        if ((tempdir = getenv("TMPDIR")) == nullptr)
            tempdir = "/tmp";
    }

    std::string bh_template = std::string(tempdir) + "/ip2unix.XXXXXX";

    char *c_bh_template = strdup(bh_template.c_str());

    char *c_tmpdir;
    if ((c_tmpdir = mkdtemp(c_bh_template)) != nullptr) {
        this->tmpdir = std::string(c_tmpdir);
        this->filepath = this->tmpdir.value() + "/blackhole.sock";
    }
    free(c_bh_template);
}

BlackHole::~BlackHole()
{
    if (this->filepath && this->tmpdir) {
        int old_errno = errno;
        unlink(this->filepath.value().c_str());
        rmdir(this->tmpdir.value().c_str());
        errno = old_errno;
    }
}
