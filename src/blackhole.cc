// SPDX-License-Identifier: LGPL-3.0-only
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <cstring>
#include <climits>
#include <cstdlib>
#include <initializer_list>
#include <string>

#include "blackhole.hh"
#include "logging.hh"

static std::optional<std::string> getenv_str(const std::string &envar)
{
    const char *result;
    result = getenv(envar.c_str());
    if (result == nullptr)
        return std::nullopt;
    return std::string(result);
}

static bool is_writable_dir(const std::string &dir)
{
    int old_errno = errno;

    char buf[PATH_MAX];
    char *resolved = realpath(dir.c_str(), buf);

    if (resolved == nullptr) {
        errno = old_errno;
        return false;
    }

    if (access(resolved, W_OK) == -1) {
        errno = old_errno;
        return false;
    }

    struct stat st;

    if (stat(resolved, &st) == -1) {
        errno = old_errno;
        return false;
    }

    return S_ISDIR(st.st_mode);
}

static std::string get_tmpdir(void)
{
    for (const std::string &tryenv : {"TMPDIR", "TMP", "TEMP", "TEMPDIR"}) {
        std::optional<std::string> tmpdir = getenv_str(tryenv);
        if (!tmpdir || !is_writable_dir(tmpdir.value()))
            continue;

        return tmpdir.value();
    }

    if (is_writable_dir("/tmp"))
        return "/tmp";

    if (is_writable_dir("/var/tmp"))
        return "/var/tmp";

    int old_errno = errno;
    char *workdir = get_current_dir_name();
    errno = old_errno;
    if (workdir != nullptr) {
        std::string wdir_str(workdir);
        free(workdir);
        if (is_writable_dir(workdir))
            return workdir;
    }

    LOG(FATAL) << "Unable to get temporary directory.";
    std::abort();
}


BlackHole::BlackHole()
    : tmpdir(std::nullopt)
    , filepath(std::nullopt)
{
    static std::string tempdir = get_tmpdir();

    std::string bh_template = tempdir + "/ip2unix.XXXXXX";

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
