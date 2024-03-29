// SPDX-License-Identifier: LGPL-3.0-only
#include "blackhole.hh"

#include "logging.hh"

#include <climits>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <initializer_list>
#include <string>

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

static bool is_writable_dir(const std::filesystem::path &dir)
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

static std::filesystem::path get_tmpdir(void)
{
    for (const char *tryenv : {"TMPDIR", "TMP", "TEMP", "TEMPDIR"}) {
        const char *tmpdir = getenv(tryenv);

        if (tmpdir == nullptr)
            continue;

        std::string tmpdir_str(tmpdir);

        if (!is_writable_dir(tmpdir_str))
            continue;

        return tmpdir_str;
    }

    if (is_writable_dir("/tmp"))
        return "/tmp";

    if (is_writable_dir("/var/tmp"))
        return "/var/tmp";

    std::string workdir = std::filesystem::current_path();

    if (is_writable_dir(workdir))
        return workdir;

    LOG(FATAL) << "Unable to get temporary directory.";
    std::abort();
}

/* This is for getting an inaccessible unique path name that can be used for
 * binding a socket on it.
 *
 * The reason why we don't use an unnamed socket is that it would be accessible
 * by other users on the system since unnamed sockets essentially boil down to
 * abstract namespaces where filesystem permissions don't apply.
 *
 * Since the directory returned by mkdtemp() is created with permissions 0700
 * and it's (usually) also directly removed after binding, other non-superusers
 * on the system can't access the socket.
 */
BlackHole::BlackHole()
    : tmpdir(std::nullopt)
    , filepath(std::nullopt)
{
    static std::filesystem::path tempdir = get_tmpdir();

    std::string bh_template = tempdir / "ip2unix.XXXXXX";

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
