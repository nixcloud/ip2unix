// SPDX-License-Identifier: LGPL-3.0-only
#define IP2UNIX_REALCALL_EXTERN
#include <initializer_list>
#include <memory>
#include <mutex>

#include "realcalls.hh"

std::mutex g_dlsym_mutex;

DlsymHandle dlsym_handle;

DlsymHandle::DlsymHandle() : handle(nullptr)
{
    std::scoped_lock<std::mutex> lock(g_dlsym_mutex);

    for (const std::string &libname : {
#ifdef LIBC_PATH
        LIBC_PATH,
#endif
        "libc.so.6"
    }) {
        this->handle = dlopen(libname.c_str(), RTLD_LAZY | RTLD_DEEPBIND);
        if (this->handle != nullptr) return;
    }

    this->handle = RTLD_NEXT;
}

DlsymHandle::~DlsymHandle()
{
    std::scoped_lock<std::mutex> lock(g_dlsym_mutex);

    if (this->handle != RTLD_NEXT)
        dlclose(this->handle);
}
