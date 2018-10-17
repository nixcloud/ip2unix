// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_REALCALLS_HH
#define IP2UNIX_REALCALLS_HH

#include <mutex>
#include <unistd.h>

#include <dlfcn.h>
#include <sys/socket.h>

static std::mutex g_dlsym_mutex;

/* This namespace is here so that we can autogenerate and call wrappers for C
 * library functions in a convenient way. For example to call the wrapper for
 * close we can just use real::close(fd).
 */
namespace real {
    template <typename Sig, typename Sym>
    struct DlsymFun
    {
        Sig fptr = nullptr;

        template <typename ... Args>
        auto operator()(Args ... args) -> decltype(fptr(args ...))
        {
            g_dlsym_mutex.lock();
            if (fptr == nullptr)
                fptr = reinterpret_cast<Sig>(dlsym(RTLD_NEXT, Sym::fname));
            g_dlsym_mutex.unlock();
            return fptr(args ...);
        }
    };

#define DLSYM_FUN(name) \
    struct name##_fun_t : public DlsymFun<decltype(&::name), name##_fun_t> { \
        static constexpr const char *fname = #name; \
    } name

    DLSYM_FUN(socket);
    DLSYM_FUN(setsockopt);
    DLSYM_FUN(bind);
    DLSYM_FUN(connect);
#ifdef SOCKET_ACTIVATION
    DLSYM_FUN(listen);
#endif
    DLSYM_FUN(accept);
    DLSYM_FUN(accept4);
    DLSYM_FUN(getpeername);
    DLSYM_FUN(getsockname);
    DLSYM_FUN(close);
}

#endif
