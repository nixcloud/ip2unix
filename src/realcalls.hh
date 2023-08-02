// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_REALCALLS_HH
#define IP2UNIX_REALCALLS_HH

#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <cstring>
#include <mutex>

#include "logging.hh"

#if HAS_EPOLL
#include <sys/epoll.h>
#endif

/* Let's declare all of the wrappers as extern, so that we can define them by
 * simply overriding IP2UNIX_REALCALL_EXTERN before the #include directive.
 */
#ifndef IP2UNIX_REALCALL_EXTERN
#define IP2UNIX_REALCALL_EXTERN extern
#endif

struct DlsymHandle
{
    DlsymHandle();
    ~DlsymHandle();

    inline void *get(void) const {
        return this->handle;
    }

    private:
        DlsymHandle(const DlsymHandle&) = delete;
        DlsymHandle &operator=(const DlsymHandle&) = delete;

        void *handle;
};

extern std::mutex g_dlsym_mutex;
extern DlsymHandle dlsym_handle;

/* This namespace is here so that we can autogenerate and call wrappers for C
 * library functions in a convenient way. For example to call the wrapper for
 * close we can just use real::close(fd).
 */
namespace real {
    template <typename Self, typename FunType>
    struct DlsymFunBase
    {
        FunType *fptr = nullptr;

        template <typename ... Args>
        auto operator()(Args ... args) -> decltype(fptr(args ...))
        {
            g_dlsym_mutex.lock();
            if (this->fptr == nullptr) {
                void *result = dlsym(dlsym_handle.get(), Self::fname);
                if (result == nullptr) {
                    LOG(FATAL) << "Loading of symbol '" << Self::fname
                               << "' failed: " << strerror(errno);
                    g_dlsym_mutex.unlock();
                    _exit(EXIT_FAILURE);
                }
                this->fptr = reinterpret_cast<decltype(fptr)>(result);
            }
            g_dlsym_mutex.unlock();
            return this->fptr(args ...);
        }
    };

    template <typename Self, typename Ret, typename... FunArgs>
    using DlsymFun = DlsymFunBase<Self, Ret(FunArgs...)>;

    template <typename Self, typename Ret, typename... FunArgs>
    using DlsymFunVaArgs = DlsymFunBase<Self, Ret(FunArgs..., ...)>;

#define DLSYM_FUN(name, ...) IP2UNIX_REALCALL_EXTERN \
    struct name##_fun_t : public DlsymFun<name##_fun_t, __VA_ARGS__> { \
        static constexpr const char *fname = #name; \
    } name

#define DLSYM_FUN_VA_ARGS(name, ...) IP2UNIX_REALCALL_EXTERN \
    struct name##_fun_t : public DlsymFunVaArgs<name##_fun_t, __VA_ARGS__> { \
        static constexpr const char *fname = #name; \
    } name

    DLSYM_FUN(accept, int, int, struct sockaddr*, socklen_t*);
    DLSYM_FUN(accept4, int, int, struct sockaddr*, socklen_t*, int);
    DLSYM_FUN(bind, int, int, const struct sockaddr*, socklen_t);
    DLSYM_FUN(close, int, int);
    DLSYM_FUN(connect, int, int, const struct sockaddr*, socklen_t);
    DLSYM_FUN(dup, int, int);
    DLSYM_FUN(dup2, int, int, int);
    DLSYM_FUN(dup3, int, int, int, int);
    DLSYM_FUN(getpeername, int, int, struct sockaddr*, socklen_t*);
    DLSYM_FUN(getsockname, int, int, struct sockaddr*, socklen_t*);
    DLSYM_FUN(ioctl, int, int, unsigned long, const void*);
#ifdef HAS_EPOLL
    DLSYM_FUN(epoll_ctl, int, int, int, int, struct epoll_event*);
#endif
#ifdef SYSTEMD_SUPPORT
    DLSYM_FUN(listen, int, int, int);
#endif
    DLSYM_FUN(recvfrom, ssize_t, int, void*, size_t, int, struct sockaddr*,
              socklen_t*);
    DLSYM_FUN(recvmsg, ssize_t, int, struct msghdr*, int);
    DLSYM_FUN(sendmsg, ssize_t, int, const struct msghdr*, int);
    DLSYM_FUN(sendto, ssize_t, int, const void*, size_t, int,
              const struct sockaddr*, socklen_t);
    DLSYM_FUN(setsockopt, int, int, int, int, const void*, socklen_t);
    DLSYM_FUN(socket, int, int, int, int);
}

#endif
