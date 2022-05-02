/*
 *  this file exists to make public header readable
 *  should not be used directly
 */
#ifndef UDBG_BITS_H
#define UDBG_BITS_H

/*
 *  define empty statements here
 */
#ifndef UDBG

#define __udbg_init_impl(path_, opt_, channels_)
#define __udbg_log_impl(ch_, fmt_, ...)
#define __udbg_hexdump_impl(ch_, label_, ptr_, len_)
#define __udbg_bindump_impl(ch_, label_, ptr_, len_)
#define __udbg_throw_impl()
#define __udbg_assert_impl(expr_)

#else // UDBG

// c
#define __udbg_demangle NULL

#ifdef __cplusplus
#   include <cstdint>
#   include <cxxabi.h>
#   undef __udbg_demangle

// gcc & clang
#   if defined(__GNUC__) || defined(__clang__)
#       define __udbg_demangle (void *)(abi::__cxa_demangle)
#   endif

// fallback
#   if !defined(__udbg_demangle)
#       define __udbg_demangle nullptr
#   endif

extern "C" {
#else
#   include <stdint.h>
#endif

// direct calls
void __udbg_init(void *, const char *, int, uint64_t);
void __udbg_throwfmt(const char *, ...);
void __udbg_log(uint64_t, const char *, ...);
void __udbg_hexdump(uint64_t, const char *, const void *, int);
void __udbg_bindump(uint64_t, const char *, const void *, int);

#ifdef __cplusplus
}
#endif // __cplusplus

// log format prefix:
// need to pass channel as string
#define __udbg_prefix(ch_) "[" ch_ "::%s(%u)] "

//
#define __udbg_init_impl(path_, opt_, channels_) \
    __udbg_init(__udbg_demangle, path_, opt_, channels_)
#define __udbg_log_impl(channel_, fmt_, ...) \
    __udbg_log(channel_, fmt_ "\n", __FUNCTION__, __LINE__,  ##__VA_ARGS__)

#define __udbg_hexdump_impl(ch_, label_, ptr_, len_) \
    __udbg_hexdump(ch_, "[" label_ "::hexdump] " #ptr_ ", " #len_, ptr_, len_)
#define __udbg_bindump_impl(ch_, label_, ptr_, len_) \
    __udbg_bindump(ch_, "[" label_ "::bindump] " #ptr_ ", " #len_, ptr_, len_)

// wrappers
#define __udbg_assert_impl(expr_)                       \
    ({if (!(expr_)){                                    \
    __udbg_throwfmt("[udbg::assert] %s\n%s() %s:%d\n",  \
    #expr_, __FUNCTION__, __FILE__, __LINE__);}})       \

#define __udbg_throw_impl()                             \
    __udbg_throwfmt("[udbg::throw] %s() %s:%u\n",       \
    __FUNCTION__, __FILE__, __LINE__)                   \

#endif // UDBG
#endif // UDBG_BITS_H
