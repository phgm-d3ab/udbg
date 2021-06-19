#ifndef UDBG_H
#define UDBG_H

#include "udbg_bits.h"

///////////////////////
///     options     ///
///////////////////////
// prefix output with timestamp
// in [hh:mm:ss] format
#define UDBG_TIME           0x1

// truncate file to zero when
// opening file for logging
#define UDBG_TRUNCATE       0x2

// add suffix with date and time to logfile
// file_yyyy-mm-dd_hh:mm:ss.log
#define UDBG_SUFFIX         0x4

// do not set udbg sighandlers
#define UDBG_NOSIG          0x8

// write out a core dump (to a default location)
// during crash, exception, assert
#define UDBG_CORE           0x10


///////////////////////////
///     routines        ///
///////////////////////////
// main initialization routine; must be called
// prior to using anything. any udbg call before
// this results in an undefined behavior
// defaults:
// path - NULL, output to STDERR
// opt - zero
// channels - zero, everything enabled by default
#define udbg_init(path_, opt_, channels_)   __udbg_init_impl(path_, opt_, channels_)

// formatted output to some channel
// [TIME][CHANNEL::function():line] <message>
#define udbg_log(channel_, fmt_, ...) \
                    __udbg_log_impl(channel_, __udbg_prefix(#channel_) fmt_, ##__VA_ARGS__)

// hex dump some object into log
#define udbg_hexdump(ch_, ptr_, len_)       __udbg_hexdump_impl(ch_, #ch_, ptr_, len_)

// binary dump some object into log
#define udbg_bindump(ch_, ptr_, len_)       __udbg_bindump_impl(ch_, #ch_, ptr_, len_)

// throw/panic/terminate
#define udbg_throw()                        __udbg_throw_impl()

// custom assert
#define udbg_assert(expr_)                  __udbg_assert_impl(expr_)


#endif // UDBG_H
