// strerrorname_np(), sigabbrev_np()
#define _GNU_SOURCE

#include "udbg.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <execinfo.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>

// convenience
#define is_set(mask, attr) ({ ((mask) & (attr)); })

#define UDBG_BUF_LEN        65536               // real
#define UDBG_BUF            (UDBG_BUF_LEN + 1)  // used
#define UDBG_BUF_RESERVED   128
#define UDBG_CALLSTACK      48

static const int udbg_signals[] =
        {
                SIGABRT,
                SIGBUS,
                SIGFPE,
                SIGILL,
                SIGIOT,
                SIGSEGV,
                SIGSYS,
                SIGTRAP,
        };


typedef struct
{
    int iterator;
    char buf[UDBG_BUF + UDBG_BUF_RESERVED];

} udbg_buf;


// main state structure
typedef struct
{
    uint64_t channels_mask;
    int fd;
    int options;

    pthread_mutex_t lock;

    // main output buffer
    udbg_buf buf_output;

    // reserved for backtrace
    udbg_buf buf_backtrace;

    // malloc() extra space in case we use demangler
    char *buf_demangle;
    char *(*demangler)(const char *input, char *output,
                       size_t *len, int *status);

    // https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=6c57d320484988e87e446e2e60ce42816bf51d53
    uint8_t *alt_stack;
    void *trace[UDBG_CALLSTACK];

} udbg_state;

static udbg_state state = {0};


// chicanery
#define panic(...) \
        __panic_get(__VA_ARGS__, __panic_exp, __panic_global)(__VA_ARGS__)

#define __panic_get(_1, _2, __variant, ...) __variant
#define __panic_base(state_, msg_) __udbg_panic(state_, msg_, __FUNCTION__, __LINE__, 0)
#define __panic_global(msg_) __panic_base(-1, msg_)
#define __panic_exp(fd_, msg_) __panic_base(fd_, msg_)

void __udbg_panic(const int fd,
                  const char *action,
                  const char *f,
                  const int line,
                  const int err)
{
    if (fd == -1)
    {
        const int err_action = errno;
        const int amt = dprintf(state.fd, "[udbg::%s] panicked at %s():%u %s\n",
                                action, f, line, strerrorname_np(err_action));
        if (amt == -1)
        {
            const int err_dprintf = errno;
            errno = err_action;

            // explicit call to save origin function and line
            __udbg_panic(STDERR_FILENO, action, f, line, err_dprintf);
        }

        exit(EXIT_FAILURE);
    }

    dprintf(STDERR_FILENO, "[udbg::stderr(%s)] panicked at %s %s():%u %s\n",
            strerrorname_np(err), action, f, line, strerrorname_np(errno));
    exit(EXIT_FAILURE);
}


static void buf_vaprintf(udbg_buf *ptr, const char *fmt, va_list args)
{
    if (ptr->iterator > UDBG_BUF)
    {
        return;
    }

    const int amt = vsnprintf(ptr->buf + ptr->iterator, UDBG_BUF - ptr->iterator,
                              fmt, args);
    if (amt == -1)
    {
        panic("vsnprintf()");
    }

    ptr->iterator += amt;
    if (ptr->iterator >= UDBG_BUF_LEN)
    {
        const int remaining = UDBG_BUF + UDBG_BUF_RESERVED - ptr->iterator;
        const int trunc_bytes = snprintf(ptr->buf + ptr->iterator, remaining,
                                         " ..\n[udbg::snprintf()] output truncated\n");
        if (trunc_bytes == -1)
        {
            panic("snprintf()");
        }

        ptr->iterator += trunc_bytes;
    }

    va_end(args);
    ptr->buf[ptr->iterator] = 0;
}


static void buf_snprintf(udbg_buf *ptr, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    buf_vaprintf(ptr, fmt, args);
    va_end(args);
}


static void buf_flush(const int fd, udbg_buf *ptr)
{
    const ssize_t amt = write(fd, ptr->buf, ptr->iterator);
    if (amt == -1)
    {
        panic("write()");
    }

    ptr->iterator = 0;
}


static void buf_timestamp(const int attr, const time_t time, udbg_buf *ptr)
{
    if (!is_set(attr, UDBG_TIME))
    {
        return;
    }

    const struct tm *ts = localtime(&time);
    if (ts == NULL)
    {
        panic("localtime()");
    }

    const size_t amt = strftime(ptr->buf + ptr->iterator, 12, "[%X]", ts);
    if (amt != 10)
    {
        panic("strftime()");
    }

    ptr->iterator += (int) amt;
}

/*
 *  append callstack to output buffer; shorter
 *  names, filters out unresolved symbols
 */
static void buf_backtrace(udbg_buf *ptr, const int depth)
{
    char **symbols = backtrace_symbols(state.trace, depth);
    if (symbols == NULL)
    {
        panic("backtrace_symbols()");
    }

    for (int i = 0; i < depth; i++)
    {
        int name = 0;
        size_t name_len = 0;
        char tail = '+';
        char *suffix = "()";

        // find name offset
        for (int n = 0; symbols[i][n]; n++)
        {
            if (symbols[i][n] == '(')
            {
                name = n + 1;
                break;
            }
        }

        if (symbols[i][name] == '+')
        {
            continue;
        }

        // safe to start at +1
        for (int n = name + 1; symbols[i][n]; n++)
        {
            if (symbols[i][n] == tail)
            {
                name_len = n - name;
                break;
            }
        }

        char *name_str = symbols[i] + name;
        if (state.demangler)
        {
            // demangle function expects null-terminated string
            name_str[name_len] = 0;

            int status = 0;
            char *tmp = state.demangler(name_str, state.buf_demangle, &name_len, &status);

            switch (status)
            {
                case -1: // allocation error
                case -3: // invalid args
                {
                    panic("demangle()");
                    break;
                }

                case -2: // demangle failed
                {
                    break;
                }

                case 0: // success
                default:
                {
                    if (tmp == NULL)
                    {
                        panic("demangled_str()");
                    }

                    name_str = tmp;
                    name_len = UDBG_BUF; // NULL-terminated anyway
                    suffix = "";
                }
            }
        }

        buf_snprintf(ptr, "[%i] %.*s%s\n",
                     depth - i, name_len, name_str, suffix);
    }
}


// remap SIGABRT to its default action and abort() if needed
static void exit_stub()
{
    if (is_set(state.options, UDBG_CORE))
    {
        struct sigaction def_action = {0};
        def_action.sa_sigaction = (void *) SIG_DFL; // !

        if (sigaction(SIGABRT, &def_action, NULL))
        {
            _exit(EXIT_FAILURE);
        }

        abort();
    }

    _exit(EXIT_FAILURE);
}


/*
 *  try locking the state
 *  wait 5 seconds then panic
 */
static time_t state_lock()
{
    struct timespec delay = {0};
    if (clock_gettime(CLOCK_REALTIME, &delay))
    {
        // we can't access shared data yet
        // so at least try to output a message
        // to STDERR before terminating
        panic(STDERR_FILENO, "clock_gettime()");
    }

    struct timespec now = delay;
    delay.tv_sec += 5;

    switch (pthread_mutex_timedlock(&state.lock, &delay))
    {
        case 0: // success
        {
            break;
        }

        case ETIMEDOUT:
        {
            panic(STDERR_FILENO, "locking timed out");
            break; //
        }

        default:
        {
            panic(STDERR_FILENO, "pthread_mutex_timedlock()");
        }
    }

    return now.tv_sec;
}


static void state_unlock()
{
    // no errors expected here
    if (pthread_mutex_unlock(&state.lock))
    {
        panic("pthread_mutex_unlock()");
    }
}


/*
 *
 */
void __udbg_sig_handler(const int sig, siginfo_t *siginfo, void *ctx)
{
    // this is not used, so suppress
    // compilation warnings
    (void) ctx;

    // https://man7.org/linux/man-pages/man3/backtrace.3.html
    // +do it here so handler is at the top
    const int depth = backtrace(state.trace, UDBG_CALLSTACK);

    if (is_set(state.options, UDBG_TIME))
    {
        struct timespec timestamp = {0};
        if (clock_gettime(CLOCK_REALTIME, &timestamp))
        {
            panic("clock_gettime()");
        }

        buf_timestamp(0xff, timestamp.tv_sec, &state.buf_backtrace);
    }

    buf_snprintf(&state.buf_backtrace, "[udbg::%s] %s\n\n",
                 sigabbrev_np(sig),
                 strerrorname_np(siginfo->si_errno) ? : "unknown_errno");

    buf_backtrace(&state.buf_backtrace, depth);

    buf_flush(state.fd, &state.buf_backtrace);
    exit_stub();
}


/*
 *
 */
void __udbg_init(void *demangler, const char *path,
                 const int opt, const uint64_t channels)
{
    state.fd = STDERR_FILENO;
    state.options = opt;
    // enable everything by default
    state.channels_mask = channels ? : ((uint64_t) (-1));
    state.buf_demangle = NULL;
    state.demangler = demangler;

    if (pthread_mutex_init(&state.lock, NULL))
    {
        panic(STDERR_FILENO, "pthread_mutex_init()");
    }

    // set signals and alternate stack
    if (!is_set(opt, UDBG_NOSIG))
    {
        state.alt_stack = malloc(SIGSTKSZ);
        if (state.alt_stack == NULL)
        {
            panic(STDERR_FILENO, "malloc()");
        }

        const stack_t stack =
                {
                        .ss_sp = state.alt_stack,
                        .ss_flags = 0,
                        .ss_size = SIGSTKSZ,
                };

        if (sigaltstack(&stack, NULL))
        {
            panic(STDERR_FILENO, "sigaltstack()");
        }

        struct sigaction sig_action = {0};
        sigset_t block_set = {0};

        if (sigemptyset(&block_set))
        {
            panic(STDERR_FILENO, "sigemptyset()");
        }

        // sa_mask specifies a mask of signals which should be blocked
        // (i.e., added to the signal mask of the thread in which the signal
        // handler is invoked) during execution of the signal handler
        for (unsigned long i = 0; i < sizeof(udbg_signals) / sizeof(int); i++)
        {
            if (sigaddset(&block_set, udbg_signals[i]))
            {
                panic(STDERR_FILENO, "sigaddset()");
            }
        }

        // deliver signal info
        // execute handler on alternate stack
        // reset to default action on entry
        sig_action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
        sig_action.sa_mask = block_set;
        sig_action.sa_sigaction = __udbg_sig_handler;

        for (unsigned long i = 0; i < sizeof(udbg_signals) / sizeof(int); i++)
        {
            if (sigaction(udbg_signals[i], &sig_action, NULL))
            {
                // let this also indicate which signal caused a failure
                panic(STDERR_FILENO, sigabbrev_np(udbg_signals[i]));
            }
        }
    }

    // open the log file
    if (path)
    {
        // and if the suffix attr is set,
        // get current time and form a full path
        const char *path_ptr = path;
        if (is_set(opt, UDBG_SUFFIX))
        {
            char time_str[32] = {0};
            struct timespec time = {0};
            if (clock_gettime(CLOCK_REALTIME, &time))
            {
                panic(STDERR_FILENO, "clock_gettime()");
            }

            const struct tm *ts = localtime(&time.tv_sec);
            if (ts == NULL)
            {
                panic(STDERR_FILENO, "localtime()");
            }

            if (strftime(time_str, 32, "%F_%X", ts) != 19)
            {
                panic(STDERR_FILENO, "strftime()");
            }

            const int amt = snprintf(state.buf_output.buf, UDBG_BUF, "%s_%s.log",
                                     path, time_str);
            if (amt == -1)
            {
                panic(STDERR_FILENO, "snprint()");
            }

            // path can become too long after appending suffix
            if (amt > PATH_MAX)
            {
                panic(STDERR_FILENO, "PATH_MAX");
            }

            path_ptr = state.buf_output.buf;
        }

        // finally open the file
        int fd_opt = O_WRONLY | O_CREAT | O_APPEND;
        if (state.options & UDBG_TRUNCATE)
        {
            fd_opt |= O_TRUNC;
        }

        const int fd = open(path_ptr, fd_opt, 0600);
        if (fd < 0)
        {
            panic(STDERR_FILENO, "open()");
        }

        state.fd = fd;
    }

    if (demangler)
    {
        state.buf_demangle = malloc(UDBG_BUF);
        if (state.buf_demangle == NULL)
        {
            panic(STDERR_FILENO, "malloc()");
        }
    }
}


void __udbg_throwfmt(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const time_t timestamp = state_lock(); // no return => no unlock

    buf_timestamp(state.options, timestamp, &state.buf_output);
    buf_vaprintf(&state.buf_output, fmt, args);

    va_end(args);

    const int depth = backtrace(state.trace, UDBG_CALLSTACK);
    buf_backtrace(&state.buf_output, depth);

    buf_flush(state.fd, &state.buf_output);
    exit_stub();
}


void __udbg_log(const uint64_t channel, const char *fmt, ...)
{
    if (!is_set(state.channels_mask, channel))
    {
        return;
    }

    va_list args;
    va_start(args, fmt);
    const time_t timestamp = state_lock();

    buf_timestamp(state.options, timestamp, &state.buf_output);
    buf_vaprintf(&state.buf_output, fmt, args);

    va_end(args);
    buf_flush(state.fd, &state.buf_output);
    state_unlock();
}


///////////////////////////////
///     hex & bin dumps     ///
///////////////////////////////

// decide if this char is printable
static inline char asc_output(const uint8_t ch)
{
    if (ch > 0x1f && ch < 0x7f)
    {
        return (char) ch;
    }

    return '.';
}

// convert a byte to printable form
static inline void hex_converter(const uint8_t input, char *output)
{
    const char hex[] = "0123456789abcdef";

    output[0] = hex[input >> 4];
    output[1] = hex[input & 0xf];
    output[2] = ' ';
}


void __udbg_hexdump(const uint64_t channel, const char *prefix,
                    const void *ptr, const int len)
{
    if (!is_set(state.channels_mask, channel))
    {
        return;
    }

    const time_t timestamp = state_lock();
    buf_timestamp(state.options, timestamp, &state.buf_output);

    const uint8_t *data = (uint8_t *) ptr;
    const uint8_t *data_end = data + len;

    buf_snprintf(&state.buf_output, "%s\n", prefix);

    //
    for (int i = 0; i < len; i += 16)
    {
        char ascii[32] = {0};
        char left[32] = {0};
        char right[32] = {0};
        const uint8_t *row = data + i;
        int asc_offset = 0;

        for (int j = 0; j < 24 && row != data_end; j += 3)
        {
            hex_converter(*row, left + j);
            ascii[asc_offset++] = asc_output(*row);
            row += 1;
        }

        for (int j = 0; j < 24 && row != data_end; j += 3)
        {
            hex_converter(*row, right + j);
            ascii[asc_offset++] = asc_output(*row);
            row += 1;
        }

        buf_snprintf(&state.buf_output, "%8d  %-24s %-24s |%-16s|\n",
                     i, left, right, ascii);
    }

    buf_flush(state.fd, &state.buf_output);
    state_unlock();
}


void __udbg_bindump(const uint64_t channel, const char *prefix,
                    const void *ptr, const int len)
{
    if (!is_set(state.channels_mask, channel))
    {
        return;
    }

    const time_t timestamp = state_lock();
    const uint8_t *data = (uint8_t *) ptr;

    buf_timestamp(state.options, timestamp, &state.buf_output);
    buf_snprintf(&state.buf_output, "%s\n", prefix);

    for (int i = 0; i < len; i += 8)
    {
        char decoded_row[72] = {0};
        int iterator = 0;

        for (int j = 0; j < 8 && j + i < len; j++)
        {
            const uint8_t byte = data[i + j];

            for (char k = 7; k >= 0; k--)
            {
                const char symbol = (byte & (1 << k)) ? '1' : '0';
                decoded_row[iterator++] = symbol;
            }

            decoded_row[iterator++] = ' ';
        }

        buf_snprintf(&state.buf_output, "%8d  %s\n", i, decoded_row);
    }

    buf_flush(state.fd, &state.buf_output);
    state_unlock();
}
