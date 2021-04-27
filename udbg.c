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
#include <signal.h>
#include <fcntl.h>

// convenience
#define is_set(mask, attr) ({ mask & attr; })

#define UDBG_BUF_LEN        8192                // real
#define UDBG_BUF            (UDBG_BUF_LEN + 1)  // used
#define UDBG_BUF_RESERVED   64
#define UDBG_CALLSTACK      32

static const char *err_buf = "output buffer overflow detected";
static const char *err_panic = "[UDBG::panic(%u)] %s\n[UDBG::errno] %s\n";

// main state structure
static struct
{
    uint64_t channels_mask;
    int fd;
    int options;

    pthread_mutex_t lock;
    struct timespec time;

    // extra bytes reserved for overflow detection
    char output_buf[UDBG_BUF + UDBG_BUF_RESERVED];

    uint8_t alt_stack[SIGSTKSZ];
    void *trace[UDBG_CALLSTACK];

} state = {0};

/*
 *  panic
 */
//  exit on critical (and unrecoverable)
//  error with message to STDERR
#define panic_std(msg_)                             \
({                                                  \
    dprintf(STDERR_FILENO, err_panic, __LINE__,     \
            msg_, strerror(errno));                 \
    exit(EXIT_FAILURE);                             \
})                                                  \

//  exit on critical (and unrecoverable)
//  error with some message to state fd
//  if descriptor output fails, at least try
//  to print the same message to STDERR
#define panic_fd(msg_)                              \
({                                                  \
    if (dprintf(state.fd, err_panic, __LINE__,      \
            msg_, strerror(errno)) <= 0)            \
    {                                               \
        dprintf(STDERR_FILENO, err_panic, __LINE__, \
            msg_, strerror(errno));                 \
    }                                               \
                                                    \
    exit(EXIT_FAILURE);                             \
})                                                  \

/*
 *  stub
 */

//  error & overflow checked snprintf()
#define snprintf_stub(offset_, ...)                         \
({                                                          \
    const int amt_ = snprintf(state.output_buf + offset_,   \
                             UDBG_BUF - offset_,            \
                             ##__VA_ARGS__);                \
    if (amt_ < 0)                                           \
    {                                                       \
        panic_fd("snprintf()");                             \
    }                                                       \
                                                            \
    if (amt_ + offset_ >= UDBG_BUF)                         \
    {                                                       \
        panic_fd(err_buf);                                  \
    }                                                       \
                                                            \
    amt_;                                                   \
})

//  error checked write()
#define write_stub(counter_)                                \
({                                                          \
    const ssize_t amt_ = write(state.fd,                    \
                               state.output_buf,            \
                               (size_t) (counter_));        \
    if (amt_ != (ssize_t) (counter_))                       \
    {                                                       \
        panic_fd("write()");                                \
    }                                                       \
                                                            \
    memset(state.output_buf, 0, counter_);                  \
})


/*
 *  put timestamp at the beginning of the output
 *  noop if attr is not set
 */
static int append_timestamp()
{
    // if attr is set
    if (!is_set(state.options, UDBG_TIME))
    {
        return 0;
    }

    // time is already saved during locking
    const struct tm *ts = localtime(&state.time.tv_sec);
    if (ts == NULL)
    {
        panic_fd("localtime()");
    }

    int tmp = 0;

    // timestamps are at the beginning so
    // do not offset state.output_buf
    const size_t amt = strftime(state.output_buf, 12, "[%X]", ts);
    if (amt != 10)
    {
        panic_fd("strftime()");
    }

    tmp += (int) amt;
    return tmp;
}

/*
 *  append callstack to output buffer; shorter
 *  names, filters out unresolved symbols
 */
static int append_callstack(const int depth, int counter)
{
    char **symbols = backtrace_symbols(state.trace, depth);
    if (symbols == NULL)
    {
        panic_fd("backtrace_symbols()");
    }

    for (int i = 0; i < depth; i++)
    {
        int name = 0;
        int name_len = 0;

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
            // skip unresolved
            continue;
        }

        // safe to start at +1
        for (int n = name + 1; symbols[i][n]; n++)
        {
            if (symbols[i][n] == '+')
            {
                name_len = n - name;
                break;
            }
        }

        counter += snprintf_stub(counter,
                                 "[%i] %.*s()\n",
                                 depth - i, name_len, symbols[i] + name);
    }

    return counter;
}


/*
 *  try locking the state
 *  wait 5 seconds then panic
 */
static void mutex_lock()
{
    // save time on the stack before modifying state
    struct timespec delay = {0};

    if (clock_gettime(CLOCK_REALTIME, &delay))
    {
        // we cant access shared data yet
        // so at least try to output a message
        // to STDERR before terminating
        panic_std("clock_gettime()");
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
            panic_std("locking timed out");
        }

        default:
        {
            panic_std("pthread_mutex_timedlock()");
        }
    }

    state.time = now;
}

static void mutex_unlock()
{
    // no errors expected here
    if (pthread_mutex_unlock(&state.lock))
    {
        panic_fd("pthread_mutex_unlock()");
    }
}

/*
 *
 */
static void sig_handler(const int sig,
                        siginfo_t *siginfo,
                        void *ctx)
{
    // this is not used, so suppress
    // compilation warnings
    (void) ctx;

    // https://man7.org/linux/man-pages/man3/backtrace.3.html
    const int depth = backtrace(state.trace, UDBG_CALLSTACK);

    int counter = append_timestamp();
    counter += snprintf_stub(counter, "[UDBG::sig_handler] %s; errno %s\n\n",
                             strsignal(sig),
                             strerror(siginfo->si_errno));

    counter = append_callstack(depth, counter);

    write_stub(counter);
    exit(EXIT_FAILURE);
}


/*
 *
 */
void __udbg_init(const char *path, const int opt, const uint64_t channels)
{
    state.fd = STDERR_FILENO;
    state.options = opt;
    // enable everything by default
    state.channels_mask = channels ? channels : 0xffffffffffffffff;

    if (pthread_mutex_init(&state.lock, NULL))
    {
        panic_std("pthread_mutex_init()");
    }

    // set signals and alternate stack
    if (!is_set(opt, UDBG_NOSIG))
    {

        const stack_t stack =
                {
                        .ss_sp = state.alt_stack,
                        .ss_flags = 0,
                        .ss_size = SIGSTKSZ,
                };

        if (sigaltstack(&stack, NULL))
        {
            panic_std("sigaltstack()");
        }

        struct sigaction sig_action = {0};
        sig_action.sa_sigaction = sig_handler;
        sig_action.sa_flags = SA_SIGINFO | SA_ONSTACK;

        int action_result = 0;
        action_result |= sigaction(SIGABRT, &sig_action, NULL);
        action_result |= sigaction(SIGBUS, &sig_action, NULL);
        action_result |= sigaction(SIGFPE, &sig_action, NULL);
        action_result |= sigaction(SIGILL, &sig_action, NULL);
        action_result |= sigaction(SIGIOT, &sig_action, NULL);
        action_result |= sigaction(SIGSEGV, &sig_action, NULL);
        action_result |= sigaction(SIGSYS, &sig_action, NULL);
        action_result |= sigaction(SIGTRAP, &sig_action, NULL);

        if (action_result)
        {
            panic_std("sigaction()");
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
            // regular snprintf()
            int offset = snprintf(state.output_buf, UDBG_BUF, "%s_", path);
            if (offset < 0)
            {
                panic_std("snprintf()");
            }

            struct timespec time;
            if (clock_gettime(CLOCK_REALTIME, &time))
            {
                panic_std("clock_gettime()");
            }

            const struct tm *ts = localtime(&time.tv_sec);
            if (ts == NULL)
            {
                panic_std("localtime()");
            }

            const size_t amt = strftime(state.output_buf + offset,
                                        UDBG_BUF - offset,
                                        "%F_%X.log", ts);
            if (amt != 23)
            {
                panic_std("strftime()");
            }

            path_ptr = state.output_buf;
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
            panic_std("open()");
        }

        state.fd = fd;
    }
}


void __udbg_throwfmt(const char *fmt, ...)
{
    mutex_lock(); // no return => no unlock
    va_list args;
    va_start(args, fmt);

    int counter = append_timestamp();
    const int bytes = vsnprintf(state.output_buf + counter,
                                UDBG_BUF - counter,
                                fmt, args);
    if (bytes <= 0)
    {
        panic_fd("vsnprintf()");
    }

    va_end(args);

    counter += bytes;
    if (counter >= UDBG_BUF)
    {
        panic_fd(err_buf);
    }

    state.output_buf[counter] = '\n';
    counter += 1;

    const int depth = backtrace(state.trace, UDBG_CALLSTACK);
    counter = append_callstack(depth, counter);

    write_stub(counter);
    exit(EXIT_FAILURE);
}


void __udbg_log(const uint64_t channel, const char *fmt, ...)
{
    if (!is_set(state.channels_mask, channel))
    {
        return;
    }

    mutex_lock();

    va_list args;
    va_start(args, fmt);
    int counter = append_timestamp();

    const int bytes = vsnprintf(state.output_buf + counter,
                                UDBG_BUF - counter, fmt, args);
    if (bytes <= 0)
    {
        panic_fd("vsnprintf()");
    }

    // plus newline
    counter += bytes;
    state.output_buf[counter] = '\n';
    counter += 1;

    write_stub(counter);
    mutex_unlock();
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

void __udbg_hexdump(const uint64_t channel, const char *prefix, const void *ptr, const int len)
{
    if (!is_set(state.channels_mask, channel))
    {
        return;
    }

    mutex_lock();

    const uint8_t *data = (uint8_t *) ptr;
    const uint8_t *data_end = data + len;
    int counter = append_timestamp();

    // initial msg
    counter += snprintf_stub(counter, "%s\n", prefix);

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

        counter += snprintf_stub(counter, "%8d  %-24s %-24s |%-16s|\n",
                                 i, left, right, ascii);
    }

    write_stub(counter);
    mutex_unlock();
}


void __udbg_bindump(const uint64_t channel, const char *prefix, const void *ptr, const int len)
{
    if (!is_set(state.channels_mask, channel))
    {
        return;
    }

    mutex_lock();

    const uint8_t *data = (uint8_t *) ptr;
    int counter = append_timestamp();

    // initial msg
    counter += snprintf_stub(counter, "%s\n", prefix);

    // cols
    for (int i = 0; i < len; i += 8)
    {
        counter += snprintf_stub(counter, "%8d   ", i);

        // rows
        for (int j = 0; j < 8 && j + i < len; j++)
        {
            const uint8_t byte = data[i + j];

            // go through bits in the current byte
            // and figure out which symbol to append
            for (char k = 7; k >= 0; k--)
            {
                const char symbol = (byte & (1 << k)) ? '1' : '0';
                state.output_buf[counter++] = symbol;
            }

            // append space at the end of each byte
            state.output_buf[counter++] = ' ';
        }

        // append new line at the end of each row
        state.output_buf[counter++] = '\n';

        // detect overflow
        if (counter >= UDBG_BUF)
        {
            panic_fd(err_buf);
        }
    }

    write_stub(counter);
    mutex_unlock();
}
