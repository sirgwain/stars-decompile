#ifndef PLATFORM_H_
#define PLATFORM_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

/* Windows UI shims: assume windows.h is included on Win32 builds. */
#ifndef _WIN32
#include <stdint.h>

/* Stars/Win16 style: HWND is a 16-bit integer handle in this codebase. */
typedef uint16_t HWND;

static inline int DestroyWindow(HWND hwnd)
{
    (void)hwnd;
    return 1;
}
#endif

/* access() / _access() portability */
#if defined(_WIN32)
#include <io.h>
#define stars_access _access
#ifndef modeWrite
#define modeWrite 2 /* MSVCRT _access: 2 == write permission check */
#endif
#else
#include <unistd.h>
#define stars_access access
#ifndef modeWrite
#define modeWrite W_OK /* POSIX access(): W_OK checks write permission */
#endif
#endif

/* =========================================================================
 * Portable platform shims
 * =========================================================================
 *
 * You can override any of these in a platform header before including this file.
 */

/* Replace the old MessageBox/GetFocus behavior with something portable.
 * Return value is kept as int16_t like Win16 MessageBox() return codes.
 */
#ifndef STARS_MESSAGEBOX
/* Default: print to stderr and return "IDOK" (1). */
static inline int16_t STARS_MESSAGEBOX(const char *caption, const char *text, int16_t mbType)
{
    (void)mbType;
    fprintf(stderr, "%s: %s\n", caption ? caption : "Stars!", text ? text : "");
    return 1;
}
#endif

/* Millisecond tick count for retry logic. */
static inline uint32_t stars_tick_ms(void)
{
#if defined(_WIN32)
    return (uint32_t)GetTickCount();
#else
    struct timespec ts;
    /* CLOCK_MONOTONIC is widely available; if not, fall back to clock(). */
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull);
#else
    return (uint32_t)((uint64_t)clock() * 1000ull / (uint64_t)CLOCKS_PER_SEC);
#endif
#endif
}

static inline void stars_sleep_ms(uint32_t ms)
{
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
    nanosleep(&ts, NULL);
#endif
}

#endif /* PLATFORM_H_ */
