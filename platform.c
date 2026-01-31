#include "platform.h"

#include <time.h>

/* Use real Windows API only on actual Windows without stubs */
#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int32_t PlatformWritePrivateProfileString(const char *section, const char *key, const char *value, const char *file_path) {
    return (int32_t)WritePrivateProfileStringA(section, key, value, file_path);
}

uint32_t PlatformTickMs(void) { return (uint32_t)GetTickCount(); }

void PlatformSleepMs(uint32_t ms) { Sleep((DWORD)ms); }

#else /* !_WIN32 || STARS_USE_WIN_STUBS */

int32_t PlatformWritePrivateProfileString(const char *section, const char *key, const char *value, const char *file_path) {
    (void)section;
    (void)key;
    (void)value;
    (void)file_path;
    return 1;
}

uint32_t PlatformTickMs(void) {
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    clock_gettime(CLOCK_REALTIME, &ts);
#endif
    return (uint32_t)((uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull);
}

void PlatformSleepMs(uint32_t ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
    nanosleep(&ts, NULL);
}

#endif
