#include "platform.h"

#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int16_t PlatformScreenWidth(void)
{
    return (int16_t)GetSystemMetrics(SM_CXSCREEN);
}

int16_t PlatformScreenHeight(void)
{
    return (int16_t)GetSystemMetrics(SM_CYSCREEN);
}

StarsHWND PlatformCreatePopupWindow(const char *class_name,
                                   const char *title,
                                   int32_t style,
                                   int16_t x,
                                   int16_t y,
                                   int16_t w,
                                   int16_t h,
                                   StarsHWND parent)
{
    HWND hwnd = CreateWindowA(class_name,
                              title,
                              (DWORD)((style & PLAT_WS_VISIBLE ? WS_VISIBLE : 0) |
                                      (style & PLAT_WS_POPUP ? WS_POPUP : 0)),
                              (int)x,
                              (int)y,
                              (int)w,
                              (int)h,
                              (HWND)(uintptr_t)parent,
                              NULL,
                              GetModuleHandleA(NULL),
                              NULL);

    /* The core uses 16-bit handles; truncate like Win16 would. */
    return (StarsHWND)(uintptr_t)hwnd;
}

void PlatformShowWindow(StarsHWND hwnd, int32_t cmd)
{
    HWND wh = (HWND)(uintptr_t)hwnd;
    int show = (cmd == PLAT_SW_HIDE) ? SW_HIDE : SW_SHOW;
    ShowWindow(wh, show);
}

void PlatformDestroyWindow(StarsHWND hwnd)
{
    DestroyWindow((HWND)(uintptr_t)hwnd);
}

int32_t PlatformWritePrivateProfileString(const char *section,
                                         const char *key,
                                         const char *value,
                                         const char *file_path)
{
    return (int32_t)WritePrivateProfileStringA(section, key, value, file_path);
}

uint32_t PlatformTickMs(void)
{
    return (uint32_t)GetTickCount();
}

void PlatformSleepMs(uint32_t ms)
{
    Sleep((DWORD)ms);
}

#else /* !_WIN32 */

int16_t PlatformScreenWidth(void)
{
    return 640;
}

int16_t PlatformScreenHeight(void)
{
    return 480;
}

StarsHWND PlatformCreatePopupWindow(const char *class_name,
                                   const char *title,
                                   int32_t style,
                                   int16_t x,
                                   int16_t y,
                                   int16_t w,
                                   int16_t h,
                                   StarsHWND parent)
{
    (void)class_name;
    (void)title;
    (void)style;
    (void)x;
    (void)y;
    (void)w;
    (void)h;
    (void)parent;

    /* Non-zero sentinel. */
    return (StarsHWND)1;
}

void PlatformShowWindow(StarsHWND hwnd, int32_t cmd)
{
    (void)hwnd;
    (void)cmd;
}

void PlatformDestroyWindow(StarsHWND hwnd)
{
    (void)hwnd;
}

int32_t PlatformWritePrivateProfileString(const char *section,
                                         const char *key,
                                         const char *value,
                                         const char *file_path)
{
    (void)section;
    (void)key;
    (void)value;
    (void)file_path;
    return 1;
}

uint32_t PlatformTickMs(void)
{
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    clock_gettime(CLOCK_REALTIME, &ts);
#endif
    return (uint32_t)((uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull);
}

void PlatformSleepMs(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
    nanosleep(&ts, NULL);
}

#endif
