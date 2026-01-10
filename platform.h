#ifndef STARS_PLATFORM_H_
#define STARS_PLATFORM_H_

#include <stdint.h>

/* Cross-platform shims for the small amount of Win16/Win32 UI glue that leaked
 * into core code (notably IO::FLoadGame error cleanup).
 */

/* The codebase models HWND as a 16-bit handle (matching Win16). */
typedef uint16_t StarsHWND;

/* Return primary display size in pixels.
 *
 * These are only used to size a temporary splash/title window on error paths.
 */
int16_t PlatformScreenWidth(void);
int16_t PlatformScreenHeight(void);

/* Create a fullscreen-ish popup window.
 *
 * On non-Windows platforms this is a no-op stub that returns a non-zero handle.
 */
StarsHWND PlatformCreatePopupWindow(const char *class_name,
                                   const char *title,
                                   int32_t style,
                                   int16_t x,
                                   int16_t y,
                                   int16_t w,
                                   int16_t h,
                                   StarsHWND parent);

/* Show/hide a window (used for hiding the main frame when the title window is
 * shown). On non-Windows platforms this is a no-op.
 */
void PlatformShowWindow(StarsHWND hwnd, int32_t cmd);

/* Destroy a window avoid direct Win32 dependency in core. */
void PlatformDestroyWindow(StarsHWND hwnd);

/* INI write helper (used for MRU list maintenance). Returns non-zero on
 * success.
 */
int32_t PlatformWritePrivateProfileString(const char *section,
                                         const char *key,
                                         const char *value,
                                         const char *file_path);

/* Monotonic tick count and sleep used by StreamOpen retry logic. */
uint32_t PlatformTickMs(void);
void PlatformSleepMs(uint32_t ms);

/* Minimal style/cmd constants used by core code. The Windows implementation
 * maps these to the real Win32 constants.
 */
enum
{
    PLAT_WS_VISIBLE = 0x00000001,
    PLAT_WS_POPUP   = 0x00000002,

    PLAT_SW_HIDE = 0,
    PLAT_SW_SHOW = 1,
};

#endif /* STARS_PLATFORM_H_ */
