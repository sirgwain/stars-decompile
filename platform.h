#ifndef STARS_PLATFORM_H_
#define STARS_PLATFORM_H_

#include <stdint.h>

/* Cross-platform shims for the small amount of Win16/Win32 UI glue that leaked
 * into core code (notably IO::FLoadGame error cleanup).
 */

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

#endif /* STARS_PLATFORM_H_ */
