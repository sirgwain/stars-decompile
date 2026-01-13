#ifndef DEBUGLOG_H_
#define DEBUGLOG_H_

/*
 * Simple debug logging for the decompile.
 *
 * - Compiles out in non-Debug builds (unless STARS_DEBUG_LOG is forced on).
 * - Runtime level can be controlled with env var STARS_LOG_LEVEL:
 *     error|warn|info|debug|trace (case-insensitive)
 */

#include <stddef.h>
#include <stdint.h>

typedef enum DebugLogLevel
{
    DBGLOG_ERROR = 0,
    DBGLOG_WARN  = 1,
    DBGLOG_INFO  = 2,
    DBGLOG_DEBUG = 3,
    DBGLOG_TRACE = 4,
} DebugLogLevel;

/* Set the minimum level that will be printed. */
void DbgLogSetLevel(DebugLogLevel level);

/* Get the current minimum level. */
DebugLogLevel DbgLogGetLevel(void);

/* Initialize from environment (safe to call multiple times). */
void DbgLogInitFromEnv(void);

/* Core logger (printf-style). */
void DbgLogPrintf(DebugLogLevel level,
                  const char *file,
                  int line,
                  const char *func,
                  const char *fmt,
                  ...);

/* Hex dump (at most max_bytes printed; 0 => no limit). */
void DbgLogHexDump(DebugLogLevel level,
                   const char *file,
                   int line,
                   const char *func,
                   const void *data,
                   size_t len,
                   size_t max_bytes,
                   const char *label);

/*
 * Build gating.
 *
 * CMake defines STARS_DEBUG in Debug builds. You can force-enable logging in
 * other configs by defining STARS_DEBUG_LOG.
 */
#if defined(STARS_DEBUG) || defined(STARS_DEBUG_LOG)

#define DBG_LOGE(...) DbgLogPrintf(DBGLOG_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define DBG_LOGW(...) DbgLogPrintf(DBGLOG_WARN,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define DBG_LOGI(...) DbgLogPrintf(DBGLOG_INFO,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define DBG_LOGD(...) DbgLogPrintf(DBGLOG_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define DBG_LOGT(...) DbgLogPrintf(DBGLOG_TRACE, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define DBG_HEXDUMP(level, data, len, max_bytes, label) \
    DbgLogHexDump((level), __FILE__, __LINE__, __func__, (data), (len), (max_bytes), (label))

#else

/* Compiled out. */
#define DBG_LOGE(...) ((void)0)
#define DBG_LOGW(...) ((void)0)
#define DBG_LOGI(...) ((void)0)
#define DBG_LOGD(...) ((void)0)
#define DBG_LOGT(...) ((void)0)
#define DBG_HEXDUMP(level, data, len, max_bytes, label) ((void)0)

#endif

#endif /* DEBUGLOG_H_ */
