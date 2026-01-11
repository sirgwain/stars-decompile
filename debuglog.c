#include "debuglog.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static DebugLogLevel g_level = DBGLOG_WARN;
static int g_inited = 0;

static const char *level_to_str(DebugLogLevel level)
{
    switch (level)
    {
    case DBGLOG_ERROR: return "ERROR";
    case DBGLOG_WARN:  return "WARN";
    case DBGLOG_INFO:  return "INFO";
    case DBGLOG_DEBUG: return "DEBUG";
    case DBGLOG_TRACE: return "TRACE";
    default:           return "LOG";
    }
}

static DebugLogLevel parse_level(const char *s)
{
    char buf[32];
    size_t n;

    if (s == NULL)
        return g_level;

    n = strlen(s);
    if (n >= sizeof(buf))
        n = sizeof(buf) - 1;

    for (size_t i = 0; i < n; i++)
        buf[i] = (char)tolower((unsigned char)s[i]);
    buf[n] = '\0';

    if (strcmp(buf, "error") == 0 || strcmp(buf, "err") == 0)
        return DBGLOG_ERROR;
    if (strcmp(buf, "warn") == 0 || strcmp(buf, "warning") == 0)
        return DBGLOG_WARN;
    if (strcmp(buf, "info") == 0)
        return DBGLOG_INFO;
    if (strcmp(buf, "debug") == 0)
        return DBGLOG_DEBUG;
    if (strcmp(buf, "trace") == 0)
        return DBGLOG_TRACE;

    /* Allow numeric: 0..4 */
    if (buf[0] >= '0' && buf[0] <= '4' && buf[1] == '\0')
        return (DebugLogLevel)(buf[0] - '0');

    return g_level;
}

void DbgLogSetLevel(DebugLogLevel level)
{
    if (level < DBGLOG_ERROR)
        level = DBGLOG_ERROR;
    if (level > DBGLOG_TRACE)
        level = DBGLOG_TRACE;
    g_level = level;
}

DebugLogLevel DbgLogGetLevel(void)
{
    return g_level;
}

void DbgLogInitFromEnv(void)
{
    if (g_inited)
        return;

#if defined(STARS_DEBUG) || defined(STARS_DEBUG_LOG)
    /* In Debug builds, default to DEBUG unless overridden. */
    g_level = DBGLOG_DEBUG;
#else
    g_level = DBGLOG_WARN;
#endif

    {
        const char *s = getenv("STARS_LOG_LEVEL");
        if (s != NULL && s[0] != '\0')
        {
            g_level = parse_level(s);
        }
    }

    g_inited = 1;
}

void DbgLogPrintf(DebugLogLevel level,
                  const char *file,
                  int line,
                  const char *func,
                  const char *fmt,
                  ...)
{
    va_list ap;

    DbgLogInitFromEnv();
    if (level > g_level)
        return;

    /* Keep output parseable and grep-friendly. */
    fprintf(stderr, "[%-5s] %s:%d %s: ", level_to_str(level), file, line, func);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
    fflush(stderr);
}

void DbgLogHexDump(DebugLogLevel level,
                   const char *file,
                   int line,
                   const char *func,
                   const void *data,
                   size_t len,
                   size_t max_bytes,
                   const char *label)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t n = len;
    size_t off = 0;

    DbgLogInitFromEnv();
    if (level > g_level)
        return;

    if (max_bytes != 0 && n > max_bytes)
        n = max_bytes;

    if (label == NULL)
        label = "hexdump";

    fprintf(stderr, "[%-5s] %s:%d %s: %s (%zu bytes%s)\n",
            level_to_str(level), file, line, func, label, n, (n < len) ? ", truncated" : "");

    while (off < n)
    {
        char ascii[17];
        size_t chunk = (n - off);
        if (chunk > 16)
            chunk = 16;

        for (size_t i = 0; i < 16; i++)
        {
            if (i < chunk)
            {
                uint8_t b = p[off + i];
                ascii[i] = (char)((b >= 32 && b < 127) ? b : '.');
            }
            else
            {
                ascii[i] = ' ';
            }
        }
        ascii[16] = '\0';

        fprintf(stderr, "  %04zx: ", off);
        for (size_t i = 0; i < 16; i++)
        {
            if (i < chunk)
                fprintf(stderr, "%02x ", (unsigned)p[off + i]);
            else
                fprintf(stderr, "   ");
        }
        fprintf(stderr, " |%s|\n", ascii);

        off += chunk;
    }

    fflush(stderr);
}
