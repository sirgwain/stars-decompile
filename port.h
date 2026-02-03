/* port.h - minimal portable helpers (no external deps) */

#ifndef STARS_PORT_H
#define STARS_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* io.h is Windows-specific; use unistd.h on other platforms or when using stubs */
#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
#include <io.h>
#define Stars_Access       _access
#define STARS_ACCESS_OK    F_OK
#define STARS_ACCESS_WRITE W_OK /* MSVCRT _access: 2 == write permission check */
#else
#include <unistd.h>
#define Stars_Access       access
#define STARS_ACCESS_OK    F_OK
#define STARS_ACCESS_WRITE W_OK /* POSIX access(): W_OK checks write permission */
#endif

/* ------------------------------------------------------------------ */
/* String utilities.                                                  */
/* ------------------------------------------------------------------ */
int Stars_stricmp(const char *a, const char *b);
int Stars_strnicmp(const char *a, const char *b, size_t n);
/* ------------------------------------------------------------------ */
/* Path utilities                                                      */
/* ------------------------------------------------------------------ */

bool Stars_PathJoin(char *out, size_t out_sz, const char *base, const char *leaf);
bool Stars_PathExists(const char *path);
bool Stars_EnsureDirRecursive(const char *path);

/*
 * Split a path into base (without extension) and extension.
 * Example: "foo/bar/TEST.HST" -> base="foo/bar/TEST", ext="HST"
 * The extension is returned WITHOUT the leading dot.
 * If no extension, ext_out will be empty string.
 * Returns false if output buffers are too small.
 */
bool Stars_PathSplitExt(const char *path, char *base_out, size_t base_sz, char *ext_out, size_t ext_sz);

/* Get just the filename from a path (no directory). */
const char *Stars_PathBasename(const char *path);

/* Get directory portion of path into out buffer. Returns false if buffer too small. */
bool Stars_PathDirname(const char *path, char *out, size_t out_sz);

/* ------------------------------------------------------------------ */
/* File I/O                                                            */
/* ------------------------------------------------------------------ */

/*
 * Portable file handle wrapper (replaces Win16 HFILE + _lread/_lclose/_lseek)
 *
 * Keep the global name `hf` so callers don't change.
 */
typedef struct StarsFile {
    FILE *fp;
    int   last_errno; /* capture errno from last open attempt */
} StarsFile;

extern StarsFile hf;

/* mdOpen flags (passed to StreamOpen / FOpenFile) */
typedef enum MdOpenFlags {
    mdRead = 0x0020,
    mdNoOpenErr = 0x4000,
} MdOpenFlags;

int      Stars_OpenFile(StarsFile *h, const char *path, int16_t mdOpen);
void     Stars_CloseFile(StarsFile *h);
size_t   Stars_Read(StarsFile *h, void *dst, size_t cb);
int      Stars_Seek(StarsFile *h, long offset, int whence);
uint16_t Stars_ReadU16Unaligned(const void *p);

/* Atomic write (temp + rename/replace). Creates parent dirs if you do that separately. */
bool Stars_WriteFileAtomic(const char *path, const void *buf, size_t len);
bool Stars_ReadFile(const char *path, uint8_t **out_buf, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Command-line parsing                                                */
/* ------------------------------------------------------------------ */

typedef struct StarsCli {
    /* Startup */
    const char *startup_file; /* positional */

    /* Flags */
    bool fNewGame;    /* -A */
    bool fBatchMode;  /* implied by -B */
    bool fCmdStartup; /* -C */
    bool fTry;        /* -T */
    bool fWait;       /* -W */
    bool fLog;        /* -L */
    bool fValidate;   /* -V */
    bool fHotseat;    /* -H */
    bool fExit;       /* -X */

    /* Options with args */
    const char *batch_file; /* -B <file> */
    int16_t     gen_turns;  /* -G<number> or -G <number>, -1 if absent */
    const char *password;   /* -P <password> */

    /* Dump flags (-D[fpm]) */
    bool dump_fleet;
    bool dump_planet;
    bool dump_map;
} StarsCli;

/* Parse argv into StarsCli. Returns false on any error (unknown option, missing arg, etc.). */
bool Stars_ParseCommandLine(int argc, const char *const *argv, StarsCli *out_cli);

#endif /* STARS_PORT_H */
