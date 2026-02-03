/* port.h - minimal portable helpers (no external deps) */

#ifndef STARS_PORT_H
#define STARS_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Path utilities                                                      */
/* ------------------------------------------------------------------ */

bool Port_PathJoin(char *out, size_t out_sz, const char *base, const char *leaf);
bool Port_PathExists(const char *path);
bool Port_EnsureDirRecursive(const char *path);

/*
 * Split a path into base (without extension) and extension.
 * Example: "foo/bar/TEST.HST" -> base="foo/bar/TEST", ext="HST"
 * The extension is returned WITHOUT the leading dot.
 * If no extension, ext_out will be empty string.
 * Returns false if output buffers are too small.
 */
bool Port_PathSplitExt(const char *path, char *base_out, size_t base_sz,
                       char *ext_out, size_t ext_sz);

/* Get just the filename from a path (no directory). */
const char *Port_PathBasename(const char *path);

/* Get directory portion of path into out buffer. Returns false if buffer too small. */
bool Port_PathDirname(const char *path, char *out, size_t out_sz);

/* ------------------------------------------------------------------ */
/* File I/O                                                            */
/* ------------------------------------------------------------------ */

bool Port_ReadFile(const char *path, uint8_t **out_buf, size_t *out_len);

/* Atomic write (temp + rename/replace). Creates parent dirs if you do that separately. */
bool Port_WriteFileAtomic(const char *path, const void *buf, size_t len);

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
bool Port_ParseCommandLine(int argc, const char *const *argv, StarsCli *out_cli);

#endif /* STARS_PORT_H */
