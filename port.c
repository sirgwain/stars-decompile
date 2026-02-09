/* port.c - minimal portable helpers (no external deps) */

#include "port.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
#define WIN32_LEAN_AND_MEAN
#include <direct.h> /* _mkdir */
#include <windows.h>
#elif defined(_WIN32) && defined(STARS_USE_WIN_STUBS)
/* When building with the Win32 stub layer on non-Windows hosts, avoid pulling
 * Windows system headers. The stub headers provide the Windows-like API.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "win_stubs.h"
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

// global file handle
StarsFile hf = {0};

/* ------------------------------------------------------------------ */
/* String utilities.                                                  */
/* ------------------------------------------------------------------ */

/* The original used the MSVCRT case-insensitive helpers. Keep local shims to
 * avoid pulling platform headers.
 */
int Stars_stricmp(const char *a, const char *b) {
    unsigned char ca;
    unsigned char cb;
    while (*a && *b) {
        ca = (unsigned char)tolower((unsigned char)*a++);
        cb = (unsigned char)tolower((unsigned char)*b++);
        if (ca != cb)
            return (int)ca - (int)cb;
    }
    return (int)tolower((unsigned char)*a) - (int)tolower((unsigned char)*b);
}

int Stars_strnicmp(const char *a, const char *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)tolower((unsigned char)a[i]);
        unsigned char cb = (unsigned char)tolower((unsigned char)b[i]);
        if (ca != cb)
            return (int)ca - (int)cb;
        if (a[i] == '\0' || b[i] == '\0')
            break;
    }
    return 0;
}

/* ====================================================================== */
/* Small internal helpers                                                  */
/* ====================================================================== */

/* mdOpen mapping:
 * - original passed mdOpen & 0xbfff to OpenFile()
 * - we map common cases you likely use in Stars:
 *     0 => "rb"
 *     1 => "r+b" (read/write existing)
 *     2 => "wb"  (truncate/create)
 * If your project already has an mdOpen enum, adjust here.
 */
static inline const char *stars_mode_from_md(int16_t mdOpen) {
    mdOpen = (int16_t)(mdOpen & (int16_t)~mdNoOpenErr);

    if (mdOpen & 0x1000) {
        return "w+b"; /* OF_CREATE | OF_READWRITE: create/truncate for read/write */
    }

    switch (mdOpen) {
    case 2:
        return "wb";
    case 1:
        return "r+b";
    default:
        return "rb";
    }
}

/* Portable "OpenFile": returns 0 on success, nonzero on failure (like hf == -1 check). */
int Stars_OpenFile(StarsFile *h, const char *path, int16_t mdOpen) {
    const char *mode = stars_mode_from_md(mdOpen);

    errno = 0;
    h->fp = fopen(path, mode);
    if (!h->fp) {
        h->last_errno = errno;

        fprintf(stderr,
                "Stars_OpenFile: fopen failed\n"
                "  path: \"%s\"\n"
                "  mode: \"%s\"\n"
                "  errno: %d (%s)\n",
                path, mode ? mode : "(null)", errno, strerror(errno));

        return 1;
    }

    h->last_errno = 0;
    return 0;
}

void Stars_CloseFile(StarsFile *h) {
    if (h->fp) {
        fclose(h->fp);
        h->fp = NULL;
    }
    h->last_errno = 0;
}

size_t Stars_Read(StarsFile *h, void *dst, size_t cb) {
    if (!h->fp)
        return 0;
    return fread(dst, 1, cb, h->fp);
}

int Stars_Seek(StarsFile *h, long offset, int whence) {
    if (h == NULL || h->fp == NULL) {
        return -1;
    }
    return fseek(h->fp, offset, whence);
}

size_t Stars_Write(StarsFile *h, const void *src, size_t cb) {
    if (h == NULL || h->fp == NULL) {
        return 0;
    }
    if (cb == 0) {
        return 0;
    }
    if (src == NULL) {
        return 0;
    }

    const uint8_t *p = (const uint8_t *)src;
    size_t         written = 0;

    while (written < cb) {
        size_t n = fwrite(p + written, 1, cb - written, h->fp);
        if (n == 0) {
            /* fwrite wrote nothing: error or inability to progress */
            break;
        }
        written += n;
    }

    return written;
}

uint16_t Stars_ReadU16Unaligned(const void *p) {
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

/* Stream helper: treat EOF like the Win16 macro. */
bool Stars_AtEOF(StarsFile *h) {
    FILE *fp = h->fp;
    long  pos = ftell(fp);
    if (pos < 0)
        return true;

    if (fseek(fp, 0, SEEK_END) != 0)
        return true;

    long end = ftell(fp);
    if (end < 0)
        return true;

    /* Restore position */
    fseek(fp, pos, SEEK_SET);

    return pos >= end;
}

static char Port_PathSep(void) {
#if defined(_WIN32)
    return '\\';
#else
    return '/';
#endif
}

static bool Port_IsSep(char c) { return (c == '/') || (c == '\\'); }

static bool Port_IsOptPrefix(char c) { return (c == '-') || (c == '/'); }

static bool Port_StrEq(const char *a, const char *b) { return strcmp(a, b) == 0; }

#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
static bool Port_Utf8ToWide(const char *u8, wchar_t **out_wide) {
    *out_wide = NULL;
    if (!u8)
        return false;

    int needed = MultiByteToWideChar(CP_UTF8, 0, u8, -1, NULL, 0);
    if (needed <= 0)
        return false;

    wchar_t *w = (wchar_t *)malloc((size_t)needed * sizeof(wchar_t));
    if (!w)
        return false;

    if (MultiByteToWideChar(CP_UTF8, 0, u8, -1, w, needed) <= 0) {
        free(w);
        return false;
    }

    *out_wide = w;
    return true;
}
#elif defined(_WIN32) && defined(STARS_USE_WIN_STUBS)
static bool Port_Utf8ToWide(const char *u8, wchar_t **out_wide) {
    /* Stub build: best-effort ASCII/UTF-8 widening (sufficient for tests). */
    *out_wide = NULL;
    if (!u8)
        return false;

    size_t   n = strlen(u8);
    wchar_t *w = (wchar_t *)malloc((n + 1) * sizeof(wchar_t));
    if (!w)
        return false;

    for (size_t i = 0; i <= n; i++) {
        w[i] = (wchar_t)(uint8_t)u8[i];
    }

    *out_wide = w;
    return true;
}
#endif

/* ====================================================================== */
/* Path utilities                                                          */
/* ====================================================================== */

bool Stars_PathJoin(char *out, size_t out_sz, const char *base, const char *leaf) {
    if (!out || out_sz == 0 || !base || !leaf)
        return false;

    size_t bl = strlen(base);
    size_t ll = strlen(leaf);

    /* Need: base + (sep?) + leaf + '\0' */
    size_t need = bl + ll + 1;
    if (bl > 0 && !Port_IsSep(base[bl - 1]))
        need += 1;

    if (need > out_sz)
        return false;

    memcpy(out, base, bl);
    size_t pos = bl;

    if (pos > 0 && !Port_IsSep(out[pos - 1])) {
        out[pos++] = Port_PathSep();
    }

    memcpy(out + pos, leaf, ll);
    out[pos + ll] = '\0';
    return true;
}

bool Stars_PathExists(const char *path) {
    if (!path || !*path)
        return false;

#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
    wchar_t *w = NULL;
    if (!Port_Utf8ToWide(path, &w))
        return false;
    DWORD attr = GetFileAttributesW(w);
    free(w);
    return attr != INVALID_FILE_ATTRIBUTES;
#else
    struct stat st;
    return stat(path, &st) == 0;
#endif
}

static bool Port_MkdirOne(const char *path) {
#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
    /* Use _mkdir for narrow paths; for full UTF-8 correctness, use CreateDirectoryW.
       Here we do UTF-8 -> wide and call CreateDirectoryW. */
    wchar_t *w = NULL;
    if (!Port_Utf8ToWide(path, &w))
        return false;
    BOOL  ok = CreateDirectoryW(w, NULL);
    DWORD err = GetLastError();
    free(w);
    if (ok)
        return true;
    return (err == ERROR_ALREADY_EXISTS);
#else
    if (mkdir(path, 0777) == 0)
        return true;
    return errno == EEXIST;
#endif
}

bool Stars_EnsureDirRecursive(const char *path) {
    if (!path || !*path)
        return false;

    /* Work on a mutable copy */
    size_t n = strlen(path);
    char  *tmp = (char *)malloc(n + 1);
    if (!tmp)
        return false;
    memcpy(tmp, path, n + 1);

    /* Trim trailing separators */
    while (n > 1 && Port_IsSep(tmp[n - 1])) {
        tmp[n - 1] = '\0';
        n--;
    }

    /* Create progressively */
    for (size_t i = 1; tmp[i] != '\0'; i++) {
        if (Port_IsSep(tmp[i])) {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (*tmp && !Port_MkdirOne(tmp)) {
                tmp[i] = saved;
                free(tmp);
                return false;
            }
            tmp[i] = saved;
        }
    }

    /* Create full path */
    if (*tmp && !Port_MkdirOne(tmp)) {
        free(tmp);
        return false;
    }

    free(tmp);
    return true;
}

bool Stars_PathSplitExt(const char *path, char *base_out, size_t base_sz, char *ext_out, size_t ext_sz) {
    if (!path || !base_out || base_sz == 0 || !ext_out || ext_sz == 0)
        return false;

    size_t len = strlen(path);

    /* Find last dot and last separator */
    const char *last_dot = NULL;
    const char *last_sep = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '.')
            last_dot = p;
        if (Port_IsSep(*p))
            last_sep = p;
    }

    /* Dot must be after last separator to be an extension */
    if (last_dot && (!last_sep || last_dot > last_sep)) {
        size_t base_len = (size_t)(last_dot - path);
        size_t ext_len = len - base_len - 1; /* -1 for the dot */

        if (base_len + 1 > base_sz || ext_len + 1 > ext_sz)
            return false;

        memcpy(base_out, path, base_len);
        base_out[base_len] = '\0';

        memcpy(ext_out, last_dot + 1, ext_len);
        ext_out[ext_len] = '\0';
    } else {
        /* No extension */
        if (len + 1 > base_sz)
            return false;
        memcpy(base_out, path, len + 1);
        ext_out[0] = '\0';
    }

    return true;
}

const char *Stars_PathBasename(const char *path) {
    if (!path || !*path)
        return path;

    const char *last_sep = NULL;
    for (const char *p = path; *p; p++) {
        if (Port_IsSep(*p))
            last_sep = p;
    }

    return last_sep ? (last_sep + 1) : path;
}

bool Stars_PathDirname(const char *path, char *out, size_t out_sz) {
    if (!path || !out || out_sz == 0)
        return false;

    const char *last_sep = NULL;
    for (const char *p = path; *p; p++) {
        if (Port_IsSep(*p))
            last_sep = p;
    }

    if (!last_sep) {
        /* No directory component, return "." */
        if (out_sz < 2)
            return false;
        out[0] = '.';
        out[1] = '\0';
        return true;
    }

    size_t dir_len = (size_t)(last_sep - path);
    if (dir_len == 0)
        dir_len = 1; /* Root directory case */

    if (dir_len + 1 > out_sz)
        return false;

    memcpy(out, path, dir_len);
    out[dir_len] = '\0';
    return true;
}

/* ====================================================================== */
/* File I/O                                                                */
/* ====================================================================== */

bool Stars_ReadFile(const char *path, uint8_t **out_buf, size_t *out_len) {
    if (!out_buf || !out_len)
        return false;
    *out_buf = NULL;
    *out_len = 0;

    if (!path || !*path)
        return false;

#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
    /* Use _wfopen for UTF-8 path correctness */
    wchar_t *wpath = NULL;
    if (!Port_Utf8ToWide(path, &wpath))
        return false;

    FILE *f = _wfopen(wpath, L"rb");
    free(wpath);
#else
    FILE *f = fopen(path, "rb");
#endif
    if (!f)
        return false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }

    long end = ftell(f);
    if (end < 0) {
        fclose(f);
        return false;
    }
    size_t len = (size_t)end;

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }

    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    if (!buf) {
        fclose(f);
        return false;
    }

    size_t got = 0;
    if (len) {
        got = fread(buf, 1, len, f);
        if (got != len) {
            free(buf);
            fclose(f);
            return false;
        }
    }

    fclose(f);
    *out_buf = buf;
    *out_len = got;
    return true;
}

static bool Port_WriteAll(FILE *f, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        size_t n = fwrite(p, 1, len, f);
        if (n == 0)
            return false;
        p += n;
        len -= n;
    }
    return true;
}

#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
static bool Port_TempPathForTarget(const char *target_u8, char *out, size_t out_sz) {
    /* Create sibling temp file: <target>.tmp */
    size_t      tl = strlen(target_u8);
    const char *suffix = ".tmp";
    size_t      sl = strlen(suffix);

    if (tl + sl + 1 > out_sz)
        return false;
    memcpy(out, target_u8, tl);
    memcpy(out + tl, suffix, sl + 1);
    return true;
}
#else
static bool Port_MkTempSibling(const char *target, char *out, size_t out_sz) {
    /* Sibling temp: <target>.tmpXXXXXX */
    const char *suffix = ".tmpXXXXXX";
    size_t      tl = strlen(target);
    size_t      sl = strlen(suffix);
    if (tl + sl + 1 > out_sz)
        return false;
    memcpy(out, target, tl);
    memcpy(out + tl, suffix, sl + 1);
    return true;
}
#endif

bool Stars_WriteFileAtomic(const char *path, const void *buf, size_t len) {
    if (!path || !*path)
        return false;
    if (len && !buf)
        return false;

#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
    /* Write to sibling <path>.tmp then MoveFileExW(tmp, path, REPLACE_EXISTING). */
    char tmp_u8[4096];
    if (!Port_TempPathForTarget(path, tmp_u8, sizeof(tmp_u8)))
        return false;

    wchar_t *wtmp = NULL;
    wchar_t *wpath = NULL;
    if (!Port_Utf8ToWide(tmp_u8, &wtmp))
        return false;
    if (!Port_Utf8ToWide(path, &wpath)) {
        free(wtmp);
        return false;
    }

    FILE *f = _wfopen(wtmp, L"wb");
    if (!f) {
        free(wtmp);
        free(wpath);
        return false;
    }

    bool ok = Port_WriteAll(f, buf, len);
    ok = ok && (fflush(f) == 0);
    ok = ok && (fclose(f) == 0);

    if (!ok) {
        _wremove(wtmp);
        free(wtmp);
        free(wpath);
        return false;
    }

    /* Replace destination */
    if (!MoveFileExW(wtmp, wpath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
        _wremove(wtmp);
        free(wtmp);
        free(wpath);
        return false;
    }

    free(wtmp);
    free(wpath);
    return true;

#else
    /* POSIX: mkstemp sibling then rename over target */
    char tmp[4096];
    if (!Port_MkTempSibling(path, tmp, sizeof(tmp)))
        return false;

    int fd = mkstemp(tmp);
    if (fd < 0)
        return false;

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlink(tmp);
        return false;
    }

    bool ok = Port_WriteAll(f, buf, len);
    ok = ok && (fflush(f) == 0);
    ok = ok && (fclose(f) == 0); /* closes fd too */

    if (!ok) {
        unlink(tmp);
        return false;
    }

    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }

    return true;
#endif
}

/* ====================================================================== */
/* Command-line parsing                                                    */
/* ====================================================================== */

static bool Cli_SetGenTurns(StarsCli *cli, const char *s) {
    if (!s || !*s)
        return false;
    long v = strtol(s, NULL, 10);
    if (v < -32768 || v > 32767)
        return false;
    cli->gen_turns = (int16_t)v;
    return true;
}

static void Cli_ParseDumpModes(StarsCli *cli, const char *modes) {
    if (!modes)
        return;
    for (const char *p = modes; *p; p++) {
        if (*p == 'f' || *p == 'F')
            cli->dump_fleet = true;
        else if (*p == 'p' || *p == 'P')
            cli->dump_planet = true;
        else if (*p == 'm' || *p == 'M')
            cli->dump_map = true;
    }
}

bool Stars_ParseCommandLine(int argc, const char *const *argv, StarsCli *out_cli) {
    if (!out_cli)
        return false;
    memset(out_cli, 0, sizeof(*out_cli));
    out_cli->gen_turns = -1;

    /* Simple argv scanner:
       - handles -LVW combined flags
       - handles /LVW too
       - handles -g10 and -g 10 (also -G10 / -G 10)
       - handles -DFP and -D FP
       - stops option parsing at "--"
    */

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!a || !*a)
            continue;

        if (Port_StrEq(a, "--")) {
            /* rest are positional */
            i++;
            if (i < argc && !out_cli->startup_file)
                out_cli->startup_file = argv[i];
            /* ignore additional positional args */
            break;
        }

        if (!Port_IsOptPrefix(a[0]) || a[1] == '\0') {
            if (!out_cli->startup_file)
                out_cli->startup_file = a;
            continue;
        }

        /* Process a cluster: -LVW or /DFP etc. */
        const char *p = a + 1;
        while (*p) {
            char ch = *p++;

            switch (ch) {
            case 'a':
            case 'A':
                out_cli->fNewGame = true;
                break;
            case 'C':
                out_cli->fCmdStartup = true;
                break;
            case 'T':
                out_cli->fTry = true;
                break;
            case 'W':
                out_cli->fWait = true;
                break;
            case 'L':
                out_cli->fLog = true;
                break;
            case 'V':
                out_cli->fValidate = true;
                break;
            case 'H':
                out_cli->fHotseat = true;
                break;
            case 'X':
                out_cli->fExit = true;
                break;

            case 'B': {
                /* -B <file> or -Bfile */
                const char *arg = (*p) ? p : ((i + 1 < argc) ? argv[++i] : NULL);
                if (!arg || !*arg)
                    return false;
                out_cli->batch_file = arg;
                out_cli->fBatchMode = true;
                p = ""; /* consume rest of cluster */
            } break;

            case 'P': {
                const char *arg = (*p) ? p : ((i + 1 < argc) ? argv[++i] : NULL);
                if (!arg)
                    return false;
                out_cli->password = arg;
                p = "";
            } break;

            case 'g':
            case 'G': {
                const char *arg = (*p) ? p : ((i + 1 < argc) ? argv[++i] : NULL);
                if (!Cli_SetGenTurns(out_cli, arg))
                    return false;
                p = "";
            } break;

            case 'D': {
                /* -D[fpm] or -D fpm. If -D alone, treat as “enable all dumps”? choose policy.
                   Here: -D alone enables all dumps (handy + matches older tools). */
                const char *modes = NULL;
                if (*p) {
                    modes = p; /* attached */
                } else if (i + 1 < argc && argv[i + 1] && !Port_IsOptPrefix(argv[i + 1][0])) {
                    modes = argv[++i]; /* separate token */
                }

                if (!modes || !*modes) {
                    out_cli->dump_fleet = true;
                    out_cli->dump_planet = true;
                    out_cli->dump_map = true;
                } else {
                    Cli_ParseDumpModes(out_cli, modes);
                }

                p = "";
            } break;

            default:
                return false; /* unknown option */
            }
        }
    }

    return true;
}
