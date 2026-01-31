
#include "globals.h"
#include "resource.h"
#include "types.h"

#include "debuglog.h"
#include "strings.h"
#include "util.h"
#include "utilgen.h"

/* globals */
char    aPNCmpr[4099] = {0};
char    rgPNLookupTable[52] = "earonilstudchmpgb ykwfvzxjq'-10239M45G6C8AOSV7BDFIPR";
int16_t aiPNChunkOffset[16] = {0, 261, 540, 791, 1055, 1348, 1603, 1857, 2120, 2380, 2624, 2869, 3116, 3378, 3641, 3936};
int16_t rgPrimes[128] = {3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103,
                         107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
                         251, 257, 263, 279, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401,
                         409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571,
                         577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727};
uint8_t acPN[999] = {0};
extern const char *const aPNUncompressed[];

// Player string compress/decompress tables
char    rgchcomp[13] = "+-,!.?:;'*%$";
char   *rgchcompstrlower = " aehilnorstbcdfgjkmpquvwxyz";
int16_t rgcompstrlower[26] = {1, 77, 93, 109, 2, 125, 141, 3, 4, 157, 173, 5, 189, 6, 7, 205, 221, 8, 9, 10, 237, 253, 14, 30, 46, 62};

/* Returns the packed code (original returned short). */
int16_t NybbleFromCh(uint8_t ch) {
    uint16_t code;

    if (ch >= (uint8_t)'a' && ch <= (uint8_t)'z') {
        /* Lowercase uses a lookup table. */
        code = (uint16_t)rgcompstrlower[ch - (uint8_t)'a'];
        return (int16_t)code;
    }

    if (ch == (uint8_t)' ') {
        return 0;
    }

    /* Uppercase A..P => class 0xB, payload 0..15 */
    if (ch >= (uint8_t)'A' && ch <= (uint8_t)'P') {
        code = (uint16_t)((ch - (uint8_t)'A') << 4) | 0x0B;
        return (int16_t)code;
    }

    /* Q..Z => class 0xC, payload 0..9 */
    if (ch >= (uint8_t)'Q' && ch <= (uint8_t)'Z') {
        code = (uint16_t)((ch - (uint8_t)'Q') << 4) | 0x0C;
        return (int16_t)code;
    }

    /* '0'..'5' => also class 0xC, payload 10..15 (matches decompile's (ch - 0x26)) */
    if (ch >= (uint8_t)'0' && ch <= (uint8_t)'5') {
        code = (uint16_t)((ch - 0x26u) << 4) | 0x0C;
        return (int16_t)code;
    }

    /* '6'..'9' => class 0xD, payload 0..3 */
    if (ch >= (uint8_t)'6' && ch <= (uint8_t)'9') {
        code = (uint16_t)((ch - 0x36u) << 4) | 0x0D;
        return (int16_t)code;
    }

    /* Other chars: check special compressible set (class 0xE) */
    {
        const char *pch = strchr(rgchcomp, (int)ch);
        if (pch == NULL) {
            /* Literal escape: class 0xF, payload is the byte itself. */
            code = (uint16_t)((uint16_t)ch << 4) | 0x0F;
            return (int16_t)code;
        } else {
            /* class 0xE, payload is index into rgchcomp (0..11) */
            uint16_t idx = (uint16_t)(pch - rgchcomp) + 4; /* matches (pcVar1 - 0x13fc) */
            code = (uint16_t)(idx << 4) | 0x0E;
            return (int16_t)code;
        }
    }
}

/* Decode a packed token value back to a character (inverse of NybbleFromCh). */
char ChFromNybble(int16_t nyb) {
    uint16_t u = (uint16_t)nyb;

    /* 0..10: one-nibble codes index directly into " aehilnorst" */
    if (u < 11u) {
        return rgchcompstrlower[u];
    }

    /* low nibble 0xF: 3-nibble escape, literal byte in bits 4..11 */
    if ((u & 0x000Fu) == 0x000Fu) {
        return (char)((u >> 4) & 0x00FFu);
    }

    {
        uint8_t grp = (uint8_t)(u & 0x0Fu);        /* 0xB..0xE in valid data */
        uint8_t idx = (uint8_t)((u >> 4) & 0x0Fu); /* 0..15 */

        switch (grp) {
        case 0x0B: /* 'A'..'P' */
            return (char)('A' + idx);

        case 0x0C: /* 'Q'..'Z' then '0'..'5' */
            if (idx < 10)
                return (char)('Q' + idx);
            return (char)('0' + (idx - 10));

        case 0x0D: /* '6'..'9' then consonants "bcdfgjkmpquv" */
            if (idx < 4)
                return (char)('6' + idx);
            /* idx 4..15 -> 12 chars starting at 'b' within rgchcompstrlower (offset 11) */
            return rgchcompstrlower[11 + (idx - 4)];

        case 0x0E: /* 'wxyz' then punctuation rgchcomp */
            if (idx < 4)
                return (char)('w' + idx);
            /* idx 4..15 -> rgchcomp[0..11] */
            return rgchcomp[idx - 4];

        default:
            return '?';
        }
    }
}

/* Returns 1 on success, 0 on failure (output would exceed *pcOut). */
int16_t FDecompressUserString(char *szIn, int16_t cIn, char *szOut, int16_t *pcOut) {
    char  szWork[1024];
    char *pchOut = szWork;

    /* false => use high nibble; true => use low nibble and advance input byte */
    bool bHalf = false;

    while (cIn > 0) {
        int16_t  iNyb;
        int16_t  firstNyb;
        uint16_t uVar4;

        if (bHalf) {
            iNyb = (int16_t)((uint8_t)*szIn & 0x0F);
            cIn--;
            szIn++;

            if (iNyb == 0x0F && cIn == 0)
                break;
        } else {
            iNyb = (int16_t)(((uint8_t)*szIn >> 4) & 0x0F);
        }

        firstNyb = iNyb;
        bHalf = !bHalf;

        if ((uint16_t)iNyb > 10u) {
            if (bHalf) {
                uVar4 = (uint16_t)(((uint8_t)*szIn & 0x0F) << 4);
                cIn--;
                szIn++;
            } else {
                uVar4 = (uint16_t)((uint8_t)*szIn & 0xF0);
            }

            iNyb = (int16_t)((uint16_t)iNyb | uVar4);
            bHalf = !bHalf;

            if (firstNyb == 0x0F) {
                if (bHalf) {
                    uVar4 = (uint16_t)(((uint8_t)*szIn & 0x0F) << 8);
                    cIn--;
                    szIn++;
                } else {
                    uVar4 = (uint16_t)(((uint8_t)*szIn & 0xF0) << 4);
                }

                iNyb = (int16_t)((uint16_t)iNyb | uVar4);
                bHalf = !bHalf;
            }
        }

        *pchOut++ = ChFromNybble(iNyb);

        if (*pcOut < (int16_t)(pchOut - szWork))
            return 0;
    }

    *pchOut = '\0';
    strcpy(szOut, szWork);
    return 1;
}

/* Returns 1 on success, 0 on failure. On success, *pcOut is set to compressed byte count. */
int16_t FCompressUserString(char *szIn, char *szOut, int16_t *pcOut) {
    uint8_t  szWork[1024];
    uint8_t *pchOut = szWork;

    bool bHalf = false;

    for (;;) {
        if (*szIn == '\0') {
            if (bHalf) {
                *pchOut |= 0x0Fu;
                pchOut++;

                if ((pchOut - szWork) > (ptrdiff_t)sizeof(szWork))
                    return 0;
            }

            if ((int16_t)(pchOut - szWork) <= *pcOut) {
                *pcOut = (int16_t)(pchOut - szWork);
                memcpy(szOut, szWork, (size_t)*pcOut);
                return 1;
            }
            return 0;
        }

        int16_t iNyb = NybbleFromCh((uint8_t)*szIn);

        int16_t cNyb;
        if ((uint16_t)iNyb < 0x000Bu)
            cNyb = 1;
        else if (((uint16_t)iNyb & 0x000Fu) == 0x000Fu)
            cNyb = 3;
        else
            cNyb = 2;

        while (cNyb != 0) {
            uint8_t nib = (uint8_t)((uint16_t)iNyb & 0x0F);

            if (bHalf) {
                *pchOut |= nib;
                pchOut++;
                bHalf = false;

                if ((pchOut - szWork) > 0x3FF)
                    return 0;
            } else {
                *pchOut = (uint8_t)(nib << 4);
                bHalf = true;
            }

            iNyb = (int16_t)(iNyb >> 4);
            cNyb--;
        }

        szIn++;
    }
}

/* functions */

void ShowProgressGauge(void) { /* TODO: implement */ }

int16_t FCheckPassword(void) {
    HWND    hwndParent;
    int32_t lSaltDef;

    if ((lSaltCur == 0) || (lSaltLast == lSaltCur) || (fAi != 0))
        return 1;

    if ((vszDefPass[0] == '\0') || ((lSaltDef = LSaltFromSz((char *)vszDefPass)) != lSaltCur)) {
        /* Original: (ini.wFlags >> 14) & 1
           INI bitfield: fValidate is bit 14 */
        if (ini.fValidate != 0)
            return 0;
#ifdef WIN32
        hwndParent = (hwndTitle != 0) ? hwndTitle : hwndFrame;

        {
            INT_PTR dlgResult = DialogBox(hInst, MAKEINTRESOURCE(IDD_PASSWORD), hwndParent, PasswordDlg);

            /* Win32: -1 means the dialog failed to create. Treat as failure. */
            if (dlgResult == (INT_PTR)-1)
                return 0;

            /* Contract per callers: only explicit success counts. */
            return (dlgResult == (INT_PTR)1) ? 1 : 0;
        }
#else
        // can't prompt, return failure with no ui
        return 0;
#endif
    }

    /* Default password matches current salt. */
    return 1;
}

int16_t CParseNumbers(char *psz, int32_t *pl, int16_t cMax) {
    int16_t iRead;
    int16_t fValid;
    int32_t lNum;

    /* TODO: implement */
    return 0;
}

void ExpandRc(RECT *prc, int16_t dx, int16_t dy) {
    prc->left = (int16_t)(prc->left - dx);
    prc->right = (int16_t)(prc->right + dx);
    prc->top = (int16_t)(prc->top - dy);
    prc->bottom = (int16_t)(prc->bottom + dy);
}

int16_t ReadBigBlock(int16_t hFile, char *lpBuffer, uint32_t dwSize) {
    // intentially left blank. Used to be called by HdibLoadBigResource, but we don't need to read it in chunks anymore
    return 0;
}

char *PszFromLongK(int32_t l, int16_t *pcch) {
    int16_t fExtraLarge;
    int16_t fLarge;
    char   *psz;

    /* TODO: implement */
    return NULL;
}

uint32_t GetDiskSerialNumber(void) {
    // we don't actually care about this and we certainly aren't replicating all the dos calls to get the original, so just
    // make the disk the same for every instance
    static const uint8_t fakeEnv[] = {'S', 'T', 'A', 'R', 'S', 0x26, 0x00};

    memcpy(vrgbEnvCur, fakeEnv, sizeof(fakeEnv));
    return sizeof(fakeEnv);
}

int16_t FIntersectCircleLine(POINT ptL1, POINT ptL2, POINT ptC, int32_t r2, int16_t dMax, int16_t *pdStart, int16_t *pdEnd) {
    int32_t dyT;
    int32_t dxdy;
    int16_t dCtr;
    int32_t dy2;
    int32_t dy;
    int32_t yI;
    int32_t dyI;
    int32_t dxT;
    int32_t lT;
    int32_t dx2;
    int16_t dOff;
    int32_t dx;
    int32_t dxI;
    int32_t xI;
    int32_t r2I;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x5464 */

    /* TODO: implement */
    return 0;
}

void Randomize2(uint32_t dw) {
    /* Indices derived from dw (7-bit) with XOR scramblers */
    uint16_t a = (uint16_t)(((uint16_t)dw & 0x7Fu) ^ 0x35u);
    uint16_t b = (uint16_t)((((uint16_t)(dw >> 1) & 0x7Fu) ^ 0x5Cu));

    /* Ensure different indices */
    if (a == b) {
        b = (uint16_t)((b + 1u) & 0x7Fu);
    }

    /* Load primes and sign-extend to 32-bit (matches CWD -> DX:AX) */
    lRandSeed1 = (int32_t)rgPrimes[a];
    lRandSeed2 = (int32_t)rgPrimes[b];
}

void Randomize(uint32_t dw) {
    /* Indices derived exactly like the assembly */
    uint16_t a = (uint16_t)(dw & 0x3Fu);
    uint16_t b = (uint16_t)((dw >> 1) & 0x3Fu);

    /* Ensure different indices */
    if (a == b) {
        b = (uint16_t)((b + 1u) & 0x3Fu);
    }

    /* Load primes and sign-extend to 32-bit */
    lRandSeed1 = (int32_t)rgPrimes[a];
    lRandSeed2 = (int32_t)rgPrimes[b];
}

// TODO: add bounds checking to make safer
int16_t CchGetString(StringId ids, char *psz) {
    char       *dst0 = psz;
    const char *src = PszGetCompressedString(ids);

    while (*src != '\0') {
        *psz++ = *src++;
    }
    *psz = '\0';

    /* number of chars copied (not including the NUL) */
    return (int16_t)(psz - dst0);
}

int32_t LSaltFromSz(char *psz) {
    const int8_t *s = (const int8_t *)psz; /* preserve signed-char semantics */
    uint32_t      salt = 0;

    if (*s == 0)
        return 0;

    for (;;) {
        /* add first char */
        salt += (int32_t)*s++;
        if (*s == 0)
            break;

        /* multiply by second char (unsigned 32-bit wrap like __aFulmul) */
        salt = (uint32_t)(salt * (uint32_t)(int32_t)*s++);
        if (*s == 0)
            break;
    }

    if (salt == 0)
        salt = 1;

    return (int32_t)salt;
}

void CopyStarsFile(char *szSrc, char *szDst) {
    char     rgb[2048];
    int16_t  fFileErrSav;
    OFSTRUCT of;
    MemJump  env;
    ;
    int16_t hfDst;
    int32_t cb;
    int16_t (*penvSav)[9];

    /* debug symbols */
    /* label LStreamError @ MEMORY_UTILGEN:0x2130 */

    /* TODO: implement */
}

uint32_t LGetNextFileXor(void) {
    /* Same core generator as Random(), but driven by file seeds and returning raw s1-s2. */
    const uint32_t q1 = 53668u, r1 = 12211u, a1 = 40014u, m1 = 2147483563u; /* 0x7FFFFFAB */
    const uint32_t q2 = 52774u, r2 = 3791u, a2 = 40692u, m2 = 2147483399u;  /* 0x7FFFFF07 */

    int32_t s1 = lFileSeed1;
    int32_t s2 = lFileSeed2;

    /* Update seed 1 */
    {
        uint32_t k = (uint32_t)s1 / q1;
        int32_t  s1mkq = (int32_t)((uint32_t)s1 - k * q1);
        s1 = (int32_t)(a1 * (uint32_t)s1mkq) - (int32_t)(r1 * k);
        if (s1 < 0) {
            s1 += (int32_t)m1;
        }
    }

    /* Update seed 2 */
    {
        uint32_t k = (uint32_t)s2 / q2;
        int32_t  s2mkq = (int32_t)((uint32_t)s2 - k * q2);
        s2 = (int32_t)(a2 * (uint32_t)s2mkq) - (int32_t)(r2 * k);
        if (s2 < 0) {
            s2 += (int32_t)m2;
        }
    }

    lFileSeed1 = s1;
    lFileSeed2 = s2;

    /* The decompile returns s1 - s2 without the "z<1 add m1-1" fixup. */
    return (uint32_t)(s1 - s2);
}

void BoundPoints(RECT *prc, POINT *rgpt, int16_t cpt) {
    if (prc == NULL || rgpt == NULL || cpt <= 0) {
        return;
    }

    int16_t xMin = rgpt[0].x;
    int16_t yMin = rgpt[0].y;
    int16_t xMax = xMin;
    int16_t yMax = yMin;

    for (int16_t ipt = 1; ipt < cpt; ++ipt) {
        const int16_t x = rgpt[ipt].x;
        const int16_t y = rgpt[ipt].y;

        if (x <= xMin)
            xMin = x;
        if (xMax <= x)
            xMax = x;

        if (y <= yMin)
            yMin = y;
        if (yMax <= y)
            yMax = y;
    }

    /* expand bounds by 1 in each direction (original did +/- 1) */
    prc->left = (int16_t)(xMin - 1);
    prc->top = (int16_t)(yMin - 1);
    prc->right = (int16_t)(xMax + 1);
    prc->bottom = (int16_t)(yMax + 1);
}

void ChopTrailingSpaces(char *pBeg, char **ppEnd) {
    while (pBeg < *ppEnd && (*ppEnd)[-1] == ' ') {
        *ppEnd = *ppEnd - 1;
    }
}

void PopRandom(void) {
    /* Original does not bounds-check. */
    cRandStack = (int16_t)(cRandStack - 1);

    /* Stack entry: [seed1, seed2] */
    lRandSeed1 = rglRandStack[(uint16_t)cRandStack][0];
    lRandSeed2 = rglRandStack[(uint16_t)cRandStack][1];
}

void SetFileSeeds(int32_t l1, int32_t l2) {
    lFileSeed1 = l1;
    lFileSeed2 = l2;
}

void GetFileSeeds(int32_t *pl1, int32_t *pl2) {
    /* Original assumes non-null pointers. */
    *pl1 = lFileSeed1;
    *pl2 = lFileSeed2;
}

void SetFileXorStream(int32_t lid, int16_t lSalt, int16_t turn, int16_t iPlayer, int16_t fCrippled) {
    /* Indices derived from salt (two 5-bit fields, then biased into 0..63). */
    uint16_t a = (uint16_t)(lSalt & 0x1F);
    uint16_t b = (uint16_t)(((uint16_t)lSalt >> 5) & 0x1F);

    if (((uint16_t)lSalt & 0x0400u) == 0) {
        b = (uint16_t)(b + 0x20u);
    } else {
        a = (uint16_t)(a + 0x20u);
    }

    /* Seeds come from rgPrimes (sign-extended like the original CWD). */
    lFileSeed1 = (int32_t)rgPrimes[a];
    lFileSeed2 = (int32_t)rgPrimes[b];

    DBG_LOGD("SetFileXorStream: lid=%ld salt=%d turn=%d iPlayer=%d crippled=%d -> idx a=%u b=%u seeds=(%ld,%ld)", (long)lid, (int)lSalt, (int)turn,
             (int)iPlayer, (int)fCrippled, (unsigned)a, (unsigned)b, (long)lFileSeed1, (long)lFileSeed2);

    /* Advance the stream a small, deterministic number of steps. */
    {
        int16_t n = (int16_t)((((lid & 3) + 1) * ((turn & 3) + 1) * ((iPlayer & 3) + 1)) + fCrippled);
        while (n > 0) {
            (void)LGetNextFileXor();
            n--;
        }
    }
}

void XorFileBuf(uint8_t *rgb, int16_t cb) {
    int32_t *pl = (int32_t *)rgb;
    int32_t *plMac = (int32_t *)(rgb + ((cb >> 2) << 2));
    int32_t  lPrev;
    uint8_t *pch;

    while (pl < plMac) {
        lPrev = (int32_t)LGetNextFileXor();
        pl[0] ^= lPrev;
        pl++;
    }

    if ((cb & 3) != 0) {
        pch = (uint8_t *)pl;
        lPrev = (int32_t)LGetNextFileXor();
        cb &= 3;
        while (cb--) {
            *pch++ ^= (uint8_t)lPrev;
            lPrev >>= 8;
        }
    }
}

char *PszGetLine(char **ppszBeg) {
    char *pszStart;
    char *psz;

    /* TODO: implement */
    return NULL;
}

int16_t Random(int16_t c) {
    /* Constants from the original generator (L'Ecuyer combined LCG). */
    const uint32_t q1 = 53668u, r1 = 12211u, a1 = 40014u, m1 = 2147483563u; /* 0x7FFFFFAB */
    const uint32_t q2 = 52774u, r2 = 3791u, a2 = 40692u, m2 = 2147483399u;  /* 0x7FFFFF07 */

    int32_t s1 = lRandSeed1;
    int32_t s2 = lRandSeed2;

    /* If c < 1, original returns 0 and does not commit new seeds. */
    if (c < 1) {
        return 0;
    }

    /* Update seed 1: k = s1 / q1; s1 = a1*(s1 - k*q1) - k*r1; if (s1 < 0) s1 += m1; */
    {
        uint32_t k = (uint32_t)s1 / q1;
        int32_t  s1mkq = (int32_t)((uint32_t)s1 - k * q1); /* preserve unsigned low-32 behavior */
        s1 = (int32_t)(a1 * (uint32_t)s1mkq) - (int32_t)(r1 * k);
        if (s1 < 0) {
            s1 += (int32_t)m1;
        }
    }

    /* Update seed 2: k = s2 / q2; s2 = a2*(s2 - k*q2) - k*r2; if (s2 < 0) s2 += m2; */
    {
        uint32_t k = (uint32_t)s2 / q2;
        int32_t  s2mkq = (int32_t)((uint32_t)s2 - k * q2);
        s2 = (int32_t)(a2 * (uint32_t)s2mkq) - (int32_t)(r2 * k);
        if (s2 < 0) {
            s2 += (int32_t)m2;
        }
    }

    /* Combine: z = s1 - s2; if (z < 1) z += (m1 - 1); */
    {
        int32_t z = s1 - s2;
        if (z < 1) {
            z += (int32_t)(m1 - 1u); /* 2147483562 == 0x7FFFFFAA */
        }

        lRandSeed1 = s1;
        lRandSeed2 = s2;

        /* Original uses unsigned remainder; c is positive here. */
        return (int16_t)((uint32_t)z % (uint32_t)(uint16_t)c);
    }
}

char *PszFromLong(int32_t l, int16_t *pcch) {
    int16_t cch;

    cch = (int16_t)sprintf(szFormatNumber, PCTLD, (long)l);
    if (pcch != NULL) {
        *pcch = cch;
    }
    return szFormatNumber;
}

void PushRandom(int32_t lNew1, int32_t lNew2) {
    /* Save current seeds on stack (no bounds-check in original). */
    rglRandStack[(uint16_t)cRandStack][0] = lRandSeed1;
    rglRandStack[(uint16_t)cRandStack][1] = lRandSeed2;

    cRandStack = (int16_t)(cRandStack + 1);

    /* Install new seeds. */
    lRandSeed1 = lNew1;
    lRandSeed2 = lNew2;
}

void OffsetRc(RECT *prc, int16_t dx, int16_t dy) {
    prc->left = (int16_t)(prc->left + dx);
    prc->right = (int16_t)(prc->right + dx);
    prc->top = (int16_t)(prc->top + dy);
    prc->bottom = (int16_t)(prc->bottom + dy);
}

int16_t ICompLong(void *arg1, void *arg2) { return *(int32_t *)arg1 - *(int32_t *)arg2; }

char *PszFromInt(int16_t i, int16_t *pcch) {
    int16_t cch;

    cch = (int16_t)sprintf(szFormatNumber, PCTD, (int)i);
    if (pcch != NULL) {
        *pcch = cch;
    }
    return szFormatNumber;
}

void AddBackTrailingSpaces(char **ppch, char *pchEnd) {
    while (*ppch < pchEnd && **ppch == ' ') {
        *ppch = *ppch + 1;
    }
}

int32_t LDistance2(POINT pt1, POINT pt2) {
    int32_t dx = (int32_t)(int16_t)(pt1.x - pt2.x);
    int32_t dy = (int32_t)(int16_t)(pt1.y - pt2.y);

    return dx * dx + dy * dy;
}

void ChopLastWord(char *pBeg, char **ppEnd) {
    /* Strip trailing spaces */
    while (pBeg < *ppEnd && (*ppEnd)[-1] == ' ') {
        *ppEnd = *ppEnd - 1;
    }
    /* Strip trailing non-space word */
    while (pBeg < *ppEnd && (*ppEnd)[-1] != ' ') {
        *ppEnd = *ppEnd - 1;
    }
    /* Strip trailing spaces again */
    while (pBeg < *ppEnd && (*ppEnd)[-1] == ' ') {
        *ppEnd = *ppEnd - 1;
    }
}

void IntToRoman(int16_t i, char *pszOut) { /* TODO: implement */ }

void OutputFileString(char *szFile, char *sz) {
    FILE  *fp;
    size_t n;

    if (szFile == NULL || sz == NULL) {
        return;
    }

    /* Win16 logic:
       - if file doesn't exist -> create
       - open for write, seek to end, write strlen bytes, close
       "ab" matches this cross-platform: create if missing, append at end. */
    fp = fopen(szFile, "ab");
    if (fp == NULL) {
        return;
    }

    n = strlen(sz);
    if (n != 0) {
        (void)fwrite(sz, 1, n, fp);
    }

    (void)fclose(fp);
}

char *PszGetCompressedPlanet(int16_t id) {
    if (iLastGet == id) {
        return szLastGet;
    }
    iLastGet = id;
    strncpy(szLastGet, aPNUncompressed[id], sizeof(szLastGet));
    return szLastGet;
}

int16_t CommaFormatLong(char *psz, int32_t l) {
    char    rgch[15];
    int16_t c;
    int16_t cSkip;
    char   *pchOut;
    char   *pch;

    /* TODO: implement */
    return 0;
}

#ifdef _WIN32

int AlertSz(const char *sz, UINT mbType) {
    int  idResult;
    char szT[256];

    /*
     * Original logic (decoded):
     * if (!fValidate && (wFlags >= 0 || !fGen)) then MessageBox
     * else log via OutputSz and return IDYES
     */
    if ((ini.fValidate == 0) && ((ini.fLogging == 0) || (ini.fGen == 0))) {
        HWND hwnd = GetFocus();
        idResult = MessageBoxA(hwnd, sz, "Stars!", mbType);
    } else {
        /* Win16 wsprintf -> safe Win32 replacement */
        snprintf(szT, sizeof(szT), "Error: %s", sz);

        idResult = ini.fValidate ? IDNO : IDYES;
        OutputSz(idResult, szT);

        /* Original function always returns IDYES after OutputSz */
        idResult = IDYES;
    }

    return idResult;
}

INT_PTR CALLBACK RandomSeedDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    char     szValue[33];
    char    *pch;
    uint32_t dw;
    RECT     rc;

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK PasswordDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    char    szPass[60];
    RECT    rc;
    int32_t lSalt;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x5b3d */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK ProgressGaugeDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    PAINTSTRUCT ps;
    RECT        rc;
    int16_t     dy;
    char       *psz;
    int16_t     dx;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x648d */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK NewPasswordDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    char    szPass[20];
    RECT    rc;
    int32_t lSalt2;
    int32_t lSalt;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x5de8 */

    /* TODO: implement */
    return 0;
}

HGLOBAL HdibLoadBigResource(int idb) {
    HRSRC hRsrc = FindResourceA(hInst, MAKEINTRESOURCEA(idb), RT_BITMAP);
    if (!hRsrc)
        return NULL;

    DWORD cb = SizeofResource(hInst, hRsrc);
    if (cb == 0)
        return NULL;

    HGLOBAL hRes = LoadResource(hInst, hRsrc);
    if (!hRes)
        return NULL;

    void *pRes = LockResource(hRes);
    if (!pRes)
        return NULL;

    HGLOBAL hdib = GlobalAlloc(GMEM_MOVEABLE, cb);
    if (!hdib)
        return NULL;

    void *p = GlobalLock(hdib);
    if (!p) {
        GlobalFree(hdib);
        return NULL;
    }

    memcpy(p, pRes, cb);
    GlobalUnlock(hdib);

    return hdib; /* writable */
}

HBRUSH HbrGet(COLORREF cr) {
    int i;
    int iFree = -1;

    for (i = 0;; ++i) {
        /* Reached end of active cache: create a new brush entry (or return directly). */
        if (i >= chbrCache) {
            HBRUSH hbr = CreateSolidBrush(cr);
            if (hbr == NULL) {
                return NULL;
            }

            if (iFree == -1) {
                /* No free slot found while scanning. Grow cache if possible; otherwise just return. */
                if (chbrCache > 0x1F) {
                    return hbr;
                }
                iFree = chbrCache++;
            }

            rghbrCacheUse[iFree] = 1;
            rghbrCache[iFree] = hbr;
            rgcrCache[iFree] = cr;
            return hbr;
        }

        /* Track last free slot seen while scanning. */
        if (rghbrCacheUse[i] == 0) {
            iFree = i;
        } else if (rgcrCache[i] == cr) {
            /* Cache hit: bump use counter and return existing brush. */
            ++rghbrCacheUse[i];
            return rghbrCache[i];
        }
    }
}

void CtrTextOut(HDC hdc, int16_t x, int16_t y, char *psz, int16_t cLen) {
    SIZE    sz;
    int16_t dx;
    int16_t x0;

    if (cLen == 0) {
        cLen = (int16_t)lstrlenA(psz);
    }

    if (!GetTextExtentPointA(hdc, psz, (int)cLen, &sz)) {
        return;
    }

    dx = (int16_t)sz.cx;
    x0 = (int16_t)(x - (dx / 2));

    TextOutA(hdc, (int)x0, (int)y, psz, (int)cLen);
}

void HideProgressGauge(void) {
    if (hwndProgressGauge != 0) {
        DestroyWindow(hwndProgressGauge);
        hwndProgressGauge = 0;
    }
}

void InitBtnTrack(BTNT *pbtnt, HWND hwnd, HDC hdc, RECT *prc, int16_t btf, int16_t dTimer, int16_t fInitDown, int16_t fNoEndRedraw, char *szText) {

    /* TODO: implement */
}

void RcCtrTextOut(HDC hdc, RECT *prc, char *psz, int16_t cLen) {
    int16_t y;
    int16_t x;
    int32_t l;

    SIZE    sz;
    int16_t dx;
    int16_t dy;

    if (cLen == 0) {
        cLen = (int16_t)lstrlenA(psz);
    }

    if (!GetTextExtentPointA(hdc, psz, (int)cLen, &sz)) {
        return;
    }

    dx = (int16_t)sz.cx;
    dy = (int16_t)sz.cy;

    x = (int16_t)(prc->left + ((prc->right - prc->left - dx) / 2));
    y = (int16_t)(prc->top + ((prc->bottom - prc->top - dy) / 2));

    (void)l; /* kept to preserve original local layout expectations */
    TextOutA(hdc, (int)x, (int)y, psz, (int)cLen);
}

HGLOBAL DibFromBitmap(HBITMAP hbm, DWORD biCompression, WORD biBits, HPALETTE hpal) {
    BITMAP           bm;
    BITMAPINFOHEADER bi;
    BITMAPINFO      *pbi;
    HGLOBAL          hdib;
    HDC              hdc;
    DWORD            imageSize;

    if (!hbm)
        return NULL;

    if (!GetObject(hbm, sizeof(bm), &bm))
        return NULL;

    if (biBits == 0)
        biBits = (WORD)(bm.bmPlanes * bm.bmBitsPixel);

    ZeroMemory(&bi, sizeof(bi));
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bm.bmWidth;
    bi.biHeight = bm.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = biBits;
    bi.biCompression = biCompression;

    imageSize = ((bi.biWidth * biBits + 31) & ~31) / 8 * bi.biHeight;
    bi.biSizeImage = imageSize;

    hdib = GlobalAlloc(GMEM_MOVEABLE, bi.biSize + PaletteSize(&bi) + imageSize);
    if (!hdib)
        return NULL;

    pbi = (BITMAPINFO *)GlobalLock(hdib);
    pbi->bmiHeader = bi;

    hdc = GetDC(NULL);
    if (hpal) {
        SelectPalette(hdc, hpal, FALSE);
        RealizePalette(hdc);
    }

    if (!GetDIBits(hdc, hbm, 0, bm.bmHeight, (uint8_t *)pbi + bi.biSize + PaletteSize(&bi), pbi, DIB_RGB_COLORS)) {
        GlobalUnlock(hdib);
        GlobalFree(hdib);
        ReleaseDC(NULL, hdc);
        return NULL;
    }

    ReleaseDC(NULL, hdc);
    GlobalUnlock(hdib);
    return hdib;
}

void DrawFuzzyBorder(HDC hdc, RECT *prc) {
    COLORREF crBack;
    int16_t  dy;
    int16_t  dx;
    HBRUSH   hbrSav;
    COLORREF crFore;

    /* TODO: implement */
}

HPALETTE HpalBlackReserved(void) {
    LOGPALETTE *plp;
    HPALETTE    hpal;

    plp = (LOGPALETTE *)LocalAlloc(LMEM_FIXED, sizeof(LOGPALETTE) + sizeof(PALETTEENTRY) * 256);
    if (!plp)
        return NULL;

    plp->palVersion = 0x0300;
    plp->palNumEntries = 256;

    for (int i = 0; i < 256; i++) {
        plp->palPalEntry[i].peRed = 0;
        plp->palPalEntry[i].peGreen = 0;
        plp->palPalEntry[i].peBlue = 0;
        plp->palPalEntry[i].peFlags = PC_RESERVED;
    }

    hpal = CreatePalette(plp);
    LocalFree(plp);
    return hpal;
}

int16_t FGetRMouseMove(POINT *ppt) {
    MSG msg;

    /* TODO: implement */
    return 0;
}

HFONT HfontPrinterCreate(HDC hdc, int16_t iSize, int16_t *pdyFont) {
    HFONT      hfontNew;
    LOGFONT   *plf;
    TEXTMETRIC tm;
    HFONT      hfontSav;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x6b28 */

    /* TODO: implement */
    return 0;
}

int16_t FStringFitsScreen(char *lpsz, int16_t dxMax) {
    HDC     hdc;
    int16_t c;
    int16_t fFit;
    HGDIOBJ hfontSav;

    fFit = 1;
    hdc = GetDC(hwndFrame);
    c = (int16_t)strlen(lpsz);
    hfontSav = SelectObject(hdc, rghfontArial8[0]);

    while (c > 0) {
        SIZE sz;
        GetTextExtentPoint32A(hdc, lpsz, c, &sz);

        if ((uint16_t)dxMax >= (uint16_t)sz.cx)
            break;

        fFit = 0;
        c--;
        lpsz[c] = '\0';
    }

    SelectObject(hdc, hfontSav);
    ReleaseDC(hwndFrame, hdc);
    return fFit;
}

uint32_t DibNumColors(const void *pv) {
    const uint8_t *p;
    uint32_t       bits;
    uint32_t       clrUsed;

    if (pv == NULL) {
        return 0;
    }

    p = (const uint8_t *)pv;

    /*
     * Win16 supported both BITMAPCOREHEADER (OS/2 1.x) and BITMAPINFOHEADER.
     *
     * BITMAPCOREHEADER:
     *   bcSize      @ +0 (DWORD) == 12
     *   bcBitCount  @ +10 (WORD)
     *
     * BITMAPINFOHEADER:
     *   biClrUsed   @ +32 (DWORD)
     *   biBitCount  @ +14 (WORD)
     */
    if (p[0] == 0x0c && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x00) {
        /* BITMAPCOREHEADER */
        bits = (uint32_t)*(const uint16_t *)(p + 10);
        clrUsed = 0;
        DBG_LOGD("DibNumColors: COREHEADER bits=%lu", (unsigned long)bits);
    } else {
        /* BITMAPINFOHEADER (or later) */
        clrUsed = *(const uint32_t *)(p + 32);
        if (clrUsed != 0) {
            DBG_LOGD("DibNumColors: INFOHEADER biClrUsed=%lu (nonzero)", (unsigned long)clrUsed);
            return clrUsed;
        }
        bits = (uint32_t)*(const uint16_t *)(p + 14);
        DBG_LOGD("DibNumColors: INFOHEADER bits=%lu biClrUsed=0", (unsigned long)bits);
    }

    switch (bits) {
    case 1:
        return 2;
    case 4:
        return 16;
    case 8:
        return 256;
    default:
        return 0;
    }
}

void RightTextOut(HDC hdc, int16_t x, int16_t y, char *psz, int16_t cLen, int16_t dxErase) {
    int16_t dx;
    RECT    rc;

    /* TODO: implement */
}

void DrawBtn(HDC hdc, RECT *prc, int16_t bt, int16_t fDown, char *szText) {
    int32_t  dxFace;
    int16_t  ipt;
    int16_t  dyOffset;
    int16_t  d;
    int16_t  fBar;
    int16_t  fDisabled;
    int16_t  dxOffset;
    int16_t  dy;
    int16_t  fNoShaft;
    int16_t  y;
    POINT    rgptDraw[6];
    HBRUSH   hbrCur;
    COLORREF crSav;
    int16_t  dx;
    HBRUSH   hbrSav;
    int16_t  cpt;
    int16_t  x;
    RECT     rc;
    int16_t  dxyT;
    int16_t  bkMode;
    HFONT    hfontSav;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x3d00 */
    /* block (block) @ MEMORY_UTILGEN:0x404f */
    /* label DrawAgain @ MEMORY_UTILGEN:0x3e1e */

    /* TODO: implement */
}

void _Draw3dFrame(HDC hdc, RECT *prc, int16_t fErase) {
    int16_t dy;
    int16_t dx;
    HBRUSH  hbrSav;
    RECT    rc;

    /* TODO: implement */
}

HPALETTE HpalFromDib(HGLOBAL hdib) {
    const BITMAPINFOHEADER *lpbi;
    const RGBQUAD          *rgb;
    LOGPALETTE             *plp;
    uint32_t                nColors;
    HPALETTE                hpal;
    LPVOID                  p;

    if (hdib == NULL)
        return NULL;

    if (hdib != NULL) {
        void *tryPtr = (void *)hdib;
        DBG_LOGI("hdib=%p\n", tryPtr);
    }

    p = GlobalLock(hdib);
    if (!p)
        return NULL;

    lpbi = (const BITMAPINFOHEADER *)p;
    nColors = DibNumColors(lpbi);

    if (nColors == 0 || nColors > 256) {
        GlobalUnlock(hdib);
        return NULL;
    }

    plp = (LOGPALETTE *)LocalAlloc(LMEM_FIXED, sizeof(LOGPALETTE) + sizeof(PALETTEENTRY) * nColors);
    if (!plp) {
        GlobalUnlock(hdib);
        return NULL;
    }

    plp->palVersion = 0x0300;
    plp->palNumEntries = (WORD)nColors;

    rgb = (const RGBQUAD *)(p + lpbi->biSize);

    for (uint32_t i = 0; i < nColors; i++) {
        plp->palPalEntry[i].peRed = rgb[i].rgbRed;
        plp->palPalEntry[i].peGreen = rgb[i].rgbGreen;
        plp->palPalEntry[i].peBlue = rgb[i].rgbBlue;
        plp->palPalEntry[i].peFlags = 0;
    }

    hpal = CreatePalette(plp);

    LocalFree(plp);
    GlobalUnlock(hdib);

    return hpal;
}

int16_t DibBlt(HDC hdc, int32_t x0, int32_t y0, int32_t dx, int32_t dy, HGLOBAL hdib, int32_t x1, int32_t y1, int32_t dxSrc, int32_t dySrc, int32_t rop) {
    const uint8_t          *pBuf;
    const BITMAPINFOHEADER *lpbi;
    const BITMAPINFO       *pbi;
    const void             *pBits;
    int                     prevStretchMode;

    if (hdib == NULL || hdc == NULL) {
        DBG_LOGD("DibBlt: invalid args (hdc=%p hdib=%p)", (void *)hdc, (void *)hdib);
        return 0;
    }

    pBuf = (const uint8_t *)GlobalLock(hdib);
    if (pBuf == NULL) {
        DBG_LOGD("DibBlt: GlobalLock(%p) failed", (void *)hdib);
        return 0;
    }

    lpbi = (const BITMAPINFOHEADER *)pBuf;
    pbi = (const BITMAPINFO *)lpbi;

    /* Default source size to full bitmap if caller passes 0/0 like Win16 often did. */
    if (dxSrc == 0) {
        dxSrc = (int32_t)lpbi->biWidth;
    }
    if (dySrc == 0) {
        int32_t h = (int32_t)lpbi->biHeight;
        dySrc = (h < 0) ? -h : h;
    }

    if (dx == 0)
        dx = dxSrc;
    if (dy == 0)
        dy = dySrc;

    /* Compute palette entries (robust when biClrUsed==0). */
    {
        uint32_t nColors = 0;
        if (lpbi->biClrUsed != 0) {
            nColors = (uint32_t)lpbi->biClrUsed;
        } else {
            switch (lpbi->biBitCount) {
            case 1:
                nColors = 2;
                break;
            case 4:
                nColors = 16;
                break;
            case 8:
                nColors = 256;
                break;
            default:
                nColors = 0;
                break;
            }
        }

        /* Bits start after header + color table (+ BI_BITFIELDS masks if present). */
        {
            uint32_t offBits = (uint32_t)lpbi->biSize + nColors * 4u;
            if (lpbi->biCompression == BI_BITFIELDS) {
                offBits += 3u * 4u; /* RGB masks */
            }
            pBits = (const void *)(pBuf + offBits);

            DBG_LOGD("DibBlt: dst=(%ld,%ld %ldx%ld) src=(%ld,%ld %ldx%ld) rop=0x%08lx", (long)x0, (long)y0, (long)dx, (long)dy, (long)x1, (long)y1, (long)dxSrc,
                     (long)dySrc, (long)rop);
            DBG_LOGD("DibBlt: biSize=%lu biW=%ld biH=%ld bitCount=%u comp=%lu clrUsed=%lu nColors=%lu offBits=%lu biSizeImage=%lu", (unsigned long)lpbi->biSize,
                     (long)lpbi->biWidth, (long)lpbi->biHeight, (unsigned)lpbi->biBitCount, (unsigned long)lpbi->biCompression, (unsigned long)lpbi->biClrUsed,
                     (unsigned long)nColors, (unsigned long)offBits, (unsigned long)lpbi->biSizeImage);
        }
    }

    /* Stretch mode: HALFTONE can look nicer but COLORONCOLOR is often more stable for pixel art. */
    prevStretchMode = SetStretchBltMode(hdc, COLORONCOLOR);
    (void)prevStretchMode;

    /* Win16 callers usually used SRCCOPY; keep accepting rop but force SRCCOPY for now. */
    (void)rop;

    {
        int rc = StretchDIBits(hdc, (int)x0, (int)y0, (int)dx, (int)dy, (int)x1, (int)y1, (int)dxSrc, (int)dySrc, pBits, pbi, DIB_RGB_COLORS, SRCCOPY);

        GlobalUnlock(hdib);

        if (rc == GDI_ERROR) {
            DBG_LOGD("DibBlt: StretchDIBits -> GDI_ERROR");
            return 0;
        }
        DBG_LOGD("DibBlt: StretchDIBits -> %d", rc);
    }

    return 1;
}

int16_t FGetMouseMove(POINT *ppt) {
    MSG msg;

    /* TODO: implement */
    return 0;
}

/*
 * StickyDlgPos
 *
 * Save or restore a dialog's screen position, with bounds clamped
 * to the current monitor's work area.
 *
 * Behavior:
 *  - If fInit == 0:
 *      Stores the dialog's current top-left screen coordinates
 *      into *ppt.
 *
 *  - If fInit != 0:
 *      Repositions the dialog:
 *        * If ppt == (-1, -1): centers the dialog on the monitor
 *          containing the window.
 *        * Otherwise: moves the dialog so its top-left corner
 *          is at ppt->x, ppt->y.
 *      The final position is clamped so the entire dialog remains
 *      visible within the monitor's work area.
 *
 * DPI behavior:
 *  - Uses monitor work-area coordinates (MonitorFromWindow /
 *    GetMonitorInfo).
 *  - Works correctly for DPI-aware processes.
 *  - In DPI-unaware processes, coordinates are automatically
 *    DPI-virtualized by Windows and remain internally consistent.
 */
void StickyDlgPos(HWND hwnd, POINT *ppt, int16_t fInit) {
    // TODO: not tested
    RECT rc;

    GetWindowRect(hwnd, &rc);

    /* fInit==0: capture current top-left */
    if (fInit == 0) {
        ppt->x = rc.left;
        ppt->y = rc.top;
        return;
    }

    /* fInit!=0: restore/reposition, clamped to the monitor work area (DPI-safe) */
    {
        HMONITOR    hmon;
        MONITORINFO mi;
        RECT        rcWork;
        int         w = rc.right - rc.left;
        int         h = rc.bottom - rc.top;

        hmon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        mi.cbSize = (DWORD)sizeof(mi);
        if (!GetMonitorInfoA(hmon, &mi)) {
            /* Fallback: primary screen work area */
            SystemParametersInfoA(SPI_GETWORKAREA, 0, &rcWork, 0);
        } else {
            rcWork = mi.rcWork;
        }

        if (ppt->x == -1 && ppt->y == -1) {
            /* center on work area */
            rc.left = rcWork.left + ((rcWork.right - rcWork.left) - w) / 2;
            rc.top = rcWork.top + ((rcWork.bottom - rcWork.top) - h) / 2;
        } else {
            /* move so top-left becomes ppt */
            rc.left = ppt->x;
            rc.top = ppt->y;
        }

        /* clamp so the whole dialog stays visible in the work area */
        if (rc.left + w > rcWork.right)
            rc.left = rcWork.right - w;
        if (rc.top + h > rcWork.bottom)
            rc.top = rcWork.bottom - h;
        if (rc.left < rcWork.left)
            rc.left = rcWork.left;
        if (rc.top < rcWork.top)
            rc.top = rcWork.top;

        SetWindowPos(hwnd, NULL, rc.left, rc.top, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

void UpdateProgressGauge(int16_t pctX10) {
    int16_t iNum;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x63ed */

    /* TODO: implement */
}

uint32_t PaletteSize(const void *pv) {
    uint32_t nColors;

    if (pv == NULL) {
        return 0;
    }

    nColors = DibNumColors(pv);

    /* BITMAPCOREHEADER (OS/2 1.x) has an RGBTRIPLE (3 bytes) color table. */
    {
        const uint8_t *p = (const uint8_t *)pv;
        const bool     isCore = (p[0] == 0x0c && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x00);

        if (isCore) {
            return nColors * 3u;
        } else {
            /* BITMAPINFOHEADER+ uses RGBQUAD (4 bytes) color table. */
            return nColors * 4u;
        }
    }
}

void FreeHbr(HBRUSH hbr) {
    int16_t i;

    if (hbr == NULL) {
        return;
    }

    i = 0;
    for (;;) {
        if (i >= chbrCache) {
            /* Not in cache: just delete it. */
            DeleteObject(hbr);
            return;
        }

        /* If cached and in-use, decrement refcount; delete on zero. */
        if (rghbrCacheUse[i] != 0 && hbr == rghbrCache[i]) {
            rghbrCacheUse[i]--;

            if (rghbrCacheUse[i] != 0) {
                return;
            }

            DeleteObject(hbr);
            return;
        }

        i++;
    }
}

int16_t FTrackBtn(BTNT *pbtnt) {
    POINT   pt;
    int16_t fInBtn;
    int32_t ticksNew;

    /* TODO: implement */
    return 0;
}

void WrapTextOut(HDC hdc, int16_t *px, int16_t *py, char *psz, int16_t cLen, int16_t xLeft, int16_t dxWidth, int16_t *pxMax, int16_t fNewLine, int16_t fPrint) {
    int16_t dxRemain;
    char   *pchEnd;
    int16_t fItFit;
    int16_t xRight;
    int16_t dx;
    char   *pchStart;
    char   *pch;

    /* debug symbols */
    /* label WrapIt @ MEMORY_UTILGEN:0x27c5 */
    /* label Done @ MEMORY_UTILGEN:0x2802 */
    /* label Top @ MEMORY_UTILGEN:0x2656 */

    /* TODO: implement */
}

int16_t DxStreamTextOut(HDC hdc, int16_t *px, int16_t y, char *psz, int16_t cLen, int16_t fPrint) {
    SIZE    sz;
    int16_t dx;

    if (cLen == 0) {
        cLen = (int16_t)lstrlenA(psz);
    }

    /* Measure text width */
    if (!GetTextExtentPointA(hdc, psz, (int)cLen, &sz)) {
        return 0;
    }

    dx = (int16_t)sz.cx;

    if (fPrint != 0) {
        TextOutA(hdc, (int)*px, (int)y, psz, (int)cLen);
    }

    *px += dx;
    return dx;
}

int32_t LDrawGauge(HDC hdc, RECT *prc, int16_t cSegs, int32_t *rgSize, HBRUSH *rghbr, int32_t cTot) {
    int16_t fHuge;
    int16_t i;
    int32_t lSum;
    int32_t dx;
    RECT    rc;

    /* debug symbols */
    /* label FinRet @ MEMORY_UTILGEN:0x330e */

    /* TODO: implement */
    return 0;
}

void DiaganolTextOut(HDC hdc, RECT *prc, char *psz, int16_t cLen) {
    double   angle;
    HFONT    hfont;
    int16_t  dxFlat;
    int16_t  yStart;
    int16_t  dy;
    double   dcos;
    int16_t  dyText;
    int16_t  xStart;
    int16_t  dyEstFont;
    int16_t  dxText;
    LOGFONT *plf;
    double   dsin;
    HFONT    hfontSav;
    int16_t  dx;
    int16_t  dyFlat;
    double   rotate;
    int32_t  l;
    int16_t  dHtX;
    int16_t  dHtY;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x2d9a */
    /* label TryAgain @ MEMORY_UTILGEN:0x2b97 */
    /* label FreeLF @ MEMORY_UTILGEN:0x2efd */

    /* TODO: implement */
}

void DrawProgressGauge(HDC hdcOrig, int16_t fFull, int16_t iNumOnly) {
    HDC     hdc;
    int16_t dy;
    int16_t fNumOnly;
    int16_t dx2;
    int16_t dx;
    RECT    rc;
    int16_t c;
    char    szT[8];

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x675d */
    /* label LRelease @ MEMORY_UTILGEN:0x6841 */

    /* TODO: implement */
}
#else

// special case because this is called everywhere, do nothing outside of win32
int16_t AlertSz(const char *sz, uint16_t mbType) { return 0; }

#endif
