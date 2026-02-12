
#include "globals.h"
#include "types.h"

#include "debuglog.h"
#include "file.h"
#include "memory.h"
#include "port.h"
#include "stars.h"
#include "strings.h"
#include "utilgen.h"

/* functions */

int16_t FSetUpBatchProcessing(void) {
    char   *pch;
    MemJump env;
    int16_t fSuccess;
    int16_t cb;

    fSuccess = 0;
    penvMem = &env;
    if (setjmp(env.env) == 0) {
        StreamOpen(szBase, mdRead);
        {
            long pos = ftell(hf.fp);
            fseek(hf.fp, 0, SEEK_END);
            cb = (int16_t)ftell(hf.fp);
            fseek(hf.fp, pos, SEEK_SET);
        }
        lpchBatch = LpAlloc(cb, htPerm);
        RgFromStream(lpchBatch, cb);
        lpchBatchMac = lpchBatch + cb;
        pch = szBase;
        while (1) {
            if (*lpchBatch == '\n' || (lpchBatch == lpchBatchMac))
                break;
            *pch = *lpchBatch;
            lpchBatch++;
            pch++;
        }
        lpchBatch++;
        pch[-1] = '\0';
        fSuccess = 1;
    }
    penvMem = NULL;
    StreamClose();
    if (fSuccess == 0) {
        szBase[0] = '\0';
    }
    return fSuccess;
}

int16_t IPlrAlsoCheater(int16_t iplr) {
    // not implementing copy protection
    return -1;
    // if (!FValidSerialLong(vrgts[iplr].lSerialNumber))
    //     return -1;
    //
    // int16_t i;
    // for (i = 0; i < game.cPlayer; i++) {
    //     if (i != iplr && rgplr[i].fCheater) {
    //         if (vrgts[iplr].lSerialNumber == vrgts[i].lSerialNumber &&
    //             memcmp(vrgts[iplr].rgbConfig, vrgts[i].rgbConfig, 11) != 0) {
    //             return i;
    //         }
    //     }
    // }
    // return -1;
}

#ifdef _WIN32

INT_PTR CALLBACK About(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RECT     rc;
    uint16_t hdc;
    int16_t  i;
    int16_t (*lpProc)(void);
    HWND hwndCtl;

    /* debug symbols */
    /* block (block) @ MEMORY_MAIN:0x12d1 */
    /* block (block) @ MEMORY_MAIN:0x14a3 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK OrderInfoDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RECT rc;

    /* TODO: implement */
    return 0;
}

int16_t FGetSystemColors(void) {
    /* Translated from Win16: update global brushes/colors from current theme. */
    COLORREF cr;

    if (hbrButtonFace != NULL) {
        FreeHbr(hbrButtonFace);
        hbrButtonFace = NULL;
    }
    if (hbrButtonHilite != NULL) {
        FreeHbr(hbrButtonHilite);
        hbrButtonHilite = NULL;
    }
    if (hbrButtonShadow != NULL) {
        FreeHbr(hbrButtonShadow);
        hbrButtonShadow = NULL;
    }
    if (hbrButtonText != NULL) {
        FreeHbr(hbrButtonText);
        hbrButtonText = NULL;
    }
    if (hbrWindowText != NULL) {
        FreeHbr(hbrWindowText);
        hbrWindowText = NULL;
    }
    if (hbrWindow != NULL) {
        FreeHbr(hbrWindow);
        hbrWindow = NULL;
    }
    if (hbrWindowFrame != NULL) {
        FreeHbr(hbrWindowFrame);
        hbrWindowFrame = NULL;
    }
    if (hbrDesktop != NULL) {
        FreeHbr(hbrDesktop);
        hbrDesktop = NULL;
    }

    crButtonFace = GetSysColor(COLOR_BTNFACE);
    hbrButtonFace = HbrGet(crButtonFace);

    crButtonHilite = GetSysColor(COLOR_BTNHIGHLIGHT); /* was 0x14 */
    hbrButtonHilite = HbrGet(crButtonHilite);

    crButtonShadow = GetSysColor(COLOR_BTNSHADOW); /* was 0x10 */
    hbrButtonShadow = HbrGet(crButtonShadow);

    crButtonText = GetSysColor(COLOR_BTNTEXT); /* was 0x12 */
    hbrButtonText = HbrGet(crButtonText);

    cr = GetSysColor(COLOR_WINDOWFRAME); /* was 6 */
    hbrWindowFrame = HbrGet(cr);

    cr = GetSysColor(COLOR_DESKTOP); /* was 1 */
    hbrDesktop = HbrGet(cr);

    crWindow = GetSysColor(COLOR_WINDOW); /* was 5 */
    hbrWindow = HbrGet(crWindow);

    crWindowText = GetSysColor(COLOR_WINDOWTEXT); /* was 8 */
    hbrWindowText = HbrGet(crWindowText);

    dyTitleBar = (int16_t)GetSystemMetrics(SM_CYCAPTION); /* was 4 */
    dxWinFrame = (int16_t)GetSystemMetrics(SM_CXFRAME);   /* was 0x20 */
    dyWinFrame = (int16_t)GetSystemMetrics(SM_CYFRAME);   /* was 0x21 */

    /*
     * Win16 patched a byte in the palette/colortable of certain DIBs:
     *   - low byte of crButtonFace
     *   - high byte of crButtonFace
     *   - a third byte computed as (MAKELONG(dxWinFrame, dyWinFrame) >> 4)
     *
     * The offsets (0x40c..0x40e etc.) are game-specific DIB layouts.
     * We preserve the exact writes for behavior parity.
     */
    if (hdibPlaque != NULL) {
        BYTE *p = (BYTE *)GlobalLock(hdibPlaque);
        if (p != NULL) {
            p[0x40e] = (BYTE)(crButtonFace & 0xFF);
            p[0x40d] = (BYTE)((crButtonFace >> 8) & 0xFF);

            /* was __aFulshr(CONCAT22(0x20,0x21), 4) i.e. (MAKELONG(0x21,0x20) >> 4) */
            {
                DWORD v = MAKELONG((WORD)dyWinFrame, (WORD)dxWinFrame);
                p[0x40c] = (BYTE)(v >> 4);
            }

            GlobalUnlock(hdibPlaque);
        }
    }

    if (hdibToolbar != NULL) {
        BYTE *p = (BYTE *)GlobalLock(hdibToolbar);
        if (p != NULL) {
            p[0x41e] = (BYTE)(crButtonFace & 0xFF);
            p[0x41d] = (BYTE)((crButtonFace >> 8) & 0xFF);

            {
                DWORD v = MAKELONG((WORD)dyWinFrame, (WORD)dxWinFrame);
                p[0x41c] = (BYTE)(v >> 4);
            }

            GlobalUnlock(hdibToolbar);
        }
    }

    /* Screen color count */
    {
        HDC hdc = GetDC(NULL);
        if (hdc != NULL) {
            int planes = GetDeviceCaps(hdc, PLANES);  /* was 0x0c */
            int bits = GetDeviceCaps(hdc, BITSPIXEL); /* was 0x0e */
            vcScreenColors = (int32_t)(planes * bits);
            ReleaseDC(NULL, hdc);
        } else {
            /* If we fail to get a DC, keep original spirit: result still success. */
            vcScreenColors = 0;
        }
    }

    DBG_LOGD("FGetSystemColors vcScreenColors=%d", vcScreenColors);

    return 1;
}

int16_t FHandleKey(HWND hwnd, int16_t iMsg, int16_t iKey, uint32_t dw) {
    HWND     hwndF;
    int16_t  i;
    int16_t  itb;
    int16_t  iWarp;
    POINT    pt;
    uint16_t md;
    int16_t  iwp;
    HWND     hwndOver;

    /* debug symbols */
    /* block (block) @ MEMORY_MAIN:0x1772 */
    /* block (block) @ MEMORY_MAIN:0x1846 */
    /* block (block) @ MEMORY_MAIN:0x194b */
    /* block (block) @ MEMORY_MAIN:0x195d */
    /* block (block) @ MEMORY_MAIN:0x1abf */
    /* block (block) @ MEMORY_MAIN:0x1ba0 */

    /* TODO: implement */
    return 0;
}

int16_t FHandleChar(HWND hwnd, uint16_t ch, LPARAM lParam) {
    HWND hwndF;

    (void)hwnd;

    if ((((hwndScanner == 0) || ((ch != '+') && (ch != '-'))) && (ch != 'v') && (ch != 'V')) || ((hwndMessage != 0) && ((hwndF = GetFocus()) == hwndMsgEdit))) {
        return 0;
    }

    SendMessage(hwndScanner, WM_CHAR, ch, lParam);
    return 1;
}

#endif /* _WIN32 */
