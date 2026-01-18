/*
 * winmain_win32_firstpass.c
 *
 * First-run Win32 translation of the decompiled WinMain init path + helpers.
 *
 * Key project conventions per user:
 *  - No namespaces (all functions global).
 *  - Globals are referenced directly (no c_common./_DATA. prefixes).
 *  - Use bitfields in INI and GDATA (gd/ini) rather than bitwise masks.
 *
 * This file is intended to compile on Windows. If you build cross-platform,
 * you can #ifdef out the Win32 entrypoint and keep the logic callable.
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
/* Non-Windows builds: provide stubs if you want to compile this file anyway. */
typedef void* HINSTANCE;
typedef void* HWND;
typedef void* HACCEL;
typedef void* HBRUSH;
typedef void* HBITMAP;
typedef void* HICON;
typedef void* HPALETTE;
typedef void* HDC;
typedef void* HRGN;
typedef void* HPEN;
typedef void* HGLOBAL;
typedef unsigned int UINT;
typedef unsigned long WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef int BOOL;
typedef struct { UINT message; HWND hwnd; WPARAM wParam; LPARAM lParam; } MSG;
#define WINAPI
#define CALLBACK
#define TRUE 1
#define FALSE 0
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>

/* ------------------------------------------------------------
 * External globals (declared in your headers; listed here for clarity).
 * These should already exist in your project. Keep/remove as needed.
 * ------------------------------------------------------------ */
#ifdef __cplusplus
extern "C" {
#endif

extern HINSTANCE hInst;
extern HWND hwndFrame;
extern HWND hwndTitle;
extern HACCEL hAccel;
extern HACCEL hAccelTitle;

extern char szBase[];         /* base filename buffer */
extern char szPassLast[15];   /* 14 chars + NUL */
extern int32_t lSaltLast;

extern struct INI ini;        /* from types.h */
extern struct GDATA gd;       /* from types.h */

/* Common colors/metrics (names based on decompile; should exist in your globals). */
extern uint32_t crButtonFace, crButtonHilite, crButtonShadow, crButtonText;
extern uint32_t crWindow, crWindowText;
extern int16_t dyTitleBar, dxWinFrame, dyWinFrame;
extern int16_t vcScreenColors;

/* Resources / objects */
extern HRGN hrgnHuge, hrgnScratch;
extern HBRUSH hbrShip, hbrStarbase, hbrBBlue, hbrEnemy, hbrSelect;
extern HBRUSH hbrRed, hbrBlue, hbrGreen, hbrRadar, hbrPurple, hbrTooltip;
extern HBRUSH hbrRadarNear;
extern HBRUSH rghbrMineral[5];
extern HBRUSH rghbrPlanetAttr[3][2];
extern HBRUSH rghbrMinSum[4][2];
extern HBRUSH hbrYellow, hbrDkYellow, hbrLightGray, hbrGray;

extern HPEN hpenShip, hpenDkGreen, hpenStarbase, hpenEnemy, hpenMassPath;
extern HPEN hpenRadar, hpenRadarNear, hpenDkBlue, hpenYellow, hpenDkYellow, hpenDkPurple;

extern HBRUSH hbr50Screen, rghbrPat[3], hbrCargo, hbrDock;

extern HBITMAP hbmpScanner, hbmpScanShip, hbmpUnknownPlanet, hbmpNumbers;
extern HGLOBAL hdibPlanets, hdibThings, hdibToolbar;
extern HGLOBAL rghdibShips[5], rghdibShipsT[5];
extern HGLOBAL rghdibInventory[7];
extern HPALETTE vhpal;
extern HGLOBAL hdibRaces, hdibRacesT, hdibRacesX;
extern HBITMAP hbmpBackBld, hbmpMsg, hbmpMono;
extern HGLOBAL hdibPlaque;

extern HICON hiconStars, hiconHost, hiconWait;
extern HICON rghiconVCR[7];

/* System-color brushes (names based on decompile) */
extern HBRUSH hbrButtonFace, hbrButtonHilite, hbrButtonShadow, hbrButtonText;
extern HBRUSH hbrWindowText, hbrWindow, hbrWindowFrame, hbrDesktop;

/* Cursors */
extern void* hcurScanner;
extern void* hcurScanAdd;
extern void* hcurOpenGrab;
extern void* hcurCloseGrab;
extern void* hcurTrashCan;
extern void* hcurNoWay;
extern void* hcurResizeWE;
extern void* hcurResizeNS;
extern void* hcurResize4Way;
extern void* hcurArrowHelp;
extern void* hcurHand;

/* Allocations */
extern uint8_t *lpLog;
extern int16_t *lpMsg;
extern uint8_t *lpb2k;
extern uint16_t *vlprgidMisc, *vlprgidPlanet, *vlprgidFleet;

/* VTimer/Tutor blocks (opaque here) */
extern struct TUTOR tutor;
extern struct VTIMER vtimer;

/* Default player template block copied into vplr (opaque sizes are in your headers). */
extern struct PLAYER vplr;
extern struct PLAYER vrgplrDef;

/* ------------------------------------------------------------
 * External functions already implemented elsewhere in your project.
 * ------------------------------------------------------------ */

/* String/UI */
extern char *PszFormatIds(int16_t ids, int16_t *pParams /*nullable*/);
extern void  AlertSz(const char *psz, int flags);

/* RNG */
extern void Randomize2(uint32_t seed);

/* Init/teardown */
extern int16_t InitMDIApp(void);
extern int16_t FCreateStuff(void);
extern int16_t FGetSystemColors(void);
extern int16_t InitInstance(int nCmdShow);
extern void   FreeStuff(void);
extern void   ReadIniSettings(void);

/* Input handling */
extern int16_t FHandleKey(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
extern int16_t FHandleChar(HWND hwnd, WPARAM wParam, LPARAM lParam);

/* Brushes/DIB helpers */
extern HBRUSH   HbrGet(uint32_t rgb);
extern void     FreeHbr(HBRUSH hbr);
extern HGLOBAL  HdibLoadBigResource(uint16_t id);
extern HPALETTE HpalFromDib(HGLOBAL hdib);
extern void     GetDiskSerialNumber(void);

/* Memory alloc */
extern void    *LpAlloc(uint32_t cb, int ht);

/* Batch stream helpers */
extern void     StreamOpen(const char *pszBase, uint16_t md);
extern void     StreamClose(void);
extern void     RgFromStream(void *pv, uint16_t cb);
extern long     FileLength(void);

/* Win32 "fake proc" pointers are direct in Win32 build */
extern LRESULT (CALLBACK *TB_FakeComboProc)(HWND, UINT, WPARAM, LPARAM);
extern LRESULT (CALLBACK *TB_FakeCEProc)(HWND, UINT, WPARAM, LPARAM);
extern LRESULT (CALLBACK *SHIP_FakeEditProc)(HWND, UINT, WPARAM, LPARAM);
extern LRESULT (CALLBACK *BUILD_FakeListProc)(HWND, UINT, WPARAM, LPARAM);
extern void    (CALLBACK *HostTimerProc)(HWND, UINT, UINT_PTR, DWORD);
extern INT_PTR (CALLBACK *BrowserDlg)(HWND, UINT, WPARAM, LPARAM);
extern INT_PTR (CALLBACK *ReportDlg)(HWND, UINT, WPARAM, LPARAM);
extern INT_PTR (CALLBACK *ProgressGaugeDlg)(HWND, UINT, WPARAM, LPARAM);

/* You likely have ids... enums; these are referenced by name here. */
extern const int16_t idsUnableInitializeStars;
extern const int16_t idsUnableLoadBitmaps;

#ifdef __cplusplus
}
#endif

/* ------------------------------------------------------------
 * Startup message: original uses 0x464 = WM_USER + 0x64
 * ------------------------------------------------------------ */
#ifndef WM_STARS_STARTUP
#define WM_STARS_STARTUP (0x400u + 0x64u)
#endif

/* ------------------------------------------------------------
 * Batch processing locals
 * ------------------------------------------------------------ */
static jmp_buf g_batchJmp;
static int16_t *g_penvMem = NULL;

static char *g_lpchBatch = NULL;
static char *g_lpchBatchMac = NULL;

/* ------------------------------------------------------------
 * Placeholder window class names and WndProcs.
 * Replace with your real class names/WndProcs as you port more UI.
 * ------------------------------------------------------------ */
#ifdef _WIN32
static const char *kFrameClassName = "StarsFrame";
static const char *kChildClassName = "StarsChild";

static LRESULT CALLBACK FrameWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return DefFrameProcA(hWnd, NULL, uMsg, wParam, lParam);
}

static LRESULT CALLBACK ChildWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return DefMDIChildProcA(hWnd, uMsg, wParam, lParam);
}
#endif


/* ------------------------------------------------------------
 * InitMDIApp (first-run scaffold)
 * ------------------------------------------------------------ */
int16_t InitMDIApp(void)
{
#ifdef _WIN32
    WNDCLASSA wc;

    memset(&wc, 0, sizeof(wc));
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);

    /* Frame class */
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc = FrameWndProc;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = kFrameClassName;
    wc.lpszMenuName = MAKEINTRESOURCEA(0x0364); /* placeholder: original used 0x364 */
    if (!RegisterClassA(&wc)) {
        return 0;
    }

    /* Child class placeholder */
    memset(&wc, 0, sizeof(wc));
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ChildWndProc;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kChildClassName;
    if (!RegisterClassA(&wc)) {
        return 0;
    }

    return 1;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------
 * FCreateStuff (first-run; uses gd/ini bitfields)
 * This is mostly the resource/brush/pens init from the decompile.
 * ------------------------------------------------------------ */
int16_t FCreateStuff(void)
{
#ifdef _WIN32
    bool failed = false;

    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);

    /* Screen size mode: gd.mdScreenSize is a 2-bit field (top bits previously). */
    if (sx < 800 || sy < 600) {
        gd.mdScreenSize = 0;
    } else if (sx < 0x400 || sy < 0x300) {
        gd.mdScreenSize = 1;
    } else if (sx < 0x457 || sy < 0x378) {
        gd.mdScreenSize = 2;
    } else {
        gd.mdScreenSize = 3;
    }

    /* old: gd.flags1 &= ~0x0480; -> clear these bitfields */
    gd.fNoIdleChecks = 0; /* 0x0080 */
    gd.fAisDone      = 0; /* 0x0400 */

    /* Copy default player template into vplr */
    memcpy(&vplr, &vrgplrDef, 0x60u * sizeof(uint16_t));

    /* Regions */
    hrgnHuge = CreateRectRgn(-10, -10, 2000, 2000);
    hrgnScratch = CreateRectRgn(0, 0, 10, 10);

    /* Brushes */
    hbrShip      = HbrGet(0x00ff00u);
    hbrStarbase  = HbrGet(0x00ffffu);
    hbrBBlue     = HbrGet(0xff0000u);
    hbrEnemy     = HbrGet(0x0000ffu);
    hbrSelect    = HbrGet(0x00ffffu);
    hbrRed       = HbrGet(0x0000ffu);
    hbrBlue      = HbrGet(0x7f0000u);
    hbrGreen     = HbrGet(0x007f00u);
    hbrRadar     = HbrGet(0x00007fu);
    hbrPurple    = HbrGet(0x7f007fu);
    hbrTooltip   = HbrGet(0x9fffffu);

    hbrRadarNear = NULL;

    rghbrMineral[0] = HbrGet(0xff0000u);
    rghbrMineral[1] = HbrGet(0x007f00u);
    rghbrMineral[2] = HbrGet(0x00ffffu);
    rghbrMineral[3] = HbrGet(0xffffffu);
    rghbrMineral[4] = HbrGet(0x0000ffu);

    rghbrPlanetAttr[0][0] = HbrGet(0x7f0000u);
    rghbrPlanetAttr[0][1] = HbrGet(0xff0000u);
    rghbrPlanetAttr[1][0] = HbrGet(0x00007fu);
    rghbrPlanetAttr[1][1] = HbrGet(0x0000ffu);
    rghbrPlanetAttr[2][0] = HbrGet(0x007f00u);
    rghbrPlanetAttr[2][1] = HbrGet(0x00ff00u);

    rghbrMinSum[0][0] = HbrGet(0xff0000u);
    rghbrMinSum[0][1] = HbrGet(0x7f0000u);
    rghbrMinSum[1][0] = HbrGet(0x00ff00u);
    rghbrMinSum[1][1] = HbrGet(0x007f00u);
    rghbrMinSum[2][0] = HbrGet(0x00ffffu);
    rghbrMinSum[2][1] = HbrGet(0x7f7f7fu);
    rghbrMinSum[3][0] = HbrGet(0x0000ffu);
    rghbrMinSum[3][1] = HbrGet(0x00007fu);

    hbrYellow    = HbrGet(0x00ffffu);
    hbrDkYellow  = HbrGet(0x007f7fu);
    hbrLightGray = HbrGet(0xc0c0c0u);
    hbrGray      = HbrGet(0x808080u);

    /* Pens */
    hpenShip      = CreatePen(PS_SOLID, 1, 0x00ff00u);
    hpenDkGreen   = CreatePen(PS_SOLID, 1, 0x007f00u);
    hpenStarbase  = CreatePen(PS_SOLID, 1, 0xff0000u);
    hpenEnemy     = CreatePen(PS_SOLID, 1, 0x0000ffu);
    hpenMassPath  = CreatePen(PS_SOLID, 1, 0x7f7f7fu);
    hpenRadar     = CreatePen(PS_SOLID, 1, 0x00007fu);
    hpenRadarNear = NULL;
    hpenDkBlue    = CreatePen(PS_SOLID, 1, 0x7f0000u);
    hpenYellow    = CreatePen(PS_SOLID, 1, 0x00ffffu);
    hpenDkYellow  = CreatePen(PS_SOLID, 1, 0x007f7fu);
    hpenDkPurple  = CreatePen(PS_SOLID, 1, 0x7f007fu);

    /* Pattern brushes from bitmaps */
    {
        HBITMAP hbmp = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x05e6)); /* screen50 */
        if (hbmp) {
            hbr50Screen = CreatePatternBrush(hbmp);
            DeleteObject(hbmp);
        } else {
            failed = true;
        }

        for (int i = 0; i < 3; i++) {
            hbmp = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x01cc + i));
            if (!hbmp) { failed = true; continue; }
            rghbrPat[i] = CreatePatternBrush(hbmp);
            DeleteObject(hbmp);
        }

        hbmp = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x05f2)); /* cargo */
        if (hbmp) {
            hbrCargo = CreatePatternBrush(hbmp);
            DeleteObject(hbmp);
        } else {
            failed = true;
        }

        hbmp = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x05fb)); /* dock */
        if (hbmp) {
            hbrDock = CreatePatternBrush(hbmp);
            DeleteObject(hbmp);
        } else {
            failed = true;
        }
    }

    /* Cursors */
    hcurScanner     = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0603));
    hcurScanAdd     = LoadCursorA(hInst, MAKEINTRESOURCEA(0x060e));
    hcurOpenGrab    = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0619));
    hcurCloseGrab   = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0625));
    hcurTrashCan    = LoadCursorA(hInst, MAKEINTRESOURCEA(0x007a));
    hcurNoWay       = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0079));
    hcurResizeWE    = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0102));
    hcurResizeNS    = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0104));
    hcurResize4Way  = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0107));
    hcurArrowHelp   = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0108));
    hcurHand        = LoadCursorA(hInst, MAKEINTRESOURCEA(0x0109));

    /* Bitmaps / DIBs */
    hbmpScanner        = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x0632));
    hbmpScanShip       = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x0058));
    hbmpUnknownPlanet  = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x063d));
    hbmpNumbers        = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x00f9));

    hdibPlanets = HdibLoadBigResource(0x0070);
    hdibThings  = HdibLoadBigResource(0x0057);
    hdibToolbar = HdibLoadBigResource(0x00b2);

    if (!hdibPlanets || !hdibThings || !hdibToolbar) {
        failed = true;
    }

    for (int i = 0; i < 5; i++) {
        rghdibShips[i]  = HdibLoadBigResource((uint16_t)(0x0228 + i));
        rghdibShipsT[i] = HdibLoadBigResource((uint16_t)(0x022d + i));
        if (!rghdibShips[i] || !rghdibShipsT[i]) {
            failed = true;
        }
    }

    for (int i = 0; i < 7; i++) {
        rghdibInventory[i] = HdibLoadBigResource((uint16_t)(500 + i));
        if (!rghdibInventory[i]) {
            failed = true;
        }
    }

    vhpal = HpalFromDib(rghdibShips[3]);

    hdibRaces  = HdibLoadBigResource(0x0085);
    hdibRacesT = HdibLoadBigResource(0x0050);
    hdibRacesX = HdibLoadBigResource(0x004f);

    hbmpBackBld = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x0077));
    hbmpMsg     = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x0086));
    hbmpMono    = LoadBitmapA(hInst, MAKEINTRESOURCEA(0x00c7));

    hdibPlaque = HdibLoadBigResource(0x0437);

    hiconStars = LoadIconA(hInst, MAKEINTRESOURCEA(0x064e));
    hiconHost  = LoadIconA(hInst, MAKEINTRESOURCEA(0x0657));
    hiconWait  = LoadIconA(hInst, MAKEINTRESOURCEA(0x065f));

    for (int i = 0; i < 7; i++) {
        /* placeholder pattern; replace with exact IDs later */
        rghiconVCR[i] = LoadIconA(hInst, MAKEINTRESOURCEA((uint16_t)(0x0667 + i)));
    }

    /* Allocations */
    lpLog = (uint8_t *)LpAlloc(32000, /*htLog*/ 0);
    lpMsg = (int16_t *)LpAlloc(0xffc8u, /*htMsg*/ 0);

    /* Win32: no MakeProcInstance; direct assignments */
    /* If you store these in globals, assign them here in your real code. */
    (void)TB_FakeComboProc;
    (void)TB_FakeCEProc;
    (void)SHIP_FakeEditProc;
    (void)BUILD_FakeListProc;
    (void)HostTimerProc;
    (void)BrowserDlg;
    (void)ReportDlg;
    (void)ProgressGaugeDlg;

    GetDiskSerialNumber();

    lpb2k      = (uint8_t *)LpAlloc(0x0800u, /*htPerm*/ 0);
    vlprgidMisc   = (uint16_t *)LpAlloc(0x0800u, /*htPerm*/ 0);
    vlprgidPlanet = (uint16_t *)LpAlloc(0x0800u, /*htPerm*/ 0);
    vlprgidFleet  = (uint16_t *)LpAlloc(0x0800u, /*htPerm*/ 0);

    if (failed ||
        !hbmpScanner || !hbmpUnknownPlanet || !hbmpBackBld ||
        !hdibRaces || !hdibRacesT || !hdibRacesX ||
        !hbmpMono || !hbmpScanShip || !hbmpMsg ||
        !hiconHost || !hiconStars || !hiconWait)
    {
        AlertSz(PszFormatIds(idsUnableLoadBitmaps, NULL), MB_ICONERROR);
        return 0;
    }

    return 1;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------
 * FGetSystemColors (Win32)
 * ------------------------------------------------------------ */
int16_t FGetSystemColors(void)
{
#ifdef _WIN32
    if (hbrButtonFace)   { FreeHbr(hbrButtonFace);   hbrButtonFace = NULL; }
    if (hbrButtonHilite) { FreeHbr(hbrButtonHilite); hbrButtonHilite = NULL; }
    if (hbrButtonShadow) { FreeHbr(hbrButtonShadow); hbrButtonShadow = NULL; }
    if (hbrButtonText)   { FreeHbr(hbrButtonText);   hbrButtonText = NULL; }
    if (hbrWindowText)   { FreeHbr(hbrWindowText);   hbrWindowText = NULL; }
    if (hbrWindow)       { FreeHbr(hbrWindow);       hbrWindow = NULL; }
    if (hbrWindowFrame)  { FreeHbr(hbrWindowFrame);  hbrWindowFrame = NULL; }
    if (hbrDesktop)      { FreeHbr(hbrDesktop);      hbrDesktop = NULL; }

    crButtonFace   = (uint32_t)GetSysColor(COLOR_BTNFACE);
    hbrButtonFace  = HbrGet(crButtonFace);

    crButtonHilite = (uint32_t)GetSysColor(COLOR_BTNHIGHLIGHT);
    hbrButtonHilite = HbrGet(crButtonHilite);

    crButtonShadow = (uint32_t)GetSysColor(COLOR_BTNSHADOW);
    hbrButtonShadow = HbrGet(crButtonShadow);

    crButtonText   = (uint32_t)GetSysColor(COLOR_BTNTEXT);
    hbrButtonText  = HbrGet(crButtonText);

    hbrWindowFrame = HbrGet((uint32_t)GetSysColor(COLOR_WINDOWFRAME));
    hbrDesktop     = HbrGet((uint32_t)GetSysColor(COLOR_DESKTOP));

    crWindow       = (uint32_t)GetSysColor(COLOR_WINDOW);
    hbrWindow      = HbrGet(crWindow);

    crWindowText   = (uint32_t)GetSysColor(COLOR_WINDOWTEXT);
    hbrWindowText  = HbrGet(crWindowText);

    dyTitleBar = (int16_t)GetSystemMetrics(SM_CYCAPTION);
    dxWinFrame = (int16_t)GetSystemMetrics(SM_CXFRAME);
    dyWinFrame = (int16_t)GetSystemMetrics(SM_CYFRAME);

    /* Patch palette-ish bytes inside plaque/toolbar DIBs like the original. */
    {
        uint32_t packed = ((uint32_t)(uint16_t)dyWinFrame << 16) | (uint16_t)dxWinFrame;
        uint8_t  v = (uint8_t)(packed >> 4);

        if (hdibPlaque) {
            uint8_t *p = (uint8_t *)GlobalLock(hdibPlaque);
            if (p) {
                p[0x40e] = (uint8_t)(crButtonFace & 0xff);
                p[0x40d] = (uint8_t)((crButtonFace >> 8) & 0xff);
                p[0x40c] = v;
                GlobalUnlock(hdibPlaque);
            }
        }

        if (hdibToolbar) {
            uint8_t *p = (uint8_t *)GlobalLock(hdibToolbar);
            if (p) {
                p[0x41e] = (uint8_t)(crButtonFace & 0xff);
                p[0x41d] = (uint8_t)((crButtonFace >> 8) & 0xff);
                p[0x41c] = v;
                GlobalUnlock(hdibToolbar);
            }
        }
    }

    {
        HDC hdc = GetDC(NULL);
        int planes = GetDeviceCaps(hdc, PLANES);
        int bpp    = GetDeviceCaps(hdc, BITSPIXEL);
        vcScreenColors = (int16_t)(planes * bpp);
        ReleaseDC(NULL, hdc);
    }

    return 1;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------
 * InitInstance (Win32)
 * Uses INI bitfields instead of masks.
 * ------------------------------------------------------------ */
int16_t InitInstance(int nCmdShow)
{
#ifdef _WIN32
    int sw;

    /* Equivalent of "ini.flags6 &= 0xfe1a" in the decompile:
     * Keep this explicit once you confirm which bits those are in your INI.
     * For now, clear the common startup toggles that were being reset.
     */
    ini.fStartupFile = 0;
    ini.fCmdLine     = 0;
    ini.fWait        = 0;
    ini.fTry         = 0;
    ini.fGen         = 0;
    ini.fNewGame     = 0;
    ini.fValidate    = 0;
    ini.fLogging     = 0;
    ini.fDumpFleets  = 0;
    ini.fDumpPlanets = 0;
    ini.fDumpMap     = 0;
    ini.fBatch       = 0;

    ini.idPlayer = -1;

    ReadIniSettings();

    hwndFrame = CreateWindowA(
        kFrameClassName,
        "Stars!",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        ini.wnFrame.rc.left,
        ini.wnFrame.rc.top,
        ini.wnFrame.rc.right,
        ini.wnFrame.rc.bottom,
        NULL, NULL, hInst, NULL
    );

    if (!hwndFrame) {
        return 0;
    }

    hAccel = LoadAcceleratorsA(hInst, MAKEINTRESOURCEA(0x0074));
    if (!hAccel) {
        return 0;
    }

    hAccelTitle = LoadAcceleratorsA(hInst, MAKEINTRESOURCEA(0x0438));
    if (!hAccelTitle) {
        return 0;
    }

    if (nCmdShow == SW_SHOWNORMAL) {
        if ((ini.wnFrame.flags5.fMaximize == 0) && (ini.wnFrame.flags5.fMinimize == 0)) {
            sw = SW_SHOWNORMAL;
        } else {
            sw = SW_MAXIMIZE;
        }
    } else {
        sw = nCmdShow;
    }

    ShowWindow(hwndFrame, sw);
    ShowWindow(hwndFrame, SW_HIDE);

    return 1;
#else
    (void)nCmdShow;
    return 0;
#endif
}

/* ------------------------------------------------------------
 * FSetUpBatchProcessing (Win32)
 * ------------------------------------------------------------ */
int16_t FSetUpBatchProcessing(void)
{
    int16_t fSuccess = 0;

    g_penvMem = (int16_t *)g_batchJmp;
    if (setjmp(g_batchJmp) == 0) {
        StreamOpen(szBase, 0x0020);

        uint16_t cb = (uint16_t)FileLength();

        g_lpchBatch = (char *)LpAlloc(cb, /*htPerm*/ 0);
        RgFromStream(g_lpchBatch, cb);

        g_lpchBatchMac = g_lpchBatch + cb;

        /* first line becomes szBase */
        char *pch = szBase;
        while (g_lpchBatch < g_lpchBatchMac) {
            if (*g_lpchBatch == '\n') break;
            *pch++ = *g_lpchBatch++;
        }
        if (g_lpchBatch < g_lpchBatchMac) {
            g_lpchBatch++;
        }

        if (pch > szBase) {
            pch[-1] = '\0';
        } else {
            *pch = '\0';
        }

        fSuccess = 1;
    }

    g_penvMem = NULL;
    StreamClose();

    if (!fSuccess) {
        szBase[0] = '\0';
    }

    return fSuccess;
}

/* ------------------------------------------------------------
 * WinMain (Win32) with INI/GDATA bitfields and global refs
 * ------------------------------------------------------------ */
#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    MSG msg;

    hInst = hInstance;

    szBase[0] = '\0';
    ini.wFlags = 0;

    memset(&tutor, 0, sizeof(tutor));
    memset(&vtimer, 0, sizeof(vtimer));
    vtimer.fAutoGenWhenIn = 1;

    if (hPrevInstance == NULL) {
        if (!InitMDIApp()) {
            AlertSz(PszFormatIds(idsUnableInitializeStars, NULL), MB_ICONERROR);
            return 0;
        }
    }

    Randomize2((uint32_t)GetTickCount());

    if (!FCreateStuff()) {
        return 0;
    }
    if (!FGetSystemColors()) {
        AlertSz(PszFormatIds(idsUnableInitializeStars, NULL), MB_ICONERROR);
        return 0;
    }
    if (!InitInstance(nCmdShow)) {
        AlertSz(PszFormatIds(idsUnableInitializeStars, NULL), MB_ICONERROR);
        return 0;
    }

    /* Command-line parsing */
    {
        char *lpT = lpCmdLine;
        char *pch;
        int16_t i;

        while (*lpT != '\0') {
            while (*lpT == ' ') lpT++;
            if (*lpT == '\0') break;

            if (*lpT == '-' || *lpT == '/') {
                lpT++;

                while (*lpT != '\0' && *lpT != ' ') {
                    switch (*lpT) {
                        case 'A':
                        case 'a':
                            ini.fNewGame = 1;
                            break;

                        case 'B':
                        case 'b':
                            lpT++;
                            while (*lpT == ' ') lpT++;

                            pch = szBase;
                            while (*lpT != '\0' && *lpT != ' ') {
                                *pch++ = *lpT++;
                            }
                            *pch = '\0';
                            if (*lpT != '\0') lpT--;

                            if (FSetUpBatchProcessing()) {
                                ini.fStartupFile = 1;
                                ini.fCmdLine     = 1;
                                ini.fGen         = 1;
                                ini.fBatch       = 1;

                                ini.fTry         = 0;
                                ini.grobjSel     = 0;
                            }
                            break;

                        case 'C':
                        case 'c':
                            ini.fCmdLine = (szBase[0] != '\0') ? 1 : 0;
                            break;

                        case 'D':
                        case 'd':
                            lpT++;
                            while (*lpT != '\0' && *lpT != ' ') {
                                switch (*lpT) {
                                    case 'F':
                                    case 'f': ini.fDumpFleets  = 1; break;
                                    case 'P':
                                    case 'p': ini.fDumpPlanets = 1; break;
                                    case 'M':
                                    case 'm': ini.fDumpMap     = 1; break;
                                }
                                lpT++;
                            }
                            if (*lpT != '\0') lpT--;
                            break;

                        case 'G':
                        case 'g':
                            ini.fGen = 1;

                            i = 0;
                            while (lpT[1] >= '0' && lpT[1] <= '9') {
                                lpT++;
                                i = (int16_t)(i * 10 + (*lpT - '0'));
                                if (i >= 1001) {
                                    i = 1000;
                                    while (lpT[1] >= '0' && lpT[1] <= '9') lpT++;
                                    break;
                                }
                            }
                            if (i > 0) {
                                ini.cTurnGen = (int16_t)(i - 1);
                            }
                            break;

                        case 'H':
                        case 'h':
                            gd.fRptSafeDraw = 1;
                            break;

                        case 'L':
                        case 'l':
                            ini.fLogging = 1;
                            break;

                        case 'P':
                        case 'p': {
                            lpT++;
                            while (*lpT == ' ') lpT++;

                            pch = szPassLast;
                            while (*lpT != '\0' && *lpT != ' ' && pch < (szPassLast + 14)) {
                                *pch++ = *lpT++;
                            }
                            *pch = '\0';

                            if (*lpT != '\0') lpT--;

                            lSaltLast = (int32_t)LSaltFromSz(szPassLast);
                            break;
                        }

                        case 'T':
                        case 't':
                            ini.fTry = 1;
                            break;

                        case 'V':
                        case 'v':
                            ini.fValidate = 1;
                            break;

                        case 'W':
                        case 'w':
                            ini.fWait = 1;
                            break;

                        case 'X':
                        case 'x':
                            gd.fChgScanner = 1;
                            break;
                    }

                    lpT++;
                }
            } else {
                pch = szBase;
                while (*lpT != '\0' && *lpT != ' ') {
                    *pch++ = *lpT++;
                }
                *pch = '\0';

                ini.fStartupFile = 1;
                ini.fCmdLine     = 1;
            }
        }
    }

    PostMessageA(hwndFrame, WM_STARS_STARTUP, 0, 0);

    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        if (hwndTitle == NULL) {
            BOOL iconic = IsIconic(hwndFrame);

            if (iconic || !TranslateAcceleratorA(hwndFrame, hAccel, &msg)) {
                TranslateMessage(&msg);

                if (msg.message == WM_KEYDOWN || msg.message == WM_SYSKEYDOWN) {
                    if (!FHandleKey(msg.hwnd, msg.message, msg.wParam, msg.lParam)) {
                        DispatchMessageA(&msg);
                    }
                } else if (msg.message == WM_CHAR) {
                    if (!FHandleChar(msg.hwnd, msg.wParam, msg.lParam)) {
                        DispatchMessageA(&msg);
                    }
                } else {
                    DispatchMessageA(&msg);
                }
            }
        } else {
            if (!TranslateAcceleratorA(hwndFrame, hAccelTitle, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }
        }
    }

    FreeStuff();
    return (int)msg.wParam;
}
#endif
