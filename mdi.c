
#include "types.h"
#include "globals.h"
#include "debuglog.h"

#include "resource.h"

#include "mdi.h"
#include "init.h"
#include "util.h"
#include "utilgen.h"
#include "tutor.h"
#include "create.h"
#include "planet.h"

/* file existence check used by TitleWndProc (matches file.c portability) */
#if defined(_WIN32) && !defined(STARS_USE_WIN_STUBS)
#include <io.h>
#define stars_access _access
#define stars_access_mode 0
#else
#include <unistd.h>
#define stars_access access
#define stars_access_mode 0
#endif

/* globals */
char rgTOWidth[2][2] = {{-3, 0}, {2, 1}};                                                                                                                       /* 1020:7702 */
uint8_t vrgbShuffleSerial[21] = {0x0b, 0x04, 0x05, 0x10, 0x11, 0x0c, 0x13, 0x0f, 0x0a, 0x01, 0x0e, 0x0d, 0x03, 0x12, 0x02, 0x14, 0x09, 0x07, 0x00, 0x08, 0x06}; /* 1020:2870 */

/* functions */
void VerifyTurns(void)
{
    int16_t idsError;
    int16_t idCur;
    int16_t cAi;
    int16_t i;
    int16_t cOut;
    int16_t fOut;

    /* TODO: implement */
}

int16_t FSerialAndEnvFromSz(int32_t *plSerial, uint8_t *pbEnv, char *pszIn)
{
    uint8_t rgbRaw[21];
    int16_t fSuccess;
    int16_t j;
    uint8_t bXor;
    int16_t i;
    int16_t cBits;
    int16_t iRaw;
    int16_t iPass;
    int32_t lSerial;
    int32_t lTank;
    uint8_t rgbRaw2[21];
    uint8_t b64;

    /* TODO: implement */
    return 0;
}

void FormatSerialAndEnv(int32_t lSerial, uint8_t *pbEnv, char *pszOut)
{
    uint8_t rgbRaw[21];
    int16_t j;
    uint8_t bXor;
    int16_t i;
    int16_t cBits;
    int16_t iRaw;
    int16_t iPass;
    int32_t lTank;
    uint8_t rgbRaw2[21];
    uint8_t b64;

    /* TODO: implement */
}

int16_t FWasRaceFile(char *szFile, int16_t fChkPass)
{
    int16_t idsError;
    int32_t lSaltSav;
    PLAYER plr;
    MemJump *penvMemSav;
    MemJump env;
    int16_t fRet;
    int16_t fSav;

    /* debug symbols */
    /* label LBadFile @ MEMORY_MDI:0x5dec */

    /* TODO: implement */
    return 0;
}

void EnsureAis(void)
{
    int16_t fHostSav;
    int16_t fErrSav;
    int16_t fOpened;
    int16_t fWorkDone;
    int16_t fSubmitSav;
    int16_t iPlayer;
    MDPLR rgmdplr[16];

    /* TODO: implement */
}

int16_t CTurnsOutSafe(void)
{
    int16_t idPlayerSav;
    int16_t fHostModeSav;
    int16_t fGenSav;
    int16_t cturn;

    /* TODO: implement */
    return 0;
}

#ifdef _WIN32

INT_PTR CALLBACK HostModeDialog(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int16_t (*lpProc)(void);
    int16_t fRet;
    RECT rc;
    int16_t mf;
    HDC hdc;
    POINT pt;
    int16_t tpm;
    int16_t i;
    int16_t iRet;
    int16_t iSel;
    int16_t iDiamond;
    HMENU hmenuPopup;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x6db6 */
    /* block (block) @ MEMORY_MDI:0x71b9 */
    /* label Done @ MEMORY_MDI:0x6d62 */

    /* TODO: implement */
    return 0;
}

int16_t FFindSomethingAndSelectIt(void)
{
    PLANET *lpplMac;
    PLANET *lppl;
    int16_t i;
    FLEET *lpfl;

    /* TODO: implement */
    return 0;
}

int16_t CFindTurnsOutstanding(void)
{
    int16_t idsError;
    int16_t cAi;
    int16_t i;
    int16_t cOut;
    int16_t fSav;
    int16_t fOut;

    /* TODO: implement */
    return 0;
}

LRESULT CALLBACK TitleWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc;
    int16_t i;
    HPALETTE hpalSav;
    RECT rc;
    int16_t dy;
    int16_t dxGap;
    int16_t dx;
    int16_t xCur;
    char *psz;
    PAINTSTRUCT ps;
    RECT rcWnd;
    HBRUSH hbrSav;
    RECT rcT;
    LOGFONT *plf;
    HFONT hfont;
    HFONT hfontSav;

    /* --------------------------------------------------------------------
     * Notes:
     * - This is a direct translation of the Win16 TitleWndProc (1020:9126).
     * - Button commands (New / Load / Continue / Exit) call existing stubs.
     * - Palette handling matches WM_QUERYNEWPALETTE / WM_PALETTECHANGED logic.
     * -------------------------------------------------------------------- */

    switch (msg)
    {
    case WM_CREATE:
    {
        DBG_LOGD("WM_CREATE: vcScreenColors=%d vhdibTitle=%p vhpalSplash=%p dyArial8=%d",
                 (int)vcScreenColors, (void *)vhdibTitle, (void *)vhpalSplash, (int)dyArial8);

        /* Load splash (256+ colors only) and palette. */
        if (vcScreenColors >= 8)
        {
            DBG_LOGD("WM_CREATE: loading splash resource IDDIB_SPLASH=%d", (int)IDDIB_SPLASH);
            vhdibTitle = HdibLoadBigResource(IDDIB_SPLASH);
            DBG_LOGD("WM_CREATE: HdibLoadBigResource -> vhdibTitle=%p", (void *)vhdibTitle);

            if (vhpalSplash == NULL && vhdibTitle != NULL)
            {
                vhpalSplash = HpalFromDib(vhdibTitle);
                DBG_LOGD("WM_CREATE: HpalFromDib(%p) -> vhpalSplash=%p", (void *)vhdibTitle, (void *)vhpalSplash);
            }
        }
        else
        {
            DBG_LOGD("WM_CREATE: skipping splash load (vcScreenColors=%d < 8)", (int)vcScreenColors);
        }

        GetClientRect(hwnd, &rc);
        DBG_LOGD("WM_CREATE: client rc: L=%d T=%d R=%d B=%d",
                 (int)rc.left, (int)rc.top, (int)rc.right, (int)rc.bottom);

        /* Use the same 4:3 letterboxed “content rect” as the splash so buttons stay inside it. */
        {
            const int32_t srcW = 800;
            const int32_t srcH = 600;

            const int32_t fullW = (int32_t)(rc.right - rc.left);
            const int32_t fullH = (int32_t)(rc.bottom - rc.top);

            int32_t contentW = fullW;
            int32_t contentH = (contentW * srcH) / srcW;
            if (contentH > fullH)
            {
                contentH = fullH;
                contentW = (contentH * srcW) / srcH;
            }

            const int32_t contentX = (fullW - contentW) / 2;
            const int32_t contentY = (fullH - contentH) / 2;

            /* Log so you can confirm the math matches WM_PAINT */
            DBG_LOGD("WM_CREATE: content rc: X=%ld Y=%ld W=%ld H=%ld",
                     (long)contentX, (long)contentY, (long)contentW, (long)contentH);

            /* Now base layout off contentW/contentH, but keep everything in 32-bit until the end. */

            /* dx: max(120, contentW/8) */
            {
                int32_t dx32 = (contentW >> 3);
                DBG_LOGD("WM_CREATE: dx init contentW>>3=%ld", (long)dx32);

                if (dx32 < 120)
                    dx32 = 120;
                DBG_LOGD("WM_CREATE: dx clamped=%ld", (long)dx32);

                /* if short content window, add dx/6 */
                if (contentH < 650)
                {
                    int32_t add32 = dx32 / 6;
                    dx32 += add32;
                    DBG_LOGD("WM_CREATE: short contentH=%ld -> dx += dx/6 (%ld) => %ld",
                             (long)contentH, (long)add32, (long)dx32);
                }

                /* dxGap = (contentW - dx*4)/4 */
                {
                    int32_t dxGap32 = (contentW - (dx32 * 4)) / 4;
                    if (dxGap32 < 0)
                        dxGap32 = 0; /* avoid negative gaps if window is very narrow */

                    /* xCur starts at left edge of content rect + half gap */
                    int32_t xCur32 = contentX + (dxGap32 / 2);

                    dx = (int16_t)dx32;
                    dxGap = (int16_t)dxGap32;
                    xCur = (int16_t)xCur32;

                    DBG_LOGD("WM_CREATE: dxGap=%ld xCur(start)=%ld (contentX=%ld)",
                             (long)dxGap32, (long)xCur32, (long)contentX);
                }
            }

            /* dy for buttons: base on contentH, not full client height */
            if (contentH > 500)
                dy = (int16_t)((5 * dyArial8) / 2);
            else
                dy = (int16_t)(dyArial8 << 1);

            DBG_LOGD("WM_CREATE: dy=%d (contentH=%ld)", (int)dy, (long)contentH);

            /* If you also compute a Y position for the buttons elsewhere,
               anchor it to contentY+contentH (bottom of the splash area) instead of rc.bottom. */
            /* Example:
               yButtons = (int16_t)(contentY + contentH - dy - margin);
            */
        }

        /* Create 4 buttons */
        for (i = 0; i < 4; i++)
        {
            psz = PszGetCompressedString(idsNewGame + i);
            DBG_LOGD("WM_CREATE: button[%d] text id=%d psz=%p '%s'",
                     (int)i, (int)(idsNewGame + i), (void *)psz, (psz ? psz : "(null)"));

            rghwndBtnSplash[i] = CreateWindow(
                "BUTTON",
                psz,
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                xCur,
                (int16_t)(rc.bottom - dy - ((5 * dyArial8) / 2)),
                dx,
                dy,
                hwnd,
                (HMENU)(uintptr_t)i,
                hInst,
                NULL);

            DBG_LOGD("WM_CREATE: CreateWindow BUTTON[%d] -> hwnd=%p at x=%d y=%d w=%d h=%d",
                     (int)i, (void *)rghwndBtnSplash[i],
                     (int)xCur, (int)(rc.bottom - dy - ((5 * dyArial8) / 2)),
                     (int)dx, (int)dy);

            if (rghwndBtnSplash[i] == NULL)
            {
                DBG_LOGD("WM_CREATE: ERROR: CreateWindow failed for button[%d]", (int)i);
            }

            if (i == 2)
            {
                DBG_LOGD("WM_CREATE: button[2] continue check: szBase[0]=0x%02x szBase='%s'",
                         (unsigned)(uint8_t)szBase[0], szBase);

                /* Default: disable unless we prove the file exists. */
                bool enable = false;

                if (szBase[0] != '\0')
                {
                    int acc = stars_access(szBase, stars_access_mode); /* mode should be 0 like __access(path,0) */
                    DBG_LOGD("WM_CREATE: stars_access('%s', mode=%d) -> %d",
                             szBase, (int)stars_access_mode, (int)acc);

                    if (acc != -1)
                    {
                        enable = true; /* file exists -> keep enabled */
                        DBG_LOGD("WM_CREATE: button[2] enabled (file exists)");
                    }
                    else
                    {
                        DBG_LOGD("WM_CREATE: button[2] will disable (file missing/unreadable)");
                    }
                }
                else
                {
                    DBG_LOGD("WM_CREATE: button[2] will disable (empty szBase)");
                }

                EnableWindow(rghwndBtnSplash[2], enable ? TRUE : FALSE);
                if (!enable)
                {
                    DBG_LOGD("WM_CREATE: disabled button[2]");
                }
            }

            if (rc.bottom < 500)
            {
                DBG_LOGD("WM_CREATE: setting font for button[%d] font=%p", (int)i, (void *)rghfontArial8[1]);
                SendMessage(rghwndBtnSplash[i], WM_SETFONT, (WPARAM)rghfontArial8[1], MAKELPARAM(TRUE, 0));
            }

            xCur = (int16_t)(xCur + dx + dxGap);
        }

        DBG_LOGD("WM_CREATE: done");
        return 0;
    }

    case WM_DESTROY:
    {
        DBG_LOGD("WM_DESTROY: vhdibTitle=%p vhpalSplash=%p fFreeingTitle=%d gd.fExitWindows=%d vretExitValue=%d",
                 (void *)vhdibTitle, (void *)vhpalSplash, (int)fFreeingTitle, (int)gd.fExitWindows, (int)vretExitValue);

        if (vhdibTitle != NULL)
        {
            DBG_LOGD("WM_DESTROY: freeing DIB %p", (void *)vhdibTitle);
            GlobalUnlock(vhdibTitle);
            FreeResource(vhdibTitle);
            vhdibTitle = NULL;
        }

        if (!fFreeingTitle)
        {
            DBG_LOGD("WM_DESTROY: normal exit path");
            if (gd.fExitWindows)
            {
                DBG_LOGD("WM_DESTROY: ExitWindows(%u)", (unsigned)(uint16_t)vretExitValue);
                ExitWindows((DWORD)(uint16_t)vretExitValue, 0);
            }
            else
            {
                DBG_LOGD("WM_DESTROY: WriteIniSettings(); PostQuitMessage(%d)", (int)vretExitValue);
                WriteIniSettings();
                PostQuitMessage(vretExitValue);
            }
        }
        else
        {
            DBG_LOGD("WM_DESTROY: fFreeingTitle=1 => skipping exit path");
        }

        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    case WM_QUERYNEWPALETTE:
        DBG_LOGD("WM_QUERYNEWPALETTE: vcScreenColors=%d vhpalSplash=%p", (int)vcScreenColors, (void *)vhpalSplash);
        /* fallthrough */
    case WM_PALETTECHANGED:
    {
        DBG_LOGD("WM_PALETTECHANGED: wParam(hwndChanged)=%p self=%p vcScreenColors=%d vhpalSplash=%p",
                 (void *)(HWND)wParam, (void *)hwnd, (int)vcScreenColors, (void *)vhpalSplash);

        if (msg == WM_PALETTECHANGED && (HWND)wParam == hwnd)
        {
            DBG_LOGD("WM_PALETTECHANGED: ignoring (we caused it)");
            return 0;
        }

        if (vcScreenColors < 8 || vhpalSplash == NULL)
        {
            DBG_LOGD("WM_PALETTE*: skipping realize (colors=%d pal=%p)", (int)vcScreenColors, (void *)vhpalSplash);
            return 0;
        }

        hdc = GetDC(hwnd);
        DBG_LOGD("WM_PALETTE*: GetDC -> %p", (void *)hdc);

        hpalSav = SelectPalette(hdc, vhpalSplash, FALSE);
        DBG_LOGD("WM_PALETTE*: SelectPalette -> old=%p new=%p", (void *)hpalSav, (void *)vhpalSplash);

        i = (int16_t)RealizePalette(hdc);
        DBG_LOGD("WM_PALETTE*: RealizePalette -> %d", (int)i);

        SelectPalette(hdc, hpalSav, FALSE);
        ReleaseDC(hwnd, hdc);

        if (i != 0)
        {
            DBG_LOGD("WM_PALETTE*: invalidating (palette changed)");
            InvalidateRect(hwnd, NULL, TRUE);
            return 1;
        }

        return 0;
    }

    case WM_COMMAND:
    {
        DBG_LOGD("WM_COMMAND: wParam=0x%lx lParam=0x%lx (id=%lu) fFreeingTitle=%d",
                 (unsigned long)wParam, (unsigned long)lParam, (unsigned long)wParam, (int)fFreeingTitle);

        switch (wParam)
        {
        case 0:
            DBG_LOGD("WM_COMMAND: NewGameWizard");
            NewGameWizard(hwnd, 0);
            DBG_LOGD("WM_COMMAND: after NewGameWizard: lpPlanets=%p game.lid=%ld",
                     (void *)lpPlanets, (long)game.lid);

            if (lpPlanets == NULL && game.lid == 0)
            {
                DBG_LOGD("WM_COMMAND: new game failed -> SetFocus(title)");
                SetFocus(hwnd);
                break;
            }

            if (!fFreeingTitle)
            {
                DBG_LOGD("WM_COMMAND: destroying title window hwndTitle=%p hwndFrame=%p",
                         (void *)hwndTitle, (void *)hwndFrame);
                fFreeingTitle = 1;
                DestroyWindow(hwndTitle);
                hwndTitle = NULL;
            }

            DBG_LOGD("WM_COMMAND: ShowWindow(hwndFrame, SW_SHOW)");
            ShowWindow(hwndFrame, SW_SHOW);
            break;

        case 1:
        case 2:
        {
            bool fStartup = ((uint16_t)wParam == 2);
            DBG_LOGD("WM_COMMAND: %s (fStartup=%d)", (wParam == 1) ? "Load" : "Continue", (int)fStartup);

            {
                int og = FOpenGame(hwnd, 0);
                DBG_LOGD("WM_COMMAND: FOpenGame -> %d (idPlayer=%d)", (int)og, (int)idPlayer);

                if (og > 0)
                {
                    if (!fFreeingTitle)
                    {
                        DBG_LOGD("WM_COMMAND: destroying title window hwndTitle=%p", (void *)hwndTitle);
                        fFreeingTitle = 1;
                        DestroyWindow(hwndTitle);
                        hwndTitle = NULL;
                    }

                    if (idPlayer != -1)
                    {
                        DBG_LOGD("WM_COMMAND: ShowWindow(hwndFrame, SW_SHOW)");
                        ShowWindow(hwndFrame, SW_SHOW);
                    }

                    DBG_LOGD("WM_COMMAND: InitializeMenu(NULL)");
                    InitializeMenu(NULL);

                    DBG_LOGD("WM_COMMAND: PostMessage(hwndFrame, WM_COMMAND, 0x0fa1)");
                    PostMessage(hwndFrame, WM_COMMAND, (WPARAM)0x0fa1, 0);

                    DBG_LOGD("WM_COMMAND: tutorial? game.fTutorial=%d idPlayer=%d",
                             (int)game.fTutorial, (int)idPlayer);

                    if (game.fTutorial && idPlayer == 0)
                    {
                        DBG_LOGD("WM_COMMAND: StartTutor(0)");
                        StartTutor(0);
                    }
                }
                else
                {
                    DBG_LOGD("WM_COMMAND: open failed -> SetFocus(title)");
                    SetFocus(hwnd);
                }
            }

            ini.fStartupFile = (uint16_t)(fStartup ? 1 : 0);
            DBG_LOGD("WM_COMMAND: ini.fStartupFile=%u", (unsigned)ini.fStartupFile);
            break;
        }

        case 3:
        default:
            DBG_LOGD("WM_COMMAND: Exit path gd.fExitWindows=%d vretExitValue=%d", (int)gd.fExitWindows, (int)vretExitValue);
            if (gd.fExitWindows)
                ExitWindows((DWORD)(uint16_t)vretExitValue, 0);
            else
            {
                WriteIniSettings();
                PostQuitMessage(vretExitValue);
            }
            break;
        }

        return 0;
    }

    case WM_PAINT:
    {
        DBG_LOGD("WM_PAINT: IsIconic=%d vcScreenColors=%d vhdibTitle=%p vhpalSplash=%p",
                 (int)IsIconic(hwnd), (int)vcScreenColors, (void *)vhdibTitle, (void *)vhpalSplash);

        if (IsIconic(hwnd))
        {
            hdc = BeginPaint(hwnd, &ps);
            DBG_LOGD("WM_PAINT(iconic): BeginPaint hdc=%p hiconStars=%p", (void *)hdc, (void *)hiconStars);
            DrawIcon(hdc, 2, 2, hiconStars);
            EndPaint(hwnd, &ps);
            return 0;
        }

        hdc = BeginPaint(hwnd, &ps);
        DBG_LOGD("WM_PAINT: BeginPaint hdc=%p", (void *)hdc);

        hbrSav = (HBRUSH)SelectObject(hdc, hbrButtonFace);
        DBG_LOGD("WM_PAINT: SelectObject(hbrButtonFace=%p) -> old=%p", (void *)hbrButtonFace, (void *)hbrSav);

        GetClientRect(hwnd, &rcWnd);
        DBG_LOGD("WM_PAINT: client rcWnd: L=%d T=%d R=%d B=%d",
                 (int)rcWnd.left, (int)rcWnd.top, (int)rcWnd.right, (int)rcWnd.bottom);

        if (vcScreenColors >= 8 && vhdibTitle != NULL)
        {
            /* source is 800x600 (4:3) */
            const int32_t srcW = 800;
            const int32_t srcH = 600;

            RECT rc;
            GetClientRect(hwnd, &rc);

            const int32_t fullW = (int32_t)(rc.right - rc.left);
            const int32_t fullH = (int32_t)(rc.bottom - rc.top);

            /* fit with preserved aspect (integer, 32-bit intermediates) */
            int32_t dstW = fullW;
            int32_t dstH = (dstW * srcH) / srcW;
            if (dstH > fullH)
            {
                dstH = fullH;
                dstW = (dstH * srcW) / srcH;
            }

            /* center in client */
            const int32_t dstX = (fullW - dstW) / 2;
            const int32_t dstY = (fullH - dstH) / 2;

            /* (optional) clear bars so you don’t see junk from previous frames */
            PatBlt(hdc, 0, 0, fullW, fullH, BLACKNESS);

            DibBlt(hdc,
                   dstX, dstY,
                   dstW, dstH,
                   vhdibTitle, 0, 0,
                   srcW, srcH,
                   SRCCOPY);
        }
        else
        {
            DBG_LOGD("WM_PAINT: fallback stars: colors=%d vhdibTitle=%p", (int)vcScreenColors, (void *)vhdibTitle);
            /* ... existing fallback ... */
        }

        psz = SzVersion();
        DBG_LOGD("WM_PAINT: SzVersion -> %p '%s'", (void *)psz, (psz ? psz : "(null)"));

        if (rghwndBtnSplash[0] == NULL)
            DBG_LOGD("WM_PAINT: WARNING: rghwndBtnSplash[0]==NULL (buttons not created?)");
        else
            DBG_LOGD("WM_PAINT: rghwndBtnSplash[0]=%p", (void *)rghwndBtnSplash[0]);

        GetWindowRect(rghwndBtnSplash[0], &rc);
        DBG_LOGD("WM_PAINT: button0 rect (screen coords): L=%d T=%d R=%d B=%d",
                 (int)rc.left, (int)rc.top, (int)rc.right, (int)rc.bottom);

        rcWnd.top = (int16_t)(rc.top - ((9 * dyArial8) / 2));
        rcWnd.bottom = (int16_t)(rcWnd.top + ((3 * dyArial8) / 2));

        DBG_LOGD("WM_PAINT: version rcWnd (mixed coords!): L=%d T=%d R=%d B=%d dyArial8=%d",
                 (int)rcWnd.left, (int)rcWnd.top, (int)rcWnd.right, (int)rcWnd.bottom, (int)dyArial8);

        RcCtrTextOut(hdc, &rcWnd, psz, (int16_t)strlen(psz));
        DBG_LOGD("WM_PAINT: RcCtrTextOut done");

        SelectObject(hdc, hbrSav);
        EndPaint(hwnd, &ps);
        DBG_LOGD("WM_PAINT: EndPaint done");
        return 0;
    }

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

void CommandHandler(HWND hwnd, uint16_t wParam)
{
    POINT pt;
    HMENU hmenu;
    int16_t (*lpProc)(void);
    int16_t dy;
    char szExt[4];
    int16_t dx;
    int16_t fRet;
    RECT rc;
    int16_t iplrOld;
    int16_t cPageX;
    int16_t idCur;
    int16_t mf;
    int16_t id;
    char *psz;
    uint16_t hcurSav;
    int16_t ids;
    PLANET *lpplMac;
    int16_t cObj;
    int16_t ifl;
    PLANET *lppl;
    FLEET *lpfl;
    int16_t i;
    // TIMERINFO ti;
    uint32_t dwTickCur;
    uint32_t dwTickBase;
    // PD pd;
    int16_t cPageY;
    int16_t xPage;
    int16_t dxMax;
    int16_t dxDPI;
    int16_t dyPrintTiny;
    int16_t dMargin;
    int16_t y;
    int32_t ldx;
    uint16_t hfontPrintTiny;
    uint16_t hfontPrint;
    POINT ptLegendB;
    POINT ptLegendA;
    int16_t dyPrint;
    int16_t dyMax;
    uint16_t hfontSav;
    int16_t dSize;
    int16_t yPage;
    int16_t cch;
    int32_t ldy;
    int16_t dyDPI;
    int16_t yOff;
    int16_t xOff;
    int32_t x;
    char szT[256];

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x3112 */
    /* block (block) @ MEMORY_MDI:0x32e6 */
    /* block (block) @ MEMORY_MDI:0x3387 */
    /* block (block) @ MEMORY_MDI:0x3602 */
    /* block (block) @ MEMORY_MDI:0x39c0 */
    /* block (block) @ MEMORY_MDI:0x3b66 */
    /* block (block) @ MEMORY_MDI:0x3bf0 */
    /* block (block) @ MEMORY_MDI:0x3f6e */
    /* block (block) @ MEMORY_MDI:0x4090 */
    /* block (block) @ MEMORY_MDI:0x440c */
    /* block (block) @ MEMORY_MDI:0x44cc */
    /* block (block) @ MEMORY_MDI:0x451d */
    /* block (block) @ MEMORY_MDI:0x4592 */
    /* block (block) @ MEMORY_MDI:0x461d */
    /* block (block) @ MEMORY_MDI:0x4818 */
    /* block (block) @ MEMORY_MDI:0x4b14 */
    /* block (block) @ MEMORY_MDI:0x4df3 */
    /* label LTutorialFinishUp @ MEMORY_MDI:0x433d */
    /* label LWaitForTurn @ MEMORY_MDI:0x47d1 */
    /* label RepGen @ MEMORY_MDI:0x42d0 */
    /* label Default @ MEMORY_MDI:0x50ba */
    /* label LNewTurnAvail @ MEMORY_MDI:0x4818 */
    /* label LRetryReport @ MEMORY_MDI:0x4504 */

    /* TODO: implement */
}

LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc;
    int16_t i;
    uint16_t hpalSav;
    int16_t ich;
    int16_t fErrSav;
    int16_t idCur;
    int16_t iOffset;
    uint16_t hcs;
    int16_t id;
    int16_t idPlanet;
    POINT ptOld;
    POINT pt;
    uint16_t uTimerIdOld;
    int16_t grSel;
    char *pch;
    RECT rc;
    char szExt[4];
    int16_t (*lpProc)(void);
    int16_t fRet;
    POINT ptAct;
    RECT rc2;
    int32_t lSerial;
    POINT ptD;
    uint16_t hbrSav;
    POINT ptStart;
    POINT ptChg;
    TEXTMETRIC tm;
    PAINTSTRUCT ps;
    int16_t yOffset;
    char szTemp[80];

    /*
     * TODO: full FrameWndProc implementation.
     *
     * For now, this minimal WndProc allows the window to be created and closed,
     * which is enough to validate that WinMain + init can launch a basic app.
     */
    switch (msg)
    {
    case WM_CREATE:
    {
        HDC hdc;
        TEXTMETRIC tm;

        hdc = GetDC(hwnd);
        if (hdc != NULL)
        {
            (void)FCreateFonts(hdc);

            /* System font height (including external leading), Win32 style */
            GetTextMetrics(hdc, &tm);
            dySysFont = (int16_t)(tm.tmHeight + tm.tmExternalLeading);

            /* Original: dySBar = (dyArial8 + 0x0c) * 2; */
            dySBar = (int16_t)((int32_t)(dyArial8 + 0x0c) * 2);

            ReleaseDC(hwnd, hdc);
        }
        else
        {
            /* Defensive fallbacks if DC acquisition fails */
            dySysFont = 0;
            dySBar = (int16_t)((int32_t)(dyArial8 + 0x0c) * 2);
        }

        InitTiles();
        EnsureTileSize(iWindowLayout == 2);
        return 0;
    }
    case WM_STARS_STARTUP:
        /*
         * Win16 behavior: if no game is currently loaded, create the full-screen
         * title/splash window (WS_POPUP|WS_VISIBLE) as a child of the hidden frame.
         */
        if (hwndTitle == NULL)
        {
            int cx = GetSystemMetrics(SM_CXSCREEN);
            int cy = GetSystemMetrics(SM_CYSCREEN);

            hwndTitle = CreateWindowA(
                szTitle,
                "Stars!",
                WS_POPUP | WS_VISIBLE,
                0,
                0,
                cx,
                cy,
                hwndFrame,
                NULL,
                hInst,
                NULL);
            fFreeingTitle = 0;
        }
        return 0;

    case WM_QUERYNEWPALETTE:
    {
        if (hwndTitle)
        {
            return SendMessage(hwndTitle, msg, wParam, lParam);
        }

        HDC hdc = GetDC(hwnd);
        HPALETTE hpalOld = SelectPalette(hdc, vhpal, FALSE);
        int changed = RealizePalette(hdc);
        SelectPalette(hdc, hpalOld, FALSE);
        ReleaseDC(hwnd, hdc);

        if (changed)
        {
            InvalidateRect(hwnd, NULL, TRUE);
            return TRUE;
        }
        return FALSE;
    }

    case WM_PALETTECHANGED:
    {
        if ((HWND)wParam == hwnd)
            return 0;

        /* forward to same logic */
        SendMessage(hwnd, WM_QUERYNEWPALETTE, 0, 0);
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void GetWindowRc(HWND hwnd, RECT *prc)
{
    WINDOWPLACEMENT wndpl;

    wndpl.length = sizeof(wndpl);
    GetWindowPlacement(hwnd, &wndpl);

    prc->left = wndpl.rcNormalPosition.left;
    prc->top = wndpl.rcNormalPosition.top;
    prc->right = (int16_t)(wndpl.rcNormalPosition.right - wndpl.rcNormalPosition.left);
    prc->bottom = (int16_t)(wndpl.rcNormalPosition.bottom - wndpl.rcNormalPosition.top);
}

void DrawHostDialog2(HWND hwnd, HDC hdcIn)
{
    uint32_t dsec;
    HDC hdc;
    uint16_t dhour;
    int16_t bkMode;
    int16_t yCur;
    int16_t i;
    uint16_t dmin;
    int16_t dday;
    int16_t cch;
    RECT rcDiamond;
    uint32_t crBackSav;
    int16_t x;
    char szStat[30];

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x6300 */

    /* TODO: implement */
}

void DrawHostOptions(HWND hwnd, HDC hdc, int16_t iDraw)
{

    // Stars! original: trivial prologue/epilogue only (no-op).
    (void)hwnd;
    (void)hdc;
    (void)iDraw;
}

void WriteIniSettings(void)
{
    int16_t ctile;
    char szPd[3];
    TILE *rgtile;
    int16_t i;
    int16_t iPass;
    char szEntry[16];
    char szIniFile[16];
    char *psz;
    char szSection[16];
    uint16_t iCol;
    char ch;

    /* TODO: implement */
}

VOID CALLBACK HostTimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    HWND hwndT;
    char szExt[4];
    int16_t cOut;
    int16_t fSav;
    int16_t idCur;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x7756 */
    /* label Done @ MEMORY_MDI:0x7997 */
    /* label RedrawText @ MEMORY_MDI:0x7906 */
    /* label Loop @ MEMORY_MDI:0x784a */

    /* TODO: implement */
}

uint16_t GetASubMenu(HWND hwnd, int16_t iMenu)
{
    int16_t fChildMenu;
    HMENU hmenu;

    /* TODO: implement */
    return 0;
}

int16_t FOpenGame(HWND hwnd, int16_t fRaceOnly)
{
    // OFN ofn;
    uint16_t i;
    char szFile[256];
    char *pch;
    char szFileTitle[256];
    char szFilter[256];
    int16_t fRet;
    int16_t grobjIni;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x5a99 */
    /* block (block) @ MEMORY_MDI:0x5cd3 */
    /* label LGotFileName @ MEMORY_MDI:0x5a99 */

    /* TODO: implement */
    return 0;
}

void InitializeMenu(HMENU hmenu)
{
    int16_t cMenu;
    int16_t i;
    HMENU hmenuSub;

    /* TODO: implement */
}

uint16_t HcrsFromFrameWindowPt(POINT pt, int16_t *pgrSel)
{
    uint16_t hcs;
    int16_t fInHBar2;
    int16_t fInHBar1;
    int16_t fInVBar;

    /* TODO: implement */
    return 0;
}

POINT InvertPaneBorder(HDC hdc, int16_t grSel, POINT dpt, POINT *pdptPrev)
{
    int16_t notMin;
    int16_t dChg;
    POINT dptT;
    POINT dptPrev;
    int16_t dyAboveMinCur;
    POINT dptOld;
    int16_t dyMsgCur;
    int16_t dyMinAboveH2;
    int16_t dyPlanMin;
    int16_t dxScanMin;
    int16_t x;
    int16_t dyMin;
    POINT pt;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x1e63 */
    /* block (block) @ MEMORY_MDI:0x1f93 */
    /* block (block) @ MEMORY_MDI:0x1fe4 */
    /* block (block) @ MEMORY_MDI:0x20ba */
    /* block (block) @ MEMORY_MDI:0x210e */

    /* TODO: implement */
    return pt;
}

void BringUpHostDlg(void)
{
    POINT pt;
    int16_t (*lpProc)(void);
    int16_t fRet;

    /* debug symbols */
    /* label LAutoMode @ MEMORY_MDI:0x60cc */
    /* label Top @ MEMORY_MDI:0x6083 */
    /* label LNextGen @ MEMORY_MDI:0x6120 */

    /* TODO: implement */
}

INT_PTR CALLBACK HostOptionsDialog(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RECT rc;
    HDC hdc;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x761b */

    /* TODO: implement */
    return 0;
}

int16_t InitMDIApp(void)
{
    WNDCLASS wc;

    /*
     * Minimal class registration to get a frame window up.
     *
     * The original Stars! registers many more classes (scanner, message, etc.).
     * Those are deferred until their respective WndProcs are implemented.
     */

    if (szFrame[0] == '\0')
    {
        strcpy(szFrame, "StarsFrame");
    }

    memset(&wc, 0, sizeof(wc));
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc = FrameWndProc;
    wc.hInstance = hInst;
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_APPWORKSPACE + 1);
    wc.lpszMenuName = MAKEINTRESOURCEA(STARSMENU);
    wc.lpszClassName = szFrame;

    if (RegisterClass(&wc) == 0)
    {
        return 0;
    }

    /* A minimal Title class is helpful for later but optional today. */
    if (szTitle[0] == '\0')
    {
        strcpy(szTitle, "StarsTitle");
    }

    memset(&wc, 0, sizeof(wc));
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc = TitleWndProc;
    wc.hInstance = hInst;
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(LTGRAY_BRUSH);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = szTitle;

    (void)RegisterClass(&wc);
    return 1;
}

void CreateChildWindows(void)
{
    char szData[100];
    POINT pt;
    char *psz;
    char szGame[15];

    /* TODO: implement */
}

void SetWindowIniString(char *sz, HWND hwnd)
{
    char ch;
    RECT rc;

    /* TODO: implement */
}

void RestoreSelection(void)
{
    PLANET *lppl;

    /* TODO: implement */
}

void RefitFrameChildren(void)
{
    int16_t dyMsg;
    HMENU hmenu;
    int16_t i;
    int16_t dyMinMin;
    int16_t dyMsgMin;
    int16_t dyMin;
    int16_t dyT;
    int16_t yScanner;
    int16_t dyTot;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x8d56 */
    /* block (block) @ MEMORY_MDI:0x8de6 */
    /* block (block) @ MEMORY_MDI:0x8fb7 */

    /* TODO: implement */
}

#endif /* _WIN32 */