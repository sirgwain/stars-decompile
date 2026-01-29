
#include "types.h"
#include "globals.h"

#include "stars.h"
#include "strings.h"
#include "utilgen.h"
#include "memory.h"
#include "debuglog.h"

/* functions */

int16_t FSetUpBatchProcessing(void)
{
    char *pch;
    MemJump env;
    ;
    int16_t fSuccess;
    int16_t cb;

    /* debug symbols */
    /* label LError @ MEMORY_MAIN:0x0785 */

    /* TODO: implement */
    return 0;
}

int16_t IPlrAlsoCheater(int16_t iplr)
{
    int16_t i;

    /* TODO: implement */
    return 0;
}

#ifdef _WIN32

INT_PTR CALLBACK About(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RECT rc;
    uint16_t hdc;
    int16_t i;
    int16_t (*lpProc)(void);
    HWND hwndCtl;

    /* debug symbols */
    /* block (block) @ MEMORY_MAIN:0x12d1 */
    /* block (block) @ MEMORY_MAIN:0x14a3 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK OrderInfoDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RECT rc;

    /* TODO: implement */
    return 0;
}

int16_t FGetSystemColors(void)
{
    /* Translated from Win16: update global brushes/colors from current theme. */
    COLORREF cr;

    if (hbrButtonFace != NULL)
    {
        FreeHbr(hbrButtonFace);
        hbrButtonFace = NULL;
    }
    if (hbrButtonHilite != NULL)
    {
        FreeHbr(hbrButtonHilite);
        hbrButtonHilite = NULL;
    }
    if (hbrButtonShadow != NULL)
    {
        FreeHbr(hbrButtonShadow);
        hbrButtonShadow = NULL;
    }
    if (hbrButtonText != NULL)
    {
        FreeHbr(hbrButtonText);
        hbrButtonText = NULL;
    }
    if (hbrWindowText != NULL)
    {
        FreeHbr(hbrWindowText);
        hbrWindowText = NULL;
    }
    if (hbrWindow != NULL)
    {
        FreeHbr(hbrWindow);
        hbrWindow = NULL;
    }
    if (hbrWindowFrame != NULL)
    {
        FreeHbr(hbrWindowFrame);
        hbrWindowFrame = NULL;
    }
    if (hbrDesktop != NULL)
    {
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
    if (hdibPlaque != NULL)
    {
        BYTE *p = (BYTE *)GlobalLock(hdibPlaque);
        if (p != NULL)
        {
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

    if (hdibToolbar != NULL)
    {
        BYTE *p = (BYTE *)GlobalLock(hdibToolbar);
        if (p != NULL)
        {
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
        if (hdc != NULL)
        {
            int planes = GetDeviceCaps(hdc, PLANES);  /* was 0x0c */
            int bits = GetDeviceCaps(hdc, BITSPIXEL); /* was 0x0e */
            vcScreenColors = (int32_t)(planes * bits);
            ReleaseDC(NULL, hdc);
        }
        else
        {
            /* If we fail to get a DC, keep original spirit: result still success. */
            vcScreenColors = 0;
        }
    }

    DBG_LOGD("FGetSystemColors vcScreenColors=%d", vcScreenColors);

    return 1;
}

void FreeStuff(void)
{
    int i, j;

    /* Solid brushes */
    if (hbrButtonFace)
    {
        FreeHbr(hbrButtonFace);
        hbrButtonFace = NULL;
    }
    if (hbrButtonHilite)
    {
        FreeHbr(hbrButtonHilite);
        hbrButtonHilite = NULL;
    }
    if (hbrButtonShadow)
    {
        FreeHbr(hbrButtonShadow);
        hbrButtonShadow = NULL;
    }
    if (hbrButtonText)
    {
        FreeHbr(hbrButtonText);
        hbrButtonText = NULL;
    }
    if (hbrWindowText)
    {
        FreeHbr(hbrWindowText);
        hbrWindowText = NULL;
    }
    if (hbrWindow)
    {
        FreeHbr(hbrWindow);
        hbrWindow = NULL;
    }
    if (hbrWindowFrame)
    {
        FreeHbr(hbrWindowFrame);
        hbrWindowFrame = NULL;
    }
    if (hbrDesktop)
    {
        FreeHbr(hbrDesktop);
        hbrDesktop = NULL;
    }
    if (hbrRed)
    {
        FreeHbr(hbrRed);
        hbrRed = NULL;
    }
    if (hbrGreen)
    {
        FreeHbr(hbrGreen);
        hbrGreen = NULL;
    }
    if (hbrBlue)
    {
        FreeHbr(hbrBlue);
        hbrBlue = NULL;
    }
    if (hbrPurple)
    {
        FreeHbr(hbrPurple);
        hbrPurple = NULL;
    }
    if (hbrTooltip)
    {
        FreeHbr(hbrTooltip);
        hbrTooltip = NULL;
    }

    for (i = 0; i < 5; i++)
    {
        if (rghbrMineral[i])
        {
            FreeHbr(rghbrMineral[i]);
            rghbrMineral[i] = NULL;
        }
    }

    for (i = 0; i < 3; i++)
    {
        for (j = 0; j < 2; j++)
        {
            if (rghbrPlanetAttr[i][j])
            {
                FreeHbr(rghbrPlanetAttr[i][j]);
                rghbrPlanetAttr[i][j] = NULL;
            }
        }
    }

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 2; j++)
        {
            if (rghbrMinSum[i][j])
            {
                FreeHbr(rghbrMinSum[i][j]);
                rghbrMinSum[i][j] = NULL;
            }
        }
    }

    /*
     * Win16: FreeProcInstance(...) for thunked WndProcs/DlgProcs.
     * Win32: not used/needed (SetWindowLongPtr stores raw function pointers).
     */

    if (hrgnHuge)
    {
        DeleteObject(hrgnHuge);
        hrgnHuge = NULL;
    }
    if (hrgnScratch)
    {
        DeleteObject(hrgnScratch);
        hrgnScratch = NULL;
    }

    /* Reset cursor to the standard arrow (Win16 0x7F00 == IDC_ARROW) */
    SetCursor(LoadCursor(NULL, IDC_ARROW));

    if (hcurScanner)
    {
        DestroyCursor(hcurScanner);
        hcurScanner = NULL;
    }
    if (hcurOpenGrab)
    {
        DestroyCursor(hcurOpenGrab);
        hcurOpenGrab = NULL;
    }
    if (hcurCloseGrab)
    {
        DestroyCursor(hcurCloseGrab);
        hcurCloseGrab = NULL;
    }
    if (hcurScanAdd)
    {
        DestroyCursor(hcurScanAdd);
        hcurScanAdd = NULL;
    }
    if (hcurTrashCan)
    {
        DestroyCursor(hcurTrashCan);
        hcurTrashCan = NULL;
    }
    if (hcurNoWay)
    {
        DestroyCursor(hcurNoWay);
        hcurNoWay = NULL;
    }
    if (hcurResizeWE)
    {
        DestroyCursor(hcurResizeWE);
        hcurResizeWE = NULL;
    }
    if (hcurResizeNS)
    {
        DestroyCursor(hcurResizeNS);
        hcurResizeNS = NULL;
    }
    if (hcurResize4Way)
    {
        DestroyCursor(hcurResize4Way);
        hcurResize4Way = NULL;
    }
    if (hcurArrowHelp)
    {
        DestroyCursor(hcurArrowHelp);
        hcurArrowHelp = NULL;
    }
    if (hcurHand)
    {
        DestroyCursor(hcurHand);
        hcurHand = NULL;
    }

    if (hbmpScanner)
    {
        DeleteObject(hbmpScanner);
        hbmpScanner = NULL;
    }
    if (hbmpNumbers)
    {
        DeleteObject(hbmpNumbers);
        hbmpNumbers = NULL;
    }
    if (hbmpScanShip)
    {
        DeleteObject(hbmpScanShip);
        hbmpScanShip = NULL;
    }
    if (hbmpUnknownPlanet)
    {
        DeleteObject(hbmpUnknownPlanet);
        hbmpUnknownPlanet = NULL;
    }

    if (hiconStars)
    {
        DestroyIcon(hiconStars);
        hiconStars = NULL;
    }
    if (hiconHost)
    {
        DestroyIcon(hiconHost);
        hiconHost = NULL;
    }
    if (hiconWait)
    {
        DestroyIcon(hiconWait);
        hiconWait = NULL;
    }

    for (i = 0; i < 7; i++)
    {
        if (rghiconVCR[i])
        {
            DestroyIcon(rghiconVCR[i]);
            rghiconVCR[i] = NULL;
        }
    }

    /* Win32 note: UnlockResource/FreeResource are obsolete; FreeResource is effectively a no-op.
       Keep calls if you still use LoadResource()/LockResource() and want symmetry. */
    if (hdibPlanets)
    {
        GlobalUnlock(hdibPlanets);
        FreeResource(hdibPlanets);
        hdibPlanets = NULL;
    }
    if (hdibThings)
    {
        GlobalUnlock(hdibThings);
        FreeResource(hdibThings);
        hdibThings = NULL;
    }
    if (hdibToolbar)
    {
        GlobalUnlock(hdibToolbar);
        FreeResource(hdibToolbar);
        hdibToolbar = NULL;
    }
    if (hdibRaces)
    {
        GlobalUnlock(hdibRaces);
        FreeResource(hdibRaces);
        hdibRaces = NULL;
    }
    if (hdibRacesT)
    {
        GlobalUnlock(hdibRacesT);
        FreeResource(hdibRacesT);
        hdibRacesT = NULL;
    }
    if (hdibRacesX)
    {
        GlobalUnlock(hdibRacesX);
        FreeResource(hdibRacesX);
        hdibRacesX = NULL;
    }

    if (hbmpBackBld)
    {
        DeleteObject(hbmpBackBld);
        hbmpBackBld = NULL;
    }
    if (hbmpMsg)
    {
        DeleteObject(hbmpMsg);
        hbmpMsg = NULL;
    }
    if (hbmpMono)
    {
        DeleteObject(hbmpMono);
        hbmpMono = NULL;
    }

    if (hdibPlaque)
    {
        FreeResource(hdibPlaque);
        hdibPlaque = NULL;
    }

    for (i = 0; i < 5; i++)
    {
        if (rghdibShips[i])
        {
            GlobalUnlock(rghdibShips[i]);
            FreeResource(rghdibShips[i]);
            rghdibShips[i] = NULL;
        }
        if (rghdibShipsT[i])
        {
            GlobalUnlock(rghdibShipsT[i]);
            FreeResource(rghdibShipsT[i]);
            rghdibShipsT[i] = NULL;
        }
    }
    for (i = 0; i < 7; i++)
    {
        if (rghdibInventory[i])
        {
            GlobalUnlock(rghdibInventory[i]);
            FreeResource(rghdibInventory[i]);
            rghdibInventory[i] = NULL;
        }
    }

    if (lpLog)
    {
        FreeLp((uint8_t *)lpLog, htLog);
        lpLog = NULL;
    }
    if (lpMsg)
    {
        FreeLp((int16_t *)lpMsg, htMsg);
        lpMsg = NULL;
    }

    if (vhpal)
    {
        DeleteObject(vhpal);
        vhpal = NULL;
    }
    if (vhpalSplash)
    {
        DeleteObject(vhpalSplash);
        vhpalSplash = NULL;
    }

    /* More brushes/pens */
    if (hbrShip)
    {
        FreeHbr(hbrShip);
        hbrShip = NULL;
    }
    if (hbrStarbase)
    {
        FreeHbr(hbrStarbase);
        hbrStarbase = NULL;
    }
    if (hbrBBlue)
    {
        FreeHbr(hbrBBlue);
        hbrBBlue = NULL;
    }
    if (hbrEnemy)
    {
        FreeHbr(hbrEnemy);
        hbrEnemy = NULL;
    }
    if (hbrSelect)
    {
        FreeHbr(hbrSelect);
        hbrSelect = NULL;
    }
    if (hbrRadar)
    {
        FreeHbr(hbrRadar);
        hbrRadar = NULL;
    }
    if (hbrRadarNear)
    {
        FreeHbr(hbrRadarNear);
        hbrRadarNear = NULL;
    }
    if (hbrLightGray)
    {
        FreeHbr(hbrLightGray);
        hbrLightGray = NULL;
    }
    if (hbrGray)
    {
        FreeHbr(hbrGray);
        hbrGray = NULL;
    }
    if (hbrYellow)
    {
        FreeHbr(hbrYellow);
        hbrYellow = NULL;
    }
    if (hbrDkYellow)
    {
        FreeHbr(hbrDkYellow);
        hbrDkYellow = NULL;
    }

    if (hbr50Screen)
    {
        DeleteObject(hbr50Screen);
        hbr50Screen = NULL;
    }
    for (i = 0; i < 3; i++)
    {
        if (rghbrPat[i])
        {
            DeleteObject(rghbrPat[i]);
            rghbrPat[i] = NULL;
        }
    }
    if (hbrCargo)
    {
        DeleteObject(hbrCargo);
        hbrCargo = NULL;
    }
    if (hbrDock)
    {
        DeleteObject(hbrDock);
        hbrDock = NULL;
    }

    if (hpenShip)
    {
        DeleteObject(hpenShip);
        hpenShip = NULL;
    }
    if (hpenDkGreen)
    {
        DeleteObject(hpenDkGreen);
        hpenDkGreen = NULL;
    }
    if (hpenDkPurple)
    {
        DeleteObject(hpenDkPurple);
        hpenDkPurple = NULL;
    }
    if (hpenStarbase)
    {
        DeleteObject(hpenStarbase);
        hpenStarbase = NULL;
    }
    if (hpenEnemy)
    {
        DeleteObject(hpenEnemy);
        hpenEnemy = NULL;
    }
    if (hpenMassPath)
    {
        DeleteObject(hpenMassPath);
        hpenMassPath = NULL;
    }
    if (hpenRadar)
    {
        DeleteObject(hpenRadar);
        hpenRadar = NULL;
    }
    if (hpenRadarNear)
    {
        DeleteObject(hpenRadarNear);
        hpenRadarNear = NULL;
    }
    if (hpenDkBlue)
    {
        DeleteObject(hpenDkBlue);
        hpenDkBlue = NULL;
    }
    if (hpenYellow)
    {
        DeleteObject(hpenYellow);
        hpenYellow = NULL;
    }
    if (hpenDkYellow)
    {
        DeleteObject(hpenDkYellow);
        hpenDkYellow = NULL;
    }

    if (rghfontArial10[0])
    {
        DeleteObject(rghfontArial10[0]);
        rghfontArial10[0] = NULL;
    }
    if (rghfontArial10[1])
    {
        DeleteObject(rghfontArial10[1]);
        rghfontArial10[1] = NULL;
    }
    for (i = 0; i < 5; i++)
    {
        if (rghfontArial8[i])
        {
            DeleteObject(rghfontArial8[i]);
            rghfontArial8[i] = NULL;
        }
    }
    if (rghfontArial6[0])
    {
        DeleteObject(rghfontArial6[0]);
        rghfontArial6[0] = NULL;
    }
    if (rghfontArial7[0])
    {
        DeleteObject(rghfontArial7[0]);
        rghfontArial7[0] = NULL;
    }

    /* Heap blocks (now flat pointers in Win32 build) */
    for (i = 0; i < 12; i++)
    {
        if (rglphb[i])
        {
            FreeHb(rglphb[i]);
            rglphb[i] = NULL;
        }
    }
}

int16_t FHandleKey(HWND hwnd, int16_t iMsg, int16_t iKey, uint32_t dw)
{
    HWND hwndF;
    int16_t i;
    int16_t itb;
    int16_t iWarp;
    POINT pt;
    uint16_t md;
    int16_t iwp;
    HWND hwndOver;

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

int16_t FHandleChar(HWND hwnd, uint16_t ch, LPARAM lParam)
{
    HWND hwndF;

    (void)hwnd;

    if ((((hwndScanner == 0) || ((ch != '+') && (ch != '-'))) &&
         (ch != 'v') && (ch != 'V')) ||
        ((hwndMessage != 0) && ((hwndF = GetFocus()) == hwndMsgEdit)))
    {
        return 0;
    }

    SendMessage(hwndScanner, WM_CHAR, ch, lParam);
    return 1;
}

#endif /* _WIN32 */
