
#include "globals.h"
#include "resource.h"
#include "types.h"

#include "debuglog.h"
#include "init.h"
#include "mdi.h"
#include "memory.h"
#include "msg.h"
#include "utilgen.h"

#ifdef _WIN32
/* globals */
uint8_t rgPalGray[20] = {0x0a, 0x14, 0x1e, 0x28, 0x3d, 0x47, 0x51, 0x5c, 0x70, 0x7a, 0x85, 0x8f, 0xa1, 0xab, 0xb6, 0xc1, 0xd7, 0xe1, 0xeb, 0xf5};

bool FCreateStuff(void) {
    DBG_LOGI("FCreateStuff");
    bool    fFailed;
    int16_t cx;
    int16_t cy;
    int16_t i;
    HBITMAP hbmp;
    HBRUSH  hbr;
    HGLOBAL hdib;

    fFailed = false;

    cx = GetSystemMetrics(SM_CXSCREEN);
    cy = GetSystemMetrics(SM_CYSCREEN);

    /* gd.grBits is a union with bitfields in types.h; mdScreenSize lives in the top 2 bits of the low word. */
    if ((cx < 800) || (cy < 600)) {
        gd.mdScreenSize = 0;
    } else if ((cx < 0x0400) || (cy < 0x0300)) {
        gd.mdScreenSize = 1;
    } else if ((cx < 0x0457) || (cy < 0x0378)) {
        gd.mdScreenSize = 2;
    } else {
        gd.mdScreenSize = 3;
    }

    /* (gd.grBits & 0xFB7F) clears bit7 and bit10 => fNoIdleChecks + fAisDone */
    gd.fNoIdleChecks = 0;
    gd.fAisDone = 0;

    // copy the default player def into vplr. This was using MOVSW.REP 0x60 which really threw off ghidra...
    memcpy(&vplr, vrgplrDef, sizeof(PLAYER));

    hrgnHuge = CreateRectRgn(-10, -10, 2000, 2000);
    hrgnScratch = CreateRectRgn(0, 0, 10, 10);

    hbrShip = HbrGet(RGB(0x00, 0xff, 0x00));
    hbrStarbase = HbrGet(RGB(0x00, 0xff, 0xff));
    hbrBBlue = HbrGet(RGB(0xff, 0x00, 0x00));
    hbrEnemy = HbrGet(RGB(0x00, 0x00, 0xff));
    hbrSelect = HbrGet(RGB(0x00, 0xff, 0xff));
    hbrRed = HbrGet(RGB(0x00, 0x00, 0xff));
    hbrBlue = HbrGet(RGB(0x7f, 0x00, 0x00));
    hbrGreen = HbrGet(RGB(0x00, 0x7f, 0x00));
    hbrRadar = HbrGet(RGB(0x00, 0x00, 0x7f));
    hbrPurple = HbrGet(RGB(0x7f, 0x00, 0x7f));
    hbrTooltip = HbrGet(RGB(0x9f, 0xff, 0xff));
    hbrRadarNear = 0;

    rghbrMineral[0] = HbrGet(RGB(0xff, 0x00, 0x00));
    rghbrMineral[1] = HbrGet(RGB(0x00, 0x7f, 0x00));
    rghbrMineral[2] = HbrGet(RGB(0x00, 0xff, 0xff));
    rghbrMineral[3] = HbrGet(RGB(0xff, 0xff, 0xff));
    rghbrMineral[4] = HbrGet(RGB(0x00, 0x00, 0xff));

    rghbrPlanetAttr[0][0] = HbrGet(RGB(0x7f, 0x00, 0x00));
    rghbrPlanetAttr[0][1] = HbrGet(RGB(0xff, 0x00, 0x00));
    rghbrPlanetAttr[1][0] = HbrGet(RGB(0x00, 0x00, 0x7f));
    rghbrPlanetAttr[1][1] = HbrGet(RGB(0x00, 0x00, 0xff));
    rghbrPlanetAttr[2][0] = HbrGet(RGB(0x00, 0x7f, 0x00));
    rghbrPlanetAttr[2][1] = HbrGet(RGB(0x00, 0xff, 0x00));

    rghbrMinSum[0][0] = HbrGet(RGB(0xff, 0x00, 0x00));
    rghbrMinSum[0][1] = HbrGet(RGB(0x7f, 0x00, 0x00));
    rghbrMinSum[1][0] = HbrGet(RGB(0x00, 0xff, 0x00));
    rghbrMinSum[1][1] = HbrGet(RGB(0x00, 0x7f, 0x00));
    rghbrMinSum[2][0] = HbrGet(RGB(0x00, 0xff, 0xff));
    rghbrMinSum[2][1] = HbrGet(RGB(0x00, 0x7f, 0x7f));
    rghbrMinSum[3][0] = HbrGet(RGB(0x00, 0x00, 0xff));
    rghbrMinSum[3][1] = HbrGet(RGB(0x00, 0x00, 0x7f));

    hbrYellow = HbrGet(RGB(0x00, 0xff, 0xff));
    hbrDkYellow = HbrGet(RGB(0x00, 0x7f, 0x7f));
    hbrLightGray = HbrGet(RGB(0xc0, 0xc0, 0xc0));
    hbrGray = HbrGet(RGB(0x80, 0x80, 0x80));

    hpenShip = CreatePen(0, 1, RGB(0x00, 0xff, 0x00));
    hpenDkGreen = CreatePen(0, 1, RGB(0x00, 0x7f, 0x00));
    hpenStarbase = CreatePen(0, 1, RGB(0xff, 0x00, 0x00));
    hpenEnemy = CreatePen(0, 1, RGB(0x00, 0x00, 0xff));
    hpenMassPath = CreatePen(2, 1, RGB(0x7f, 0x7f, 0x7f));
    hpenRadar = CreatePen(0, 1, RGB(0x00, 0x00, 0x7f));
    hpenRadarNear = 0;
    hpenDkBlue = CreatePen(0, 1, RGB(0x7f, 0x00, 0x00));
    hpenYellow = CreatePen(0, 1, RGB(0x00, 0xff, 0xff));
    hpenDkYellow = CreatePen(0, 1, RGB(0x00, 0x7f, 0x7f));
    hpenDkPurple = CreatePen(0, 1, RGB(0x7f, 0x00, 0x7f));

    hbmp = LoadBitmap(hInst, MAKEINTRESOURCEA(IDB_SCREEN50));
    hbr50Screen = CreatePatternBrush(hbmp);
    DeleteObject(hbmp);

    for (i = 0; i < 3; i++) {
        hbmp = LoadBitmap(hInst, MAKEINTRESOURCEA((uint16_t)(IDB_MINESPAT_BASE + i)));
        hbr = CreatePatternBrush(hbmp);
        rghbrPat[i] = hbr;
        DeleteObject(hbmp);
    }

    hbmp = LoadBitmap(hInst, MAKEINTRESOURCEA(IDB_CARGO));
    hbrCargo = CreatePatternBrush(hbmp);
    DeleteObject(hbmp);

    hbmp = LoadBitmap(hInst, MAKEINTRESOURCEA(IDB_DOCK));
    hbrDock = CreatePatternBrush(hbmp);
    DeleteObject(hbmp);

    hcurScanner = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_SCANNER));
    hcurScanAdd = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_SCANNER_ADD));
    hcurOpenGrab = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_OPEN_GRAB));
    hcurCloseGrab = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_CLOSE_GRAB));

    hcurTrashCan = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_TRASH));
    hcurNoWay = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_INVALID));
    hcurResizeWE = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_HSPLIT));
    hcurResizeNS = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_VSPLIT));
    hcurResize4Way = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_MOVEARROWS));
    hcurArrowHelp = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_TOOLTIP_QUESTION));
    hcurHand = LoadCursor(hInst, MAKEINTRESOURCEA(IDC_HAND_CUSTOM));

    hbmpScanner = LoadBitmap(hInst, MAKEINTRESOURCEA(IDB_SCANNER));
    hbmpUnknownPlanet = LoadBitmap(hInst, MAKEINTRESOURCEA(IDB_UNKNOWNPLANET));
    hbmpNumbers = LoadBitmap(hInst, MAKEINTRESOURCEA(IDB_FONT_DIGITS));

    /*
     * Original decompile used numeric IDs - mapped to resource.h constants.
     * 0x0058 -> scannerfleets (scanner ship icons)
     * 0x0077 -> numdesignsplate (background build plate) - FIXME: verify this mapping
     * 0x0086 -> messageicons (message filter checkbox)
     * 0x00c7 -> monochromeicons
     */
    hbmpScanShip = LoadBitmap(hInst, MAKEINTRESOURCEA(IDDIB_SCANNER_TOOLBAR));
    hbmpBackBld = LoadBitmap(hInst, MAKEINTRESOURCEA(IDDIB_NUM_DESIGNS_PLATE));
    hbmpMsg = LoadBitmap(hInst, MAKEINTRESOURCEA(IDB_MSGFILTER_CHECKBOX));
    hbmpMono = LoadBitmap(hInst, MAKEINTRESOURCEA(IDB_FILTER_CHECKBOX_MONO));

    hdibPlanets = HdibLoadBigResource(IDDIB_PLANET_ICONS);
    hdibThings = HdibLoadBigResource(IDDIB_THING_ICONS);
    hdibToolbar = HdibLoadBigResource(IDDIB_SCANNER_TOOLBAR);

    if ((hdibPlanets == 0) || (hdibThings == 0) || (hdibToolbar == 0)) {
        fFailed = true;

        DBG_LOGE("Critical DIB load failure during init: "
                 "hdibPlanets=%p hdibThings=%p hdibToolbar=%p",
                 hdibPlanets, hdibThings, hdibToolbar);
    }

    for (i = 0; i < 5; i++) {
        uint16_t id;

        id = (uint16_t)(IDDIB_HULL_ICONS_BASE + i);
        hdib = HdibLoadBigResource(id);
        rghdibShips[i] = hdib;

        if (hdib == 0) {
            fFailed = true;
            DBG_LOGE("Failed to load ship hull icon (large): resource id=0x%04x index=%d", id, i);
        }

        id = (uint16_t)(IDDIB_HULL_ICONS_SMALL_BASE + i);
        hdib = HdibLoadBigResource(id);
        rghdibShipsT[i] = hdib;

        if (hdib == 0) {
            fFailed = true;
            DBG_LOGE("Failed to load ship hull icon (small): resource id=0x%04x index=%d", id, i);
        }
    }

    for (i = 0; i < 7; i++) {
        uint16_t id;

        id = (uint16_t)(IDDIB_TECH_ICONS_BASE + i);
        hdib = HdibLoadBigResource(id);
        rghdibInventory[i] = hdib;

        if (hdib == 0) {
            fFailed = true;
            DBG_LOGE("Failed to load tech inventory icon: resource id=0x%04x index=%d", id, i);
        }
    }

    vhpal = HpalFromDib(rghdibShips[3]);

    hdibRaces = HdibLoadBigResource(IDDIB_PLAYER_ICONS);

    /* 0x50/0x4f in original mapped to player icon variants */
    hdibRacesT = HdibLoadBigResource(IDDIB_PLAYER_ICONS_SMALL);
    hdibRacesX = HdibLoadBigResource(IDDIB_PLAYER_ICONS_TINY);

    hdibPlaque = HdibLoadBigResource(IDDIB_NUM_DESIGNS_PLATE);

    hiconStars = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_STARS));
    hiconHost = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_HOST));
    hiconWait = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_WAIT));

    rghiconVCR[0] = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_BANG1));
    rghiconVCR[1] = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_BANG2));
    rghiconVCR[2] = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_BANG3));
    rghiconVCR[3] = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_TORP1));
    rghiconVCR[4] = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_TORP2));
    rghiconVCR[5] = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_TORP3));
    rghiconVCR[6] = LoadIcon(hInst, MAKEINTRESOURCEA(IDI_TORP4));

    lpLog = (uint8_t *)LpAlloc(cbLogAllocSize, htLog);
    lpMsg = (int16_t *)LpAlloc(cbPackedMsgAllocSize, htMsg);

    /*
     * Win16 required MakeProcInstance() for callback thunks.
     * In modern Win32 builds, these can be used directly (and should not be wrapped).
     */
    /*
    lpfnFakeComboProc  = MakeProcInstance(FakeComboProc, hInst);
    lpfnFakeCEProc     = MakeProcInstance(FakeCEProc, hInst);
    lpfnFakeEditProc   = MakeProcInstance(FakeEditProc, hInst);
    lpfnFakeListProc   = MakeProcInstance(FakeListProc, hInst);
    lpfnHostTimerProc  = MakeProcInstance(HostTimerProc, hInst);
    lpfnBrowserDlgProc = MakeProcInstance(BrowserDlg, hInst);
    lpfnReportDlgProc  = MakeProcInstance(ReportDlg, hInst);
    lpfnGaugeDlgProc   = MakeProcInstance(ProgressGaugeDlg, hInst);
    */

    GetDiskSerialNumber();

    lpb2k = (uint8_t *)LpAlloc(0x800, htPerm);
    vlprgidMisc = (uint16_t *)LpAlloc(0x800, htPerm);
    vlprgidPlanet = (uint16_t *)LpAlloc(0x800, htPerm);
    vlprgidFleet = (uint16_t *)LpAlloc(0x800, htPerm);

    /* Log all critical resources for debugging */
    DBG_LOGI("Resource check: fFailed=%d", fFailed);
    DBG_LOGI("  hbmpScanner=%p hbmpUnknownPlanet=%p hbmpBackBld=%p", (void *)hbmpScanner, (void *)hbmpUnknownPlanet, (void *)hbmpBackBld);
    DBG_LOGI("  hdibRaces=%p hdibRacesT=%p hdibRacesX=%p", (void *)hdibRaces, (void *)hdibRacesT, (void *)hdibRacesX);
    DBG_LOGI("  hbmpMono=%p hbmpScanShip=%p hbmpMsg=%p", (void *)hbmpMono, (void *)hbmpScanShip, (void *)hbmpMsg);
    DBG_LOGI("  hiconHost=%p hiconStars=%p hiconWait=%p", (void *)hiconHost, (void *)hiconStars, (void *)hiconWait);

    if (fFailed || (hbmpScanner == 0) || (hbmpUnknownPlanet == 0) || (hbmpBackBld == 0) || (hdibRaces == 0) || (hdibRacesT == 0) || (hdibRacesX == 0) ||
        (hbmpMono == 0) || (hbmpScanShip == 0) || (hbmpMsg == 0) || (hiconHost == 0) || (hiconStars == 0) || (hiconWait == 0)) {
        DBG_LOGE("Resource load failed - one or more handles are NULL (see above)");
        char *sz = PszFormatIds(idsUnableLoadBitmaps, (int16_t *)0);
        AlertSz(sz, MB_ICONSTOP);
        return false;
    }

    return true;
}

bool FCreateFonts(HDC hdc) {
    LOGFONT    lf;
    TEXTMETRIC tm;
    HFONT      hfontSav;
    SIZE       sz;

    /* Ensure our Arial face-name strings are loaded (4 variants). */
    for (int i = 0; i < 4; i++) {
        if (rgszArial[i][0] == '\0') {
            CchGetString((int16_t)(idsArial2 + i), rgszArial[i]);
        }
    }

    memset(&lf, 0, sizeof(lf));
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
    lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
    lf.lfQuality = DEFAULT_QUALITY;
    lf.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;

    /* Arial 10pt (two variants: rgszArial[0], rgszArial[1]) */
    {
        int16_t logPixY = (int16_t)GetDeviceCaps(hdc, LOGPIXELSY);
        int16_t h = (int16_t)MulDiv(10, logPixY, 72);
        lf.lfHeight = (int16_t)(-h);

        for (int i = 0; i < 2; i++) {
            strcpy(lf.lfFaceName, rgszArial[i]);
            rghfontArial10[i] = CreateFontIndirect(&lf);
        }
    }

    /* Arial 6pt (rgszArial[0]) */
    {
        int16_t logPixY = (int16_t)GetDeviceCaps(hdc, LOGPIXELSY);
        int16_t h = (int16_t)MulDiv(6, logPixY, 72);
        lf.lfHeight = (int16_t)(-h);

        strcpy(lf.lfFaceName, rgszArial[0]);
        rghfontArial6[0] = CreateFontIndirect(&lf);
    }

    /* Arial 7pt (rgszArial[0]) */
    {
        int16_t logPixY = (int16_t)GetDeviceCaps(hdc, LOGPIXELSY);
        int16_t h = (int16_t)MulDiv(7, logPixY, 72);
        lf.lfHeight = (int16_t)(-h);

        strcpy(lf.lfFaceName, rgszArial[0]);
        rghfontArial7[0] = CreateFontIndirect(&lf);
    }

    /* Arial 8pt (four variants: rgszArial[0..3]) */
    {
        int16_t logPixY = (int16_t)GetDeviceCaps(hdc, LOGPIXELSY);
        int16_t h = (int16_t)MulDiv(8, logPixY, 72);
        lf.lfHeight = (int16_t)(-h);

        for (int i = 0; i < 4; i++) {
            strcpy(lf.lfFaceName, rgszArial[i]);
            rghfontArial8[i] = CreateFontIndirect(&lf);
        }

        /* Special rotated 8pt font: face = rgszArial[1], escapement = 0x0C4E */
        strcpy(lf.lfFaceName, rgszArial[1]);
        lf.lfEscapement = 0x0C4E;
        rghfontArial8[4] = CreateFontIndirect(&lf);
        lf.lfEscapement = 0;
    }

    /* Measure metrics (dyArial*) and dxMaxMineralQuan */
    hfontSav = (HFONT)SelectObject(hdc, rghfontArial8[0]);
    GetTextMetrics(hdc, &tm);
    dyArial8 = (int16_t)(tm.tmHeight + tm.tmExternalLeading);

    /* "88888888kT" is the measuring string in the original (len=10) */
    (void)GetTextExtentPoint32A(hdc, "88888888kT", 10, &sz);
    dxMaxMineralQuan = (int16_t)sz.cx;

    SelectObject(hdc, rghfontArial7[0]);
    GetTextMetrics(hdc, &tm);
    dyArial7 = (int16_t)(tm.tmHeight + tm.tmExternalLeading);

    SelectObject(hdc, rghfontArial6[0]);
    GetTextMetrics(hdc, &tm);
    dyArial6 = (int16_t)(tm.tmHeight + tm.tmExternalLeading);

    SelectObject(hdc, rghfontArial10[0]);
    GetTextMetrics(hdc, &tm);
    dyArial10 = (int16_t)(tm.tmHeight + tm.tmExternalLeading);

    SelectObject(hdc, hfontSav);
    return 1;
}

/* ------------------------------------------------------------------
 * Local helper: produce "MM/DD/YY" (8 chars + NUL) like MSVCRT __strdate.
 * The original code assumes this exact layout when it does szWork[5]=0,
 * szWork[2]=0, and then reads yy from szWork+6, mm from szWork, dd from szWork+3.
 * ------------------------------------------------------------------ */
static void StrDate_MMDDYY(char *dst /* >= 9 bytes */) {
    time_t    t = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    /* tm_mon: 0-11, tm_mday: 1-31, tm_year: years since 1900 */
    int mm = tmv.tm_mon + 1;
    int dd = tmv.tm_mday;
    int yy = (tmv.tm_year + 1900) % 100;

    dst[0] = (char)('0' + (mm / 10));
    dst[1] = (char)('0' + (mm % 10));
    dst[2] = '/';
    dst[3] = (char)('0' + (dd / 10));
    dst[4] = (char)('0' + (dd % 10));
    dst[5] = '/';
    dst[6] = (char)('0' + (yy / 10));
    dst[7] = (char)('0' + (yy % 10));
    dst[8] = '\0';
}

void ReadIniTileSettings(char *pszFormat, TILE *rgtile, int16_t ctile) {
    uint16_t iCol = 0;
    int16_t  iTile = 0;

    for (; *pszFormat != '\0'; pszFormat++) {
        char ch = *pszFormat;

        /* '*' bumps column from 0 -> 1 (once) */
        if (ch == '*') {
            if (iCol == 0)
                iCol = 1;
            continue;
        }

        /* Decode tile id and “popped” flag from character */
        uint16_t id;
        uint16_t fPopped;

        if (ch >= 'A' && ch <= 'P') {
            id = (uint16_t)(ch - 'A');
            fPopped = 1;
        } else if (ch >= 'a' && ch <= 'p') {
            id = (uint16_t)(ch - 'a');
            fPopped = 0;
        } else {
            continue;
        }

        /* Find matching tile by id, starting at iTile */
        int16_t i = iTile;
        while (i < ctile) {
            if ((uint16_t)rgtile[i].id == id)
                break;
            i++;
        }

        if (i == ctile)
            continue;

        /* Update flags via bitfields */
        rgtile[i].iCol = iCol;
        rgtile[i].fPopped = fPopped;

        /* Bring tile forward if needed */
        if (i != iTile) {
            TILE tmp = rgtile[i];
            rgtile[i] = rgtile[iTile];
            rgtile[iTile] = tmp;
        }

        iTile++;
    }

    /* Clamp remaining tiles to at least current column */
    for (int16_t i = iTile; i < ctile; i++) {
        if ((uint16_t)rgtile[i].iCol < iCol)
            rgtile[i].iCol = iCol;
    }
}

void ReadIniSettings(void) {
    char szSection[16];
    char szIniFile[256];
    char szEntry[16];
    WN   wnT;

    int16_t  i;
    int16_t  iPass;
    uint16_t w;

    /* clear ini.fWait/fGen/fTry (bits 2..4) */
    ini.fWait = 0;
    ini.fGen = 0;
    ini.fTry = 0;

    CchGetString(idsWindows, szSection);
    CchGetString(idsStarsIni, szIniFile);

    /* prepend user AppData path */
    {
        char szTmp[256];

        lstrcpyA(szTmp, szStarsPath); /* "%APPDATA%\Stars\" */
        lstrcatA(szTmp, szIniFile);   /* "Stars.ini" */
        lstrcpyA(szIniFile, szTmp);
    }

    /* main frame position/state */
    GetIniWinRc(szSection, szIniFile, idsMain, &ini.wnFrame);

    /* report window remembered positions */
    GetIniWinRc(szSection, szIniFile, idsReportfleetwin, &wnT);
    if (wnT.rc.left != (int16_t)0x8000) {
        vrptFleet.ptDlg.x = wnT.rc.left;
        vrptFleet.ptDlg.y = wnT.rc.top;
        vrptFleet.ptSize.x = (int16_t)(wnT.rc.right - wnT.rc.left);
        vrptFleet.ptSize.y = (int16_t)(wnT.rc.bottom - wnT.rc.top);
    }

    GetIniWinRc(szSection, szIniFile, idsReportefleetwin, &wnT);
    if (wnT.rc.left != (int16_t)0x8000) {
        vrptEFleet.ptDlg.x = wnT.rc.left;
        vrptEFleet.ptDlg.y = wnT.rc.top;
        vrptEFleet.ptSize.x = (int16_t)(wnT.rc.right - wnT.rc.left);
        vrptEFleet.ptSize.y = (int16_t)(wnT.rc.bottom - wnT.rc.top);
    }

    GetIniWinRc(szSection, szIniFile, idsReportbtlwin, &wnT);
    if (wnT.rc.left != (int16_t)0x8000) {
        vrptBattle.ptDlg.x = wnT.rc.left;
        vrptBattle.ptDlg.y = wnT.rc.top;
        vrptBattle.ptSize.x = (int16_t)(wnT.rc.right - wnT.rc.left);
        vrptBattle.ptSize.y = (int16_t)(wnT.rc.bottom - wnT.rc.top);
    }

    GetIniWinRc(szSection, szIniFile, idsReportplanwin, &wnT);
    if (wnT.rc.left != (int16_t)0x8000) {
        vrptPlanet.ptDlg.x = wnT.rc.left;
        vrptPlanet.ptDlg.y = wnT.rc.top;
        vrptPlanet.ptSize.x = (int16_t)(wnT.rc.right - wnT.rc.left);
        vrptPlanet.ptSize.y = (int16_t)(wnT.rc.bottom - wnT.rc.top);
    }

    /* resolution warning */
    CchGetString(idsResolution, szEntry);
    {
        uint16_t uRes = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 0, szIniFile);
        if (uRes == 0) {
            if ((vcScreenColors < 5) || (gd.mdScreenSize == 0)) {
                char *sz = PszFormatIds(idsNoteStarsPrefersScreenResolutionLeast800x600, (short *)0);
                AlertSz(sz, 0x10);
            }
        }
    }

    /* layout (clamped to 0..2) */
    CchGetString(idsLayout, szEntry);
    iWindowLayout = (int16_t)GetPrivateProfileInt(szSection, szEntry, 1, szIniFile);
    if (iWindowLayout < 0) {
        iWindowLayout = 0;
    } else if (iWindowLayout >= 3) {
        iWindowLayout = 2;
    }

    /* style sizing wants: clamp to [10, 2000] */
    CchGetString(idsStyle1width, szEntry);
    vfs.dxPlanWant = (int16_t)GetPrivateProfileInt(szSection, szEntry, 0x18c, szIniFile);
    if (vfs.dxPlanWant < 10)
        vfs.dxPlanWant = 10;
    if (vfs.dxPlanWant > 2000)
        vfs.dxPlanWant = 2000;

    CchGetString(idsStyle1height, szEntry);
    vfs.dyMsgWant = (int16_t)GetPrivateProfileInt(szSection, szEntry, 0x6e, szIniFile);
    if (vfs.dyMsgWant < 10)
        vfs.dyMsgWant = 10;
    if (vfs.dyMsgWant > 2000)
        vfs.dyMsgWant = 2000;

    CchGetString(idsStyle1height2, szEntry);
    vfs.dyMinWant = (int16_t)GetPrivateProfileInt(szSection, szEntry, 0xc0, szIniFile);
    if (vfs.dyMinWant < 10)
        vfs.dyMinWant = 10;
    if (vfs.dyMinWant > 2000)
        vfs.dyMinWant = 2000;

    CchGetString(idsStyle2width, szEntry);
    vfs.dx2PlanWant = (int16_t)GetPrivateProfileInt(szSection, szEntry, 0x18c, szIniFile);
    if (vfs.dx2PlanWant < 10)
        vfs.dx2PlanWant = 10;
    if (vfs.dx2PlanWant > 2000)
        vfs.dx2PlanWant = 2000;

    CchGetString(idsStyle2height, szEntry);
    vfs.dy2MsgWant = (int16_t)GetPrivateProfileInt(szSection, szEntry, 0x6e, szIniFile);
    if (vfs.dy2MsgWant < 10)
        vfs.dy2MsgWant = 10;
    if (vfs.dy2MsgWant > 2000)
        vfs.dy2MsgWant = 2000;

    CchGetString(idsStyle2height2, szEntry);
    vfs.dy2MinWant = (int16_t)GetPrivateProfileInt(szSection, szEntry, 0xc0, szIniFile);
    if (vfs.dy2MinWant < 10)
        vfs.dy2MinWant = 10;
    if (vfs.dy2MinWant > 2000)
        vfs.dy2MinWant = 2000;

    /* toolbar flag */
    CchGetString(idsToolbar, szEntry);
    gd.fToolbar = (GetPrivateProfileInt(szSection, szEntry, 1, szIniFile) != 0);

    /* serial + machine config blob */
    CchGetString(idsGlobalsettings, szEntry);
    {
        int16_t cch = (int16_t)GetPrivateProfileString(szSection, szEntry, "", szWork, 0x28, szIniFile);
        if (cch == 0x1c) {
            FSerialAndEnvFromSz(&vSerialNumber, vrgbMachineConfig, szWork);
        } else {
            vSerialNumber = 0;
        }
    }

    /* tile settings */
    CchGetString(idsPlanettiles, szEntry);
    GetPrivateProfileString(szSection, szEntry, "X", szWork, 0x14, szIniFile);
    ReadIniTileSettings(szWork, rgtilePlanet, 6);

    CchGetString(idsShiptiles, szEntry);
    GetPrivateProfileString(szSection, szEntry, "X", szWork, 0x14, szIniFile);
    ReadIniTileSettings(szWork, rgtileShip, 7);

    /* selection: N / P / S / E + optional player + optional id */
    CchGetString(idsSelection, szEntry);
    {
        int16_t cch = (int16_t)GetPrivateProfileString(szSection, szEntry, "N", szWork, 0x14, szIniFile);

        ini.grobjSel = 0;
        if (cch >= 3) {
            if (szWork[0] == 'P')
                ini.grobjSel = 1;
            else if (szWork[0] == 'S')
                ini.grobjSel = 2;
            else if (szWork[0] == 'E')
                ini.grobjSel = 4;
            else
                ini.grobjSel = 0; /* 'N' or unknown */

            if ((szWork[1] < 'B') || ('Q' < szWork[1])) {
                ini.grobjSel = 0;
            } else {
                ini.idPlayer = (int16_t)(szWork[1] - 'B');
            }

            if (ini.grobjSel != 0) {
                ini.iObjSel = (int16_t)atoi(szWork + 2);
            }
        }
    }

    /* message */
    CchGetString(idsMessage, szEntry);
    ini.iMsg = (int16_t)GetPrivateProfileInt(szSection, szEntry, 0, szIniFile);

    /* game id (hex-ish) */
    CchGetString(idsGameid, szEntry);
    {
        int16_t  cch = (int16_t)GetPrivateProfileString(szSection, szEntry, "0", szWork, 10, szIniFile);
        uint32_t u = 0;
        for (i = 0; i < cch; i++) {
            char     ch = szWork[i];
            uint32_t digit;

            u = (u << 4) & 0xffffffffu;

            if (('0' <= ch) && (ch <= '9'))
                digit = (uint32_t)(ch - '0');
            else if (('a' <= ch) && (ch <= 'f'))
                digit = (uint32_t)(ch - 'a' + 10);
            else
                digit = 0;

            u = (u + digit) & 0xffffffffu;
        }
        ini.lid = (int32_t)u;
    }

    /* scanner prefs */
    CchGetString(idsScanzoom, szEntry);
    {
        uint16_t uZoom = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 4, szIniFile);
        if ((uZoom != 0) && (uZoom < 10)) {
            iScanZoom = (int16_t)(uZoom - 5);
        }
    }

    CchGetString(idsScanfilterv25, szEntry);
    grbitScanShip = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 0, szIniFile);

    CchGetString(idsScanefilterv25, szEntry);
    grbitScanEShip = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 0, szIniFile);

    CchGetString(idsScanmines, szEntry);
    grbitScanMines = (uint16_t)(GetPrivateProfileInt(szSection, szEntry, 0x0f, szIniFile) & 0x0f);

    CchGetString(idsScanradar, szEntry);
    w = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 100, szIniFile);
    if (w > 100)
        w = 100;
    vpctRadarView = w;

    CchGetString(idsScanmodev25, szEntry);
    grbitScan = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 0x00e0, szIniFile);
    if ((grbitScan & 0xc00f) > 5) {
        grbitScan = 0;
        grbitScanShip = 0;
    }

    /* minerals graph scale */
    CchGetString(idsMineralscale, szEntry);
    cMinGrafMax = (int16_t)GetPrivateProfileInt(szSection, szEntry, cMinGrafMax, szIniFile);
    if ((cMinGrafMax < 100) || (cMinGrafMax > 30000)) {
        cMinGrafMax = 5000;
    }

    /* Files section */
    CchGetString(idsFiles, szSection);

    CchGetString(idsLogging, szEntry);
    ini.fLogging = (GetPrivateProfileInt(szSection, szEntry, 0, szIniFile) != 0);

    CchGetString(idsWait2, szEntry);
    ini.fWait = ((GetPrivateProfileInt(szSection, szEntry, 0, szIniFile) & 1) != 0);

    /* startup file + base */
    CchGetString(idsFile1, szEntry);
    {
        int16_t cch = (int16_t)GetPrivateProfileString(szSection, szEntry, "str", szWork, 0x100, szIniFile);
        if (cch < 4) {
            ini.fStartupFile = 0;
        } else {
            ini.fStartupFile = 1;
            strcpy(szBase, szWork);
        }
    }

    /* MRU list (9 entries of 0x100 each) */
    if (vrgszMRU == 0) {
        vrgszMRU = LpAlloc(0x900, htPerm);
    }

    {
        uint16_t baseLen = (uint16_t)strlen(szEntry);
        for (i = 0; i < 9; i++) {
            szEntry[baseLen - 1] = (char)('1' + i);
            if (GetPrivateProfileString(szSection, szEntry, "str", vrgszMRU + (i * 0x100), 0x100, szIniFile) < 4) {
                vrgszMRU[i * 0x100] = '\0';
            }
        }

        /* compact non-empty entries to front */
        iPass = 0;
        for (i = 0; i < 9; i++) {
            if (vrgszMRU[i * 0x100] != '\0') {
                if (i != iPass) {
                    strcpy(vrgszMRU + (iPass * 0x100), vrgszMRU + (i * 0x100));
                    vrgszMRU[i * 0x100] = '\0';
                }
                iPass++;
            }
        }
    }

    /* turn */
    CchGetString(idsTurn, szEntry);
    ini.turn = (uint16_t)GetPrivateProfileInt(szSection, szEntry, game.turn, szIniFile);

    /* Misc section */
    CchGetString(idsMisc, szSection);

    CchGetString(idsDefaultpassword, szEntry);
    GetPrivateProfileString(szSection, szEntry, "", vszDefPass, 0x10, szIniFile);

    CchGetString(idsProgress, szEntry);
    gd.fProgressTxt = (GetPrivateProfileInt(szSection, szEntry, 0, szIniFile) != 0);

    CchGetString(idsNewreports, szEntry);
    gd.fPerPlayerDumps = (GetPrivateProfileInt(szSection, szEntry, 0, szIniFile) != 0);

    CchGetString(idsNohostnames, szEntry);
    gd.fNoHostNames = (GetPrivateProfileInt(szSection, szEntry, 0, szIniFile) != 0);

    CchGetString(idsBackups, szEntry);
    vcBackupDirs = (int16_t)GetPrivateProfileInt(szSection, szEntry, 1, szIniFile);
    if ((vcBackupDirs < 1) || (vcBackupDirs > 999)) {
        vcBackupDirs = 1;
    }

    /* report visible fields + sorts */
    CchGetString(idsReportplanfld, szEntry);
    vrptPlanet.grbitVisible = (uint16_t)GetPrivateProfileInt(szSection, szEntry, (uint16_t)0xffff, szIniFile);

    CchGetString(idsReportplansort, szEntry);
    {
        uint16_t v = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 0, szIniFile);
        vrptPlanet.fAscending = ((v & 0x100) != 0);
        vrptPlanet.icolSort = (uint8_t)(v & 0xff);
    }

    CchGetString(idsReportfleetfld, szEntry);
    vrptFleet.grbitVisible = (uint16_t)GetPrivateProfileInt(szSection, szEntry, (uint16_t)0xffff, szIniFile);

    CchGetString(idsReportfleetsort, szEntry);
    {
        uint16_t v = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 0, szIniFile);
        vrptFleet.fAscending = ((v & 0x100) != 0);
        vrptFleet.icolSort = (uint8_t)(v & 0xff);
    }

    CchGetString(idsReportefleetfld, szEntry);
    vrptEFleet.grbitVisible = (uint16_t)GetPrivateProfileInt(szSection, szEntry, (uint16_t)0xffff, szIniFile);

    CchGetString(idsReportefltsort, szEntry);
    {
        uint16_t v = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 0, szIniFile);
        vrptEFleet.fAscending = ((v & 0x100) != 0);
        vrptEFleet.icolSort = (uint8_t)(v & 0xff);
    }

    CchGetString(idsReportbtlfld, szEntry);
    vrptBattle.grbitVisible = (uint16_t)GetPrivateProfileInt(szSection, szEntry, (uint16_t)0xffff, szIniFile);

    CchGetString(idsReportbtlsort, szEntry);
    {
        uint16_t v = (uint16_t)GetPrivateProfileInt(szSection, szEntry, 0, szIniFile);
        vrptBattle.fAscending = ((v & 0x100) != 0);
        vrptBattle.icolSort = (uint8_t)(v & 0xff);
    }

    CchGetString(idsReportdefgraph, szEntry);
    gd.iCurGraph = (uint16_t)(GetPrivateProfileInt(szSection, szEntry, 7, szIniFile) & 0x0f);
    if (gd.iCurGraph > 7) {
        gd.iCurGraph = 7;
    }

    /* VCR speed */
    CchGetString(idsVcrspeed, szEntry);
    viSpeedVCR = (int16_t)GetPrivateProfileInt(szSection, szEntry, 1, szIniFile);

    /* trial / install date bookkeeping */
    StrDate_MMDDYY(szWork);
    szWork[5] = '\0';
    szWork[2] = '\0';
    {
        int16_t  yy = (int16_t)atoi(szWork + 6);
        int16_t  mm = (int16_t)atoi(szWork);
        int16_t  dd = (int16_t)atoi(szWork + 3);
        uint32_t uDateCur = (uint32_t)dd + (uint32_t)mm * 31u + (uint32_t)yy * 372u;

        CchGetString(idsHistoryinfo, szEntry);
        {
            int32_t installed = (int32_t)GetPrivateProfileInt(szSection, szEntry, -1, szIniFile);
            uDateInstalled = (uint16_t)uDateCur;
            if ((uint32_t)installed <= uDateCur) {
                uDateInstalled = (uint16_t)installed;
            }
        }

        gd.fTrialPeriodOver = ((uint32_t)uDateInstalled + 21u <= uDateCur);
    }

    /* Fonts section: override arial names */
    CchGetString(idsFonts, szSection);
    for (i = 0; i < 4; i++) {
        CchGetString((int16_t)(idsArial + i), szEntry);
        GetPrivateProfileString(szSection, szEntry, "", szWork, 0x50, szIniFile);
        {
            uint16_t len = (uint16_t)strlen(szWork);
            if ((len > 4) && (len < 0x20)) {
                strncpy(rgszArial[i], szWork, sizeof(rgszArial[i]) - 1);
                rgszArial[i][sizeof(rgszArial[i]) - 1] = '\0';
            }
        }
    }

    /* ZipOrders section */
    CchGetString(idsZiporders, szSection);
    memset(vrgZip, 0, sizeof(vrgZip));

    for (i = 0; i < 4; i++) {
        char *psz;

        strcpy(szEntry, szSection);
        {
            uint16_t len = (uint16_t)strlen(szEntry);
            szEntry[len] = (char)('1' + i);
            szEntry[len + 1] = '\0';
        }

        GetPrivateProfileString(szSection, szEntry, "", szWork, 0x50, szIniFile);

        {
            uint16_t len = (uint16_t)strlen(szWork);
            if ((len > 0x13) && (len < 0x21)) {
                /* must have at least 20 chars of a..p */
                int16_t ok = 0;
                psz = szWork;
                while (ok < 0x14 && ('a' <= *psz) && (*psz <= 'p')) {
                    ok++;
                    psz++;
                }

                if (ok > 0x13) {
                    /* parse 5 * 4 nibbles, then name */
                    psz = szWork;
                    for (iPass = 0; iPass < 5; iPass++) {
                        uint16_t action = (uint16_t)(psz[0] - 'a');
                        uint16_t qty = (uint16_t)(psz[1] - 'a') | (uint16_t)((psz[2] - 'a') << 4) | (uint16_t)((psz[3] - 'a') << 8);

                        vrgZip[i].txp.rgia[iPass].iAction = action;
                        vrgZip[i].txp.rgia[iPass].cQuan = qty;

                        psz += 4;
                    }

                    strcpy(vrgZip[i].szName, psz);
                    vrgZip[i].fValid = 1;
                }
            }
        }
    }

    /* ZipProdQ section */
    memset(vrgZipProd, 0, sizeof(vrgZipProd));

    for (i = 0; i < 5; i++) {
        strcpy(szEntry, szSection);
        {
            uint16_t len = (uint16_t)strlen(szEntry);
            szEntry[len] = 'P';
            szEntry[len + 1] = (char)('1' + i);
            szEntry[len + 2] = '\0';
        }

        GetPrivateProfileString(szSection, szEntry, "", szWork, 0x50, szIniFile);

        {
            uint16_t len = (uint16_t)strlen(szWork);
            if ((len > 2) && (len < 0x41)) {
                int16_t cpq = (int16_t)(szWork[1] - 'a');
                if ((cpq >= 0) && (cpq < 13)) {
                    char   *psz2 = szWork;
                    int16_t need = (int16_t)(cpq * 4 + 2);
                    int16_t ok = 0;

                    while (ok < need && ('a' <= *psz2) && (*psz2 <= 'p')) {
                        ok++;
                        psz2++;
                    }

                    if (ok >= need) {
                        if (strlen(psz2) < 13) {
                            strcpy(vrgZipProd[i].szName, psz2);
                            vrgZipProd[i].fNoResearch = (uint8_t)(szWork[0] != 'a');
                            vrgZipProd[i].cpq = (uint8_t)cpq;
                            vrgZipProd[i].fValid = 1;

                            psz2 = szWork + 2;
                            for (iPass = 0; iPass < cpq; iPass++) {
                                uint16_t w0 = (uint16_t)(psz2[0] - 'a');
                                uint16_t w1 = (uint16_t)(psz2[1] - 'a');
                                uint16_t w2 = (uint16_t)(psz2[2] - 'a');
                                uint16_t w3 = (uint16_t)(psz2[3] - 'a');
                                uint16_t ww = (uint16_t)(w0 | (w1 << 4) | (w2 << 8) | (w3 << 12));

                                /* clamp cQuan (upper 10 bits) to <= 0x3fc; if too large, force cQuan=1 */
                                if ((uint16_t)(ww >> 6) > 0x3fcu) {
                                    ww = (uint16_t)((ww & 0x003fu) | 0x0040u);
                                }
                                /* clamp mdIdle (low 6 bits) to <= 6; else clear */
                                if ((ww & 0x003fu) > 6u) {
                                    ww = (uint16_t)(ww & 0xffc0u);
                                }

                                vrgZipProd[i].rgpq[iPass].w = ww;
                                psz2 += 4;
                            }
                        }
                    }
                }
            }
        }
    }

    CchGetString(idsDefault, vrgZipProd[0].szName);
    vrgZipProd[0].fValid = 1;
}

void InitStarsPath() {
    szStarsPath[0] = '\0';
    GetCurrentDirectoryA(sizeof(szStarsPath), szStarsPath);
    lstrcatA(szStarsPath, "\\");
}

int16_t InitInstance(int16_t nCmdShow) {
    int16_t sw;
    RECT    rc;

    (void)rc;

    InitStarsPath();

    /* decompile: ini.wFlags = ini.wFlags & 0xfe1a; */
    ini.wFlags &= 0xFE1Au;
    ini.idPlayer = -1;

    ReadIniSettings();

    hwndFrame = CreateWindowA(szFrame, "Stars!", WS_OVERLAPPEDWINDOW, ini.wnFrame.rc.left, ini.wnFrame.rc.top, ini.wnFrame.rc.right, ini.wnFrame.rc.bottom,
                              NULL, NULL, hInst, NULL);

    if (hwndFrame == NULL) {
        return 0;
    }

    hAccel = LoadAcceleratorsA(hInst, MAKEINTRESOURCEA(IDA_MAIN));
    if (hAccel == NULL) {
        return 0;
    }

    hAccelTitle = LoadAcceleratorsA(hInst, MAKEINTRESOURCEA(IDA_TITLE));
    if (hAccelTitle == NULL) {
        return 0;
    }

    /*
     * decompile:
     *   if (nCmdShow == 1) { if (!min && !max) sw=1; else sw=3; } else sw=nCmdShow;
     */
    if (nCmdShow == SW_SHOWNORMAL) {
        if ((ini.wnFrame.fMinimized == 0) && (ini.wnFrame.fMaximized == 0)) {
            sw = SW_SHOWNORMAL;
        } else {
            sw = SW_SHOWMAXIMIZED;
        }
    } else {
        sw = nCmdShow;
    }

    ShowWindow(hwndFrame, sw);
    ShowWindow(hwndFrame, SW_HIDE);
    UpdateWindow(hwndFrame);
    return 1;
}

void GetIniWinRc(char *szSection, char *szIniFile, StringId ids, WN *pwn) {
    /* INI value format (17 chars total): [M|R|I] then 4 fixed-width signed fields (4 chars each). */
    char szEntry[16];
    RECT rc;
    bool fOk = false;

    bool fMaximized = false;
    bool fMinimized = false;
    bool fInitalized = false;

    CchGetString(ids, szEntry);

    /* Default value is "X" (i.e., not present / invalid). */
    {
        uint32_t cch = GetPrivateProfileStringA(szSection, szEntry, "X", szWork, 0x14, szIniFile);

        if (cch == 0x11 && (szWork[0] == 'M' || szWork[0] == 'R' || szWork[0] == 'I')) {
            const char *pch = szWork + 1;
            int16_t     rg[4];
            int         i;

            for (i = 0; i < 4; i++) {
                int16_t val = 0;
                bool    fNeg = false;
                int     j;

                for (j = 0; j < 4; j++) {
                    char ch = *pch++;
                    if (ch == '-') {
                        /* Win16 quirk: any '-' in the 4-char field makes it negative. */
                        fNeg = true;
                        continue;
                    }
                    if (ch < '0' || ch > '9') {
                        goto INIT_NoRc;
                    }
                    val = (int16_t)(val * 10 + (int16_t)(ch - '0'));
                }

                if (fNeg)
                    val = (int16_t)-val;

                rg[i] = val;
            }

            rc.left = rg[0];
            rc.top = rg[1];
            rc.right = rg[2];
            rc.bottom = rg[3];

            fMaximized = (szWork[0] == 'M');
            fMinimized = (szWork[0] == 'I');
            fInitalized = true;
            fOk = true;
        }
    }

INIT_NoRc:
    if (!fOk) {
        rc.left = (int16_t)-0x8000;
        rc.right = (int16_t)-0x8000;
        rc.top = 0;
        rc.bottom = 0;

        /* Default for main window only: maximized. */
        fMaximized = (ids == idsMain);
        fMinimized = false;
        fInitalized = false;
    }

    pwn->rc = rc;
    pwn->fMaximized = (uint16_t)(fMaximized ? 1 : 0);
    pwn->fMinimized = (uint16_t)(fMinimized ? 1 : 0);
    pwn->fInitalized = (uint16_t)(fInitalized ? 1 : 0);
}

void InitTiles(void) {
    int16_t  yTop;
    int16_t  ctile;
    TILE    *rgtile;
    int16_t  i;
    int16_t  iPass;
    uint16_t iCol;

    /* TODO: implement */
}

#endif