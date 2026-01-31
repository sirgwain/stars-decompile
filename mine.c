
#include "globals.h"
#include "types.h"

#include "mine.h"

/*
 * GetMineFieldCounts
 *
 * Count the current player's minefields and determine the ordinal index
 * (1-based) of a specific minefield within that set.
 *
 * This function scans the global THING array (lpThings[0..cThing-1]) and
 * selects only minefield THINGs:
 *   - ith == 0        : minefield object
 *   - iplr == idPlayer : owned by the current player
 *
 * For each qualifying minefield, a running total is maintained. When a
 * minefield whose idFull matches the supplied `id` is encountered, its
 * ordinal position among the current player's minefields is recorded.
 *
 * Parameters:
 *   id     - Full THING id (idFull) of the minefield to locate.
 *   pithm  - [out] Receives the 1-based index of the matching minefield
 *            among the current player's minefields, or 0 if not found.
 *   pcthm  - [out] Receives the total number of minefields owned by the
 *            current player.
 *
 * Notes:
 *   - The original Win16 code performed pointer arithmetic in bytes over
 *     0x12-byte THING records; this modern C version iterates using typed
 *     THING pointers, preserving the same ordering and counts.
 *   - The function does not inspect the THMINE payload itself; ownership
 *     and type are determined solely from the THING header bitfields.
 */
void GetMineFieldCounts(uint16_t id, int16_t *pithm, int16_t *pcthm) {
    int16_t ithFound = 0; /* 1-based index of the minefield with matching id (within current player's minefields) */
    int16_t cthTotal = 0; /* total minefields owned by current player */

    THING *lpth = lpThings;
    THING *lpthEnd = lpThings + (size_t)cThing;

    for (; lpth < lpthEnd; ++lpth) {
        /* In the Win16 layout this matches:
           (idFull >> 13) == 0  => ith == 0 (minefield "thing" kind)
           ((idFull >> 9) & 0xF) == idPlayer => iplr == current player
        */
        if (lpth->ith == ithMinefield && lpth->iplr == (uint16_t)idPlayer) {
            cthTotal++;

            /* ithFound is the ordinal position (1..cthTotal) of the minefield whose idFull matches `id` */
            if (lpth->idFull == id) {
                ithFound = cthTotal;
            }
        }
    }

    *pithm = ithFound;
    *pcthm = cthTotal;
}

void EstMineralsMined(PLANET *lppl, int32_t *plQuan, int32_t cMines, int16_t fApply) {
    int32_t lQuanRem;
    int32_t lQuanAct;
    int16_t i;
    int32_t lQuan;
    int16_t fMacintosh;
    int16_t fRemote;
    int32_t lMine;
    int32_t lMineEff;
    int32_t lConc;
    int32_t lLeft;
    int32_t lLevel;
    int32_t rglQuan[3];
    int16_t ifl;
    FLEET  *lpfl;
    int32_t lLength;

    /* debug symbols */
    /* block (block) @ MEMORY_MINE:0x5498 */
    /* block (block) @ MEMORY_MINE:0x5666 */
    /* block (block) @ MEMORY_MINE:0x58ae */

    /* TODO: implement */
}

#ifdef _WIN32

void MineClick(int16_t x, int16_t y, int16_t msg, int16_t sks) {
    PLANET *lppl;
    int16_t ht;
    int16_t rgMin[3];
    int16_t fOurs;
    PART    part;
    FLEET  *lpfl;
    int16_t i;
    int32_t rglQuan[3];
    int16_t idNew;
    SCAN    scan;
    PLANET  pl;
    int16_t rgCost[3];
    int16_t rgMax[3];
    int32_t rglT[3];
    int16_t ifl;
    char    rgsz[9][10];
    int32_t cMines;
    int32_t lVal;
    int16_t rgi[9];
    int16_t iChecked;
    char   *psz[1];
    char   *rgpsz[1];
    int16_t c;
    int16_t rgid[16];
    int16_t ishdef;

    /* debug symbols */
    /* block (block) @ MEMORY_MINE:0x3b9e */
    /* block (block) @ MEMORY_MINE:0x3c2a */
    /* block (block) @ MEMORY_MINE:0x3ca9 */
    /* block (block) @ MEMORY_MINE:0x3f41 */
    /* block (block) @ MEMORY_MINE:0x40a4 */
    /* block (block) @ MEMORY_MINE:0x443c */
    /* block (block) @ MEMORY_MINE:0x456f */
    /* block (block) @ MEMORY_MINE:0x4608 */
    /* label NoTerra @ MEMORY_MINE:0x4010 */
    /* label CheckThing @ MEMORY_MINE:0x40cb */
    /* label ChangeIt @ MEMORY_MINE:0x43d9 */
    /* label CheckPlanet @ MEMORY_MINE:0x429f */
    /* label CheckFleet @ MEMORY_MINE:0x42f3 */

    /* TODO: implement */
}

int16_t FOtherStuffAtScanSel(void) {
    int16_t c;
    int16_t i;
    THING  *lpth;
    FLEET  *lpfl;
    THING  *lpthMac;

    /* TODO: implement */
    return 0;
}

void DrawMineSurvey(HDC hdc, RECT *prc) {
    PLANET   pl;
    HBRUSH   hbrSav;
    int32_t  l2;
    uint32_t crFore;
    int16_t  c2;
    int32_t  rgl[3];
    int16_t  c;
    int16_t  i;
    FLEET   *lpfl;
    uint32_t crBack;
    HDC      hdcMem;
    int16_t  bkMode;
    char    *psz;
    int16_t  cch;
    RECT     rcGauge;
    char     szT[80];
    int16_t  grobj;
    int32_t  l;
    RECT     rc;
    int16_t  yTop;
    int16_t  fCanTerraform;
    uint16_t hbmpSav;
    int32_t  cMass;
    THING   *lpth;
    int16_t  xLeft;
    int16_t  rgMin[3];
    int32_t  pctDecay;
    int16_t  xL;
    int32_t  cShip;
    int16_t  ibmp;
    int16_t  dyRow;
    int16_t  iOffset;
    int32_t  lDecay;
    int16_t  iMax;
    ORDER   *lpord;
    int16_t  yBot;
    int16_t  iplrbmp;
    int16_t  fShortLabels;
    int16_t  cNum;
    THING   *lpthDest;
    int16_t  dy;
    char     szWP[30];
    char    *pszT;
    PLAYER   plrSav;
    int16_t  iMin;
    int16_t  xEnd;
    int16_t  yCur;
    int16_t  dxBar;
    int16_t  dxNum;
    int16_t  xR;
    int16_t  dxRLabels;
    int16_t  iCur;
    int16_t  rgCost[3];
    int16_t  rgMax[3];
    int16_t  dxLabels;
    int16_t  dx;
    int16_t  xBeg;
    int16_t  dNum;
    int16_t  dBest;
    int16_t  iT;
    int16_t  iPass;
    POINT    pt;
    uint32_t crBkSav;
    uint32_t crTextSav;
    int32_t  rglT[3];
    int16_t  ifl;
    int32_t  cMines;

    /* debug symbols */
    /* block (block) @ MEMORY_MINE:0x071c */
    /* block (block) @ MEMORY_MINE:0x0d75 */
    /* block (block) @ MEMORY_MINE:0x1022 */
    /* block (block) @ MEMORY_MINE:0x1162 */
    /* block (block) @ MEMORY_MINE:0x1869 */
    /* block (block) @ MEMORY_MINE:0x1fb8 */
    /* block (block) @ MEMORY_MINE:0x2201 */
    /* block (block) @ MEMORY_MINE:0x2405 */
    /* block (block) @ MEMORY_MINE:0x25a0 */
    /* block (block) @ MEMORY_MINE:0x2b36 */
    /* block (block) @ MEMORY_MINE:0x31b2 */
    /* block (block) @ MEMORY_MINE:0x3598 */
    /* block (block) @ MEMORY_MINE:0x36f9 */
    /* label FinishUp @ MEMORY_MINE:0x3776 */

    /* TODO: implement */
}

void InvalidateMineralBars(void) {
    HDC      hdc;
    int16_t  dyRow;
    uint16_t hfontSav;
    RECT     rcPop;
    int16_t  dx;
    int16_t  dxPop;
    RECT     rc;

    /* TODO: implement */
}

LRESULT CALLBACK MineWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    PAINTSTRUCT ps;
    RECT        rc;
    int16_t     fDetonate;
    POINT       pt;
    uint32_t    crFore;
    int16_t     ht;
    uint16_t    dxMax;
    RTLOGTHING  rtlt;
    uint32_t    crBack;
    int16_t     cch;
    RECT        rc2;

    switch (msg) {
    case WM_CREATE:
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC         hdc = BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        /* if you paint the whole client yourself, returning 1 avoids flicker */
        return 0;

    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);

    /* TODO: implement */
    return 0;
}

void DrawSelectionArrow(HDC hdc, RECT *prc, int16_t fEnabled) {
    uint16_t hbmpSav;
    HDC      hdcMem;
    int16_t  xCtr;

    /* TODO: implement */
}

void PopupMineralScanChoices(HWND hwnd, int16_t x, int16_t y) {
    int16_t fSep;
    int16_t id;
    int16_t fOurs;
    PLANET *lppl;
    int16_t i;
    int16_t c;
    THING  *lpth;
    FLEET  *lpfl;
    THING  *lpthMac;
    int32_t rgid[100];
    int16_t idNew;
    int16_t iChecked;
    SCAN    scan;

    /* TODO: implement */
}

void SetMineralTitleBar(HWND hwnd) {
    char    szDeepSpace[40];
    char    szSummary[40];
    int16_t fVisCB;
    char   *psz;
    int16_t grobj;
    RECT    rc;

    /* TODO: implement */
}

int16_t HtMineWindow(HWND hwnd, int16_t x, int16_t y) {
    PLANET  pl;
    int16_t dyRow;
    int16_t yCur;
    int16_t grobj;
    RECT    rc;

    /* TODO: implement */
    return 0;
}

void DrawDiamond(HDC hdc, RECT *prc, HBRUSH hbr) {
    HBRUSH  hbrSav;
    int16_t yTop;
    int16_t yBot;
    int16_t xCtr;
    int16_t dx;
    int16_t xCur;

    /* TODO: implement */
}
#endif /* _WIN32 */
