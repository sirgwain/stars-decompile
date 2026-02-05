
#include "globals.h"
#include "types.h"

#include "mine.h"
#include "planet.h"
#include "race.h"
#include "ship2.h"
#include "utilgen.h"

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
    int32_t lMineEff;
    int32_t lConc;
    int32_t lLevel;
    int32_t rglQuan[3];
    int16_t ifl;
    FLEET  *lpfl;
    int32_t lDecayAmt;
    int32_t lThreshold;
    int32_t lLevelDecay;

    fRemote = (cMines != -1);

    /* Check if planet owner is Alternate Reality (AR/Macintosh) race */
    if (lppl->iPlayer == -1 || GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) != raMacintosh) {
        fMacintosh = 0;
    } else {
        fMacintosh = 1;
    }

    if (cMines == -1) {
        /* Local mining: calculate from planet's mines */
        if (lppl->iPlayer == -1 || lppl->rgwtMin[3] == 0) {
            /* No owner or no population - return -1 for all minerals */
            for (i = 0; i < 3; i++) {
                plQuan[i] = -1;
            }
            return;
        }
        cMines = (int32_t)CMinesOperating(lppl);
        if (fMacintosh == 0) {
            lMineEff = (int32_t)GetRaceStat(&rgplr[lppl->iPlayer], rsMineProd);
        } else {
            lMineEff = 10;
        }
    } else {
        /* Remote mining: efficiency is always 10 */
        lMineEff = 10;
    }

    i = 0;
    do {
        if (i > 2) {
            /* After processing all 3 minerals, handle AR fleet mining */
            if (fMacintosh != 0 && fRemote == 0) {
                for (ifl = 0; ifl < cFleet; ifl++) {
                    lpfl = rglpfl[ifl];
                    if (lpfl == NULL) {
                        return;
                    }

                    /* Check fleet is at this planet, owned by planet owner, not dead, orbiting, with Remote Mining task (grTask == 3) */
                    if (lpfl->idPlanet == lppl->id &&
                        lpfl->iPlayer == lppl->iPlayer &&
                        !lpfl->fDead &&
                        lpfl->cord < 2 &&
                        lpfl->lpplord->rgord[0].grTask == 3) {

                        int32_t lFleetMines = CMineFromLpfl(lpfl);
                        if (lFleetMines >= 0 && lFleetMines > 0) {
                            EstMineralsMined(lppl, rglQuan, lFleetMines, fApply);

                            /* Add fleet's mining to output */
                            for (i = 0; i < 3; i++) {
                                plQuan[i] += rglQuan[i];
                            }

                            if (fApply) {
                                /* Clear the fHereAllTurn flag */
                                lpfl->wRaw_0004 &= 0xdfff;
                            }
                        }
                    }
                }
            }
            return;
        }

        lConc = (int32_t)lppl->rgMinConc[i];

        /* If concentration < 30 and planet is homeworld, boost to 30 for local mining or AR */
        if (lConc < 30 && lppl->fHomeworld && (fRemote == 0 || fMacintosh != 0)) {
            lConc = 30;
        }

        /* Calculate raw quantity: cMines * concentration */
        lQuanAct = cMines * lConc;

        if (fRemote == 0) {
            /* Local mining: apply mine efficiency */
            lQuan = (lQuanAct * lMineEff) / 10;
        } else {
            lQuan = lQuanAct;
        }

        /* Divide by 100 to get actual minerals, keeping remainder */
        lQuanRem = lQuan % 100;
        lQuan = lQuan / 100;

        /* Probabilistic rounding based on remainder if generating turn */
        if (lQuanRem != 0 && gd.fGeneratingTurn) {
            if (Random(100) < (int16_t)lQuanRem) {
                lQuan++;
            }
        }

        plQuan[i] = lQuan;

        if (fApply) {
            /* Add mined minerals to planet surface */
            lppl->rgwtMin[i] += lQuan;

            /* Calculate concentration decay based on raw mining amount */
            lDecayAmt = lQuanAct / 100;
            while (lDecayAmt >= 1 && lppl->rgMinConc[i] >= 2) {
                lLevel = (int32_t)lppl->rgpctMinLevel[i];
                lConc = (int32_t)lppl->rgMinConc[i];

                if (lLevel == 0) {
                    lLevel = 256;
                }

                /* Clamp concentration for decay calculation */
                if (lConc >= 101) {
                    lConc = 100;
                } else if (lConc < 5) {
                    lConc = 10;
                } else if (lConc < 25) {
                    lConc = 25;
                }

                /* Calculate threshold: 0x30d4 (12500) * level / 256 / concentration */
                lThreshold = (12500L * lLevel) / 256 / lConc;

                if (lDecayAmt < lThreshold) {
                    /* Not enough mining to fully decay - update sub-level */
                    lLevelDecay = 12500L / lConc;
                    /* Convert remaining decay amount to sub-level (0-255) */
                    lLevel = (lDecayAmt * 256) / lLevelDecay;
                    if (lLevel < 1) {
                        lLevel = 1;
                    }
                    /* Ensure we don't exceed current level */
                    if (lLevel >= (lppl->rgpctMinLevel[i] == 0 ? 256 : lppl->rgpctMinLevel[i])) {
                        lLevel = (lppl->rgpctMinLevel[i] == 0 ? 256 : lppl->rgpctMinLevel[i]) - 1;
                    }
                    lppl->rgpctMinLevel[i] = (uint8_t)lLevel;
                    if (lLevel == 0) {
                        lppl->rgMinConc[i]--;
                    }
                    break;
                }

                /* Enough mining to decay concentration by 1 */
                lDecayAmt -= lThreshold;
                lppl->rgMinConc[i]--;
                lppl->rgpctMinLevel[i] = 0;
            }
        }

        i++;
    } while (1);
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

void DrawDiamond(HDC hdc, RECT *prc, HBRUSH hbrFill) {
    int     xCenter;
    int     xLeft;
    int     xRight;
    int     yTop;
    int     yBottom;
    int     fillWidth;
    HGDIOBJ hbrPrev;

    /* Center x of the diamond. */
    xCenter = ((prc->right - prc->left) / 2) + prc->left;

    /*
     * The original uses PatBlt with rop 0xF00021 (PATCOPY).
     * It relies on the currently selected brush, so we switch brushes to draw:
     *  - highlight edges (hbrButtonHilite)
     *  - shadow edges   (hbrButtonShadow)
     *  - interior fill  (hbrFill)
     */
    hbrPrev = SelectObject(hdc, hbrButtonHilite);

    /* --- Highlight edge (left-leaning) --- */
    yTop = prc->top;
    yBottom = prc->bottom - 2;
    xLeft = xCenter;
    while (1) {
        yTop += 1;
        xLeft -= 1;
        if (yTop > yBottom) {
            break;
        }
        PatBlt(hdc, xLeft, yTop, 2, 1, PATCOPY);
        PatBlt(hdc, xLeft, yBottom, 2, 1, PATCOPY);
        yBottom -= 1;
    }

    /* --- Shadow edge (center spine) --- */
    SelectObject(hdc, hbrButtonShadow);
    PatBlt(hdc, xCenter, prc->top, 1, 1, PATCOPY);
    PatBlt(hdc, xCenter, prc->bottom - 1, 1, 1, PATCOPY);

    /* --- Shadow edge (right-leaning) --- */
    yTop = prc->top;
    yBottom = prc->bottom - 2;
    xRight = xCenter;
    while (1) {
        yTop += 1;
        if (yTop > yBottom) {
            break;
        }
        PatBlt(hdc, xRight, yTop, 2, 1, PATCOPY);
        PatBlt(hdc, xRight, yBottom, 2, 1, PATCOPY);
        xRight += 1;
        yBottom -= 1;
    }

    /* --- Interior fill --- */
    SelectObject(hdc, hbrFill);
    fillWidth = 1;
    xLeft = xCenter;
    yTop = prc->top + 4;
    yBottom = prc->bottom - 5;
    while (yTop <= yBottom) {
        PatBlt(hdc, xLeft, yTop, fillWidth, 1, PATCOPY);
        PatBlt(hdc, xLeft, yBottom, fillWidth, 1, PATCOPY);
        fillWidth += 2;
        xLeft -= 1;
        yBottom -= 1;
        yTop += 1;
    }

    SelectObject(hdc, hbrPrev);
}

#endif /* _WIN32 */
