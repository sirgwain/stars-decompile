
#include "globals.h"
#include "types.h"

#include "report.h"
#include "vcr.h"

/* globals */
uint16_t mpicolgrbitBU[12] = {0x00ff, 0x00ff, 0x00ff, 0x00ff, 0x00ff, 0x00ff, 0x00ff, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080};

void DumpUniverse(void) {
    int16_t  ids;
    int16_t  i;
    MemJump  env;
    int16_t  fOpen;
    int16_t  fSuccess;
    int16_t  fSilentSav;
    MemJump *penvMemSav;
    int16_t  cch;

    /* debug symbols */
    /* label DisplayStatus @ MEMORY_REPORT:0x866b */

    /* TODO: implement */
}

void DumpFleets(void) {
    int16_t iplr;
    int16_t ids;
    char    szFile[256];
    char    szForm[256];
    int16_t ifl;
    FLEET  *lpfl;
    int16_t j;
    int16_t i;
    MemJump env;
    ;
    int16_t  fOpen;
    int16_t  fSuccess;
    int16_t  fSilentSav;
    MemJump *penvMemSav;
    char    *psz;
    int16_t  cch;
    int32_t  l;

    /* debug symbols */
    /* label DisplayStatus @ MEMORY_REPORT:0xa144 */

    /* TODO: implement */
}

void DumpPlanets(void) {
    PLANET *lpplMac;
    int16_t ids;
    PLANET *lppl;
    char    szFile[256];
    char    szForm[256];
    int16_t j;
    int16_t i;
    MemJump env;
    ;
    int16_t  fOpen;
    int16_t  fSuccess;
    int16_t  fSilentSav;
    MemJump *penvMemSav;
    char    *psz;
    int16_t  cch;
    int32_t  l;
    float    pct;
    PART     part;
    int32_t  rgl[4];

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x8ac2 */
    /* block (block) @ MEMORY_REPORT:0x8c01 */
    /* block (block) @ MEMORY_REPORT:0x8e3b */
    /* block (block) @ MEMORY_REPORT:0x9348 */
    /* label DisplayStatus @ MEMORY_REPORT:0x94b2 */

    /* TODO: implement */
}

char *PszGetETA(HDC hdc, FLEET *lpfl, int16_t *pcYears) {
    POINT   pt;
    int16_t c;
    int16_t i;
    ORDER   ord;
    char   *psz;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x5339 */
    /* label LNoETA @ MEMORY_REPORT:0x539c */

    /* TODO: implement */
    return NULL;
}

char *PszGetTaskName(FLEET *lpfl, int16_t *picr) {
    int16_t icr;
    int16_t ids;
    int16_t opOrd;
    int16_t iZip;
    int16_t i;
    ORDER   ord;
    int16_t fPercent;
    char   *psz;

    /* debug symbols */
    /* label LShowTask @ MEMORY_REPORT:0x54a6 */

    /* TODO: implement */
    return NULL;
}

char *PszGetDestName(FLEET *lpfl, HDC hdc) {
    int16_t i;
    ORDER   ord;

    /* debug symbols */
    /* label LDelayed @ MEMORY_REPORT:0x500e */
    /* label LNoDest @ MEMORY_REPORT:0x50a7 */

    /* TODO: implement */
    return NULL;
}

void InvalidateReport(int16_t irpt, int16_t fReload) {
    int16_t   fClearRpt;
    RPT      *prptSav;
    uint16_t *lprgidSav;
    bool      fRestoreSav;

    fClearRpt = 0;
    fRestoreSav = false;
    if (gd.fGeneratingTurn || fAi)
        return;
#ifdef _WIN32
    if (hwndReportDlg == 0 || irpt != vprptCur->irpt) {
#else
    if (vprptCur == NULL || irpt != vprptCur->irpt) {
#endif
        if (vprptCur == NULL) {
            fClearRpt = fReload;
            if (irpt == 0)
                vprptCur = &vrptPlanet;
            else
                vprptCur = &vrptFleet;
        } else if (fReload != 0 && vprptCur->irpt != irpt) {
            lprgidSav = vlprgidRep;
            prptSav = vprptCur;
            fRestoreSav = true;
            if (irpt == 0)
                vprptCur = &vrptPlanet;
            else
                vprptCur = &vrptFleet;
        }
    } else {
#ifdef _WIN32
        RECT rc;
        GetClientRect(hwndReportDlg, &rc);
        if (fReload != 2) {
            rc.top = dyArial8 + 6;
            rc.bottom = (dyArial8 + 4) * vprptCur->cRowsVis + rc.top;
        }
        InvalidateRect(hwndReportDlg, &rc, fReload == 2);
#endif
        gd.fRptSafeDraw = 1;
    }
    vprptCur->fCached = 0;
#ifdef _WIN32
    if (fReload != 0) {
        SortReportCache(vprptCur->irpt, vprptCur->icolSort);
    }
#endif
    if (fClearRpt != 0) {
        vprptCur = NULL;
    } else if (fRestoreSav) {
        vprptCur = prptSav;
        vlprgidRep = lprgidSav;
#ifdef _WIN32
    } else if (fReload != 0 && hwndReportDlg != 0 && irpt == vprptCur->irpt) {
        SetScrollRange((HWND)(uintptr_t)vprptCur->hwndVScroll, 2, 0, vprptCur->cRows - vprptCur->cRowsVis, 0);
        InvalidateRect(hwndReportDlg, NULL, 1);
#endif
    }
}

#ifdef _WIN32

/* functions */
INT_PTR CALLBACK ScoreXDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HDC         hdc;
    POINT       pt;
    PAINTSTRUCT ps;
    char        szT[40];
    int16_t     cchHistory;
    char       *rgszScan[1];
    int16_t     c;
    int32_t     rgid[12];
    char       *psz;
    int16_t     iSel;
    int16_t     cch;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x0ff1 */
    /* block (block) @ MEMORY_REPORT:0x1065 */
    /* block (block) @ MEMORY_REPORT:0x10c3 */

    /* TODO: implement */
    return 0;
}

// Renamed from ReportDlg, because it's used like a window, not a dialog
LRESULT CALLBACK ReportWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    /* locals (function scope) */
    HDC     hdc;    /* [BP-6]  */
    HMENU   hmenu;  /* [BP-8]  */
    RECT    rc;     /* [BP-16] */
    int16_t i;      /* [BP-18] */
    int16_t dx;     /* [BP-20] */

    /* locals (block 2) */
    uint16_t swp;   /* [BP-18] */
    int16_t  cRow;  /* [BP-20] */
    // int16_t  dx;    /* [BP-22] */

    /* locals (block 3) */
    POINT    pt;    /* [BP-20] */
    // int16_t  i;     /* [BP-22] */
    int16_t  ibit;  /* [BP-24] */
    int16_t  iCol;  /* [BP-26] */
    int16_t  iRow;  /* [BP-28] */
    int16_t  xCur;  /* [BP-30] */

    /* locals (block 4) */
    int16_t  iCur;  /* [BP-18] */
    int16_t  iNew;  /* [BP-20] */

    /* locals (block 5) */
    // int16_t  iCur;  /* [BP-18] */
    // int16_t  iNew;  /* [BP-20] */

    /* locals (block 6) */
    // int16_t  i;     /* [BP-22] */
    // int16_t  ibit;  /* [BP-24] */

    /* locals (block 7) */
    PAINTSTRUCT ps; /* [BP-48] */

    /* locals (block 8) */
    int16_t idm;    /* [BP-18] */

    switch (msg) {
    case WM_CREATE:
        return 0;

    case WM_SIZE:
        /* TODO: layout report child controls */
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC         hdc = BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

INT_PTR CALLBACK PrintMapDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t i;
    RECT    rc;
    HWND    hwndEdit;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0xa1d9 */
    /* block (block) @ MEMORY_REPORT:0xa2dc */

    /* TODO: implement */
    return 0;
}

void SetHScrollBar(void) {
    uint16_t swp;
    int16_t  dy;
    int16_t  ccolSkipped;
    int16_t  ccolHidden;
    int16_t  i;
    int16_t  ibit;
    int16_t  xRight;
    int16_t  dx;
    int16_t  xTitle;
    RECT     rc;

    /* TODO: implement */
}

void SortReportCache(int16_t irpt, int16_t icol) {
    uint16_t rgidRep[1024];
    int16_t  cRows;
    uint16_t iItem;
    PLANET  *lppl;
    FLEET   *lpfl;
    int16_t  i;

    cRows = 0;
    iItem = 0;
    if (vprptCur->icolSort != icol) {
        vicolSortPrev = vprptCur->icolSort;
        viSubsortPrev = vprptCur->iSubsort;
        vfAscendingPrev = vprptCur->fAscending;
        vprptCur->icolSort = icol;
        gd.fChgReports = 1;
    }
    if (hwndReportDlg != 0 || vprptCur->fCached == 0) {
        if (irpt == 0) {
            vlprgidRep = vlprgidPlanet;
            lppl = (PLANET *)lpPlanets;
            while (lppl < (PLANET *)lpPlanets + cPlanet) {
                if (lppl->iPlayer == idPlayer && lppl->det == detAll) {
                    rgidRep[cRows] = iItem;
                    cRows++;
                }
                iItem++;
                lppl++;
            }
        } else if (irpt == 1) {
            vlprgidRep = vlprgidFleet;
            for (iItem = 0; (int16_t)iItem < cFleet; iItem++) {
                lpfl = rglpfl[iItem];
                if (lpfl == NULL)
                    break;
                if (lpfl->iplr == idPlayer) {
                    rgidRep[cRows] = iItem;
                    cRows++;
                }
            }
        } else if (irpt == 2) {
            vlprgidRep = vlprgidMisc;
            vrptBattle.fCached = 0;
            for (iItem = 0; (int16_t)iItem < cFleet; iItem++) {
                lpfl = rglpfl[iItem];
                if (lpfl == NULL)
                    break;
                if (lpfl->iplr != idPlayer) {
                    rgidRep[cRows] = iItem;
                    cRows++;
                }
                if (cRows >= 1020)
                    break;
            }
        } else if (irpt == 3) {
            vlprgidRep = vlprgidMisc;
            vrptEFleet.fCached = 0;
            cRows = CBattles();
            for (i = 0; i < cRows; i++) {
                rgidRep[i] = i;
            }
        } else {
            return;
        }
        vprptCur->cRows = cRows;
        qsort(rgidRep, cRows, 2, (int (*)(const void *, const void *))ICompReport);
        memcpy(vlprgidRep, rgidRep, cRows * 2);
        vprptCur->fCached = 1;
    }
}

void InitScoreDlg(HWND hwnd, int16_t fVictory) {
    HDC     hdc;
    int16_t dxDig;
    int16_t dy;
    int16_t dyFrame;
    int16_t dxFrame;
    RECT    rcWindow;
    char   *psz;
    int16_t dx;
    RECT    rc;

    /* TODO: implement */
}

void ReportColumnPopup(POINT pt, int16_t icol, int16_t fRightBtn) {
    HDC     hdc;
    char    szT[50];
    char    rgsz[32][50];
    int16_t iBase;
    int16_t cSubsort;
    int16_t j;
    int16_t i;
    int16_t ibit;
    int16_t fccolChange;
    int16_t rgcol[32];
    char    szColTitle[50];
    int16_t cItems;
    char   *psz[1];
    int16_t cch;
    int16_t iRet;
    int16_t iHide;
    int16_t iSortLast;

    /* TODO: implement */
}

int16_t FDestIsWP0(FLEET *lpfl) {
    int16_t i;
    ORDER   ord;

    /* TODO: implement */
    return 0;
}

int16_t ICompReport(void *arg1, void *arg2) {
    char     szT[80];
    int32_t  l2;
    int16_t  fAscending;
    int16_t  icolSort;
    int16_t  i1;
    int16_t  j;
    int16_t  i;
    int32_t  l1;
    int16_t  iSubsort;
    char    *psz;
    int16_t  iRet;
    int16_t  i2;
    int16_t  fTier2;
    int16_t  irpt;
    PLANET  *lppl2;
    FLEET   *lpfl2;
    BTLDATA *lpbd1;
    int16_t  ibtl2;
    PLANET  *lppl1;
    FLEET   *lpfl1;
    int16_t  ibtl1;
    int16_t  iFirst;
    float    pct2;
    int16_t  iLast;
    BTLDATA *lpbd2;
    float    pct1;
    int32_t  rgl[4];

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x5bfc */
    /* block (block) @ MEMORY_REPORT:0x5ff4 */
    /* block (block) @ MEMORY_REPORT:0x619c */
    /* block (block) @ MEMORY_REPORT:0x6283 */
    /* block (block) @ MEMORY_REPORT:0x63d5 */
    /* block (block) @ MEMORY_REPORT:0x69eb */
    /* block (block) @ MEMORY_REPORT:0x6d5f */
    /* label LEFleetCount @ MEMORY_REPORT:0x7262 */
    /* label BtlUnitsCom @ MEMORY_REPORT:0x6c18 */
    /* label LUnitsLeft @ MEMORY_REPORT:0x6ca1 */
    /* label LRetDiff @ MEMORY_REPORT:0x691c */
    /* label TryTier2 @ MEMORY_REPORT:0x5bf3 */

    /* TODO: implement */
    return 0;
}

void DrawReport(HWND hwnd, HDC hdc, RECT *prc) {
    char    szTit[40];
    int16_t irowLast;
    int16_t j;
    int16_t i;
    int16_t yRow;
    int16_t ibit;
    int16_t dx;
    int16_t xCol;
    RECT    rc;

    /* debug symbols */
    /* label NoHdrDraw @ MEMORY_REPORT:0x0d4e */

    /* TODO: implement */
}

int16_t DxReportColHdr(int16_t irpt, int16_t iCol, char *psz, HDC hdc) {
    char    szT[40];
    int16_t ids;
    int16_t dxDigit;
    int16_t dx;
    int16_t cch;
    int16_t dx2;

    /* debug symbols */
    /* label DxChk @ MEMORY_REPORT:0x3115 */
    /* label ChkAltString @ MEMORY_REPORT:0x30ee */

    /* TODO: implement */
    return 0;
}

int32_t LFetchScoreXVal(SCOREX *lpsx, int16_t iVal) {

    /* TODO: implement */
    return 0;
}

void ExecuteReportClick(POINT pt, int16_t irpt, int16_t icol, int16_t irow) {
    HDC      hdc;
    BTLDATA *lpbd;
    PLANET  *lppl;
    int16_t  i;
    FLEET   *lpfl;
    int16_t  ibit;
    int32_t  rglQuan[4];
    int16_t  xCur;
    int16_t  dxOffset;
    SCAN     scan;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x8328 */
    /* label LShowStarbase @ MEMORY_REPORT:0x7d84 */
    /* label LDisplayVCRAnyway @ MEMORY_REPORT:0x8399 */

    /* TODO: implement */
}

void DrawVCReport(HDC hdc) {
    int16_t  grbitVC;
    int16_t  xStart;
    int16_t  dxDig;
    int16_t  yTop;
    POINT    pt;
    int16_t  cCurSav;
    int16_t  ids;
    COLORREF cr;
    int16_t  cCur;
    HDC      hdcMem;
    int16_t  j;
    int16_t  i;
    int16_t  iPass;
    char    *psz;
    HBITMAP  hbmpSav;
    int16_t  cch;
    int16_t  xLeft;
    int32_t  l;
    int16_t  idsT;
    int16_t  vcVal;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x1c88 */
    /* label LOrIt @ MEMORY_REPORT:0x19f4 */

    /* TODO: implement */
}

void DrawReportItem(HDC hdc, RECT *prc, int16_t irpt, int16_t irow, int16_t icol) {
    BTLDATA *lpbd;
    char     szT[100];
    char     chT;
    char    *lpsz;
    PLANET  *lppl;
    int16_t  j;
    int16_t  i;
    FLEET   *lpfl;
    int16_t  dx;
    char    *psz;
    int16_t  xCur;
    int16_t  cch;
    int32_t  l;
    HBRUSH   hbr;
    int16_t  iItem;
    int16_t  fEnough;
    float    pct;
    RECT     rc;
    int32_t  rgl[4];
    PLANET   pl;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x3612 */
    /* block (block) @ MEMORY_REPORT:0x3829 */
    /* block (block) @ MEMORY_REPORT:0x3b49 */
    /* block (block) @ MEMORY_REPORT:0x3c43 */
    /* block (block) @ MEMORY_REPORT:0x3c99 */
    /* block (block) @ MEMORY_REPORT:0x41c7 */
    /* label LEFleetCount @ MEMORY_REPORT:0x4c70 */
    /* label DrawPlusDef @ MEMORY_REPORT:0x39b9 */
    /* label DrawMineFact @ MEMORY_REPORT:0x39a3 */
    /* label BtlUnitsCom @ MEMORY_REPORT:0x4725 */
    /* label LUnitsLeft @ MEMORY_REPORT:0x47b3 */

    /* TODO: implement */
}

void DrawMineralItem(HDC hdc, int16_t x, int16_t y, int16_t iMineral, int32_t l) {
    char   *psz;
    int16_t cch;

    /* TODO: implement */
}

void DrawHistoryReport(HDC hdc) {
    char     szT[100];
    RECT     rcChart;
    uint16_t dYear;
    POINT    pt;
    int16_t  dy;
    int32_t  cYears;
    int32_t  cCur;
    uint16_t iYearBase;
    int16_t  j;
    int16_t  i;
    int16_t  yCur;
    int16_t  cDrawn;
    char    *psz;
    int16_t  dx;
    int32_t  cScaleMax;
    int16_t  xCur;
    int32_t  cInc;
    int16_t  cch;
    RECT     rcDiamond;
    RECT     rc;
    HPEN     hpenSav;
    HPEN     hpen;
    SCOREX  *lpsx;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x2db3 */
    /* block (block) @ MEMORY_REPORT:0x2e41 */

    /* TODO: implement */
}

void DrawScoreReport(HDC hdc) {
    int16_t  dxDig;
    int16_t  yTop;
    POINT    pt;
    int16_t  dx45;
    int16_t  ids;
    COLORREF cr;
    int32_t  lMax;
    int16_t  j;
    int16_t  i;
    int16_t  iPass;
    char    *psz;
    int32_t  lVal;
    int16_t  cch;
    int16_t  xLeft;
    int32_t  l;

    /* TODO: implement */
}

#endif /* _WIN32 */
