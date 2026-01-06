
#include "types.h"

#include "report.h"

/* globals */
uint16_t mpicolgrbitBU[12];  /* MEMORY_REPORT:0x0000 */

/* functions */
int16_t ScoreXDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t i;
    RECT rc;
    uint16_t hdc;
    POINT pt;
    PAINTSTRUCT ps;
    char szT[40];
    int16_t cchHistory;
    char * rgszScan[1];
    int16_t c;
    int32_t rgid[12];
    char *psz;
    int16_t iSel;
    int16_t cch;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x0ff1 */
    /* block (block) @ MEMORY_REPORT:0x1065 */
    /* block (block) @ MEMORY_REPORT:0x10c3 */

    /* TODO: implement */
    return 0;
}

int32_t ReportDlg(uint16_t hwnd, uint16_t msg, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    uint16_t hmenu;
    RECT rc;
    int16_t i;
    uint16_t swp;
    int16_t iCur;
    int16_t idm;
    int16_t dx;
    int16_t cRow;
    POINT pt;
    int16_t iNew;
    int16_t ibit;
    int16_t iCol;
    int16_t iRow;
    int16_t xCur;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x0027 */
    /* block (block) @ MEMORY_REPORT:0x019b */
    /* block (block) @ MEMORY_REPORT:0x0362 */
    /* block (block) @ MEMORY_REPORT:0x04fc */
    /* block (block) @ MEMORY_REPORT:0x067c */
    /* block (block) @ MEMORY_REPORT:0x0788 */
    /* block (block) @ MEMORY_REPORT:0x0818 */
    /* block (block) @ MEMORY_REPORT:0x0860 */

    /* TODO: implement */
    return 0;
}

int16_t PrintMapDlg(uint16_t hwnd, uint16_t msg, uint16_t wParam, int32_t lParam)
{
    int16_t i;
    RECT rc;
    uint16_t hwndEdit;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0xa1d9 */
    /* block (block) @ MEMORY_REPORT:0xa2dc */

    /* TODO: implement */
    return 0;
}

void SetHScrollBar(void)
{
    uint16_t swp;
    int16_t dy;
    int16_t ccolSkipped;
    int16_t ccolHidden;
    int16_t i;
    int16_t ibit;
    int16_t xRight;
    int16_t dx;
    int16_t xTitle;
    RECT rc;

    /* TODO: implement */
}

void SortReportCache(int16_t irpt, int16_t icol)
{
    uint16_t rgidRep[1024];
    PLANET * lpplMac;
    int16_t cRows;
    uint16_t iItem;
    PLANET * lppl;
    FLEET * lpfl;
    int16_t i;

    /* TODO: implement */
}

void InitScoreDlg(uint16_t hwnd, int16_t fVictory)
{
    uint16_t hdc;
    int16_t dxDig;
    int16_t dy;
    int16_t dyFrame;
    int16_t dxFrame;
    RECT rcWindow;
    char *psz;
    int16_t dx;
    RECT rc;

    /* TODO: implement */
}

void ReportColumnPopup(POINT pt, int16_t icol, int16_t fRightBtn)
{
    uint16_t hdc;
    char szT[50];
    char rgsz[32][50];
    int16_t iBase;
    int16_t cSubsort;
    int16_t j;
    int16_t i;
    int16_t ibit;
    int16_t fccolChange;
    int16_t rgcol[32];
    char szColTitle[50];
    int16_t cItems;
    char * psz[1];
    int16_t cch;
    int16_t iRet;
    int16_t iHide;
    int16_t iSortLast;

    /* TODO: implement */
}

int16_t FDestIsWP0(FLEET *lpfl)
{
    int16_t i;
    ORDER ord;

    /* TODO: implement */
    return 0;
}

int16_t ICompReport(void *arg1, void *arg2)
{
    char szT[80];
    int32_t l2;
    int16_t fAscending;
    int16_t icolSort;
    int16_t i1;
    int16_t j;
    int16_t i;
    int32_t l1;
    int16_t iSubsort;
    char *psz;
    int16_t iRet;
    int16_t i2;
    int16_t fTier2;
    int16_t irpt;
    PLANET * lppl2;
    FLEET * lpfl2;
    BTLDATA * lpbd1;
    int16_t ibtl2;
    PLANET * lppl1;
    FLEET * lpfl1;
    int16_t ibtl1;
    int16_t iFirst;
    float pct2;
    int16_t iLast;
    BTLDATA * lpbd2;
    float pct1;
    int32_t rgl[4];

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

void DrawReport(uint16_t hwnd, uint16_t hdc, RECT *prc)
{
    char szTit[40];
    int16_t irowLast;
    int16_t j;
    int16_t i;
    int16_t yRow;
    int16_t ibit;
    int16_t dx;
    int16_t xCol;
    RECT rc;

    /* debug symbols */
    /* label NoHdrDraw @ MEMORY_REPORT:0x0d4e */

    /* TODO: implement */
}

void InvalidateReport(int16_t irpt, int16_t fReload)
{
    int16_t fResetRpt;
    int16_t fClearRpt;
    RPT * prptSav;
    uint16_t * lprgidSav;
    RECT rc;

    /* TODO: implement */
}

void DumpUniverse(void)
{
    int16_t ids;
    int16_t i;
    int16_t env[9];
    int16_t fOpen;
    int16_t fSuccess;
    int16_t fSilentSav;
    int16_t (* penvMemSav)[9];
    int16_t cch;

    /* debug symbols */
    /* label DisplayStatus @ MEMORY_REPORT:0x866b */

    /* TODO: implement */
}

void DumpFleets(void)
{
    int16_t iplr;
    int16_t ids;
    char szFile[256];
    char szForm[256];
    int16_t ifl;
    FLEET * lpfl;
    int16_t j;
    int16_t i;
    int16_t env[9];
    int16_t fOpen;
    int16_t fSuccess;
    int16_t fSilentSav;
    int16_t (* penvMemSav)[9];
    char *psz;
    int16_t cch;
    int32_t l;

    /* debug symbols */
    /* label DisplayStatus @ MEMORY_REPORT:0xa144 */

    /* TODO: implement */
}

int16_t DxReportColHdr(int16_t irpt, int16_t iCol, char *psz, uint16_t hdc)
{
    char szT[40];
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

void DumpPlanets(void)
{
    PLANET * lpplMac;
    int16_t ids;
    PLANET * lppl;
    char szFile[256];
    char szForm[256];
    int16_t j;
    int16_t i;
    int16_t env[9];
    int16_t fOpen;
    int16_t fSuccess;
    int16_t fSilentSav;
    int16_t (* penvMemSav)[9];
    char *psz;
    int16_t cch;
    int32_t l;
    float pct;
    PART part;
    int32_t rgl[4];

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x8ac2 */
    /* block (block) @ MEMORY_REPORT:0x8c01 */
    /* block (block) @ MEMORY_REPORT:0x8e3b */
    /* block (block) @ MEMORY_REPORT:0x9348 */
    /* label DisplayStatus @ MEMORY_REPORT:0x94b2 */

    /* TODO: implement */
}

int32_t LFetchScoreXVal(SCOREX *lpsx, int16_t iVal)
{

    /* TODO: implement */
    return 0;
}

char * PszGetETA(uint16_t hdc, FLEET *lpfl, int16_t *pcYears)
{
    POINT pt;
    int16_t c;
    int16_t i;
    ORDER ord;
    char *psz;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x5339 */
    /* label LNoETA @ MEMORY_REPORT:0x539c */

    /* TODO: implement */
    return NULL;
}

void ExecuteReportClick(POINT pt, int16_t irpt, int16_t icol, int16_t irow)
{
    uint16_t hdc;
    BTLDATA * lpbd;
    PLANET * lppl;
    int16_t i;
    FLEET * lpfl;
    int16_t ibit;
    int32_t rglQuan[4];
    int16_t xCur;
    int16_t dxOffset;
    SCAN scan;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x8328 */
    /* label LShowStarbase @ MEMORY_REPORT:0x7d84 */
    /* label LDisplayVCRAnyway @ MEMORY_REPORT:0x8399 */

    /* TODO: implement */
}

void DrawVCReport(uint16_t hdc)
{
    int16_t grbitVC;
    int16_t xStart;
    int16_t dxDig;
    int16_t yTop;
    POINT pt;
    int16_t cCurSav;
    int16_t ids;
    uint32_t cr;
    int16_t cCur;
    uint16_t hdcMem;
    int16_t j;
    int16_t i;
    int16_t iPass;
    char *psz;
    uint16_t hbmpSav;
    int16_t cch;
    int16_t xLeft;
    int32_t l;
    int16_t idsT;
    int16_t vcVal;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x1c88 */
    /* label LOrIt @ MEMORY_REPORT:0x19f4 */

    /* TODO: implement */
}

void DrawReportItem(uint16_t hdc, RECT *prc, int16_t irpt, int16_t irow, int16_t icol)
{
    BTLDATA * lpbd;
    char szT[100];
    char chT;
    char *lpsz;
    PLANET * lppl;
    int16_t j;
    int16_t i;
    FLEET * lpfl;
    int16_t dx;
    char *psz;
    int16_t xCur;
    int16_t cch;
    int32_t l;
    uint16_t hbr;
    int16_t iItem;
    int16_t fEnough;
    float pct;
    RECT rc;
    int32_t rgl[4];
    PLANET pl;

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

char * PszGetTaskName(FLEET *lpfl, int16_t *picr)
{
    int16_t icr;
    int16_t ids;
    int16_t opOrd;
    int16_t iZip;
    int16_t i;
    ORDER ord;
    int16_t fPercent;
    char *psz;

    /* debug symbols */
    /* label LShowTask @ MEMORY_REPORT:0x54a6 */

    /* TODO: implement */
    return NULL;
}

char * PszGetDestName(FLEET *lpfl, uint16_t hdc)
{
    int16_t i;
    ORDER ord;

    /* debug symbols */
    /* label LDelayed @ MEMORY_REPORT:0x500e */
    /* label LNoDest @ MEMORY_REPORT:0x50a7 */

    /* TODO: implement */
    return NULL;
}

void DrawMineralItem(uint16_t hdc, int16_t x, int16_t y, int16_t iMineral, int32_t l)
{
    char *psz;
    int16_t cch;

    /* TODO: implement */
}

void DrawHistoryReport(uint16_t hdc)
{
    char szT[100];
    RECT rcChart;
    uint16_t dYear;
    POINT pt;
    int16_t dy;
    int32_t cYears;
    int32_t cCur;
    uint16_t iYearBase;
    int16_t j;
    int16_t i;
    int16_t yCur;
    int16_t cDrawn;
    char *psz;
    int16_t dx;
    int32_t cScaleMax;
    int16_t xCur;
    int32_t cInc;
    int16_t cch;
    RECT rcDiamond;
    RECT rc;
    uint16_t hpenSav;
    uint16_t hpen;
    SCOREX * lpsx;

    /* debug symbols */
    /* block (block) @ MEMORY_REPORT:0x2db3 */
    /* block (block) @ MEMORY_REPORT:0x2e41 */

    /* TODO: implement */
}

void DrawScoreReport(uint16_t hdc)
{
    int16_t dxDig;
    int16_t yTop;
    POINT pt;
    int16_t dx45;
    int16_t ids;
    uint32_t cr;
    int32_t lMax;
    int16_t j;
    int16_t i;
    int16_t iPass;
    char *psz;
    int32_t lVal;
    int16_t cch;
    int16_t xLeft;
    int32_t l;

    /* TODO: implement */
}
