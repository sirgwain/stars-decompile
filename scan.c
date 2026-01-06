
#include "types.h"

#include "scan.h"

/* globals */
int16_t vrgPopRad[19];  /* MEMORY_SCAN:0x0000 */
uint32_t rgcrScanMine[3];  /* MEMORY_SCAN:0x0026 */

/* functions */
int16_t FindDlg(uint16_t hwnd, uint16_t msg, uint16_t wParam, int32_t lParam)
{
    char szName[40];
    RECT rc;

    /* TODO: implement */
    return 0;
}

void DrawScannerSBar(uint16_t hdc, RECT *prc, SBAR *psbar, int16_t fFullRedraw)
{
    int16_t fhdc;
    uint32_t crText;
    POINT pt2;
    int16_t id;
    POINT pt;
    int16_t grReal;
    int16_t iBkPrev;
    int16_t c;
    uint32_t crBk;
    int16_t dxHole;
    uint16_t hfontSav;
    RECT rcClip;
    char *psz;
    uint16_t hbrSav;
    int16_t fDoName;
    int32_t l;
    int16_t grobj;
    RECT rcT;
    RECT rc;
    char szBuf[100];

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x69a6 */
    /* label GotCoords @ MEMORY_SCAN:0x6602 */
    /* label DrawTheName @ MEMORY_SCAN:0x66d7 */

    /* TODO: implement */
}

void DrawRadarCircle(DRAWCIR *pdc, RECT *prc)
{
    int16_t y2;
    int32_t r2;
    uint32_t crSav;
    int16_t dy;
    int16_t y;
    int16_t iFree;
    int16_t i;
    int16_t dx;
    int16_t x2;
    int16_t rad;
    int32_t l;
    int16_t x;
    RECT rc;

    /* debug symbols */
    /* label DrawEllipse @ MEMORY_SCAN:0x5002 */
    /* label L2ndEl @ MEMORY_SCAN:0x5316 */

    /* TODO: implement */
}

int32_t ScannerWndProc(uint16_t hwnd, uint16_t msg, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    POINT pt;
    PAINTSTRUCT ps;
    RECT rc;
    int16_t iScanNew;
    int16_t d;
    uint16_t hpenSav;
    int16_t dy;
    int16_t dx;
    int16_t iRopSav;
    int16_t i;
    uint32_t tick;
    PLANET plT;
    int16_t fChgScan;
    SCAN scan;
    int16_t c;
    THING * lpth;
    FLEET * lpfl;
    int16_t fSep;
    int32_t rgid[100];
    int16_t iChecked;
    int16_t iSel;
    THING * lpthMac;
    int16_t id;

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x0068 */
    /* block (block) @ MEMORY_SCAN:0x007a */
    /* block (block) @ MEMORY_SCAN:0x0126 */
    /* block (block) @ MEMORY_SCAN:0x03e6 */
    /* block (block) @ MEMORY_SCAN:0x06cf */
    /* block (block) @ MEMORY_SCAN:0x0955 */
    /* block (block) @ MEMORY_SCAN:0x0d47 */
    /* block (block) @ MEMORY_SCAN:0x0dd5 */
    /* block (block) @ MEMORY_SCAN:0x0e21 */
    /* label Default @ MEMORY_SCAN:0x0e6d */
    /* label DblClick @ MEMORY_SCAN:0x0c42 */

    /* TODO: implement */
    return 0;
}

int16_t IWarpBestForWaypoint(FLEET *lpfl, ORDER *lpord)
{
    int32_t lFuel;
    int16_t iWarp;
    int16_t cTravel;
    int16_t iwp;
    int16_t lDist;
    int16_t cSpeed;
    int16_t fGoFlatOutAi;
    int16_t fGoFlatOut;
    int16_t iWarpAi;
    int16_t iWarpSav;
    int16_t j;
    int16_t i;
    PLANET * lppl;
    int16_t iWarpOld;
    SCAN scan;

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x7afd */
    /* block (block) @ MEMORY_SCAN:0x7c4f */
    /* label LTryLimitedSpeed @ MEMORY_SCAN:0x7e27 */
    /* label LOptimizeSpeed @ MEMORY_SCAN:0x7f83 */
    /* label LDecWarp @ MEMORY_SCAN:0x7f39 */

    /* TODO: implement */
    return 0;
}

void SetScanScrollBars(uint16_t hwnd)
{
    int16_t xMax;
    int16_t dy;
    int16_t yMax;
    int16_t dx;
    RECT rc;

    /* TODO: implement */
}

int32_t CShipsScanVis(FLEET *lpfl)
{
    int16_t j;
    int32_t csh;
    int16_t k;
    uint16_t grbitSh;

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x4cd9 */
    /* block (block) @ MEMORY_SCAN:0x4d6c */

    /* TODO: implement */
    return 0;
}

void DrawShipScanPath(uint16_t hdc, int16_t fShow)
{
    ORDER * lpord2;
    int16_t rgDup[87];
    int16_t j;
    uint16_t hpenSav;
    POINT pt2;
    POINT pt;
    int16_t iRopSav;
    int16_t dy;
    ORDER * lpord1;
    POINT ptCur;
    FLEET * lpfl;
    int16_t i;
    int16_t fHdc;
    int32_t lWarp2;
    int16_t dRad;
    int16_t dx;
    RECT rc;
    int16_t id;
    THING * lpth;
    int16_t fDoneRoute;
    double dAngle;
    POINT rgptArrow[2];
    int16_t dx5;
    POINT ptTick;
    int16_t dy5;
    double m;

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x54c6 */
    /* block (block) @ MEMORY_SCAN:0x5691 */
    /* block (block) @ MEMORY_SCAN:0x5c94 */
    /* label LNextCheck @ MEMORY_SCAN:0x5623 */
    /* label LCommonLineCode @ MEMORY_SCAN:0x56f9 */
    /* label LNoObjPath @ MEMORY_SCAN:0x5c8a */
    /* label LDrawPath @ MEMORY_SCAN:0x5cd8 */
    /* label LFinishUp @ MEMORY_SCAN:0x62bc */
    /* label DoNext @ MEMORY_SCAN:0x5f8f */

    /* TODO: implement */
}

void GetScanFleetOrientation(FLEET *lpfl, POINT *ppt, POINT *pptD)
{
    int16_t dy;
    int16_t dx;

    /* debug symbols */
    /* label NoInfo @ MEMORY_SCAN:0x97cf */

    /* TODO: implement */
}

int16_t PtToScan(int16_t d)
{

    /* TODO: implement */
    return 0;
}

int16_t ScanToPt(int16_t d)
{

    /* TODO: implement */
    return 0;
}

int16_t SetScanWp(int16_t iNew)
{
    SCAN scan;

    /* TODO: implement */
    return 0;
}

int16_t FAddWayPoint(POINT ptIn, SCAN *pscan)
{
    uint16_t hdc;
    int16_t id;
    int16_t dy;
    ORDER * lpord;
    int16_t lDist;
    POINT rgpt[3];
    int16_t dx;
    int16_t cpt;
    int16_t ipt;
    RECT rc;

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x79b9 */

    /* TODO: implement */
    return 0;
}

int16_t FSelectSz(char *szName)
{
    char *pch;
    int16_t ifl;
    FLEET * lpfl;
    int16_t ipl;
    int16_t cch;
    char szT[20];
    int16_t iplPartial;
    SCAN scan;

    /* debug symbols */
    /* label GoWithPartial @ MEMORY_SCAN:0x94ef */
    /* label LNotAFleetId @ MEMORY_SCAN:0x96ff */
    /* label LFoundFleetId @ MEMORY_SCAN:0x9689 */

    /* TODO: implement */
    return 0;
}

void GetDxDyOrientation(int16_t dx, int16_t dy, POINT *ppt, POINT *pptD)
{
    double dbl;
    int16_t iBmp;

    /* debug symbols */
    /* label LFinishUp @ MEMORY_SCAN:0x9925 */

    /* TODO: implement */
}

void ScanToLogical(POINT *ppt)
{

    /* TODO: implement */
}

void DrawLockLight(uint16_t hdc, RECT *prc, int16_t fFullRedraw)
{
    int16_t dy;
    int16_t dx;
    RECT rc;

    /* TODO: implement */
}

int16_t FGetNextObjHere(SCAN *pscan, int16_t fOnlyOurs)
{
    FLEET * lpfl;
    int16_t i;
    int16_t fFound;

    /* TODO: implement */
    return 0;
}

int16_t FHandleMeasuringTape(SCAN *pscan, POINT pt)
{
    uint16_t hdc;
    uint16_t hpenSav;
    SBAR sbar;
    POINT ptLogLast;
    int16_t grTypeIn;
    POINT ptLogical;
    POINT ptBase;
    int16_t iropSav;
    POINT ptNew;
    char szT[20];
    int16_t fVirgin;
    SCAN scan;
    RECT rc;

    /* TODO: implement */
    return 0;
}

int16_t FEnsurePointOnScreen(POINT pt, int16_t fScroll)
{
    int16_t cy;
    int16_t fFix;
    int16_t cx;
    POINT ptCtr;
    RECT rc;

    /* TODO: implement */
    return 0;
}

void ChangeScanSel(SCAN *pscan, int16_t fValidScan)
{
    int16_t fMineFieldSel;
    RECT rcMine;
    int16_t fChgWp;
    int16_t iRad;
    uint16_t hdc;

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x8d78 */
    /* block (block) @ MEMORY_SCAN:0x8f11 */
    /* block (block) @ MEMORY_SCAN:0x8f7d */
    /* block (block) @ MEMORY_SCAN:0x9032 */

    /* TODO: implement */
}

void RedrawScanSel(uint16_t hdc, int16_t fVis)
{
    int16_t sel_grobj;
    int16_t fhdc;
    int16_t dOff;
    POINT pt;
    int16_t sel_id;
    int16_t fNoSelRedraw;
    SCAN sel_scan;
    RECT rc;
    int16_t sel_grobjFull;

    /* TODO: implement */
}

int16_t FHandleWayPointDrag(POINT pt)
{
    int16_t fChg;
    uint16_t hdc;
    uint16_t hpenSav;
    SBAR sbar;
    int16_t fMarker;
    char szDeepSpace[40];
    int16_t fDup;
    int16_t grTypeIn;
    uint16_t hcurSav;
    ORDER * lpord;
    int16_t i;
    POINT ptLogical;
    POINT ptNext;
    int16_t fDel;
    POINT rgpt[4];
    POINT ptNew;
    int16_t cpt;
    POINT ptPrev;
    SCAN scan;
    int16_t fFirst;
    RECT rc;

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x8a9f */
    /* label DoNext @ MEMORY_SCAN:0x8559 */
    /* label Done @ MEMORY_SCAN:0x8a7c */

    /* TODO: implement */
    return 0;
}

void LogicalToScan(POINT *ppt)
{

    /* TODO: implement */
}

int16_t FNearAWayPoint(POINT pt, int16_t fLogical)
{
    ORDER * lpord;
    int16_t i;
    SCAN scan;

    /* TODO: implement */
    return 0;
}

void ScrollScanner(int16_t dx, int16_t dy)
{
    uint16_t hdc;
    RECT rcUpd;
    RECT rcUpd2;
    RECT rc;

    /* debug symbols */
    /* label RelDC @ MEMORY_SCAN:0x6f1e */

    /* TODO: implement */
}

void DrawScanFleetCount(FLEET *lpfl, int16_t x, int16_t y, uint16_t hdc, uint16_t hdcMem)
{
    int32_t l2;
    int16_t f999;
    uint32_t cr;
    FLEET * lpflWalk;
    int16_t iPlr;
    uint16_t hbmpSav;
    int32_t l;

    /* TODO: implement */
}

int16_t DrawScanner(uint16_t hdc, RECT *prc)
{
    int16_t xOff;
    int16_t dExpand;
    uint16_t hpenSav;
    FLEET * lpflT;
    int16_t j;
    int16_t yTop;
    int16_t xMax;
    POINT pt;
    int16_t id;
    uint32_t crFore;
    int16_t iBkPrev;
    POINT ptD;
    PLANET * lpplMac;
    int16_t yBmp;
    int16_t dy;
    uint16_t hbmpXSav;
    uint16_t hbmpScreen;
    int16_t id2;
    uint16_t hdcScreen;
    PLANET * lppl;
    int16_t yMax;
    char rgWhatsHere[999];
    uint16_t hdcMem;
    THING * lpth;
    FLEET * lpfl;
    int16_t i;
    int16_t xMin;
    uint16_t hbmpSav;
    int16_t iord;
    RECT rcClip;
    int16_t yOff;
    RECT rcDraw;
    int16_t dRange;
    int16_t idP;
    POINT ptO;
    int16_t fSelected;
    int16_t fMA;
    int16_t fStarbase;
    POINT ptSelMain;
    THING * lpthMac;
    int16_t fStargate;
    uint16_t mdScanBase;
    int16_t yMin;
    int16_t dx;
    uint16_t hbrSav;
    int16_t xLeft;
    int16_t fDoDraw;
    POINT ptOrigin;
    RECT rc;
    int32_t l;
    uint32_t crBack;
    int16_t fTerra;
    int16_t iOff;
    int16_t iRel;
    POINT pt2;
    int16_t dRad;
    uint32_t cr;
    int16_t pctDesire;
    int16_t xOut;
    THING * lpthDest;
    uint16_t hbr;
    int16_t fConc;
    int16_t yOut;
    int32_t lPop;
    uint16_t hbmpTrSav;
    int16_t rgy[250];
    int16_t fPlanetScanner;
    int16_t ropSav;
    int16_t rgx[250];
    int16_t rgrad[250];
    DRAWCIR dc;
    int16_t dPlanRange;
    int16_t dThingRange;
    int16_t fDetonating;

    /* debug symbols */
    /* block (block) @ MEMORY_SCAN:0x14c6 */
    /* block (block) @ MEMORY_SCAN:0x157a */
    /* block (block) @ MEMORY_SCAN:0x16d2 */
    /* block (block) @ MEMORY_SCAN:0x1894 */
    /* block (block) @ MEMORY_SCAN:0x19ff */
    /* block (block) @ MEMORY_SCAN:0x1b3a */
    /* block (block) @ MEMORY_SCAN:0x1f26 */
    /* block (block) @ MEMORY_SCAN:0x2057 */
    /* block (block) @ MEMORY_SCAN:0x25ee */
    /* block (block) @ MEMORY_SCAN:0x2813 */
    /* block (block) @ MEMORY_SCAN:0x33e4 */
    /* block (block) @ MEMORY_SCAN:0x3609 */
    /* block (block) @ MEMORY_SCAN:0x3759 */
    /* block (block) @ MEMORY_SCAN:0x3a09 */
    /* block (block) @ MEMORY_SCAN:0x4505 */
    /* label LNormalScannerMode @ MEMORY_SCAN:0x3bd8 */
    /* label LBailIn @ MEMORY_SCAN:0x2e4b */

    /* TODO: implement */
    return 0;
}

void CtrPointScan(POINT pt, int16_t fScroll)
{
    int16_t dxCur;
    int16_t cy;
    int16_t y;
    int16_t cx;
    int16_t dyCur;
    int16_t x;
    RECT rc;

    /* TODO: implement */
}

void DrawScanXorLines(uint16_t hdc, POINT *rgpt, int16_t cpt)
{
    uint16_t hpenSav;
    int16_t iRopSav;
    int16_t i;
    RECT rc;

    /* TODO: implement */
}
