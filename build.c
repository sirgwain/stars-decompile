
#include "types.h"

#include "build.h"

/* globals */
uint16_t rghstCat[14];  /* MEMORY_BUILD:0x0000 */
int16_t rgidsCat[14];  /* MEMORY_BUILD:0x001c */
uint16_t rggrbitParts[13];  /* MEMORY_BUILD:0x0038 */
int16_t rgidsParts[13];  /* MEMORY_BUILD:0x0052 */
uint16_t rggrbitPartsSB[8];  /* MEMORY_BUILD:0x006c */
int16_t rgidsPartsSB[8];  /* MEMORY_BUILD:0x007c */

/* functions */
int16_t FCheckQueuedShip(uint16_t hwnd, SHDEF *lpshdef, int16_t fEdit)
{
    char rgch[40];
    int16_t fProgress;
    int16_t id;
    int16_t ids;
    int16_t cshQueued;

    /* TODO: implement */
    return 0;
}

int16_t SlotDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    RECT rcWindow;
    uint16_t hdc;
    RECT rcGBox;
    SHDEF * lpshdef;
    int16_t left;
    PAINTSTRUCT ps;
    uint16_t hwndItem;
    int16_t cch;
    int32_t lSel;
    RECT rc;
    int16_t i;
    int16_t fProgress;
    DRAWITEMSTRUCT * lpdis;
    MEASUREITEMSTRUCT * lpmis;
    POINT pt;
    int16_t fProtoSB;
    int16_t cshQueued;
    int16_t j;
    PART part;

    /* debug symbols */
    /* block (block) @ MEMORY_BUILD:0x07ca */
    /* block (block) @ MEMORY_BUILD:0x0865 */
    /* block (block) @ MEMORY_BUILD:0x0880 */
    /* block (block) @ MEMORY_BUILD:0x08f9 */
    /* block (block) @ MEMORY_BUILD:0x10bd */
    /* block (block) @ MEMORY_BUILD:0x10dc */
    /* block (block) @ MEMORY_BUILD:0x124a */
    /* block (block) @ MEMORY_BUILD:0x14fb */
    /* block (block) @ MEMORY_BUILD:0x17d9 */
    /* block (block) @ MEMORY_BUILD:0x1923 */
    /* block (block) @ MEMORY_BUILD:0x1b02 */
    /* block (block) @ MEMORY_BUILD:0x1bd5 */
    /* block (block) @ MEMORY_BUILD:0x211b */
    /* label LStripDown @ MEMORY_BUILD:0x1938 */
    /* label FixupShip @ MEMORY_BUILD:0x0fdd */
    /* label EditDesign @ MEMORY_BUILD:0x1f67 */
    /* label LRestart @ MEMORY_BUILD:0x0d5b */
    /* label LClearSelection @ MEMORY_BUILD:0x13b0 */

    /* TODO: implement */
    return 0;
}

void DrawDlgLBEntireItem(DRAWITEMSTRUCT *lpdis, int16_t inflate)
{
    uint32_t cr;
    uint32_t crForeSav;
    int16_t ibmp;
    int16_t bkSav;
    RECT rc;

    /* TODO: implement */
}

void KillQueuedMassPackets(PLANET *lppl)
{
    int16_t iprod;
    int16_t iDst;
    PROD * lpprod;

    /* TODO: implement */
}

int16_t IEmptyBmpFromGrhst(int16_t grhst)
{
    int16_t i;

    /* TODO: implement */
    return 0;
}

void DrawBuildSelHull(uint16_t hwnd, uint16_t hdc, int16_t iDraw, RECT *prc)
{
    char rgch[20];
    DV dv;
    uint16_t rgCosts[4];
    int16_t fCreatedDC;
    uint32_t crForeSav;
    int16_t dxMineral;
    int16_t k;
    uint32_t crBackSav;
    int16_t csh;
    HUL * lphul;
    int32_t dpShield;
    int16_t cch;
    int32_t dp;
    int16_t dxkT;
    RECT rc;
    int16_t i;
    int16_t pct;
    int32_t lwt;
    int16_t j;
    int16_t dPlanRange;
    int16_t dRange;
    int16_t pctDetect;

    /* debug symbols */
    /* block (block) @ MEMORY_BUILD:0x49fb */
    /* block (block) @ MEMORY_BUILD:0x4d48 */
    /* block (block) @ MEMORY_BUILD:0x4f17 */
    /* block (block) @ MEMORY_BUILD:0x5263 */
    /* label LReleaseDC @ MEMORY_BUILD:0x53bf */
    /* label LDeadToken @ MEMORY_BUILD:0x5397 */

    /* TODO: implement */
}

int16_t ShipBuilder(POINT ptDlgSize)
{
    int16_t (* lpProcSlot)(void);
    int16_t fSuccess;

    /* TODO: implement */
    return 0;
}

void DrawBuildSelComp(uint16_t hwnd, uint16_t hdc, int16_t iDraw)
{
    uint16_t grhst;
    HS hsShip;
    uint16_t rgCosts[4];
    int16_t fCreatedDC;
    int16_t c;
    int16_t i;
    uint32_t crForeSav;
    int16_t fPlural;
    int16_t k;
    char szWord[80];
    uint32_t crBackSav;
    HS hsHul;
    int16_t cch;
    PART part;
    int16_t x;
    int16_t dxkT;
    RECT rc;
    int16_t iSel;
    char *pch;

    /* debug symbols */
    /* block (block) @ MEMORY_BUILD:0x3b7b */
    /* block (block) @ MEMORY_BUILD:0x3df6 */
    /* label Restore @ MEMORY_BUILD:0x42a4 */
    /* label HullPart @ MEMORY_BUILD:0x3f2b */

    /* TODO: implement */
}

void DrawSlotDlg(uint16_t hwnd, uint16_t hdc, RECT *prc, int16_t iDraw)
{
    int16_t yTop;
    int16_t iMax;
    int16_t cSlot;
    int16_t fCreatedDC;
    uint16_t hdcMem;
    int16_t c;
    int16_t i;
    int16_t bkMode;
    int16_t j;
    int16_t cItem;
    int16_t ibmp;
    uint16_t hbmpSav;
    int16_t xLeft;
    PART part;
    HULDEF * lphuldef;
    RECT rc;
    int16_t iInventSel;
    uint16_t hpenSav;
    uint16_t hbrSav;
    uint32_t crBkSav;

    /* debug symbols */
    /* block (block) @ MEMORY_BUILD:0x286f */
    /* block (block) @ MEMORY_BUILD:0x2e4b */

    /* TODO: implement */
}

void ShowMainControls(uint16_t hwnd, int16_t sw)
{

    /* TODO: implement */
}

void FillBuildDD(uint16_t hwndDD, int16_t md)
{
    int16_t ishdefMac;
    int16_t fProgress;
    int16_t fAdded;
    int16_t i;
    int16_t j;
    SHDEF * lpshdef;
    RECT rc;
    PART part;

    /* TODO: implement */
}

SHDEF * NthValidShdef(int16_t n)
{
    int16_t i;

    /* TODO: implement */
    return NULL;
}

SHDEF * NthValidEnemyShdef(int16_t n)
{
    int16_t i;
    int16_t j;

    /* TODO: implement */
    return NULL;
}

int16_t IDropPart(POINT pt, HS hsSrc, int16_t iSrc, int16_t fNoModify)
{
    int16_t cSlot;
    int16_t cNew;
    int16_t i;
    HS hsHul;
    HS hsDst;
    RECT rc;

    /* TODO: implement */
    return 0;
}

int16_t PctJammerFromHul(HUL *lphul)
{
    int32_t pctJam;
    int16_t ihs;
    int16_t i;
    int32_t pctHit;
    PART part;

    /* TODO: implement */
    return 0;
}

void MakeNewName(char *lpsz)
{
    int16_t cLen;

    /* TODO: implement */
}

void KillQueuedShips(PLANET *lppl)
{
    int16_t iprod;
    int16_t iDst;
    PROD * lpprod;

    /* TODO: implement */
}

void FillBuildPartsLB(uint16_t hwndLB, int16_t grbit)
{
    int16_t mdAvail;
    int16_t i;
    char sz[200];
    int16_t grbitCur;
    PART part;

    /* TODO: implement */
}

int32_t FakeListProc(uint16_t hwnd, uint16_t msg, uint16_t wParam, int32_t lParam)
{
    int16_t iSel;
    POINT pt;

    /* debug symbols */
    /* block (block) @ MEMORY_BUILD:0x676a */
    /* block (block) @ MEMORY_BUILD:0x6813 */

    /* TODO: implement */
    return 0;
}

void UpdateSlotGlobals(void)
{
    int16_t yTop;
    int16_t cSlot;
    int16_t i;
    uint16_t wrc;
    int16_t xLeft;
    HULDEF * lphuldef;

    /* TODO: implement */
}

int16_t FTrackSlot(uint16_t hwnd, int16_t x, int16_t y, int16_t fkb, int16_t fListBox, int16_t fRightBtn)
{
    uint16_t hdc;
    POINT ptOld;
    POINT ptTileSize;
    int16_t ibmpY;
    POINT pt;
    int16_t cSlot;
    int16_t iSrc;
    POINT ptDNew;
    int16_t ibmpX;
    uint16_t hdcMem;
    int16_t i;
    uint16_t hbmpFullSav;
    RECT rcStart;
    int16_t fUseMem;
    uint16_t hbmpScreen;
    int16_t ibmp;
    uint16_t hbmpOld;
    uint16_t hdcMemFull;
    POINT ptD;
    int16_t iSel;
    uint16_t hbmpSav;
    HS hs;
    int16_t fFirst;
    PART part;
    RECT rc;
    int16_t iDir;
    int16_t dyStart;
    int16_t yTop;
    int16_t dxStart;
    int16_t bt;
    BTNT btnt;
    RECT * prc;
    int16_t iBase;
    int16_t iCur;
    int16_t xLeft;

    /* debug symbols */
    /* block (block) @ MEMORY_BUILD:0x3102 */
    /* block (block) @ MEMORY_BUILD:0x3860 */

    /* TODO: implement */
    return 0;
}

void SetBuildSelection(int16_t iSrc)
{
    int16_t iSelOld;
    RECT rc;

    /* debug symbols */
    /* label RedrawSel @ MEMORY_BUILD:0x544c */

    /* TODO: implement */
}
