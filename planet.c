
#include "types.h"

#include "planet.h"

/* functions */
void DrawPlanShip(uint16_t hdc, int16_t grbit)
{
    uint16_t hfontSav;
    OBJ objNull;
    int16_t ctile;
    uint32_t crFore;
    OBJ obj;
    int16_t fMin;
    int16_t i;
    uint32_t crBack;
    int16_t fErase;
    TILE * ptile;
    int16_t fDC;
    RECT rc;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x0e3a */

    /* TODO: implement */
}

int16_t PctCloakFromHuldef(HUL *lphul, int16_t iplr, int16_t *ppctSteal)
{
    int16_t chs;
    HS * lphs;
    int32_t cPts;
    int16_t cScore;
    int16_t j;

    /* TODO: implement */
    return 0;
}

int16_t PctPlanetOptValue(PLANET *lppl, int16_t iPlr)
{
    int16_t rgMax[3];
    int16_t i;
    int16_t rgMin[3];
    int16_t pctDesire;
    int16_t rgCost[3];
    int16_t rgiValSav[3];
    int16_t iNewVal;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x6c50 */

    /* TODO: implement */
    return 0;
}

int16_t IWarpMAFromLppl(PLANET *lppl, int16_t *pfTwo)
{
    int16_t fTwo;
    int16_t iWarp;
    int16_t i;
    HUL * lphul;
    int16_t iNew;

    /* TODO: implement */
    return 0;
}

void DrawPlanetStats(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t dxRight;
    int32_t l2;
    int16_t yTop;
    int16_t xRight;
    int16_t c;
    int16_t cRes;
    int16_t dRangeP;
    float pct;
    int16_t cResAvail;
    int16_t dRange;
    char *psz;
    int16_t xLeft;
    uint16_t hbrSav;
    int32_t l;
    RECT rc;
    PART part;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x1ca1 */
    /* block (block) @ MEMORY_PLANET:0x2034 */

    /* TODO: implement */
}

int16_t FGetBestDefensePart(PART *ppart)
{
    int16_t fRet;
    int16_t i;
    PART part;

    /* TODO: implement */
    return 0;
}

void DrawPlanetShipList(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t swp;
    int16_t fDoneDrawing;
    int32_t l2;
    int16_t yTop;
    int16_t fObjIsThing;
    int16_t fUnknown;
    int16_t idSkip;
    int16_t xStart;
    int16_t xRight;
    int16_t i;
    int16_t c;
    RECT rcGauge;
    XFER xf;
    FLEET * pfl;
    int32_t lSel;
    int16_t xLeft;
    int32_t l;
    RECT rc;

    /* TODO: implement */
}

void DrawPlanetStarbase(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t fTwo;
    int16_t dxRight;
    int16_t iWarp;
    int16_t bt;
    int16_t yTop;
    int16_t xRight;
    int16_t c;
    SHDEF * lpshdef;
    uint32_t crForeSav;
    uint16_t w;
    char *psz;
    int16_t xLeft;
    uint16_t hbrSav;
    int32_t l;
    RECT rc;

    /* TODO: implement */
}

int16_t PctPlanetDesirability(PLANET *lppl, int16_t iPlr)
{
    int16_t iMin;
    int16_t d;
    int16_t iMax;
    int32_t pctNeg;
    int16_t iPref;
    int16_t i;
    int16_t dPenalty;
    int32_t pctPos;
    int16_t pctVar;
    int16_t iPlanet;
    int32_t pctMod;

    /* TODO: implement */
    return 0;
}

void DrawPlanetMinSum(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t dxRight;
    int16_t yTop;
    int16_t xRight;
    int16_t c;
    int16_t i;
    int16_t xLeft;
    uint16_t hbrSav;
    PLANET * ppl;
    RECT rc;

    /* TODO: implement */
}

int16_t CResourcesAtPlanet(PLANET *lppl, int16_t iplr)
{
    int16_t cRes;
    int32_t lPop;
    int16_t cFact;
    int32_t lPopMax;
    int16_t iEff;
    int16_t pctVal;
    int16_t iEnergy;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x7990 */
    /* label LFinishUp @ MEMORY_PLANET:0x7af5 */

    /* TODO: implement */
    return 0;
}

int16_t CMaxOperableDefenses(PLANET *lppl, int16_t iplr, int16_t fNextYear)
{
    int16_t cMax;
    int32_t cCur;
    int32_t lPop;

    /* TODO: implement */
    return 0;
}

char * PszProductionETA(PLANET *lppl, PLPROD *lpplprod, int16_t iItem, int16_t *etaFirst, int16_t *etaLast)
{
    int16_t iTurnEnd;
    int16_t iTurnBegin;
    int16_t c;
    int16_t ids;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x3160 */

    /* TODO: implement */
    return NULL;
}

int16_t FCanTerraformLppl(PLANET *lppl, int16_t *rgEnvMin, int16_t *rgEnvMax, int16_t *rgEnvCost, int16_t fHelp)
{
    int16_t fRet;
    int16_t i;
    int16_t rgMove[3];
    int16_t iPlrSav;
    PART part;
    int16_t dMin;
    int16_t dMax;
    int16_t dCur;
    int16_t ienvIdeal;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x85bd */

    /* TODO: implement */
    return 0;
}

void DrawCBEntireItem(DRAWITEMSTRUCT *lpdis, int16_t inflate)
{
    int16_t fListbox;
    int16_t fSelected;
    RECT rc;

    /* TODO: implement */
}

char * PszCalcEnvVar(int16_t iEnv, int16_t iVar)
{

    /* TODO: implement */
    return NULL;
}

int16_t CMaxOperableFactories(PLANET *lppl, int16_t iplr, int16_t fNextYear)
{
    int16_t cMax;
    int32_t cCur;
    int32_t lPop;
    int16_t iEff;

    /* TODO: implement */
    return 0;
}

int16_t CMaxFactories(PLANET *lppl, int16_t iplr)
{
    int32_t cMax;
    int32_t lPopMax;
    int16_t iEff;

    /* TODO: implement */
    return 0;
}

void DrawMassWarpGauge(uint16_t hdc, RECT *prc, int16_t iBest, int16_t iCur)
{
    int32_t lMax;
    int16_t c;
    int16_t fTwoMAs;
    int16_t iMode;
    uint16_t hbr;
    int32_t lCur;
    int32_t l;

    /* TODO: implement */
}

char * PszCalcGravity(int16_t iGravity)
{
    int16_t d;
    int16_t iVal;

    /* TODO: implement */
    return NULL;
}

int16_t CMaxMines(PLANET *lppl, int16_t iplr)
{
    int32_t cMax;
    int32_t lPopMax;
    int16_t iEff;

    /* TODO: implement */
    return 0;
}

int16_t FProdIsTerra(PROD *lpprod)
{

    /* TODO: implement */
    return 0;
}

int16_t CMaxDefenses(PLANET *lppl, int16_t iplr)
{
    int16_t cMax;
    int16_t pctDesire;

    /* TODO: implement */
    return 0;
}

void DrawPlanetProduction(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t swp;
    int16_t dxRight;
    int16_t yTop;
    int16_t xStart;
    int16_t xRight;
    char szT[40];
    int16_t i;
    int16_t c;
    int16_t dyWrong;
    char *psz;
    int16_t iSel;
    int16_t cch;
    int16_t xLeft;
    RECT rcT;
    PLANET * ppl;
    RECT rc;

    /* TODO: implement */
}

void DrawPlanShipBitmap(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t yTop;
    int16_t dy;
    int16_t xRight;
    int16_t i;
    char *psz;
    int16_t dx;
    int16_t xLeft;
    uint16_t hbrSav;
    int16_t iOffset;
    RECT rc;

    /* debug symbols */
    /* label DoBtns @ MEMORY_PLANET:0x368d */

    /* TODO: implement */
}

int16_t FDrawTileNC(uint16_t hdc, TILE *ptile, RECT *prc, char *pszTitle)
{
    int16_t bt;
    RECT rcT;

    /* debug symbols */
    /* label FinishUp @ MEMORY_PLANET:0x128f */

    /* TODO: implement */
    return 0;
}

int16_t IBestTerraform(PLANET *lppl, int16_t fHelp)
{
    int16_t iSave;
    int16_t iBest;
    int16_t rgMax[3];
    int16_t pctT;
    int16_t i;
    int16_t iPlr;
    int16_t iEnv;
    int16_t pctCur;
    int16_t rgMin[3];
    int16_t rgpctBest[3];
    int16_t rgCost[3];
    int16_t iPlrSav;

    /* TODO: implement */
    return 0;
}

void SetPlanetTitleBar(uint16_t hwnd)
{
    char szTitle[30];
    char *psz;

    /* TODO: implement */
}

void HandleFocusState(DRAWITEMSTRUCT *lpdis, int16_t inflate)
{

    /* TODO: implement */
}

int16_t IpctCanTerraformLppl(PLANET *lppl)
{
    int16_t rgMax[3];
    int16_t i;
    int16_t rgMin[3];
    int16_t rgCost[3];
    int16_t ipct;

    /* TODO: implement */
    return 0;
}

int32_t PlanetWndProc(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    PAINTSTRUCT ps;
    XFER xf;
    int16_t i;
    char *psz;
    int32_t lSel;
    RECT rc;
    POINT pt;
    DRAWITEMSTRUCT * lpdis;
    MEASUREITEMSTRUCT * lpmis;
    PLANET * lpplMac;
    uint16_t hcs;
    PLANET * lppl;
    FLEET * lpfl;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x05a2 */
    /* block (block) @ MEMORY_PLANET:0x065b */
    /* block (block) @ MEMORY_PLANET:0x0705 */
    /* block (block) @ MEMORY_PLANET:0x073c */
    /* block (block) @ MEMORY_PLANET:0x0b44 */
    /* label LRefocus @ MEMORY_PLANET:0x0941 */
    /* label Default @ MEMORY_PLANET:0x0c77 */

    /* TODO: implement */
    return 0;
}

int16_t IdFindAdjStarbase(int16_t idPlanet, int16_t fNext)
{
    PLANET * lpplMac;
    int16_t idLast;
    int16_t idFirst;
    PLANET * lppl;
    int16_t idAfter;
    int16_t idBefore;

    /* TODO: implement */
    return 0;
}

int32_t CalcPlanetMaxPop(int16_t idpl, int16_t iplr)
{
    PLANET pl;
    int32_t lMaxPop;
    int32_t pctDesire;
    int16_t ihuldef;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x70ce */

    /* TODO: implement */
    return 0;
}

void FillShipDD(int16_t idSkip)
{
    THING * lpthMac;
    int16_t i;
    THING * lpth;
    FLEET * lpfl;
    POINT ptSel;

    /* TODO: implement */
}

void ChangeMainObjSel(int16_t grobjNew, int16_t iObjSel)
{
    int16_t fSameType;
    int16_t idSkip;
    int16_t i;
    FLEET * lpfl;

    /* TODO: implement */
}

void DrawProductionItem(uint16_t hdc, RECT *prc, char *psz, int16_t inflate, int16_t fSelected, int16_t fListbox)
{
    uint16_t hfntSav;
    char *pch;
    int16_t ichT;
    uint32_t cr;
    int16_t pctDmg;
    char szT[20];
    RECT rcIn;
    int16_t ich;
    int16_t fDoubleDraw;
    uint32_t crForeSav;
    int16_t fFleet;
    RECT rcDraw;
    int16_t dx;
    uint16_t hbr;
    int16_t fItalic;
    int16_t cch;
    int16_t bkSav;
    RECT rc;

    /* debug symbols */
    /* label LDefCase @ MEMORY_PLANET:0x6269 */
    /* label LDefCaseSel @ MEMORY_PLANET:0x6337 */
    /* label LRightOut @ MEMORY_PLANET:0x6657 */

    /* TODO: implement */
}

void UninhabitPlanet(PLANET *lppl)
{
    int16_t i;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x876c */

    /* TODO: implement */
}

int16_t StargateRangeFromLppl(PLANET *lppl, int16_t iplr, int16_t ish)
{
    int16_t i;
    HUL * lphul;
    PART part;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x7e3b */

    /* TODO: implement */
    return 0;
}

void FillPlanetProdLB(uint16_t hwnd, PLPROD *lpplprod, PLANET *lppl)
{
    int16_t fMinimal;
    int32_t rgwtMin[4];
    int16_t i;
    int16_t cItem;
    char szTemp[80];
    int32_t resCost;
    char *psz;
    char ch;
    PROD * lpprod;
    int16_t etaLast;
    int16_t etaFirst;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x6831 */
    /* label NoMsg @ MEMORY_PLANET:0x67a8 */

    /* TODO: implement */
}

void EnsureTileSize(int16_t fSmallTiles)
{
    int16_t iMul;
    int16_t i;
    int16_t grobjSav;

    /* TODO: implement */
}

uint16_t ClickInPlanetOrders(POINT pt, int16_t sks, int16_t fCursor, int16_t fRightBtn)
{
    int16_t i;
    int32_t rglQuan[3];
    int16_t iWarp;
    BTNT btnt;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x55c5 */
    /* block (block) @ MEMORY_PLANET:0x5715 */
    /* block (block) @ MEMORY_PLANET:0x57e4 */

    /* TODO: implement */
    return 0;
}

int16_t CMaxOperableMines(PLANET *lppl, int16_t iplr, int16_t fNextYear)
{
    int16_t cMax;
    int32_t cCur;
    int32_t lPop;
    int16_t iEff;

    /* TODO: implement */
    return 0;
}

int16_t CMinesOperating(PLANET *lppl)
{
    int16_t iplr;
    int16_t cMinesOp;
    int16_t cMines;

    /* TODO: implement */
    return 0;
}

void PlanetClick(int16_t x, int16_t y, int16_t sks, int16_t fRightBtn)
{
    int16_t bt;
    POINT pt;
    int16_t ctile;
    int16_t dy;
    RECT rcTitle;
    int16_t i;
    int16_t xRel;
    uint16_t iCol;
    int16_t iCur;
    TILE * prgtile;
    RECT rc;
    uint16_t hdc;
    TILE tile;
    POINT ptNew;
    BTNT btnt;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x4a90 */
    /* block (block) @ MEMORY_PLANET:0x4bb8 */

    /* TODO: implement */
}

int16_t PctPlanetCapacity(PLANET *lppl)
{
    int32_t pctCap;
    int32_t lPopMax;

    /* TODO: implement */
    return 0;
}

void SelectAdjPlanet(int16_t dInc, int16_t idPlanet)
{
    PLANET * lpPlT;
    int16_t i;
    PLANET * lpPl;
    SCAN scan;
    int16_t fWrap;

    /* debug symbols */
    /* label FinishUp @ MEMORY_PLANET:0x46f3 */

    /* TODO: implement */
}

void ReflowColumn(int16_t iCol, int16_t iTile, int16_t fRedraw)
{
    uint16_t hdc;
    int16_t yTop;
    int16_t ctile;
    int16_t i;
    int16_t grbit;
    TILE * ptile;
    RECT rc;

    /* TODO: implement */
}

int16_t CFactoriesOperating(PLANET *lppl)
{
    int16_t iplr;
    int16_t cFacts;
    int16_t cFactsOp;

    /* TODO: implement */
    return 0;
}
