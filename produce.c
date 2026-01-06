
#include "types.h"

#include "produce.h"

/* functions */
void ProdCommandHandler(uint16_t hwnd, uint16_t wParam, int32_t lParam)
{
    int32_t lSel;
    int16_t iSrc;
    uint16_t hwndLB;
    int16_t c;
    int16_t iDst;
    PROD prodLast;
    int16_t ipl;
    int16_t fRefillSrc;
    int16_t iMac;
    RECT rc;
    PROD * lpprod;
    PROD prod;
    int16_t cMax;
    PLPROD * lpplprodT;

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x28cd */
    /* label RingItUp @ MEMORY_PRODUCE:0x1dc4 */
    /* label FixedUp @ MEMORY_PRODUCE:0x215e */
    /* label RedrawText @ MEMORY_PRODUCE:0x2e12 */
    /* label RemoveItem @ MEMORY_PRODUCE:0x21ec */
    /* label AddItem @ MEMORY_PRODUCE:0x19a3 */

    /* TODO: implement */
}

int16_t ChangeProduction(int16_t fClear)
{
    int16_t env[9];
    int16_t (* penvMemSav)[9];
    int16_t (* lpProcProd)(void);
    PROD rgprod[64];
    int16_t fSuccess;

    /* debug symbols */
    /* label LWriteProdQ @ MEMORY_PRODUCE:0x011b */

    /* TODO: implement */
    return 0;
}

void EnableZipProdBtns(uint16_t hwnd, int16_t iSel)
{
    int16_t fEnabled;

    /* TODO: implement */
}

int16_t ProductionDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    PAINTSTRUCT ps;
    RECT rc;
    int16_t dxPBtn;
    int16_t dy;
    DRAWITEMSTRUCT * lpdis;
    MEASUREITEMSTRUCT * lpmis;
    POINT pt;
    int16_t cMax;
    uint16_t hcs;
    char sz255[2];
    int16_t i;
    RECT rcT;
    int16_t xCtr;
    int16_t dx;
    int16_t dyLB;
    char * rgszZip[1];
    int16_t rgidProdBtns[10];
    ZIPPRODQ rgzp[4];
    int16_t (* lpProc)(void);
    int16_t fRet;

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x1213 */
    /* block (block) @ MEMORY_PRODUCE:0x1563 */
    /* block (block) @ MEMORY_PRODUCE:0x15d4 */
    /* block (block) @ MEMORY_PRODUCE:0x166f */
    /* block (block) @ MEMORY_PRODUCE:0x16e9 */
    /* block (block) @ MEMORY_PRODUCE:0x17a3 */
    /* block (block) @ MEMORY_PRODUCE:0x1881 */

    /* TODO: implement */
    return 0;
}

int16_t ZipProdDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    PAINTSTRUCT ps;
    int16_t i;
    int16_t iBase;
    RECT rc;
    int16_t dy;
    int16_t (* lpProc)(void);
    char *psz;
    RECT rcGBox;
    char *pszT;
    RECT rc2;
    int16_t cch;
    int16_t cpq;
    uint16_t hwndRad;

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x549f */
    /* block (block) @ MEMORY_PRODUCE:0x55b4 */
    /* block (block) @ MEMORY_PRODUCE:0x571a */
    /* block (block) @ MEMORY_PRODUCE:0x5967 */
    /* block (block) @ MEMORY_PRODUCE:0x5a07 */
    /* block (block) @ MEMORY_PRODUCE:0x5abb */
    /* label LDontRename @ MEMORY_PRODUCE:0x5ab1 */

    /* TODO: implement */
    return 0;
}

void FillProdSrcLB(uint16_t hwndLB, int16_t mdFill)
{
    char szT[80];
    int16_t i;
    char *psz;

    /* TODO: implement */
}

char * PszNameProdItem(PROD *lpprod)
{
    uint32_t iItem;
    int16_t iDelta;

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x3d94 */
    /* label LBogus @ MEMORY_PRODUCE:0x3d3b */

    /* TODO: implement */
    return NULL;
}

void EstimateItemProdSched(PLANET *lppl, PLPROD *lpplprod, int16_t iItem, int16_t *piFirst, int16_t *piLast)
{
    int32_t cResearch;
    PLANET pl;
    int32_t rglQuan[3];
    int16_t cBuilt;
    PROD prodPartial;
    int16_t mdStatus;
    int16_t i;
    int16_t j;
    int16_t iPass;
    int16_t fAlchemy;
    int16_t iMac;
    int32_t rgRes[4];
    PROD * lpprod;

    /* debug symbols */
    /* label LCleanUp @ MEMORY_PRODUCE:0x5469 */

    /* TODO: implement */
}

void DrawProductionDlg(uint16_t hwnd, uint16_t hdc, RECT *prc, int16_t iDraw)
{
    int32_t lSel;
    int16_t iSrc;
    int16_t idc;
    int16_t fCreatedDC;
    int16_t i;
    int16_t c;
    int32_t rgCost[4];
    int16_t dxkT;
    int16_t k;
    RECT rc;
    PROD prod;
    char szT[100];

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x3964 */

    /* TODO: implement */
}

void FinishProduction(int16_t fWrite)
{

    /* TODO: implement */
}

void GetProductionCosts(PLANET *lppl, PROD *lpprod, uint32_t *rgCost, int16_t iplr, int16_t fOnlyOne)
{
    uint16_t rgCostsCur[4];
    uint32_t iItem;
    uint16_t rgCosts[4];
    int16_t i;
    int16_t j;
    SHDEF * lpshdef;
    int16_t raMajor;
    uint32_t cItem;
    int16_t fStarbase;
    PART part;
    int16_t cost;
    int16_t chs;
    HUL * lphulNew;
    HUL * lphulCur;
    int16_t costUpg;
    int16_t costHalf;
    HUL * lphulT;
    int16_t rgCostsPartCur[4];
    int16_t rgCostsPartNew[4];

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x40a4 */
    /* block (block) @ MEMORY_PRODUCE:0x4111 */
    /* block (block) @ MEMORY_PRODUCE:0x418e */

    /* TODO: implement */
}

void InitializeProductionDlg(uint16_t hwnd)
{
    char rgch[86];
    int16_t i;
    int16_t iSel;
    PROD * lpprod;

    /* TODO: implement */
}

void FillZipProdLB(uint16_t hwndDlg, ZIPPRODQ *pzpq)
{
    int16_t i;
    uint16_t hwndLB;
    char szAuto[40];
    char szFormat[15];
    RECT rc;

    /* TODO: implement */
}

void InitProduction(PROD *rgprod)
{
    int16_t iWarp;
    int16_t iSrc;
    uint16_t u;
    int16_t i;
    int16_t ipl;
    PART part;
    PROD * lpprod;

    /* TODO: implement */
}
