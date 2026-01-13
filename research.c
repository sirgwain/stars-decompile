
#include "types.h"
#include "globals.h"

#include "research.h"
#include "parts.h"

/* globals */
uint16_t rggrbitBrParts[17] = {0x19ff, 0x0008, 0x0010, 0x0040, 0x0800, 0x0001, 0x1000, 0x0100, 0x0080, 0x0200, 0x8000, 0x0002, 0x0004, 0x4000, 0x0400, 0x2000, 0x0020};
int32_t rglTechCost[27] = {0, 50, 80, 130, 210, 340, 550, 890, 1440, 2330, 3770, 6100, 9870, 13850, 18040, 22440, 27050, 31870, 36900, 42140, 47590, 53250, 59120, 65200, 71490, 77990, 84700};

/* functions */
int32_t CostOfDevelopingItem(char *rgTech)
{
    int32_t lSpent;
    char *pTech;
    char rgTechSav[6];
    int32_t lCost;
    int16_t fUnreachable;
    int16_t i;
    int32_t lCur;

    /* TODO: implement */
    return 0;
}

int32_t GetTechLevelCost(int16_t iTech, int16_t iLevel, int16_t iplr)
{
    int32_t lCost;
    int16_t i;
    int16_t cTech;

    /* TODO: implement */
    return 0;
}

int32_t ProjectedResearchSpending(int32_t pct)
{
    int32_t lRes;
    PLANET *lppl;
    int16_t cRes;
    int32_t lSpend;
    PLANET *lpplMac;
    char pctSav;
    int16_t cBogus;

    /* TODO: implement */
    return 0;
}

int16_t FShouldPartBeHidden(PART *ppart)
{
    int16_t iItem;
    uint16_t grbitTrader;

    if (idPlayer == -1)
        return false; // no player context => don't block here

    iItem = ppart->hs.iItem;
    const uint16_t grhst = ppart->hs.grhst;

    unsigned required_mask = grbitTraderNone;

    switch (grhst)
    {
    case hstBomb:
        // Hush-A-Boom
        if (iItem == ibombHushABoom)
            required_mask = grbitTraderBomb;
        break;

    case hstTorp:
        // Anti-Matter Torpedo
        if (iItem == itorpAntiMatterTorpedo)
            required_mask = grbitTraderTorp;
        break;

    case hstEngine:
        // Enigma Pulsar
        if (iItem == iengineEnigmaPulsar)
            required_mask = grbitTraderEngine;
        break;

    case hstShield:
        // Langston Shell
        if (iItem == ishieldLangstonShell)
            required_mask = grbitTraderShield;
        break;

    case hstArmor:
        // Mega Poly Shell
        if (iItem == iarmorMegaPolyShell)
            required_mask = grbitTraderArmor;
        break;

    case hstBeam:
        // Multi-Contained Munition
        if (iItem == ibeamMultiContainedMunition)
            required_mask = grbitTraderBeam;
        break;

    case hstMining:
        // Alien Miner
        if (iItem == iminingAlienMiner)
            required_mask = grbitTraderMiner;
        break;

    case hstSpecialE:
        // Multi-Function Pod
        if (iItem == ispecialEMultiFunctionPod)
            required_mask = grbitTraderSpecial;
        break;

    case hstSpecialM:
        // Multi Cargo Pod or Jump Gate
        if (iItem == ispecialMMultiCargoPod)
            required_mask = grbitTraderCargo;
        else if (iItem == ispecialMJumpGate)
            required_mask = grbitTraderJumpgate;
        break;

    case hstHull:
        // Mini Morph hull needs a hull trader perk in the original code.
        if (iItem == ihuldefMiniMorph)
            required_mask = grbitTraderHull;
        break;

    case hstPlanetary:
        // Genesis Device
        if (iItem == iplanetaryGenesisDevice)
            required_mask = grbitTraderGenesis;
        break;

    default:
        break;
    }

    if (required_mask != grbitTraderNone)
    {
        // Same field the original used (rgplr[idPlayer].grbitTrader)
        const unsigned grbitTrader = *(const unsigned *)((const char *)&rgplr[0].grbitTrader + idPlayer * 0xC0);

        // If the needed perk bit is not set, this component is blocked
        if ((grbitTrader & required_mask) == 0)
            return true;
    }

    return false;
}

#ifdef _WIN32

INT_PTR CALLBACK ResearchDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc;
    int16_t y;
    int16_t i;
    PAINTSTRUCT ps;
    int16_t dx;
    RECT rc;
    int16_t iResTechNext;
    HWND hwndRad;
    POINT pt;
    int16_t fChg;
    int16_t dxCurrent;
    PLANET *lppl;
    int16_t c;
    PLANET *lpplMac;
    uint16_t hfontSav;
    char *psz;
    RECT rcWindow;

    /* debug symbols */
    /* block (block) @ MEMORY_RESEARCH:0x000f */
    /* block (block) @ MEMORY_RESEARCH:0x05a3 */
    /* block (block) @ MEMORY_RESEARCH:0x06c4 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK BrowserDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc;
    uint16_t hmenu;
    int16_t i;
    int16_t c;
    PAINTSTRUCT ps;
    uint16_t hfontSav;
    int16_t dx;
    RECT rc;
    HWND hwndDD;
    int16_t fAllHsts;
    int32_t lSel;
    uint16_t iItemStart;
    int16_t md;
    int16_t fShowAll;
    int16_t iStart;
    int16_t cIter;
    int16_t iOff;

    /* debug symbols */
    /* block (block) @ MEMORY_RESEARCH:0x1ee7 */
    /* block (block) @ MEMORY_RESEARCH:0x2453 */
    /* block (block) @ MEMORY_RESEARCH:0x2586 */
    /* label Top @ MEMORY_RESEARCH:0x2675 */
    /* label NullItem @ MEMORY_RESEARCH:0x280e */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK BrowserWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc;
    POINT pt;
    int16_t i;
    PAINTSTRUCT ps;
    RECT rc;

    /* debug symbols */
    /* label Validate @ MEMORY_RESEARCH:0x2939 */
    /* label Default @ MEMORY_RESEARCH:0x2a6f */

    /* TODO: implement */
    return 0;
}

int16_t FTrackResearchDlg(HWND hwnd, int16_t x, int16_t y, int16_t fkb)
{
    int16_t bt;
    POINT pt;
    int16_t dChg;
    int16_t i;
    int16_t cNew;
    RECT *prc;
    BTNT btnt;
    RECT rc;

    /* TODO: implement */
    return 0;
}

void DrawResearchDlg(HWND hwnd, HDC hdc, RECT *prc, int16_t grbitDraw)
{
    int16_t dxCurrent;
    char szTemp[60];
    RECT rcT;
    int16_t iMax;
    int16_t iTechSav;
    int16_t iter;
    int16_t fCreatedDC;
    int16_t mdAvail;
    int16_t i;
    int16_t c;
    int16_t grbitCur;
    COLORREF crBackSav;
    COLORREF crForeSav;
    uint16_t hfontSav;
    int16_t xNum;
    int16_t xCtr;
    int16_t dx;
    char szTemp2[60];
    PART part;
    int32_t l;
    int16_t iMin;
    RECT rc;
    HBRUSH hbrSav;
    int16_t cch;
    int32_t lSpent;
    int32_t lRBEffective;

    /* debug symbols */
    /* block (block) @ MEMORY_RESEARCH:0x0fdf */
    /* block (block) @ MEMORY_RESEARCH:0x10c9 */
    /* block (block) @ MEMORY_RESEARCH:0x1374 */
    /* block (block) @ MEMORY_RESEARCH:0x190b */
    /* label TooManyToFinish @ MEMORY_RESEARCH:0x0ea6 */
    /* label CleanUp @ MEMORY_RESEARCH:0x1a4a */
    /* label DrawResourceAlloc @ MEMORY_RESEARCH:0x1509 */
    /* label DrawYearComplete @ MEMORY_RESEARCH:0x12c8 */
    /* label PrintYear @ MEMORY_RESEARCH:0x13e9 */
    /* label DrawAnnualRes @ MEMORY_RESEARCH:0x158d */
    /* label DrawTotalSpent @ MEMORY_RESEARCH:0x160a */
    /* label DrawBudget @ MEMORY_RESEARCH:0x169b */
    /* label DrawRightSide @ MEMORY_RESEARCH:0x0ee3 */
    /* label DrawComingAttractions @ MEMORY_RESEARCH:0x0b92 */
    /* label DrawResPct @ MEMORY_RESEARCH:0x171b */
    /* label DrawProjBudg @ MEMORY_RESEARCH:0x1831 */
    /* label DrawProjBudgData @ MEMORY_RESEARCH:0x1888 */

    /* TODO: implement */
}

void DisplayComponentInfo(HDC hdc, int16_t dx, int16_t dy, PART *ppart)
{
    uint16_t rgCosts[4];
    int16_t idsT;
    int16_t ids;
    int16_t dxStr;
    int16_t c;
    int16_t yText;
    int16_t i;
    int16_t yCur;
    int16_t fReq;
    int16_t yStart;
    int16_t xNum;
    int16_t xText;
    RECT rcData;
    int32_t l;
    int16_t dxT;
    char rgch[2];
    int16_t dmgMin;
    int16_t dyPct;
    int16_t dmgShipRam;
    int16_t dxDigit;
    int16_t pct;
    int16_t iWarp;
    int16_t yBase;
    char *psz;
    int16_t dmgShip;
    RECT rcT;
    int16_t y;
    int16_t pctHit;
    int16_t dxWarp;
    int16_t dxLabel;
    int16_t dmgMinRam;
    int16_t fWarp10;
    int16_t iEff;
    COLORREF crFore;
    int16_t cch;
    int16_t x;
    uint16_t hpenSav;
    int16_t pctT;
    COLORREF crBack;
    HBRUSH hbrSav;
    char szT[256];
    int16_t dyText;
    int16_t dmgFloor;
    int32_t lpct;
    int16_t xBase;
    int16_t dxQuan;
    char ch;
    int32_t ldelta;

    /* debug symbols */
    /* block (block) @ MEMORY_RESEARCH:0x34c6 */
    /* block (block) @ MEMORY_RESEARCH:0x37b1 */
    /* block (block) @ MEMORY_RESEARCH:0x39ed */
    /* block (block) @ MEMORY_RESEARCH:0x3aeb */
    /* block (block) @ MEMORY_RESEARCH:0x3c94 */
    /* block (block) @ MEMORY_RESEARCH:0x3fc2 */
    /* block (block) @ MEMORY_RESEARCH:0x40d6 */
    /* block (block) @ MEMORY_RESEARCH:0x43e7 */
    /* block (block) @ MEMORY_RESEARCH:0x4518 */
    /* block (block) @ MEMORY_RESEARCH:0x4686 */
    /* block (block) @ MEMORY_RESEARCH:0x4a2f */
    /* block (block) @ MEMORY_RESEARCH:0x4cc8 */
    /* block (block) @ MEMORY_RESEARCH:0x57fe */
    /* block (block) @ MEMORY_RESEARCH:0x5c6d */
    /* block (block) @ MEMORY_RESEARCH:0x5d93 */
    /* block (block) @ MEMORY_RESEARCH:0x5df4 */
    /* block (block) @ MEMORY_RESEARCH:0x64dd */
    /* label PrintSpecial @ MEMORY_RESEARCH:0x5183 */
    /* label LShieldDisp @ MEMORY_RESEARCH:0x449b */
    /* label LArmDisp @ MEMORY_RESEARCH:0x45cc */

    /* TODO: implement */
}

#endif /* _WIN32 */
