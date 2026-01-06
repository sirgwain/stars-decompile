
#include "types.h"

#include "race.h"
#include "util.h"
#include "parts.h"
#include "ship.h"

extern GDATA gd;

/* functions */
void UpdateOrdersDDs(int16_t iLevel)
{
    int32_t rglSel[3];
    int16_t iMin;
    int16_t i;
    char *psz;
    int16_t iSel;
    int16_t iMax;
    char szT[80];

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x9496 */
    /* block (block) @ MEMORY_SHIP:0x969e */
    /* label DoMinerals @ MEMORY_SHIP:0x946b */

    /* TODO: implement */
}

void SetFleetDropDownSel(int16_t id)
{
    int16_t idSkip;
    int16_t i;
    FLEET * lpfl;
    int16_t iOffset;

    /* TODO: implement */
}

int32_t GetFuelFree(FLEET *lpfl)
{

    /* TODO: implement */
    return 0;
}

void ShipCommandProc(uint16_t hwnd, uint16_t wParam, int32_t lParam)
{
    int16_t fPercent;
    int16_t (* lpProc)(void);
    int32_t lSel;
    XFER xf;
    char szT[34];
    int32_t lMin;
    int16_t ishdef;
    int16_t grbit;
    int16_t ifl;
    int16_t ish;
    FLEET * lpfl;
    char rgb[8];
    int16_t ishPrimary;
    int16_t i;
    int16_t iInit;
    FLEET * lpflBest;
    int16_t rgifl[512];

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x2a13 */
    /* block (block) @ MEMORY_SHIP:0x2e7c */
    /* block (block) @ MEMORY_SHIP:0x2f05 */
    /* block (block) @ MEMORY_SHIP:0x3505 */
    /* block (block) @ MEMORY_SHIP:0x3b00 */

    /* TODO: implement */
}

void DrawShipOrders(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t swp;
    int16_t dxRight;
    int16_t iWarp;
    int16_t yTop;
    POINT pt;
    RECT rcT;
    int16_t dWrong;
    int32_t lTot;
    int16_t c;
    FLEET * pfl;
    int16_t xRight;
    int16_t iScanActual;
    RECT rcGauge;
    char *psz;
    int16_t xLeft;
    ORDER ord;
    int32_t l;
    RECT rc;

    /* debug symbols */
    /* label DoDistance @ MEMORY_SHIP:0x04aa */
    /* label DoCheckBox @ MEMORY_SHIP:0x0884 */

    /* TODO: implement */
}

int32_t GetCargoFree(FLEET *lpfl)
{
    int32_t cHave;
    int16_t i;

    /* TODO: implement */
    return 0;
}

int32_t XferSupply(int16_t iSupply, int32_t cQuan)
{
    int16_t iSrc;
    int32_t dChg;
    int32_t cAvailable;

    /* TODO: implement */
    return 0;
}

void DrawFleetGauge(uint16_t hdc, RECT *prc, FLEET *lpfl, int16_t grbit)
{
    uint16_t rghbr[5];
    int32_t lMax;
    int16_t c;
    int16_t i;
    int32_t rgSize[5];
    int16_t iMode;
    int16_t cSections;
    int32_t l;

    /* TODO: implement */
}

int16_t CshQueued(int16_t ishdef, int16_t *pfProgress, int16_t fSpaceDocks)
{
    int16_t iprod;
    PLANET * lppl;
    int16_t csh;
    PLANET * lpplMac;
    PROD * lpprod;

    /* TODO: implement */
    return 0;
}

int32_t LGetFleetStat(FLEET *lpfl, int16_t grStat)
{
    int16_t i;
    int32_t l;

    /* TODO: implement */
    return 0;
}

void FillBattleDD(int16_t iSel)
{
    int16_t i;

    /* TODO: implement */
}

int16_t FCanSplitAll(int32_t cBoat)
{

    /* TODO: implement */
    return 0;
}

int32_t EstFuelUse(FLEET *lpfl, int16_t iOrd, int16_t iWarp, int32_t dTravel, int16_t fRangeOnly)
{
    int32_t iEffNext;
    int32_t lT;
    int16_t fEfficient;
    double d;
    int32_t iEffCur;
    int32_t wtCargoT;
    int32_t lFuel;
    ORDER * lpord;
    int16_t i;
    SHDEF * lpshdef;
    int32_t wtCargo;
    int16_t j;
    int32_t wtMass;
    int32_t rgieff[16];

    if (lpfl == NULL || lpfl->lpplord == NULL) {
        return 0;
    }

    /* Clear the "radiating engine" flag bit (set later if needed). */
    gd.fRadiatingEngine = 0;

    /* If warp not provided, use the next waypoint's warp setting. */
    if (iWarp == -1) {
        if (iOrd + 1 < lpfl->lpplord->iordMac) {
            iWarp = (int16_t)lpfl->lpplord->rgord[iOrd + 1].iWarp;
        } else {
            iWarp = 0;
        }
    }

    /*
     * Race attribute bit 0 is used here as an efficiency toggle in the
     * original code path.
     */
    fEfficient = GetRaceGrbit(&rgplr[lpfl->iPlayer], 0);

    /* Build per-design "efficiency" values (engine fuel use at this warp). */
    {
        SHDEF *base = rglpshdef[lpfl->iPlayer];
        for (i = 0; i < 16; i++) {
            if (lpfl->rgcsh[i] <= 0) {
                rgieff[i] = 0;
                continue;
            }

            lpshdef = (SHDEF *)((uint8_t *)base + (int32_t)i * 0x93);

            /* Find the first non-destroyed hull slot (status != 1). */
            for (j = 0; j < (int16_t)lpshdef->hul.chs; j++) {
                if (lpshdef->hul.rghs[j].grhst != 1) {
                    break;
                }
            }

            /* If no usable engine slot, treat as "very inefficient". */
            if (j >= (int16_t)lpshdef->hul.chs) {
                rgieff[i] = 99999;
                continue;
            }

            /* Use the engine in slot j. */
            {
                uint8_t engineId = (uint8_t)lpshdef->hul.rghs[j].iItem;
                ENGINE *lpeng = LpengineFromId(engineId);

                /* Engine fuel use table is indexed by warp (0..11). */
                int32_t eff = (int32_t)lpeng->rgcFuelUsed[iWarp];

                /* Apply the "efficient" race bonus (15% reduction). */
                if (fEfficient) {
                    eff -= (eff * 15) / 100;
                }

                rgieff[i] = eff;

                /* Engine id 10 toggles the global radiating-engine flag. */
                if (engineId == 10) {
                    gd.fRadiatingEngine = 1;
                }
            }
        }
    }

    /* Sum cargo weight (first 4 cargo buckets; the 5th is fuel). */
    wtCargo = 0;
    for (i = 0; i < 4; i++) {
        wtCargo += lpfl->rgwtMin[i];
    }

    /* Determine travel distance if requested. */
    if (dTravel == -1) {
        if (fRangeOnly == 0) {
            if (iOrd + 1 < lpfl->lpplord->iordMac) {
                lpord = &lpfl->lpplord->rgord[iOrd];
                dTravel = (int32_t)(DGetDistance(lpord[0].pt.x, lpord[0].pt.y,
                                                     lpord[1].pt.x, lpord[1].pt.y) + 0.0);
            } else {
                dTravel = 0;
            }
        } else {
            /* Range-only mode uses a fixed nominal distance. */
            dTravel = 1000;
        }
    }

    /*
     * Original algorithm processes ship designs by increasing efficiency
     * buckets, allocating cargo as it goes.
     */
    lFuel = 0;
    iEffCur = 0;
    while (1) {
        iEffNext = 0x000f423f; /* 999999 as a sentinel "none" */

        for (i = 0; i < 16; i++) {
            int16_t csh = lpfl->rgcsh[i];
            if (csh <= 0) {
                continue;
            }

            if (rgieff[i] == iEffCur) {
                /* Cargo allocation for this design. */
                int16_t capPerShip = WtMaxShdefStat((SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)i * 0x93), 2);
                int32_t capTotal = (int32_t)csh * (int32_t)capPerShip;
                wtCargoT = (wtCargo < capTotal) ? wtCargo : capTotal;
                wtCargo -= wtCargoT;

                /* Empty mass = count * wtEmpty. */
                wtMass = wtCargoT + (int32_t)csh * (int32_t)((SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)i * 0x93))->hul.wtEmpty;

                /* lT = iEffCur * dTravel (32-bit signed in original helpers). */
                lT = (int32_t)((int64_t)iEffCur * (int64_t)dTravel);

                /* Fuel used is roughly wtMass*lT/2000 (with float fallback in Win16). */
                if (wtMass <= 0 || lT <= 0) {
                    /* no-op */
                } else {
                    int64_t num = (int64_t)wtMass * (int64_t)lT;
                    int32_t add;

                    /* Preserve the original "use double when huge" behavior, but
                     * still compute with correct math.
                     */
                    if (num > (int64_t)INT32_MAX * 2000LL) {
                        d = ((double)wtMass * (double)lT) / 2000.0;
                        add = (int32_t)d;
                    } else {
                        add = (int32_t)(num / 2000LL);
                    }

                    lFuel += add;
                }
            } else if (rgieff[i] > iEffCur) {
                if (rgieff[i] < iEffNext) {
                    iEffNext = rgieff[i];
                }
            }
        }

        if (iEffNext == 0x000f423f) {
            break;
        }
        iEffCur = iEffNext;
    }

    /* Convert internal 1/10 units to whole fuel units. */
    if (fRangeOnly == 0) {
        lFuel += 9;
    }
    lFuel = lFuel / 10;

    if (fRangeOnly != 0) {
        /* Range = (fuel_on_board * 1000) / fuel_per_1000_distance. */
        if (lFuel == 0) {
            return (int32_t)0xca00; /* "infinite" sentinel used by original */
        }

        if (lFuel < 100001) {
            int64_t num = (int64_t)lpfl->rgwtMin[4] * 1000LL;
            return (int32_t)(num / (int64_t)lFuel);
        }

        /* Avoid overflow by scaling fuel use first (mirrors original). */
        {
            int32_t scaled = lFuel / 1000;
            if (scaled <= 0) {
                return (int32_t)0xca00;
            }
            return lpfl->rgwtMin[4] / scaled;
        }
    }

    return lFuel;
}

void DeleteCurWayPoint(int16_t fBackup)
{
    POINT pt;
    POINT rgpt[3];
    int16_t cpt;
    SCAN scan;
    int16_t ipt;
    RECT rc;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x9dce */

    /* TODO: implement */
}

void DrawFleetCargoXferSide(uint16_t hdc, RECT *prc, FLEET *pfl, int16_t iSupply)
{
    int16_t yTop;
    int16_t fOtherPlr;
    int16_t c;
    int16_t i;
    int16_t xRight;
    FLEET fl;
    int16_t dxLabels;
    RECT rcGauge;
    int16_t xLeft;
    RECT rc;
    int16_t iMap;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x74a2 */

    /* TODO: implement */
}

int32_t FakeEditProc(uint16_t hwnd, uint16_t msg, uint16_t wParam, int32_t lParam)
{

    /* TODO: implement */
    return 0;
}

int16_t TransferStuff(int16_t id1, int16_t grobj1, int16_t id2, int16_t grobj2, int16_t mdXfer)
{
    XFER xfer[2];
    int16_t (* lpProcXfer)(void);
    int16_t rgValidHull[16];
    int32_t lPopPrev;
    int16_t iDelFleet;
    int16_t i;
    FLEET * lpfl;
    int16_t fSuccess;
    int16_t grbit;
    int16_t j;
    BTN rgbtn[32];
    POINT pt;
    RECT rc;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x55c8 */
    /* label CancelSplit @ MEMORY_SHIP:0x5654 */
    /* label LInvalScanPlan @ MEMORY_SHIP:0x55c8 */

    /* TODO: implement */
    return 0;
}

void DrawThingXferSide(uint16_t hdc, RECT *prc, THING *pth, int16_t iSupply)
{
    int16_t yTop;
    int16_t i;
    int16_t xRight;
    int16_t dxLabels;
    RECT rcGauge;
    int16_t xLeft;
    RECT rc;

    /* TODO: implement */
}

void DrawShipWayPtOrders(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t dxKt;
    int16_t dxT;
    int16_t swp;
    int16_t dxRight;
    int16_t yTop;
    int16_t yTopMsg;
    int16_t ids;
    int16_t edWid;
    PLANET * lppl;
    ORDER * lpord;
    FLEET * pfl;
    int16_t i;
    int16_t fActive;
    int16_t xRight;
    uint16_t grtask;
    char szT[8];
    int16_t yBot;
    int16_t dxRight2;
    char *psz;
    int16_t cch;
    int16_t xLeft;
    int32_t l;
    RECT rc;
    char *pszT;
    int16_t j;
    int32_t cMine;
    RECT rcT;
    int16_t dyCur;
    int16_t c;
    int32_t rgl[4];

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x0d93 */
    /* block (block) @ MEMORY_SHIP:0x0dfa */
    /* block (block) @ MEMORY_SHIP:0x1324 */
    /* block (block) @ MEMORY_SHIP:0x1363 */
    /* block (block) @ MEMORY_SHIP:0x153c */
    /* block (block) @ MEMORY_SHIP:0x15b7 */
    /* label LDisplayMsg2 @ MEMORY_SHIP:0x14af */
    /* label FoundColony @ MEMORY_SHIP:0x146f */
    /* label ShowString @ MEMORY_SHIP:0x172b */
    /* label DoneMine @ MEMORY_SHIP:0x179f */
    /* label LDisplayMsg @ MEMORY_SHIP:0x14a1 */

    /* TODO: implement */
}

void Merge2Fleets(FLEET *lpflDst, FLEET *lpflDel, int16_t fNoDelete)
{
    FLEET rgfl[2];
    int16_t i;

    /* TODO: implement */
}

int16_t TransferDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    int16_t dyMore;
    PAINTSTRUCT ps;
    POINT pt;
    uint16_t hwndBtn;
    RECT rcBtn;
    int16_t dx;
    RECT rc;

    /* TODO: implement */
    return 0;
}

void DrawXferDlg(uint16_t hwnd, uint16_t hdc, RECT *prc, int16_t iSupply)
{
    RECT rgrc[2];
    int16_t fCreatedDC;
    int16_t i;
    int16_t dxCtr;

    /* debug symbols */
    /* label RelDC @ MEMORY_SHIP:0x6b2b */

    /* TODO: implement */
}

void DrawFleetShipsXferSide(uint16_t hdc, RECT *prc, FLEET *pfl, int16_t iSupply)
{
    int16_t yTop;
    int16_t fOtherPlr;
    int16_t c;
    int16_t i;
    int16_t xRight;
    FLEET fl;
    int16_t xLeft;
    RECT rc;

    /* TODO: implement */
}

void DrawShipPlanet(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t yTop;
    int16_t dy;
    int16_t i;
    int16_t xRight;
    char *psz;
    int16_t dx;
    int16_t xLeft;
    RECT rc;
    THING * lpth;
    THING * lpthMac;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x1923 */

    /* TODO: implement */
}

void DrawFleetComp(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int32_t cBoat;
    int16_t swp;
    int16_t dxRight;
    int16_t yTop;
    RECT rcT;
    int16_t dyWrong;
    int16_t c;
    int16_t i;
    FLEET * pfl;
    int16_t xStart;
    int16_t xRight;
    int16_t dxLabel;
    int16_t xLeft;
    int32_t l;
    RECT rc;

    /* TODO: implement */
}

void FleetTransferCargoBalance(FLEET *pflNew1, FLEET *pflNew2)
{
    int16_t iplr;
    int32_t rgCargoCapLoss[2];
    int32_t wtCargoXfer;
    int16_t fDeadFleet;
    int32_t wtCargoTot;
    int16_t rgrgcshLoss[2][16];
    int32_t rgrgCargoDelta[2][5];
    int32_t rgFuelCapacity[2];
    FLEET * rgpflNew[1];
    int16_t wtCargoMax;
    int16_t wtFuelMax;
    int16_t i;
    int32_t lChg;
    int32_t rgFuelCapLoss[2];
    FLEET rgflCur[2];
    int16_t j;
    SHDEF * lpshdef;
    int32_t rgCargoCapacity[2];
    int16_t ishdef;
    int32_t l;
    int32_t cshDmgDst;
    int32_t cshDmgSrc;
    int16_t iSrc;
    int32_t pctNew;
    int32_t cshDmgMoved;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0xb227 */
    /* block (block) @ MEMORY_SHIP:0xb3c2 */
    /* block (block) @ MEMORY_SHIP:0xb81c */
    /* block (block) @ MEMORY_SHIP:0xbb73 */

    /* TODO: implement */
}

void SetOrdersLbSel(int16_t iSel)
{

    /* TODO: implement */
}

void SelectAdjFleet(int16_t dInc, int16_t idFleet)
{
    POINT pt;
    int16_t idOld;
    int16_t i;
    FLEET * lpfl;
    int16_t idNew;
    FLEET * lpflT;
    SCAN scan;

    /* debug symbols */
    /* label FinishUp @ MEMORY_SHIP:0x3fa9 */

    /* TODO: implement */
}

int16_t IFindIdealWarp(FLEET *lpfl, int16_t fIgnoreScoops)
{
    int16_t i;
    int16_t j;
    int16_t iWorst;
    ENGINE * lpengine;

    /* TODO: implement */
    return 0;
}

void DrawPlanetXferSide(uint16_t hdc, RECT *prc, PLANET *ppl, int16_t iSupply)
{
    PLANET pl;
    int16_t yTop;
    int16_t c;
    int16_t i;
    int16_t xRight;
    char *psz;
    int16_t xLeft;
    RECT rc;

    /* TODO: implement */
}

void DeleteWpFar(FLEET *lpfl, int16_t iDel, int16_t fRecycle)
{
    ORDER ord;

    /* TODO: implement */
}

int32_t ChgCargo(int16_t grobj, int16_t id, int16_t iSupply, int32_t dChg, void *pobj)
{
    THING * pth;
    XFER xfer;
    int16_t i;
    FLEET * pfl;
    PLANET * ppl;
    int32_t wtFree;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x61db */

    /* TODO: implement */
    return 0;
}

int16_t FTrackXfer(uint16_t hwnd, int16_t x, int16_t y, int16_t fkb)
{
    POINT ptOld;
    POINT pt;
    int32_t dChg;
    BTNT btnt;
    int32_t cCur;
    int16_t i;
    int16_t iBtn;
    int16_t iVal;
    BTN btn;
    int32_t cNew;
    RECT rc;

    /* debug symbols */
    /* label FinishUp @ MEMORY_SHIP:0x5f70 */

    /* TODO: implement */
    return 0;
}

int16_t FCanSplit(int32_t cBoat)
{

    /* TODO: implement */
    return 0;
}

int16_t FCanMerge(FLEET *pfl)
{
    int16_t i;
    FLEET * lpfl;
    int32_t csh;
    int16_t cfl;
    int16_t ishdef;

    /* TODO: implement */
    return 0;
}

void FillFleetCompLB(void)
{
    int16_t i;
    int32_t pctDmg;

    /* TODO: implement */
}

uint16_t ClickInShipOrders(POINT pt, int16_t sks, int16_t fCursor, int16_t fRightBtn)
{
    int32_t lCur;
    uint16_t hdc;
    PLANET pl;
    int16_t iWarp;
    POINT ptOld;
    int16_t idPlan;
    int32_t lMax;
    int32_t lSel;
    int16_t iSkip;
    int32_t xRnd;
    int16_t grbit;
    XFER xf;
    int32_t lNew;
    int16_t irc;
    int32_t dx;
    int32_t lTempMin;
    int16_t fFirst;
    int16_t fTwoMAs;
    int32_t lTempMax;
    int16_t cMax;
    int16_t fSep;
    char sz255[2];
    int16_t i;
    THING * lpth;
    int16_t c;
    THING * lpthMac;
    ORDER * lpord;
    FLEET * lpfl;
    char * rgszZip[1];
    TASKXPORT * lptxp;
    ZIPORDER rgzo[4];
    int16_t (* lpProc)(void);
    int16_t fRet;
    int32_t rgid[100];
    int16_t iChecked;
    SCAN scan;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x7d37 */
    /* block (block) @ MEMORY_SHIP:0x7e50 */
    /* block (block) @ MEMORY_SHIP:0x7f96 */
    /* block (block) @ MEMORY_SHIP:0x826c */
    /* block (block) @ MEMORY_SHIP:0x894f */
    /* block (block) @ MEMORY_SHIP:0x8a3b */
    /* label LWriteZip @ MEMORY_SHIP:0x81f0 */
    /* label FixMinWin @ MEMORY_SHIP:0x9006 */

    /* TODO: implement */
    return 0;
}

void DestroyAllIshdef(int16_t ishdef, int16_t iplr)
{
    FLEET flDead;
    int16_t cKill;
    FLEET * lpfl;
    int16_t i;
    int16_t grbit;
    int16_t j;
    int16_t cDel;
    FLEET flNew;

    /* debug symbols */
    /* label IncrementI @ MEMORY_SHIP:0xc5b8 */

    /* TODO: implement */
}

int16_t WtMaxShdefStat(SHDEF *lpshdef, int16_t grStat)
{
    int16_t wt;
    int16_t j;
    HUL * lphul;

    if (lpshdef == NULL) {
        return 0;
    }

    /* Base stats come from the hull definition. */
    {
        HULDEF *lphuldef = LphuldefFromId(lpshdef->hul.ihuldef);
        if (lphuldef == NULL) {
            return 0;
        }
        lphul = &lphuldef->hul;
    }

    if (grStat == 1) {
        /* Fuel capacity. */
        wt = lphul->wtFuelMax;

        /* Add-ons from certain hull slots. */
        for (j = 0; j < (int16_t)lpshdef->hul.chs; j++) {
            HS *hs = &lpshdef->hul.rghs[j];
            if (hs->grhst == 0x1000) {
                if (hs->iItem == 5) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 250);
                } else if (hs->iItem == 6) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 500);
                }
            } else if (hs->grhst == 0x0800) {
                if (hs->iItem == 0x10) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 200);
                }
            }
        }
        return wt;
    }

    if (grStat == 2) {
        /* Cargo capacity. */
        wt = lphul->wtCargoMax;

        for (j = 0; j < (int16_t)lpshdef->hul.chs; j++) {
            HS *hs = &lpshdef->hul.rghs[j];
            if (hs->grhst == 0x1000) {
                if (hs->iItem == 2) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 50);
                } else if (hs->iItem == 3) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 100);
                } else if (hs->iItem == 4) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 250);
                }
            }
        }
        return wt;
    }

    return 0;
}

int16_t FEnumCalcJettison(void *lprt, int16_t rt, int16_t cb, PLANET *lppl, int16_t iFleet)
{
    POINT pt;
    int16_t i;
    int16_t grbit;
    FLEET fl;
    int16_t j;
    RTXFERX * prtxferx;
    RTXFER * prtxfer;

    /* TODO: implement */
    return 0;
}

void UpdateXferBtns(void)
{
    int16_t iSide;
    int16_t i;
    int16_t iLastButton;
    int16_t iVal;
    int32_t lLeft;

    /* TODO: implement */
}

int16_t FSetupXferBtns(RECT *prc)
{
    int16_t cBtn;
    int16_t iMax;
    int16_t dy;
    int16_t iMin;
    int16_t i;
    int16_t fThingXfer;
    int16_t j;
    int16_t dxCtr;
    RECT rcRight;
    int16_t dxLabels;
    RECT rcBtn;
    RECT rcLeft;
    RECT rc;

    /* debug symbols */
    /* label NoGauges @ MEMORY_SHIP:0x7070 */

    /* TODO: implement */
    return 0;
}

void DrawFleetBitmap(FLEET *lpfl, uint16_t hdc, int16_t x, int16_t y, int16_t fFrame, int16_t ibmp, int16_t cDiff, int16_t fShrink, int16_t ibmpRace, int16_t csh)
{
    int16_t dxyPlus;
    int16_t yCur;
    int16_t c;
    int16_t i;
    int16_t dxy;
    int16_t dx;
    int16_t xCur;
    int16_t dxyPlusWidth;
    uint16_t hbrSav;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x4920 */

    /* TODO: implement */
}

void DestroyAllIshdefSB(int16_t ishdefSB, int16_t iplr)
{
    PLANET * lppl;
    PLANET * lpplMac;

    /* TODO: implement */
}

void GetTruePartCost(int16_t iPlayer, PART *ppart, uint16_t *rgCost)
{
    int16_t cExcess;
    int16_t cCur;
    int16_t i;
    COMPART * lpcom;

    /* debug symbols */
    /* label LOtherDiddles @ MEMORY_SHIP:0xcf99 */

    /* TODO: implement */
}

void RemoveIshdefFromAllQueues(int16_t ishdef, int16_t fSpaceDocks)
{
    int16_t iprod;
    PLANET * lppl;
    int16_t iDst;
    PLANET * lpplMac;
    PROD * lpprod;

    /* TODO: implement */
}

void DrawShipCargo(uint16_t hdc, TILE *ptile, OBJ obj)
{
    int16_t dxRight;
    int32_t l2;
    int16_t yTop;
    int16_t i;
    int16_t c;
    FLEET * pfl;
    int16_t xRight;
    RECT rcGauge;
    int16_t xLeft;
    int32_t l;
    RECT rc;

    /* TODO: implement */
}

void FillOrdersLB(void)
{
    int16_t i;
    char *psz;
    ORDER ord;

    /* TODO: implement */
}

int32_t LFuelUseToWaypoint(FLEET *lpfl, int16_t iwp, int16_t fMaxCargo)
{
    int32_t lCur;
    int16_t iWarp;
    int16_t dist;
    PLANET * lppl;
    int16_t i;
    int32_t lTot;
    ORDER * lpord;
    int16_t cYears;
    SHDEF * lpshdef;
    int16_t j;
    double dbl;
    int32_t l;
    int32_t lOneYearUse;
    int32_t lFuelGain;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0xab6d */

    (void)fMaxCargo; /* not used by the original logic in this build */

    if (lpfl == NULL || lpfl->lpplord == NULL) {
        return 0;
    }

    lTot = 0;    /* max running total */
    lCur = 0;    /* current running total */

    /*
     * Sum fuel required leg-by-leg up to (but not including) waypoint iwp,
     * tracking the maximum running total (worst case) and resetting at friendly
     * starbases that can refuel.
     */
    for (i = 0; i < iwp; i++) {
        int32_t legUse = 0;
        int32_t minUse = 0;

        /* Warp is stored on the destination waypoint. */
        lpord = &lpfl->lpplord->rgord[i];
        iWarp = (int16_t)lpord[1].iWarp;

        if (iWarp <= 0 || iWarp > 10) {
            cYears = 1;
            dist = 0;
            legUse = 0;
        } else {
            /* Distance between waypoints (integer). */
            dbl = DGetDistance(lpord[0].pt.x, lpord[0].pt.y, lpord[1].pt.x, lpord[1].pt.y);
            dist = (int16_t)dbl;

            /* Years required at this warp: ceil(dist / (warp*warp)). */
            {
                int32_t w2 = (int32_t)iWarp * (int32_t)iWarp;
                if (w2 <= 0) {
                    cYears = 1;
                } else {
                    cYears = (int16_t)((dist + w2 - 1) / w2);
                    if (cYears < 1) {
                        cYears = 1;
                    }
                }
            }

            /* Fuel for a one-year (single-step) move. */
            minUse = EstFuelUse(lpfl, i, iWarp, -1, 0);
            legUse = minUse;
        }

        if (cYears > 1) {
            /* Fuel for a full year's travel at this warp (distance = warp^2). */
            int32_t w2 = (int32_t)iWarp * (int32_t)iWarp;
            lOneYearUse = EstFuelUse(lpfl, i, iWarp, w2, 0);

            /* Total for (cYears-1) full years plus remainder distance. */
            {
                int32_t fullYears = (int32_t)(cYears - 1);
                int32_t rem = (int32_t)dist - w2 * fullYears;
                if (rem < 0) {
                    rem = 0;
                }
                legUse = (int32_t)((int64_t)lOneYearUse * (int64_t)fullYears);
                legUse += EstFuelUse(lpfl, i, iWarp, rem, 0);
            }

            /* Ensure we never estimate less than the basic one-year use. */
            if (legUse < minUse) {
                legUse = minUse;
            }

            /* Potential fuel gain from ram scoops (and certain tanker hulls). */
            lFuelGain = LCalcFuelGainFromRamScoops(lpfl, iWarp, w2);
            for (j = 0; j < 16; j++) {
                int16_t csh = lpfl->rgcsh[j];
                if (csh <= 0) {
                    continue;
                }
                lpshdef = (SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)j * 0x93);
                if (lpshdef->hul.ihuldef == 0x19 || lpshdef->hul.ihuldef == 0x1a) {
                    /* Tankers add a fixed "gain" per ship (200 in original). */
                    lFuelGain += (int32_t)csh * 200;
                }
            }

            /* If gains reduce per-year usage, apply to the full-years portion. */
            if (lFuelGain > 0 && lFuelGain < lOneYearUse) {
                int32_t fullYears = (int32_t)(cYears - 1);
                int32_t reducedYear = lOneYearUse - lFuelGain;
                int32_t alt = (int32_t)((int64_t)reducedYear * (int64_t)fullYears) + lOneYearUse;
                if (alt < legUse) {
                    legUse = alt;
                }
            }
        }

        lCur += legUse;
        if (lCur > lTot) {
            lTot = lCur;
        }

        /* Refuel reset at friendly starbases (grobj == 1 for planet). */
        if ((int16_t)lpord[1].grobj == 1) {
            lppl = LpplFromId(lpord[1].id);
            if (lppl != NULL && lppl->iPlayer == lpfl->iPlayer && lppl->fStarbase) {
                /* Check the starbase design hull for "has capacity". */
                SHDEF *sb = rglpshdefSB[lpfl->iPlayer];
                int16_t isb = (int16_t)lppl->isb;
                if (sb != NULL && isb >= 0) {
                    SHDEF *sbdef = (SHDEF *)((uint8_t *)sb + (int32_t)isb * 0x93);
                    HULDEF *huldef = LphuldefFromId(sbdef->hul.ihuldef);
                    if (huldef != NULL && huldef->hul.wtCargoMax != 0) {
                        lCur = 0;
                    }
                }
            }
        }
    }

    return lTot;
}

void FleetOrdersChangeTarget(FLEET *lpflOld)
{
    int16_t id;
    POINT pt;
    int16_t fChg;
    FLEET * lpfl;
    int16_t iord;
    int16_t iflMac;
    SCAN scan;
    int16_t grobj;

    /* TODO: implement */
}

void GetXferLeftRightRcs(RECT *prcWhole, RECT *prcLeft, RECT *prcRight)
{

    /* TODO: implement */
}
