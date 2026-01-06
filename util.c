
#include "types.h"

#include "util.h"

/* Minimal externs required by the implementations below. */
extern GAME game;
extern PLANET *lpPlanets;
extern int16_t cPlanet;
extern SHDEF *rglpshdef[]; /* per-player ship design tables */

/* globals */
uint8_t vrgbTachyon[18];  /* MEMORY_UTIL:0x50be */
int32_t rgDSDivCnt[5];  /* MEMORY_UTIL:0x5f7e */
uint32_t rgcrDrawStars[5];  /* MEMORY_UTIL:0x5f92 */
int32_t rgDSDivCnt2[5];  /* MEMORY_UTIL:0x5fa6 */
uint32_t rgcrDrawStars2a[5];  /* MEMORY_UTIL:0x5fba */
uint32_t rgcrDrawStars2b[5];  /* MEMORY_UTIL:0x5fce */

/* functions */
char * PszGetLocName(int16_t grobj, int16_t id, int16_t x, int16_t y)
{

    /* debug symbols */
    /* label NoObj @ MEMORY_UTIL:0x3b68 */

    /* TODO: implement */
    return NULL;
}

int16_t FCanFleetUseStargates(FLEET *lpfl, POINT ptSrc, POINT ptDst)
{
    int16_t dTravel;
    PLANET * lpplDst;
    int16_t pctDmg;
    int16_t fSrcPlanet;
    int16_t fUncertain;
    int16_t i;
    int16_t fDanger;
    PLANET * lpplSrc;
    int16_t isbsDst;
    int16_t fCargo;
    int16_t ishdef;
    int16_t isbsSrc;
    SCAN scan;

    /* debug symbols */
    /* label LSrcChk @ MEMORY_UTIL:0x76a6 */
    /* label LJumpgate @ MEMORY_UTIL:0x7743 */

    /* TODO: implement */
    return 0;
}

FLEET * LpflFromId(int16_t idFleet)
{
    int16_t iplr;
    int16_t idGuess;
    int16_t iLo;
    int16_t iGuess;
    int16_t i;
    FLEET * lpfl;
    int16_t iplrCur;
    int16_t iHi;

    /* TODO: implement */
    return NULL;
}

PLANET * LpplFromId(int16_t idPlanet)
{
    int16_t idGuess;
    int16_t iLo;
    PLANET * lppl;
    int16_t iGuess;
    int16_t iHi;

    if (idPlanet < 0 || idPlanet >= game.cPlanMax) {
        return NULL;
    }

    /* If we have a dense array of all planets loaded, direct index. */
    if (cPlanet == game.cPlanMax) {
        return (PLANET *)((uint8_t *)lpPlanets + (int32_t)idPlanet * (int32_t)sizeof(PLANET));
    }

    /* Otherwise the planet list is sorted by id and has only cPlanet entries. */
    iLo = -1;
    iHi = cPlanet;
    while (true) {
        if (iHi <= (int16_t)(iLo + 1)) {
            return NULL;
        }
        iGuess = (int16_t)((iLo + iHi) >> 1);
        lppl = (PLANET *)((uint8_t *)lpPlanets + (int32_t)iGuess * (int32_t)sizeof(PLANET));
        idGuess = lppl->id;
        if (idGuess < idPlanet) {
            iLo = iGuess;
        } else if (idPlanet < idGuess) {
            iHi = iGuess;
        } else {
            return lppl;
        }
    }
}

THING * LpthFromId(int16_t idth)
{
    THING * lpth;
    THING * lpthMac;

    /* TODO: implement */
    return NULL;
}

int32_t LCalcFuelGainFromRamScoops(FLEET *lpfl, int16_t iWarp, int32_t dTravel)
{
    int16_t i;
    int16_t * rgiFuel;
    SHDEF * lpshdef;
    int32_t pct10;
    int32_t pctShip10;

    (void)rgiFuel;
    pct10 = 0;

    if (iWarp >= 11) {
        return 0;
    }

    /*
     * Port of the original Win16 logic:
     *  - For each ship design present in the fleet, if its engine uses 0 fuel
     *    at the current warp (and possibly the next few warps), add a % gain
     *    proportional to engine count.
     *  - Multiply by ship count and then by distance.
     */
    for (i = 0; i < 16; i++) {
        int16_t csh = lpfl->rgcsh[i];
        if (csh <= 0) {
            continue;
        }

        lpshdef = (SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)i * 0x93);

        /* Engine is always slot 0 in this data model. */
        {
            uint8_t engineId = (uint8_t)lpshdef->hul.rghs[0].iItem;
            uint8_t cEngines = (uint8_t)lpshdef->hul.rghs[0].cItem;
            ENGINE *lpeng = PARTS::LpengineFromId(engineId);

            pctShip10 = 0;
            if (iWarp < 10) {
                if (lpeng->rgcFuelUsed[iWarp] == 0) {
                    pctShip10 += (int32_t)cEngines;
                    if (lpeng->rgcFuelUsed[iWarp + 1] == 0) {
                        pctShip10 += (int32_t)cEngines * 2;
                        if (iWarp < 9 && lpeng->rgcFuelUsed[iWarp + 2] == 0) {
                            pctShip10 += (int32_t)cEngines * 3;
                            if (iWarp < 8 && lpeng->rgcFuelUsed[iWarp + 3] == 0) {
                                pctShip10 += (int32_t)cEngines * 4;
                            }
                        }
                    }
                }
            }

            pct10 += pctShip10 * (int32_t)csh;
        }
    }

    /* distance scaling (32-bit signed multiply in the original helpers) */
    return (int32_t)((int64_t)pct10 * (int64_t)dTravel);
}

int16_t IshdefPrimaryFromLpfl(FLEET *lpfl, int16_t *pcDiff)
{
    int16_t cDiff;
    int16_t ish;
    int16_t i;
    int16_t csh;
    int16_t ihul;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x3e7d */

    /* TODO: implement */
    return 0;
}

int16_t GetCachedFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal)
{
    int16_t dT;
    int16_t dPlanRange;
    int16_t i;
    int16_t iPlr;
    int16_t dRange;
    int16_t iSteal;
    int16_t pctDetect;

    /* TODO: implement */
    return 0;
}

int16_t FLookupSelShip(FLEET *pfl)
{

    /* TODO: implement */
    return 0;
}

int16_t FMatchTarget(FLEET *lpflTarget, int16_t mdTarget, int16_t fExact)
{
    int16_t imd;
    int16_t ish;

    /* TODO: implement */
    return 0;
}

void ClearFile(int16_t dt)
{
    char *pch;
    char szFile[256];

    /* TODO: implement */
}

int32_t LComputePower(SHDEF *lpshdef)
{
    int16_t dSpeed;
    int16_t dxRange;
    int16_t ihs;
    int32_t dpTorps;
    int16_t i;
    int32_t pctCap;
    int32_t dpBeams;
    int32_t dpBombs;
    int32_t dp;
    PART part;

    /* TODO: implement */
    return 0;
}

char * PszGetFleetName(int16_t id)
{
    int16_t cshdef;
    int16_t iplr;
    char *lpsz;
    char szShdef[34];
    int16_t ifl;
    FLEET * lpfl;
    char szPlr[34];
    int16_t ishdef;
    int16_t cch;

    /* TODO: implement */
    return NULL;
}

char * PszGetThingName(int16_t id)
{
    THING * lpth;
    char szPlr[54];

    /* TODO: implement */
    return NULL;
}

int32_t LongFromSerialCh(char ch)
{
    int32_t l;

    /* TODO: implement */
    return 0;
}

uint16_t WPackLong(int32_t l)
{
    uint16_t exp;

    /* TODO: implement */
    return 0;
}

double DGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2)
{
    int32_t dy;
    int32_t dx;
    int32_t l;

    dx = (int32_t)x2 - (int32_t)x1;
    dy = (int32_t)y2 - (int32_t)y1;
    l = (int32_t)((int64_t)dx * (int64_t)dx + (int64_t)dy * (int64_t)dy);
    /* Use double sqrt like the original (which routed through the C runtime). */
    return __builtin_sqrt((double)l);
}

int16_t FDeleteFleet(int16_t idFleet, int16_t grobjSel, int16_t idSel)
{
    int16_t i;
    FLEET * lpfl;
    int16_t iPlr;
    int16_t idDel;
    PLANET * lppl;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x2eb7 */

    /* TODO: implement */
    return 0;
}

int32_t WtFromLpfl(FLEET *lpfl)
{
    int32_t cMass;
    int16_t i;

    /* TODO: implement */
    return 0;
}

void SelectOursAtObject(POINT *ppt)
{
    int16_t id;
    POINT pt;
    int16_t ish;
    int16_t i;
    FLEET * lpfl;
    SCAN scan;

    /* TODO: implement */
}

int16_t CchGetETA(uint16_t hdc, FLEET *lpfl, char *sz, int16_t iwp, int16_t fSmall)
{
    int16_t iWarp;
    double dbl;
    ORDER * lpord;
    int16_t i;
    int16_t c;
    int16_t iSpeed;
    int16_t j;
    int16_t cYears;
    int16_t ids;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x3d24 */

    /* TODO: implement */
    return 0;
}

char * PszGetPlanetName(int16_t id)
{
    int16_t fInOrbit;
    char *psz;

    /* TODO: implement */
    return NULL;
}

int16_t FDupFleet(FLEET *lpfl, FLEET *pfl)
{
    PLORD * lpplordT;

    /* TODO: implement */
    return 0;
}

int16_t FDupPlanet(PLANET *lppl, PLANET *ppl)
{
    PLPROD * lpplprodT;

    /* TODO: implement */
    return 0;
}

char * PszFleetNameFromWord(uint16_t w)
{
    char *lpsz;
    char szShdef[34];
    int16_t ishdef;
    int16_t cch;

    /* TODO: implement */
    return NULL;
}

int16_t FValidSerialNo(char *psz, int32_t *plSerial)
{
    int32_t lBuild;
    int16_t i;
    int32_t lCur;
    int32_t lSerial;
    int32_t l;

    /* TODO: implement */
    return 0;
}

void DrawABunchOfStars(uint16_t hdc, RECT *prc)
{
    int32_t lPixTot;
    int16_t iMax;
    int16_t dy;
    int16_t i;
    int16_t iClr;
    int16_t dx;
    RECT rcOut;
    RECT rc;

    /* TODO: implement */
}

char * PszGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2)
{
    int32_t d;
    int16_t fStarted;
    int32_t d2;

    /* TODO: implement */
    return NULL;
}

void CalcPctSurvive(PLANET *lppl, float *ppct, float *ppctSmart)
{
    int16_t iPlrSav;
    int32_t cDefenses;
    float pct;
    PART part;
    int16_t cMax;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x0369 */

    /* TODO: implement */
}

int16_t IshFindSimilarDesign(HUL *lphul, int16_t iPlrDst)
{
    SHDEF * lpshdefDest;
    int16_t i;
    int16_t j;

    /* TODO: implement */
    return 0;
}

void DecorateHullName(int16_t iplr, int16_t ish, char *psz)
{
    int16_t i;
    int16_t c;
    SHDEF * lpshdef;
    int16_t iVal;

    /* TODO: implement */
}

int16_t FCanBuildShdef(SHDEF *lpshdef, int16_t iplr)
{
    int16_t j;
    int16_t iplrSav;
    PART part;

    /* debug symbols */
    /* label LFail @ MEMORY_UTIL:0x7bbb */

    /* TODO: implement */
    return 0;
}

int16_t FFleetMergeAll(FLEET *pfl)
{
    int16_t iplr;
    int32_t dpT;
    int16_t fCshOverflow;
    int16_t rgcshDamaged[16];
    int16_t cflMerge;
    int16_t i;
    FLEET * lpfl;
    int16_t cshT;
    SHDEF * lpshdef;
    FLEET * lpflMerge;
    int32_t rgdp[16];
    int16_t j;

    /* TODO: implement */
    return 0;
}

int16_t ICompFleetPoint2(void *arg1, void *arg2)
{
    int32_t l2;
    int32_t l1;

    /* TODO: implement */
    return 0;
}

void TurnLog(int16_t ids)
{
    char szTemp[256];

    /* TODO: implement */
}

char * PszPlayerName(int16_t iPlayer, int16_t fCapital, int16_t fPlural, int16_t fThe, int16_t grWord, PLAYER *pplr)
{
    char *pchEnd;
    char szName[50];

    /* TODO: implement */
    return NULL;
}

int16_t IStargateFromLppl(PLANET *lppl)
{
    int16_t chs;
    HS * lphs;
    int16_t ihs;
    HUL * lphul;

    /* TODO: implement */
    return 0;
}

int32_t DpOfLpflIshdef(FLEET *lpfl, int16_t ishdef)
{
    int16_t dpShdef;
    int32_t dp;

    /* TODO: implement */
    return 0;
}

int16_t FFleetSplitAll(FLEET *pfl)
{
    FLEET flNew;
    int16_t cSplit;
    int16_t c;
    int16_t i;
    FLEET * lpflNew;

    /* TODO: implement */
    return 0;
}

int16_t ICompFleetPoint(void *arg1, void *arg2)
{
    int32_t l2;
    int32_t l1;

    /* TODO: implement */
    return 0;
}

void OutputSz(int16_t dt, char *sz)
{
    char szTime[100];
    char szFile[256];
    char szDate[100];
    char szTemp[256];

    /* TODO: implement */
}

void ComputeShdefPowers(void)
{
    int16_t iplr;
    int16_t ishdef;

    /* TODO: implement */
}

int16_t GetPlanetScannerRange(PLANET *lppl, int16_t *pDeep)
{
    int16_t iPlrSav;
    int16_t dRange;
    PART part;

    /* debug symbols */
    /* label LFinishUp @ MEMORY_UTIL:0x4def */

    /* TODO: implement */
    return 0;
}

FLEET * LpflNew(int16_t iPlr, int16_t idPl)
{
    int16_t i;
    ORDER * lpord;
    FLEET * lpfl;
    int16_t iflPrev;

    /* TODO: implement */
    return NULL;
}

void UpdateShdefCost(SHDEF *lpshdef)
{
    int16_t dpT;
    uint32_t wt;
    int16_t k;
    int16_t c;
    uint16_t rgCosts[4];
    int16_t fWeakArmor;
    HUL * lphul;
    uint32_t resCost;
    uint32_t rgMin[3];
    PART part;

    /* TODO: implement */
}

int16_t FLookupSelPlanet(PLANET *ppl)
{

    /* TODO: implement */
    return 0;
}

int16_t FLookupThing(int16_t idth, THING *pth)
{
    THING * lpth;
    int16_t fWrite;

    /* TODO: implement */
    return 0;
}

int16_t FLookupFleet(int16_t idFleet, FLEET *pfl)
{
    FLEET * lpfl;
    int16_t fWrite;

    /* TODO: implement */
    return 0;
}

int16_t FLookupOrbitingXfer(int16_t idPlanet, int16_t iNth, XFER *pxf, int16_t idSkip)
{
    int16_t i;
    THING * lpth;
    FLEET * lpfl;
    THING * lpthMac;

    /* TODO: implement */
    return 0;
}

void LinkFleets(int16_t fUnused)
{
    FLEET * * pSearch;
    POINT pt;
    FLEET * rglpflSrc[1];
    FLEET * lpflTail;
    FLEET * lpflHead;
    int16_t i;
    int16_t iflTail;
    int16_t iflHead;
    int16_t cSrc;

    /* TODO: implement */
}

int16_t FCalcFleetBombDamage(FLEET *lpfl, int32_t *pdmgPeople, int32_t *pdmgPeopleMin, int32_t *pdmgPeopleSmart, int32_t *pdmgBldg, int32_t *ppctTerra, int16_t *pfMulti)
{
    int16_t iplr;
    int16_t cfl;
    FLEET * lpflNext;
    int16_t dmgFloor;
    FLEET * lpflHead;
    double dmgSmart;
    int16_t fBomber;
    int16_t j;
    int16_t ishdef;
    PART part;
    int32_t cIter;
    double dmgT;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x1615 */

    /* TODO: implement */
    return 0;
}

int16_t IflFromLpfl(FLEET *lpfl)
{
    int16_t i;

    /* TODO: implement */
    return 0;
}

int32_t DpShieldOfShdef(SHDEF *lpshdef, int16_t iplr)
{
    int16_t chs;
    HS * lphs;
    int16_t ihs;
    int32_t dpShdef;
    HUL * lphul;
    PART part;

    /* TODO: implement */
    return 0;
}

void GetTrueHullCost(int16_t iPlayer, HUL *lphul, uint16_t *rgCost)
{
    int16_t i;

    /* TODO: implement */
}

void DrawPlanetPrintDot(uint16_t hdc, int16_t x, int16_t y, int16_t iSize)
{

    /* TODO: implement */
}

int16_t GetShdefScannerRange(SHDEF *lpshdef, int16_t iplr, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal)
{
    int16_t chs;
    HS * lphs;
    int16_t dRangeT2;
    double lBIR4;
    int16_t dRangeT;
    int16_t fHasScanner;
    int16_t iScanner;
    int16_t fBuiltIn;
    int16_t cDetectors;
    double lPlanRange4;
    int16_t dRange;
    double lT;
    int16_t iSteal;
    int16_t j;
    double lBIPR4;
    double lRange4;

    /* debug symbols */
    /* label LPlanScan @ MEMORY_UTIL:0x53ed */
    /* label LOddBallScanners @ MEMORY_UTIL:0x5482 */

    /* TODO: implement */
    return 0;
}

void ValidateWaypoints(void)
{
    int16_t mdTarget;
    FLEET * lpflTarget;
    int16_t ifl2;
    int32_t wt;
    FLEET * lpflMatch;
    int32_t wtMatch;
    ORDER * lpord;
    int16_t ifl;
    THING * lpth;
    FLEET * lpfl;
    int16_t cFound;
    int16_t iord;
    FLEET * lpfl2;
    int16_t iplrHi;

    /* TODO: implement */
}

int32_t ChgPopFromPlanet(PLANET *lppl, int16_t fUpdate)
{
    int32_t lMaxPop;
    int16_t fPopDied;
    int32_t lPopIncDelta;
    int16_t DeltaCur;
    int32_t pctGrow100;
    int16_t pctDesire;
    int32_t lPopInc100;
    int32_t lPopInc;
    int32_t lPopOld;
    int32_t pctRetard;
    int32_t pctFull;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x72b1 */
    /* label LUpdateAndExit @ MEMORY_UTIL:0x756b */

    /* TODO: implement */
    return 0;
}

int16_t FFleetCanJumpgate(FLEET *lpfl)
{
    HS * lphs;
    int16_t chs;
    int16_t i;
    int16_t j;

    /* TODO: implement */
    return 0;
}

int32_t CalcPlayerScore(int16_t iPlr, SCORE *pscore)
{
    int32_t rgcsh[3];
    int32_t lTemp;
    SCORE score;
    PLANET * lpplMac;
    PLANET * lppl;
    int16_t i;
    int16_t ifl;
    FLEET * lpfl;
    int16_t iTech;
    int32_t lPower;
    int16_t rgType[16];

    /* TODO: implement */
    return 0;
}

int16_t FLookupPlanet(int16_t iPlanet, PLANET *ppl)
{
    PLANET * lpPl;
    int16_t fWrite;

    /* debug symbols */
    /* label FinishCopy @ MEMORY_UTIL:0x06af */

    /* TODO: implement */
    return 0;
}

FLEET * LpflNewSplit(FLEET *pfl)
{
    int16_t iordMac;
    FLEET * lpflNew;

    /* TODO: implement */
    return NULL;
}

uint16_t WFromLpfl(FLEET *lpfl)
{
    int16_t cshdef;
    uint16_t w;
    int16_t ishdef;

    /* TODO: implement */
    return 0;
}

int16_t FLookupObject(int16_t grobj, int16_t id, void *pobj)
{

    /* TODO: implement */
    return 0;
}

int16_t GetFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal)
{
    int16_t iplr;
    int16_t dPlanRange;
    int16_t i;
    int16_t dRange;
    int16_t iSteal;
    int16_t dPlanRangeBest;
    int16_t dRangeBest;
    int16_t pctDetect;

    /* TODO: implement */
    return 0;
}

int16_t FFindNearestObject(POINT pt, int16_t grobj, SCAN *pscan)
{
    POINT ptWp;
    POINT * ppt;
    int16_t dy;
    int32_t lTry;
    THING * lpth;
    FLEET * lpfl;
    int16_t i;
    THING * lpthMac;
    int32_t lSquare;
    SCAN scanT;
    int16_t iNearest;
    int16_t dx;
    SCAN scan;

    /* debug symbols */
    /* label SelectThing @ MEMORY_UTIL:0x4523 */
    /* label SelectSpace @ MEMORY_UTIL:0x46c3 */
    /* label SelectShip @ MEMORY_UTIL:0x439d */

    /* TODO: implement */
    return 0;
}
