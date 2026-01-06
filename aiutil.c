
#include "types.h"

#include "aiutil.h"

/* globals */
uint8_t vrgSBAip[85];  /* MEMORY_AIU:0x7688 */
uint8_t vrgSBMacAisb[6];  /* MEMORY_AIU:0x76de */
int32_t vrgAiPacketDist[2];  /* MEMORY_AIU:0x7dce */

/* functions */
void QueueAiStarbases(PROD *rgprod, int16_t ishdefSBLatest)
{
    PLANET * lpplMac;
    PLANET * lppl;
    int16_t i;
    PROD * lpprod;

    /* TODO: implement */
}

int16_t FGetAIPart(int16_t aip, PART *ppart)
{
    int16_t cTry;
    int16_t iOffset;
    int16_t i;
    int16_t cItem;
    PART part;

    /* TODO: implement */
    return 0;
}

FLEET * LpflFindClosestEnum(FLEET *lpfl, int16_t (*pfn)(FLEET *, FLEET *))
{
    FLEET * lpflT;
    POINT pt;
    int16_t dy;
    int16_t ish;
    int16_t dx;
    FLEET * lpflBest;
    int32_t l;
    int32_t lBest;

    /* TODO: implement */
    return NULL;
}

PLANET * LpplFindClosestEnum(PLANET *lppl, int16_t (*pfn)(PLANET *, PLANET *))
{
    POINT pt;
    int16_t dy;
    PLANET * lpplTMac;
    PLANET * lpplBest;
    PLANET * lpplT;
    int16_t dx;
    int32_t l;
    int32_t lBest;

    /* TODO: implement */
    return NULL;
}

void AddItemToQueue(uint16_t iItem, uint16_t cItem, uint16_t grobj, int16_t mdAddItem)
{
    int16_t fSingle;
    int16_t iprod;
    int16_t i;
    PROD rgprod[64];

    /* TODO: implement */
}

int16_t IdTargetAttack(FLEET *lpfl, FLEET *lpflAtk, FLEET *lpflEnemy, int16_t fOnlyHumans)
{
    FLEET * lpflClosest;
    FLEET * lpflT;
    int32_t lDistBest;
    PLANET * lpplMac;
    POINT pt;
    int16_t dy;
    PLANET * lppl;
    int32_t lDist;
    int16_t idClosest;
    int16_t i;
    int16_t cShipsAtk;
    int16_t cShipsDst;
    PLANET * lpplClosest;
    uint8_t * lpb;
    int16_t dx;
    FLEET * lpflAtk2;
    ORDER ord;

    /* debug symbols */
    /* label NextTarg @ MEMORY_AIU:0x2237 */
    /* label ThwakSumthin @ MEMORY_AIU:0x27d7 */

    /* TODO: implement */
    return 0;
}

int16_t FQueueAiDefenses(PLANET *lppl, int32_t *rgResAvail, int32_t *rgResCost)
{
    int16_t i;
    int16_t j;
    PROD * lpprod;

    /* TODO: implement */
    return 0;
}

int16_t XferAiSupply(int16_t grobjSrc, int16_t idSrc, int16_t grobjDst, int16_t idDst, int16_t iSupply, int16_t cQuan)
{
    int16_t dChg;
    int16_t iT;
    int32_t cAvailable;

    /* TODO: implement */
    return 0;
}

int16_t FFleetInField(FLEET *lpfl, THING *lpth)
{
    int16_t dy;
    int16_t dx;
    int32_t dxy2;

    /* TODO: implement */
    return 0;
}

void InitRandomPlanetList(void)
{
    PLANET * lpplMac;
    int16_t iT;
    PLANET * lppl;
    int16_t i;

    /* TODO: implement */
}

void MergeAllShdefs(int16_t grbitish)
{
    int16_t crglpflW;
    FLEET * rglpflW[1];
    int16_t iMax;
    int16_t iMin;
    int16_t i;
    int16_t ifl;
    FLEET * lpfl;
    int16_t grbit;
    int16_t rgish[16];
    FLEET * lpflNextPass;
    int16_t iflNextPass;

    /* debug symbols */
    /* label NextPass @ MEMORY_AIU:0x59d2 */

    /* TODO: implement */
}

int16_t FAIFling(PLANET *lppl, int32_t *rgResAvail)
{
    PLANET * lpplHit;
    POINT pt;
    int32_t dy;
    int16_t iT;
    int32_t d2;
    int32_t dBigAssPacket;
    int16_t i;
    int16_t fTwoMAs;
    int16_t iLevelBest;
    PLANET * lpplBest;
    int32_t dx;
    int16_t cFound;
    PLANET * lpplHitMac;
    int32_t l;
    PROD * lpprod;
    int16_t iKeep;

    /* debug symbols */
    /* block (block) @ MEMORY_AIU:0x8334 */

    /* TODO: implement */
    return 0;
}

int16_t XferAiTroopers(int16_t idSrc, int16_t idDst, int16_t cQuan)
{
    int32_t cAvailable;

    /* TODO: implement */
    return 0;
}

int16_t IdNearestColonizablePlanet(FLEET *lpflCol, THING * *plpthWorm)
{
    PLANET * lpplMac;
    POINT pt;
    int32_t dy;
    int32_t d2;
    PLANET * lppl;
    int16_t idBest;
    int16_t ifl;
    FLEET * lpfl;
    int16_t i;
    int16_t iVal;
    int32_t dx;
    uint8_t * lpb;
    int32_t d2Cur;

    /* debug symbols */
    /* label LFindNearest @ MEMORY_AIU:0x10ea */

    /* TODO: implement */
    return 0;
}

void GetProdQCost(PLANET *lppl, int32_t *rgCost)
{
    int32_t rgCostCur[4];
    PLPROD * lpplprod;
    int16_t i;
    int16_t j;
    PROD * lpprod;

    /* TODO: implement */
}

void MoveToNearestPlanetOrEnemy(FLEET *lpfl, int16_t dEnemyRange)
{
    POINT pt;
    int16_t id;
    int16_t dy;
    PLANET * lpplTMac;
    PLANET * lpplBest;
    PLANET * lpplT;
    int16_t dx;
    ORDER ord;
    int32_t l;
    int32_t lBest;
    SCAN scan;

    /* TODO: implement */
}

void PickANameAndBmp(SHDEF *pshdef, int16_t ids, int16_t cids, int16_t ibmpStart)
{
    int16_t i;
    int16_t rgfBmpUsed[4];
    int16_t ishdef;

    /* TODO: implement */
}

int16_t FIsAiAttack(FLEET *lpfl)
{
    int16_t ihul;
    int16_t i;

    /* TODO: implement */
    return 0;
}

void SplitOutShdefs(uint8_t *rgbIsh)
{
    int16_t iLast;
    int16_t iFirst;
    int16_t ifl;
    int16_t i;
    FLEET * lpfl;
    int16_t fUnmarked;
    FLEET flNew;
    int16_t fMarked;
    FLEET * lpflNew;

    /* debug symbols */
    /* label LTopOfLoop @ MEMORY_AIU:0x9937 */
    /* label LDoTheSplit @ MEMORY_AIU:0x9a13 */

    /* TODO: implement */
}

int16_t FGotoWormholeAiFleet(FLEET *lpfl, THING *lpthWorm)
{
    ORDER ord;

    /* TODO: implement */
    return 0;
}

int16_t FFindBuddyAndJoinUp(FLEET *lpfl, int16_t ishLo, int16_t ishHi, int32_t lMaxDist1, int32_t lMaxDist2)
{
    int32_t lDistBest;
    int32_t lDist;
    int16_t i;
    int16_t ifl;
    FLEET * lpflOther;
    FLEET * lpflBest;
    ORDER ord;

    /* debug symbols */
    /* block (block) @ MEMORY_AIU:0x9eab */

    /* TODO: implement */
    return 0;
}

void SetAiFleetIdealSpeed(FLEET *lpfl, int16_t wtFuelMax, int16_t cMinefields, THING * *rglpth)
{
    THING * lpth;
    int16_t i;
    int16_t j;
    int16_t ith;
    THING * lpthMac;
    int16_t fMinefield;

    /* debug symbols */
    /* label LSelectFleet @ MEMORY_AIU:0x1ec0 */
    /* label WarpSet @ MEMORY_AIU:0x1fa5 */

    /* TODO: implement */
}

int16_t IdTargetFreighter(FLEET *lpflFr, PLANET *lpplHome)
{
    int32_t lWorst2;
    int32_t scoreBest;
    PLANET * lpplMac;
    int32_t score;
    POINT pt;
    int16_t dy;
    int32_t lWorst;
    int16_t pctFull;
    int16_t idBest;
    PLANET * lppl;
    int32_t wtPlanCargo;
    FLEET * lpfl;
    int32_t wtCargoMax;
    int16_t ifl;
    int16_t i;
    int16_t iWorst2;
    int32_t wtCargoFree;
    THING * lpthBest;
    int16_t iWorst;
    PLANET * lpplBest;
    int16_t ishFreighter;
    int16_t pctHere;
    int16_t dx;
    uint8_t * lpb;
    int16_t fNeedy;
    ORDER ord;
    int16_t fSalvage;
    int32_t l;

    /* debug symbols */
    /* label LScore @ MEMORY_AIU:0x3236 */
    /* label ScorePctHere @ MEMORY_AIU:0x3158 */

    /* TODO: implement */
    return 0;
}

int16_t FCreateAiShdef(int16_t ishdef, int16_t ihul, uint8_t *rgaip)
{
    int16_t ids;
    int32_t grbitHull;
    int16_t cItem;
    int16_t ihs;
    HUL * lphul;
    PART part;
    SHDEF shdef;

    /* TODO: implement */
    return 0;
}

int16_t FIsTurinDroneAiAttack(FLEET *lpfl)
{
    int16_t ihul;
    int16_t i;

    /* TODO: implement */
    return 0;
}

int16_t FMoveAiFleet(FLEET *lpfl, ORDER *pord, int16_t fAppend)
{
    int16_t iord;

    /* TODO: implement */
    return 0;
}

void KeepFleetsMoving(void)
{
    int16_t i;
    int16_t ifl;
    FLEET * lpfl;
    THING * lpth;
    THING * rglpth[1];
    int16_t ith;
    THING * lpthMac;

    /* debug symbols */
    /* label LKeepMovn @ MEMORY_AIU:0x4690 */

    /* TODO: implement */
}

int16_t FUpgradeAiStarbase(PLANET *lppl, int16_t ishdefSBLatest)
{
    int16_t isbCur;
    int16_t iDesigns;
    int16_t i;
    int16_t pctUpg;
    int16_t isbNew;
    PROD * lpprod;
    int16_t ishdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AIU:0x8b9b */
    /* label LDoMacUpgrade @ MEMORY_AIU:0x893c */
    /* label LDoMacUpgrade2 @ MEMORY_AIU:0x8990 */

    /* TODO: implement */
    return 0;
}

uint32_t UlFleetPower(FLEET *lpfl)
{
    uint32_t ul;
    int16_t iplr;
    int16_t ishdef;

    /* TODO: implement */
    return 0;
}

int16_t IdplFindClosestStarbase(FLEET *lpfl, int16_t fBigOnes)
{
    POINT pt;
    int16_t dy;
    PLANET * lpplTMac;
    PLANET * lpplBest;
    PLANET * lpplT;
    int16_t dx;
    int32_t l;
    int32_t lBest;

    /* TODO: implement */
    return 0;
}

void GetResourcesAvailable(PLANET *lppl, int32_t *rgRes)
{
    int16_t i;
    int32_t cRes;

    /* TODO: implement */
}

int16_t IshdefAiSBLatest(void)
{

    /* TODO: implement */
    return 0;
}

int16_t FEnumOurStarbase(PLANET *lpplSrc, PLANET *lpplTest)
{

    /* TODO: implement */
    return 0;
}

int16_t FSalvageTargetFreighter2(FLEET *lpflFr, int16_t fNeedy, int16_t iWorst, int16_t pctFull, int32_t wtCargoMax, int32_t scoreBest, THING * *plpthBest, int16_t *pidBest)
{
    POINT pt;
    int32_t score;
    int16_t dy;
    int16_t i;
    int32_t wtPlanCargo;
    THING * lpth;
    int16_t pctHere;
    int16_t dx;
    THING * lpthMac;
    int16_t fSalvage;
    int32_t l;

    /* TODO: implement */
    return 0;
}

int16_t IdTargetScout(FLEET *lpfl, FLEET *lpflAtk, FLEET *lpflEnemy, int16_t fOnlyHumans, THING * *plpthWorm)
{
    FLEET * lpflClosest;
    FLEET * lpflT;
    int32_t lDistBest;
    PLANET * lpplMac;
    POINT pt;
    int16_t dy;
    PLANET * lppl;
    int32_t lDist;
    int16_t idClosest;
    PLANET * lpplClosest;
    int16_t dx;
    FLEET * lpflAtk2;
    ORDER ord;

    /* debug symbols */
    /* label LFindPlanet @ MEMORY_AIU:0x6699 */
    /* label NextTarg @ MEMORY_AIU:0x63ad */
    /* label ThwakSumthin @ MEMORY_AIU:0x67aa */

    /* TODO: implement */
    return 0;
}

void MarkPlanetsUnderAttack(void)
{
    PLANET * lppl;
    int16_t i;
    int16_t ifl;
    FLEET * lpfl;
    int16_t j;

    /* TODO: implement */
}

THING * LpthWormFind(POINT *ppt, int32_t d2)
{
    int16_t pctGood;
    int16_t dy;
    int32_t d2Worm;
    uint16_t grbitplr;
    THING * lpth;
    THING * lpthBest;
    int16_t iVal;
    int16_t dx;
    THING * lpthMac;
    int32_t d2Cur;

    /* TODO: implement */
    return NULL;
}

void ClearAiCurrentTask(FLEET *lpfl, int16_t fChangeSel)
{

    /* TODO: implement */
}

int16_t FCreateAiStarbase(int16_t ishdef, int16_t iLevel, int16_t aisb, int16_t isb)
{
    int16_t i;
    SHDEF shdef;
    HS * lphs;

    /* debug symbols */
    /* block (block) @ MEMORY_AIU:0x7c67 */

    /* TODO: implement */
    return 0;
}

void EnsureAiStarbaseDesigns(void)
{
    uint16_t wTurnLast;
    int16_t iSetNew;
    int16_t i;
    int16_t iSetLast;

    /* debug symbols */
    /* label LOrbital @ MEMORY_AIU:0x74a3 */

    /* TODO: implement */
}

int16_t FShouldWeBuildColonizers(int16_t *pcCol)
{
    int16_t iMax;
    int16_t cColFl;
    uint32_t cBuilt;
    int16_t iMin;
    int16_t ifl;
    int16_t i;
    FLEET * lpfl;
    int16_t rgish[16];
    int16_t cColPl;

    /* TODO: implement */
    return 0;
}

int16_t FColonizeAiFleet(FLEET *lpfl, int16_t idPlanet)
{
    ORDER ord;

    /* TODO: implement */
    return 0;
}

int16_t IroEnsureAi(uint8_t *lpbRes, int16_t cRes, int16_t *pishdefSBLatest, int16_t pct)
{
    int16_t iSmallest;
    int16_t i;
    int16_t pctTech;
    int16_t ilvl;

    /* TODO: implement */
    return 0;
}

void EnsureMacintiStarbaseDesigns(uint8_t *rgSB)
{
    int16_t k;
    int16_t iOld;
    int16_t cAge;
    int16_t i;
    int16_t j;
    int16_t iNew;

    /* TODO: implement */
}

int16_t IshdefAiSBLatestOF(void)
{

    /* TODO: implement */
    return 0;
}

int16_t FQueueAiScanner(PLANET *lppl, int32_t *rgResAvail, int32_t *rgResCost)
{
    int16_t i;
    int16_t j;
    int32_t rgItemCost[4];
    PROD * lpprod;

    /* TODO: implement */
    return 0;
}

void IncreaseAIMinefieldSizes(void)
{
    THING * lpth;
    int32_t cMines;
    THING * lpthMac;

    /* TODO: implement */
}

int16_t FMoveToNearestStarbase(FLEET *lpfl, int16_t fBigOnes)
{
    int16_t id;
    ORDER ord;

    /* TODO: implement */
    return 0;
}

void QuickBuildDefenses(PLANET *lppl, PROD *rgprod)
{
    int16_t cMax;
    int16_t cAlch;
    int16_t cCur;
    int16_t i;
    int16_t cRes;
    int32_t lVal;
    int16_t cDef;
    int32_t rgRes[4];
    PROD * lpprod;

    /* TODO: implement */
}

int16_t FIsAiTransport(FLEET *lpfl)
{
    int16_t ihul;
    int16_t i;

    /* TODO: implement */
    return 0;
}

int16_t FChangeAiShdef(SHDEF *pshdef, int16_t ishdef)
{
    SHDEF * lpshdefBase;
    int16_t iDir;
    int16_t ishdefWork;
    SHDEF shdef;

    /* TODO: implement */
    return 0;
}

int16_t FFleetMightHaveTeeth(FLEET *lpfl)
{
    HUL * lphul;
    int16_t ishdef;

    /* TODO: implement */
    return 0;
}

void HandleBasicAiTasks(int16_t iroCur, PROD *rgprod, int16_t ishdefSBLatest, int32_t *rgResAvail, int32_t *rgResCost)
{
    PLANET * lppl;
    int16_t i;
    int16_t ipl;
    int16_t fWrite;

    /* TODO: implement */
}

int16_t FQueueAiTerraforming(PLANET *lppl, int32_t *rgResAvail, int32_t *rgResCost)
{
    int16_t i;
    int16_t j;
    int16_t dEnv;
    int32_t rgItemCost[4];
    PROD * lpprod;

    /* TODO: implement */
    return 0;
}

int16_t IdNearestUnknownPlanet(FLEET *lpfl, THING * *plpthWorm)
{
    POINT pt;
    int32_t dy;
    int32_t d2;
    int16_t idBest;
    int16_t i;
    int32_t dx;
    uint8_t * lpb;
    int32_t d2Cur;

    /* TODO: implement */
    return 0;
}

void ValidateStarbaseHistory(void)
{
    int16_t iWrite;
    int16_t iBest;
    PLANET * lpplMac;
    POINT pt;
    int16_t id;
    int16_t dy;
    int16_t cFr2;
    PLANET * lppl;
    int16_t ifl;
    FLEET * lpfl;
    int16_t i;
    int16_t j;
    int16_t ipl;
    int16_t cFr;
    int16_t dx;
    int32_t lBest;
    int32_t l;

    /* TODO: implement */
}

void AddMinesToBlockedQueues(void)
{
    PROD prod;
    int32_t cMaxBuild;
    int16_t etaBetterAlchemy;
    int32_t cBuild;
    int16_t etaFirst;
    PLANET * lppl;
    int32_t cResMine;
    int32_t cRes;
    int16_t ipl;
    int32_t rgCost[4];
    PROD rgprod[64];
    int16_t etaBetterMines;

    /* TODO: implement */
}

int16_t IdRandomPlanetNearby(POINT pt, int16_t cDist, int16_t fAvoidStarbases)
{
    int16_t iChance;
    int32_t lDistMax;
    int32_t dy;
    int16_t idBest;
    int16_t i;
    int32_t dx;
    int16_t cExtraAttempts;
    int32_t d2Cur;
    PLANET * lppl;

    /* debug symbols */
    /* block (block) @ MEMORY_AIU:0x6076 */
    /* label LRetry @ MEMORY_AIU:0x5f72 */

    /* TODO: implement */
    return 0;
}

int16_t CheckAiShdefStatus(int16_t ishBeg, int16_t ishEnd, uint16_t cRecyclePeriod, int16_t *piLatest, uint8_t *rgbOld)
{
    uint32_t cExist;
    int16_t i;
    SHDEF shdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AIU:0x9bde */

    /* TODO: implement */
    return 0;
}

PLANET * LpplFindBestEnum(PLANET *lppl, int16_t (*pfn)(PLANET *, PLANET *))
{
    int16_t iBest;
    POINT pt;
    int16_t dy;
    PLANET * lpplTMac;
    PLANET * lpplBest;
    PLANET * lpplT;
    int16_t iCur;
    int16_t dx;
    int32_t l;
    int32_t lBest;

    /* TODO: implement */
    return NULL;
}

void FixPlanetsUnderAttack(PROD *rgprod)
{
    PLANET * lppl;
    int16_t ipl;

    /* TODO: implement */
}

int16_t FShouldPlanetBuildColonizer(PLANET *lpplSrc)
{
    POINT pt;
    int16_t i;
    int32_t lCur;
    uint8_t * lpb;
    int32_t lBest;

    /* TODO: implement */
    return 0;
}
