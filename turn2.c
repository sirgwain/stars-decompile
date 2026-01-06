
#include "types.h"

#include "turn2.h"

/* functions */
void Produce(void)
{
    int32_t lResCur;
    int16_t cMax;
    int32_t rgResAvail[4];
    int16_t iprodCur;
    int16_t mdStatus;
    int16_t cBuilt;
    int16_t fNoResearch;
    PLANET * lppl;
    int16_t i;
    int16_t idm;
    PROD prodPartial;
    int16_t fPrevProdIsAlch;
    int16_t fAutoBuildDone;
    int32_t lResearchTake;
    PROD * lpprod;
    PLANET * lpplMac;
    int16_t cMax2;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x05c2 */
    /* block (block) @ MEMORY_TURN2:0x06cd */
    /* block (block) @ MEMORY_TURN2:0x075c */
    /* label TopOfQueue @ MEMORY_TURN2:0x0371 */
    /* label RemoveFromQueue @ MEMORY_TURN2:0x09d0 */
    /* label LCantBuildP @ MEMORY_TURN2:0x0623 */
    /* label LCantBuildP2 @ MEMORY_TURN2:0x0628 */

    /* TODO: implement */
}

void CreateBackupDir(void)
{
    char *pchT;

    /* TODO: implement */
}

void ThingDecay(void)
{
    THING * lpthMac;
    int32_t pctDecay;
    int16_t i;
    int16_t ifl;
    FLEET * lpfl;
    THING * lpth;
    uint16_t wDecay;
    int32_t lDecay;
    int16_t fMineExpert;
    int32_t dy;
    int32_t dx;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x7346 */
    /* block (block) @ MEMORY_TURN2:0x7391 */
    /* label LFixUpLpth @ MEMORY_TURN2:0x72ca */

    /* TODO: implement */
}

void DropColonists(void)
{
    COLDROP * lpcdLook;
    int16_t fTie;
    int32_t cMax;
    PLANET pl;
    int32_t lDefensePower;
    int32_t cPowerTot;
    COLDROP * lpcdCur;
    int16_t iMax;
    int16_t idPlanet;
    int16_t iplrOldOwner;
    int32_t cColTot;
    int32_t lOldPop;
    int32_t c2nd;
    int16_t i;
    int32_t rgcPower[16];
    int16_t cSides;
    float pctSurvive;
    int32_t rgcCol[16];
    int32_t lPower;
    COLDROP * lpcdMax;
    int16_t cpq;
    int16_t iTech;
    int16_t iDst;
    int16_t iBonus;
    PROD prod;
    int16_t ipq;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x3ebb */
    /* block (block) @ MEMORY_TURN2:0x3f27 */
    /* block (block) @ MEMORY_TURN2:0x4329 */
    /* label IncCur @ MEMORY_TURN2:0x442b */
    /* label WritePlanet @ MEMORY_TURN2:0x42fc */

    /* TODO: implement */
}

void TossNonAutoBuildItems(PLANET *lppl)
{
    int16_t iDst;
    int16_t iSrc;

    /* TODO: implement */
}

void UpdateResearchStatus(int16_t fUsePool)
{
    int16_t mdAvail;
    int16_t fRedoItAll;
    int16_t iTechCur;
    int16_t fUsePoolOrig;
    int16_t iTechNext;
    int16_t iT;
    int16_t iItem;
    int16_t fGeneral;
    int16_t fChgNow;
    int16_t i;
    int16_t ibitCur;
    int32_t rglFieldSpent[6];
    int16_t grbitCur;
    int16_t cPlrAlive;
    int32_t lSpent;
    PART part;
    int32_t l;
    int16_t iTT;
    int16_t iTechNext2;
    char TechLevel;
    int32_t l15pct;
    int16_t jj;
    int16_t iGoto;
    int16_t idm;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x824f */
    /* block (block) @ MEMORY_TURN2:0x82cf */
    /* block (block) @ MEMORY_TURN2:0x8520 */
    /* block (block) @ MEMORY_TURN2:0x858f */
    /* block (block) @ MEMORY_TURN2:0x86c0 */
    /* block (block) @ MEMORY_TURN2:0x8814 */
    /* label RedoItAll @ MEMORY_TURN2:0x81cf */
    /* label CheckForBreakthrough @ MEMORY_TURN2:0x83dc */

    /* TODO: implement */
}

void RemoteTerraforming(void)
{
    int16_t fHelp;
    int16_t iBest;
    int16_t pctCur;
    PLANET * lppl;
    int16_t ifl;
    FLEET * lpfl;
    int16_t cDone;
    int16_t iEnv;
    int16_t cAllowed;
    int32_t ipct;
    int16_t pctNew;

    /* TODO: implement */
}

void UpdatePopulations(void)
{
    int32_t lPopChg;
    PLANET * lppl;
    PLANET * lpplMac;
    int16_t fMac;
    int32_t lPopOld;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x515b */
    /* block (block) @ MEMORY_TURN2:0x5278 */
    /* label NextPlanet @ MEMORY_TURN2:0x5254 */

    /* TODO: implement */
}

void SweepForMines(void)
{
    int16_t iplr;
    THING * lpthMac;
    POINT pt;
    int32_t dy;
    int32_t lCur;
    PLANET * lppl;
    int16_t ifl;
    FLEET * lpfl;
    THING * lpth;
    int32_t cMineCur;
    int32_t dx;
    int32_t cMine;
    uint16_t grbitPlr;
    PLANET * lpplMac;

    /* TODO: implement */
}

void UpdatePlayerScores(void)
{
    int32_t lScoreTot;
    int16_t cFirst;
    SCORE score;
    int16_t cDead;
    int16_t c;
    int16_t i;
    uint8_t rgcCond[16];
    uint16_t wWinners2;
    int32_t rglScore[16];
    int16_t iScoreMax;
    int16_t j;
    uint16_t wWinners;
    int16_t imsg;
    int32_t lScore2nd;
    int32_t lScoreMax;

    /* TODO: implement */
}

void UpdateGuesses(void)
{
    PLANET * lppl;
    float pct;
    PLANET * lpplMac;
    int32_t l;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x5377 */

    /* TODO: implement */
}

void MysteryTrader(void)
{
    int16_t iSrc;
    int16_t cRand;
    int16_t i;
    THING * lpth;
    int16_t grbitTrader;
    int16_t rgC[4];

    /* TODO: implement */
}

int16_t FQueueColonistDrop(FLEET *lpfl, PLANET *lppl, int32_t cColonists)
{
    int16_t iColDrop;
    COLDROP * lpcdT;

    /* TODO: implement */
    return 0;
}

int16_t CBuildProdItem(PLANET *lppl, PROD *lpprod, PROD *pprodPartial, int32_t *rgRes, int16_t fAlchemy, int16_t *pmdStatus, int16_t fCalcOnly)
{
    int32_t pctT;
    int16_t cMax;
    uint32_t iobjOther;
    int32_t cCanBuild;
    int32_t lMinNeeded;
    int32_t lAlchCost;
    PROD prod;
    int16_t fAutoBuild;
    int16_t cBuilt;
    int16_t cAlchemy;
    int32_t rgCostPaid[4];
    int16_t i;
    int16_t fResourceBlocked;
    int32_t pctInitial;
    int32_t pctTooBig;
    int32_t pct;
    int32_t rgCost[4];
    int16_t fMineralBlocked;
    int32_t AddCost;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x1324 */
    /* label LAlchemize @ MEMORY_TURN2:0x13e1 */

    /* TODO: implement */
    return 0;
}

void AutoTerraform(void)
{
    int16_t rgMax[3];
    int16_t rgp[16];
    PLANET * lppl;
    int16_t i;
    int16_t rgMin[3];
    int16_t rgCost[3];
    int16_t fTerra;
    PLANET * lpplMac;

    /* TODO: implement */
}

int16_t FPacketDecay(THING *lpth, int16_t pctRate)
{
    uint16_t iRateMin;
    int16_t iRate;
    int16_t i;
    uint16_t wDecay;
    int32_t lDecay;

    /* TODO: implement */
    return 0;
}

void TransferToOthers(void)
{
    int32_t l2;
    int16_t idDst;
    XFER rgxf[2];
    int16_t idSrc;
    int16_t i;
    int16_t idm;
    XFERFULL * lpxfMax;
    XFERFULL * lpxfCur;
    int32_t l;

    /* debug symbols */
    /* label DoNext @ MEMORY_TURN2:0x34c6 */

    /* TODO: implement */
}

void MineMinerals(void)
{
    int32_t rglQuan[3];
    PLANET * lppl;
    PLANET * lpplMac;

    /* TODO: implement */
}

int16_t FBuildObject(PLANET *lppl, int16_t grobj, int16_t iItem, int16_t cBuilt, int32_t *rgMinerals)
{
    int16_t iWarp;
    int16_t i;
    FLEET * lpfl;
    int16_t idm;
    int16_t fTwoMAs;
    SHDEF * lpshdef;
    int16_t cAllowed;
    int16_t iEnv;
    int32_t dpOrig;
    THING * lpthMac;
    int16_t cshDamaged;
    int16_t cshOrig;
    int16_t iDecayRate;
    PART part;
    uint16_t dpShdef;
    THING * lpth;
    int16_t raMajor;
    int16_t iWarpAsked;
    int16_t cSize;
    int16_t rgwt[3];
    int32_t l;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x1d3a */
    /* block (block) @ MEMORY_TURN2:0x2681 */
    /* block (block) @ MEMORY_TURN2:0x2785 */
    /* block (block) @ MEMORY_TURN2:0x2dd5 */
    /* block (block) @ MEMORY_TURN2:0x2ec1 */
    /* label SendMsgFactMine @ MEMORY_TURN2:0x248b */

    /* TODO: implement */
    return 0;
}

int16_t IBestRemoteTerra(PLANET *lppl, int16_t iplr, int16_t fHelp)
{
    int16_t iBest;
    int16_t i;
    PLAYER plrSav;

    /* TODO: implement */
    return 0;
}

void PlanetaryClimateChange(void)
{
    int16_t iT;
    PLANET * lppl;
    int16_t i;
    int16_t j;

    /* TODO: implement */
}

void DiscoverNewMinerals(void)
{
    PLANET * lppl;
    int16_t i;

    /* TODO: implement */
}

void MeteorStrike(void)
{
    int16_t rgEnv[3];
    int16_t iT;
    int32_t rgQuan[4];
    int16_t iSize;
    PLANET * lppl;
    int16_t rgAffect[3];
    int16_t i;
    int16_t iConc;
    int16_t j;

    /* TODO: implement */
}

void HealShips(void)
{
    int16_t pctShipHeal;
    int16_t dpHeal;
    PLANET * lppl;
    int16_t i;
    FLEET * lpfl;
    SHDEF * lpshdef;
    int16_t pct;
    int16_t ishdef;
    PLANET * lpplMac;

    /* TODO: implement */
}

void CreateShip(int16_t iPlr, FLEET *lpfl, int16_t ishdef, int16_t cShip)
{

    /* TODO: implement */
}

void BreedColonistsInTransit(void)
{
    int16_t fNoBreeders;
    char grfBreeder[16];
    int32_t lColGain;
    PLANET * lppl;
    int16_t ifl;
    FLEET * lpfl;
    int16_t i;
    int32_t lColGainAct;

    /* TODO: implement */
}

void RandomEvents(void)
{

    /* TODO: implement */
}

void UnmarkMineFields(void)
{
    THING * lpthMac;
    THING * lpth;

    /* TODO: implement */
}
