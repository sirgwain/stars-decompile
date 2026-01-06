
#include "types.h"

#include "ai4.h"

/* globals */
uint8_t vrgAiCybertronResOrder[42];  /* MEMORY_AI4:0x0000 */
uint16_t vrgCyberIshAip[36];  /* MEMORY_AI4:0x46b0 */
uint8_t vrgCyberAip[301];  /* MEMORY_AI4:0x46f8 */

/* functions */
int16_t FEnumDropOffStage2(PLANET *lpplSrc, PLANET *lpplTest)
{
    CYBERINFOTEMP * lpciPlanTemp;
    int16_t dOffsetPlanTemp;

    /* TODO: implement */
    return 0;
}

int16_t FEnumDropOffStage1(PLANET *lpplSrc, PLANET *lpplTest)
{
    CYBERINFOTEMP * lpciPlanTemp;
    int16_t dOffsetPlanTemp;

    /* TODO: implement */
    return 0;
}

int16_t FEnumNeedMinerals(PLANET *lpplSrc, PLANET *lpplTest)
{
    double dDistance;
    int16_t iWarpSrc;
    int16_t fTwoMA;
    int16_t iMinLimit;
    CYBERINFO * lpciPlan;
    int16_t iWarpDst;
    CYBERINFOTEMP * lpciPlanTemp;
    int16_t dOffsetPlanTemp;

    /* TODO: implement */
    return 0;
}

int16_t FFillProdMinesAndFactories(PLANET *lppl)
{
    int32_t rgResCost[4];
    int32_t rgResAvail[4];
    int16_t iAddFactories;
    int16_t iAddMines;
    PROD prod;
    int32_t rgAlchCost[4];
    int32_t rgMineCost[4];
    int32_t rgFactCost[4];
    int32_t rgResLeft[4];
    int16_t iAddAlchemy;
    int16_t iMaxTerra;
    int16_t i;
    int16_t iMaxFactories;
    int16_t iMaxFactBuildable;
    int16_t iMaxMines;
    int16_t fInsert;
    PROD * lpprod;
    int16_t cAdd;

    /* debug symbols */
    /* block (block) @ MEMORY_AI4:0x3204 */
    /* label LAdd @ MEMORY_AI4:0x3612 */

    /* TODO: implement */
    return 0;
}

void EnsureCyberAiShdefs(int16_t iroCur)
{
    int16_t low;
    int16_t ish;
    int16_t ishCur;
    int16_t i;
    int16_t high;
    SHDEF shdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AI4:0x4889 */
    /* label LBomber @ MEMORY_AI4:0x4cb5 */
    /* label LCruiser @ MEMORY_AI4:0x4c39 */

    /* TODO: implement */
}

int16_t iAddAttackFleet(PLANET *lppl, int16_t iAttackStr, int16_t iBestDestroyer, int16_t iBestBattle, int16_t iBestSBDefender)
{
    int16_t fRet;
    int16_t iMaxFactories;
    int16_t iMaxMines;
    int16_t iRand;

    /* TODO: implement */
    return 0;
}

void TargetCyberArmada(FLEET *lpfl)
{
    FLEET * lpflTarget;
    ORDER ord;
    PLANET * lppl;
    int16_t cshBomb;
    int16_t cshWar;
    PLANET * lpplTarget;

    /* debug symbols */
    /* label LTryNewTarget @ MEMORY_AI4:0x52b2 */
    /* label TargetPotentArmada @ MEMORY_AI4:0x5390 */
    /* label TargetEveryArmada @ MEMORY_AI4:0x53fd */
    /* label FinishTargeting @ MEMORY_AI4:0x545d */

    /* TODO: implement */
}

int16_t FAddPacketToQueue(PLANET *lppl)
{
    int32_t rgResCost[4];
    int16_t iMineral;
    int32_t rgResAvail[4];

    /* TODO: implement */
    return 0;
}

int16_t FEnumCalcEnemyPlanets(PLANET *lpplSrc, PLANET *lpplTest)
{

    /* TODO: implement */
    return 0;
}

void DoCyberPackets(void)
{
    int16_t fTwoMA;
    int32_t rgResCost[4];
    int32_t rgResAvail[4];
    int16_t iWarp;
    PLANET * lpplDst;
    PLANET * lppl;
    int16_t i;
    int16_t ipl;
    int16_t iWarpDst;
    CYBERINFO * lpciPlan;
    PROD rgprod[64];
    int16_t dOffsetPlanTemp;
    int16_t idPlanDst;
    CYBERINFOTEMP * lpciPlanTemp;
    int16_t fWrite;
    int16_t iPacketMax;
    int16_t iMinLimit;
    int32_t * plMinMax;
    CYBERINFO * lpciPlanDst;
    int16_t iPacketAdd;
    int32_t lPackets;
    int32_t lMineral;
    CYBERINFOTEMP * lpciPlanT;
    int16_t cResLeft;
    int16_t iWarpSrc;
    double dDistance;
    double dMod;
    int16_t cPacket[3];
    int32_t lMinNeeded;
    double dDistanceTgt;
    int16_t iMin;

    /* debug symbols */
    /* block (block) @ MEMORY_AI4:0x1c29 */
    /* block (block) @ MEMORY_AI4:0x1c93 */
    /* block (block) @ MEMORY_AI4:0x1ee6 */
    /* block (block) @ MEMORY_AI4:0x200b */
    /* block (block) @ MEMORY_AI4:0x2159 */
    /* block (block) @ MEMORY_AI4:0x241c */
    /* block (block) @ MEMORY_AI4:0x26bb */
    /* label LFinish @ MEMORY_AI4:0x2814 */

    /* TODO: implement */
}

int16_t IdGetBestScannerDest(PLANET *lppl, int16_t iDir)
{
    int16_t iDistance;
    int16_t iWarp;
    PLANET * lpplDst;
    int16_t dAdjust;
    int16_t iSize;
    POINT ptEdge;
    SCAN scan;

    /* TODO: implement */
    return 0;
}

int16_t FEnumPickUp(PLANET *lpplSrc, PLANET *lpplTest)
{

    /* TODO: implement */
    return 0;
}

int16_t iBuildCyberStarbase(PLANET *lppl)
{
    int16_t ishdefSB;
    PROD rgprod[64];

    /* TODO: implement */
    return 0;
}

void DoCyberFreighter(FLEET *lpfl, CYBERINFOTEMP *lpciPlanTemp)
{
    ORDER ord;
    PLANET * lpplDst;
    PLANET * lpplCur;
    int16_t fDropOff;
    int16_t idPlanDst;
    SCAN scan;

    /* debug symbols */
    /* label LTarget @ MEMORY_AI4:0x3c32 */

    /* TODO: implement */
}

void FillProductionQueue(void)
{
    PLANET * lppl;
    int16_t ipl;
    PROD rgprod[64];

    /* TODO: implement */
}

void DoCyberAiTurn(PROD *rgprod)
{
    int32_t rgResCost[4];
    int16_t cSBDefenderFleets;
    int32_t rgResAvail[4];
    FLEET * lpflEnemy;
    int32_t cExistColony;
    int16_t cFlMineLayers;
    uint8_t rgRecycleShdef[16];
    PLANET * lppl;
    int16_t cMineLayers;
    int16_t ifl;
    int16_t i;
    FLEET * lpfl;
    int16_t cFlDestroyers;
    int16_t cFlArmadas;
    int16_t iLatestSBDefender;
    int32_t cExistCargo;
    int16_t iroCur;
    int16_t j;
    FLEET * lpflAttack;
    int16_t iLatestCargo;
    int16_t pctValueIdeal;
    int16_t ipl;
    int16_t * lpiHistSize;
    int16_t iBuilt;
    int16_t iLatestDestroyer;
    uint16_t cRecyclePeriod;
    int16_t ishdefLatestSB;
    int16_t pctValue;
    PLANET * lpplMac;
    CYBERINFO * lpciPlan;
    int32_t lNewPop;
    int16_t iLatestBattle;
    int16_t dOffsetPlanTemp;
    int16_t iAttackStr;
    CYBERINFOTEMP * lpciPlanTemp;
    int16_t idPlanDst;
    int16_t fWrite;
    int16_t fScrap;
    int16_t id;
    int16_t iStrDef;
    int16_t iSBDef;
    int16_t cFr;
    uint8_t * lpb;
    PLANET * lpplEnemy;
    uint8_t rgRecycleSBShdef[16];
    ORDER ord;
    SHDEF shdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AI4:0x0312 */
    /* block (block) @ MEMORY_AI4:0x0397 */
    /* block (block) @ MEMORY_AI4:0x047e */
    /* block (block) @ MEMORY_AI4:0x09aa */
    /* block (block) @ MEMORY_AI4:0x0cf1 */
    /* block (block) @ MEMORY_AI4:0x1293 */
    /* block (block) @ MEMORY_AI4:0x179f */
    /* block (block) @ MEMORY_AI4:0x1893 */
    /* block (block) @ MEMORY_AI4:0x18e6 */
    /* label LFinishProduction @ MEMORY_AI4:0x1a18 */

    /* TODO: implement */
}

int16_t FEnumPktAttack(PLANET *lpplSrc, PLANET *lpplTest)
{
    double dDistance;
    int16_t fTwoMA;
    double dMod;
    int16_t iWarp;
    int32_t * plMinMax;
    int32_t lMineral;
    int32_t lMinNeeded;
    CYBERINFO * lpciPlan;
    int16_t iWarpDst;
    int16_t dOffsetPlanTemp;
    double dDistanceTgt;

    /* TODO: implement */
    return 0;
}
