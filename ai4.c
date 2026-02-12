
#include "types.h"

#include "ai4.h"
#include "globals.h"

/* globals */
uint8_t vrgAiCybertronResOrder[42] = {0x64, 0x42, 0x83, 0xa3, 0x23, 0x46, 0x66, 0x86, 0x0a, 0x6a, 0x48, 0x6d, 0x26, 0xa9,
                                      0x89, 0x27, 0x49, 0x70, 0x0e, 0x2b, 0x8c, 0xab, 0x4d, 0x72, 0x2f, 0x12, 0x91, 0x31,
                                      0x74, 0x51, 0xb2, 0x95, 0x17, 0x56, 0x75, 0x37, 0x5a, 0x9a, 0x1a, 0x3a, 0x7a, 0xba};
uint8_t vrgCyberAip[301] = {
    0x08, 0x04, 0x04, 0x12, 0x11, 0x12, 0x14, 0x08, 0x04, 0x04, 0x05, 0x11, 0x12, 0x14, 0x08, 0x04, 0x04, 0x04, 0x11, 0x12, 0x13, 0x08, 0x03, 0x03, 0x0e, 0x11,
    0x12, 0x13, 0x08, 0x04, 0x03, 0x02, 0x11, 0x12, 0x14, 0x08, 0x00, 0x00, 0x12, 0x11, 0x12, 0x13, 0x08, 0x00, 0x00, 0x0a, 0x11, 0x12, 0x13, 0x08, 0x00, 0x00,
    0x0b, 0x11, 0x12, 0x13, 0x08, 0x01, 0x01, 0x0b, 0x11, 0x12, 0x13, 0x08, 0x01, 0x01, 0x0b, 0x11, 0x12, 0x0b, 0x2c, 0x0a, 0x0f, 0x04, 0x04, 0x2c, 0x11, 0x0b,
    0x00, 0x00, 0x18, 0x1a, 0x19, 0x0a, 0x08, 0x15, 0x17, 0x17, 0x17, 0x0c, 0x0a, 0x08, 0x15, 0x16, 0x16, 0x16, 0x0c, 0x0a, 0x08, 0x0e, 0x0a, 0x21, 0x21, 0x21,
    0x21, 0x21, 0x11, 0x14, 0x13, 0x08, 0x12, 0x14, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x08, 0x14, 0x13, 0x04, 0x04, 0x0d, 0x11, 0x08,
    0x14, 0x13, 0x04, 0x03, 0x03, 0x11, 0x08, 0x14, 0x13, 0x03, 0x02, 0x0a, 0x11, 0x08, 0x13, 0x0b, 0x00, 0x00, 0x00, 0x11, 0x08, 0x13, 0x0b, 0x00, 0x00, 0x12,
    0x11, 0x08, 0x13, 0x0b, 0x00, 0x00, 0x0a, 0x11, 0x08, 0x13, 0x0b, 0x01, 0x01, 0x0b, 0x11, 0x08, 0x13, 0x0b, 0x01, 0x01, 0x00, 0x11, 0x08, 0x13, 0x0b, 0x01,
    0x01, 0x0a, 0x11, 0x08, 0x12, 0x0a, 0x02, 0x02, 0x03, 0x03, 0x02, 0x11, 0x14, 0x14, 0x08, 0x14, 0x0a, 0x02, 0x02, 0x03, 0x03, 0x02, 0x11, 0x14, 0x14, 0x08,
    0x12, 0x0a, 0x00, 0x00, 0x03, 0x03, 0x02, 0x11, 0x14, 0x0b, 0x08, 0x12, 0x0a, 0x01, 0x01, 0x00, 0x00, 0x01, 0x11, 0x0b, 0x0b, 0x08, 0x0b, 0x0a, 0x01, 0x01,
    0x00, 0x00, 0x01, 0x11, 0x0b, 0x0b, 0x08, 0x14, 0x0a, 0x01, 0x01, 0x02, 0x02, 0x01, 0x11, 0x0b, 0x0b, 0x08, 0x0b, 0x0a, 0x01, 0x01, 0x01, 0x01, 0x01, 0x11,
    0x0b, 0x0b, 0x08, 0x0b, 0x0b, 0x01, 0x01, 0x01, 0x14, 0x14, 0x02, 0x03, 0x03, 0x0f, 0x13, 0x08, 0x0b, 0x0b, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x13, 0x13,
    0x0f, 0x13, 0x08, 0x14, 0x14, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x13, 0x13, 0x0f, 0x13};
uint16_t vrgCyberIshAip[36] = {0x0000, 0x0007, 0x000e, 0x0015, 0x001c, 0x0023, 0x002a, 0x0031, 0x0038, 0x003f, 0x0046, 0x004b,
                               0x0050, 0x0054, 0x005b, 0x0062, 0x006d, 0x007a, 0x0081, 0x0088, 0x008f, 0x0096, 0x009d, 0x00a4,
                               0x00ab, 0x00b2, 0x00b9, 0x00c4, 0x00cf, 0x00da, 0x00e5, 0x00f0, 0x00fb, 0x0106, 0x0113, 0x0120};

/* functions */
int16_t FEnumDropOffStage2(PLANET *lpplSrc, PLANET *lpplTest) {
    CYBERINFOTEMP *lpciPlanTemp;
    int16_t        dOffsetPlanTemp;

    /* TODO: implement */
    return 0;
}

int16_t FEnumDropOffStage1(PLANET *lpplSrc, PLANET *lpplTest) {
    CYBERINFOTEMP *lpciPlanTemp;
    int16_t        dOffsetPlanTemp;

    /* TODO: implement */
    return 0;
}

int16_t FEnumNeedMinerals(PLANET *lpplSrc, PLANET *lpplTest) {
    double         dDistance;
    int16_t        iWarpSrc;
    int16_t        fTwoMA;
    int16_t        iMinLimit;
    CYBERINFO     *lpciPlan;
    int16_t        iWarpDst;
    CYBERINFOTEMP *lpciPlanTemp;
    int16_t        dOffsetPlanTemp;

    /* TODO: implement */
    return 0;
}

int16_t FFillProdMinesAndFactories(PLANET *lppl) {
    int32_t rgResCost[4];
    int32_t rgResAvail[4];
    int16_t iAddFactories;
    int16_t iAddMines;
    PROD    prod;
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
    PROD   *lpprod;
    int16_t cAdd;

    /* debug symbols */
    /* block (block) @ MEMORY_AI4:0x3204 */
    /* label LAdd @ MEMORY_AI4:0x3612 */

    /* TODO: implement */
    return 0;
}

void EnsureCyberAiShdefs(int16_t iroCur) {
    int16_t low;
    int16_t ish;
    int16_t ishCur;
    int16_t i;
    int16_t high;
    SHDEF   shdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AI4:0x4889 */
    /* label LBomber @ MEMORY_AI4:0x4cb5 */
    /* label LCruiser @ MEMORY_AI4:0x4c39 */

    /* TODO: implement */
}

int16_t iAddAttackFleet(PLANET *lppl, int16_t iAttackStr, int16_t iBestDestroyer, int16_t iBestBattle, int16_t iBestSBDefender) {
    int16_t fRet;
    int16_t iMaxFactories;
    int16_t iMaxMines;
    int16_t iRand;

    /* TODO: implement */
    return 0;
}

void TargetCyberArmada(FLEET *lpfl) {
    FLEET  *lpflTarget;
    ORDER   ord;
    PLANET *lppl;
    int16_t cshBomb;
    int16_t cshWar;
    PLANET *lpplTarget;

    /* debug symbols */
    /* label LTryNewTarget @ MEMORY_AI4:0x52b2 */
    /* label TargetPotentArmada @ MEMORY_AI4:0x5390 */
    /* label TargetEveryArmada @ MEMORY_AI4:0x53fd */
    /* label FinishTargeting @ MEMORY_AI4:0x545d */

    /* TODO: implement */
}

int16_t FAddPacketToQueue(PLANET *lppl) {
    int32_t rgResCost[4];
    int16_t iMineral;
    int32_t rgResAvail[4];

    /* TODO: implement */
    return 0;
}

int16_t FEnumCalcEnemyPlanets(PLANET *lpplSrc, PLANET *lpplTest) {
    if (lpplTest->iPlayer == idPlayer || lpplTest->iPlayer == -1)
        return 0;
    return 1;
}

void DoCyberPackets(void) {
    int16_t        fTwoMA;
    int32_t        rgResCost[4];
    int32_t        rgResAvail[4];
    int16_t        iWarp;
    PLANET        *lpplDst;
    PLANET        *lppl;
    int16_t        i;
    int16_t        ipl;
    int16_t        iWarpDst;
    CYBERINFO     *lpciPlan;
    PROD           rgprod[64];
    int16_t        dOffsetPlanTemp;
    int16_t        idPlanDst;
    CYBERINFOTEMP *lpciPlanTemp;
    int16_t        fWrite;
    int16_t        iPacketMax;
    int16_t        iMinLimit;
    int32_t       *plMinMax;
    CYBERINFO     *lpciPlanDst;
    int16_t        iPacketAdd;
    int32_t        lPackets;
    int32_t        lMineral;
    CYBERINFOTEMP *lpciPlanT;
    int16_t        cResLeft;
    int16_t        iWarpSrc;
    double         dDistance;
    double         dMod;
    int16_t        cPacket[3];
    int32_t        lMinNeeded;
    double         dDistanceTgt;
    int16_t        iMin;

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

int16_t IdGetBestScannerDest(PLANET *lppl, int16_t iDir) {
    int16_t iDistance;
    int16_t iWarp;
    PLANET *lpplDst;
    int16_t dAdjust;
    int16_t iSize;
    POINT   ptEdge;
    SCAN    scan;

    /* TODO: implement */
    return 0;
}

int16_t FEnumPickUp(PLANET *lpplSrc, PLANET *lpplTest) {

    /* TODO: implement */
    return 0;
}

int16_t iBuildCyberStarbase(PLANET *lppl) {
    int16_t ishdefSB;
    PROD    rgprod[64];

    /* TODO: implement */
    return 0;
}

void DoCyberFreighter(FLEET *lpfl, CYBERINFOTEMP *lpciPlanTemp) {
    ORDER   ord;
    PLANET *lpplDst;
    PLANET *lpplCur;
    int16_t fDropOff;
    int16_t idPlanDst;
    SCAN    scan;

    /* debug symbols */
    /* label LTarget @ MEMORY_AI4:0x3c32 */

    /* TODO: implement */
}

void FillProductionQueue(void) {
    PLANET *lppl;
    int16_t ipl;
    PROD    rgprod[64];

    /* TODO: implement */
}

void DoCyberAiTurn(PROD *rgprod) {
    int32_t        rgResCost[4];
    int16_t        cSBDefenderFleets;
    int32_t        rgResAvail[4];
    FLEET         *lpflEnemy;
    int32_t        cExistColony;
    int16_t        cFlMineLayers;
    uint8_t        rgRecycleShdef[16];
    PLANET        *lppl;
    int16_t        cMineLayers;
    int16_t        ifl;
    int16_t        i;
    FLEET         *lpfl;
    int16_t        cFlDestroyers;
    int16_t        cFlArmadas;
    int16_t        iLatestSBDefender;
    int32_t        cExistCargo;
    int16_t        iroCur;
    int16_t        j;
    FLEET         *lpflAttack;
    int16_t        iLatestCargo;
    int16_t        pctValueIdeal;
    int16_t        ipl;
    int16_t       *lpiHistSize;
    int16_t        iBuilt;
    int16_t        iLatestDestroyer;
    uint16_t       cRecyclePeriod;
    int16_t        ishdefLatestSB;
    int16_t        pctValue;
    PLANET        *lpplMac;
    CYBERINFO     *lpciPlan;
    int32_t        lNewPop;
    int16_t        iLatestBattle;
    int16_t        dOffsetPlanTemp;
    int16_t        iAttackStr;
    CYBERINFOTEMP *lpciPlanTemp;
    int16_t        idPlanDst;
    int16_t        fWrite;
    int16_t        fScrap;
    int16_t        id;
    int16_t        iStrDef;
    int16_t        iSBDef;
    int16_t        cFr;
    uint8_t       *lpb;
    PLANET        *lpplEnemy;
    uint8_t        rgRecycleSBShdef[16];
    ORDER          ord;
    SHDEF          shdef;

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

int16_t FEnumPktAttack(PLANET *lpplSrc, PLANET *lpplTest) {
    double     dDistance;
    int16_t    fTwoMA;
    double     dMod;
    int16_t    iWarp;
    int32_t   *plMinMax;
    int32_t    lMineral;
    int32_t    lMinNeeded;
    CYBERINFO *lpciPlan;
    int16_t    iWarpDst;
    int16_t    dOffsetPlanTemp;
    double     dDistanceTgt;

    /* TODO: implement */
    return 0;
}
