
#include "types.h"

#include "ai.h"

/* globals */
uint8_t vrgAiRobotoidResOrder[36];  /* MEMORY_AI:0x02ee */
uint16_t vrgRobIshAip[38];  /* MEMORY_AI:0x1f34 */
uint8_t vrgRobAip[301];  /* MEMORY_AI:0x1f80 */
uint8_t vrgTDIshAip[19];  /* MEMORY_AI:0x35ae */
uint8_t vrgTDAip[141];  /* MEMORY_AI:0x35c2 */
uint8_t vrgAiTurinDroneResOrder[31];  /* MEMORY_AI:0x3650 */

/* functions */
void DoAiTurn(int16_t iPlayer, uint16_t wMdPlr)
{
    char szExt[4];
    PROD rgprod[64];
    int16_t idSav;

    /* debug symbols */
    /* label Cleanup @ MEMORY_AI:0x0239 */

    /* TODO: implement */
}

int16_t FEnumCalcArmadaHumanDest(PLANET *lpplSrc, PLANET *lpplTest)
{
    int16_t id;
    uint8_t b;
    int32_t l2;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x348a */

    /* TODO: implement */
    return 0;
}

void EnsureRobotoidShdefs(void)
{
    int16_t ish;
    int16_t i;
    int16_t shBase;
    SHDEF shdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x24ae */
    /* block (block) @ MEMORY_AI:0x2628 */
    /* block (block) @ MEMORY_AI:0x283b */

    /* TODO: implement */
}

int16_t FEnumCalcArmadaDest(PLANET *lpplSrc, PLANET *lpplTest)
{
    int16_t id;
    uint8_t b;
    int32_t l2;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x32e2 */

    /* TODO: implement */
    return 0;
}

void DoTurinDroneAiTurn(PROD *rgprod)
{
    int32_t rgResCost[4];
    int16_t iLatestCruiser;
    int32_t rgResAvail[4];
    FLEET * lpflEnemy;
    int16_t cExistCargo;
    int16_t iLatestDestroyer;
    THING * lpthWorm;
    PLANET * lpplDest;
    uint8_t rgRecycleShdef[16];
    int16_t idPlanDst;
    int16_t j;
    int16_t iLatestLayer;
    ORDER ord;
    PLANET * lppl;
    int16_t iLatestTroop;
    uint16_t rgCosts[4];
    PLANET * lpplHome;
    FLEET * lpflAttack;
    FLEET * lpfl;
    int16_t ifl;
    int16_t i;
    FLEET * lpflT;
    uint8_t b;
    int16_t cRes;
    int16_t iroCur;
    int16_t iLatestMiner;
    int16_t iLatestCargo;
    int16_t cplMiners;
    PLANET * lpplMac;
    int16_t ishdefSBLatest;
    int16_t cplNegative;
    int16_t ipl;
    uint16_t cRecyclePeriod;
    uint16_t cplanCol;
    int16_t cFr;
    int16_t cplBadGuy;
    int16_t iLatestBattle;
    int16_t iLatestBomber;
    int32_t l;
    PROD * lpprod;
    int16_t fWrite;
    int16_t iPlanet;
    uint8_t bT;
    int16_t pct;
    int16_t id;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x3a3e */
    /* block (block) @ MEMORY_AI:0x3b04 */
    /* block (block) @ MEMORY_AI:0x4097 */
    /* block (block) @ MEMORY_AI:0x4195 */
    /* label LTargetBomber @ MEMORY_AI:0x565a */
    /* label LTryMinelayers @ MEMORY_AI:0x580e */
    /* label LScrapFleet @ MEMORY_AI:0x5135 */
    /* label LTryFreighters @ MEMORY_AI:0x5378 */
    /* label FinishProd @ MEMORY_AI:0x4863 */
    /* label LTryBombers @ MEMORY_AI:0x54f2 */
    /* label BestSpeed @ MEMORY_AI:0x5893 */
    /* label LBlowAwayOrders @ MEMORY_AI:0x4a70 */
    /* label LTryScouts @ MEMORY_AI:0x5770 */
    /* label LCheckForColDrop @ MEMORY_AI:0x4ba7 */

    /* TODO: implement */
}

void EnsureTurinDroneShdefs(int16_t iroCur)
{
    SHDEF shdef;
    int16_t i;

    /* TODO: implement */
}

int16_t FEnumCalcMinerDest(PLANET *lpplSrc, PLANET *lpplTest)
{
    int16_t id;
    uint8_t b;

    /* TODO: implement */
    return 0;
}

int16_t FEnumCalcEnemyFleets(FLEET *lpflSrc, FLEET *lpflTest)
{

    /* TODO: implement */
    return 0;
}

int16_t IdTargetArmada(FLEET *lpfl)
{
    int16_t cshWar;
    FLEET * lpflTarget;
    PLANET * lpplTarget;
    ORDER ord;
    int16_t ish;
    PLANET * lppl;
    int32_t cCol;
    int16_t cshBomb;
    int32_t pctDef;
    int32_t lPopUs;
    int32_t lPopEnemy;
    int32_t cXfer;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x2f38 */
    /* block (block) @ MEMORY_AI:0x306e */
    /* label LTryNewTarget @ MEMORY_AI:0x29a3 */
    /* label TargetPotentArmada @ MEMORY_AI:0x2bbe */
    /* label TargetEveryArmada @ MEMORY_AI:0x2c2b */
    /* label FinishTargeting @ MEMORY_AI:0x2c8b */

    /* TODO: implement */
    return 0;
}

int16_t FEnumCalcColonistDrop(PLANET *lpplSrc, PLANET *lpplTest)
{
    int16_t id;
    uint8_t bWant;
    uint8_t bEnemy;

    /* TODO: implement */
    return 0;
}

void DoRobotoidAiTurn(PROD *rgprod)
{
    int32_t rgResCost[4];
    FLEET * lpflEnemy;
    int32_t rgResAvail[4];
    int16_t cExistCargo;
    int16_t cFlDestroyers;
    int16_t iLatestDestroyer;
    int16_t cColFleet;
    THING * lpthWorm;
    int16_t idPlanDst;
    int16_t j;
    uint8_t rgRecycleShdef[16];
    int16_t fShouldColonize;
    PLANET * lppl;
    int16_t ifl;
    int16_t i;
    uint16_t rgCosts[4];
    FLEET * lpflAttack;
    FLEET * lpfl;
    PLANET * lpplHome;
    int16_t cRes;
    int16_t iroCur;
    int16_t iAiLvl;
    int16_t iLatestCargo;
    int16_t ipl;
    int16_t fTonsOfMinerals;
    int16_t ishdefSBLatest;
    PLANET * lpplMac;
    int16_t iLatestMeta;
    uint16_t cRecyclePeriod;
    int16_t cFr;
    int16_t iLatestBattle;
    int16_t iPlanet;
    int16_t iLatestBomber;
    int32_t l;
    int16_t fWrite;
    PROD * lpprod;
    int16_t id;
    int16_t iLatest;
    int16_t dy;
    PLANET * lpplDrop;
    int32_t lDist;
    uint8_t * lpb;
    int16_t dx;
    uint8_t rgRecycleSBShdef[16];
    ORDER ord;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x0586 */
    /* block (block) @ MEMORY_AI:0x0b11 */
    /* block (block) @ MEMORY_AI:0x0c66 */
    /* block (block) @ MEMORY_AI:0x0db2 */
    /* block (block) @ MEMORY_AI:0x1126 */
    /* block (block) @ MEMORY_AI:0x128b */
    /* block (block) @ MEMORY_AI:0x1443 */
    /* block (block) @ MEMORY_AI:0x166d */
    /* block (block) @ MEMORY_AI:0x16f7 */
    /* label TryShip3 @ MEMORY_AI:0x0f12 */
    /* label AtkMissions @ MEMORY_AI:0x1bfc */
    /* label TryShip2 @ MEMORY_AI:0x0af3 */
    /* label FinishProd @ MEMORY_AI:0x1088 */

    /* TODO: implement */
}

int16_t FPotentRobWarFleet(FLEET *lpfl, int16_t iPotency)
{
    int16_t ish;
    int16_t cEquiv;

    /* TODO: implement */
    return 0;
}
