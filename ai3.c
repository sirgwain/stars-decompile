
#include "types.h"

#include "ai3.h"

/* globals */
uint8_t vrgAiMacintiResOrder[8];  /* MEMORY_AI3:0x0000 */
uint16_t vrgMacIshAip[31];  /* MEMORY_AI3:0x2a06 */
uint8_t vrgMacAip[248];  /* MEMORY_AI3:0x2a44 */

/* functions */
int16_t FPotentMacWarFleet(FLEET *lpfl, int16_t *pcEquiv)
{
    int16_t ish;
    int16_t cEquiv;

    /* debug symbols */
    /* label Success @ MEMORY_AI3:0x43f7 */

    /* TODO: implement */
    return 0;
}

void EnsureMacintiShdefs(void)
{
    int16_t ish;
    int16_t i;
    PART part;
    int16_t fAdvanced;
    int16_t shBase;
    SHDEF shdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AI3:0x2b6b */
    /* block (block) @ MEMORY_AI3:0x2e83 */
    /* block (block) @ MEMORY_AI3:0x2fe8 */
    /* block (block) @ MEMORY_AI3:0x30a5 */
    /* block (block) @ MEMORY_AI3:0x3319 */

    /* TODO: implement */
}

int16_t IdTargetMacFreighter(FLEET *lpfl)
{
    int32_t cMax;
    int32_t cColLeft;
    int16_t cResGainMost;
    int32_t cColHaul;
    int16_t cResGain;
    ORDER ord;
    PLANET * lpplHere;
    int16_t pctCapMost;
    int16_t pctCapHere;
    int16_t cResLost;
    PLANET * lppl;
    int16_t pctKilled;
    int16_t i;
    int32_t lDist;
    int16_t ipl;
    PLANET * lpplBest;
    int16_t iM;

    /* debug symbols */
    /* label LMoveToLpplBest @ MEMORY_AI3:0x395d */
    /* label LFindPickup @ MEMORY_AI3:0x3a22 */

    /* TODO: implement */
    return 0;
}

void TargetMacArmada(FLEET *lpfl)
{
    FLEET * lpflTarget;
    ORDER ord;
    int16_t cshBomb;
    PLANET * lppl;
    int16_t cshWar;
    PLANET * lpplTarget;

    /* debug symbols */
    /* label TargetPotentArmada @ MEMORY_AI3:0x3ff4 */
    /* label TargetEveryArmada @ MEMORY_AI3:0x4061 */
    /* label FinishTargeting @ MEMORY_AI3:0x40c1 */
    /* label LTryNewTarget @ MEMORY_AI3:0x3f49 */

    /* TODO: implement */
}

int16_t FRetargetMiner(FLEET *lpfl)
{
    int16_t cConc;
    ORDER ord;
    int16_t cConcBest;
    PLANET * lppl;
    int16_t cConcCur;
    int16_t ipl;
    PLANET * lpplBest;

    /* TODO: implement */
    return 0;
}

void DoMacintiAiTurn(PROD *rgprod)
{
    int16_t iLatestCargo;
    int16_t cColFleet;
    int32_t rgResCost[4];
    int16_t idPlanDst;
    int16_t j;
    FLEET * lpflEnemy;
    int32_t rgResAvail[4];
    PLANET * lpplMac;
    int16_t iLatestCruiser;
    int16_t ishLastBattle;
    THING * lpthWorm;
    int16_t cFlMineLayers;
    int16_t fShouldColonize;
    int16_t cFlDestroyers;
    int16_t cshDestroyer;
    int16_t iAiLvl;
    int16_t iLatestBattle;
    PLANET * lppl;
    int16_t cFlCargo;
    int16_t iLatestBomber;
    int16_t ifl;
    int16_t i;
    FLEET * lpfl;
    int16_t cGenesis;
    int16_t cFlArmadas;
    int16_t cRes;
    int16_t cFr;
    int16_t iroCur;
    int16_t iLatestMiner;
    int16_t fUsingTempColonizer;
    int16_t iLatestDestroyer;
    int16_t ipl;
    int16_t iLatestColony;
    uint16_t cRecyclePeriod;
    uint8_t rgRecycleShdef[16];
    uint8_t * lpb;
    int16_t cFlMineLayersBase;
    int16_t cFlMiners;
    uint16_t rgCosts[4];
    FLEET * lpflAttack;
    int16_t iPlanet;
    int32_t l;
    int16_t fWrite;
    int16_t fTonsOfMinerals;
    uint8_t rgRecycleSBShdef[10];
    PROD * lpprod;
    PART part;
    int16_t id;
    int16_t cConc;
    int16_t iLatest;
    int16_t dy;
    PLANET * lpplDest;
    int32_t cMine;
    PLANET * lpplDrop;
    int32_t lDist;
    int32_t lLeast;
    int16_t dx;
    PLANET * lpplBest;
    int16_t iplDest;
    ORDER ord;
    SHDEF shdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AI3:0x00b9 */
    /* block (block) @ MEMORY_AI3:0x033d */
    /* block (block) @ MEMORY_AI3:0x0b8c */
    /* block (block) @ MEMORY_AI3:0x119f */
    /* block (block) @ MEMORY_AI3:0x1361 */
    /* block (block) @ MEMORY_AI3:0x14d7 */
    /* block (block) @ MEMORY_AI3:0x160e */
    /* block (block) @ MEMORY_AI3:0x17fe */
    /* block (block) @ MEMORY_AI3:0x1aa2 */
    /* block (block) @ MEMORY_AI3:0x1c8b */
    /* block (block) @ MEMORY_AI3:0x1fc6 */
    /* block (block) @ MEMORY_AI3:0x2288 */
    /* label LTryCargo @ MEMORY_AI3:0x0f5b */
    /* label LAddBombers @ MEMORY_AI3:0x15b0 */
    /* label TryShip2 @ MEMORY_AI3:0x1153 */
    /* label LTryCruiser @ MEMORY_AI3:0x17ce */
    /* label FinishProd @ MEMORY_AI3:0x1a02 */
    /* label TryShip3 @ MEMORY_AI3:0x188d */
    /* label TryShip2b @ MEMORY_AI3:0x1315 */
    /* label LUpgradeMiner @ MEMORY_AI3:0x031e */
    /* label LRecycle @ MEMORY_AI3:0x2178 */

    /* TODO: implement */
}
