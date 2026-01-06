
#include "types.h"

#include "ai2.h"

/* globals */
uint8_t vrgISIshAip[19];  /* MEMORY_AI2:0x0064 */
uint8_t vrgISAip[182];  /* MEMORY_AI2:0x0078 */
uint8_t vrgAiISResOrder[18];  /* MEMORY_AI2:0x01ce */

/* functions */
void DoRototillAiTurn(PROD *rgprod)
{
    int32_t rgResCost[4];
    int32_t rgResAvail[4];
    FLEET * lpflEnemy;
    ORDER ord;
    PLANET * lpplDest;
    int16_t cplNegative;
    THING * lpthWorm;
    int16_t fColonyShipInQueue;
    int16_t idPlanDst;
    int16_t cplBadGuy;
    PLANET * lpplMac;
    PLANET * lppl;
    PLANET * lpplHome;
    FLEET * lpfl;
    int16_t ifl;
    int16_t i;
    int16_t iroCur;
    FLEET * lpflT;
    FLEET * lpflAttack;
    uint8_t b;
    int16_t ishdefSBLatest;
    int16_t fBomberInQueue;
    uint16_t cplanCol;
    int16_t j;
    PROD * lpprod;
    int16_t fWrite;
    int16_t iPlanet;
    uint8_t bT;

    /* debug symbols */
    /* block (block) @ MEMORY_AI2:0x1f75 */
    /* block (block) @ MEMORY_AI2:0x25a5 */
    /* label BestSpeed @ MEMORY_AI2:0x2ffb */
    /* label LBlowAwayOrders @ MEMORY_AI2:0x2402 */
    /* label LTryScouts @ MEMORY_AI2:0x2f69 */
    /* label LCheckForColDrop @ MEMORY_AI2:0x24f5 */
    /* label LTargetBomber @ MEMORY_AI2:0x2e53 */
    /* label LTryFighters @ MEMORY_AI2:0x2ff5 */
    /* label LTryFreighters @ MEMORY_AI2:0x2b33 */
    /* label LScrapFleet @ MEMORY_AI2:0x29ff */
    /* label LTryBombers @ MEMORY_AI2:0x2d17 */

    /* TODO: implement */
}

void DoAutomitronAiTurn(PROD *rgprod)
{
    int16_t cExistCargo;
    uint16_t rgCosts[4];
    int32_t rgResCost[4];
    int16_t iLatestCruiser;
    int32_t rgResAvail[4];
    FLEET * lpflEnemy;
    ORDER ord;
    uint8_t rgRecycleShdef[16];
    PLANET * lpplDest;
    int16_t cplNegative;
    THING * lpthWorm;
    int16_t cFr;
    int16_t idPlanDst;
    int16_t cplBadGuy;
    PLANET * lpplMac;
    PLANET * lppl;
    PLANET * lpplHome;
    FLEET * lpfl;
    int16_t ifl;
    int16_t i;
    int16_t cRes;
    int16_t iroCur;
    FLEET * lpflT;
    FLEET * lpflAttack;
    uint8_t b;
    int16_t ishdefSBLatest;
    uint16_t cRecyclePeriod;
    uint16_t cplanCol;
    int16_t iLatestCargo;
    int16_t iLatestBomber;
    int16_t j;
    int16_t iLatestBattle;
    int32_t l;
    PROD * lpprod;
    int16_t fWrite;
    int16_t iPlanet;
    int16_t id;

    /* debug symbols */
    /* block (block) @ MEMORY_AI2:0x084d */
    /* block (block) @ MEMORY_AI2:0x0946 */
    /* block (block) @ MEMORY_AI2:0x0f27 */
    /* label LTryScouts @ MEMORY_AI2:0x188b */
    /* label LCheckForColDrop @ MEMORY_AI2:0x0e77 */
    /* label LBlowAwayOrders @ MEMORY_AI2:0x103a */
    /* label LTargetBomber @ MEMORY_AI2:0x1775 */
    /* label LTryFighters @ MEMORY_AI2:0x190c */
    /* label FinishProd @ MEMORY_AI2:0x0d21 */
    /* label LScrapFleet @ MEMORY_AI2:0x11ea */
    /* label LTryFreighters @ MEMORY_AI2:0x1430 */
    /* label LTryBombers @ MEMORY_AI2:0x161f */
    /* label BestSpeed @ MEMORY_AI2:0x1912 */

    /* TODO: implement */
}

int16_t FPotentISWarFleet(FLEET *lpfl, int16_t iPotency)
{
    int16_t ish;
    int16_t cEquiv;

    /* TODO: implement */
    return 0;
}

void EnsureCAShdefs(int16_t iroCur)
{

    /* TODO: implement */
}

void EnsureISShdefs(int16_t iroCur)
{
    SHDEF shdef;
    int16_t i;

    /* TODO: implement */
}

void DoMaidAiTurn(PROD *rgprod)
{
    int32_t rgResCost[4];
    int32_t rgResAvail[4];
    int16_t iroCur;

    /* TODO: implement */
}
