
#include "types.h"

#include "turn.h"

/* globals */
int16_t rgrgdmgMine[3][2];  /* MEMORY_TURN:0x4f3c */
int16_t rgrgdmgMinMine[3][2];  /* MEMORY_TURN:0x4f48 */
int16_t rgpctMineHit[3];  /* MEMORY_TURN:0x4f54 */
int16_t rgiWarpSafe[3];  /* MEMORY_TURN:0x4f5a */

/* functions */
void DoOrders(int16_t fPostMovement)
{
    PLANET * lppl;
    PLANET * lpplMac;

    /* TODO: implement */
}

void FuelFleets(void)
{
    int16_t j;
    int32_t cPods;
    PLANET * lppl;
    int16_t i;
    int16_t ifl;
    FLEET * lpfl;
    SHDEF * lpshdef;
    int32_t csh;
    HUL * lphul;

    /* debug symbols */
    /* label LChkFuelTransport @ MEMORY_TURN:0x306e */

    /* TODO: implement */
}

int16_t FGenerateTurn(void)
{
    int16_t fErrSav;
    char *pchT;
    int16_t ish;
    int16_t j;
    uint8_t mpiplr2[16];
    uint8_t rgfNoXFile[16];
    int16_t (* penvMemSav)[9];
    int16_t ifl;
    FLEET * lpfl;
    char *pchCur;
    int16_t i;
    int16_t env[9];
    char szT[256];
    uint16_t hcurSav;
    int16_t idCur;
    int16_t fFollow;
    char *pchBak;
    int16_t fSuccess;
    int16_t fDone;
    int16_t cAdv;
    int16_t dPlanRange;
    FLEET * lpflTarget;
    PLANET * lppl;
    int16_t dRange;
    int16_t iSteal;
    PLANET * lpplMac;
    int16_t pctDetect;
    ORDER ord;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN:0x09bf */
    /* block (block) @ MEMORY_TURN:0x0c59 */
    /* block (block) @ MEMORY_TURN:0x0f8c */
    /* block (block) @ MEMORY_TURN:0x1310 */
    /* label FreeStuffUp @ MEMORY_TURN:0x16a6 */
    /* label LUnmark @ MEMORY_TURN:0x0a8e */

    /* TODO: implement */
    return 0;
}

void MoveFleets(void)
{
    int32_t dTravel;
    int16_t cPass;
    int32_t wtFuel2Dest;
    double d;
    int16_t fGotEnufFuel;
    int16_t fRanOutOfFuel;
    ORDER * lpord;
    POINT ptEnd;
    int16_t ifl;
    FLEET * lpfl;
    double r;
    int32_t pct;
    int16_t dMineTravel;
    int32_t dRange;
    POINT ptBeg;
    int32_t wtFuelUsed;
    int32_t dActTravel;
    int32_t lFuelGain;
    int16_t fDone;
    SCAN scan;
    int16_t cKill;
    int16_t i;
    int16_t dy;
    int16_t iCtr;
    PLANET * lpplDst;
    int32_t cDie;
    int16_t ish;
    int16_t dx;
    int32_t lFuelGainAct;
    THING * lpthDest;
    int32_t wtColonists;
    double dyRound;
    THING * lpth;
    int16_t grbitPlr;
    PLANET * lpplSrc;
    int16_t fJumpgate;
    double dxRound;
    int16_t isbsDst;
    int16_t isbsSrc;
    POINT ptMsg;
    int32_t wtMinerals;
    FLEET flSrc;
    int16_t cTry;
    FLEET flDead;
    int16_t cKillTot;
    int16_t fDead;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN:0x354f */
    /* block (block) @ MEMORY_TURN:0x3eb5 */
    /* block (block) @ MEMORY_TURN:0x3f79 */
    /* block (block) @ MEMORY_TURN:0x457f */
    /* block (block) @ MEMORY_TURN:0x4686 */
    /* block (block) @ MEMORY_TURN:0x48df */
    /* block (block) @ MEMORY_TURN:0x49ed */
    /* block (block) @ MEMORY_TURN:0x4bb6 */
    /* block (block) @ MEMORY_TURN:0x4d1e */
    /* block (block) @ MEMORY_TURN:0x4d5b */
    /* label LNoGateNeeded @ MEMORY_TURN:0x36ab */
    /* label LMakeItToDest @ MEMORY_TURN:0x4983 */
    /* label MoveUnfinishedFleets @ MEMORY_TURN:0x32e9 */
    /* label LWarp10Kill @ MEMORY_TURN:0x4122 */

    /* TODO: implement */
}

int16_t FTravelThroughMineFields(FLEET *lpfl, int16_t *pdTravel, THING *lpthHit)
{
    int32_t d2Closest;
    int16_t rgishInc[16];
    int16_t dTravel;
    POINT ptAct;
    int16_t iWarp;
    POINT ptDst;
    int16_t dy;
    int32_t d2;
    int16_t j;
    int16_t dEnd;
    FLEET flSrc;
    int32_t dpsh;
    int16_t cshT;
    int32_t dmgReduce;
    int32_t dmgToApply;
    int16_t i;
    THING * lpth;
    int16_t dmgExtra;
    int16_t cshDamaged;
    int16_t fMineExpert;
    POINT ptSrc;
    int16_t iPlayer;
    int16_t cFields;
    int16_t dStart;
    FLEET flDead;
    THING * lpthMac;
    int32_t csh;
    int16_t rgi[3];
    int16_t pct;
    int32_t dmgTot;
    int16_t cshDead;
    int16_t rgcField[3];
    int16_t raMajor;
    int16_t dx;
    int32_t dpShield;
    int16_t iType;
    int16_t rgFieldE[3][8];
    THING * lpthClosest;
    int16_t cishInc;
    THING * lpthSalvage;
    int16_t fHasRamScoop;
    int16_t dmgPer;
    int16_t rgFieldS[3][8];
    int16_t cEngines;
    uint16_t ibit;
    int32_t dmgPerShip;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN:0x590c */
    /* block (block) @ MEMORY_TURN:0x6184 */
    /* label LHitSkip2 @ MEMORY_TURN:0x57f1 */
    /* label LHitSkip1 @ MEMORY_TURN:0x5591 */
    /* label LDoNext @ MEMORY_TURN:0x676d */
    /* label LFinishHit @ MEMORY_TURN:0x5d7f */

    /* TODO: implement */
    return 0;
}

void MoveThings(int16_t fPostProd)
{
    int16_t k;
    int16_t dUni;
    double d;
    POINT pt;
    int16_t iMax;
    POINT ptDst;
    int16_t dLeft;
    THING * lpth;
    int16_t fAnythingMoved;
    int16_t fMajorMove;
    int16_t idm;
    int16_t iLow;
    POINT ptSrc;
    THING * lpthMac;
    int16_t dRange;
    POINT ptBase;
    int16_t iX;
    int16_t rgC[2];
    int16_t rgwtTerra[3];
    double dyRound;
    int32_t wtTot;
    int16_t iWarp2;
    int16_t iWarp;
    int16_t fTerra;
    double dxRound;
    PLANET * lppl;
    int16_t wtCur;
    int16_t pctMinKeep;
    double r;
    int16_t fTwoMAs;
    int32_t lDefKilled;
    int32_t lColKilled;
    int16_t i;
    int16_t pctCaught;
    float pct;
    int32_t dmgRaw;
    int16_t iWarpPacket;
    int16_t iWarpPacket2;
    int16_t pctRate;
    int16_t iplr;
    THING * lpth2;
    THING * lpth2Mac;
    int16_t rgMin[3];
    int16_t cTerraPerm;
    int16_t cTerraTemp;
    int16_t rgMax[3];
    int16_t rgCost[3];

    /* debug symbols */
    /* block (block) @ MEMORY_TURN:0x1b40 */
    /* block (block) @ MEMORY_TURN:0x1da3 */
    /* block (block) @ MEMORY_TURN:0x1db9 */
    /* block (block) @ MEMORY_TURN:0x1ea7 */
    /* block (block) @ MEMORY_TURN:0x2215 */
    /* block (block) @ MEMORY_TURN:0x2d93 */
    /* block (block) @ MEMORY_TURN:0x2e01 */
    /* label LPacketAlreadyFreed @ MEMORY_TURN:0x2d88 */
    /* label LSpeedUpOnly @ MEMORY_TURN:0x1be2 */
    /* label LRetargetFreighter @ MEMORY_TURN:0x1b5c */
    /* label LAllSafe @ MEMORY_TURN:0x2950 */
    /* label MoveTh @ MEMORY_TURN:0x1d5a */
    /* label LFreeThePacket @ MEMORY_TURN:0x2d7a */
    /* label MadeItThere @ MEMORY_TURN:0x1da3 */

    /* TODO: implement */
}
