
#include "globals.h"
#include "types.h"

#include "ai.h"
#include "ai2.h"
#include "ai3.h"
#include "ai4.h"
#include "aiutil.h"
#include "file.h"
#include "log.h"
#include "memory.h"
#include "util.h"

/* globals */
uint8_t vrgAiRobotoidResOrder[36] = {0x42, 0x63, 0x23, 0x64, 0x02, 0x83, 0x46, 0x25, 0x66, 0xa4, 0x85, 0x06, 0x27, 0x6a, 0x06, 0x87, 0x2a, 0x49,
                                     0x4c, 0x6d, 0x2e, 0x70, 0x09, 0x8a, 0x50, 0xaa, 0x0f, 0x34, 0x54, 0x90, 0xac, 0x38, 0x93, 0x78, 0x16, 0x7a};
uint8_t vrgAiTurinDroneResOrder[31] = {0x42, 0x64, 0xa4, 0x04, 0x25, 0x46, 0x66, 0x28, 0x06, 0x86, 0x49, 0xa7, 0x68, 0x88, 0xa5, 0x69,
                                       0x07, 0x8a, 0x2a, 0x4c, 0x6b, 0x0a, 0x2c, 0x8d, 0x50, 0x2e, 0x6f, 0x8e, 0xaa, 0x30, 0x0e};
uint8_t vrgRobAip[301] = {
    0x08, 0x04, 0x0a, 0x0a, 0x0d, 0x09, 0x09, 0x08, 0x0a, 0x05, 0x04, 0x0d, 0x0c, 0x0f, 0x08, 0x0a, 0x04, 0x07, 0x0d, 0x0c, 0x0e, 0x08, 0x0a, 0x03, 0x03, 0x0d,
    0x0c, 0x0e, 0x08, 0x09, 0x01, 0x01, 0x0b, 0x0b, 0x0c, 0x08, 0x00, 0x09, 0x0a, 0x0d, 0x0b, 0x0c, 0x08, 0x09, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x08, 0x01, 0x09,
    0x0c, 0x0c, 0x0b, 0x0b, 0x08, 0x0a, 0x10, 0x10, 0x03, 0x0c, 0x02, 0x08, 0x10, 0x04, 0x03, 0x0e, 0x0c, 0x0d, 0x08, 0x03, 0x10, 0x0a, 0x10, 0x0c, 0x0e, 0x08,
    0x10, 0x01, 0x0b, 0x0c, 0x0a, 0x0a, 0x08, 0x10, 0x0b, 0x0c, 0x10, 0x01, 0x00, 0x08, 0x0a, 0x10, 0x10, 0x0b, 0x00, 0x00, 0x08, 0x0a, 0x0f, 0x04, 0x04, 0x08,
    0x09, 0x0b, 0x00, 0x00, 0x08, 0x04, 0x04, 0x04, 0x11, 0x12, 0x13, 0x08, 0x03, 0x03, 0x0e, 0x11, 0x12, 0x13, 0x08, 0x04, 0x03, 0x02, 0x11, 0x12, 0x14, 0x08,
    0x04, 0x04, 0x05, 0x11, 0x12, 0x14, 0x08, 0x00, 0x00, 0x0a, 0x11, 0x12, 0x13, 0x08, 0x00, 0x00, 0x0b, 0x11, 0x12, 0x13, 0x08, 0x01, 0x01, 0x0b, 0x11, 0x12,
    0x13, 0x08, 0x01, 0x01, 0x0b, 0x11, 0x12, 0x0b, 0x18, 0x15, 0x17, 0x17, 0x17, 0x0c, 0x0a, 0x18, 0x15, 0x16, 0x16, 0x16, 0x0c, 0x0a, 0x18, 0x1a, 0x19, 0x0a,
    0x08, 0x0b, 0x0a, 0x01, 0x01, 0x01, 0x01, 0x02, 0x09, 0x0b, 0x13, 0x08, 0x0d, 0x0a, 0x01, 0x01, 0x00, 0x00, 0x00, 0x09, 0x0b, 0x13, 0x08, 0x0d, 0x0a, 0x00,
    0x00, 0x01, 0x01, 0x00, 0x09, 0x0b, 0x13, 0x08, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x03, 0x09, 0x0b, 0x13, 0x08, 0x0d, 0x0a, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x09, 0x14, 0x13, 0x08, 0x0d, 0x0a, 0x04, 0x03, 0x03, 0x07, 0x02, 0x09, 0x14, 0x13, 0x08, 0x0d, 0x0a, 0x02, 0x03, 0x07, 0x07, 0x03, 0x09, 0x14, 0x13, 0x08,
    0x0d, 0x0a, 0x04, 0x04, 0x03, 0x03, 0x05, 0x09, 0x14, 0x13, 0x08, 0x21, 0x0a, 0x11, 0x0c, 0x21, 0x21, 0x08, 0x0d, 0x0a, 0x21, 0x21, 0x21, 0x21, 0x21, 0x11,
    0x14, 0x13, 0x08, 0x0a, 0x0a, 0x07, 0x05, 0x14, 0x14, 0x04, 0x04, 0x13, 0x04, 0x02, 0x03};
uint16_t vrgRobIshAip[38] = {0x0000, 0x0007, 0x000e, 0x0015, 0x001c, 0x0023, 0x002a, 0x0031, 0x0038, 0x003f, 0x0046, 0x004d, 0x0054,
                             0x005b, 0x0062, 0x0067, 0x006c, 0x0073, 0x007a, 0x0081, 0x0088, 0x008f, 0x0096, 0x009d, 0x00a4, 0x00ab,
                             0x00b2, 0x00b6, 0x00c1, 0x00cc, 0x00d7, 0x00e2, 0x00ed, 0x00f8, 0x0103, 0x010e, 0x0115, 0x0120};
uint8_t  vrgTDAip[141] = {0x08, 0x1f, 0x08, 0x1a, 0x00, 0x25, 0x08, 0x00, 0x00, 0x00, 0x09, 0x12, 0x0b, 0x08, 0x01, 0x01, 0x0b, 0x09, 0x12, 0x0b, 0x08,
                          0x25, 0x0f, 0x07, 0x04, 0x06, 0x09, 0x08, 0x0b, 0x0d, 0x00, 0x00, 0x00, 0x09, 0x08, 0x25, 0x0f, 0x07, 0x03, 0x06, 0x11, 0x08,
                          0x0b, 0x0d, 0x01, 0x01, 0x01, 0x11, 0x08, 0x0c, 0x25, 0x06, 0x03, 0x05, 0x03, 0x07, 0x09, 0x14, 0x14, 0x08, 0x0c, 0x25, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x09, 0x13, 0x0b, 0x08, 0x0c, 0x25, 0x06, 0x03, 0x04, 0x02, 0x07, 0x11, 0x14, 0x14, 0x08, 0x0c, 0x25,
                          0x01, 0x01, 0x01, 0x01, 0x01, 0x11, 0x13, 0x0b, 0x08, 0x0a, 0x10, 0x1b, 0x11, 0x00, 0x0d, 0x27, 0x0b, 0x08, 0x15, 0x16, 0x0c,
                          0x27, 0x08, 0x0a, 0x0c, 0x19, 0x19, 0x08, 0x25, 0x11, 0x00, 0x0d, 0x0b, 0x10, 0x1b, 0x08, 0x0d, 0x1c, 0x1c, 0x08, 0x0d, 0x1c,
                          0x1c, 0x1c, 0x1c, 0x08, 0x25, 0x10, 0x1a, 0x11, 0x0a, 0x0d, 0x13, 0x27, 0x00, 0x00, 0x00};
uint8_t  vrgTDIshAip[19] = {0x00, 0x02, 0x06, 0x0d, 0x14, 0x1b, 0x22, 0x29, 0x30, 0x3b, 0x46, 0x51, 0x5c, 0x65, 0x6a, 0x6f, 0x77, 0x7b, 0x81};

/* functions */
void DoAiTurn(int16_t iPlayer, uint16_t wMdPlr) {
    char       szExt[4];
    PROD       rgprod[64];
    int16_t    idSav;
    uint8_t   *lpbSavPlanet;
    PLANET   **lppplSavAi;
    int16_t    fLoaded;

    /* debug symbols */
    /* label Cleanup @ MEMORY_AI:0x0239 */

    idSav = idPlayer;
    fAi = 1;
    snprintf(szExt, sizeof(szExt), MPCTD, iPlayer + 1);
    DestroyCurGame();
    fLoaded = FLoadGame(szBase, szExt);
    lpbSavPlanet = vlpbAiPlanet;
    lppplSavAi = vrglpplAi;

    if (fLoaded) {
        if (!rgplr[idPlayer].fDead) {
            vlpbAiPlanet = LpAlloc(game.cPlanMax << 4, htMisc);
            vrglpplAi = LpAlloc(game.cPlanMax << 2, htMisc);

            if (vlpbAiData == NULL) {
                vlpbAiData = LpAlloc(0x2000, htMisc);
                if (vlpbAiData != NULL) {
                    vlpbAiData[0] = 2;
                    vlpbAiData[1] = 0;
                }
            }

            if (vlpbAiPlanet != NULL && vlpbAiData != NULL && vrglpplAi != NULL) {
                memset(vlpbAiPlanet, 0, game.cPlanMax << 4);
                ComputeShdefPowers();
                MarkPlanetsUnderAttack();
                IncreaseAIMinefieldSizes();
                InitRandomPlanetList();

                if (wMdPlr != 0xFFFF) {
                    rgplr[iPlayer].wMdPlr = wMdPlr;
                }

                switch (rgplr[iPlayer].idAi) {
                case 0:
                    DoRobotoidAiTurn(rgprod);
                    break;
                case 1:
                    DoTurinDroneAiTurn(rgprod);
                    break;
                case 2:
                    DoAutomitronAiTurn(rgprod);
                    break;
                case 3:
                    DoRototillAiTurn(rgprod);
                    break;
                case 4:
                    DoCyberAiTurn(rgprod);
                    break;
                case 5:
                    DoMacintiAiTurn(rgprod);
                    break;
                default:
                    break;
                case 7:
                    DoMaidAiTurn(rgprod);
                }
            }
        }

        FWriteLogFile(szBase, iPlayer);
        FWriteHistFile(iPlayer);

        if (vrglpplAi != NULL) {
            FreeLp(vrglpplAi, htMisc);
        }
        lppplSavAi = NULL;

        if (vlpbAiData != NULL) {
            vrglpplAi = lppplSavAi;
            FreeLp(vlpbAiPlanet, htMisc);
            FreeLp(vlpbAiData, htMisc);
            vlpbAiData = NULL;
            lpbSavPlanet = NULL;
            lppplSavAi = vrglpplAi;
        }
    }

    fAi = 0;
    vrglpplAi = lppplSavAi;
    vlpbAiPlanet = lpbSavPlanet;
    idPlayer = idSav;
}

int16_t FEnumCalcArmadaHumanDest(PLANET *lpplSrc, PLANET *lpplTest) {
    int16_t id;
    uint8_t b;
    int32_t l2;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x348a */

    /* TODO: implement */
    return 0;
}

void EnsureRobotoidShdefs(void) {
    int16_t ish;
    int16_t i;
    int16_t shBase;
    SHDEF   shdef;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x24ae */
    /* block (block) @ MEMORY_AI:0x2628 */
    /* block (block) @ MEMORY_AI:0x283b */

    /* TODO: implement */
}

int16_t FEnumCalcArmadaDest(PLANET *lpplSrc, PLANET *lpplTest) {
    int16_t id;
    uint8_t b;
    int32_t l2;

    /* debug symbols */
    /* block (block) @ MEMORY_AI:0x32e2 */

    /* TODO: implement */
    return 0;
}

void DoTurinDroneAiTurn(PROD *rgprod) {
    int32_t  rgResCost[4];
    int16_t  iLatestCruiser;
    int32_t  rgResAvail[4];
    FLEET   *lpflEnemy;
    int16_t  cExistCargo;
    int16_t  iLatestDestroyer;
    THING   *lpthWorm;
    PLANET  *lpplDest;
    uint8_t  rgRecycleShdef[16];
    int16_t  idPlanDst;
    int16_t  j;
    int16_t  iLatestLayer;
    ORDER    ord;
    PLANET  *lppl;
    int16_t  iLatestTroop;
    uint16_t rgCosts[4];
    PLANET  *lpplHome;
    FLEET   *lpflAttack;
    FLEET   *lpfl;
    int16_t  ifl;
    int16_t  i;
    FLEET   *lpflT;
    uint8_t  b;
    int16_t  cRes;
    int16_t  iroCur;
    int16_t  iLatestMiner;
    int16_t  iLatestCargo;
    int16_t  cplMiners;
    PLANET  *lpplMac;
    int16_t  ishdefSBLatest;
    int16_t  cplNegative;
    int16_t  ipl;
    uint16_t cRecyclePeriod;
    uint16_t cplanCol;
    int16_t  cFr;
    int16_t  cplBadGuy;
    int16_t  iLatestBattle;
    int16_t  iLatestBomber;
    int32_t  l;
    PROD    *lpprod;
    int16_t  fWrite;
    int16_t  iPlanet;
    uint8_t  bT;
    int16_t  pct;
    int16_t  id;

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

void EnsureTurinDroneShdefs(int16_t iroCur) {
    SHDEF   shdef;
    int16_t i;

    /* TODO: implement */
}

int16_t FEnumCalcMinerDest(PLANET *lpplSrc, PLANET *lpplTest) {
    int16_t id;
    uint8_t b;

    /* TODO: implement */
    return 0;
}

int16_t FEnumCalcEnemyFleets(FLEET *lpflSrc, FLEET *lpflTest) {

    /* TODO: implement */
    return 0;
}

int16_t IdTargetArmada(FLEET *lpfl) {
    int16_t cshWar;
    FLEET  *lpflTarget;
    PLANET *lpplTarget;
    ORDER   ord;
    int16_t ish;
    PLANET *lppl;
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

int16_t FEnumCalcColonistDrop(PLANET *lpplSrc, PLANET *lpplTest) {
    int16_t id;
    uint8_t bWant;
    uint8_t bEnemy;

    /* TODO: implement */
    return 0;
}

void DoRobotoidAiTurn(PROD *rgprod) {
    int32_t  rgResCost[4];
    FLEET   *lpflEnemy;
    int32_t  rgResAvail[4];
    int16_t  cExistCargo;
    int16_t  cFlDestroyers;
    int16_t  iLatestDestroyer;
    int16_t  cColFleet;
    THING   *lpthWorm;
    int16_t  idPlanDst;
    int16_t  j;
    uint8_t  rgRecycleShdef[16];
    int16_t  fShouldColonize;
    PLANET  *lppl;
    int16_t  ifl;
    int16_t  i;
    uint16_t rgCosts[4];
    FLEET   *lpflAttack;
    FLEET   *lpfl;
    PLANET  *lpplHome;
    int16_t  cRes;
    int16_t  iroCur;
    int16_t  iAiLvl;
    int16_t  iLatestCargo;
    int16_t  ipl;
    int16_t  fTonsOfMinerals;
    int16_t  ishdefSBLatest;
    PLANET  *lpplMac;
    int16_t  iLatestMeta;
    uint16_t cRecyclePeriod;
    int16_t  cFr;
    int16_t  iLatestBattle;
    int16_t  iPlanet;
    int16_t  iLatestBomber;
    int32_t  l;
    int16_t  fWrite;
    PROD    *lpprod;
    int16_t  id;
    int16_t  iLatest;
    int16_t  dy;
    PLANET  *lpplDrop;
    int32_t  lDist;
    uint8_t *lpb;
    int16_t  dx;
    uint8_t  rgRecycleSBShdef[16];
    ORDER    ord;

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

int16_t FPotentRobWarFleet(FLEET *lpfl, int16_t iPotency) {
    int16_t ish;
    int16_t cEquiv;

    /* TODO: implement */
    return 0;
}
