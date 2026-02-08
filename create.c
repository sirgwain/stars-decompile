
#include "globals.h"
#include "types.h"

#include "create.h"
#include "file.h"
#include "port.h"
#include "mdi.h"
#include "memory.h"
#include "msg.h"
#include "parts.h"
#include "planet.h"
#include "race.h"
#include "resource.h"
#include "save.h"
#include "ship.h"
#include "thing.h"
#include "turn.h"
#include "util.h"
#include "utilgen.h"

/* On Win16, ICompLong used *(int*) which was 16-bit, so qsort on
 * STARSPOINT sorted by x only (the first field). On 32-bit platforms,
 * ICompLong reads 32 bits, giving a y-primary sort on little-endian.
 * This comparator preserves the original x-sort behavior. */
static int ICompStarsPointX(const void *a, const void *b) {
    int16_t xa = ((const STARSPOINT *)a)->x;
    int16_t xb = ((const STARSPOINT *)b)->x;
    return (xa > xb) - (xa < xb);
}

/* globals */
BTLPLAN rgbtlplanT[5] = {
    {.szName = "Default"}, {.szName = "Kill Starbase"}, {.szName = "Max-Defense"}, {.szName = "Sniper"}, {.szName = "Chicken"}}; /* 1078:000c */
char   rgNG3Width[9][2] = {{-3, 0}, {2, 1}, {5, 0}, {-3, 0}, {3, 0}, {3, 0}, {3, 0}, {1, 0}, {3, 0}};                            /* 1078:9d4c */
PLAYER vrgplrComp[6][4] = {
    {
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {-1, -1, -1},
         .rgEnvVarMin = {-1, -1, -1},
         .rgEnvVarMax = {-1, -1, -1},
         .pctIdealGrowth = 5,
         .pctResearch = 15,
         .rgAttr = {10, 12, 10, 16, 10, 5, 10, 0, 1, 1, 2, 1, 1, 0, 0, 0},
         .grbitAttr = 0x00001341},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {-1, -1, -1},
         .rgEnvVarMin = {-1, -1, -1},
         .rgEnvVarMax = {-1, -1, -1},
         .pctIdealGrowth = 6,
         .pctResearch = 15,
         .rgAttr = {9, 13, 9, 16, 10, 4, 11, 0, 1, 1, 2, 1, 1, 0, 0, 0},
         .grbitAttr = 0x00000341},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {-1, -1, -1},
         .rgEnvVarMin = {-1, -1, -1},
         .rgEnvVarMax = {-1, -1, -1},
         .pctIdealGrowth = 6,
         .pctResearch = 15,
         .rgAttr = {8, 13, 9, 18, 10, 4, 12, 0, 1, 2, 2, 2, 1, 0, 0, 0},
         .grbitAttr = 0x80000261},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {-1, -1, -1},
         .rgEnvVarMin = {-1, -1, -1},
         .rgEnvVarMax = {-1, -1, -1},
         .pctIdealGrowth = 7,
         .pctResearch = 15,
         .rgAttr = {8, 13, 9, 16, 10, 4, 8, 0, 1, 2, 1, 2, 1, 0, 0, 0},
         .grbitAttr = 0x80000261},
    },
    {
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {58, 35, 65},
         .rgEnvVarMin = {27, 7, 35},
         .rgEnvVarMax = {89, 63, 95},
         .pctIdealGrowth = 14,
         .pctResearch = 15,
         .rgAttr = {10, 9, 10, 9, 9, 5, 8, 0, 1, 0, 1, 1, 1, 0, 1, 0},
         .grbitAttr = 0x00002045},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {62, 33, 61},
         .rgEnvVarMin = {32, 6, 26},
         .rgEnvVarMax = {92, 60, 96},
         .pctIdealGrowth = 14,
         .pctResearch = 15,
         .rgAttr = {10, 10, 10, 10, 10, 5, 9, 0, 1, 1, 1, 1, 1, 1, 1, 0},
         .grbitAttr = 0x80002045},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {63, 28, 62},
         .rgEnvVarMin = {31, 4, 30},
         .rgEnvVarMax = {95, 52, 94},
         .pctIdealGrowth = 14,
         .pctResearch = 15,
         .rgAttr = {9, 11, 10, 10, 10, 5, 9, 0, 0, 1, 0, 1, 1, 1, 1, 0},
         .grbitAttr = 0x80002045},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {62, 29, -1},
         .rgEnvVarMin = {31, 5, -1},
         .rgEnvVarMax = {93, 53, -1},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {8, 15, 10, 25, 10, 5, 9, 0, 0, 0, 0, 0, 0, 0, 1, 0},
         .grbitAttr = 0xa0002045},
    },
    {
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {35, 60, 38},
         .rgEnvVarMin = {7, 26, 5},
         .rgEnvVarMax = {63, 94, 71},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {9, 11, 10, 14, 11, 6, 14, 1, 0, 0, 0, 0, 0, 0, 4, 0},
         .grbitAttr = 0x20000f10},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {35, 60, 38},
         .rgEnvVarMin = {7, 26, 5},
         .rgEnvVarMax = {63, 94, 71},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {8, 13, 9, 14, 10, 6, 14, 1, 0, 0, 0, 0, 0, 0, 4, 0},
         .grbitAttr = 0xa0000f10},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {35, 60, 38},
         .rgEnvVarMin = {7, 26, 5},
         .rgEnvVarMax = {63, 94, 71},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {8, 14, 9, 15, 14, 5, 15, 1, 0, 0, 0, 0, 0, 0, 4, 0},
         .grbitAttr = 0xa0000e10},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {35, -1, 50},
         .rgEnvVarMin = {7, -1, 0},
         .rgEnvVarMax = {63, -1, 100},
         .pctIdealGrowth = 16,
         .pctResearch = 15,
         .rgAttr = {8, 14, 9, 14, 14, 5, 14, 1, 0, 0, 0, 0, 0, 0, 4, 0},
         .grbitAttr = 0xa0000e10},
    },
    {
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {32, 31, 31},
         .rgEnvVarMax = {68, 69, 69},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {10, 10, 10, 10, 10, 5, 10, 1, 0, 0, 0, 0, 0, 2, 3, 0},
         .grbitAttr = 0x20001f02},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {32, 31, 31},
         .rgEnvVarMax = {68, 69, 69},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {8, 12, 10, 12, 14, 5, 12, 1, 0, 0, 0, 0, 0, 2, 3, 0},
         .grbitAttr = 0x20001e02},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {23, 24, 25},
         .rgEnvVarMax = {77, 76, 75},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {8, 12, 10, 12, 14, 5, 12, 1, 0, 0, 0, 0, 0, 2, 3, 0},
         .grbitAttr = 0x20001e02},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {-1, 50, 50},
         .rgEnvVarMin = {-1, 24, 25},
         .rgEnvVarMax = {-1, 76, 75},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {8, 15, 10, 15, 15, 5, 15, 1, 0, 0, 0, 0, 0, 2, 3, 0},
         .grbitAttr = 0x20001e02},
    },
    {
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {22, 22, 22},
         .rgEnvVarMax = {78, 78, 78},
         .pctIdealGrowth = 12,
         .pctResearch = 15,
         .rgAttr = {10, 9, 18, 9, 9, 10, 8, 1, 1, 0, 0, 1, 0, 0, 6, 0},
         .grbitAttr = 0x20000a03},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {19, 19, 19},
         .rgEnvVarMax = {81, 81, 81},
         .pctIdealGrowth = 17,
         .pctResearch = 15,
         .rgAttr = {10, 10, 13, 19, 10, 10, 7, 1, 1, 0, 0, 1, 1, 1, 6, 0},
         .grbitAttr = 0x20000e03},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {18, 18, 18},
         .rgEnvVarMax = {82, 82, 82},
         .pctIdealGrowth = 17,
         .pctResearch = 15,
         .rgAttr = {10, 14, 10, 20, 10, 10, 6, 1, 1, 1, 0, 1, 1, 2, 6, 0},
         .grbitAttr = 0xa0000e43},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {17, 17, 17},
         .rgEnvVarMax = {83, 83, 83},
         .pctIdealGrowth = 19,
         .pctResearch = 15,
         .rgAttr = {10, 15, 9, 25, 10, 10, 5, 1, 2, 2, 0, 2, 1, 1, 6, 0},
         .grbitAttr = 0xa0000e43},
    },
    {
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {20, 20, 20},
         .rgEnvVarMax = {80, 80, 80},
         .pctIdealGrowth = 10,
         .pctResearch = 15,
         .rgAttr = {16, 10, 10, 10, 10, 5, 10, 0, 1, 1, 1, 1, 0, 1, 8, 0},
         .grbitAttr = 0x0000011b},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {15, 15, 15},
         .rgEnvVarMax = {85, 85, 85},
         .pctIdealGrowth = 14,
         .pctResearch = 15,
         .rgAttr = {12, 10, 10, 10, 10, 5, 10, 0, 2, 1, 1, 1, 0, 1, 8, 0},
         .grbitAttr = 0x0000001b},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {15, 15, 15},
         .rgEnvVarMax = {85, 85, 85},
         .pctIdealGrowth = 17,
         .pctResearch = 15,
         .rgAttr = {10, 10, 10, 10, 10, 5, 10, 0, 2, 1, 1, 1, 1, 1, 8, 0},
         .grbitAttr = 0x0000007f},
        {.iPlayer = -1,
         .lSalt = -1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {15, 15, 15},
         .rgEnvVarMax = {85, 85, 85},
         .pctIdealGrowth = 20,
         .pctResearch = 15,
         .rgAttr = {10, 10, 10, 10, 10, 5, 10, 0, 2, 1, 1, 2, 1, 1, 8, 0},
         .grbitAttr = 0x0000007f},
    },
};
int16_t vrgvcMax[10] = {16, 18, 4, 19, 28, 49, 29, 87, 7, 47}; /* 1078:b5a8 */
uint8_t vrgWormholeMin[5] = {0x00, 0x01, 0x01, 0x03, 0x04};    /* 1078:0000 */
uint8_t vrgWormholeVar[5] = {0x03, 0x03, 0x05, 0x04, 0x05};    /* 1078:0006 */

/* functions */
int16_t CreateStartupShip(int16_t iplr, int16_t idPlanet, int16_t ishdef, int16_t fAddShdef) {
    SHDEF *lpshdef;
    FLEET *lpfl;

    if (fAddShdef) {
        // grab a starter ship from the templates
        int16_t ishMac = rgplr[iplr].cShDef++;
        SHDEF  *lpshdefT = LpshdefT();
        rglpshdef[iplr][ishMac] = lpshdefT[ishdef];
        rglpshdef[iplr][ishMac].ishdef = ishMac;
        ishdef = ishMac;
    }

    lpshdef = &rglpshdef[iplr][ishdef];
    lpshdef->cExist++;
    lpshdef->cBuilt++;

    lpfl = LpflNew(iplr, idPlanet);
    lpfl->rgcsh[ishdef] = 1;
    lpfl->rgwtMin[4] = LGetFleetStat(lpfl, grStatFuel);
    lpfl->iplan = 0;

    return ishdef;
}

int16_t GetVCCheck(GAME *pgame, VictoryCondition vc) { return (pgame->rgvc[vc] & 0x80) != 0; }

void InitBattlePlan(BTLPLAN *lpbtlplan, int16_t iplan, int16_t iplr) {
    *lpbtlplan = rgbtlplanT[iplan];
    lpbtlplan->iplr = iplr;
    if (game.fSinglePlr && iplan == 0) {
        lpbtlplan->iplrAttack = 3;
    }
}

void InitNewGame3() {
    // empty in decompile
}

void InitNewGamePlr(int16_t iStepMaxSoFar, int16_t lvlAi) {
    int16_t sVar2;
    int16_t i;

    uint8_t *plrType = (uint8_t *)vrgplrTypeNew;
    // TODO: not tested
    /*
     * The original `if` used the comma operator:
     *   (SetVCVal(...), iStepMaxSoFar < 1)
     *
     * Meaning:
     *   - Only call SetVCVal() if (iStepMaxSoFar < 2 && !fRCWReadOnly)
     *   - Enter the body only if iStepMaxSoFar < 1
     *   - BUT still call SetVCVal() even when iStepMaxSoFar == 1 (and then skip body)
     */
    if ((iStepMaxSoFar < 2) && (fRCWReadOnly == 0)) {
        SetVCVal((GAME *)&game, 9, (int16_t)(game.mdSize << 1));

        if (iStepMaxSoFar >= 1)
            return;
    } else {
        return;
    }

    /* Choose number of players based on universe size (mdSize) and AI level (lvlAi). */
    if (game.mdSize == 0) {
        if ((lvlAi == 3) && (Random(3) == 0))
            game.cPlayer = 3;
        else
            game.cPlayer = 2;
    } else if (game.mdSize == 1) {
        if ((lvlAi == 3) && (Random(4) == 0))
            game.cPlayer = 5;
        else if ((lvlAi < 2) || (Random((int16_t)(6 - lvlAi)) != 0))
            game.cPlayer = 3;
        else
            game.cPlayer = 4;
    } else if (game.mdSize == 2) {
        if ((lvlAi == 3) && (Random(10) == 0))
            game.cPlayer = 9;
        else if ((lvlAi == 3) && (Random(10) == 0))
            game.cPlayer = 5;
        else if ((lvlAi < 2) || (Random((int16_t)(7 - lvlAi)) != 0)) {
            if ((lvlAi < 2) || (Random((int16_t)(7 - lvlAi)) != 0))
                game.cPlayer = 7;
            else
                game.cPlayer = 6;
        } else {
            game.cPlayer = 8;
        }
    } else if (game.mdSize == 3) {
        if ((lvlAi == 3) && (Random(10) == 0)) {
            game.cPlayer = (int16_t)(Random(2) + 14);
        } else if ((lvlAi == 3) && (Random(10) == 0)) {
            game.cPlayer = (int16_t)(10 - Random(2));
        } else if ((lvlAi < 2) || (Random((int16_t)(7 - lvlAi)) != 0)) {
            if ((lvlAi < 2) || (Random((int16_t)(7 - lvlAi)) != 0))
                game.cPlayer = 12;
            else
                game.cPlayer = 11;
        } else {
            game.cPlayer = 13;
        }
    } else if (game.mdSize == 4) {
        if ((lvlAi == 3) && (Random(10) == 0)) {
            game.cPlayer = (int16_t)(0x0d - Random(3));
        } else if ((lvlAi < 2) || (Random((int16_t)(9 - lvlAi)) != 0)) {
            if ((lvlAi < 2) || (Random((int16_t)(7 - lvlAi)) != 0))
                game.cPlayer = 0x10;
            else
                game.cPlayer = 0x0f;
        } else {
            game.cPlayer = 0x0e;
        }
    }

    /*
     * Assign “new player type” bytes for AI players 1..cPlayer-1.
     * Index 0 is presumably reserved (human / special slot), so it’s never written here.
     *
     * The thresholds are integer math with truncation (as in the original).
     */
    i = 1;
    if (lvlAi == 0) {
        for (; i < game.cPlayer; i++) {
            if (i < (int16_t)(((game.cPlayer + 1) / 3) + 1))
                plrType[i] = 0x0b;
            else if (i < (int16_t)((((game.cPlayer + 1) * 2) / 3) + 1))
                plrType[i] = 0x0f;
            else if (i < (int16_t)((((game.cPlayer + 1) * 5) / 6) + 1))
                plrType[i] = 0x07;
            else
                plrType[i] = 0x1b;
        }
    } else if (lvlAi == 1) {
        for (; i < game.cPlayer; i++) {
            if (i < (int16_t)((((game.cPlayer + 5) * 2) / 7) + 1))
                plrType[i] = 0x27;
            else if (i < (int16_t)((((game.cPlayer - 1) * 3 + 6) / 7) + 1))
                plrType[i] = 0x23;
            else if (i < (int16_t)((((game.cPlayer - 1) * 4 + 6) / 7) + 1))
                plrType[i] = 0x2b;
            else if (i < (int16_t)((((game.cPlayer - 1) * 5 + 6) / 7) + 1))
                plrType[i] = 0x2f;
            else if (i < (int16_t)((((game.cPlayer - 1) * 6 + 6) / 7) + 1))
                plrType[i] = 0x33;
            else
                plrType[i] = 0x9b;
        }
    } else if (lvlAi == 2) {
        for (; i < game.cPlayer; i++) {
            if (i < (int16_t)((((game.cPlayer + 5) * 2) / 7) + 1))
                plrType[i] = 0x53;
            else if (i < (int16_t)((((game.cPlayer - 1) * 3 + 6) / 7) + 1))
                plrType[i] = 0x47;
            else if (i < (int16_t)((((game.cPlayer - 1) * 4 + 6) / 7) + 1))
                plrType[i] = 0x43;
            else if (i < (int16_t)((((game.cPlayer - 1) * 5 + 6) / 7) + 1))
                plrType[i] = 0x57;
            else if (i < (int16_t)((((game.cPlayer - 1) * 6 + 6) / 7) + 1))
                plrType[i] = 0x5b;
            else
                plrType[i] = 0x9b;
        }
    } else if (lvlAi == 3) {
        for (; i < game.cPlayer; i++) {
            if (i < (int16_t)(((game.cPlayer + 1) / 3) + 1))
                plrType[i] = 99;
            else if (i < (int16_t)((((game.cPlayer - 1) * 6 + 0x0b) / 0x0c) + 1))
                plrType[i] = 0x77;
            else if (i < (int16_t)((((game.cPlayer - 1) * 5 + 5) / 6) + 1))
                plrType[i] = 0x73;
            else
                plrType[i] = 0x7b;
        }
    }

    /*
     * Shuffle the AI type bytes for indices 1..cPlayer-1.
     * This is a Fisher–Yates style swap, but:
     *   - starts at i=1 (never touches slot 0)
     *   - uses a swap target in [i+1, cPlayer-1] (never swaps with itself)
     *   - stops at i < cPlayer-1 (leaves the last iteration-free)
     */
    for (i = 1; i < (int16_t)(game.cPlayer - 1); i++) {
        sVar2 = Random((int16_t)(game.cPlayer - i - 1)); /* 0..(cPlayer-i-2) */
        {
            uint8_t tmp = plrType[i];
            plrType[i] = plrType[i + 1 + sVar2];
            plrType[i + 1 + sVar2] = tmp;
        }
    }
}

int16_t GetVCVal(GAME *pgame, VictoryCondition vc, int16_t fRaw) {
    int16_t  c;
    int16_t  i;
    uint16_t val;

    val = pgame->rgvc[vc] & 0x7f;

    if (fRaw == 0) {
        switch ((VictoryCondition)vc) {

        case vcOwnsPercentPlanets:
            /* Owns % of all planets */
            val = val * 5 + 20;
            break;

        case vcAttainsTechLevel:
            /* Attains Tech X in Y fields (level) */
            val = val + 8;
            break;

        case vcAttainsTechFields:
            /* Number of tech fields */
            val = val + 2;
            break;

        case vcExceedsScore:
            /* Exceeds a score of X */
            val = val * 1000 + 1000;
            break;

        case vcExceedsSecondPlaceBy:
            /* Exceeds second place score by X */
            val = val * 10 + 20;
            break;

        case vcProductionCapacity:
        case vcOwnsCapitalShips:
            /* Production (thousands) or capital ships */
            val = val * 10 + 10;
            break;

        case vcHighestScoreAfterYears:
            /* Highest score after X years */
            val = val * 10 + 30;
            break;

        case vcMinYearsBeforeWin:
            /* Minimum years before winner declared */
            val = val * 10 + 30;
            break;

        case vcMeetsNumCriteria:
        default:
            /*
             * Clamp "N of selected criteria" to the number
             * of currently enabled criteria.
             *
             * Criteria are vc 0..7, excluding vcAttainsTechFields (2).
             */
            c = 0;
            for (i = 0; i < vcMeetsNumCriteria; i++) {
                if (i != vcAttainsTechFields && (pgame->rgvc[i] & 0x80) != 0) {
                    c++;
                }
            }
            if (c < (int16_t)val) {
                val = c;
            }
            break;
        }
    }

    return val;
}

void SetVCCheck(GAME *pgame, VictoryCondition vc, int16_t fChecked) {
    uint8_t hi;

    hi = (fChecked == 0) ? 0 : 0x80;
    pgame->rgvc[vc] = (uint8_t)((pgame->rgvc[vc] & 0x7f) | hi);
}

void CreateTutorWorld(void) {
    PLAYER *pplrComp;
    char   *pszFmt;
    int16_t i;

    memset(&game, 0, sizeof(GAME));
    game.cPlayer = 2;
    game.mdDensity = 0;
    game.mdSize = 0;
    game.mdStartDist = 1;
    game.fTutorial = 1;
    game.fBBSPlay = 1;
    game.fVisScores = 1;
    game.fNoRandom = 1;
    game.lid = 0x008CEF49;
    game.rgvc[7] = 0x80;
    game.rgvc[8] = 0x81;
    CchGetString(idsTutorialGame, game.szName);

    memcpy(&rgplr[0], &vrgplrDef[0], sizeof(PLAYER));
    CchGetString(idsHumanoid, rgplr[0].szName);
    sprintf(rgplr[0].szNames, "%ss", rgplr[0].szName);

    pplrComp = LpplrComp(1, 0);
    memcpy(&rgplr[1], pplrComp, sizeof(PLAYER));
    rgplr[1].fAi = 1;
    rgplr[1].lvlAi = 0;
    rgplr[1].idAi = 1;
    CchGetString(idsBerserker, rgplr[1].szName);

    Randomize(1234567890);

    for (i = 1; i < 3; i++) {
        pszFmt = PszGetCompressedString(idsSHD);
        sprintf(szWork, pszFmt, szBase, (int)i);
        remove(szWork);

        pszFmt = PszGetCompressedString(idsSXD);
        sprintf(szWork, pszFmt, szBase, (int)i);
        remove(szWork);
    }

    GenerateWorld(0);
}

void CreateTinyTestWorld(void) {
    PLAYER *pplrComp;
    char   *pszFmt;
    int16_t i;

    memset(&game, 0, sizeof(GAME));
    game.cPlayer = 2;
    game.mdDensity = 0;
    game.mdSize = 0;
    game.mdStartDist = 1;
    game.fTutorial = 0;
    game.fBBSPlay = 0;
    game.fVisScores = 0;
    game.fNoRandom = 0;
    SetVCCheck(&game, vcOwnsPercentPlanets, true);
    SetVCVal(&game, vcOwnsPercentPlanets, (60 - 20) / 5);
    SetVCCheck(&game, vcAttainsTechLevel, true);
    SetVCVal(&game, vcAttainsTechLevel, 26 - 8);
    SetVCCheck(&game, vcAttainsTechFields, true);
    SetVCVal(&game, vcAttainsTechFields, 4 - 2);
    strncpy(game.szName, "Tiny Test Game", sizeof(game.szName));

    memcpy(&rgplr[0], &vrgplrDef[0], sizeof(PLAYER));
    CchGetString(idsHumanoid, rgplr[0].szName);
    sprintf(rgplr[0].szNames, "%ss", rgplr[0].szName);

    pplrComp = LpplrComp(0, 1);
    memcpy(&rgplr[1], pplrComp, sizeof(PLAYER));
    rgplr[1].fAi = 1;
    rgplr[1].lvlAi = 1;
    rgplr[1].idAi = 0;
    CchGetString(idsHicardi, rgplr[1].szName);
    snprintf(rgplr[1].szNames, sizeof(rgplr[1].szNames), "%ss", rgplr[1].szName);

    Randomize(12345);

    rgplr[0].iPlrBmp = Random(game.cPlayer) == 0;

    for (i = 1; i < 3; i++) {
        pszFmt = PszGetCompressedString(idsSHD);
        sprintf(szWork, pszFmt, szBase, (int)i);
        remove(szWork);

        pszFmt = PszGetCompressedString(idsSXD);
        sprintf(szWork, pszFmt, szBase, (int)i);
        remove(szWork);
    }

    GenerateWorld(0);
}

int16_t SetVCVal(GAME *pgame, VictoryCondition vc, int16_t val) {
    int16_t cur;

    if (val < 0) {
        val = 0;
    } else if (vrgvcMax[vc] < val) {
        val = vrgvcMax[vc];
    }
    pgame->rgvc[vc] = (pgame->rgvc[vc] & 0x80) | (uint8_t)val;

    if (vc == 8) {
        cur = GetVCVal(pgame, 8, 0);
        if (cur != val) {
            pgame->rgvc[8] = (pgame->rgvc[8] & 0x80) | (uint8_t)cur;
            val = cur;
        }
    }
    return val;
}

int16_t GenerateWorld(int16_t fBatchMode) {
    int32_t    *pl;
    int16_t     iBest;
    int16_t     cKill;
    char        grUsed[128];
    MemJump    *penvMemSav;
    STARSPOINT *ppt;
    int16_t     raMajor;
    int16_t     k;
    STARSPOINT  pt;
    int16_t     fFound;
    int16_t     iMax;
    STARPACK    starpack;
    int16_t     dy;
    int16_t     dGalMinSq;
    int16_t     iLow;
    PLANET     *lppl;
    int16_t     iMin;
    int16_t     i;
    MemJump     env;
    int16_t     xOld;
    int16_t     iplrSingle;
    STARSPOINT *pptMax;
    int16_t     dMin;
    int16_t     ktLeft;
    SHDEF      *lpshdef;
    int32_t     lDistMax2;
    int32_t     lDistIdeal2;
    int16_t     rgi[16];
    int16_t     iNewLine;
    uint8_t    *pb;
    int16_t     dMax;
    int32_t     lDistMin2;
    int16_t     j;
    int16_t     cPlanMax;
    int16_t     dx;
    int16_t     cKillMax;
    STARSPOINT *pptT;
    int32_t     lBest;
    int32_t     l;
    int16_t     iT;
    int16_t     jj;
    int16_t     iTechMin;
    int16_t     pct10;
    int16_t     idHome; // shares stackspace with lpth, szExt
    int16_t     ishRet;
    THING      *lpth;     // shares stackspace with szExt, idhome
    char        szExt[4]; // shares stackspace with lpth, idhome
    uint16_t    idLast;
    THING      *lpthLast;
    PART        part;
    int16_t     cFit;
    HS         *lphs;
    PLANET     *lpplClosest;
    int16_t     chs;
    int16_t     cTry;
    POINT       ptHome;
    PLANET     *lpplPicked;
    int32_t     lDistCur2;
    int16_t     rgTry[5];

    // ------------------- Create Planets -----------------
    dGal = (int16_t)(game.mdSize * 400 + 400);
    dGalInv = (int16_t)(dGal + 2 * dGalOff);

    cPlanMax = (int16_t)((int32_t)dGal * (int32_t)dGal / 5000L);
    cPlanMax = (int16_t)(cPlanMax + (cPlanMax / 4) * (game.mdDensity - 1));
    if (game.mdDensity >= 3)
        cPlanMax = (int16_t)(cPlanMax + cPlanMax / 4);
    cPlanMax = min(cPlanMax, cPlanetAbsMax);

    dGalMinSq = (int16_t)(dGalMinDist * dGalMinDist);
    iMax = min((int16_t)(cPlanMax + cPlanMax / 7), cPlanetAbsMax);
    dx = dGalOff + 10;
    dy = dGal + 1 - 20;
    for (i = 0; i < iMax; i++) {
        rgptPlan[i].x = (int16_t)(dx + Random(dy));
        rgptPlan[i].y = (int16_t)(dx + Random(dy));
    }
    qsort((void *)rgptPlan, iMax, sizeof(STARSPOINT), ICompStarsPointX);

    pptMax = &rgptPlan[iMax];
    cKill = 0;
    for (ppt = rgptPlan; ppt < pptMax; ppt++) {
        if (ppt->y < 0)
            continue;

        pptT = ppt + 1;
        iNewLine = (int16_t)(ppt->x + dGalMinDist);

        for (; pptT < pptMax && pptT->x <= iNewLine; pptT++) {
            dy = (int16_t)abs(ppt->y - pptT->y);
            if (dy > dGalMinDist)
                continue;
            dx = (int16_t)(ppt->x - pptT->x);
            if (dx * dx + dy * dy <= dGalMinSq) {
                pptT->y = -100;
                cKill++;
            }
        }
    }

    cKillMax = (int16_t)(iMax - cPlanMax);
    while (cKill < cKillMax) {
        i = Random(iMax);
        if (rgptPlan[i].y < 0)
            continue;
        rgptPlan[i].y = -100;
        cKill++;
    }

    for (ppt = pptT = rgptPlan; ppt < pptMax; ppt++) {
        if (ppt->y >= 0)
            *pptT++ = *ppt;
    }

    cPlanMax = (int16_t)(iMax - cKill);

    // ------------------- Cluster Planets -----------------
    if (game.fClumping) {
        for (i = 0; i < cPlanMax; i++) {
            lBest = 10000000L;
            iBest = 0;

            j = Random(cPlanMax);
            pt.x = rgptPlan[j].x;
            pt.y = rgptPlan[j].y;

            for (k = 0; k < cPlanMax; k++) {
                if (k == j)
                    continue;
                dx = (int16_t)(pt.x - rgptPlan[k].x);
                dy = (int16_t)(pt.y - rgptPlan[k].y);
                l = (int32_t)dx * (int32_t)dx + (int32_t)dy * (int32_t)dy;
                if (l < lBest) {
                    lBest = l;
                    iBest = k;
                }
            }

            if (lBest > 12 * 12) {
                if (lBest > 40 * 40) {
                    rgptPlan[j].x = (int16_t)((rgptPlan[j].x + 2 * rgptPlan[iBest].x) / 3);
                    rgptPlan[j].y = (int16_t)((rgptPlan[j].y + 2 * rgptPlan[iBest].y) / 3);
                } else if (lBest > 25 * 25) {
                    rgptPlan[j].x = (int16_t)((rgptPlan[j].x + rgptPlan[iBest].x) / 2);
                    rgptPlan[j].y = (int16_t)((rgptPlan[j].y + rgptPlan[iBest].y) / 2);
                } else if (lBest > 18 * 18) {
                    rgptPlan[j].x = (int16_t)((2 * rgptPlan[j].x + rgptPlan[iBest].x) / 3);
                    rgptPlan[j].y = (int16_t)((2 * rgptPlan[j].y + rgptPlan[iBest].y) / 3);
                } else {
                    rgptPlan[j].x = (int16_t)((4 * rgptPlan[j].x + rgptPlan[iBest].x) / 5);
                    rgptPlan[j].y = (int16_t)((4 * rgptPlan[j].y + rgptPlan[iBest].y) / 5);
                }
            }
        }

        qsort((void *)rgptPlan, cPlanMax, sizeof(STARSPOINT), ICompStarsPointX);
    }

    // ------------------- Planet Names -----------------

    memset(grUsed, 0, 1024 / 8);
    Assert(cPlanMax < 1000);
    for (i = 0; i < cPlanMax; i++) {
        dx = Random(999);
        while (grUsed[dx >> 3] & bitTbl[dx & 7]) {
            dx++;
            if (dx >= 999 + (int16_t)game.fTutorial)
                dx = 0;
        }
        grUsed[dx >> 3] |= (char)bitTbl[dx & 7];
        rgidPlan[i] = dx;
    }

    // ------------------- Planet Stats -----------------

    cPlanet = cPlanMax;
    penvMemSav = penvMem;
    penvMem = &env;
    if (setjmp(env.env)) {
        DestroyCurGame();
        return 0;
    }
    lpPlanets = (PLANET *)LpAlloc((uint16_t)(sizeof(PLANET) * cPlanMax), htPlanets);
    memset(lpPlanets, 0, sizeof(PLANET) * cPlanMax);

    Assert(lpPlanets != NULL);

    for (i = 0, lppl = lpPlanets; i < cPlanMax; i++, lppl++) {
        lppl->id = i;
        lppl->iPlayer = iPlayerNil;
        lppl->det = detAll;
        lppl->iScanner = iPlanetPartNone;
        if (!game.fNoRandom)
            lppl->fArtifact = (Random(3) == 0);
        lppl->rgEnvVar[0] = (uint8_t)(1 + Random(90));
        lppl->rgEnvVar[0] = (uint8_t)(lppl->rgEnvVar[0] + Random(10));
        lppl->rgEnvVarOrig[0] = lppl->rgEnvVar[0];
        lppl->rgEnvVar[1] = (uint8_t)(1 + Random(90));
        lppl->rgEnvVar[1] = (uint8_t)(lppl->rgEnvVar[1] + Random(10));
        lppl->rgEnvVarOrig[1] = lppl->rgEnvVar[1];
        lppl->rgEnvVar[2] = lppl->rgEnvVarOrig[2] = (uint8_t)(1 + Random(99));
        if (game.fTutorial) {
            switch (i) {
            case 11: // Hack to make sure the AI has a relativly near by habitable planet.
                lppl->rgEnvVar[0] = (uint8_t)(lppl->rgEnvVar[0] + 20);
                lppl->rgEnvVarOrig[0] = lppl->rgEnvVar[0];
                break;
            case 5: // Hack to make sure the AI has a relativly near by habitable planet.
                for (j = 0; j < 3; j++) {
                    lppl->rgEnvVar[j] = (uint8_t)(lppl->rgEnvVar[j] - 5);
                    lppl->rgEnvVarOrig[j] = lppl->rgEnvVar[j];
                }
                break;
            }
        }
        for (j = 0; j < 3; j++) {
            if (game.fExtraFuel) // fExtraFuel is now 'unlimited minerals'
                lppl->rgMinConc[j] = 100;
            else {
                lppl->rgwtMin[j] = 0;
                lppl->rgMinConc[j] = (uint8_t)(Random(45) + Random(45) + 31);

                if (lppl->rgEnvVar[2] >= 90)
                    lppl->rgMinConc[j] = (uint8_t)(lppl->rgMinConc[j] + Random(99 - lppl->rgMinConc[j]) / 2);
            }

            lppl->rgpctMinLevel[j] = 0;
            lppl->rgwtMin[j] = 0;

            if (game.fBBSPlay && lppl->rgMinConc[j] < 40)
                lppl->rgMinConc[j] = (uint8_t)(lppl->rgMinConc[j] + 5);
        }

        if (game.fExtraFuel)
            iT = 100;
        else
            iT = Random(27);

        if (iT < 18) // Limit at least one mineral
        {
            if (iT >= 9) {
                jj = Random(30); // Gets around compiler wierdnesses
                j = Random(3);
                lppl->rgMinConc[j] = (uint8_t)(1 + jj);
            } else {
                iT++;
                while (iT < 16) {
                    jj = Random(30); // Gets around compiler wierdnesses
                    j = Random(3);
                    lppl->rgMinConc[j] = (uint8_t)(1 + jj);
                    iT = (int16_t)(iT << 1);
                }
            }
        }
    }

    // ------------------- Surface Minerals -----------------
    for (j = 0; j < 3; j++) {
        lpPlanets[0].rgwtMin[j] = (uint16_t)(Random((int16_t)lpPlanets[0].rgMinConc[j] * 10) + 10);
        if (lpPlanets[0].rgwtMin[j] < 200)
            lpPlanets[0].rgwtMin[j] = (uint16_t)(lpPlanets[0].rgwtMin[j] + 155 + Random(150));

        if (game.fBBSPlay)
            lpPlanets[0].rgwtMin[j] = (uint16_t)(lpPlanets[0].rgwtMin[j] + lpPlanets[0].rgwtMin[j] / 4);
    }

    // ------------------- Place players -----------------

    l = (int32_t)dGal * 6L; // Minimum distance allowed
    lDistIdeal2 = (int32_t)dGal * (int32_t)dGal / (int32_t)game.cPlayer - l;
    if (lDistIdeal2 < 0)
        lDistIdeal2 = 0;
    else
        lDistIdeal2 = lDistIdeal2 * 9 / 10; // Shave a bit off
    lDistIdeal2 = lDistIdeal2 * (int32_t)game.mdStartDist / 3L + l;
    lDistMin2 = lDistIdeal2 * 9 / 10;
    lDistMax2 = lDistIdeal2 * 7 / 6;

RetryAll:
    // Find a starting planet for player 0, preferring one near center of galaxy
    lBest = 100000000L;
    iMin = (int16_t)(dGal / 4 + dGalOff);
    dMax = (int16_t)((dGal * 3) / 4 + dGalOff);
    for (i = 0; i < 50; i++) {
        rgi[0] = Random(cPlanMax);
        pt.x = rgptPlan[rgi[0]].x;
        pt.y = rgptPlan[rgi[0]].y;

        if (pt.x < iMin)
            dx = (int16_t)(iMin - pt.x);
        else if (dMax < pt.x)
            dx = (int16_t)(pt.x - dMax);
        else
            dx = 0;

        if (pt.y < iMin)
            dy = (int16_t)(iMin - pt.y);
        else if (dMax < pt.y)
            dy = (int16_t)(pt.y - dMax);
        else
            dy = 0;

        if (dx == 0 && dy == 0)
            break;

        l = (int32_t)dy * (int32_t)dy + (int32_t)dx * (int32_t)dx;
        if (l < lBest) {
            iBest = rgi[0];
            lBest = l;
        }
    }
    if (i == 50) {
        rgi[0] = iBest;
    }

    // Set bounds for other player homeworlds based on player count
    if (game.cPlayer > 4) {
        dMin = (int16_t)(dGal / 20 + dGalOff);
        dMax = (int16_t)(muldiv_i16((int16_t)dGal, 19, 20) + dGalOff);
    } else if (game.cPlayer > 2) {
        dMin = (int16_t)(dGal / 10 + dGalOff);
        dMax = (int16_t)(muldiv_i16((int16_t)dGal, 9, 10) + dGalOff);
    } else {
        dMin = (int16_t)(muldiv_i16((int16_t)dGal, 3, 20) + dGalOff);
        dMax = (int16_t)(muldiv_i16((int16_t)dGal, 17, 20) + dGalOff);
    }

    // ------------------- Place player homeworlds -----------------
    for (i = 1; i < game.cPlayer; i++) {
        // Try random positions first
        for (j = 0; j < 50; j++) {
            rgi[i] = Random(cPlanMax);
            pt.x = rgptPlan[rgi[i]].x;
            pt.y = rgptPlan[rgi[i]].y;

            // Check if within bounds
            if (dMin <= pt.x && dMin <= pt.y && pt.x <= dMax && pt.y <= dMax) {
                fFound = 0;

                // Check distance from all previously placed players
                for (k = 0; k < i; k++) {
                    dx = (int16_t)(pt.x - rgptPlan[rgi[k]].x);
                    dy = (int16_t)(pt.y - rgptPlan[rgi[k]].y);
                    l = (int32_t)dy * (int32_t)dy + (int32_t)dx * (int32_t)dx;

                    if (l < 1 || l < lDistMin2)
                        break; // Too close
                    if (l <= lDistMax2)
                        fFound = 1; // Within acceptable range
                }

                if (k == i && fFound)
                    break; // Found valid position
            }
        }

        // If random search failed, try sequential search
        if (j == 50) {
            int16_t start = rgi[i];

            for (;;) {
                /* find a candidate point index within bounds */
                for (;;) {
                    rgi[i]++;

                    if (rgi[i] == start) {
                        break; /* no progress -> widen + RetryAll */
                    }
                    if (rgi[i] >= cPlanMax) {
                        rgi[i] = 0;
                        if (start == 0) {
                            break; /* no progress -> widen + RetryAll */
                        }
                    }

                    pt = rgptPlan[rgi[i]];
                    if (pt.x >= dMin && pt.y >= dMin && pt.x <= dMax && pt.y <= dMax) {
                        break; /* have in-bounds pt; now check distances */
                    }
                    /* else keep incrementing rgi[i] */
                }

                /* this corresponds to LAB_1078_1566 */
                if (rgi[i] == start) {
                    int32_t delta = (int32_t)(lDistIdeal2 / 0x23L);
                    lDistMin2 -= delta;
                    lDistMax2 += delta;
                    goto RetryAll;
                }

                fFound = 0;
                for (k = 0; k < i; k++) {
                    dx = (int16_t)(pt.x - rgptPlan[rgi[k]].x);
                    dy = (int16_t)(pt.y - rgptPlan[rgi[k]].y);

                    /* keep original “unsigned mul then add” behavior:
                       dx,dy are sign-extended to 32-bit, then treated as unsigned by __aFulmul.
                       In practice squaring gives same bits; the important part is 32-bit wrap. */
                    l = (int32_t)((uint32_t)(dx * dx) + (uint32_t)(dy * dy));

                    if (l < 1 || l < lDistMin2)
                        break;
                    if (l <= lDistMax2)
                        fFound = 1;
                }

                if (k == i && fFound)
                    break; /* success */
                /* else retry (jump back to LAB_1078_13a1 equivalent) */
            }
        }
    }

    // ------------------- Player tech levels -----------------

    for (i = 0; i < game.cPlayer; i = i + 1) {
        int16_t pick;
        int16_t iMajorAdv;
        int16_t minTech;
        PLAYER *pplr;

        /* Shuffle rgi[] (Fisher–Yates style, forward) */
        pick = Random(game.cPlayer - i);
        j = pick + i;
        pick = rgi[j];
        rgi[j] = rgi[i];
        rgi[i] = pick;

        pplr = &rgplr[i];

        /* If AI player, generate a random race */
        if (GetRaceGrbit(pplr, ibitRaceAIPlayer) != 0) {
            CreateRandomRace(pplr);
        }

        /* Clear specific player flags */
        pplr->fDead = 0;    /* mask 0xfffeffff -> clears bit 16 => wFlags bit 0 */
        pplr->fLearned = 0; /* mask 0xfff7ffff -> clears bit 19 => wFlags bit 3 */

        /* Reset trader bits */
        pplr->grbitTrader = 0;

        /* Zero starting tech levels + spent resources */
        for (j = 0; j < 6; j = j + 1) {
            pplr->rgTech[j] = 0;
            pplr->rgResSpent[j] = 0;
        }

        /* Apply major advantage starting tech */
        iMajorAdv = GetRaceStat(pplr, rsMajorAdv);
        switch (iMajorAdv) {
        case raStealth:
            pplr->rgTech[Electronics] = 5;
            break;
        case raAttack:
            pplr->rgTech[Weapons] = 6;
            pplr->rgTech[Propulsion] = 1;
            pplr->rgTech[Energy] = 1;
            break;
        case raTerra:
            pplr->rgTech[Biotechnology] = 6;
            pplr->rgTech[Construction] = 2;
            pplr->rgTech[Energy] = 1;
            pplr->rgTech[Weapons] = 1;
            pplr->rgTech[Propulsion] = 1;
            break;
        case raMines:
            pplr->rgTech[Propulsion] = 2;
            pplr->rgTech[Biotechnology] = 2;
            break;
        case raMassAccel:
            pplr->rgTech[Energy] = 4;
            break;
        case raStargate:
            pplr->rgTech[Propulsion] = 5;
            pplr->rgTech[Construction] = 5;
            break;
        case raMacintosh:
            pplr->rgTech[Energy] = 1;
            break;
        case raNone:
            for (j = 0; j < 6; j = j + 1) {
                pplr->rgTech[j] = 3;
            }
            break;
        default:
            break;
        }

        /* Tech 3: raise lows to minTech when no per-field bonus is present */
        if (GetRaceGrbit(pplr, ibitRaceTech3) != 0) {
            iMajorAdv = GetRaceStat(pplr, rsMajorAdv);
            minTech = (int16_t)(((iMajorAdv == 9) ? 1 : 0) + 3); /* 3 normally, 4 if MA==9 */

            for (j = 0; j < 6; j = j + 1) {
                if ((int16_t)pplr->rgTech[j] < minTech) {
                    if (GetRaceStat(pplr, (int16_t)(j + rsTechBonus1)) == 0) {
                        pplr->rgTech[j] = (int8_t)minTech;
                    }
                }
            }
        }

        /* Cheap Engines: +1 Propulsion (rgTech[2]) */
        if (GetRaceGrbit(pplr, ibitRaceCheapEngines) != 0) {
            pplr->rgTech[Propulsion] = (int8_t)(pplr->rgTech[Propulsion] + 1);
        }

        /* IFE: +1 Propulsion unless tutorial game */
        if ((GetRaceGrbit(pplr, ibitRaceIFE) != 0) && (game.fTutorial == 0)) {
            pplr->rgTech[Propulsion] = (int8_t)(pplr->rgTech[Propulsion] + 1);
        }

        /* Send startup tips */
        for (j = 0; j < 4; j = j + 1) {
            FSendPlrMsg(i, (int16_t)(j + idmTipCanHideUnimportantMessagesClickingCheckmark), -1, 0, 0, 0, 0, 0, 0, 0);
        }
    }

    // ------------------- Player homeworld minerals -----------------

    for (i = 0; i < game.cPlayer; i = i + 1) {
        PLANET *plHome;
        PLAYER *pplr;

        iMin = rgi[i];
        plHome = &lpPlanets[iMin];
        pplr = &rgplr[i];

        /* assign owner */
        plHome->iPlayer = i;
        plHome->fHomeworld = 1;

        /* wRaw_0004: set starbase flag */
        plHome->fStarbase = 1;

        /* lStarbase union: clear low 4 bits (isb) */
        plHome->isb = 0;

        /* clear artifact bit in dwRaw_0014 */
        plHome->fArtifact = 0;

        /* set factories/mines/defenses via bitfields */
        plHome->cFactories = 10;
        plHome->cMines = 10;
        plHome->cDefenses = 10;

        // after assigning owner/homeworld/starbase...

        // Set initial population like the original (offset +0x28 = rgwtMin[3]).
        if (GetRaceGrbit(pplr, ibitRaceLowStartingPop) != 0) {
            plHome->rgwtMin[3] = 175;
        } else {
            plHome->rgwtMin[3] = 250;
        }

        // Then derive pop guess from that population.
        plHome->uPopGuess = (uint16_t)(plHome->rgwtMin[3] / 4); // 0xAF/4=43, 0xFA/4=62

        /* setup pop guess amount */
        plHome->uPopGuess = plHome->rgwtMin[3] / 4;

        for (j = 0; j < 3; j = j + 1) {
            /* copy mineral weights from planet 0 template into this homeworld */
            plHome->rgwtMin[j] = lpPlanets[0].rgwtMin[j];

            /* clamp minimum concentrations on homeworld */
            if (game.fTutorial == 0) {
                plHome->rgMinConc[j] = (lpPlanets[0].rgMinConc[j] < 30) ? 30 : lpPlanets[0].rgMinConc[j];
            } else {
                plHome->rgMinConc[j] = (lpPlanets[0].rgMinConc[j] < 25) ? 25 : lpPlanets[0].rgMinConc[j];
            }
        }

        /* decompile did (&0xfffe0fff) on dwRaw_0014: this is "clear iScanner bitfield" */
        plHome->iScanner = 0;

        FSendPlrMsg(i, idmHomePlanetPeopleReadyLeaveNestExplore, iMin, iMin, 0, 0, 0, 0, 0, 0);

        // cap advantage points at 50
        iT = min(50, CAdvantagePoints(pplr));

        // boost pop for hard ai players
        if ((pplr->fAi != 0) && (pplr->lvlAi > 2)) {
            iT = 50;
            plHome->rgwtMin[3] = plHome->rgwtMin[3] + (plHome->rgwtMin[3] / 10);
        }

        if (game.fBBSPlay) {
            int16_t pctGrowth = PctTrueMaxGrowth(i);
            int16_t scale10 = (int16_t)(pctGrowth * 2 + 10);

            plHome->rgwtMin[3] = (plHome->rgwtMin[3] * scale10) / 10;

            plHome->uPopGuess <<= 2;
        }

        j = GetRaceStat(pplr, rsUseLeftover);

        switch (j) {
        case 0: /* Surface minerals */
        default: {
            int16_t  iLow;
            int16_t  ktLeft16;
            int16_t  shareAll16;
            uint16_t rem2;

            if (plHome->rgwtMin[0] < plHome->rgwtMin[1]) {
                iLow = (plHome->rgwtMin[0] < plHome->rgwtMin[2]) ? 0 : 2;
            } else {
                iLow = (plHome->rgwtMin[1] < plHome->rgwtMin[2]) ? 1 : 2;
            }

            ktLeft16 = (int16_t)(iT * 10);
            rem2 = (uint16_t)ktLeft16 & 3u;
            shareAll16 = (int16_t)(ktLeft16 >> 2);

            plHome->rgwtMin[iLow] += (int32_t)(shareAll16 + (int16_t)rem2);

            ktLeft16 = shareAll16;
            plHome->rgwtMin[0] += ktLeft16;
            plHome->rgwtMin[1] += ktLeft16;
            plHome->rgwtMin[2] += ktLeft16;

            /* Explicit jump, matching original JMP CREATE::LConcentrations */
            if (pplr->fAi && pplr->lvlAi >= 2)
                goto LConcentrations;

            break;
        }

        case 1: /* Mineral concentrations */
        LConcentrations: {
            int16_t ktLeft;

            if (iT > 0 && iT < 3)
                ktLeft = 1;
            else
                ktLeft = (int16_t)(iT / 2);

            iLow = 0;
            for (jj = 1; jj < 3; jj++) {
                if (plHome->rgMinConc[jj] < plHome->rgMinConc[iLow])
                    iLow = jj;
            }

            plHome->rgMinConc[iLow] = (uint8_t)(plHome->rgMinConc[iLow] + ktLeft);

            ktLeft = (int16_t)((ktLeft + 1) / 2);

            plHome->rgMinConc[0] = (uint8_t)(plHome->rgMinConc[0] + ktLeft);
            plHome->rgMinConc[1] = (uint8_t)(plHome->rgMinConc[1] + ktLeft);
            plHome->rgMinConc[2] = (uint8_t)(plHome->rgMinConc[2] + ktLeft);

            break;
        }

        case 2: /* Mines */
            plHome->cMines += (uint32_t)(int16_t)(iT >> 1);
            break;

        case 3: /* Factories */
            plHome->cFactories += (uint32_t)(iT / 5);
            break;

        case 4: /* Defenses */
            plHome->cDefenses += (uint32_t)((iT + 5) / 10);
            break;
        }

        // zero out mines/factories/defenses for
        if (GetRaceStat(pplr, rsMajorAdv) == raMacintosh) {
            plHome->cMines = 0;
            plHome->cFactories = 0;
            plHome->cDefenses = 0;
        }

        /* Assign player index and home planet */
        pplr->iPlayer = (int8_t)i;
        pplr->idPlanetHome = iMin;

        /* Initialize planet environmental variables (current + original) */
        for (jj = 0; jj < 3; jj++) {
            int16_t v;

            if (pplr->rgEnvVarMax[jj] == -1) {
                /* Random(99) returns 0..98, then +1 => 1..99 */
                v = (int16_t)(Random(99) + 1);
            } else {
                /* midpoint = min + (max - min)/2, signed truncation */
                v = (int16_t)pplr->rgEnvVarMin[jj] + (int16_t)(((int16_t)pplr->rgEnvVarMax[jj] - (int16_t)pplr->rgEnvVarMin[jj]) / 2);
            }

            plHome->rgEnvVar[jj] = (uint8_t)v;
            plHome->rgEnvVarOrig[jj] = (uint8_t)v;
        }

        /* Non-AI players start with fixed research allocation */
        if (!pplr->fAi) {
            pplr->pctResearch = 0x0F;
        }

        /*
         * Initialize current research tech.
         *
         * The Win16 code:
         *   - clears low nibble
         *   - clears high nibble
         *   - ORs 0x60
         *
         * Net result is always exactly 0x60, regardless of prior value.
         */
        pplr->iTechCur = 0x60;

        /* Clear per-player yearly resources and score */
        pplr->lResLastYear = 0;
        pplr->wScore = 0;

        for (j = 0; j < game.cPlayer; j++) {
            pplr->rgmdRelation[j] = 0;
        }

        /* Player i starts with exactly 1 starbase design slot in use. (Preserve cFleet.) */
        pplr->cshdefSB = 1;

        /* Allocate 10 SHDEF entries for this player's starbase designs. */
        lpshdef = (SHDEF *)LpAlloc((uint16_t)(10 * (int16_t)sizeof(SHDEF)), htShips);

        /* Copy the built-in SBT template for the first 4 entries (0x24c == 4 * 0x93). */
        memmove(lpshdef, LpshdefSBT(), (size_t)(4 * sizeof(SHDEF)));

        /* Zero the remaining 6 entries (0x372 == 6 * 0x93). */
        memset((uint8_t *)lpshdef + 4 * sizeof(SHDEF), 0, (size_t)(6 * sizeof(SHDEF)));

        /* Entry 0 starts as "built/exist = 1". */
        lpshdef[0].cBuilt = 1;
        lpshdef[0].cExist = 1;

        /* Publish the per-player starbase design list pointer. */
        rglpshdefSB[i] = lpshdef;

        /* Mark entries 1..9 as free (sets bit 0x0200 in wFlags => fFree). */
        for (j = 1; j < 10; j++) {
            lpshdef[j].fFree = 1;
        }

        raMajor = GetRaceStat(pplr, rsMajorAdv);

        if (raMajor == raMassAccel) {
            /* Set slot0 iItem = 7; and set cItem bit0 (matches OR 0x100). */
            lpshdef[0].hul.rghs[0].iItem = ispecialSBMassDriver5;
            lpshdef[0].hul.rghs[0].cItem = 1;

            if (game.mdSize > 0) {
                /* Clear fFree on design #1. */
                lpshdef[1].fFree = 0;

                /* Increment player's cshdefSB nibble (upper 4 bits in wRaw_0004). */
                pplr->cshdefSB++;

                /* Mark design #1 as built/existing (low word set to 1; high word was already 0). */
                lpshdef[1].cBuilt = 1;
                lpshdef[1].cExist = 1;
            }
        } else if (raMajor == raStargate && !game.fTutorial) {
            /* Set slot0 iItem = 0; and set cItem bit0 (matches OR 0x100). */
            lpshdef[0].hul.rghs[0].iItem = ispecialSBStargate100250;
            lpshdef[0].hul.rghs[0].cItem = 1;

            if (game.mdSize > 0) {
                /* Copy design 0 -> design 1 (REP MOVSW/MOVSB of 0x93 bytes). */
                memcpy(&lpshdef[1], &lpshdef[0], sizeof(SHDEF));

                /* Set design #1 ishdef to 0x11 and clear fFree. (mask 0x83ff | 0x4400, then &~0x200) */
                lpshdef[1].ishdef = 17; // starbase 2
                lpshdef[1].fFree = 0;

                pplr->cshdefSB++;

                lpshdef[1].cBuilt = 1;
                lpshdef[1].cExist = 1;
            }
        } else if (raMajor == raMacintosh) { /* raMacintosh */
            if (game.mdSize > 0) {
                /* Save home id before we start shuffling designs (ASM reads [player+0x8]). */
                idHome = pplr->idPlanetHome;

                /* Copy design 0 -> -> design 1. */
                memcpy(&lpshdef[1], &lpshdef[0], sizeof(SHDEF));
                lpshdef[1].ishdef = 17; /* 0x4400 */
                /* (No fFree clear here in the first mask; ASM doesn't do it until later on shdef[0]). */

                /* Copy design 3 -> design 0. (offset 0x1b9 == 3 * 0x93) */
                memcpy(&lpshdef[0], &lpshdef[3], sizeof(SHDEF));

                /* Set design #0 ishdef to 0x10 and clear fFree. (mask 0x83ff | 0x4000, then &~0x200) */
                lpshdef[0].ishdef = 16;
                lpshdef[0].fFree = 0;

                /* Increment player's cshdefSB nibble. */
                pplr->cshdefSB++;

                /* Clear built/exist on design #0 (writes both words to 0). */
                lpshdef[0].cBuilt = 0;
                lpshdef[0].cExist = 0;

                /* Home planet: set starbase design index (isb) to 1, keep pctDp. */
                lpPlanets[idHome].isb = 1;
            }
        }
    }

    // setup fleet alloc
    cFleet = 0;
    rglpfl = (FLEET **)LpAlloc(4, htMisc);

    for (i = 0; i < game.cPlayer; i++) {
        PLAYER *pplr;
        int16_t idHome;
        int16_t ishdef;
        PLANET *lpplHome = &lpPlanets[idHome];

        /* Set global current-player context for per-player ship design creation. */
        idPlayer = i;

        pplr = &rgplr[i];
        idHome = pplr->idPlanetHome;

        /* Allocate and clear 16 ship designs (0x930 == 16 * 0x93). */
        lpshdef = (SHDEF *)LpAlloc((uint16_t)(cShdefMax * (int16_t)sizeof(SHDEF)), htShips);
        memset(lpshdef, 0, (size_t)(cShdefMax * sizeof(SHDEF)));

        /* Mark all 16 entries as free (same 0x0200 bit at +0x7b in each 0x93 entry). */
        for (j = 0; j < cShdefMax; j++) {
            lpshdef[j].fFree = 1;
        }

        /* Store pointer to this player's ship-design array. */
        rglpshdef[i] = lpshdef;

        raMajor = GetRaceStat(pplr, rsMajorAdv);

        /* ----------- initial “main” startup ship(s) ----------- */
        if (raMajor == raMassAccel) {
            CreateStartupShip(i, idHome, LongRangeScout, 1);

            /* The decompile masks 0xC3FFFFFF | 0x04000000 at planet+0x2e.
               That’s bit 10 of the high word of PLANET.lStarbase => iWarpFling = 1. */
            lpPlanets[idHome].iWarpFling = 1;

        } else if (raMajor == raAttack) {
            CreateStartupShip(i, idHome, ArmedProbe, 1);

            /* rgTech[3] gate from decompile: if > 2, spawn two more. */
            if (pplr->rgTech[Construction] > 2) {
                CreateStartupShip(i, idHome, StalwartDefender, 1);
                CreateStartupShip(i, idHome, Gadfly, 1);
            }

        } else if (raMajor == raNone) {
            CreateStartupShip(i, idHome, ArmedProbe, 1);
            CreateStartupShip(i, idHome, LongRangeScout, 1);

        } else if (raMajor == raStealth) {
            /* tech gate uses rgTech[0] < 2 ? 2 : 5 */
            ishdef = (pplr->rgTech[Energy] < 2) ? SmaugarianPeepingTom : ShadowSleuth;
            CreateStartupShip(i, idHome, ishdef, 1);

            /* If not AI, create extra ship type 1 */
            if (!pplr->fAi) {
                CreateStartupShip(i, idHome, ShadowTransport, 1);
            }

        } else {
            CreateStartupShip(i, idHome, SmaugarianPeepingTom, 1);
        }

        /* ----------- secondary ship (or special chaining) ----------- */
        if (raMajor == raCheapCol) {
            ishdef = CreateStartupShip(i, idHome, SporeCloud, 1);
            for (j = 1; j < 3; j++) {
                CreateStartupShip(i, idHome, ishdef, 0);
            }
        } else if (raMajor == raStargate) {
            CreateStartupShip(i, idHome, Mayflower, 1);
        } else if (raMajor == raMacintosh) {
            CreateStartupShip(i, idHome, Pinta, 1);
        } else {
            ishdef = CreateStartupShip(i, idHome, SantaMaria, 1);
        }

        /* ----------- additional conditional spawns / possible 2nd planet ----------- */
        if (raMajor == raMines) {
            CreateStartupShip(i, idHome, LittleHen, 1);
            CreateStartupShip(i, idHome, SpeedTurtle, 1);

        } else if (raMajor == raTerra) {
            CreateStartupShip(i, idHome, ChangeofHeart, 1);

        } else if (raMajor == raStargate) {
            CreateStartupShip(i, idHome, StalwartDefender, 1);
            CreateStartupShip(i, idHome, Swashbuckler, 1);

            if (game.mdSize > 0) {
                goto LGive2ndPlanet;
            }
        } else if ((raMajor == raMassAccel) && game.mdSize > 0) {
        LGive2ndPlanet:

            lpplClosest = lpplPicked = NULL;
            STARSPOINT ptHome = rgptPlan[idHome];
            cFit = 0;

            lDistMin2 = (long)dGal * 15 / 100;
            lDistMin2 *= lDistMin2;

            lDistMax2 = (long)dGal * 23 / 100;
            lDistMax2 *= lDistMax2;

            lDistIdeal2 = (long)dGal * 20 / 100;
            lDistIdeal2 *= lDistIdeal2; /* your snippet had a typo; ASM squares it */

            lBest = 10000000;

            pptMax = &rgptPlan[cPlanMax];
            for (ppt = rgptPlan, lppl = lpPlanets; ppt < pptMax; ppt++, lppl++) {
                if (lppl->iPlayer == -1) {
                    dx = ppt->x - ptHome.x;
                    dy = ppt->y - ptHome.y;

                    lDistCur2 = (long)dx * dx + (long)dy * dy;

                    if (lDistCur2 >= lDistMin2 && lDistCur2 <= lDistMax2) {
                        if (Random(++cFit) == 0)
                            lpplPicked = lppl;
                    } else if (lpplPicked == NULL && lDistCur2 < lBest) {
                        lBest = lDistCur2;
                        lpplClosest = lppl;
                    }
                }
            }

            /* Fallback if no in-range planet found */
            if (lpplPicked == NULL)
                lpplPicked = lpplClosest;

            /* Mark: planet has been “given as 2nd planet” (ASM touches word at +0x2E) */
            lpplPicked->iWarpFling |= 1;

            /* Try up to 100 times to get desirability >= 10 by randomizing env vars */
            cTry = 0;
            while (PctPlanetDesirability(lpplPicked, i) < 10) {
                if (cTry++ >= 100)
                    break;

                for (j = 0; j < 3; j++) {
                    uint8_t v = Random(97) + 2; /* 2..98 */
                    lpplPicked->rgEnvVar[j] = v;
                    lpplPicked->rgEnvVarOrig[j] = v;
                }
            }

            /* If we failed 100 tries, copy env vars from the home planet */
            if (cTry >= 100) {
                for (j = 0; j < 3; j++) {
                    lpplPicked->rgEnvVar[j] = lpplHome->rgEnvVar[j];
                    lpplPicked->rgEnvVarOrig[j] = lpplHome->rgEnvVarOrig[j];
                }
            }

            /* Claim the planet */
            lpplPicked->iScanner = 0;
            lpplPicked->iPlayer = i;

            /* Give it a starbase: set planet flag + set starbase slot index */
            lpplPicked->fStarbase = 1;
            lpplPicked->isb = 1;

            /* Split the original home population: picked gets 2/5, home keeps 4/5 */
            {
                int32_t pop0 = lpplHome->rgwtMin[3];
                lpplPicked->rgwtMin[3] = (pop0 << 1) / 5;
                lpplHome->rgwtMin[3] = (pop0 << 2) / 5;
            }

            /* Update population guesses (low 12 bits) */
            lpplPicked->uPopGuess = (uint16_t)(lpplPicked->rgwtMin[3] / 4);
            lpplHome->uPopGuess = (uint16_t)(lpplHome->rgwtMin[3] / 4);

            /* Seed surface minerals: Random(200)+100 in each bucket */
            for (j = 0; j < 3; j++) {
                lpplPicked->rgwtMin[j] = (int32_t)(Random(200) + 100);
            }

            /* Give the player a startup ship at the new planet */
            CreateStartupShip(i, lpplPicked->id, 0, 0);

            /* (then it JMPs back out of the label) */
        } else if (raMajor == raNone) {
            int16_t ishdefFreighter;

            /* If propulsion(?) tech byte [3] < 4 => type 6 else type 8. */
            ishdefFreighter = (pplr->rgTech[3] < 4) ? Teamster : Swashbuckler;

            CreateStartupShip(i, idHome, ishdefFreighter, 1);
            CreateStartupShip(i, idHome, StalwartDefender, 1);
            CreateStartupShip(i, idHome, CottonPicker, 1);
        }

        /* If NOT OBRM, and ARM is set create two potato bugs*/
        if (GetRaceGrbit(pplr, ibitRaceARM) && !GetRaceGrbit(pplr, ibitRaceOBRM)) {
            int16_t ishdef;

            ishdef = CreateStartupShip(i, idHome, PotatoBug, 1);
            CreateStartupShip(i, idHome, ishdef, 0);
        }

        SHDEF  *pshdef = rglpshdef[i]; /* per-player SHDEF array (count = rgplr[i].cShDef) */
        int16_t cShDef = rgplr[i].cShDef;

        for (j = 0; j < cShDef; j++) {
            SHDEF  *sh = &pshdef[j];
            uint8_t cSlots = sh->hul.chs;

            for (k = 0; k < (int16_t)cSlots; k++) {
                HS     *hs = &sh->hul.rghs[k];
                PART    part;
                uint8_t candidates[6];
                int16_t nCand = 0;

                /* start from the current slot */
                part.hs = *hs;

                switch ((HullSlotType)part.hs.grhst) {
                case hstEngine:
                    if (part.hs.iItem == iengineQuickJump5) {
                        /* gate matches decompile/asm: envVar[2] == -1 OR ihuldef != 0x0F OR envVar[2] < 0x55 */
                        if (rgplr[i].rgEnvVar[Radiation] == -1 || rgplr[i].rgEnvVar[Radiation] < 85 || sh->hul.ihuldef != ihuldefColonyShip) {
                            candidates[nCand++] = iengineRadiatingHydroRamScoop;
                        }
                        candidates[nCand++] = iengineAlphaDrive8;
                        candidates[nCand++] = iengineDaddyLongLegs7;
                        candidates[nCand++] = iengineFuelMizer;
                        candidates[nCand++] = iengineLongHump6;
                    }
                    break;

                case hstScanner:
                    if (part.hs.iItem == iscannerBatScanner || part.hs.iItem == iscannerRhinoScanner) {
                        candidates[nCand++] = iscannerPossumScanner;
                        candidates[nCand++] = iscannerMoleScanner;
                        candidates[nCand++] = iscannerRhinoScanner;
                    }
                    break;

                case hstShield:
                case hstArmor:
                    if (part.hs.iItem == ishieldMoleSkinShield || part.hs.iItem == ishieldCowHideShield) {
                        candidates[nCand++] = ishieldWolverineDiffuseShield;
                        candidates[nCand++] = ishieldCowHideShield;
                    }
                    break;

                case hstBeam:
                    if (part.hs.iItem == ibeamLaser || part.hs.iItem == ibeamXRayLaser) {
                        candidates[nCand++] = ibeamYakimoraLightPhaser;
                        candidates[nCand++] = ibeamXRayLaser;
                    }
                    break;

                case hstTorp:
                case hstBomb:
                    if (part.hs.iItem == itorpAlphaTorpedo) {
                        candidates[nCand++] = itorpBetaTorpedo;
                    }
                    break;

                case hstMining:
                    if (part.hs.iItem == iminingRoboMidgetMiner || part.hs.iItem == iminingRoboMiniMiner) {
                        candidates[nCand++] = iminingRoboMiner;
                        candidates[nCand++] = iminingRoboMidgetMiner;
                    }
                    break;

                default:
                    break;
                }

                for (l = 0; l < nCand; l++) {
                    part.hs.iItem = candidates[l]; /* ONLY low byte changes; cItem preserved automatically */
                    if (FLookupPart(&part) == LookupOk) {
                        hs->iItem = candidates[l]; /* same: preserve hs->cItem */
                        break;
                    }
                }
            }
        }

        if (GetRaceStat(&rgplr[i], rsMajorAdv) == raMacintosh) {
            PLANET *lppl = &lpPlanets[idHome];
            lppl->iScanner = 31; /* sets the 5-bit field to 0x1F (matches asm) */
        }
    }

    /* ----------- “After last player” sentinel branch ----------- */
    /* When i reaches game.cPlayer, we stop per-player setup and finalize the universe/game files. */
    if (game.cPlayer <= i) {

        /* We are in “no current player context” mode for shared setup. */
        idPlayer = -1;

        /* ----------- Special-case: if first planet is unowned, clear some per-planet fields ----------- */
        if (lpPlanets->iPlayer == -1) {
            /* Zero 3 entries of a 32-bit-per-entry array at lpPlanets + 0x1c (j * 4). */
            for (j = 0; j < 3; j = j + 1) {
                lpPlanets->rgwtMin[j] = 0;
            }
        }

        /* ----------- Allocate and initialize per-player battle plans ----------- */
        for (i = 0; i < game.cPlayer; i = i + 1) {

            /* Default: each player starts with 5 battle plans (?) */
            rgcbtlplan[i] = 5;

            /* Allocate one BTLPLAN block per player (0x240 bytes). */
            rglpbtlplan[i] = (BTLPLAN *)LpAlloc(sizeof(BTLPLAN) * BTLPLANMAX, htShips);

            /* Initialize 5 individual plans within that block; each plan is 0x24 bytes. */
            for (j = 0; j < 5; j = j + 1) {
                InitBattlePlan(&rglpbtlplan[i][j], j, i);
            }
        }

        /* Record max planet count into the GAME struct. */
        game.cPlanMax = cPlanMax;

        /* ----------- Optional wormhole count selection ----------- */
        /* If fNoRandom is NOT set, choose random count based on mdSize table. */
        if (!game.fNoRandom) {
            iBest = (int16_t)(vrgWormholeMin[game.mdSize] + Random(vrgWormholeVar[game.mdSize]));
        } else {
            /* Otherwise: no wormholes. */
            iBest = 0;
        }

        /* ----------- Wormhole creation loop ----------- */
        if (iBest > 0) {
            for (i = 0; i < iBest; i = i + 1) {

                uint16_t   idFirstEndpoint = 0;
                THING     *lpthPartner;
                STARSPOINT ptBest;
                int16_t    bestBadness;
                int16_t    badness;

                /* Each wormhole is made of a pair of THINGs that link to each other. */
                for (j = 0; j < 2; j = j + 1) {

                    /* Allocate a new THING of type wormhole. */
                    lpth = LpthNew(0, ithWormhole);

                    /* Randomize a small attribute (0..2). Stored in THWORM.iStable (2 bits). */
                    lpth->thw.iStable = (uint16_t)Random(3);

                    /* If this is the second endpoint, link endpoints together by idFull. */
                    if (j == 1) {
                        lpthPartner = LpthFromId(idFirstEndpoint);
                        lpth->thw.idPartner = lpthPartner->idFull;
                        lpthPartner->thw.idPartner = lpth->idFull;
                    } else {
                        /* First endpoint: remember its id for the second endpoint to use. */
                        idFirstEndpoint = lpth->idFull;
                    }

                    /* ----------- Place wormhole: random attempts with “best-so-far” fallback ----------- */
                    k = 0;
                    bestBadness = 16;

                    while (k < 100) {

                        /* Random position in galaxy, then bias by +1000. */
                        lpth->pt.x = (int16_t)(Random(dGal) + 1000);
                        lpth->pt.y = (int16_t)(Random(dGal) + 1000);

                        /* Validate position; returns 0 if OK, otherwise “badness” score. */
                        badness = IValidateWormholePos(lpth);
                        if (badness == 0)
                            break;

                        k = (int16_t)(k + 1);

                        /* Track best (lowest badness) candidate location. */
                        if (badness < bestBadness) {
                            ptBest.x = lpth->pt.x;
                            ptBest.y = lpth->pt.y;
                            bestBadness = badness;
                        }
                    }

                    /* If never found a valid location, revert to the best candidate. */
                    if (badness != 0) {
                        lpth->pt.x = ptBest.x;
                        lpth->pt.y = ptBest.y;
                    }
                }
            }
        }

        /* ----------- Race tampering detection / notifications ----------- */
        for (i = 0; i < game.cPlayer; i = i + 1) {
            /* If player i has “tampered” flag set, notify them and (some) others. */
            if (rgplr[i].fHacker) {
                FSendPlrMsg2(i, idmRaceDefinitionHasTamperedStatisticsHaveAltered, -1, 0, 0);

                for (j = 0; j < game.cPlayer; j = j + 1) {
                    /* Notify other players who are NOT AI. */
                    if ((i != j) && !rgplr[j].fAi) {
                        FSendPlrMsg2(j, idmHackedRaceDiscoveredRaceStatisticsHaveAltered, -1, i, 0);
                    }
                }
            }
        }

        /* ----------- Detect “single human” mode and seed AI salts ----------- */
        iplrSingle = -1;

        for (i = 0; i < game.cPlayer; i = i + 1) {

            /* If player is human OR has special idAi==7, consider for “single player” selection. */
            if ((rgplr[i].fAi == 0) || (rgplr[i].idAi == 7)) {

                if (iplrSingle != -1)
                    break; /* more than one qualifies => not single-player */

                iplrSingle = i;

            } else {
                /* AI players: seed per-player salt with fixed constants. */
                rgplr[i].lSalt = (int32_t)0x094DABEE;
            }
        }

        /* If loop reached end and found exactly one qualifying player => single-player mode enabled. */
        if ((i == game.cPlayer) && (iplrSingle != -1)) {
            iNewLine = 1;
        } else {
            iNewLine = 0;
        }

        /* Stash flag and also set game.fSinglePlr. */
        game.fSinglePlr = (uint16_t)iNewLine;

        /* ----------- If single-player, initialize player relation matrix to “2” (neutral?) ----------- */
        if (game.fSinglePlr != 0) {
            for (i = 0; i < game.cPlayer; i = i + 1) {
                for (j = 0; j < game.cPlayer; j = j + 1) {
                    if (i != j) {
                        rgplr[i].rgmdRelation[j] = 2;
                    }
                }
            }
        }

        /* ----------- Seed GAME.lid with GetTickCount unless tutorial flag is set ----------- */
        if (game.fTutorial == 0) {
            game.lid = (int32_t)GetTickCount();
        }

        /* ----------- Create the universe definition file (.XY?) ----------- */
        snprintf(szWork, sizeof(szWork), "%s.xy", szBase);

        ishRet = FCreateFile(dtXY, -1, NULL);
        if (ishRet != 0) {

            /* Write GAME record (rt=7? size=0x40). */
            WriteRt(7, 0x40, &game);

            /* ----------- Serialize starpack / planet positions ----------- */
            xOld = 1000;
            for (i = 0; i < cPlanMax; i = i + 1) {

                /* Pack directly into STARPACK bitfields (types.h). */
                starpack.y = (uint32_t)(uint16_t)rgptPlan[i].y;
                starpack.id = (uint32_t)(uint16_t)rgidPlan[i];

                /* Delta-x encoding relative to previous xOld (10-bit field, wrap matches original). */
                dx = (int16_t)(rgptPlan[i].x - xOld);
                starpack.dx = (uint32_t)(uint16_t)dx;

                /* Emit 4 bytes to stream. */
                RgToStream(&starpack, 4);

                xOld = rgptPlan[i].x;
            }

            /* ----------- Finalize XY stream: write player count, close ----------- */
            i = game.cPlayer;
            WriteRt(0, 2, &i);
            StreamClose();

            /* ----------- Write per-player data files (-1 then each player) ----------- */
            for (i = -1; i < game.cPlayer; i = i + 1) {
                FWriteDataFile(szBase, i, 0);
            }

/* ----------- If not batch mode, launch UI / load single-player turn ----------- */
#ifdef _WIN32
            if (fBatchMode == 0) {
                if (game.fSinglePlr == 0) {
                    idPlayer = -1;
                    imemLogCur = 0;
                    CreateChildWindows();
                } else {
                    DestroyCurGame();
                    snprintf(szExt, sizeof(szExt), MPCTD, iplrSingle + 1);
                    ishRet = FLoadGame(szBase, szExt);
                    if (ishRet == 0) {
                        Error(idsUnableOpenNewTurnFile);
                        return 0;
                    }
                    idPlayer = iplrSingle;
                    CreateChildWindows();
                    SendMessage(hwndFrame, WM_COMMAND, IDM_FRAME_POST_OPEN, 0);
                }
                return 1;
            }
#endif
            return 1;
        }

        /* ----------- Error path: couldn’t create universe definition file ----------- */
        Error(idsUnableCreateUniverseDefinitionFile);
        DestroyCurGame();
        return 0;
    }

    return 0;
}

PLAYER *LpplrComp(int16_t idAi, int16_t lvlAi) { return &vrgplrComp[idAi][lvlAi]; }

int16_t FGetNewGameName(char *szFileSuggest) {
    char     szXY[3];
    uint16_t i;
    char     szFileTitle[256];
    char     szFile[256];
    char     szFilter[256];
    // OFN ofn;

    /* TODO: implement */
    return 0;
}

int16_t GenNewGameFromFile(char *pszFile) {
    int32_t  rgl[10];
    int16_t  rgplrbmp[16];
    int16_t  c;
    int16_t  i;
    int16_t  fSuccess;
    char    *lpbStart;
    MemJump  env;
    int16_t  j;
    char    *lpb;
    char    *pszLine;
    char    *pszErr;
    int16_t  idAi;
    int16_t  lvlAi;
    int16_t  cParsed;
    uint16_t cbFile;
    char    *lpbDef;
    int16_t  cPlayers;
    PLAYER  *pplr;

    fSuccess = 0;

    /* ---- Setup filename scratch + install error trampoline ---- */
    strcpy(szWork, pszFile);
    penvMem = &env;
    if (setjmp(env.env) != 0)
        goto LError;

    /* ---- If INI flags indicate logging: compute base name and log "Generating..." ---- */
    if (ini.fLogging) {
        strcpy(szBase, pszFile);
        *strrchr(szBase, '.') = '\0';
        TurnLog(idsGeneratingYearD);
    }

    /* ---- Reset game struct ---- */
    memset(&game, 0, sizeof(GAME));

    /* ---- Read entire definition file into memory ---- */
    StreamOpen(pszFile, 0x20);
    fseek(hf.fp, 0, SEEK_END);
    cbFile = (uint16_t)ftell(hf.fp);
    fseek(hf.fp, 0, SEEK_SET);
    if (cbFile > 15999) {
        FileError(idsUniverseCreationFileAppearsInvalid);
        goto LError;
    }
    lpbDef = LpAlloc(cbFile + 1, htPerm);
    lpbDefMac = lpbDef + cbFile;
    RgFromStream(lpbDef, cbFile);
    StreamClose();
    lpbDef[cbFile] = '\0';

    lpb = lpbDef;

    /* ---- Line 1: Game title (non-empty, <= 31 chars) ---- */
    pszLine = PszGetLine(&lpb);
    if (*pszLine == '\0' || strlen(pszLine) > 31) {
        pszErr = PszFormatIds(idsIllegalGameTitle, NULL);
        AlertSz(pszErr, 0x10);
        goto LError;
    }
    strcpy(game.szName, pszLine);

    /* ---- Line 2: Universe core parameters (up to 4 numbers) ---- */
    if (lpb >= lpbDefMac)
        goto LUniDefShort;

    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 4);
    if (cParsed == -1)
        goto LUniDefError;

    /* Validate parameters 0..2: must be in [0..4], but params 1-2 max is 3 */
    for (i = 0; i < cParsed; i++) {
        if (i < 3) {
            if (rgl[i] < 0 || rgl[i] > 4)
                goto LUniDefError;
            if (rgl[i] == 4 && i != 0)
                goto LUniDefError;
        }
    }

    if (cParsed > 0)
        game.mdSize = (int16_t)rgl[0];
    if (cParsed > 1)
        game.mdDensity = (int16_t)rgl[1];
    if (cParsed > 2)
        game.mdStartDist = (int16_t)rgl[2];
    if (cParsed > 3)
        Randomize((uint32_t)rgl[3]);

    /* ---- Line 3: Universe option bits (up to 7 booleans) ---- */
    if (lpb >= lpbDefMac)
        goto LUniDefShort;

    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 7);
    if (cParsed == -1)
        goto LUniDefError3;

    for (i = 0; i < cParsed; i++) {
        if (rgl[i] < 0 || rgl[i] > 1)
            goto LUniDefError3;
    }

    if (cParsed > 0)
        game.fExtraFuel = (uint16_t)rgl[0] & 1;
    if (cParsed > 1)
        game.fSlowTech = (uint16_t)rgl[1] & 1;
    if (cParsed > 2)
        game.fBBSPlay = (uint16_t)rgl[2] & 1;
    if (cParsed > 3)
        game.fNoRandom = (uint16_t)rgl[3] & 1;
    if (cParsed > 4)
        game.fAisBand = (uint16_t)rgl[4] & 1;
    if (cParsed > 5)
        game.fVisScores = (uint16_t)rgl[5] & 1;
    if (cParsed > 6)
        game.fClumping = (uint16_t)rgl[6] & 1;

    /* ---- Line 4: number of players (1..16) ---- */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 1);
    cPlayers = (int16_t)rgl[0];
    if (cParsed < 1 || rgl[0] < 1 || rgl[0] > 16) {
        pszErr = PszFormatIds(idsLine4HasImproperNumberPlayerFiles, NULL);
        AlertSz(pszErr, 0x10);
        goto LError;
    }

    if (lpb >= lpbDefMac)
        goto LUniDefShort;

    game.cPlayer = cPlayers;

    /* ---- Per-player definition lines ---- */
    for (i = 0; i < cPlayers; i++) {
        pszLine = PszGetLine(&lpb);
        if (lpb >= lpbDefMac)
            goto LUniDefShort;

        lpbStart = pszLine;

        if (*pszLine != '#') {
            /* (A) Load a race file into vplr, copy to rgplr[i] */
            strcpy(szWork, pszLine);
            if (FWasRaceFile(szWork, 0) == 0)
                goto LCantGetRace;
            memcpy(&rgplr[i], &vplr, sizeof(PLAYER));
        } else {
            /* (B) Computer player spec "#race ai" */
            cParsed = CParseNumbers(lpbStart + 1, rgl, 2);

            if (cParsed < 2 || rgl[0] < 0 || rgl[0] > 6 || rgl[1] < 0 || rgl[1] > 4) {
                strcpy(szWork, pszLine);
            LCantGetRace:
                pszErr = PszGetCompressedString(idsLineDUnableLoadRaceFileS);
                wsprintf(szWork, pszErr, i + 5, lpbStart);
                AlertSz(szWork, 0x10);
                goto LError;
            }

            /* ai: 0 = random [0..3]; otherwise 1..4 maps to [0..3] */
            if (rgl[1] == 0)
                lvlAi = Random(4);
            else
                lvlAi = (int16_t)(rgl[1] - 1);

            /* race: 0 = random [0..5]; otherwise 1..6 maps to [0..5] */
            if (rgl[0] == 0)
                idAi = Random(6);
            else
                idAi = (int16_t)(rgl[0] - 1);

            pplr = LpplrComp(idAi, lvlAi);
            memcpy(&rgplr[i], pplr, sizeof(PLAYER));

            /* Mark AI + stash AI race id and AI level */
            rgplr[i].fAi = 1;
            rgplr[i].idAi = idAi;
            rgplr[i].lvlAi = lvlAi & 7;
        }
    }

    /* ---- Victory Conditions ---- */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 2);
    if (lpb >= lpbDefMac)
        goto LUniDefShort;

    i = 0;

    /* VC 0: Owns % of all planets (20..100, step 5) */
    if (cParsed < 1 || rgl[0] < 0 || rgl[0] > 1)
        goto LBadDefVc;
    if (rgl[0] == 1) {
        if (cParsed < 2 || rgl[1] < 20 || rgl[1] > 100)
            goto LBadDefVc;
        SetVCCheck(&game, vcOwnsPercentPlanets, 1);
        SetVCVal(&game, vcOwnsPercentPlanets, (int16_t)((rgl[1] - 20) / 5));
    }

    /* VC 1/2: Attains tech level/fields */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 3);
    if (lpb >= lpbDefMac)
        goto LUniDefShort;
    i = 1;
    if (cParsed < 1 || rgl[0] < 0 || rgl[0] > 1)
        goto LBadDefVc;
    if (rgl[0] == 1) {
        if (cParsed < 3 || rgl[1] < 8 || rgl[1] > 26 || rgl[2] < 2 || rgl[2] > 6)
            goto LBadDefVc;
        SetVCCheck(&game, vcAttainsTechLevel, 1);
        SetVCCheck(&game, vcAttainsTechFields, 1);
        SetVCVal(&game, vcAttainsTechLevel, (int16_t)(rgl[1] - 8));
        SetVCVal(&game, vcAttainsTechFields, (int16_t)(rgl[2] - 2));
    }

    /* VC 3: Exceeds a score */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 2);
    if (lpb >= lpbDefMac)
        goto LUniDefShort;
    i = 2;
    if (cParsed < 1 || rgl[0] < 0 || rgl[0] > 1)
        goto LBadDefVc;
    if (rgl[0] == 1) {
        if (cParsed < 2 || rgl[1] < 1000 || rgl[1] > 20000)
            goto LBadDefVc;
        SetVCCheck(&game, vcExceedsScore, 1);
        SetVCVal(&game, vcExceedsScore, (int16_t)((rgl[1] - 1000) / 1000));
    }

    /* VC 4: Exceeds second place score by */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 2);
    if (lpb >= lpbDefMac)
        goto LUniDefShort;
    i = 3;
    if (cParsed < 1 || rgl[0] < 0 || rgl[0] > 1)
        goto LBadDefVc;
    if (rgl[0] == 1) {
        if (cParsed < 2 || rgl[1] < 20 || rgl[1] > 300)
            goto LBadDefVc;
        SetVCCheck(&game, vcExceedsSecondPlaceBy, 1);
        SetVCVal(&game, vcExceedsSecondPlaceBy, (int16_t)((rgl[1] - 20) / 10));
    }

    /* VC 5: Production capacity */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 2);
    if (lpb >= lpbDefMac)
        goto LUniDefShort;
    i = 4;
    if (cParsed < 1 || rgl[0] < 0 || rgl[0] > 1)
        goto LBadDefVc;
    if (rgl[0] == 1) {
        if (cParsed < 2 || rgl[1] < 10 || rgl[1] > 500)
            goto LBadDefVc;
        SetVCCheck(&game, vcProductionCapacity, 1);
        SetVCVal(&game, vcProductionCapacity, (int16_t)((rgl[1] - 10) / 10));
    }

    /* VC 6: Owns capital ships */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 2);
    if (lpb >= lpbDefMac)
        goto LUniDefShort;
    i = 5;
    if (cParsed < 1 || rgl[0] < 0 || rgl[0] > 1)
        goto LBadDefVc;
    if (rgl[0] == 1) {
        if (cParsed < 2 || rgl[1] < 10 || rgl[1] > 300)
            goto LBadDefVc;
        SetVCCheck(&game, vcOwnsCapitalShips, 1);
        SetVCVal(&game, vcOwnsCapitalShips, (int16_t)((rgl[1] - 10) / 10));
    }

    /* VC 7: Highest score after years */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 2);
    if (lpb >= lpbDefMac)
        goto LUniDefShort;
    i = 6;
    if (cParsed < 1 || rgl[0] < 0 || rgl[0] > 1)
        goto LBadDefVc;
    if (rgl[0] == 1) {
        if (cParsed < 2 || rgl[1] < 30 || rgl[1] > 900)
            goto LBadDefVc;
        SetVCCheck(&game, vcHighestScoreAfterYears, 1);
        SetVCVal(&game, vcHighestScoreAfterYears, (int16_t)((rgl[1] - 30) / 10));
    }

    /* VC 8/9: Meets N criteria / min years */
    pszLine = PszGetLine(&lpb);
    cParsed = CParseNumbers(pszLine, rgl, 2);
    if (lpb >= lpbDefMac)
        goto LUniDefShort;
    i = 7;
    if (cParsed < 1 || rgl[0] < 0 || rgl[0] > 7)
        goto LBadDefVc;
    if (rgl[0] > 0) {
        if (cParsed < 2 || rgl[1] < 30 || rgl[1] > 500)
            goto LBadDefVc;
        SetVCVal(&game, vcMeetsNumCriteria, (int16_t)rgl[0]);
        SetVCVal(&game, vcMinYearsBeforeWin, (int16_t)((rgl[1] - 30) / 10));
    }

    /* ---- Base filename: strip ".xy" extension if present ---- */
    pszLine = PszGetLine(&lpb);
    {
        uint16_t len = (uint16_t)strlen(pszLine);
        if (len > 3 && pszLine[len - 1] == 'y' && pszLine[len - 2] == 'x' && pszLine[len - 3] == '.') {
            pszLine[len - 3] = '\0';
        }
    }
    strcpy(szBase, pszLine);

    /* Ensure the output directory exists (e.g. "./test/data/generated/" for
       szBase = "./test/data/generated/tiny"). */
    {
        char szDir[256];
        strncpy(szDir, szBase, sizeof(szDir) - 1);
        szDir[sizeof(szDir) - 1] = '\0';
        char *pSlash = strrchr(szDir, '/');
#ifdef _WIN32
        char *pBSlash = strrchr(szDir, '\\');
        if (pBSlash > pSlash)
            pSlash = pBSlash;
#endif
        if (pSlash) {
            *pSlash = '\0';
            Stars_EnsureDirRecursive(szDir);
        }
    }

    if (lpb + 4 < lpbDefMac) {
        lpbDefUni = lpb;
    }

    /* ---- Post-parse player normalization ---- */
    for (i = 0; i < game.cPlayer; i++) {
        if (!rgplr[i].fAi && CAdvantagePoints(&rgplr[i]) < 0) {
            memcpy(&rgplr[i], &vrgplrDef[0], sizeof(PLAYER));
            rgplr[i].fHacker = 1;
        }
        if (rgplr[i].szName[0] == '\0') {
            CchGetString(Random(0x18) + idsBerserker, rgplr[i].szName);
            strcpy(rgplr[i].szNames, rgplr[i].szName);
            strcat(rgplr[i].szNames, "s");
        }
    }

    /* ---- Ensure unique player names ---- */
    for (i = 1; i < game.cPlayer; i++) {
        for (j = 0; j < i; j++) {
            if (strcmp(rgplr[i].szName, rgplr[j].szName) == 0)
                break;
        }
        if (j < i) {
            c = Random(0x18);
        LFindUniqueName:
            for (j = 0; j < game.cPlayer; j++) {
                pszErr = PszGetCompressedString(c + idsBerserker);
                if (strcmp(rgplr[j].szName, pszErr) == 0)
                    break;
            }
            if (j != game.cPlayer) {
                c++;
                if (c > 0x17)
                    c = 0;
                goto LFindUniqueName;
            }
            CchGetString(c + idsBerserker, rgplr[i].szName);
            strcpy(rgplr[i].szNames, rgplr[i].szName);
            strcat(rgplr[i].szNames, "s");
        }
    }

    /* ---- Player bitmap assignment ---- */
    for (i = 0; i < game.cPlayer; i++) {
        rgplrbmp[i] = rgplr[i].iPlrBmp;
        if (rgplrbmp[i] < 0 || rgplrbmp[i] > 31)
            rgplrbmp[i] = -1;
    }
    for (i = 1; i < game.cPlayer; i++) {
        if (rgplrbmp[i] != -1) {
            for (j = 0; j < i && rgplrbmp[j] != rgplrbmp[i]; j++)
                ;
            if (j < i) {
                int16_t pick = Random(2);
                rgplrbmp[pick == 0 ? j : i] = -1;
            }
        }
    }
    for (i = 0; i < game.cPlayer; i++) {
        if (rgplrbmp[i] == -1) {
            rgplrbmp[i] = Random(0x20);
            while (1) {
                for (j = 0; j < game.cPlayer && (j == i || rgplrbmp[i] != rgplrbmp[j]); j++)
                    ;
                if (j == game.cPlayer)
                    break;
                rgplrbmp[i]++;
                if (rgplrbmp[i] > 31)
                    rgplrbmp[i] = 0;
            }
        }
    }
    for (i = 0; i < game.cPlayer; i++) {
        rgplr[i].iPlrBmp = rgplrbmp[i] & 0x1f;
    }

    /* ---- Generate world and succeed ---- */
    GenerateWorld(1);
    fSuccess = 1;
    goto LError;

LBadDefVc:
    pszErr = PszGetCompressedString(idsLineDHasImproperVictoryConditionDefinition);
    wsprintf(szWork, pszErr, i + cPlayers + 5);
    AlertSz(szWork, 0x10);
    goto LError;

LUniDefError:
    pszErr = PszFormatIds(idsLine2HasBadUniverseDefinitionParameter, NULL);
    AlertSz(pszErr, 0x10);
    goto LError;

LUniDefError3:
    pszErr = PszFormatIds(idsLine3HasBadUniverseDefinitionParameter, NULL);
    AlertSz(pszErr, 0x10);
    goto LError;

LUniDefShort:
    pszErr = PszFormatIds(idsUniverseDefinitionFileAppearsTooShort, NULL);
    AlertSz(pszErr, 0x10);

LError:
    penvMem = NULL;
    StreamClose();
    lpbDefUni = NULL;
    TurnLog(fSuccess + idsFailed);
    return fSuccess;
}

#ifdef _WIN32

void SetNGWTitle(HWND hwnd, int16_t iStep) {
    int16_t cch;
    char    szBuf[50];

    /* TODO: implement */
}

int16_t FTrackNewGameDlg3(HWND hwnd, POINT pt, int16_t kbd) {
    int16_t bt;
    int16_t irc;
    BTNT    btnt;
    int16_t i;
    int16_t dShift;
    int16_t iMod;
    int16_t iStat;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0xa2cb */

    /* TODO: implement */
    return 0;
}

void NewGameWizard(HWND hwnd, int16_t fReadOnly) {
    int16_t iStepMaxSoFar;
    int16_t mdRet;
    int16_t (*lpProc)(void);
    int16_t fIdleSav;
    int16_t rgplrbmp[16];
    int16_t i;
    int16_t c;
    char    szFile[256];
    int16_t idAi;
    int16_t fEasy;
    char    szFileLocal[208];
    int16_t j;
    RECT    rgrcStack[20];
    PLAYER  rgplrLocal[16];
    int16_t lvlAi;
    GAME    gameT;

    /* debug symbols */
    /* label Cancel @ MEMORY_CREATE:0x63a3 */
    /* label Finish @ MEMORY_CREATE:0x64e6 */
    /* label Step1 @ MEMORY_CREATE:0x635b */
    /* label Step2 @ MEMORY_CREATE:0x63f5 */

    /* TODO: implement */
}

INT_PTR CALLBACK NewGameDlg3(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HDC         hdc;
    POINT       pt;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x9b45 */
    /* block (block) @ MEMORY_CREATE:0x9b88 */
    /* block (block) @ MEMORY_CREATE:0x9bc0 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK NewGameDlg2(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    int16_t     iNewVal;
    HDC         hdc;
    POINT       pt;
    int16_t     iDiamond;
    RECT        rcT;
    int16_t     dyBut;
    int16_t     j;
    int16_t     dy;
    char       *psz;
    int16_t     dyCur;
    int16_t     tpm;
    HWND        hwndBtn;
    int16_t     iChecked;
    PAINTSTRUCT ps;
    uint16_t    rghmenuSubPopup[14];
    HMENU       hmenuPopup;
    int16_t     iCurVal;
    RECT       *prcSav;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x87e1 */
    /* block (block) @ MEMORY_CREATE:0x89da */
    /* block (block) @ MEMORY_CREATE:0x8a76 */
    /* block (block) @ MEMORY_CREATE:0x8fc8 */
    /* block (block) @ MEMORY_CREATE:0x912e */
    /* block (block) @ MEMORY_CREATE:0x9401 */
    /* label FinishClick @ MEMORY_CREATE:0x93f6 */
    /* label PlaceNew @ MEMORY_CREATE:0x9056 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK NewGameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HDC         hdc;
    int16_t     iRet;
    RECT        rcGBox;
    int16_t     c;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x8261 */
    /* block (block) @ MEMORY_CREATE:0x8510 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK SimpleNewGameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HWND        hwndDD;
    HDC         hdc;
    RECT       *prcSav;
    RECT        rcGBox;
    int16_t     dy;
    int16_t     c;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x76b9 */
    /* block (block) @ MEMORY_CREATE:0x7858 */
    /* block (block) @ MEMORY_CREATE:0x7cde */

    /* TODO: implement */
    return 0;
}
void DrawNewGame3(HWND hwnd, HDC hdc, int16_t iDraw) {
    int16_t  yTop;
    int16_t  bt;
    int16_t  vcCur;
    int16_t  irc;
    int16_t  ids;
    int16_t  fCreatedDC;
    int16_t  i;
    int16_t  dxItem;
    RECT     rcCBox;
    int16_t  j;
    uint32_t crBkSav;
    int16_t  bkMode;
    int16_t  dxDig;
    int16_t  xLeft;
    int16_t  cch;
    RECT     rc;

    /* TODO: implement */
}

void DrawNewGame2(HWND hwnd, HDC hdc, int16_t iDraw) {
    int16_t fCreatedDC;
    int16_t yCur;
    int16_t i;
    int16_t iPlr;
    int16_t bkMode;
    int16_t cch;
    RECT    rcDiamond;
    RECT    rc;
    int16_t ids;
    char    szT[20];

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x977e */
    /* block (block) @ MEMORY_CREATE:0x97b5 */
    /* label DisplayName @ MEMORY_CREATE:0x996b */

    /* TODO: implement */
}
#endif