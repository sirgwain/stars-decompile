#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "memory.h"
#include "produce.h"
#include "types.h"

static PLANET make_starter_planet(int16_t iplr) {
    PLANET pl;
    memset(&pl, 0, sizeof(pl));
    pl.iPlayer = iplr;
    pl.rgEnvVar[0] = 50;
    pl.rgEnvVar[1] = 50;
    pl.rgEnvVar[2] = 50;
    pl.rgwtMin[0] = 100; /* 100 kT iron */
    pl.rgwtMin[1] = 100; /* 100 kT bor */
    pl.rgwtMin[2] = 100; /* 100 kT germ */
    pl.rgwtMin[3] = 250; /* 25,000 colonists */
    pl.cMines = 10;
    pl.cFactories = 10;
    return pl;
}

static PLPROD *make_queue(PROD *items, int16_t count) {
    PLPROD *plprod = (PLPROD *)LpplAlloc(sizeof(PROD), count, htOrd);
    plprod->iprodMac = count;
    memcpy(&plprod->rgprod[0], items, count * sizeof(PROD));
    return plprod;
}

static void test_EstimateItemProdSched_mine_completes_year1(void) {
    const int16_t iplr = 0;
    PLAYER        oldPlr = rgplr[iplr];
    GAME          oldGame = game;
    PLANET       *oldPlanets = lpPlanets;
    int           oldCPlanet = cPlanet;

    memcpy(&rgplr[iplr], &vrgplrDef[0], sizeof(PLAYER));
    rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raNone;

    memset(&game, 0, sizeof(GAME));
    game.cPlanMax = 1;

    PLANET pl = make_starter_planet(iplr);
    cPlanet = 1;
    lpPlanets = (PLANET *)LpAlloc((uint16_t)(sizeof(PLANET) * cPlanet), htPlanets);
    memcpy(&lpPlanets[0], &pl, sizeof(PLANET));

    PROD mine;
    memset(&mine, 0, sizeof(PROD));
    mine.grobj = grobjPlanet;
    mine.iItem = iobjMine;
    mine.cItem = 1;

    PLPROD *plprod = make_queue(&mine, 1);
    pl.lpplprod = plprod;

    int16_t iFirst = -99, iLast = -99;
    EstimateItemProdSched(&pl, plprod, 0, &iFirst, &iLast);

    TEST_CHECK_(iFirst == 1, "mine iFirst: got=%d want=1", (int)iFirst);
    TEST_CHECK_(iLast == 1, "mine iLast: got=%d want=1", (int)iLast);

    FreePl((PL *)plprod);
    FreeLp(lpPlanets, htPlanets);
    lpPlanets = oldPlanets;
    cPlanet = oldCPlanet;
    game = oldGame;
    rgplr[iplr] = oldPlr;
}

static void test_EstimateItemProdSched_factory_completes_year1(void) {
    const int16_t iplr = 0;
    PLAYER        oldPlr = rgplr[iplr];
    GAME          oldGame = game;
    PLANET       *oldPlanets = lpPlanets;
    int           oldCPlanet = cPlanet;

    memcpy(&rgplr[iplr], &vrgplrDef[0], sizeof(PLAYER));
    rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raNone;

    memset(&game, 0, sizeof(GAME));
    game.cPlanMax = 1;

    PLANET pl = make_starter_planet(iplr);
    cPlanet = 1;
    lpPlanets = (PLANET *)LpAlloc((uint16_t)(sizeof(PLANET) * cPlanet), htPlanets);
    memcpy(&lpPlanets[0], &pl, sizeof(PLANET));

    PROD factory;
    memset(&factory, 0, sizeof(PROD));
    factory.grobj = grobjPlanet;
    factory.iItem = iobjFactory;
    factory.cItem = 1;

    PLPROD *plprod = make_queue(&factory, 1);
    pl.lpplprod = plprod;

    int16_t iFirst = -99, iLast = -99;
    EstimateItemProdSched(&pl, plprod, 0, &iFirst, &iLast);

    TEST_CHECK_(iFirst == 1, "factory iFirst: got=%d want=1", (int)iFirst);
    TEST_CHECK_(iLast == 1, "factory iLast: got=%d want=1", (int)iLast);

    FreePl((PL *)plprod);
    FreeLp(lpPlanets, htPlanets);
    lpPlanets = oldPlanets;
    cPlanet = oldCPlanet;
    game = oldGame;
    rgplr[iplr] = oldPlr;
}

TEST_LIST = {
    {"EstimateItemProdSched mine completes year 1", test_EstimateItemProdSched_mine_completes_year1},
    {"EstimateItemProdSched factory completes year 1", test_EstimateItemProdSched_factory_completes_year1},
    {NULL, NULL},
};
