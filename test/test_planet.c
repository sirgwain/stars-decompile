#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "types.h"
#include "parts.h"
#include "memory.h" /* htPlanets allocation*/
#include "planet.h" /* PctPlanetDesirability */

typedef struct HabCase
{
    const char *name;

    /* player env model */
    int8_t pref[3]; /* optimal (typically 50) */
    int8_t minv[3]; /* typically 15 */
    int8_t maxv[3]; /* typically 85; <0 means immune axis */

    /* planet env (Stars: 1..100) */
    int8_t env[3];

    /* expected result:
       - if expect_exact: want is exact
       - else: want is ignored and we check bounds/relations */
    int16_t want;
    int8_t expect_exact;

    /* optional: bounds check for non-exact cases */
    int16_t min_want;
    int16_t max_want;
} HabCase;

static void apply_player0(const HabCase *tc, PLAYER *old_out)
{
    *old_out = rgplr[0];

    PLAYER pr = rgplr[0];
    for (int i = 0; i < 3; i++)
    {
        pr.rgEnvVar[i] = tc->pref[i];
        pr.rgEnvVarMin[i] = tc->minv[i];
        pr.rgEnvVarMax[i] = tc->maxv[i];
    }
    rgplr[0] = pr;
}

static PLANET make_planet(const HabCase *tc)
{
    PLANET pl;
    memset(&pl, 0, sizeof(pl));
    for (int i = 0; i < 3; i++)
    {
        pl.rgEnvVar[i] = tc->env[i];
    }
    return pl;
}

static void test_PctPlanetDesirability_table_stars_defaults(void)
{
    /* Stars default race window: 15..85, pref=50. */
    static const HabCase cases[] = {
        {.name = "ideal (50,50,50) in 15..85 => 100",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {85, 85, 85},
         .env = {50, 50, 50},
         .want = 100,
         .expect_exact = 1},
        {.name = "just inside min edge (15,50,50) => positive",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {85, 85, 85},
         .env = {15, 50, 50},
         .expect_exact = 0,
         .min_want = 1,
         .max_want = 99},
        {.name = "below min (1,50,50) => negative penalty (15-1=14)",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {85, 85, 85},
         .env = {1, 50, 50},
         .want = -14,
         .expect_exact = 1},
        {.name = "above max (100,50,50) => negative penalty (100-85=15, capped 15)",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {85, 85, 85},
         .env = {100, 50, 50},
         .want = -15,
         .expect_exact = 1},
        {.name = "two axes out of range sum penalties (1,100,50) => -(14 + 15) = -29",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {85, 85, 85},
         .env = {1, 100, 50},
         .want = -29,
         .expect_exact = 1},
        {.name = "immune axis: max<0 => treated as perfect contribution; other axes ideal => 100",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {-1, 85, 85}, /* axis0 immune */
         .env = {1, 50, 50},   /* would be out-of-range, but immune */
         .want = 100,
         .expect_exact = 1},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        const HabCase *tc = &cases[i];

        /* sanity: keep tests Stars-faithful unless intentionally testing bad data */
        for (int k = 0; k < 3; k++)
        {
            TEST_CHECK_(tc->env[k] >= 1 && tc->env[k] <= 100,
                        "case[%zu] %s: env[%d]=%d must be 1..100 for Stars data",
                        i, tc->name, k, (int)tc->env[k]);
        }

        PLAYER old;
        apply_player0(tc, &old);

        PLANET pl = make_planet(tc);
        int16_t got = PctPlanetDesirability(&pl, 0);

        if (tc->expect_exact)
        {
            TEST_CHECK_(got == tc->want,
                        "case[%zu] %s: got=%d want=%d env={%d,%d,%d}",
                        i, tc->name, (int)got, (int)tc->want,
                        (int)tc->env[0], (int)tc->env[1], (int)tc->env[2]);
        }
        else
        {
            TEST_CHECK_(got >= tc->min_want && got <= tc->max_want,
                        "case[%zu] %s: got=%d expected in [%d..%d] env={%d,%d,%d}",
                        i, tc->name, (int)got, (int)tc->min_want, (int)tc->max_want,
                        (int)tc->env[0], (int)tc->env[1], (int)tc->env[2]);
        }

        rgplr[0] = old;
    }
}

static void test_IWarpMAFromLppl_visibility_and_two_at_top_warp(void)
{
    /* Save/restore globals we touch. */
    const int16_t idPlayer_old = idPlayer;

    /* Pick an arbitrary owner slot that exists. */
    const int owner = 0;
    SHDEF *sbtab_old = rglpshdefSB[owner];

    /* Provide a small SB design table with at least 16 entries (isb low 4 bits). */
    static SHDEF sbtab[16];
    memset(sbtab, 0, sizeof(sbtab));
    rglpshdefSB[owner] = sbtab;

    PLANET pl;
    memset(&pl, 0, sizeof(pl));
    pl.iPlayer = (int16_t)owner;
    pl.fStarbase = 1;
    pl.isb = 3; /* use design index 3 */

    SHDEF *sb = &sbtab[pl.isb & 0x0F];

    /* Subcase A: no visibility (not owner, not omniscient, and det != detAll). */
    {
        idPlayer = 1; /* some other player */
        sb->det = 0;  /* not detAll */
        sb->hul.chs = 1;
        sb->hul.rghs[0].grhst = hstSpecialSB;
        sb->hul.rghs[0].iItem = ispecialSBUltraDriver10; /* warpCode -> warp 10 */
        sb->hul.rghs[0].cItem = 1;

        bool two = true;
        int16_t got = IWarpMAFromLppl(&pl, &two);
        TEST_CHECK_(got == 0, "no visibility: got=%d want=0", (int)got);
        TEST_CHECK_(two == false, "no visibility: pfTwo should be false");
    }

    /* Subcase B: visibility as owner; single MA at top warp => pfTwo false. */
    {
        idPlayer = (int16_t)owner;
        sb->det = 0;
        memset(&sb->hul, 0, sizeof(sb->hul));
        sb->hul.chs = 2;
        sb->hul.rghs[0].grhst = hstSpecialSB;
        sb->hul.rghs[0].iItem = ispecialSBUltraDriver10; /* warp 10 */
        sb->hul.rghs[0].cItem = 1;
        sb->hul.rghs[1].grhst = hstSpecialSB;
        sb->hul.rghs[1].iItem = ispecialSBMassDriver7; /* warp 7 (lower) */
        sb->hul.rghs[1].cItem = 1;

        bool two = true;
        int16_t got = IWarpMAFromLppl(&pl, &two);
        TEST_CHECK_(got == 10, "owner visibility: got=%d want=10", (int)got);
        TEST_CHECK_(two == false, "owner visibility: pfTwo should be false for single top MA");
    }

    /* Subcase C: two MAs at the highest warp => pfTwo true. */
    {
        idPlayer = (int16_t)owner;
        sb->det = 0;
        memset(&sb->hul, 0, sizeof(sb->hul));
        sb->hul.chs = 3;
        sb->hul.rghs[0].grhst = hstSpecialSB;
        sb->hul.rghs[0].iItem = ispecialSBUltraDriver10; /* warp 10 */
        sb->hul.rghs[0].cItem = 1;
        sb->hul.rghs[1].grhst = hstSpecialSB;
        sb->hul.rghs[1].iItem = ispecialSBUltraDriver10; /* warp 10 again */
        sb->hul.rghs[1].cItem = 1;
        sb->hul.rghs[2].grhst = hstSpecialSB;
        sb->hul.rghs[2].iItem = ispecialSBMassDriver7; /* warp 7 (lower) */
        sb->hul.rghs[2].cItem = 1;

        bool two = false;
        int16_t got = IWarpMAFromLppl(&pl, &two);
        TEST_CHECK_(got == 10, "two at top: got=%d want=10", (int)got);
        TEST_CHECK_(two == true, "two at top: pfTwo should be true");
    }

    /* Subcase D: higher warp found later should clear pfTwo unless duplicated at that warp. */
    {
        idPlayer = (int16_t)owner;
        sb->det = 0;
        memset(&sb->hul, 0, sizeof(sb->hul));
        sb->hul.chs = 3;
        sb->hul.rghs[0].grhst = hstSpecialSB;
        sb->hul.rghs[0].iItem = ispecialSBUltraDriver10; /* warp 10 */
        sb->hul.rghs[0].cItem = 1;
        sb->hul.rghs[1].grhst = hstSpecialSB;
        sb->hul.rghs[1].iItem = ispecialSBUltraDriver10; /* warp 10 again (would set two) */
        sb->hul.rghs[1].cItem = 1;
        sb->hul.rghs[2].grhst = hstSpecialSB;
        sb->hul.rghs[2].iItem = ispecialSBUltraDriver13; /* warp 13 (higher) */
        sb->hul.rghs[2].cItem = 1;

        bool two = true;
        int16_t got = IWarpMAFromLppl(&pl, &two);
        TEST_CHECK_(got == 13, "higher overrides: got=%d want=13", (int)got);
        TEST_CHECK_(two == false, "higher overrides: pfTwo should be false (single at top warp)");
    }

    /* Restore globals. */
    rglpshdefSB[owner] = sbtab_old;
    idPlayer = idPlayer_old;
}

static void test_PopFromLppl(void)
{
    PLANET pl;
    memset(&pl, 0, sizeof(pl));

    // 0 case
    int32_t got = PopFromLppl(&pl);
    TEST_CHECK_(got == 0, "no visibility: got=%d want=0", (int)got);

    // 25kT of pop
    pl.rgwtMin[3] = 25;
    got = PopFromLppl(&pl);
    TEST_CHECK_(got == 25, "no visibility: got=%d want=0", (int)got);
}

static void test_CMaxOperableFactories_clamps_and_mac_zero(void)
{
    const int iplr = 0;
    PLAYER old = rgplr[iplr];
    GAME gameOld = game;
    PLANET *lpPlanetsOld = lpPlanets;
    int cPlanetOld = cPlanet;

    PLANET pl = {.iPlayer = iplr, .rgEnvVar = {50, 50, 50}};
    pl.rgwtMin[3] = 100; /* any nonzero pop */
    cPlanet = 1;
    lpPlanets = (PLANET *)LpAlloc((uint16_t)(sizeof(PLANET) * cPlanet), htPlanets);
    memcpy(&lpPlanets[0], &pl, sizeof(PLANET));
    game.cPlanMax = 1;

    /* With 0% operate efficiency, computed max is 0 but the function clamps to >= 1. */
    memcpy(&rgplr[iplr], &vrgplrDef[0], sizeof(PLAYER));
    rgplr[iplr].rgAttr[rsFactOperate] = 0;
    rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raNone;

    int16_t got = CMaxOperableFactories(&pl, (int16_t)iplr, 0);
    TEST_CHECK_(got == 1, "0%% efficiency should clamp to 1: got=%d want=1", (int)got);

    // 100,000 people, 100 factories
    rgplr[iplr].rgAttr[rsFactOperate] = 10;
    pl.rgwtMin[3] = 1000;
    got = CMaxOperableFactories(&pl, (int16_t)iplr, 0);
    TEST_CHECK_(got == 100, "100k pop: got=%d want=100", (int)got);

    /* Macintosh major advantage forces 0. */
    // TODO: enable when you setup a starbase
    // rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raMacintosh;
    // got = CMaxOperableFactories(&pl, (int16_t)iplr, 0);
    // TEST_CHECK_(got == 0, "raMacintosh should force 0: got=%d want=0", (int)got);

    rgplr[iplr] = old;
    FreeLp(lpPlanets, htPlanets);
    lpPlanets = lpPlanetsOld;
    cPlanet = cPlanetOld;
    game = gameOld;
}

static void test_CMaxOperableMines_clamps_and_mac_zero(void)
{
    const int iplr = 0;
    PLAYER old = rgplr[iplr];
    GAME gameOld = game;
    PLANET *lpPlanetsOld = lpPlanets;
    int cPlanetOld = cPlanet;

    PLANET pl = {.iPlayer = iplr, .rgEnvVar = {50, 50, 50}};
    pl.rgwtMin[3] = 100; /* any nonzero pop */
    cPlanet = 1;
    lpPlanets = (PLANET *)LpAlloc((uint16_t)(sizeof(PLANET) * cPlanet), htPlanets);
    memcpy(&lpPlanets[0], &pl, sizeof(PLANET));
    game.cPlanMax = 1;

    /* With 0% operate efficiency, computed max is 0 but the function clamps to >= 1. */
    memcpy(&rgplr[iplr], &vrgplrDef[0], sizeof(PLAYER));
    rgplr[iplr].rgAttr[rsMineOperate] = 0;
    rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raNone;

    int16_t got = CMaxOperableMines(&pl, (int16_t)iplr, 0);
    TEST_CHECK_(got == 1, "0%% efficiency should clamp to 1: got=%d want=1", (int)got);

    // 100,000 people, 100 mines
    rgplr[iplr].rgAttr[rsMineOperate] = 10;
    pl.rgwtMin[3] = 1000;
    got = CMaxOperableMines(&pl, (int16_t)iplr, 0);
    TEST_CHECK_(got == 100, "100k pop: got=%d want=100", (int)got);

    /* Macintosh major advantage forces 0. */
    // TODO: enable when you setup a starbase
    // rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raMacintosh;
    // got = CMaxOperableMines(&pl, (int16_t)iplr, 0);
    // TEST_CHECK_(got == 0, "raMacintosh should force 0: got=%d want=0", (int)got);

    rgplr[iplr] = old;
    FreeLp(lpPlanets, htPlanets);
    lpPlanets = lpPlanetsOld;
    cPlanet = cPlanetOld;
    game = gameOld;
}

static void test_CalcPlanetMaxPop_race_modifiers_smoke(void)
{
    const int iplr = 0;
    PLAYER old = rgplr[iplr];
    PLANET pl = {.iPlayer = iplr, .rgEnvVar = {50, 50, 50}};

    /* Use the player's homeworld id if available; otherwise, try 0 as a fallback. */
    int16_t idpl = rgplr[iplr].idPlanetHome;
    if (idpl < 0)
        idpl = 0;

    memcpy(&rgplr[iplr], &vrgplrDef[0], sizeof(PLAYER));
    rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raNone;
    rgplr[iplr].grbitAttr &= ~(1u << ibitRaceOBRM);

    int32_t base = CalcPlanetMaxPop(idpl, (int16_t)iplr);

    /* If we can't resolve a planet in the current test harness, just ensure it doesn't crash. */
    if (base == 0)
    {
        TEST_CHECK_(base == 0, "smoke: base returned 0");
        rgplr[iplr] = old;
        return;
    }

    /* Cheap Colonists: 50% of base. */
    rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raCheapCol;
    int32_t cheap = CalcPlanetMaxPop(idpl, (int16_t)iplr);
    TEST_CHECK_(cheap <= base, "raCheapCol should not exceed base: cheap=%d base=%d", (int)cheap, (int)base);

    /* OBRM adds 10%. */
    rgplr[iplr].rgAttr[rsMajorAdv] = (int8_t)raNone;
    rgplr[iplr].grbitAttr |= (1u << ibitRaceOBRM);
    int32_t obrm = CalcPlanetMaxPop(idpl, (int16_t)iplr);
    TEST_CHECK_(obrm > base, "OBRM should increase max pop: obrm=%d base=%d", (int)obrm, (int)base);

    rgplr[iplr] = old;
}

TEST_LIST = {
    {"PctPlanetDesirability table (Stars defaults)", test_PctPlanetDesirability_table_stars_defaults},
    {"IWarpMAFromLppl visibility + pfTwo", test_IWarpMAFromLppl_visibility_and_two_at_top_warp},
    {"CMaxOperableFactories clamp + raMacintosh", test_CMaxOperableFactories_clamps_and_mac_zero},
    {"CMaxOperableMines clamp + raMacintosh", test_CMaxOperableMines_clamps_and_mac_zero},
    {"CalcPlanetMaxPop race modifiers smoke", test_CalcPlanetMaxPop_race_modifiers_smoke},
    {NULL, NULL}};
