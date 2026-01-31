#include "acutest.h"

#include <string.h>

#include "globals.h"
#include "types.h"

/* util.c */
int32_t ChgPopFromPlanet(PLANET *lppl, int16_t fUpdate);

typedef struct PopCase {
    const char *name;

    /* player env model (use Stars defaults) */
    int8_t pref[3];
    int8_t minv[3];
    int8_t maxv[3];

    /* planet env */
    int8_t env[3];

    /* population + accumulator */
    int32_t pop;
    uint8_t acc;

    int32_t want_inc;
    int32_t want_pop_after;
    uint8_t want_acc_after;
} PopCase;

static void apply_player0_env(const PopCase *tc, PLAYER *old_out) {
    *old_out = rgplr[0];

    PLAYER pr = rgplr[0];
    for (int i = 0; i < 3; i++) {
        pr.rgEnvVar[i] = tc->pref[i];
        pr.rgEnvVarMin[i] = tc->minv[i];
        pr.rgEnvVarMax[i] = tc->maxv[i];
    }
    rgplr[0] = pr;
}

static PLANET make_planet_for_pop(const PopCase *tc) {
    PLANET pl;
    memset(&pl, 0, sizeof(pl));

    pl.iPlayer = 0;
    for (int i = 0; i < 3; i++)
        pl.rgEnvVar[i] = tc->env[i];

    pl.rgwtMin[3] = tc->pop;
    pl.rgbImp[0] = tc->acc;

    return pl;
}

static void test_ChgPopFromPlanet_negative_desire_table(void) {
    /*
     * These cases stay entirely in the pctDesire < 0 path, so they don't depend
     * on CalcPlanetMaxPop / growth scaling and are stable to test.
     *
     * Stars default race window: 15..85, pref=50.
     * env {1,50,50} -> pctDesire = -(15-1) = -14.
     * env {0,50,50} -> pctDesire = -(15-0) = -15.
     */
    static const PopCase cases[] = {
        {.name = "pop=100 acc=0 desire=-14 => -2 with borrow, acc=60",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {85, 85, 85},
         .env = {1, 50, 50},
         .pop = 100,
         .acc = 0,
         .want_inc = -2, /* (100*14/10)=140 => whole=1 rem=40; 0-40 borrows => -(1+1) */
         .want_pop_after = 98,
         .want_acc_after = 60},

        {.name = "pop=100 acc=90 desire=-15 => -1, acc decreases without borrow",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {85, 85, 85},
         .env = {0, 50, 50},
         .pop = 100,
         .acc = 90,
         .want_inc = -1, /* (100*15/10)=150 => whole=1 rem=50; 90-50=40 => -1 */
         .want_pop_after = 99,
         .want_acc_after = 40},

        {.name = "pop=100 acc=0 desire=-15 => -2 with borrow, acc=50",
         .pref = {50, 50, 50},
         .minv = {15, 15, 15},
         .maxv = {85, 85, 85},
         .env = {0, 50, 50},
         .pop = 100,
         .acc = 0,
         .want_inc = -2, /* whole=1 rem=50; 0-50 borrows => -(1+1); acc=50 */
         .want_pop_after = 98,
         .want_acc_after = 50},
    };

    for (int i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        const PopCase *tc = &cases[i];

        PLAYER old0;
        apply_player0_env(tc, &old0);

        PLANET pl = make_planet_for_pop(tc);

        /* fUpdate=0: no mutation */
        PLANET  pl_copy = pl;
        int32_t inc = ChgPopFromPlanet(&pl, 0);
        TEST_CHECK_(inc == tc->want_inc, "%s: inc=%d want=%d", tc->name, (int)inc, (int)tc->want_inc);
        TEST_CHECK_(memcmp(&pl, &pl_copy, sizeof(pl)) == 0, "%s: fUpdate=0 must not mutate", tc->name);

        /* fUpdate=1: accumulator + pop update */
        pl = make_planet_for_pop(tc);
        inc = ChgPopFromPlanet(&pl, 1);
        TEST_CHECK_(inc == tc->want_inc, "%s (update): inc=%d want=%d", tc->name, (int)inc, (int)tc->want_inc);
        TEST_CHECK_(pl.rgwtMin[3] == tc->want_pop_after, "%s (update): pop=%d want=%d", tc->name, (int)pl.rgwtMin[3], (int)tc->want_pop_after);
        TEST_CHECK_(pl.rgbImp[0] == tc->want_acc_after, "%s (update): acc=%u want=%u", tc->name, (unsigned)pl.rgbImp[0], (unsigned)tc->want_acc_after);

        rgplr[0] = old0;
    }
}

TEST_LIST = {{"ChgPopFromPlanet negative desire table", test_ChgPopFromPlanet_negative_desire_table}, {NULL, NULL}};
