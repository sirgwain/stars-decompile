#include "acutest.h"

#include <stdlib.h>
#include <string.h>

#include "globals.h"
#include "types.h"
#include "thing.h"
#include "turn2.h"
#include "build.h"

static void test_FreeLpth_shifts_and_decrements(void)
{
    THING *saved_lpThings = lpThings;
    int16_t saved_cThing = cThing;

    lpThings = (THING *)calloc(3, sizeof(THING));
    TEST_CHECK(lpThings != NULL);

    cThing = 3;

    lpThings[0].idFull = 0x1111;
    lpThings[1].idFull = 0x2222;
    lpThings[2].idFull = 0x3333;

    FreeLpth(&lpThings[1]);

    TEST_CHECK(cThing == 2);
    TEST_CHECK(lpThings[0].idFull == 0x1111);
    TEST_CHECK(lpThings[1].idFull == 0x3333);

    free(lpThings);
    lpThings = saved_lpThings;
    cThing = saved_cThing;
}

static void test_PctWormholeMoves_clamps_and_uses_fields(void)
{
    THING th = {0};

    /* pct = (cLastMove/5) - (2 - iStable), clamped to [0,6] */
    th.thw.cLastMove = 0;
    th.thw.iStable = 0;
    TEST_CHECK(PctWormholeMoves(&th) == 0);

    th.thw.cLastMove = 10; /* /5 => 2 */
    th.thw.iStable = 2;
    /* 2 - (2 - 2) = 2 */
    TEST_CHECK(PctWormholeMoves(&th) == 2);

    th.thw.cLastMove = 1000; /* /5 => 200, should clamp */
    th.thw.iStable = 2;
    TEST_CHECK(PctWormholeMoves(&th) == 6);
}

static void test_UnmarkMineFields_clears_grbitPlrNow_only_for_mines(void)
{
    THING *saved_lpThings = lpThings;
    int16_t saved_cThing = cThing;

    lpThings = (THING *)calloc(2, sizeof(THING));
    TEST_CHECK(lpThings != NULL);

    cThing = 2;

    /* Mine (ith == 0) */
    lpThings[0].ith = 0;
    lpThings[0].thm.grbitPlrNow = 0xBEEF;

    /* Not a mine */
    lpThings[1].ith = 1;
    lpThings[1].thm.grbitPlrNow = 0xCAFE;

    UnmarkMineFields();

    TEST_CHECK(lpThings[0].thm.grbitPlrNow == 0);
    TEST_CHECK(lpThings[1].thm.grbitPlrNow == 0xCAFE);

    free(lpThings);
    lpThings = saved_lpThings;
    cThing = saved_cThing;
}

static void test_IEmptyBmpFromGrhst_finds_index_or_zero(void)
{
    /* rgmapBuildBmps[0] is some sentinel; function returns 0 when not found */
    TEST_CHECK(IEmptyBmpFromGrhst((HullSlotType)rgmapBuildBmps[0]) == 0);
    TEST_CHECK(IEmptyBmpFromGrhst((HullSlotType)rgmapBuildBmps[1]) == 1);
    TEST_CHECK(IEmptyBmpFromGrhst((HullSlotType)0x7fff) == 0);
}

TEST_LIST = {
    {"FreeLpth", test_FreeLpth_shifts_and_decrements},
    {"PctWormholeMoves", test_PctWormholeMoves_clamps_and_uses_fields},
    {"UnmarkMineFields", test_UnmarkMineFields_clears_grbitPlrNow_only_for_mines},
    {"IEmptyBmpFromGrhst", test_IEmptyBmpFromGrhst_finds_index_or_zero},
    {NULL, NULL},
};
