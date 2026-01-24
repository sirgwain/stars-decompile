#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "types.h"
#include "parts.h"
#include "ship.h" /* WtMaxShdefStat, LGetFleetStat */


static void test_WtMaxShdefStat_table(void)
{
    struct Case
    {
        const char *name;
        SHDEF shdef;
        int16_t grStat;
        int16_t want;
    };

    static const struct Case cases[] = {
        {"Small Freighter Cargo returns wtCargoMax", {.hul = {.ihuldef = ihuldefSmallFreighter}}, grStatCargo, 70},
        {"Small Freighter Fuel returns wtFuelMax", {.hul = {.ihuldef = ihuldefSmallFreighter}}, grStatFuel, 130},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        const struct Case *tc = &cases[i];

        int16_t got = WtMaxShdefStat(&tc->shdef, tc->grStat);

        TEST_CHECK_(got == tc->want,
                    "case[%zu] %s: got=%d want=%d",
                    i, tc->name, (int)got, (int)tc->want);
    }
}

static void test_LGetFleetStat_basic(void)
{
    /* Save/restore the per-player SHDEF table pointer. */
    SHDEF *old0 = rglpshdef[0];

    /* Construct a small SHDEF table for player 0. */
    SHDEF shdefs[16];
    memset(shdefs, 0, sizeof(shdefs));

    /* Two ship designs with known caps. */    
    shdefs[0] = (SHDEF){.hul = {.ihuldef = ihuldefSmallFreighter}};
    shdefs[1] = (SHDEF){.hul = {.ihuldef = ihuldefFuelTransport}};

    rglpshdef[0] = shdefs;

    /* Fleet containing 3 ships of design 0 and 2 ships of design 1. */
    FLEET fl;
    memset(&fl, 0, sizeof(fl));
    fl.iPlayer = 0;
    fl.det = 7; /* normal fleet: enable summation path */
    fl.rgcsh[0] = 3;
    fl.rgcsh[1] = 2;

    {
        int32_t got = LGetFleetStat(&fl, grStatCargo);
        int32_t want = (int32_t)3 * 70 + (int32_t)2 * 0;
        TEST_CHECK_(got == want, "grStatCargo: got=%ld want=%ld", (long)got, (long)want);
    }

    {
        int32_t got = LGetFleetStat(&fl, grStatFuel);
        int32_t want = (int32_t)3 * 130 + (int32_t)2 * 750;
        TEST_CHECK_(got == want, "grStatFuel: got=%ld want=%ld", (long)got, (long)want);
    }

    /* Non-normal fleets return the sentinel. */
    fl.det = 0;
    {
        int32_t got = LGetFleetStat(&fl, grStatCargo);
        TEST_CHECK_(got == 32000, "det!=7 sentinel: got=%ld want=32000", (long)got);
    }

    rglpshdef[0] = old0;
}

TEST_LIST = {
    {"WtMaxShdefStat table", test_WtMaxShdefStat_table},
    {"LGetFleetStat basic", test_LGetFleetStat_basic},
    {NULL, NULL}};
