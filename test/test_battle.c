#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "types.h"
#include "parts.h"
#include "battle.h" /* SpdOfShip */

typedef struct SpdOfShipArgs
{
    /* These mirror the table the user provided (mostly for documentation). */
    int16_t idealEngineSpeed; /* warp */
    uint16_t mass;            /* kT -> hul.wtEmpty */
    uint8_t numEngines;       /* engine count in slot 0 */
    int16_t movementBonus_x2; /* movement bonus * 2 (so 0.5 == 1, 2.5 == 5) */

    /* What we actually need to construct the SHDEF for the test. */
    uint8_t iengine;     /* iengine enum value stored in HS.iItem */
    uint8_t addThruster; /* add 1x Maneuvering Jet (hstSpecialM) */
    uint8_t fAttack;     /* set player's major advantage to raAttack */
} SpdOfShipArgs;

typedef struct SpdOfShipCase
{
    const char *name;
    SpdOfShipArgs args;
    int16_t want;
} SpdOfShipCase;

static void set_engine_maxwarp(uint8_t iengine, int16_t wantWarp, ENGINE *old_out)
{
    ENGINE *pe = LpengineFromId((int16_t)iengine);
    TEST_CHECK_(pe != NULL, "LpengineFromId(%u) returned NULL", (unsigned)iengine);

    if (old_out != NULL)
    {
        *old_out = *pe;
    }

    /* SpdOfShip scans iWarp from 9 down to 1 and picks the highest where fuelUsed[iWarp] <= 120.
       Force that behavior by setting >120 above wantWarp and <=120 at/below wantWarp.

       Note: special engines (Interspace10/Enigma/TransStar10/.../GalaxyScoop) ignore this,
       but it is harmless to set anyway.
    */
    for (int i = 0; i < 12; i++)
    {
        pe->rgcFuelUsed[i] = 0;
    }

    for (int i = 9; i > 0; i--)
    {
        pe->rgcFuelUsed[i] = (i > wantWarp) ? 121 : 0;
    }
}

static SHDEF make_shdef_spd(uint16_t mass, uint8_t iengine, uint8_t numEngines, uint8_t addThruster)
{
    SHDEF sh;
    memset(&sh, 0, sizeof(sh));

    sh.hul.wtEmpty = mass;
    sh.hul.wtCargoMax = 0; /* keep SpdOfShip out of cargo math */

    /* slot 0 is used as the divisor for weight penalty (num engines). */
    sh.hul.rghs[0].grhst = hstEngine;
    sh.hul.rghs[0].iItem = iengine;
    sh.hul.rghs[0].cItem = numEngines;

    sh.hul.chs = 1;

    if (addThruster)
    {
        sh.hul.rghs[1].grhst = hstSpecialM;
        sh.hul.rghs[1].iItem = ispecialMManeuveringJet;
        sh.hul.rghs[1].cItem = 1;
        sh.hul.chs = 2;
    }

    return sh;
}

static void test_SpdOfShip_table(void)
{
    static const SpdOfShipCase cases[] = {
        {"248 kT Destroyer + Trans Galactic Drive + thruster",
         {.idealEngineSpeed = 9, .mass = 248, .numEngines = 1, .movementBonus_x2 = 2, .iengine = iengineTransGalacticDrive, .addThruster = 1, .fAttack = 0},
         3},

        {"69 kT Destroyer + 1 Enigma Pulsar",
         {.idealEngineSpeed = 10, .mass = 69, .numEngines = 1, .movementBonus_x2 = 1, .iengine = iengineEnigmaPulsar, .addThruster = 0, .fAttack = 0},
         7},

        {"71 kT Destroyer + 1 Enigma Pulsar",
         {.idealEngineSpeed = 10, .mass = 71, .numEngines = 1, .movementBonus_x2 = 1, .iengine = iengineEnigmaPulsar, .addThruster = 0, .fAttack = 0},
         6},

        {"71 kT Destroyer + 1 Enigma Pulsar + WM",
         {.idealEngineSpeed = 10, .mass = 71, .numEngines = 1, .movementBonus_x2 = 5, .iengine = iengineEnigmaPulsar, .addThruster = 0, .fAttack = 1},
         8},

        {"71 kT Cruiser w/ 2 Enigma Pulsars",
         {.idealEngineSpeed = 10, .mass = 71, .numEngines = 2, .movementBonus_x2 = 2, .iengine = iengineEnigmaPulsar, .addThruster = 0, .fAttack = 0},
         7},

        {"572 kT Miner w/ Radiating Hydro Ram Scoop",
         {.idealEngineSpeed = 6, .mass = 572, .numEngines = 1, .movementBonus_x2 = 0, .iengine = iengineRadiatingHydroRamScoop, .addThruster = 0, .fAttack = 0},
         0},
    };

    /* Save/restore globals we touch. */
    const PLAYER plr0_old = rgplr[0];

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        const SpdOfShipCase *tc = &cases[i];

        /* Prepare engine lookup behavior for this test. */
        ENGINE eng_old;
        set_engine_maxwarp(tc->args.iengine, tc->args.idealEngineSpeed, &eng_old);

        /* Set up player major advantage for WM case. */
        rgplr[0] = plr0_old;
        if (tc->args.fAttack)
        {
            /* SpdOfShip adds +2 if GetRaceStat(..., rsMajorAdv) == raAttack.
               GetRaceStat reads PLAYER.rgAttr[RaceStat]. */
            rgplr[0].rgAttr[rsMajorAdv] = (int8_t)raAttack;
        }

        /* Minimal fleet context (we keep ptok NULL to avoid Random()) */
        FLEET fl;
        memset(&fl, 0, sizeof(fl));
        fl.iPlayer = 0;

        SHDEF sh = make_shdef_spd(tc->args.mass, tc->args.iengine, tc->args.numEngines, tc->args.addThruster);

        int16_t got = SpdOfShip(&fl, 0, NULL, 0, &sh);

        TEST_CHECK_(got == tc->want,
                    "case[%zu] %s: got=%d want=%d (warp=%d mass=%u engines=%u bonus=%.1f)",
                    i, tc->name, (int)got, (int)tc->want,
                    (int)tc->args.idealEngineSpeed, (unsigned)tc->args.mass, (unsigned)tc->args.numEngines,
                    (double)tc->args.movementBonus_x2 / 2.0);

        /* Restore engine table entry. */
        *LpengineFromId((int16_t)tc->args.iengine) = eng_old;
    }

    rgplr[0] = plr0_old;
}

TEST_LIST = {
    {"SpdOfShip table", test_SpdOfShip_table},
    {NULL, NULL}};
