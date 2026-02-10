#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "create.h"
#include "file.h"
#include "globals.h"
#include "init.h"
#include "mdi.h"
#include "turn.h"
#include "types.h"

/* Snapshot/restore globals this test mutates. */
typedef struct SaveGlobalsSnapshot {
    char    szBase[sizeof(szBase)];
    char    szWork[sizeof(szWork)];
    int16_t idPlayerSav;
} SaveGlobalsSnapshot;

static SaveGlobalsSnapshot snapshot_globals(void) {
    SaveGlobalsSnapshot s;
    memcpy(s.szBase, szBase, sizeof(szBase));
    memcpy(s.szWork, szWork, sizeof(szWork));
    s.idPlayerSav = idPlayer;
    return s;
}

static void restore_globals(const SaveGlobalsSnapshot *s) {
    memcpy(szBase, s->szBase, sizeof(szBase));
    memcpy(szWork, s->szWork, sizeof(szWork));
    idPlayer = s->idPlayerSav;
}

static void test_turn__FGenerateTurn_pop_grows(void) {
    SaveGlobalsSnapshot snap = snapshot_globals();
    MemJump             env;
    int                 j;
    uint32_t            popBefore;
    uint32_t            popAfter;

    DestroyCurGame();
    FAllocStuff();

    penvMem = &env;
    j = setjmp(env.env);
    if (j != 0) {
        DeallocStuff();
        restore_globals(&snap);
        TEST_MSG("longjmp'd (fatal error)");
        TEST_ASSERT(false);
        return;
    }

    /* 1. Generate a new world from the .def file. */
    int16_t ok = GenNewGameFromFile("./test/data/game.def");
    TEST_ASSERT_(ok, "GenNewGameFromFile succeeded");

    /* 2. Record player 0's homeworld population before the turn. */
    DestroyCurGame();
    idPlayer = 0;
    TEST_ASSERT_(FLoadGame(szBase, "M1"), "FLoadGame M1 before turn");

    popBefore = 0;
    for (int16_t i = 0; i < cPlanet; i++) {
        if (lpPlanets[i].iPlayer == 0 && lpPlanets[i].fHomeworld) {
            popBefore = (uint32_t)lpPlanets[i].rgwtMin[3];
            break;
        }
    }
    TEST_CHECK_(popBefore > 0, "homeworld has initial pop: %u", (unsigned)popBefore);

    DestroyCurGame();

    /* 3. Generate a turn (host context, mirrors cli.c do_generate_turns_from_host). */
    idPlayer = -1;
    EnsureAis();
    ok = FGenerateTurn();
    TEST_CHECK_(ok, "FGenerateTurn succeeded");

    /* 4. Load the updated M1 and verify population changed. */
    DestroyCurGame();
    idPlayer = 0;
    TEST_ASSERT_(FLoadGame(szBase, "M1"), "FLoadGame M1 after turn");

    popAfter = 0;
    for (int16_t i = 0; i < cPlanet; i++) {
        if (lpPlanets[i].iPlayer == 0 && lpPlanets[i].fHomeworld) {
            popAfter = (uint32_t)lpPlanets[i].rgwtMin[3];
            break;
        }
    }
    TEST_CHECK_(popAfter > 0, "homeworld has pop after turn: %u", (unsigned)popAfter);
    TEST_CHECK_(popAfter != popBefore,
                "population changed: before=%u after=%u",
                (unsigned)popBefore, (unsigned)popAfter);

    DestroyCurGame();
    DeallocStuff();
    restore_globals(&snap);
}

TEST_LIST = {
    {"turn/FGenerateTurn population grows", test_turn__FGenerateTurn_pop_grows},
    {NULL, NULL},
};
