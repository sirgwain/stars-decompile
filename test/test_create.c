#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "create.h"
#include "file.h"
#include "globals.h"
#include "init.h"
#include "types.h"

/* Snapshot/restore just the globals this test mutates. */
typedef struct SaveGlobalsSnapshot {
    char szBase[sizeof(szBase)];
    char szWork[sizeof(szWork)];
} SaveGlobalsSnapshot;

static SaveGlobalsSnapshot snapshot_globals(void) {
    SaveGlobalsSnapshot s;
    memcpy(s.szBase, szBase, sizeof(szBase));
    memcpy(s.szWork, szWork, sizeof(szWork));
    return s;
}

static void restore_globals(const SaveGlobalsSnapshot *s) {
    memcpy(szBase, s->szBase, sizeof(szBase));
    memcpy(szWork, s->szWork, sizeof(szWork));
}

static void generate_tutorial(void) {
    memset(szBase, 0, sizeof(szBase));
    strncpy(szBase, "./test/data/generated/tutorial", sizeof(szBase) - 1);
    CreateTutorWorld();
}

static void test_create__CreateTutorWorld(void) {
    SaveGlobalsSnapshot snap = snapshot_globals();
    MemJump             env;
    int                 j;

    DestroyCurGame();
    FAllocStuff();

    penvMem = &env;
    j = setjmp(env.env);
    if (j != 0) {
        DeallocStuff();
        restore_globals(&snap);
        TEST_MSG("CreateTutorWorld longjmp'd (fatal error)");
        TEST_ASSERT(false);
        return;
    }

    generate_tutorial();

    /* Verify game struct was populated correctly. */
    TEST_CHECK(game.cPlayer == 2);
    TEST_CHECK(game.lid == 0x008CEF49);
    TEST_CHECK(game.fTutorial == 1);
    TEST_CHECK(game.fNoRandom == 1);
    TEST_CHECK(game.mdSize == 0);
    TEST_CHECK(game.mdDensity == 0);
    TEST_CHECK(game.mdStartDist == 1);

    DestroyCurGame();
    DeallocStuff();
    restore_globals(&snap);
}

static void test_create__FLoadGame_tutor_HST(void) {
    SaveGlobalsSnapshot snap = snapshot_globals();
    MemJump             env;
    int                 j;

    DestroyCurGame();
    FAllocStuff();

    /* First, generate the tutorial world. */
    penvMem = &env;
    j = setjmp(env.env);
    if (j != 0) {
        DeallocStuff();
        restore_globals(&snap);
        TEST_MSG("CreateTutorWorld longjmp'd (fatal error)");
        TEST_ASSERT(false);
        return;
    }

    generate_tutorial();
    DestroyCurGame();

    /* Now load the generated HST file. */
    j = setjmp(env.env);
    if (j != 0) {
        DeallocStuff();
        restore_globals(&snap);
        TEST_MSG("FLoadGame HST longjmp'd (fatal file error)");
        TEST_ASSERT(false);
        return;
    }

    TEST_CHECK(FLoadGame("./test/data/generated/tutorial", "HST"));

    TEST_CHECK(game.cPlayer == 2);
    TEST_CHECK(game.lid == 0x008CEF49);
    TEST_CHECK(cPlanet > 0);

    /* Verify player names were loaded. */
    TEST_CHECK(rgplr[0].szName[0] != '\0');
    TEST_CHECK(rgplr[1].szName[0] != '\0');

    DestroyCurGame();
    DeallocStuff();
    restore_globals(&snap);
}

static void test_create__FLoadGame_tutor_M1(void) {
    SaveGlobalsSnapshot snap = snapshot_globals();
    MemJump             env;
    int                 j;

    DestroyCurGame();
    FAllocStuff();

    /* First, generate the tutorial world. */
    penvMem = &env;
    j = setjmp(env.env);
    if (j != 0) {
        DeallocStuff();
        restore_globals(&snap);
        TEST_MSG("CreateTutorWorld longjmp'd (fatal error)");
        TEST_ASSERT(false);
        return;
    }

    generate_tutorial();
    DestroyCurGame();

    /* Now load the generated M1 file. */
    j = setjmp(env.env);
    if (j != 0) {
        DeallocStuff();
        restore_globals(&snap);
        TEST_MSG("FLoadGame M1 longjmp'd (fatal file error)");
        TEST_ASSERT(false);
        return;
    }

    idPlayer = 0;
    TEST_CHECK(FLoadGame("./test/data/generated/tutorial", "M1"));

    TEST_CHECK(game.cPlayer == 2);
    TEST_CHECK(game.lid == 0x008CEF49);
    TEST_CHECK(cPlanet > 0);

    /* Player 0 should be fully loaded with detAll. */
    TEST_CHECK(rgplr[0].szName[0] != '\0');
    TEST_CHECK(rgplr[0].det == detAll);

    DestroyCurGame();
    DeallocStuff();
    restore_globals(&snap);
}

TEST_LIST = {
    // {"create/CreateTutorWorld populates game struct", test_create__CreateTutorWorld},
    {"create/FLoadGame loads tutorial HST", test_create__FLoadGame_tutor_HST},
    {"create/FLoadGame loads tutorial M1", test_create__FLoadGame_tutor_M1},
    {NULL, NULL},
};
