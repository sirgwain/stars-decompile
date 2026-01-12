#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "types.h"
#include "file.h" /* FLoadGame */

/* Snapshot/restore just the globals this test mutates. */
typedef struct SaveGlobalsSnapshot
{
    char szBase[sizeof(szBase)];
    char szWork[sizeof(szWork)];
} SaveGlobalsSnapshot;

static SaveGlobalsSnapshot snapshot_globals(void)
{
    SaveGlobalsSnapshot s;
    memcpy(s.szBase, szBase, sizeof(szBase));
    memcpy(s.szWork, szWork, sizeof(szWork));
    return s;
}

static void restore_globals(const SaveGlobalsSnapshot *s)
{
    memcpy(szBase, s->szBase, sizeof(szBase));
    memcpy(szWork, s->szWork, sizeof(szWork));
}

static void set_base(const char *base)
{
    /* Ensure deterministic contents, then copy. */
    memset(szBase, 0, sizeof(szBase));
    memset(szWork, 0, sizeof(szWork));
    strncpy(szBase, base, sizeof(szBase) - 1);
}

static void test_file__FLoadGame_tiny_2400(void)
{
    SaveGlobalsSnapshot snap = snapshot_globals();
    MemJump env;
    int j;

    /* Ensure globals are in a known state for this test. */
    DestroyCurGame();

    penvMem = &env;
    j = setjmp(env.env);
    if (j != 0)
    {
        restore_globals(&snap);
        TEST_MSG("FLoadGame longjmp'd (fatal file error)");
        TEST_ASSERT(false);
        return;
    }

    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    printf("CWD = %s\n", cwd);
    TEST_CHECK(FLoadGame("./test/data/tiny/2401/TEST", "HST"));

    /* Tiny test files represent year 2400 (turn 1). Validate that we parsed
     * something plausible.
     */
    TEST_CHECK(game.turn == 1);
    TEST_CHECK(game.cPlayer > 0);
    TEST_CHECK(cPlanet > 0);

    /* Cleanup and restore.
     * DestroyCurGame() may touch UI globals but is stubbed for non-Windows.
     */
    DestroyCurGame();
    restore_globals(&snap);
}

TEST_LIST = {
    {"file/FLoadGame loads tiny 2400", test_file__FLoadGame_tiny_2400},
    {NULL, NULL}};
