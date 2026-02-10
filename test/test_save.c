#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "save.h" /* SetSzWorkFromDt */
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

static void set_base(const char *base) {
    /* Ensure deterministic contents, then copy. */
    memset(szBase, 0, sizeof(szBase));
    memset(szWork, 0, sizeof(szWork));
    strncpy(szBase, base, sizeof(szBase) - 1);
}

static void test_SetSzWorkFromDt_table(void) {
    const SaveGlobalsSnapshot snap = snapshot_globals();

    typedef struct {
        const char *name;
        const char *base_in;
        DtFileType  dt;
        int16_t     iPlayer;
        const char *want_work;
        const char *want_base_after;
    } Case;

    const Case cases[] = {
        {
            "dtTurn appends .xy and strips extension",
            "game1.sta",
            dtXY,
            7,
            "game1.xy",
            "game1",
        },
        {
            "dtHost appends .hst and strips extension (path)",
            "C:\\GAMES\\STARS\\mystuff.gam",
            dtHost,
            3,
            "C:\\GAMES\\STARS\\mystuff.hst",
            "C:\\GAMES\\STARS\\mystuff",
        },
        {
            "dtLog uses .mN with %c%d format",
            "foo.bar",
            dtTurn,
            10,
            "foo.m11",
            "foo",
        },
        {
            "dtXY uses .xN with %c%d format",
            "foo.bar",
            dtLog,
            0,
            "foo.x1",
            "foo",
        },
        {
            "dtHist uses .hN with %c%d format",
            "foo.bar",
            dtHist,
            15,
            "foo.h16",
            "foo",
        },
        {
            "dot in directory does not count as extension",
            "C:\\dir.name\\file",
            dtXY,
            2,
            "C:\\dir.name\\file.xy",
            "C:\\dir.name\\file",
        },
        {
            "dot before last backslash is not stripped",
            "C:\\dir.name\\file.ext",
            dtXY,
            2,
            "C:\\dir.name\\file.xy",
            "C:\\dir.name\\file",
        },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const Case *tc = &cases[i];

        set_base(tc->base_in);
        SetSzWorkFromDt(tc->dt, tc->iPlayer);

        TEST_CHECK(strcmp(szWork, tc->want_work) == 0);
        if (strcmp(szWork, tc->want_work) != 0) {
            TEST_MSG("%s: szWork got='%s' want='%s'", tc->name, szWork, tc->want_work);
        }

        TEST_CHECK(strcmp(szBase, tc->want_base_after) == 0);
        if (strcmp(szBase, tc->want_base_after) != 0) {
            TEST_MSG("%s: szBase got='%s' want='%s'", tc->name, szBase, tc->want_base_after);
        }
    }

    restore_globals(&snap);
}

TEST_LIST = {{"save/SetSzWorkFromDt (table)", test_SetSzWorkFromDt_table}, {NULL, NULL}};
