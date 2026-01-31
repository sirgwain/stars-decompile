#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "memory.h"
#include "msg.h" /* PctPlanetDesirability */
#include "types.h"

/* Keep these local to the test file. */
enum { TEST_MAX_PLAYERS = 3, TEST_MAX_SHDEF = 16 };

/* Backing storage for each player's design table. */
static SHDEF g_test_shdef[TEST_MAX_PLAYERS][TEST_MAX_SHDEF];

/* Snapshot rglpshdef pointers (not the structs they point to). */
typedef struct MsgGlobalsSnapshot {
    int16_t idPlayer;
    GAME    game;

    /* Save/restore the pointer table entries. */
    SHDEF *rglpshdef_ptrs[TEST_MAX_PLAYERS];

    int16_t rgidPlan[999];
    char    szBase[256];
    char    szWork[360];

    PLAYER rgplr0;
    PLAYER rgplr1;
    PLAYER rgplr2;

    int16_t *lpMsg
} MsgGlobalsSnapshot;

static void snapshot_globals(MsgGlobalsSnapshot *out) {
    out->idPlayer = idPlayer;
    out->game = game;

    /* Save current pointer table (first N players we touch in tests). */
    for (int i = 0; i < TEST_MAX_PLAYERS; i++) {
        out->rglpshdef_ptrs[i] = rglpshdef[i];
    }

    memcpy(out->rgidPlan, rgidPlan, sizeof(out->rgidPlan));
    memcpy(out->szBase, szBase, sizeof(out->szBase));
    memcpy(out->szWork, szWork, sizeof(out->szWork));

    out->rgplr0 = rgplr[0];
    out->rgplr1 = rgplr[1];
    out->rgplr2 = rgplr[2];

    out->lpMsg = lpMsg;
    // have to initalize lpMsg
    lpMsg = (int16_t *)LpAlloc(65480, htMsg);
}

static void restore_globals(const MsgGlobalsSnapshot *in) {
    idPlayer = in->idPlayer;
    game = in->game;

    /* Restore pointer table entries. */
    for (int i = 0; i < TEST_MAX_PLAYERS; i++) {
        rglpshdef[i] = in->rglpshdef_ptrs[i];
    }

    memcpy(rgidPlan, in->rgidPlan, sizeof(in->rgidPlan));
    memcpy(szBase, in->szBase, sizeof(in->szBase));
    memcpy(szWork, in->szWork, sizeof(in->szWork));

    rgplr[0] = in->rgplr0;
    rgplr[1] = in->rgplr1;
    rgplr[2] = in->rgplr2;

    // free our memmory and restore
    FreeLp(lpMsg, htMsg);
    lpMsg = in->lpMsg;
}

static void apply_minimal_fixtures(void) {
    /* Keep tests deterministic. */
    idPlayer = 1;
    game.cPlayer = 3;

    for (size_t i = 0; i < sizeof(rgidPlan) / sizeof(rgidPlan[0]); i++) {
        rgidPlan[i] = (int16_t)i;
    }

    strcpy(szBase, "BASEPATH");
    strcpy(szWork, "WORKTEXT");

    /* Player names for cases that route through PszPlayerName */
    rgplr[0] = (PLAYER){.iPlayer = 0, .szName = "Alpha", .szNames = "Alphas"};
    rgplr[1] = (PLAYER){.iPlayer = 1, .szName = "Bravo", .szNames = "Bravos"};
    rgplr[2] = (PLAYER){.iPlayer = 2, .szName = "Charlie", .szNames = "Charlies"};

    /* ---------------------------
     * Minimal SHDEF setup
     * --------------------------- */

    /* Zero the backing tables. */
    memset(g_test_shdef, 0, sizeof(g_test_shdef));

    /* Point the global pointer table at our backing storage. */
    for (int iplr = 0; iplr < TEST_MAX_PLAYERS; iplr++) {
        rglpshdef[iplr] = &g_test_shdef[iplr][0];
    }

    /* Populate a couple of designs for player 1 (idPlayer) */
    {
        SHDEF *tbl = rglpshdef[1];

        /* A non-free design (what your code path cares about). */
        tbl[2].fFree = 0;
        strcpy(tbl[2].hul.szClass, "Scout");

        /* A free design entry to exercise the other branch if you want. */
        tbl[3].fFree = 1;
        tbl[3].hul.szClass[0] = '\0';
    }

    /* Optionally: if other players’ ship names are needed in \z formatting */
    {
        SHDEF *tbl0 = rglpshdef[0];
        tbl0[2].fFree = 0;
        strcpy(tbl0[2].hul.szClass, "Raider");
    }
}

/* ------------------------------------------------------------
 * Table-driven tests
 * ------------------------------------------------------------ */

typedef struct MsgCase {
    const char *name;
    const char *fmt;
    int16_t     params[6];
    const char *want;
} MsgCase;

static void test_PszFormatString_table(void) {
    static const MsgCase cases[] = {
        {
            .name = "literal passthrough",
            .fmt = "Hello world",
            .want = "Hello world",
        },
        {
            .name = "unknown escape emits literal",
            .fmt = "\\Q",
            .want = "Q",
        },

        /* Direct table lookups (we control the tables) */
        {
            .name = "M minefield table",
            .fmt = "\\M",
            .params = {2},
            .want = "Speed Bump",
        },
        {
            .name = "e planet attribute table",
            .fmt = "\\e",
            .params = {1},
            .want = "Temperature",
        },
        {
            .name = "m mineral table",
            .fmt = "\\m",
            .params = {4},
            .want = "Fuel",
        },
        {
            .name = "w copies szWork",
            .fmt = "A\\wB",
            .want = "AWORKTEXTB",
        },
        {
            .name = "E calls PszCalcEnvVar with hi/lo bytes",
            .fmt = "\\E",
            .params = {(int16_t)0x0207}, /* env=2 var=7 */
            .want = "7mR",
        },
        {
            .name = "F calls PszFleetNameFromWord",
            .fmt = "blah\\F",
            .params = {123},
            .want = "blah #124",
        },
        {
            .name = "I calls PszGetCompressedString(idsDecreased+param)",
            .fmt = "\\I",
            .params = {0},
            .want = "decreased",
        },
        {
            .name = "I calls PszGetCompressedString(idsDecreased+param)",
            .fmt = "\\I",
            .params = {1},
            .want = "increased",
        },
        {
            .name = "j calls PszGetCompressedString(idsEnergy+param)",
            .fmt = "\\j",
            .params = {0},
            .want = "Energy",
        },
        {
            .name = "L player name from flags (capital)",
            .fmt = "\\L",
            .params = {(int16_t)(2 | 0x10 | 0x20 | (1 << 6))}, /* iPlayer=2 plural+the grWord=1 */
            .want = "The Charlies have",
        },
        {
            .name = "l player name from flags (not capital)",
            .fmt = "\\l",
            .params = {(int16_t)(0)}, /* iPlayer=0 */
            .want = "Alpha",
        },
        {
            .name = "O owner packed in bits 9..12",
            .fmt = "\\O",
            .params = {(int16_t)(3 << 9)},
            .want = "Player %d's",
        },
        {
            .name = "g thing name",
            .fmt = "\\g",
            .params = {0},
            .want = "",
        },
        {
            .name = "p planet name",
            .fmt = "\\p",
            .params = {0},
            .want = "007",
        },
        {
            .name = "p planet name 2 orbiting",
            .fmt = "\\p",
            .params = {1 | 0x8000},
            .want = "Orbiting 14 coli",
        },
        {
            .name = "s force fleet name (sets high bit)",
            .fmt = "\\s",
            .params = {0x0123},
            .want = "Alpha Fleet #292",
        },
        {
            .name = "n location name uses grobjNone,-1 and x/y",
            .fmt = "\\n",
            .params = {7, 8},
            .want = "Space (7, 8)",
        },

        /* Pure formatting in PszFormatString itself */
        {
            .name = "u prints unsigned",
            .fmt = "\\u",
            .params = {(int16_t)65535},
            .want = "65535",
        },
        {
            .name = "i prints signed decimal via PCTD",
            .fmt = "\\i",
            .params = {-123},
            .want = "-123",
        },
        {
            .name = "P prints percent with fraction",
            .fmt = "\\P",
            .params = {1234},
            .want = "12.34%",
        },
        {
            .name = "P prints percent w/o fraction (your current behavior uses %dkT)",
            .fmt = "\\P",
            .params = {1200},
            .want = "12kT",
        },
    };

    MsgGlobalsSnapshot snap;
    snapshot_globals(&snap);
    apply_minimal_fixtures();

    for (size_t idx = 0; idx < sizeof(cases) / sizeof(cases[0]); idx++) {
        const MsgCase *tc = &cases[idx];

        /* Run */
        char *got = PszFormatString((char *)tc->fmt, (int16_t *)tc->params);

        TEST_CHECK_(got == szMsgBuf, "case[%zu] %s: return pointer must be szMsgBuf", idx, tc->name);
        TEST_CHECK_(strcmp(got, tc->want) == 0, "case[%zu] %s:\n  fmt=\"%s\"\n  got =\"%s\"\n  want=\"%s\"", idx, tc->name, tc->fmt, got, tc->want);
    }

    restore_globals(&snap);
}

/* ------------------------------------------------------------
 * PackageUpMsg packing tests
 * ------------------------------------------------------------ */

static MessageId find_msg_with_nargs(uint8_t n) {
    /* Message ids are stored in 9 bits (0..0x1FF). */
    for (uint16_t i = 0; i <= 0x01FFu; i++) {
        if (((const uint8_t *)rgcMsgArgs)[i] == n)
            return (MessageId)i;
    }

    /* If this ever trips, the message table layout changed. */
    return (MessageId)0;
}

static void test_PackageUpMsg_packs_bytes_and_words(void) {
    MsgGlobalsSnapshot snap;
    snapshot_globals(&snap);
    apply_minimal_fixtures();

    /* Ensure the gating logic allows the message to be queued. */
    rgplr[2].fAi = 0;
    rgplr[2].idAi = 0;

    /* Pick any message id that expects exactly 3 params so we can
     * deterministically test grWord and cbParams. */
    MessageId iMsg = find_msg_with_nargs(3);
    TEST_CHECK_(iMsg != (MessageId)0, "need a message id with 3 params in rgcMsgArgs");

    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));

    /* Keep the offset small so the bounds check passes. */
    imemMsgCur = 0;

    /* p1 fits in a byte, p2 forces a word, p3 fits in a byte. */
    int16_t cb = PackageUpMsg(buf, /*iPlr=*/2, iMsg, /*iObj=*/-123,
                              /*p1=*/0x12,
                              /*p2=*/(int16_t)0x1234,
                              /*p3=*/(int16_t)0x00FF,
                              /*p4=*/0, /*p5=*/0, /*p6=*/0, /*p7=*/0);

    TEST_CHECK_(cb == 9, "expected packed size 9 (5 header + 4 params), got %d", (int)cb);

    {
        const MSGTURN *mt = (const MSGTURN *)buf;

        TEST_CHECK_(mt->iPlr == 2, "iPlr nibble wrong: got %u", (unsigned)mt->iPlr);
        TEST_CHECK_(mt->cbParams == 4, "cbParams wrong: got %u", (unsigned)mt->cbParams);

        TEST_CHECK_(mt->msghdr.iMsg == ((uint16_t)iMsg & 0x01FFu), "iMsg wrong: got %u", (unsigned)mt->msghdr.iMsg);
        TEST_CHECK_(mt->msghdr.wGoto == -123, "wGoto wrong: got %d", (int)mt->msghdr.wGoto);

        /* Only the 2nd arg (bit 1) should be a word. */
        TEST_CHECK_(mt->msghdr.grWord == 0x0002u, "grWord wrong: got 0x%X", (unsigned)mt->msghdr.grWord);
    }

    /* Verify payload bytes (little-endian word). */
    TEST_CHECK_(buf[5] == 0x12, "p1 byte wrong: got 0x%02X", (unsigned)buf[5]);
    TEST_CHECK_(buf[6] == 0x34 && buf[7] == 0x12, "p2 word bytes wrong: got 0x%02X 0x%02X", (unsigned)buf[6], (unsigned)buf[7]);
    TEST_CHECK_(buf[8] == 0xFF, "p3 byte wrong: got 0x%02X", (unsigned)buf[8]);

    restore_globals(&snap);
}

static void test_FSendPlrMsg_appends_first_player_message(void) {
    MsgGlobalsSnapshot snap;
    snapshot_globals(&snap);
    apply_minimal_fixtures();

    /* Ensure player 0 is allowed to receive messages */
    rgplr[0].fAi = 0;
    rgplr[0].idAi = 0;

    /* Start with empty message buffer */
    imemMsgCur = 0;
    cMsg = 0;

    /* Use the first message a player gets */
    {
        int16_t i = 0;
        int16_t iMin = 0;

        int16_t ret = FSendPlrMsg(i, idmHomePlanetPeopleReadyLeaveNestExplore, iMin, iMin, 0, 0, 0, 0, 0, 0);

        TEST_CHECK_(ret == 1, "FSendPlrMsg should return 1 for initial player message");
    }

    /* One message should now be queued */
    TEST_CHECK_(cMsg == 1, "expected cMsg == 1, got %d", (int)cMsg);
    TEST_CHECK_(imemMsgCur > 0, "imemMsgCur should advance after message append");

    /* Inspect the queued message header */
    {
        const MSGTURN *mt = (const MSGTURN *)lpMsg;

        TEST_CHECK_(mt->iPlr == 0, "iPlr wrong: got %u", (unsigned)mt->iPlr);

        TEST_CHECK_(mt->msghdr.iMsg == (uint16_t)idmHomePlanetPeopleReadyLeaveNestExplore, "iMsg wrong: got %u", (unsigned)mt->msghdr.iMsg);
    }

    restore_globals(&snap);
}

TEST_LIST = {
    {"MSG/PszFormatString table", test_PszFormatString_table},
    {"MSG/PackageUpMsg packs bytes+words", test_PackageUpMsg_packs_bytes_and_words},
    {"MSG/FSendPlrMsg appends first message", test_FSendPlrMsg_appends_first_player_message},
    {NULL, NULL},
};
