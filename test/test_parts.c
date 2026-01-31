#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "parts.h"
#include "types.h"

/*
 * test_parts.c
 *
 * Basic unit tests for FLookupPart():
 *  - pointer attachment and range checking
 *  - tech status return codes (Ok / Near / deficit)
 *  - disallowed lookups gated by RaMajor (PRT), e.g. Settler's Delight.
 */

static void save_player0(PLAYER *out_old) { *out_old = rgplr[0]; }

static void restore_player0(const PLAYER *old) { rgplr[0] = *old; }

static void clear_player0_for_tests(void) {
    /* Start from a clean baseline so tests are deterministic. */
    memset(&rgplr[0], 0, sizeof(rgplr[0]));
}

static PART make_part(HullSlotType grhst, uint16_t iItem, uint8_t cItem) {
    PART p;
    memset(&p, 0, sizeof(p));
    p.hs.grhst = grhst;
    p.hs.iItem = (uint16_t)(iItem & 0xFFu);
    p.hs.cItem = cItem;
    return p;
}

static void test_FLookupPart_basic_engine_attach(void) {
    const int16_t idPlayer_old = idPlayer;
    idPlayer = -1; /* no gating / no tech checks */

    PART    part = make_part(hstEngine, iengineQuickJump5, 1);
    int16_t got = FLookupPart(&part);

    TEST_CHECK_(got == LookupOk, "QuickJump5 without player: got=%d want=%d", (int)got, (int)LookupOk);
    TEST_CHECK_(part.pengine == &rgengine[iengineQuickJump5], "attached engine pointer mismatch: got=%p want=%p", (void *)part.pengine,
                (void *)&rgengine[iengineQuickJump5]);

    idPlayer = idPlayer_old;
}

static void test_FLookupPart_tech_status_ok_near_deficit(void) {
    const int16_t idPlayer_old = idPlayer;
    PLAYER        old0;
    save_player0(&old0);

    clear_player0_for_tests();

    idPlayer = 0;

    /* Neutral PRT; no special gating for these engines. */
    rgplr[0].rgAttr[rsMajorAdv] = raNone;

    /*
     * Alpha Drive 8 requires Propulsion 7 (rgengine[iengineAlphaDrive8].rgTech[2] == 7).
     * With no tech, we should get deficit = (need-have)+1 = (7-0)+1 = 8.
     */
    {
        PART    part = make_part(hstEngine, iengineAlphaDrive8, 1);
        int16_t got = FLookupPart(&part);
        TEST_CHECK_(got == 8, "AlphaDrive8 with tech 0: got=%d want=8", (int)got);
    }

    /*
     * "Near" case: exactly one short by 1 in the current research field.
     * Need 7, have 6, and iTechCur == 2 (Propulsion) => LookupNear (2).
     */
    {
        rgplr[0].rgTech[2] = 6;
        rgplr[0].iTechCur = 2;

        PART    part = make_part(hstEngine, iengineAlphaDrive8, 1);
        int16_t got = FLookupPart(&part);
        TEST_CHECK_(got == LookupNear, "AlphaDrive8 have6 need7 iTechCur=2: got=%d want=%d", (int)got, (int)LookupNear);
    }

    /*
     * OK case: meet the tech requirement exactly.
     */
    {
        rgplr[0].rgTech[2] = 7;
        rgplr[0].iTechCur = 0;

        PART    part = make_part(hstEngine, iengineAlphaDrive8, 1);
        int16_t got = FLookupPart(&part);
        TEST_CHECK_(got == LookupOk, "AlphaDrive8 have7: got=%d want=%d", (int)got, (int)LookupOk);
    }

    restore_player0(&old0);
    idPlayer = idPlayer_old;
}

static void test_FLookupPart_disallowed_settlers_delight_requires_HE(void) {
    const int16_t idPlayer_old = idPlayer;
    PLAYER        old0;
    save_player0(&old0);

    clear_player0_for_tests();
    idPlayer = 0;

    PART part = make_part(hstEngine, iengineSettlersDelight, 1);

    /* Not HE (raCheapCol) => disallowed */
    rgplr[0].rgAttr[rsMajorAdv] = raNone;
    {
        int16_t got = FLookupPart(&part);
        TEST_CHECK_(got == LookupDisallowed, "SettlersDelight without HE: got=%d want=%d", (int)got, (int)LookupDisallowed);
    }

    /* HE => allowed and (tech is 0) should be OK */
    rgplr[0].rgAttr[rsMajorAdv] = raCheapCol;
    {
        int16_t got = FLookupPart(&part);
        TEST_CHECK_(got == LookupOk, "SettlersDelight with HE: got=%d want=%d", (int)got, (int)LookupOk);
    }

    restore_player0(&old0);
    idPlayer = idPlayer_old;
}

TEST_LIST = {
    {"parts: FLookupPart basic engine attach", test_FLookupPart_basic_engine_attach},
    {"parts: FLookupPart tech status (ok/near/deficit)", test_FLookupPart_tech_status_ok_near_deficit},
    {"parts: FLookupPart disallowed (Settler's Delight requires HE)", test_FLookupPart_disallowed_settlers_delight_requires_HE},
    {NULL, NULL},
};
