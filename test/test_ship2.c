#include "acutest.h"

#include <stdint.h>
#include <string.h>
#include "globals.h"
#include "ship2.h"
#include "types.h"

static int16_t expected_colonizer_for_shdef(const SHDEF *psh) {
    /* FColonizer: ((wFlags << 1) & 0xC000) != 0  <=>  (wFlags & 0x6000) != 0
       SHDEF overlay: wFlags bits 13..14 are ishdef bits 3..4 -> mask 0x18 */
    return (int16_t)((((uint16_t)psh->ishdef & 0x0018u) != 0) ? 1 : 0);
}

static int16_t expected_scout_for_shdef(const SHDEF *psh) {
    /* FScout: ((wFlags << 1) & 0x70) != 0  <=>  (wFlags & 0x38) != 0
       SHDEF overlay: low byte is det -> det bits 3..5 mask 0x38 */
    return (int16_t)((((uint16_t)psh->det & 0x0038u) != 0) ? 1 : 0);
}

static void test_FColonizer_and_FScout_basic(void) {
    SHDEF old_rgshdef[ishdefMax];
    memcpy(old_rgshdef, rgshdef, sizeof(old_rgshdef));
    memset(rgshdef, 0, sizeof(old_rgshdef));

    /* Each case controls SHDEF flags directly (independent of hulldef). */
    struct {
        uint8_t  det;
        uint16_t ishdef;
        int16_t  wantScout;
        int16_t  wantColonizer;
    } cases[] = {
        /* none set */
        {0x00, 0x00, 0, 0},

        /* scout only: det bits 3..5 (0x38) */
        {0x08, 0x00, 1, 0},
        {0x20, 0x00, 1, 0},

        /* colonizer only: ishdef bits 3..4 (0x18) */
        {0x00, 0x08, 0, 1},
        {0x00, 0x10, 0, 1},
        {0x00, 0x18, 0, 1},

        /* both */
        {0x38, 0x18, 1, 1},
    };

    for (int ci = 0; ci < (int)(sizeof(cases) / sizeof(cases[0])); ci++) {
        int16_t ish = 3; /* arbitrary slot */
        memset(rgshdef, 0, sizeof(old_rgshdef));

        rgshdef[ish].det = cases[ci].det;
        rgshdef[ish].ishdef = cases[ci].ishdef;

        FLEET fl;
        memset(&fl, 0, sizeof(fl));
        fl.rgcsh[ish] = 1;

        int16_t wantS = expected_scout_for_shdef(&rgshdef[ish]);
        int16_t wantC = expected_colonizer_for_shdef(&rgshdef[ish]);
        int16_t gotS = FScout(&fl);
        int16_t gotC = FColonizer(&fl);

        TEST_CHECK_(wantS == cases[ci].wantScout, "case %d scout expected helper mismatch", ci);
        TEST_CHECK_(wantC == cases[ci].wantColonizer, "case %d colonizer expected helper mismatch", ci);

        TEST_CHECK_(gotS == wantS, "case %d scout got=%d want=%d det=0x%02x", ci, (int)gotS, (int)wantS, (unsigned)cases[ci].det);
        TEST_CHECK_(gotC == wantC, "case %d colonizer got=%d want=%d ishdef=0x%x", ci, (int)gotC, (int)wantC, (unsigned)cases[ci].ishdef);
    }

    /* No ships -> false */
    {
        FLEET fl;
        memset(&fl, 0, sizeof(fl));
        TEST_CHECK(FColonizer(&fl) == 0);
        TEST_CHECK(FScout(&fl) == 0);
    }

    /* Multiple ships: any matching slot should trigger */
    {
        memset(rgshdef, 0, sizeof(old_rgshdef));

        FLEET fl;
        memset(&fl, 0, sizeof(fl));

        fl.rgcsh[0] = 1;
        rgshdef[0].det = 0x00;
        rgshdef[0].ishdef = 0x00;

        fl.rgcsh[5] = 1;
        rgshdef[5].det = 0x10; /* scout true */
        rgshdef[5].ishdef = 0x00;

        fl.rgcsh[9] = 1;
        rgshdef[9].det = 0x00;
        rgshdef[9].ishdef = 0x08; /* colonizer true */

        TEST_CHECK(FScout(&fl) == 1);
        TEST_CHECK(FColonizer(&fl) == 1);
    }

    memcpy(rgshdef, old_rgshdef, sizeof(old_rgshdef));
}

TEST_LIST = {
    {"FColonizer/FScout follow shdef flag rule", test_FColonizer_and_FScout_basic},
    {NULL, NULL},
};
