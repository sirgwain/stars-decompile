#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "parts.h"
#include "race.h" /* CAdvantagePoints */
#include "types.h"

static void test_CAdvantagePoints_table(void) {
    struct Case {
        const char *name;
        PLAYER     *plr;
        int16_t     want;
    };

    struct Case cases[] = {
        {"Humanoids", &vrgplrDef[0], 25},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const struct Case *tc = &cases[i];

        int16_t got = CAdvantagePoints(tc->plr);

        TEST_CHECK_(got == tc->want, "case[%zu] %s: got=%d want=%d", i, tc->name, (int)got, (int)tc->want);
    }
}

TEST_LIST = {{"CAdvantagePoints table", test_CAdvantagePoints_table}, {NULL, NULL}};
