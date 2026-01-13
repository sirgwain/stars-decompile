#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "types.h"
#include "utilgen.h"

static void test_FCompressDecompressUserString(void)
{
    typedef struct Case
    {
        const char *in;
    } Case;

    /* Keep inputs to characters that Stars' NybbleFromCh/ChFromNybble mapping is expected to support. */
    const Case cases[] = {
        {""},
        {"Bob"},
        {"Bob's Empire"},
        {"The quick brown fox jumps over the lazy dog"},
        {"Stars! 2.6j RC3"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        const char *in = cases[i].in;

        uint8_t comp[256];
        char out[256];

        int16_t cbCompCap = (int16_t)sizeof(comp);
        int16_t cbOutCap = (int16_t)sizeof(out);

        memset(comp, 0xCC, sizeof(comp));
        memset(out, 0xCC, sizeof(out));

        /* Compress */
        int16_t cbComp = cbCompCap;
        int16_t okC = FCompressUserString((char *)in, (char *)comp, &cbComp);

        TEST_CHECK(okC != 0);
        if (okC == 0)
        {
            TEST_MSG("compress failed for case %zu: '%s'", i, in);
            continue;
        }

        TEST_CHECK(cbComp >= 0 && cbComp <= cbCompCap);
        if (cbComp < 0 || cbComp > cbCompCap)
        {
            TEST_MSG("bad compressed size for case %zu: cbComp=%d cap=%d", i, (int)cbComp, (int)cbCompCap);
            continue;
        }

        /* Decompress */
        int16_t okD = FDecompressUserString((char *)comp, cbComp, out, &cbOutCap);

        TEST_CHECK(okD != 0);
        if (okD == 0)
        {
            TEST_MSG("decompress failed for case %zu: '%s' (cbComp=%d)", i, in, (int)cbComp);
            continue;
        }

        TEST_CHECK(strcmp(out, in) == 0);
        if (strcmp(out, in) != 0)
        {
            TEST_MSG("roundtrip mismatch case %zu:\n  in : '%s'\n  out: '%s'\n  cbComp=%d",
                     i, in, out, (int)cbComp);
        }
    }

    /* Negative test: decompress should fail if output cap is too small */
    {
        const char *in = "This is longer than 4";

        uint8_t comp[256];
        char out[256];

        int16_t cbComp = (int16_t)sizeof(comp);
        int16_t okC = FCompressUserString((char *)in, (char *)comp, &cbComp);
        TEST_CHECK(okC != 0);

        memset(out, 0, sizeof(out));
        int16_t tinyCap = 4; /* intentionally too small */
        int16_t okD = FDecompressUserString((char *)comp, cbComp, out, &tinyCap);

        TEST_CHECK(okD == 0);
    }
}

TEST_LIST = {
    {"compress/decompress user string", test_FCompressDecompressUserString},
    {NULL, NULL}};
