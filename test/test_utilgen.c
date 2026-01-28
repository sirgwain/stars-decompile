#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "types.h"
#include "utilgen.h"

static void test_ICompLong(void)
{
    int32_t a, b;

    /* a < b => negative */
    a = 10; b = 20;
    TEST_CHECK(ICompLong(&a, &b) < 0);

    /* a > b => positive */
    a = 20; b = 10;
    TEST_CHECK(ICompLong(&a, &b) > 0);

    /* a == b => zero */
    a = 42; b = 42;
    TEST_CHECK(ICompLong(&a, &b) == 0);

    /* negative values */
    a = -100; b = 50;
    TEST_CHECK(ICompLong(&a, &b) < 0);

    /* zero vs positive */
    a = 0; b = 1;
    TEST_CHECK(ICompLong(&a, &b) < 0);
}

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

static void test_AddBackTrailingSpaces(void)
{
    char buf[] = "   hello";
    char *p = buf;
    char *end = buf + 3;

    AddBackTrailingSpaces(&p, end);
    TEST_CHECK(p == end);

    /* Already past spaces */
    char buf2[] = "hello";
    p = buf2;
    end = buf2 + 5;
    AddBackTrailingSpaces(&p, end);
    TEST_CHECK(p == buf2);

    /* Empty range */
    p = buf;
    end = buf;
    AddBackTrailingSpaces(&p, end);
    TEST_CHECK(p == buf);
}

static void test_ChopTrailingSpaces(void)
{
    char buf[] = "hello   ";
    char *end = buf + 8;

    ChopTrailingSpaces(buf, &end);
    TEST_CHECK(end == buf + 5);

    /* No trailing spaces */
    char buf2[] = "hello";
    end = buf2 + 5;
    ChopTrailingSpaces(buf2, &end);
    TEST_CHECK(end == buf2 + 5);

    /* All spaces */
    char buf3[] = "   ";
    end = buf3 + 3;
    ChopTrailingSpaces(buf3, &end);
    TEST_CHECK(end == buf3);
}

static void test_ChopLastWord(void)
{
    char buf[] = "hello world foo";
    char *end = buf + 15;

    ChopLastWord(buf, &end);
    TEST_CHECK(end == buf + 11);

    ChopLastWord(buf, &end);
    TEST_CHECK(end == buf + 5);

    /* Trailing spaces before word */
    char buf2[] = "hello   world   ";
    end = buf2 + 16;
    ChopLastWord(buf2, &end);
    TEST_CHECK(end == buf2 + 5);
}

static void test_LDistance2(void)
{
    POINT p1 = {0, 0};
    POINT p2 = {3, 4};
    TEST_CHECK(LDistance2(p1, p2) == 25);

    POINT p3 = {10, 10};
    POINT p4 = {10, 10};
    TEST_CHECK(LDistance2(p3, p4) == 0);

    POINT p5 = {-5, 0};
    POINT p6 = {5, 0};
    TEST_CHECK(LDistance2(p5, p6) == 100);
}

static void test_PszFromInt(void)
{
    int16_t cch;
    char *result;

    result = PszFromInt(42, &cch);
    TEST_CHECK(strcmp(result, "42") == 0);
    TEST_CHECK(cch == 2);

    result = PszFromInt(-7, &cch);
    TEST_CHECK(strcmp(result, "-7") == 0);
    TEST_CHECK(cch == 2);

    result = PszFromInt(0, NULL);
    TEST_CHECK(strcmp(result, "0") == 0);
}

static void test_PszFromLong(void)
{
    int16_t cch;
    char *result;

    result = PszFromLong(123456, &cch);
    TEST_CHECK(strcmp(result, "123456") == 0);
    TEST_CHECK(cch == 6);

    result = PszFromLong(-99, &cch);
    TEST_CHECK(strcmp(result, "-99") == 0);
    TEST_CHECK(cch == 3);

    result = PszFromLong(0, NULL);
    TEST_CHECK(strcmp(result, "0") == 0);
}

static void test_LSaltFromSz(void)
{
    /* Empty string returns 0 */
    TEST_CHECK(LSaltFromSz("") == 0);

    /* Single char: adds char value, no multiply, result must be non-zero */
    int32_t s1 = LSaltFromSz("A");
    TEST_CHECK(s1 == (int32_t)'A');

    /* Two chars: adds first, multiplies by second */
    int32_t s2 = LSaltFromSz("AB");
    int32_t expected = ((int32_t)'A' + 0) * (int32_t)'B'; /* 0 + 'A' = 65, then * 'B' = 65*66 */
    /* Actually: lSalt starts at 0, add 'A' -> 65, multiply by 'B' -> 65*66 = 4290 */
    TEST_CHECK(s2 == 65 * 66);

    /* Result of 0 becomes 1 */
    /* Null char string that results in 0 sum: not easily testable since all printable chars > 0 */

    /* Consistent hashing */
    int32_t s3a = LSaltFromSz("Hello");
    int32_t s3b = LSaltFromSz("Hello");
    TEST_CHECK(s3a == s3b);
    TEST_CHECK(s3a != 0);
}

TEST_LIST = {
    {"ICompLong", test_ICompLong},
    {"compress/decompress user string", test_FCompressDecompressUserString},
    {"AddBackTrailingSpaces", test_AddBackTrailingSpaces},
    {"ChopTrailingSpaces", test_ChopTrailingSpaces},
    {"ChopLastWord", test_ChopLastWord},
    {"LDistance2", test_LDistance2},
    {"PszFromInt", test_PszFromInt},
    {"PszFromLong", test_PszFromLong},
    {"LSaltFromSz", test_LSaltFromSz},
    {NULL, NULL}};
