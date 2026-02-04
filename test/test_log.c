#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "init.h"
#include "log.h"
#include "types.h"

#include "file.h" /* FLoadGame */

static int16_t cb_seen;
static int16_t rt_seen;
static int16_t calls_seen;

static void   *pass_seen;
static int16_t ipass_seen;

static uint8_t payload0_seen[8];

static int16_t enum_cb(void *lpv, int16_t rt, int16_t cb, void *lpPass, int16_t iPass) {
    calls_seen++;
    rt_seen = rt;
    cb_seen = cb;
    pass_seen = lpPass;
    ipass_seen = iPass;

    /* Capture payload bytes from the first record. */
    if (cb > 0) {
        int16_t n = cb;
        if (n > (int16_t)sizeof(payload0_seen))
            n = (int16_t)sizeof(payload0_seen);
        memcpy(payload0_seen, lpv, (size_t)n);
    }

    /* Stop after first call. */
    return 0;
}

static void test_EnumLogRts_stops_on_zero(void) {
    uint8_t buf[64];

    uint8_t *old_lpLog = lpLog;
    int16_t  old_imemLogCur = imemLogCur;

    memset(buf, 0, sizeof(buf));
    memset(payload0_seen, 0, sizeof(payload0_seen));

    /* Record 1 at offset 0: rt=3, cb=4, payload 0xaa 0xbb 0xcc 0xdd */
    {
        const uint16_t w1 = (uint16_t)((3u << 10) | 4u);
        memcpy(buf + 0, &w1, sizeof(w1));
        buf[2] = 0xaa;
        buf[3] = 0xbb;
        buf[4] = 0xcc;
        buf[5] = 0xdd;
    }

    /* Record 2 at offset 6 (should not be visited): rt=1, cb=1, payload 0x77 */
    {
        const uint16_t w2 = (uint16_t)((1u << 10) | 1u);
        memcpy(buf + 6, &w2, sizeof(w2));
        buf[8] = 0x77;
    }

    lpLog = buf;
    imemLogCur = (int16_t)((2 + 4) + (2 + 1)); /* rec1 + rec2 */

    calls_seen = 0;
    cb_seen = 0;
    rt_seen = -1;
    pass_seen = NULL;
    ipass_seen = -1;

    {
        int dummy = 123;
        EnumLogRts(enum_cb, &dummy, 7);

        TEST_CHECK(calls_seen == 1);
        TEST_CHECK(rt_seen == 3);
        TEST_CHECK(cb_seen == 4);
        TEST_CHECK(pass_seen == &dummy);
        TEST_CHECK(ipass_seen == 7);

        /* Verify payload pointer/offset correctness by verifying copied bytes. */
        TEST_CHECK(payload0_seen[0] == 0xaa);
        TEST_CHECK(payload0_seen[1] == 0xbb);
        TEST_CHECK(payload0_seen[2] == 0xcc);
        TEST_CHECK(payload0_seen[3] == 0xdd);
    }

cleanup:
    lpLog = old_lpLog;
    imemLogCur = old_imemLogCur;
}

static void test_FGetPrevLogRt_reads_prev_record(void) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));

    uint8_t *old_lpLog = lpLog;
    int16_t  old_imemLogPrev = imemLogPrev;

    lpLog = buf;

    /* Put one record at offset 10: rt=5, cb=3, payload 0x11 0x22 0x33 */
    {
        const uint16_t w = (uint16_t)((5u << 10) | 3u);
        memcpy(buf + 10, &w, sizeof(w));
        buf[12] = 0x11;
        buf[13] = 0x22;
        buf[14] = 0x33;
    }

    imemLogPrev = 10;

    {
        HDR     out;
        uint8_t payload[8];

        memset(&out, 0, sizeof(out));
        memset(payload, 0, sizeof(payload));

        TEST_CHECK(FGetPrevLogRt(&out, payload) == 1);
        TEST_CHECK(out.rt == 5);
        TEST_CHECK(out.cb == 3);
        TEST_CHECK(payload[0] == 0x11);
        TEST_CHECK(payload[1] == 0x22);
        TEST_CHECK(payload[2] == 0x33);
    }

    /* cb == 0 should not modify payload buffer. */
    {
        const int16_t  off = 20;
        const uint16_t w0 = (uint16_t)((2u << 10) | 0u);
        HDR            out;
        uint8_t        payload[8];

        memcpy(buf + off, &w0, sizeof(w0));
        imemLogPrev = off;

        memset(&out, 0, sizeof(out));
        memset(payload, 0xCC, sizeof(payload));

        TEST_CHECK(FGetPrevLogRt(&out, payload) == 1);
        TEST_CHECK(out.rt == 2);
        TEST_CHECK(out.cb == 0);
        TEST_CHECK(payload[0] == 0xCC); /* unchanged */
    }

    /* pb == NULL is safe when cb == 0. */
    {
        const int16_t  off = 24;
        const uint16_t w0 = (uint16_t)((7u << 10) | 0u);
        HDR            out;

        memcpy(buf + off, &w0, sizeof(w0));
        imemLogPrev = off;

        memset(&out, 0, sizeof(out));
        TEST_CHECK(FGetPrevLogRt(&out, NULL) == 1);
        TEST_CHECK(out.rt == 7);
        TEST_CHECK(out.cb == 0);
    }

    /* No previous record. */
    imemLogPrev = (int16_t)-1;
    {
        HDR     out;
        uint8_t payload[8];
        memset(&out, 0, sizeof(out));
        memset(payload, 0, sizeof(payload));
        TEST_CHECK(FGetPrevLogRt(&out, payload) == 0);
    }

cleanup:
    lpLog = old_lpLog;
    imemLogPrev = old_imemLogPrev;
}

static void test_FLoadLogFile_tiny_2400(void) {
    MemJump env;
    int     j;

    /* Ensure we have the heap blocks Stars expects (lpLog, lpMsg, etc.). */
    FAllocStuff();

    DestroyCurGame();
    gd.fGeneratingTurn = 0;

    penvMem = &env;
    j = setjmp(env.env);
    if (j != 0) {
        DeallocStuff();
        TEST_MSG("FLoadLogFile longjmp'd (fatal file error)");
        TEST_ASSERT(false);
        return;
    }

    /* Load a known tiny game first (so GAME/PLAYER globals match the log file). */
    TEST_CHECK(FLoadGame("./test/data/tiny/2400/TEST", "HST"));

    /* Now load the corresponding player-1 log. */
    TEST_CHECK(FLoadLogFile("./test/data/tiny/2400/TEST.X1") == 1);

    /* We should have parsed at least some log bytes into lpLog. */
    TEST_CHECK(imemLogCur > 0);
    {
        HDR hdr0;
        memcpy(&hdr0, lpLog, sizeof(hdr0));
        TEST_CHECK(hdr0.rt != 0);
    }

    DestroyCurGame();
    DeallocStuff();
}

TEST_LIST = {
    {"LOG/EnumLogRts stops on callback 0", test_EnumLogRts_stops_on_zero},
    {"LOG/FGetPrevLogRt reads previous record", test_FGetPrevLogRt_reads_prev_record},
    {"LOG/FLoadLogFile loads tiny 2400 log", test_FLoadLogFile_tiny_2400},
    {NULL, NULL},
};
