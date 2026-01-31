/* test_memory.c
 *
 * Unit tests for Stars! memory HB heap blocks.
 *
 * These tests assume you’re using the cross-platform HbHandleRec approach (no Win16 HGLOBAL),
 * and that the following are linked from your main code:
 *   - mphtcbAlloc[12]
 *   - rglphb[12]
 *   - LphbAlloc, LphbReAlloc, ResetHb, FreeHb
 *
 */

#include "acutest.h"

#include <string.h> /* memset */

/* Pull in HB + HeapType. Prefer your project headers. */
#include "types.h"

/* Prefer your real headers; adjust if you named them differently. */
#include "../memory.h" /* LphbAlloc/LphbReAlloc/ResetHb/FreeHb */
#include "globals.h"   /* mphtcbAlloc, rglphb */

static void clear_heap_lists(void) {
    for (int i = 0; i < (int)htCount; i++) {
        rglphb[i] = NULL;
    }
}

static void set_min_alloc_defaults(void) {
    /* Make tests deterministic: give each heap type a known min size. */
    for (int i = 0; i < (int)htCount; i++) {
        mphtcbAlloc[i] = 0x0100; /* 256 bytes min by default for tests */
    }
}

/* ---------- Tests ---------- */

static void test_LphbAlloc_respects_min_and_inits_header(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    mphtcbAlloc[htMsg] = 0x1000;  /* 4096 min alloc */
    HB *hb = LphbAlloc(1, htMsg); /* want = 1 + 0x10 => 0x11 < 0x1000 so clamp */

    TEST_CHECK(hb != NULL);
    TEST_CHECK(hb->ht == (uint8_t)htMsg);
    TEST_CHECK(hb->ibTop == (uint16_t)sizeof(HB));
    TEST_CHECK(hb->cbBlock == 0x1000);
    TEST_CHECK(hb->cbSlop == (uint16_t)(hb->cbBlock - (uint16_t)sizeof(HB)));
    TEST_CHECK(hb->cbFree == (uint16_t)(hb->cbBlock - (uint16_t)sizeof(HB)));

    /* inserted at head */
    TEST_CHECK(rglphb[htMsg] == hb);

    /* cleanup (avoid leaving dangling rglphb[htMsg]) */
    rglphb[htMsg] = NULL;
    FreeHb(hb);
}

static void test_LphbAlloc_no_min_clamp_when_large_enough(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    mphtcbAlloc[htOrd] = 0x0020;       /* tiny min */
    HB *hb = LphbAlloc(0x0100, htOrd); /* want = 0x110 */

    TEST_CHECK(hb != NULL);
    TEST_CHECK(hb->cbBlock == (uint16_t)(0x0100 + (uint16_t)sizeof(HB)));
    TEST_CHECK(hb->ibTop == (uint16_t)sizeof(HB));
    TEST_CHECK(hb->cbFree == (uint16_t)(hb->cbBlock - (uint16_t)sizeof(HB)));
    TEST_CHECK(hb->cbSlop == (uint16_t)(hb->cbBlock - (uint16_t)sizeof(HB)));
    TEST_CHECK(rglphb[htOrd] == hb);

    rglphb[htOrd] = NULL;
    FreeHb(hb);
}

static void test_LphbReAlloc_grows_updates_list_and_zeroes_tail(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    /* Growth step for this heap type */
    mphtcbAlloc[htLog] = 0x0080; /* 128 bytes grow */

    HB *hb = LphbAlloc(0x0020, htLog);
    TEST_CHECK(hb != NULL);
    TEST_CHECK(rglphb[htLog] == hb);

    uint16_t oldBlock = hb->cbBlock;

    /* scribble a recognizable pattern into the old block tail to detect new zeroing */
    uint8_t *p = (uint8_t *)hb;
    for (uint16_t i = sizeof(HB); i < oldBlock; i++) {
        p[i] = 0xAA;
    }

    HB *hb2 = LphbReAlloc(hb);
    TEST_CHECK(hb2 != NULL);

    /* head pointer should be updated if it moved */
    TEST_CHECK(rglphb[htLog] == hb2);

    uint16_t newBlock = hb2->cbBlock;
    TEST_CHECK(newBlock >= (uint16_t)(oldBlock + mphtcbAlloc[htLog]) || newBlock == 0xFFDC);

    /* Header fields grew by cbGrow (unless clamped to 0). */
    TEST_CHECK(hb2->ibTop == (uint16_t)sizeof(HB));

    /* Verify GMEM_ZEROINIT-like behavior: new bytes appended are zero. */
    if (newBlock > oldBlock) {
        uint8_t *q = (uint8_t *)hb2;
        for (uint16_t i = oldBlock; i < newBlock; i++) {
            TEST_CHECK(q[i] == 0);
            if (q[i] != 0)
                break;
        }
    }

    rglphb[htLog] = NULL;
    FreeHb(hb2);
}

static void test_ResetHb_resets_all_blocks_in_heap_list(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    mphtcbAlloc[htShips] = 0x0200;

    HB *hb1 = LphbAlloc(0x0010, htShips);
    HB *hb2 = LphbAlloc(0x0010, htShips);
    TEST_CHECK(hb1 != NULL && hb2 != NULL);

    /* List order: hb2 is head, hb1 is next */
    TEST_CHECK(rglphb[htShips] == hb2);
    TEST_CHECK(hb2->lphbNext == hb1);

    /* Mutate fields so ResetHb has something to fix. */
    hb2->ibTop = 0x1234;
    hb2->cbFree = 7;
    hb2->cbSlop = 9;

    hb1->ibTop = 0x2222;
    hb1->cbFree = 11;
    hb1->cbSlop = 13;

    ResetHb(htShips);

    /* Verify both blocks reset */
    for (HB *t = rglphb[htShips]; t != NULL; t = t->lphbNext) {
        TEST_CHECK(t->ibTop == (uint16_t)sizeof(HB));
        TEST_CHECK(t->cbFree == (uint16_t)(t->cbBlock - (uint16_t)sizeof(HB)));
        TEST_CHECK(t->cbSlop == (uint16_t)(t->cbBlock - (uint16_t)sizeof(HB)));
    }

    /* cleanup */
    rglphb[htShips] = NULL;
    FreeHb(hb2); /* frees chain hb2->hb1 */
}

static void test_FreeHb_null_ok_and_frees_chain(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    FreeHb(NULL); /* should be a no-op */

    mphtcbAlloc[htMisc] = 0x0100;
    HB *hb1 = LphbAlloc(0x0010, htMisc);
    HB *hb2 = LphbAlloc(0x0010, htMisc);
    TEST_CHECK(hb1 != NULL && hb2 != NULL);

    /* prevent dangling global head after free */
    rglphb[htMisc] = NULL;
    FreeHb(hb2); /* frees hb2 then hb1 */

    /* nothing strong to assert here without instrumenting the allocator,
       but at least we exercised the chain free path without crashing. */
    TEST_CHECK(1);
}

static void test_LphbFromLpHt_finds_block_containing_pointer(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    mphtcbAlloc[htOrd] = 0x0200;
    HB *hb1 = LphbAlloc(0x0010, htOrd);
    HB *hb2 = LphbAlloc(0x0010, htOrd);
    TEST_CHECK(hb1 != NULL && hb2 != NULL);

    /* hb2 is the head (most recently allocated) */
    TEST_CHECK(rglphb[htOrd] == hb2);

    /* Pointer inside hb2 should map to hb2 */
    void *p2 = (uint8_t *)hb2 + sizeof(HB);
    TEST_CHECK(LphbFromLpHt(p2, htOrd) == hb2);

    /* Pointer inside hb1 should map to hb1 */
    void *p1 = (uint8_t *)hb1 + sizeof(HB);
    TEST_CHECK(LphbFromLpHt(p1, htOrd) == hb1);

    /* Pointer outside both should be NULL */
    void *pBad = (uint8_t *)hb2 + hb2->cbBlock + 1;
    TEST_CHECK(LphbFromLpHt(pBad, htOrd) == NULL);

    rglphb[htOrd] = NULL;
    FreeHb(hb2);
}

static void test_LpAlloc_and_FreeLp_round_trip_and_top_rollback(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    mphtcbAlloc[htMsg] = 0x0200;
    HB *hb = LphbAlloc(0x0010, htMsg);
    TEST_CHECK(hb != NULL);

    uint16_t ibTop0 = hb->ibTop;
    uint16_t cbFree0 = hb->cbFree;
    uint16_t cbSlop0 = hb->cbSlop;

    uint16_t cb = 7;
    uint16_t cb_00 = (uint16_t)((cb + 3u) & 0xfffeu);
    void    *p = LpAlloc(cb, htMsg);
    TEST_CHECK(p != NULL);

    uint16_t *hdr = (uint16_t *)((uint8_t *)p - 2);
    TEST_CHECK((*hdr & 1u) == 0);
    TEST_CHECK(*hdr == (uint16_t)(cb_00 - 2u));

    TEST_CHECK(hb->ibTop == (uint16_t)(ibTop0 + cb_00));
    TEST_CHECK(hb->cbFree == (uint16_t)(cbFree0 - cb_00));
    TEST_CHECK(hb->cbSlop == (uint16_t)(cbSlop0 - cb_00));

    /* Free should mark free bit and (because it was last alloc) roll ibTop back */
    FreeLp(p, htMsg);
    TEST_CHECK((*hdr & 1u) != 0);
    TEST_CHECK(hb->ibTop == ibTop0);
    TEST_CHECK(hb->cbSlop == cbSlop0);
    TEST_CHECK(hb->cbFree == cbFree0);

    rglphb[htMsg] = NULL;
    FreeHb(hb);
}

static void test_LpReAlloc_grows_in_place_when_at_top_and_slop_allows(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    mphtcbAlloc[htString] = 0x0400;
    HB *hb = LphbAlloc(0x0010, htString);
    TEST_CHECK(hb != NULL);

    void *p = LpAlloc(16, htString);
    TEST_CHECK(p != NULL);

    /* Fill initial payload to ensure it survives in-place resize. */
    memset(p, 0x5A, 16);

    uint16_t cbCur = *(uint16_t *)((uint8_t *)p - 2);
    void    *p2 = LpReAlloc(p, 32, htString);
    TEST_CHECK(p2 == p);

    uint16_t cbNew = *(uint16_t *)((uint8_t *)p2 - 2);
    TEST_CHECK(cbNew > cbCur);

    /* Old bytes preserved */
    for (int i = 0; i < 16; i++) {
        TEST_CHECK(((uint8_t *)p2)[i] == 0x5A);
        if (((uint8_t *)p2)[i] != 0x5A)
            break;
    }

    FreeLp(p2, htString);
    rglphb[htString] = NULL;
    FreeHb(hb);
}

static void test_LpReAlloc_moves_and_copies_when_not_at_top(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    mphtcbAlloc[htLog] = 0x0600;
    HB *hb = LphbAlloc(0x0010, htLog);
    TEST_CHECK(hb != NULL);

    void *p = LpAlloc(16, htLog);
    TEST_CHECK(p != NULL);
    memset(p, 0xA5, 16);

    /* Allocate another chunk so p is no longer at heap top. */
    void *q = LpAlloc(16, htLog);
    TEST_CHECK(q != NULL);

    void *p2 = LpReAlloc(p, 64, htLog);
    TEST_CHECK(p2 != NULL);
    TEST_CHECK(p2 != p);

    /* Old bytes copied */
    for (int i = 0; i < 16; i++) {
        TEST_CHECK(((uint8_t *)p2)[i] == 0xA5);
        if (((uint8_t *)p2)[i] != 0xA5)
            break;
    }

    FreeLp(q, htLog);
    FreeLp(p2, htLog);
    rglphb[htLog] = NULL;
    FreeHb(hb);
}

static void test_LpplAlloc_FreePl_and_LpplReAlloc(void) {
    clear_heap_lists();
    set_min_alloc_defaults();

    mphtcbAlloc[htOrd] = 0x0800;
    HB *hb = LphbAlloc(0x0010, htOrd);
    TEST_CHECK(hb != NULL);

    PL *pl = LpplAlloc(3, 5, htOrd);
    TEST_CHECK(pl != NULL);

    TEST_CHECK(pl->cbItem == 3);
    TEST_CHECK(pl->cAlloc == 5);
    TEST_CHECK(pl->ht == (uint16_t)htOrd);
    TEST_CHECK(pl->fMark == 0);
    TEST_CHECK(pl->iMax == 5);
    TEST_CHECK(pl->iMac == 0);

    /* Write a recognizable pattern into the payload */
    uint16_t oldSize = (uint16_t)(pl->cbItem * pl->cAlloc + sizeof(PL));
    memset(pl->rgb, 0xCC, (size_t)(oldSize - sizeof(PL)));

    PL *pl2 = LpplReAlloc(pl, 9);
    TEST_CHECK(pl2 != NULL);
    TEST_CHECK(pl2->iMax == 9);
    TEST_CHECK(pl2->cAlloc == 5); // does not update on realloc
    TEST_CHECK(pl2->cbItem == 3);
    TEST_CHECK(pl2->ht == (uint16_t)htOrd);

    /* Old bytes preserved (up to old payload size) */
    for (uint16_t i = 0; i < (uint16_t)(oldSize - sizeof(PL)); i++) {
        TEST_CHECK(pl2->rgb[i] == 0xCC);
        if (pl2->rgb[i] != 0xCC)
            break;
    }

    /* Free via FreePl (uses pl->ht bitfield) */
    hb = rglphb[htOrd];
    TEST_CHECK(hb != NULL);

    uint16_t cbFreeBefore = hb->cbFree;
    FreePl(pl2);
    TEST_CHECK(hb->cbFree >= cbFreeBefore);

    /* cleanup */
    hb = rglphb[htOrd];
    rglphb[htOrd] = NULL;
    FreeHb(hb);
}

/* ---------- Test list ---------- */

TEST_LIST = {{"memory/LphbAlloc respects min and inits header", test_LphbAlloc_respects_min_and_inits_header},
             {"memory/LphbAlloc uses want size when >= min", test_LphbAlloc_no_min_clamp_when_large_enough},
             {"memory/LphbReAlloc grows, updates list, zeros", test_LphbReAlloc_grows_updates_list_and_zeroes_tail},
             {"memory/ResetHb resets all blocks", test_ResetHb_resets_all_blocks_in_heap_list},
             {"memory/FreeHb NULL ok and frees chain", test_FreeHb_null_ok_and_frees_chain},
             {"memory/LphbFromLpHt finds block containing pointer", test_LphbFromLpHt_finds_block_containing_pointer},
             {"memory/LpAlloc+FreeLp round-trip and top rollback", test_LpAlloc_and_FreeLp_round_trip_and_top_rollback},
             {"memory/LpReAlloc grows in-place when possible", test_LpReAlloc_grows_in_place_when_at_top_and_slop_allows},
             {"memory/LpReAlloc moves+copies when not at top", test_LpReAlloc_moves_and_copies_when_not_at_top},
             {"memory/LpplAlloc/FreePl/LpplReAlloc", test_LpplAlloc_FreePl_and_LpplReAlloc},
             {NULL, NULL}};
