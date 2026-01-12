
#include "types.h"

#include "memory.h"
#include "msg.h"
#include "strings.h"
#include "utilgen.h"
#include "globals.h"

uint16_t mphtcbAlloc[12] = {0xf800, 0x1000, 0x1000, 0x1000, 0x2000, 0xf800, 0xff00, 0x4440, 0x1000, 0x1800, 0x0800, 0xff00};
HB *rglphb[12] = {0};

/* ---- minimal 16-bit handle table (cross-platform replacement for HGLOBAL) ---- */
typedef struct HbHandleRec
{
    uint16_t h;
    void *p;
    struct HbHandleRec *next;
} HbHandleRec;

static HbHandleRec *g_hbHandles;
static uint16_t g_nextHbHandle = 1;

static uint16_t HbHandleAlloc(void *p)
{
    HbHandleRec *r = (HbHandleRec *)malloc(sizeof(*r));
    uint16_t h;

    if (!r)
    {
        return 0;
    }

    /* wrap-safe: 0 is reserved as invalid */
    h = g_nextHbHandle++;
    if (h == 0)
    {
        h = g_nextHbHandle++;
    }

    r->h = h;
    r->p = p;
    r->next = g_hbHandles;
    g_hbHandles = r;
    return h;
}

/* Update existing handle -> pointer mapping (handle stays the same across realloc). */
static void HbHandleUpdate(uint16_t h, void *pNew)
{
    HbHandleRec *r;
    for (r = g_hbHandles; r != NULL; r = r->next)
    {
        if (r->h == h)
        {
            r->p = pNew;
            return;
        }
    }
    /* If this ever happens, something is inconsistent; ignore like Win16 would. */
}

/* Remove handle mapping. Returns the pointer that was mapped (or NULL). */
static void *HbHandleFree(uint16_t h)
{
    HbHandleRec **pp = &g_hbHandles;
    HbHandleRec *cur;

    while ((cur = *pp) != NULL)
    {
        if (cur->h == h)
        {
            void *p = cur->p;
            *pp = cur->next;
            free(cur);
            return p;
        }
        pp = &cur->next;
    }
    return NULL;
}

/* Lookup a handle -> pointer mapping (replacement for GlobalLock). */
static void *HbHandleLock(uint16_t h)
{
    HbHandleRec *r;
    for (r = g_hbHandles; r != NULL; r = r->next)
    {
        if (r->h == h)
        {
            return r->p;
        }
    }
    return NULL;
}

/* functions */
void ResetHb(HeapType ht)
{
    HB *lphb;
    uint16_t cb;

    if ((uint16_t)ht >= (uint16_t)htCount)
    {
        return;
    }

    lphb = rglphb[(uint16_t)ht];
    while (lphb != NULL)
    {
        lphb->ibTop = sizeof(HB);

        cb = lphb->cbBlock;
        /* decompile uses int math but values are uint16_t; preserve wrap behavior */
        cb = (uint16_t)(cb - sizeof(HB));

        lphb->cbSlop = cb;
        lphb->cbFree = cb;

        lphb = lphb->lphbNext;
    }
}

void FreePl(PL *lppl)
{
    if (lppl != NULL)
    {
        FreeLp(lppl, (HeapType)lppl->ht);
    }
}

HB *LphbReAlloc(HB *lphb)
{
    uint16_t cbCur;
    uint16_t cbGrow;
    uint16_t hmem;
    uint8_t ht;
    size_t newSize;
    HB *lphbNew;

    if (lphb == NULL)
    {
        return NULL;
    }

    hmem = lphb->hmem;
    cbCur = lphb->cbBlock;
    ht = lphb->ht;

    cbGrow = mphtcbAlloc[(uint16_t)ht];

    /* Win16 caps blocks at 0xFFDC (= 0x10000 - 0x24). If already at/over, OOM. */
    if (cbCur >= 0xFFDC)
    {
        goto LReAllocOOM;
    }

    /* Clamp growth so cbCur + cbGrow <= 0xFFDC. */
    if ((uint16_t)(0xFFDC - cbCur) < cbGrow)
    {
        cbGrow = (uint16_t)(0xFFDC - cbCur);
    }

    /* GlobalReAlloc(..., GMEM_MOVEABLE|GMEM_ZEROINIT):
       - may move
       - zero-inits new tail if it grows */
    newSize = (size_t)cbCur + (size_t)cbGrow;
    lphbNew = (HB *)realloc(lphb, newSize);
    if (lphbNew == NULL)
    {
        goto LReAllocOOM;
    }

    /* Zero-init the grown bytes to match GMEM_ZEROINIT. */
    if (cbGrow != 0)
    {
        memset(((uint8_t *)lphbNew) + cbCur, 0, (size_t)cbGrow);
    }

    /* Handle stays the same in our model; update mapping and store it back. */
    HbHandleUpdate(hmem, lphbNew);
    lphbNew->hmem = hmem;

    /* Fix up per-heap HB linked list if the block moved. */
    if (rglphb[(uint16_t)ht] == lphb)
    {
        rglphb[(uint16_t)ht] = lphbNew;
    }
    else
    {
        HB *t = rglphb[(uint16_t)ht];
        while (t != NULL && t->lphbNext != lphb)
        {
            t = t->lphbNext;
        }
        if (t != NULL)
        {
            t->lphbNext = lphbNew;
        }
        /* If not found, leave list unchanged (matches the decompile's "best effort"). */
    }

    /* Update sizes (these are uint16_t fields in HB). */
    lphbNew->cbBlock = (uint16_t)(lphbNew->cbBlock + cbGrow);
    lphbNew->cbFree = (uint16_t)(lphbNew->cbFree + cbGrow);
    lphbNew->cbSlop = (uint16_t)(lphbNew->cbSlop + cbGrow);

    return lphbNew;

LReAllocOOM:
{
    int16_t mbType = 0x10;
    char *sz = PszFormatIds(idsMemory, (int16_t *)0);
    AlertSz(sz, mbType);
    longjmp(penvMem->env, -1);
}
}

PL *LpplReAlloc(PL *lppl, uint16_t cAlloc)
{
    PL *lpplNew;

    lpplNew = (PL *)LpReAlloc(
        lppl,
        (uint16_t)(lppl->cbItem * cAlloc + sizeof(PL)),
        (HeapType)lppl->ht);

    lpplNew->iMax = cAlloc;

    return lpplNew;
}

HB *LphbFromLpHt(void *lp, HeapType ht)
{
    HB *lphb;

    /* bounds-check like the decompile: (ht < 0) || (0xb < ht) */
    if ((int)ht < 0 || (int)ht >= (int)htCount)
    {
        return NULL;
    }

    lphb = rglphb[ht];

    /* find the HB whose address range contains lp:
       (lphb < lp) && (lp < (uint8_t*)lphb + lphb->cbBlock) */
    while (lphb != NULL)
    {
        uint8_t *base = (uint8_t *)lphb;
        uint8_t *end = base + lphb->cbBlock;

        if ((void *)lphb < lp && lp < (void *)end)
        {
            break;
        }

        lphb = lphb->lphbNext;
    }

    return lphb;
}

void FreeLp(void *lp, HeapType ht)
{
    HB *lphb;
    uint16_t cbSpan;
    uint16_t *phdr;

    if (lp == NULL)
        return;

    lphb = LphbFromLpHt(lp, ht);

    phdr = (uint16_t *)((uint8_t *)lp - 2);

    /* total span in heap includes the 2-byte header */
    cbSpan = (*phdr + 2u);

    /* mark chunk free */
    *phdr |= 1u;

    lphb->cbFree += cbSpan;

    /* if this was the last allocation at the top, roll ibTop back and return span to slop */
    if ((uint16_t)(((uint8_t *)lp - (uint8_t *)lphb) + cbSpan - 2u) == lphb->ibTop)
    {
        lphb->ibTop -= cbSpan;
        lphb->cbSlop += cbSpan;
    }
}

void *LpAlloc(uint16_t cb, HeapType ht)
{
    HB *lphb;
    uint16_t cb_00;
    uint8_t *lpbTop;
    uint8_t *lpb;

    /* round payload up like the original: (cb + 3) & 0xfffe */
    cb_00 = (cb + 3u) & 0xfffeu;

    lphb = rglphb[ht];

    for (;;)
    {
        if (lphb == NULL || cb_00 <= lphb->cbFree)
        {
            if (lphb == NULL)
            {
                lphb = LphbAlloc(cb_00, ht);
            }

            lpbTop = (uint8_t *)lphb + lphb->ibTop;

            /* fast path: allocate from slop at top of heap */
            if (cb_00 <= lphb->cbSlop)
            {
                *(uint16_t *)lpbTop = cb_00 - 2u; /* size word (no free bit) */
                lphb->ibTop += cb_00;
                lphb->cbFree -= cb_00;
                lphb->cbSlop -= cb_00;
                return lpbTop + 2;
            }

            /* scan the chunk list starting at +0x10 up to ibTop */
            lpb = (uint8_t *)lphb + 0x10;
            while ((uint16_t)(lpb - (uint8_t *)lphb) < lphb->ibTop)
            {
                uint8_t *start = lpb;
                uint16_t hdr = *(uint16_t *)lpb;

                lpb += (hdr & 0xfffeu) + 2u;

                if ((hdr & 1u) != 0)
                {
                    /* coalesce consecutive free chunks until big enough or hit top */
                    while ((uint16_t)(lpb - (uint8_t *)lphb) < lphb->ibTop)
                    {
                        uint16_t hdr2 = *(uint16_t *)lpb;
                        if ((hdr2 & 1u) == 0)
                            break;
                        if ((uint16_t)(lpb - start) >= cb_00)
                            break;
                        lpb += (hdr2 & 0xfffeu) + 2u;
                    }

                    {
                        uint16_t span = (uint16_t)(lpb - start);

                        /* mark merged span as one free chunk */
                        *(uint16_t *)start = (span - 2u) | 1u;

                        if (cb_00 <= span)
                        {
                            /* allocate the *entire* span (no splitting) */
                            *(uint16_t *)start &= 0xfffeu;
                            lphb->cbFree -= span;
                            return start + 2;
                        }
                    }
                }
            }
        }

        /* next heap block in chain */
        lphb = lphb->lphbNext;
    }
}

void *LpReAlloc(void *lp, uint16_t cb, HeapType ht)
{
    uint16_t cbCur;
    uint16_t cb_00;
    uint16_t cbGrow;
    HB *lphb;
    void *lpNew;

    cbCur = *(uint16_t *)((uint8_t *)lp - 2);
    cb_00 = (cb + 1u) & 0xfffeu; /* original used +1 here */

    if (cbCur >= cb_00)
    {
        return lp;
    }

    cbGrow = cb_00 - cbCur;

    lphb = LphbFromLpHt(lp, ht);

    /* If the pointer isn't found in this heap chain, we can't do in-place growth. */
    if (lphb != NULL)
    {
        for (;;)
        {
            /* in-place grow only if this allocation is exactly at the heap top and slop is enough */
            if ((uint8_t *)lphb + lphb->ibTop == (uint8_t *)lp + cbCur &&
                cbGrow <= lphb->cbSlop)
            {
                lphb->cbSlop -= cbGrow;
                lphb->cbFree -= cbGrow;
                lphb->ibTop += cbGrow;
                *(uint16_t *)((uint8_t *)lp - 2) = cb_00;
                return lp;
            }

            /* planets/things heaps can move during HB realloc; update lp accordingly */
            if (ht != htPlanets && ht != htThings)
            {
                break;
            }

            lphb = LphbReAlloc(lphb);
            lp = (uint8_t *)lphb + 0x12;

            /* After moving, re-read current size header from the new location */
            cbCur = *(uint16_t *)((uint8_t *)lp - 2);
            if (cbCur >= cb_00)
            {
                return lp;
            }
            cbGrow = cb_00 - cbCur;
        }
    }

    /* fallback: allocate new, copy old payload, free old */
    lpNew = LpAlloc(cb_00, ht);
    memcpy(lpNew, lp, cbCur);
    FreeLp(lp, ht);
    return lpNew;
}

HB *LphbAlloc(uint16_t cb, HeapType ht)
{
    uint16_t want;
    uint16_t hmem;
    HB *lphb;

    /* Header size is 16 bytes in the original Win16 build, but in our
     * cross-platform build HB can be larger (e.g. 64-bit pointers). Use the
     * actual C struct size so the allocator never hands out space that overlaps
     * the HB header.
     */
    uint16_t cbHdr = (uint16_t)sizeof(HB);

    /* Original adds 0x10 for the HB header. Modern equivalent: add sizeof(HB). */
    want = (uint16_t)(cb + cbHdr);

    if ((uint16_t)ht >= (uint16_t)htCount)
    {
        /* original likely never calls with invalid ht; be defensive */
        int16_t mbType = 0x10;
        char *sz = PszFormatIds(0x1a, (int16_t *)0);
        AlertSz(sz, mbType);
        longjmp(penvMem->env, -1);
    }

    if (want < mphtcbAlloc[(uint16_t)ht])
    {
        want = mphtcbAlloc[(uint16_t)ht];
    }

    /* Win16 GlobalAlloc(0x22, cb) ~= calloc (zeroed) */
    lphb = (HB *)calloc(1, (size_t)want);
    if (!lphb)
    {
        int16_t mbType = 0x10;
        char *sz = PszFormatIds(0x1a, (int16_t *)0);
        AlertSz(sz, mbType);
        longjmp(penvMem->env, -1);
    }

    /* Create a 16-bit “handle” for this block (replacement for HGLOBAL). */
    hmem = HbHandleAlloc(lphb);
    if (hmem == 0)
    {
        /* extremely rare; treat as OOM like the original */
        free(lphb);
        {
            int16_t mbType = 0x10;
            char *sz = PszFormatIds(0x1a, (int16_t *)0);
            AlertSz(sz, mbType);
            longjmp(penvMem->env, -1);
        }
    }

    /* Header setup exactly matching the decompile */
    lphb->hmem = hmem;
    lphb->cbBlock = want;
    lphb->cbSlop = (uint16_t)(want - cbHdr);
    lphb->cbFree = (uint16_t)(want - cbHdr);
    lphb->ibTop = cbHdr;
    lphb->ht = (uint8_t)ht;

    /* push on head of heap list */
    lphb->lphbNext = rglphb[(uint16_t)ht];
    rglphb[(uint16_t)ht] = lphb;

    return lphb;
}

PL *LpplAlloc(uint16_t cbItem, uint16_t cAlloc, HeapType ht)
{
    PL *lppl;

    /* sizeof(PL) is verified to match original layout in your asserts */
    lppl = (PL *)LpAlloc((uint16_t)(cbItem * cAlloc + sizeof(PL)), ht);

    /* matches decompile writes at +2/+3 */
    lppl->iMax = (uint8_t)cAlloc;
    lppl->iMac = 0;

    /* use your bitfields instead of raw flag twiddling */
    lppl->fMark = 0;
    lppl->cbItem = cbItem;
    lppl->ht = ht;
    lppl->cAlloc = cAlloc;

    return lppl;
}

void FreeHb(HB *lphb)
{
    while (lphb != NULL)
    {
        HB *lphbNext = lphb->lphbNext;
        uint16_t hmem = lphb->hmem;

        /* In Win16: GlobalUnlock(hmem); GlobalFree(hmem); */
        {
            void *p = HbHandleFree(hmem);
            /* Prefer freeing the handle-mapped pointer, in case a caller passes
             * a stale HB* after a move/realloc.
             */
            if (p != NULL)
            {
                free(p);
            }
            else
            {
                free(lphb);
            }
        }

        lphb = lphbNext;
    }
}
