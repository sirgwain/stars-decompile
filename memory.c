
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

    /* TODO: implement */
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
    char *sz = PszFormatIds(idsOutOfMemory, (int16_t *)0);
    AlertSz(sz, mbType);
    longjmp(penvMem, -1);
}
}

PL *LpplReAlloc(PL *lppl, uint16_t cAlloc)
{

    /* TODO: implement */
    return NULL;
}

HB *LphbFromLpHt(void *lp, HeapType ht)
{
    HB *lphb;

    /* TODO: implement */
    return NULL;
}

void FreeLp(void *lp, HeapType ht)
{
    uint16_t cbFree;
    HB *lphb;

    /* TODO: implement */
}

void *LpAlloc(uint16_t cb, HeapType ht)
{
    int16_t fFree;
    uint16_t cbItem;
    uint8_t *lpbPrev;
    uint8_t *lpbTop;
    HB *lphb;
    uint8_t *lpb;

    /* debug symbols */
    /* label LTryNextBlock @ MEMORY_MEMORY:0x03fc */

    /* TODO: implement */
    return NULL;
}

void *LpReAlloc(void *lp, uint16_t cb, HeapType ht)
{
    void *lpNew;
    HB *lphb;
    uint16_t cbCur;
    uint16_t cbGrow;

    /* debug symbols */
    /* label LGrewHeap @ MEMORY_MEMORY:0x06b3 */

    /* TODO: implement */
    return NULL;
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
        longjmp(penvMem, -1);
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
        longjmp(penvMem, -1);
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
            longjmp(penvMem, -1);
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

    /* TODO: implement */
    return NULL;
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
