
#include "types.h"

#include "memory.h"

/* functions */
void ResetHb(int16_t ht)
{
    HB * lphb;

    /* TODO: implement */
}

void FreePl(PL *lppl)
{

    /* TODO: implement */
}

HB * LphbReAlloc(HB *lphb)
{
    uint16_t hmem;
    HB * lphbT;
    HB * lphbNew;
    uint16_t cbCur;
    uint16_t cbGrow;

    /* debug symbols */
    /* label LReAllocOOM @ MEMORY_MEMORY:0x01aa */

    /* TODO: implement */
    return NULL;
}

PL * LpplReAlloc(PL *lppl, uint16_t cAlloc)
{

    /* TODO: implement */
    return NULL;
}

HB * LphbFromLpHt(void *lp, int16_t ht)
{
    HB * lphb;

    /* TODO: implement */
    return NULL;
}

void FreeLp(void *lp, int16_t ht)
{
    uint16_t cbFree;
    HB * lphb;

    /* TODO: implement */
}

void * LpAlloc(uint16_t cb, int16_t ht)
{
    int16_t fFree;
    uint16_t cbItem;
    uint8_t * lpbPrev;
    uint8_t * lpbTop;
    HB * lphb;
    uint8_t * lpb;

    /* debug symbols */
    /* label LTryNextBlock @ MEMORY_MEMORY:0x03fc */

    /* TODO: implement */
    return NULL;
}

void * LpReAlloc(void *lp, uint16_t cb, int16_t ht)
{
    void * lpNew;
    HB * lphb;
    uint16_t cbCur;
    uint16_t cbGrow;

    /* debug symbols */
    /* label LGrewHeap @ MEMORY_MEMORY:0x06b3 */

    /* TODO: implement */
    return NULL;
}

HB * LphbAlloc(uint16_t cb, int16_t ht)
{
    uint16_t hmem;
    HB * lphb;

    /* TODO: implement */
    return NULL;
}

PL * LpplAlloc(uint16_t cbItem, uint16_t cAlloc, int16_t ht)
{
    PL * lppl;

    /* TODO: implement */
    return NULL;
}

void FreeHb(HB *lphb)
{
    uint16_t hmem;
    HB * lphbNext;

    /* TODO: implement */
}
