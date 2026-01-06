
#include "types.h"

#include "parts.h"

/* globals */
ENGINE rgengine[16];  /* MEMORY_PARTS:0x0000 */
ARMOR rgarmor[12];  /* MEMORY_PARTS:0x04e0 */
SCANNER rgscanner[16];  /* MEMORY_PARTS:0x0768 */
SHIELD rgshield[10];  /* MEMORY_PARTS:0x0ae8 */
SPECIAL rgspecialE[17];  /* MEMORY_PARTS:0x0d04 */
SPECIAL rgspecialM[11];  /* MEMORY_PARTS:0x109a */
MINES rgmines[10];  /* MEMORY_PARTS:0x12ec */
MINING rgmining[8];  /* MEMORY_PARTS:0x1508 */
PLANETARY rgplanetary[15];  /* MEMORY_PARTS:0x16b8 */
TERRA rgterra[20];  /* MEMORY_PARTS:0x19e2 */
BOMB rgbomb[15];  /* MEMORY_PARTS:0x1e1a */
TORP rgtorp[12];  /* MEMORY_PARTS:0x2180 */
BEAM rgbeam[24];  /* MEMORY_PARTS:0x2450 */
HULDEF rghuldef[32];  /* MEMORY_PARTS:0x29f0 */
SHDEF rgshdefT[22];  /* MEMORY_PARTS:0x3bd0 */
HULDEF rghuldefSB[5];  /* MEMORY_PARTS:0x4872 */
SHDEF rgshdefSBT[4];  /* MEMORY_PARTS:0x4b3e */
SPECIALSB rgspecialSB[16];  /* MEMORY_PARTS:0x4d8a */

/* functions */
void LookupBestPlanetaryScanner(PART *ppart)
{

    /* TODO: implement */
}

int16_t FLookupPart(PART *ppart)
{
    int16_t raMajor;
    HS hs;

    /* TODO: implement */
    return 0;
}

HULDEF * LphuldefFromId(int16_t id)
{
    if (id < 0) {
        return NULL;
    }

    /* Normal hulls are 0..31. */
    if (id < 32) {
        return &rghuldef[id];
    }

    /* "Starbase" hulls are indexed after the normal hull set. */
    return LphuldefSBFromId((int16_t)(id - 32));
}

int16_t TechStatus(char *rgTech)
{
    int16_t fInAWhile;
    int16_t i;
    int16_t fAlmost;
    int16_t cMiss;

    /* TODO: implement */
    return 0;
}

HULDEF * LphuldefSBFromId(int16_t id)
{
    if (id < 0 || id >= (int16_t)(sizeof(rghuldefSB) / sizeof(rghuldefSB[0]))) {
        return NULL;
    }
    return &rghuldefSB[id];
}

SHDEF * LpshdefT(void)
{

    /* TODO: implement */
    return NULL;
}

PLANETARY * LpplanetaryFromId(int16_t id)
{

    /* TODO: implement */
    return NULL;
}

SHDEF * LpshdefSBT(void)
{

    /* TODO: implement */
    return NULL;
}

int16_t FLookupPartX(PART *ppart, uint16_t grhst, uint16_t iItem)
{

    /* TODO: implement */
    return 0;
}

SCANNER * LpscannerFromId(int16_t id)
{

    /* TODO: implement */
    return NULL;
}

ENGINE * LpengineFromId(int16_t id)
{

    /* TODO: implement */
    return NULL;
}
