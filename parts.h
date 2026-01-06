#ifndef PARTS_H_
#define PARTS_H_


#include "types.h"

/* globals */
extern ENGINE rgengine[16];  /* MEMORY_PARTS:0x0000 */
extern ARMOR rgarmor[12];  /* MEMORY_PARTS:0x04e0 */
extern SCANNER rgscanner[16];  /* MEMORY_PARTS:0x0768 */
extern SHIELD rgshield[10];  /* MEMORY_PARTS:0x0ae8 */
extern SPECIAL rgspecialE[17];  /* MEMORY_PARTS:0x0d04 */
extern SPECIAL rgspecialM[11];  /* MEMORY_PARTS:0x109a */
extern MINES rgmines[10];  /* MEMORY_PARTS:0x12ec */
extern MINING rgmining[8];  /* MEMORY_PARTS:0x1508 */
extern PLANETARY rgplanetary[15];  /* MEMORY_PARTS:0x16b8 */
extern TERRA rgterra[20];  /* MEMORY_PARTS:0x19e2 */
extern BOMB rgbomb[15];  /* MEMORY_PARTS:0x1e1a */
extern TORP rgtorp[12];  /* MEMORY_PARTS:0x2180 */
extern BEAM rgbeam[24];  /* MEMORY_PARTS:0x2450 */
extern HULDEF rghuldef[32];  /* MEMORY_PARTS:0x29f0 */
extern SHDEF rgshdefT[22];  /* MEMORY_PARTS:0x3bd0 */
extern HULDEF rghuldefSB[5];  /* MEMORY_PARTS:0x4872 */
extern SHDEF rgshdefSBT[4];  /* MEMORY_PARTS:0x4b3e */
extern SPECIALSB rgspecialSB[16];  /* MEMORY_PARTS:0x4d8a */

/* functions */
void LookupBestPlanetaryScanner(PART *);  /* MEMORY_PARTS:0x60be */
int16_t FLookupPart(PART *);  /* MEMORY_PARTS:0x524e */
HULDEF * LphuldefFromId(int16_t);  /* RETFAR */  /* MEMORY_PARTS:0x512c */
int16_t TechStatus(char *);  /* MEMORY_PARTS:0x6148 */
HULDEF * LphuldefSBFromId(int16_t);  /* RETFAR */  /* MEMORY_PARTS:0x510a */
SHDEF * LpshdefT(void);  /* RETFAR */  /* MEMORY_PARTS:0x51ac */
PLANETARY * LpplanetaryFromId(int16_t);  /* RETFAR */  /* MEMORY_PARTS:0x51dc */
SHDEF * LpshdefSBT(void);  /* RETFAR */  /* MEMORY_PARTS:0x51c4 */
int16_t FLookupPartX(PART *, uint16_t, uint16_t);  /* MEMORY_PARTS:0x51fe */
SCANNER * LpscannerFromId(int16_t);  /* RETFAR */  /* MEMORY_PARTS:0x518a */
ENGINE * LpengineFromId(int16_t);  /* RETFAR */  /* MEMORY_PARTS:0x5168 */

#endif /* PARTS_H_ */
