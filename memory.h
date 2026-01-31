#ifndef MEMORY_H_
#define MEMORY_H_

#include "types.h"

typedef enum HeapType { htOrd = 0, htString, htMsg, htPlanets, htLog, htFleets, htMisc, htShips, htPlrMsg, htPerm, htThings, htBattle, htCount } HeapType;

extern uint16_t mphtcbAlloc[12]; /*1120:0d64*/
// TODO: figure out how to get ghidra to override this type
extern HB *rglphb[12]; /*1120:0d34*/

/* functions */
void  ResetHb(HeapType ht);                                                  /* MEMORY_MEMORY:0x0348 */
void  FreePl(PL *lppl);                                                      /* MEMORY_MEMORY:0x0918 */
HB   *LphbReAlloc(HB *lphb); /* RETFAR */                                    /* MEMORY_MEMORY:0x0108 */
PL   *LpplReAlloc(PL *lppl, uint16_t cAlloc); /* RETFAR */                   /* MEMORY_MEMORY:0x0836 */
HB   *LphbFromLpHt(void *lp, HeapType ht); /* RETFAR */                      /* MEMORY_MEMORY:0x058c */
void  FreeLp(void *lp, HeapType ht);                                         /* MEMORY_MEMORY:0x07a8 */
void *LpAlloc(uint16_t cb, HeapType ht); /* RETFAR */                        /* MEMORY_MEMORY:0x03b2 */
void *LpReAlloc(void *lp, uint16_t cb, HeapType ht); /* RETFAR */            /* MEMORY_MEMORY:0x0660 */
HB   *LphbAlloc(uint16_t cb, HeapType ht); /* RETFAR */                      /* MEMORY_MEMORY:0x0000 */
PL   *LpplAlloc(uint16_t cbItem, uint16_t cAlloc, HeapType ht); /* RETFAR */ /* MEMORY_MEMORY:0x088c */
void  FreeHb(HB *lphb);                                                      /* MEMORY_MEMORY:0x02d8 */

#endif /* MEMORY_H_ */
