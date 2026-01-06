#ifndef MEMORY_H_
#define MEMORY_H_


#include "types.h"

/* functions */
void ResetHb(int16_t);  /* MEMORY_MEMORY:0x0348 */
void FreePl(PL *);  /* MEMORY_MEMORY:0x0918 */
HB * LphbReAlloc(HB *);  /* RETFAR */  /* MEMORY_MEMORY:0x0108 */
PL * LpplReAlloc(PL *, uint16_t);  /* RETFAR */  /* MEMORY_MEMORY:0x0836 */
HB * LphbFromLpHt(void *, int16_t);  /* RETFAR */  /* MEMORY_MEMORY:0x058c */
void FreeLp(void *, int16_t);  /* MEMORY_MEMORY:0x07a8 */
void * LpAlloc(uint16_t, int16_t);  /* RETFAR */  /* MEMORY_MEMORY:0x03b2 */
void * LpReAlloc(void *, uint16_t, int16_t);  /* RETFAR */  /* MEMORY_MEMORY:0x0660 */
HB * LphbAlloc(uint16_t, int16_t);  /* RETFAR */  /* MEMORY_MEMORY:0x0000 */
PL * LpplAlloc(uint16_t, uint16_t, int16_t);  /* RETFAR */  /* MEMORY_MEMORY:0x088c */
void FreeHb(HB *);  /* MEMORY_MEMORY:0x02d8 */

#endif /* MEMORY_H_ */
