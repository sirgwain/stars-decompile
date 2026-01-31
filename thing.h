#ifndef THING_H_
#define THING_H_

#include "types.h"

/* functions */
int16_t IdmGiveTraderPart(uint16_t grbitTrader, int16_t iplr, uint16_t *piGoto); /* MEMORY_THING:0x1a96 */
void    DrawThingGauge(uint16_t hdc, RECT *prc, THING *lpth, int16_t md);        /* MEMORY_THING:0x044e */
void    FreeLpth(THING *lpth);                                                   /* MEMORY_THING:0x0224 */
int16_t CPlanetsInCircle(POINT pt, int32_t r2);                                  /* MEMORY_THING:0x02a0 */
int16_t PctWormholeMoves(THING *lpth);                                           /* MEMORY_THING:0x0adc */
void    DoThingInteractions(int16_t fPostMove);                                  /* MEMORY_THING:0x0b3a */
THING  *LpthNew(int16_t iplr, ThingType ith); /* RETFAR */                       /* MEMORY_THING:0x0000 */
int16_t IValidateWormholePos(THING *lpthWorm);                                   /* MEMORY_THING:0x064c */

#endif /* THING_H_ */
