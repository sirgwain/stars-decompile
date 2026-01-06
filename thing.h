#ifndef THING_H_
#define THING_H_


#include "types.h"

/* functions */
int16_t IdmGiveTraderPart(uint16_t, int16_t, uint16_t *);  /* MEMORY_THING:0x1a96 */
void DrawThingGauge(uint16_t, RECT *, THING *, int16_t);  /* MEMORY_THING:0x044e */
void FreeLpth(THING *);  /* MEMORY_THING:0x0224 */
int16_t CPlanetsInCircle(POINT, int32_t);  /* MEMORY_THING:0x02a0 */
int16_t PctWormholeMoves(THING *);  /* MEMORY_THING:0x0adc */
void DoThingInteractions(int16_t);  /* MEMORY_THING:0x0b3a */
THING * LpthNew(int16_t, int16_t);  /* RETFAR */  /* MEMORY_THING:0x0000 */
int16_t IValidateWormholePos(THING *);  /* MEMORY_THING:0x064c */

#endif /* THING_H_ */
