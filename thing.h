#ifndef THING_H_
#define THING_H_

#include "types.h"

int16_t IdmGiveTraderPart(uint16_t grbitTrader, int16_t iplr, uint16_t *piGoto);
void    FreeLpth(THING *lpth);
int16_t CPlanetsInCircle(POINT pt, int32_t r2);
int16_t PctWormholeMoves(THING *lpth);
void    DoThingInteractions(int16_t fPostMove);
THING  *LpthNew(int16_t iplr, ThingType ith);
int16_t IValidateWormholePos(THING *lpthWorm);

#ifdef _WIN32
void DrawThingGauge(uint16_t hdc, RECT *prc, THING *lpth, int16_t md);
#endif /* _WIN32 */

#endif /* THING_H_ */
