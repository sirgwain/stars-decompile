#ifndef TURN_H_
#define TURN_H_


#include "types.h"

/* globals */
extern int16_t rgrgdmgMine[3][2];  /* MEMORY_TURN:0x4f3c */
extern int16_t rgrgdmgMinMine[3][2];  /* MEMORY_TURN:0x4f48 */
extern int16_t rgpctMineHit[3];  /* MEMORY_TURN:0x4f54 */
extern int16_t rgiWarpSafe[3];  /* MEMORY_TURN:0x4f5a */

/* functions */
void DoOrders(int16_t);  /* MEMORY_TURN:0x179a */
void FuelFleets(void);  /* MEMORY_TURN:0x2efa */
int16_t FGenerateTurn(void);  /* MEMORY_TURN:0x0000 */
void MoveFleets(void);  /* MEMORY_TURN:0x32ce */
int16_t FTravelThroughMineFields(FLEET *, int16_t *, THING *);  /* MEMORY_TURN:0x4f60 */
void MoveThings(int16_t);  /* MEMORY_TURN:0x18f4 */

#endif /* TURN_H_ */
