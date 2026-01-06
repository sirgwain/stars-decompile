#ifndef AI2_H_
#define AI2_H_


#include "types.h"

/* globals */
extern uint8_t vrgISIshAip[19];  /* MEMORY_AI2:0x0064 */
extern uint8_t vrgISAip[182];  /* MEMORY_AI2:0x0078 */
extern uint8_t vrgAiISResOrder[18];  /* MEMORY_AI2:0x01ce */

/* functions */
void DoRototillAiTurn(PROD *);  /* MEMORY_AI2:0x1e22 */
void DoAutomitronAiTurn(PROD *);  /* MEMORY_AI2:0x01e0 */
int16_t FPotentISWarFleet(FLEET *, int16_t);  /* MEMORY_AI2:0x012e */
void EnsureCAShdefs(int16_t);  /* MEMORY_AI2:0x3020 */
void EnsureISShdefs(int16_t);  /* MEMORY_AI2:0x1938 */
void DoMaidAiTurn(PROD *);  /* MEMORY_AI2:0x0000 */

#endif /* AI2_H_ */
