#ifndef AI3_H_
#define AI3_H_


#include "types.h"

/* globals */
extern uint8_t vrgAiMacintiResOrder[8];  /* MEMORY_AI3:0x0000 */
extern uint16_t vrgMacIshAip[31];  /* MEMORY_AI3:0x2a06 */
extern uint8_t vrgMacAip[248];  /* MEMORY_AI3:0x2a44 */

/* functions */
int16_t FPotentMacWarFleet(FLEET *, int16_t *);  /* MEMORY_AI3:0x42ec */
void EnsureMacintiShdefs(void);  /* MEMORY_AI3:0x2b3c */
int16_t IdTargetMacFreighter(FLEET *);  /* MEMORY_AI3:0x3524 */
void TargetMacArmada(FLEET *);  /* MEMORY_AI3:0x3e3a */
int16_t FRetargetMiner(FLEET *);  /* MEMORY_AI3:0x336c */
void DoMacintiAiTurn(PROD *);  /* MEMORY_AI3:0x0008 */

#endif /* AI3_H_ */
