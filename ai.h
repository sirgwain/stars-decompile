#ifndef AI_H_
#define AI_H_


#include "types.h"

/* globals */
extern uint8_t vrgAiRobotoidResOrder[36];  /* MEMORY_AI:0x02ee */
extern uint16_t vrgRobIshAip[38];  /* MEMORY_AI:0x1f34 */
extern uint8_t vrgRobAip[301];  /* MEMORY_AI:0x1f80 */
extern uint8_t vrgTDIshAip[19];  /* MEMORY_AI:0x35ae */
extern uint8_t vrgTDAip[141];  /* MEMORY_AI:0x35c2 */
extern uint8_t vrgAiTurinDroneResOrder[31];  /* MEMORY_AI:0x3650 */

/* functions */
void DoAiTurn(int16_t, uint16_t);  /* MEMORY_AI:0x0000 */
int16_t FEnumCalcArmadaHumanDest(PLANET *, PLANET *);  /* MEMORY_AI:0x3406 */
void EnsureRobotoidShdefs(void);  /* MEMORY_AI:0x20ae */
int16_t FEnumCalcArmadaDest(PLANET *, PLANET *);  /* MEMORY_AI:0x3286 */
void DoTurinDroneAiTurn(PROD *);  /* MEMORY_AI:0x3670 */
void EnsureTurinDroneShdefs(int16_t);  /* MEMORY_AI:0x58ba */
int16_t FEnumCalcMinerDest(PLANET *, PLANET *);  /* MEMORY_AI:0x5f32 */
int16_t FEnumCalcEnemyFleets(FLEET *, FLEET *);  /* MEMORY_AI:0x325c */
int16_t IdTargetArmada(FLEET *);  /* MEMORY_AI:0x288e */
int16_t FEnumCalcColonistDrop(PLANET *, PLANET *);  /* MEMORY_AI:0x5fc8 */
void DoRobotoidAiTurn(PROD *);  /* MEMORY_AI:0x0312 */
int16_t FPotentRobWarFleet(FLEET *, int16_t);  /* MEMORY_AI:0x31bc */

#endif /* AI_H_ */
