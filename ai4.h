#ifndef AI4_H_
#define AI4_H_


#include "types.h"

/* globals */
extern uint8_t vrgAiCybertronResOrder[42];  /* MEMORY_AI4:0x0000 */
extern uint16_t vrgCyberIshAip[36];  /* MEMORY_AI4:0x46b0 */
extern uint8_t vrgCyberAip[301];  /* MEMORY_AI4:0x46f8 */

/* functions */
int16_t FEnumDropOffStage2(PLANET *, PLANET *);  /* MEMORY_AI4:0x3dfe */
int16_t FEnumDropOffStage1(PLANET *, PLANET *);  /* MEMORY_AI4:0x3d00 */
int16_t FEnumNeedMinerals(PLANET *, PLANET *);  /* MEMORY_AI4:0x3f5e */
int16_t FFillProdMinesAndFactories(PLANET *);  /* MEMORY_AI4:0x2d72 */
void EnsureCyberAiShdefs(int16_t);  /* MEMORY_AI4:0x4826 */
int16_t iAddAttackFleet(PLANET *, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_AI4:0x4eba */
void TargetCyberArmada(FLEET *);  /* MEMORY_AI4:0x51a4 */
int16_t FAddPacketToQueue(PLANET *);  /* MEMORY_AI4:0x2bc0 */
int16_t FEnumCalcEnemyPlanets(PLANET *, PLANET *);  /* MEMORY_AI4:0x45a6 */
void DoCyberPackets(void);  /* MEMORY_AI4:0x1a78 */
int16_t IdGetBestScannerDest(PLANET *, int16_t);  /* MEMORY_AI4:0x282a */
int16_t FEnumPickUp(PLANET *, PLANET *);  /* MEMORY_AI4:0x3f00 */
int16_t iBuildCyberStarbase(PLANET *);  /* MEMORY_AI4:0x45de */
void DoCyberFreighter(FLEET *, CYBERINFOTEMP *);  /* MEMORY_AI4:0x37b0 */
void FillProductionQueue(void);  /* MEMORY_AI4:0x2ce2 */
void DoCyberAiTurn(PROD *);  /* MEMORY_AI4:0x002a */
int16_t FEnumPktAttack(PLANET *, PLANET *);  /* MEMORY_AI4:0x4204 */

#endif /* AI4_H_ */
