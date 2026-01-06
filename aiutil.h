#ifndef AIUTIL_H_
#define AIUTIL_H_


#include "types.h"

/* globals */
extern uint8_t vrgSBAip[85];  /* MEMORY_AIU:0x7688 */
extern uint8_t vrgSBMacAisb[6];  /* MEMORY_AIU:0x76de */
extern int32_t vrgAiPacketDist[2];  /* MEMORY_AIU:0x7dce */

/* functions */
void QueueAiStarbases(PROD *, int16_t);  /* MEMORY_AIU:0x8524 */
int16_t FGetAIPart(int16_t, PART *);  /* MEMORY_AIU:0x043e */
FLEET * LpflFindClosestEnum(FLEET *, int16_t (*)(FLEET *, FLEET *));  /* RETFAR */  /* MEMORY_AIU:0x5bae */
PLANET * LpplFindClosestEnum(PLANET *, int16_t (*)(PLANET *, PLANET *));  /* RETFAR */  /* MEMORY_AIU:0x5cd4 */
void AddItemToQueue(uint16_t, uint16_t, uint16_t, int16_t);  /* MEMORY_AIU:0x3e50 */
int16_t IdTargetAttack(FLEET *, FLEET *, FLEET *, int16_t);  /* MEMORY_AIU:0x1ffe */
int16_t FQueueAiDefenses(PLANET *, int32_t *, int32_t *);  /* MEMORY_AIU:0x939a */
int16_t XferAiSupply(int16_t, int16_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_AIU:0x0ad0 */
int16_t FFleetInField(FLEET *, THING *);  /* MEMORY_AIU:0x1cf6 */
void InitRandomPlanetList(void);  /* MEMORY_AIU:0xa082 */
void MergeAllShdefs(int16_t);  /* MEMORY_AIU:0x58be */
int16_t FAIFling(PLANET *, int32_t *);  /* MEMORY_AIU:0x7dd6 */
int16_t XferAiTroopers(int16_t, int16_t, int16_t);  /* MEMORY_AIU:0x0bc2 */
int16_t IdNearestColonizablePlanet(FLEET *, THING * *);  /* MEMORY_AIU:0x0e3e */
void GetProdQCost(PLANET *, int32_t *);  /* MEMORY_AIU:0x57c0 */
void MoveToNearestPlanetOrEnemy(FLEET *, int16_t);  /* MEMORY_AIU:0x7014 */
void PickANameAndBmp(SHDEF *, int16_t, int16_t, int16_t);  /* MEMORY_AIU:0x055a */
int16_t FIsAiAttack(FLEET *);  /* MEMORY_AIU:0x4a72 */
void SplitOutShdefs(uint8_t *);  /* MEMORY_AIU:0x98d8 */
int16_t FGotoWormholeAiFleet(FLEET *, THING *);  /* MEMORY_AIU:0x0d5c */
int16_t FFindBuddyAndJoinUp(FLEET *, int16_t, int16_t, int32_t, int32_t);  /* MEMORY_AIU:0x9d18 */
void SetAiFleetIdealSpeed(FLEET *, int16_t, int16_t, THING * *);  /* MEMORY_AIU:0x1d9e */
int16_t IdTargetFreighter(FLEET *, PLANET *);  /* MEMORY_AIU:0x286c */
int16_t FCreateAiShdef(int16_t, int16_t, uint8_t *);  /* MEMORY_AIU:0x012c */
int16_t FIsTurinDroneAiAttack(FLEET *);  /* MEMORY_AIU:0x4b9a */
int16_t FMoveAiFleet(FLEET *, ORDER *, int16_t);  /* MEMORY_AIU:0x3d0a */
void KeepFleetsMoving(void);  /* MEMORY_AIU:0x45ca */
int16_t FUpgradeAiStarbase(PLANET *, int16_t);  /* MEMORY_AIU:0x882a */
uint32_t UlFleetPower(FLEET *);  /* MEMORY_AIU:0x14de */
int16_t IdplFindClosestStarbase(FLEET *, int16_t);  /* MEMORY_AIU:0x6e04 */
void GetResourcesAvailable(PLANET *, int32_t *);  /* MEMORY_AIU:0x56d0 */
int16_t IshdefAiSBLatest(void);  /* MEMORY_AIU:0x84be */
int16_t FEnumOurStarbase(PLANET *, PLANET *);  /* MEMORY_AIU:0x6110 */
int16_t FSalvageTargetFreighter2(FLEET *, int16_t, int16_t, int16_t, int32_t, int32_t, THING * *, int16_t *);  /* MEMORY_AIU:0x395a */
int16_t IdTargetScout(FLEET *, FLEET *, FLEET *, int16_t, THING * *);  /* MEMORY_AIU:0x61de */
void MarkPlanetsUnderAttack(void);  /* MEMORY_AIU:0x6896 */
THING * LpthWormFind(POINT *, int32_t);  /* RETFAR */  /* MEMORY_AIU:0x12e6 */
void ClearAiCurrentTask(FLEET *, int16_t);  /* MEMORY_AIU:0x60c0 */
int16_t FCreateAiStarbase(int16_t, int16_t, int16_t, int16_t);  /* MEMORY_AIU:0x7bca */
void EnsureAiStarbaseDesigns(void);  /* MEMORY_AIU:0x7222 */
int16_t FShouldWeBuildColonizers(int16_t *);  /* MEMORY_AIU:0x476a */
int16_t FColonizeAiFleet(FLEET *, int16_t);  /* MEMORY_AIU:0x0c78 */
int16_t IroEnsureAi(uint8_t *, int16_t, int16_t *, int16_t);  /* MEMORY_AIU:0x425a */
void EnsureMacintiStarbaseDesigns(uint8_t *);  /* MEMORY_AIU:0x76e4 */
int16_t IshdefAiSBLatestOF(void);  /* MEMORY_AIU:0x8458 */
int16_t FQueueAiScanner(PLANET *, int32_t *, int32_t *);  /* MEMORY_AIU:0x90d6 */
void IncreaseAIMinefieldSizes(void);  /* MEMORY_AIU:0x9c66 */
int16_t FMoveToNearestStarbase(FLEET *, int16_t);  /* MEMORY_AIU:0x6f7e */
void QuickBuildDefenses(PLANET *, PROD *);  /* MEMORY_AIU:0x6a7e */
int16_t FIsAiTransport(FLEET *);  /* MEMORY_AIU:0x4c08 */
int16_t FChangeAiShdef(SHDEF *, int16_t);  /* MEMORY_AIU:0x08a2 */
int16_t FFleetMightHaveTeeth(FLEET *);  /* MEMORY_AIU:0x6152 */
void HandleBasicAiTasks(int16_t, PROD *, int16_t, int32_t *, int32_t *);  /* MEMORY_AIU:0x95a4 */
int16_t FQueueAiTerraforming(PLANET *, int32_t *, int32_t *);  /* MEMORY_AIU:0x8d28 */
int16_t IdNearestUnknownPlanet(FLEET *, THING * *);  /* MEMORY_AIU:0x15a4 */
void ValidateStarbaseHistory(void);  /* MEMORY_AIU:0x4cf0 */
void AddMinesToBlockedQueues(void);  /* MEMORY_AIU:0x1792 */
int16_t IdRandomPlanetNearby(POINT, int16_t, int16_t);  /* MEMORY_AIU:0x5f54 */
int16_t CheckAiShdefStatus(int16_t, int16_t, uint16_t, int16_t *, uint8_t *);  /* MEMORY_AIU:0x9b10 */
PLANET * LpplFindBestEnum(PLANET *, int16_t (*)(PLANET *, PLANET *));  /* RETFAR */  /* MEMORY_AIU:0x5e06 */
void FixPlanetsUnderAttack(PROD *);  /* MEMORY_AIU:0x69e6 */
int16_t FShouldPlanetBuildColonizer(PLANET *);  /* MEMORY_AIU:0x9f30 */

#endif /* AIUTIL_H_ */
