#ifndef AIUTIL_H_
#define AIUTIL_H_

#include "strings.h"
#include "types.h"

/* globals */
extern uint8_t vrgSBAip[85];       /* MEMORY_AIU:0x7688 */
extern uint8_t vrgSBMacAisb[6];    /* MEMORY_AIU:0x76de */
extern int32_t vrgAiPacketDist[2]; /* MEMORY_AIU:0x7dce */

/* functions */
void     QueueAiStarbases(PROD *rgprod, int16_t ishdefSBLatest);                                                         /* MEMORY_AIU:0x8524 */
int16_t  FGetAIPart(int16_t aip, PART *ppart);                                                                           /* MEMORY_AIU:0x043e */
FLEET   *LpflFindClosestEnum(FLEET *lpfl, int16_t (*pfn)(FLEET *, FLEET *)); /* RETFAR */                                /* MEMORY_AIU:0x5bae */
PLANET  *LpplFindClosestEnum(PLANET *lppl, int16_t (*pfn)(PLANET *, PLANET *)); /* RETFAR */                             /* MEMORY_AIU:0x5cd4 */
void     AddItemToQueue(uint16_t iItem, uint16_t cItem, GrobjClass grobj, int16_t mdAddItem);                            /* MEMORY_AIU:0x3e50 */
int16_t  IdTargetAttack(FLEET *lpfl, FLEET *lpflAtk, FLEET *lpflEnemy, int16_t fOnlyHumans);                             /* MEMORY_AIU:0x1ffe */
int16_t  FQueueAiDefenses(PLANET *lppl, int32_t *rgResAvail, int32_t *rgResCost);                                        /* MEMORY_AIU:0x939a */
int16_t  XferAiSupply(int16_t grobjSrc, int16_t idSrc, int16_t grobjDst, int16_t idDst, int16_t iSupply, int16_t cQuan); /* MEMORY_AIU:0x0ad0 */
int16_t  FFleetInField(FLEET *lpfl, THING *lpth);                                                                        /* MEMORY_AIU:0x1cf6 */
void     InitRandomPlanetList(void);                                                                                     /* MEMORY_AIU:0xa082 */
void     MergeAllShdefs(int16_t grbitish);                                                                               /* MEMORY_AIU:0x58be */
int16_t  FAIFling(PLANET *lppl, int32_t *rgResAvail);                                                                    /* MEMORY_AIU:0x7dd6 */
int16_t  XferAiTroopers(int16_t idSrc, int16_t idDst, int16_t cQuan);                                                    /* MEMORY_AIU:0x0bc2 */
int16_t  IdNearestColonizablePlanet(FLEET *lpflCol, THING **plpthWorm);                                                  /* MEMORY_AIU:0x0e3e */
void     GetProdQCost(PLANET *lppl, int32_t *rgCost);                                                                    /* MEMORY_AIU:0x57c0 */
void     MoveToNearestPlanetOrEnemy(FLEET *lpfl, int16_t dEnemyRange);                                                   /* MEMORY_AIU:0x7014 */
void     PickANameAndBmp(SHDEF *pshdef, StringId ids, int16_t cids, int16_t ibmpStart);                                  /* MEMORY_AIU:0x055a */
int16_t  FIsAiAttack(FLEET *lpfl);                                                                                       /* MEMORY_AIU:0x4a72 */
void     SplitOutShdefs(uint8_t *rgbIsh);                                                                                /* MEMORY_AIU:0x98d8 */
int16_t  FGotoWormholeAiFleet(FLEET *lpfl, THING *lpthWorm);                                                             /* MEMORY_AIU:0x0d5c */
int16_t  FFindBuddyAndJoinUp(FLEET *lpfl, int16_t ishLo, int16_t ishHi, int32_t lMaxDist1, int32_t lMaxDist2);           /* MEMORY_AIU:0x9d18 */
void     SetAiFleetIdealSpeed(FLEET *lpfl, int16_t wtFuelMax, int16_t cMinefields, THING **rglpth);                      /* MEMORY_AIU:0x1d9e */
int16_t  IdTargetFreighter(FLEET *lpflFr, PLANET *lpplHome);                                                             /* MEMORY_AIU:0x286c */
int16_t  FCreateAiShdef(int16_t ishdef, int16_t ihul, uint8_t *rgaip);                                                   /* MEMORY_AIU:0x012c */
int16_t  FIsTurinDroneAiAttack(FLEET *lpfl);                                                                             /* MEMORY_AIU:0x4b9a */
int16_t  FMoveAiFleet(FLEET *lpfl, ORDER *pord, int16_t fAppend);                                                        /* MEMORY_AIU:0x3d0a */
void     KeepFleetsMoving(void);                                                                                         /* MEMORY_AIU:0x45ca */
int16_t  FUpgradeAiStarbase(PLANET *lppl, int16_t ishdefSBLatest);                                                       /* MEMORY_AIU:0x882a */
uint32_t UlFleetPower(FLEET *lpfl);                                                                                      /* MEMORY_AIU:0x14de */
int16_t  IdplFindClosestStarbase(FLEET *lpfl, int16_t fBigOnes);                                                         /* MEMORY_AIU:0x6e04 */
void     GetResourcesAvailable(PLANET *lppl, int32_t *rgRes);                                                            /* MEMORY_AIU:0x56d0 */
int16_t  IshdefAiSBLatest(void);                                                                                         /* MEMORY_AIU:0x84be */
int16_t  FEnumOurStarbase(PLANET *lpplSrc, PLANET *lpplTest);                                                            /* MEMORY_AIU:0x6110 */
int16_t  FSalvageTargetFreighter2(FLEET *lpflFr, int16_t fNeedy, int16_t iWorst, int16_t pctFull, int32_t wtCargoMax, int32_t scoreBest, THING **plpthBest,
                                  int16_t *pidBest);                                                                        /* MEMORY_AIU:0x395a */
int16_t  IdTargetScout(FLEET *lpfl, FLEET *lpflAtk, FLEET *lpflEnemy, int16_t fOnlyHumans, THING **plpthWorm);              /* MEMORY_AIU:0x61de */
void     MarkPlanetsUnderAttack(void);                                                                                      /* MEMORY_AIU:0x6896 */
THING   *LpthWormFind(POINT *ppt, int32_t d2); /* RETFAR */                                                                 /* MEMORY_AIU:0x12e6 */
void     ClearAiCurrentTask(FLEET *lpfl, int16_t fChangeSel);                                                               /* MEMORY_AIU:0x60c0 */
int16_t  FCreateAiStarbase(int16_t ishdef, int16_t iLevel, int16_t aisb, int16_t isb);                                      /* MEMORY_AIU:0x7bca */
void     EnsureAiStarbaseDesigns(void);                                                                                     /* MEMORY_AIU:0x7222 */
int16_t  FShouldWeBuildColonizers(int16_t *pcCol);                                                                          /* MEMORY_AIU:0x476a */
int16_t  FColonizeAiFleet(FLEET *lpfl, int16_t idPlanet);                                                                   /* MEMORY_AIU:0x0c78 */
int16_t  IroEnsureAi(uint8_t *lpbRes, int16_t cRes, int16_t *pishdefSBLatest, int16_t pct);                                 /* MEMORY_AIU:0x425a */
void     EnsureMacintiStarbaseDesigns(uint8_t *rgSB);                                                                       /* MEMORY_AIU:0x76e4 */
int16_t  IshdefAiSBLatestOF(void);                                                                                          /* MEMORY_AIU:0x8458 */
int16_t  FQueueAiScanner(PLANET *lppl, int32_t *rgResAvail, int32_t *rgResCost);                                            /* MEMORY_AIU:0x90d6 */
void     IncreaseAIMinefieldSizes(void);                                                                                    /* MEMORY_AIU:0x9c66 */
int16_t  FMoveToNearestStarbase(FLEET *lpfl, int16_t fBigOnes);                                                             /* MEMORY_AIU:0x6f7e */
void     QuickBuildDefenses(PLANET *lppl, PROD *rgprod);                                                                    /* MEMORY_AIU:0x6a7e */
int16_t  FIsAiTransport(FLEET *lpfl);                                                                                       /* MEMORY_AIU:0x4c08 */
int16_t  FChangeAiShdef(SHDEF *pshdef, int16_t ishdef);                                                                     /* MEMORY_AIU:0x08a2 */
int16_t  FFleetMightHaveTeeth(FLEET *lpfl);                                                                                 /* MEMORY_AIU:0x6152 */
void     HandleBasicAiTasks(int16_t iroCur, PROD *rgprod, int16_t ishdefSBLatest, int32_t *rgResAvail, int32_t *rgResCost); /* MEMORY_AIU:0x95a4 */
int16_t  FQueueAiTerraforming(PLANET *lppl, int32_t *rgResAvail, int32_t *rgResCost);                                       /* MEMORY_AIU:0x8d28 */
int16_t  IdNearestUnknownPlanet(FLEET *lpfl, THING **plpthWorm);                                                            /* MEMORY_AIU:0x15a4 */
void     ValidateStarbaseHistory(void);                                                                                     /* MEMORY_AIU:0x4cf0 */
void     AddMinesToBlockedQueues(void);                                                                                     /* MEMORY_AIU:0x1792 */
int16_t  IdRandomPlanetNearby(POINT pt, int16_t cDist, int16_t fAvoidStarbases);                                            /* MEMORY_AIU:0x5f54 */
int16_t  CheckAiShdefStatus(int16_t ishBeg, int16_t ishEnd, uint16_t cRecyclePeriod, int16_t *piLatest, uint8_t *rgbOld);   /* MEMORY_AIU:0x9b10 */
PLANET  *LpplFindBestEnum(PLANET *lppl, int16_t (*pfn)(PLANET *, PLANET *)); /* RETFAR */                                   /* MEMORY_AIU:0x5e06 */
void     FixPlanetsUnderAttack(PROD *rgprod);                                                                               /* MEMORY_AIU:0x69e6 */
int16_t  FShouldPlanetBuildColonizer(PLANET *lpplSrc);                                                                      /* MEMORY_AIU:0x9f30 */

#endif /* AIUTIL_H_ */
