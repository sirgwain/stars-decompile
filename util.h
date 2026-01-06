#ifndef UTIL_H_
#define UTIL_H_


#include "types.h"

/* globals */
extern uint8_t vrgbTachyon[18];  /* MEMORY_UTIL:0x50be */
extern int32_t rgDSDivCnt[5];  /* MEMORY_UTIL:0x5f7e */
extern uint32_t rgcrDrawStars[5];  /* MEMORY_UTIL:0x5f92 */
extern int32_t rgDSDivCnt2[5];  /* MEMORY_UTIL:0x5fa6 */
extern uint32_t rgcrDrawStars2a[5];  /* MEMORY_UTIL:0x5fba */
extern uint32_t rgcrDrawStars2b[5];  /* MEMORY_UTIL:0x5fce */

/* functions */
char * PszGetLocName(int16_t, int16_t, int16_t, int16_t);  /* MEMORY_UTIL:0x3b08 */
int16_t FCanFleetUseStargates(FLEET *, POINT, POINT);  /* MEMORY_UTIL:0x75e2 */
FLEET * LpflFromId(int16_t);  /* RETFAR */  /* MEMORY_UTIL:0x2078 */
PLANET * LpplFromId(int16_t);  /* RETFAR */  /* MEMORY_UTIL:0x021e */
THING * LpthFromId(int16_t);  /* RETFAR */  /* MEMORY_UTIL:0x01b2 */
int32_t LCalcFuelGainFromRamScoops(FLEET *, int16_t, int32_t);  /* MEMORY_UTIL:0x56b8 */
int16_t IshdefPrimaryFromLpfl(FLEET *, int16_t *);  /* MEMORY_UTIL:0x3e1c */
int16_t GetCachedFleetScannerRange(FLEET *, int16_t *, int16_t *, int16_t *);  /* MEMORY_UTIL:0x4e02 */
int16_t FLookupSelShip(FLEET *);  /* MEMORY_UTIL:0x2032 */
int16_t FMatchTarget(FLEET *, int16_t, int16_t);  /* MEMORY_UTIL:0x6612 */
void ClearFile(int16_t);  /* MEMORY_UTIL:0x7f6a */
int32_t LComputePower(SHDEF *);  /* MEMORY_UTIL:0x0b32 */
char * PszGetFleetName(int16_t);  /* MEMORY_UTIL:0x292c */
char * PszGetThingName(int16_t);  /* MEMORY_UTIL:0x26de */
int32_t LongFromSerialCh(char);  /* MEMORY_UTIL:0x6280 */
uint16_t WPackLong(int32_t);  /* MEMORY_UTIL:0x4ba2 */
double DGetDistance(int16_t, int16_t, int16_t, int16_t);  /* MEMORY_UTIL:0x3fe4 */
int16_t FDeleteFleet(int16_t, int16_t, int16_t);  /* MEMORY_UTIL:0x2d44 */
int32_t WtFromLpfl(FLEET *);  /* MEMORY_UTIL:0x7a68 */
void SelectOursAtObject(POINT *);  /* MEMORY_UTIL:0x08f2 */
int16_t CchGetETA(uint16_t, FLEET *, char *, int16_t, int16_t);  /* MEMORY_UTIL:0x3bc8 */
char * PszGetPlanetName(int16_t);  /* MEMORY_UTIL:0x2c6a */
int16_t FDupFleet(FLEET *, FLEET *);  /* MEMORY_UTIL:0x2332 */
int16_t FDupPlanet(PLANET *, PLANET *);  /* MEMORY_UTIL:0x0032 */
char * PszFleetNameFromWord(uint16_t);  /* MEMORY_UTIL:0x2b5e */
int16_t FValidSerialNo(char *, int32_t *);  /* MEMORY_UTIL:0x62f8 */
void DrawABunchOfStars(uint16_t, RECT *);  /* MEMORY_UTIL:0x5fe2 */
char * PszGetDistance(int16_t, int16_t, int16_t, int16_t);  /* MEMORY_UTIL:0x3f00 */
void CalcPctSurvive(PLANET *, float *, float *);  /* MEMORY_UTIL:0x02f6 */
int16_t IshFindSimilarDesign(HUL *, int16_t);  /* MEMORY_UTIL:0x7c5e */
void DecorateHullName(int16_t, int16_t, char *);  /* MEMORY_UTIL:0x5e0e */
int16_t FCanBuildShdef(SHDEF *, int16_t);  /* MEMORY_UTIL:0x7b40 */
int16_t FFleetMergeAll(FLEET *);  /* MEMORY_UTIL:0x34d8 */
int16_t ICompFleetPoint2(void *, void *);  /* MEMORY_UTIL:0x1fa2 */
void TurnLog(int16_t);  /* MEMORY_UTIL:0x80c2 */
char * PszPlayerName(int16_t, int16_t, int16_t, int16_t, int16_t, PLAYER *);  /* MEMORY_UTIL:0x11f2 */
int16_t IStargateFromLppl(PLANET *);  /* MEMORY_UTIL:0x10fa */
int32_t DpOfLpflIshdef(FLEET *, int16_t);  /* MEMORY_UTIL:0x0746 */
int16_t FFleetSplitAll(FLEET *);  /* MEMORY_UTIL:0x3a00 */
int16_t ICompFleetPoint(void *, void *);  /* MEMORY_UTIL:0x1f0c */
void OutputSz(int16_t, char *);  /* MEMORY_UTIL:0x7fe6 */
void ComputeShdefPowers(void);  /* MEMORY_UTIL:0x0e4e */
int16_t GetPlanetScannerRange(PLANET *, int16_t *);  /* MEMORY_UTIL:0x4c02 */
FLEET * LpflNew(int16_t, int16_t);  /* RETFAR */  /* MEMORY_UTIL:0x300c */
void UpdateShdefCost(SHDEF *);  /* MEMORY_UTIL:0x47b0 */
int16_t FLookupSelPlanet(PLANET *);  /* MEMORY_UTIL:0x0000 */
int16_t FLookupThing(int16_t, THING *);  /* MEMORY_UTIL:0x07fe */
int16_t FLookupFleet(int16_t, FLEET *);  /* MEMORY_UTIL:0x2160 */
int16_t FLookupOrbitingXfer(int16_t, int16_t, XFER *, int16_t);  /* MEMORY_UTIL:0x24fa */
void LinkFleets(int16_t);  /* MEMORY_UTIL:0x1bb4 */
int16_t FCalcFleetBombDamage(FLEET *, int32_t *, int32_t *, int32_t *, int32_t *, int32_t *, int16_t *);  /* MEMORY_UTIL:0x145c */
int16_t IflFromLpfl(FLEET *);  /* MEMORY_UTIL:0x2ce8 */
int32_t DpShieldOfShdef(SHDEF *, int16_t);  /* MEMORY_UTIL:0x0f24 */
void GetTrueHullCost(int16_t, HUL *, uint16_t *);  /* MEMORY_UTIL:0x5dba */
void DrawPlanetPrintDot(uint16_t, int16_t, int16_t, int16_t);  /* MEMORY_UTIL:0x7e44 */
int16_t GetShdefScannerRange(SHDEF *, int16_t, int16_t *, int16_t *, int16_t *);  /* MEMORY_UTIL:0x50d0 */
void ValidateWaypoints(void);  /* MEMORY_UTIL:0x68c6 */
int32_t ChgPopFromPlanet(PLANET *, int16_t);  /* MEMORY_UTIL:0x7082 */
int16_t FFleetCanJumpgate(FLEET *);  /* MEMORY_UTIL:0x7960 */
int32_t CalcPlayerScore(int16_t, SCORE *);  /* MEMORY_UTIL:0x58a6 */
int16_t FLookupPlanet(int16_t, PLANET *);  /* MEMORY_UTIL:0x04a6 */
FLEET * LpflNewSplit(FLEET *);  /* RETFAR */  /* MEMORY_UTIL:0x3372 */
uint16_t WFromLpfl(FLEET *);  /* MEMORY_UTIL:0x2b10 */
int16_t FLookupObject(int16_t, int16_t, void *);  /* MEMORY_UTIL:0x24a0 */
int16_t GetFleetScannerRange(FLEET *, int16_t *, int16_t *, int16_t *);  /* MEMORY_UTIL:0x4fb8 */
int16_t FFindNearestObject(POINT, int16_t, SCAN *);  /* MEMORY_UTIL:0x4070 */

#endif /* UTIL_H_ */
