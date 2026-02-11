#ifndef UTIL_H_
#define UTIL_H_

#include "strings.h"
#include "types.h"

/* globals */
extern uint8_t vrgbTachyon[18];
extern int32_t rgDSDivCnt[5];
extern int32_t rgDSDivCnt2[5];

#ifdef _WIN32

extern COLORREF rgcrDrawStars[5];
extern COLORREF rgcrDrawStars2a[5];
extern COLORREF rgcrDrawStars2b[5];

#endif /* _WIN32 */

/* functions */
int16_t  muldiv_i16(int16_t number, int16_t numer, int16_t denom);
char    *SzVersion(void); /* MEMORY_MAIN:0x1212 */
char    *PszGetLocName(GrobjClass grobj, int16_t id, int16_t x, int16_t y);
int16_t  FCanFleetUseStargates(FLEET *lpfl, POINT ptSrc, POINT ptDst);
FLEET   *LpflFromId(int16_t idFleet);  /* RETFAR */
PLANET  *LpplFromId(int16_t idPlanet); /* RETFAR */
THING   *LpthFromId(int16_t idth);     /* RETFAR */
int32_t  LCalcFuelGainFromRamScoops(FLEET *lpfl, int16_t iWarp, int32_t dTravel);
int16_t  IshdefPrimaryFromLpfl(FLEET *lpfl, int16_t *pcDiff);
int16_t  GetCachedFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal);
int16_t  FLookupSelShip(FLEET *pfl);
int16_t  FMatchTarget(FLEET *lpflTarget, int16_t mdTarget, int16_t fExact);
void     ClearFile(int16_t dt);
int32_t  LComputePower(SHDEF *lpshdef);
char    *PszGetFleetName(int16_t id);
char    *PszGetThingName(int16_t id);
int32_t  LongFromSerialCh(char ch);
uint16_t WPackLong(int32_t l);
double   DGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2);
int16_t  FDeleteFleet(int16_t idFleet, int16_t grobjSel, int16_t idSel);
int32_t  WtFromLpfl(FLEET *lpfl);
void     SelectOursAtObject(POINT *ppt);
char    *PszGetPlanetName(int16_t id);
int16_t  FDupFleet(FLEET *lpfl, FLEET *pfl);
int16_t  FDupPlanet(PLANET *lppl, PLANET *ppl);
char    *PszFleetNameFromWord(uint16_t w);
int16_t  FValidSerialNo(char *psz, int32_t *plSerial);
char    *PszGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2);
void     CalcPctSurvive(PLANET *lppl, float *ppct, float *ppctSmart);
int16_t  IshFindSimilarDesign(HUL *lphul, int16_t iPlrDst);
void     DecorateHullName(int16_t iplr, int16_t ish, char *psz);
int16_t  FCanBuildShdef(SHDEF *lpshdef, int16_t iplr);
int16_t  FFleetMergeAll(FLEET *pfl);
int16_t  ICompFleetPoint2(void *arg1, void *arg2);
void     TurnLog(StringId ids);
char    *PszPlayerName(int16_t iPlayer, int16_t fCapital, int16_t fPlural, int16_t fThe, int16_t grWord, PLAYER *pplr);
int16_t  IStargateFromLppl(PLANET *lppl);
int32_t  DpOfLpflIshdef(FLEET *lpfl, int16_t ishdef);
int16_t  FFleetSplitAll(FLEET *pfl);
int16_t  ICompFleetPoint(void *arg1, void *arg2);
void     OutputSz(int16_t dt, char *sz);
void     ComputeShdefPowers(void);
int16_t  GetPlanetScannerRange(PLANET *lppl, int16_t *pDeep);
FLEET   *LpflNew(int16_t iPlr, int16_t idPl); /* RETFAR */
void     UpdateShdefCost(SHDEF *lpshdef);
int16_t  FLookupSelPlanet(PLANET *ppl);
int16_t  FLookupThing(int16_t idth, THING *pth);
int16_t  FLookupFleet(int16_t idFleet, FLEET *pfl);
int16_t  FLookupOrbitingXfer(int16_t idPlanet, int16_t iNth, XFER *pxf, int16_t idSkip);
void     LinkFleets(int16_t fUnused);
int16_t  FCalcFleetBombDamage(FLEET *lpfl, int32_t *pdmgPeople, int32_t *pdmgPeopleMin, int32_t *pdmgPeopleSmart, int32_t *pdmgBldg, int32_t *ppctTerra,
                              int16_t *pfMulti);
int16_t  IflFromLpfl(FLEET *lpfl);
int32_t  DpShieldOfShdef(SHDEF *lpshdef, int16_t iplr);
void     GetTrueHullCost(int16_t iPlayer, HUL *lphul, uint16_t *rgCost);
int16_t  GetShdefScannerRange(SHDEF *lpshdef, int16_t iplr, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal);
void     ValidateWaypoints(void);
int32_t  ChgPopFromPlanet(PLANET *lppl, int16_t fUpdate);
int16_t  FFleetCanJumpgate(FLEET *lpfl);
int32_t  CalcPlayerScore(int16_t iPlr, SCORE *pscore);
int16_t  FLookupPlanet(int16_t iPlanet, PLANET *ppl);
FLEET   *LpflNewSplit(FLEET *pfl); /* RETFAR */
uint16_t WFromLpfl(FLEET *lpfl);
int16_t  FLookupObject(GrobjClass grobj, int16_t id, void *pobj);
int16_t  GetFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal);
int16_t  FFindNearestObject(STARSPOINT pt, GrobjClass grobj, SCAN *pscan);

#ifdef _WIN32

int16_t CchGetETA(HDC hdc, FLEET *lpfl, char *sz, int16_t iwp, int16_t fSmall);

// randomly draws stores if screen colors < 8! :)
void DrawABunchOfStars(HDC hdc, RECT *prc);
void DrawPlanetPrintDot(HDC hdc, int16_t x, int16_t y, int16_t iSize);

#endif /* _WIN32 */

#endif /* UTIL_H_ */
