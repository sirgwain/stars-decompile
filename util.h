#ifndef UTIL_H_
#define UTIL_H_

#include "types.h"
#include "strings.h"

/* globals */
extern uint8_t vrgbTachyon[18]; /* MEMORY_UTIL:0x50be */
extern int32_t rgDSDivCnt[5];   /* MEMORY_UTIL:0x5f7e */
extern int32_t rgDSDivCnt2[5];  /* MEMORY_UTIL:0x5fa6 */

#ifdef _WIN32

extern COLORREF rgcrDrawStars[5];   /* MEMORY_UTIL:0x5f92 */
extern COLORREF rgcrDrawStars2a[5]; /* MEMORY_UTIL:0x5fba */
extern COLORREF rgcrDrawStars2b[5]; /* MEMORY_UTIL:0x5fce */

#endif /* _WIN32 */

/* functions */
char *SzVersion(void);                                                                                                                                                     /* MEMORY_MAIN:0x1212 */
char *PszGetLocName(GrobjClass grobj, int16_t id, int16_t x, int16_t y);                                                                                                   /* MEMORY_UTIL:0x3b08 */
int16_t FCanFleetUseStargates(FLEET *lpfl, POINT ptSrc, POINT ptDst);                                                                                                      /* MEMORY_UTIL:0x75e2 */
FLEET *LpflFromId(int16_t idFleet); /* RETFAR */                                                                                                                           /* MEMORY_UTIL:0x2078 */
PLANET *LpplFromId(int16_t idPlanet); /* RETFAR */                                                                                                                         /* MEMORY_UTIL:0x021e */
THING *LpthFromId(int16_t idth); /* RETFAR */                                                                                                                              /* MEMORY_UTIL:0x01b2 */
int32_t LCalcFuelGainFromRamScoops(FLEET *lpfl, int16_t iWarp, int32_t dTravel);                                                                                           /* MEMORY_UTIL:0x56b8 */
int16_t IshdefPrimaryFromLpfl(FLEET *lpfl, int16_t *pcDiff);                                                                                                               /* MEMORY_UTIL:0x3e1c */
int16_t GetCachedFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal);                                                              /* MEMORY_UTIL:0x4e02 */
int16_t FLookupSelShip(FLEET *pfl);                                                                                                                                        /* MEMORY_UTIL:0x2032 */
int16_t FMatchTarget(FLEET *lpflTarget, int16_t mdTarget, int16_t fExact);                                                                                                 /* MEMORY_UTIL:0x6612 */
void ClearFile(int16_t dt);                                                                                                                                                /* MEMORY_UTIL:0x7f6a */
int32_t LComputePower(SHDEF *lpshdef);                                                                                                                                     /* MEMORY_UTIL:0x0b32 */
char *PszGetFleetName(int16_t id);                                                                                                                                         /* MEMORY_UTIL:0x292c */
char *PszGetThingName(int16_t id);                                                                                                                                         /* MEMORY_UTIL:0x26de */
int32_t LongFromSerialCh(char ch);                                                                                                                                         /* MEMORY_UTIL:0x6280 */
uint16_t WPackLong(int32_t l);                                                                                                                                             /* MEMORY_UTIL:0x4ba2 */
double DGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2);                                                                                                       /* MEMORY_UTIL:0x3fe4 */
int16_t FDeleteFleet(int16_t idFleet, int16_t grobjSel, int16_t idSel);                                                                                                    /* MEMORY_UTIL:0x2d44 */
int32_t WtFromLpfl(FLEET *lpfl);                                                                                                                                           /* MEMORY_UTIL:0x7a68 */
void SelectOursAtObject(POINT *ppt);                                                                                                                                       /* MEMORY_UTIL:0x08f2 */
char *PszGetPlanetName(int16_t id);                                                                                                                                        /* MEMORY_UTIL:0x2c6a */
int16_t FDupFleet(FLEET *lpfl, FLEET *pfl);                                                                                                                                /* MEMORY_UTIL:0x2332 */
int16_t FDupPlanet(PLANET *lppl, PLANET *ppl);                                                                                                                             /* MEMORY_UTIL:0x0032 */
char *PszFleetNameFromWord(uint16_t w);                                                                                                                                    /* MEMORY_UTIL:0x2b5e */
int16_t FValidSerialNo(char *psz, int32_t *plSerial);                                                                                                                      /* MEMORY_UTIL:0x62f8 */
char *PszGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2);                                                                                                      /* MEMORY_UTIL:0x3f00 */
void CalcPctSurvive(PLANET *lppl, float *ppct, float *ppctSmart);                                                                                                          /* MEMORY_UTIL:0x02f6 */
int16_t IshFindSimilarDesign(HUL *lphul, int16_t iPlrDst);                                                                                                                 /* MEMORY_UTIL:0x7c5e */
void DecorateHullName(int16_t iplr, int16_t ish, char *psz);                                                                                                               /* MEMORY_UTIL:0x5e0e */
int16_t FCanBuildShdef(SHDEF *lpshdef, int16_t iplr);                                                                                                                      /* MEMORY_UTIL:0x7b40 */
int16_t FFleetMergeAll(FLEET *pfl);                                                                                                                                        /* MEMORY_UTIL:0x34d8 */
int16_t ICompFleetPoint2(void *arg1, void *arg2);                                                                                                                          /* MEMORY_UTIL:0x1fa2 */
void TurnLog(StringId ids);                                                                                                                                                /* MEMORY_UTIL:0x80c2 */
char *PszPlayerName(int16_t iPlayer, int16_t fCapital, int16_t fPlural, int16_t fThe, int16_t grWord, PLAYER *pplr);                                                       /* MEMORY_UTIL:0x11f2 */
int16_t IStargateFromLppl(PLANET *lppl);                                                                                                                                   /* MEMORY_UTIL:0x10fa */
int32_t DpOfLpflIshdef(FLEET *lpfl, int16_t ishdef);                                                                                                                       /* MEMORY_UTIL:0x0746 */
int16_t FFleetSplitAll(FLEET *pfl);                                                                                                                                        /* MEMORY_UTIL:0x3a00 */
int16_t ICompFleetPoint(void *arg1, void *arg2);                                                                                                                           /* MEMORY_UTIL:0x1f0c */
void OutputSz(int16_t dt, char *sz);                                                                                                                                       /* MEMORY_UTIL:0x7fe6 */
void ComputeShdefPowers(void);                                                                                                                                             /* MEMORY_UTIL:0x0e4e */
int16_t GetPlanetScannerRange(PLANET *lppl, int16_t *pDeep);                                                                                                               /* MEMORY_UTIL:0x4c02 */
FLEET *LpflNew(int16_t iPlr, int16_t idPl); /* RETFAR */                                                                                                                   /* MEMORY_UTIL:0x300c */
void UpdateShdefCost(SHDEF *lpshdef);                                                                                                                                      /* MEMORY_UTIL:0x47b0 */
int16_t FLookupSelPlanet(PLANET *ppl);                                                                                                                                     /* MEMORY_UTIL:0x0000 */
int16_t FLookupThing(int16_t idth, THING *pth);                                                                                                                            /* MEMORY_UTIL:0x07fe */
int16_t FLookupFleet(int16_t idFleet, FLEET *pfl);                                                                                                                         /* MEMORY_UTIL:0x2160 */
int16_t FLookupOrbitingXfer(int16_t idPlanet, int16_t iNth, XFER *pxf, int16_t idSkip);                                                                                    /* MEMORY_UTIL:0x24fa */
void LinkFleets(int16_t fUnused);                                                                                                                                          /* MEMORY_UTIL:0x1bb4 */
int16_t FCalcFleetBombDamage(FLEET *lpfl, int32_t *pdmgPeople, int32_t *pdmgPeopleMin, int32_t *pdmgPeopleSmart, int32_t *pdmgBldg, int32_t *ppctTerra, int16_t *pfMulti); /* MEMORY_UTIL:0x145c */
int16_t IflFromLpfl(FLEET *lpfl);                                                                                                                                          /* MEMORY_UTIL:0x2ce8 */
int32_t DpShieldOfShdef(SHDEF *lpshdef, int16_t iplr);                                                                                                                     /* MEMORY_UTIL:0x0f24 */
void GetTrueHullCost(int16_t iPlayer, HUL *lphul, uint16_t *rgCost);                                                                                                       /* MEMORY_UTIL:0x5dba */
int16_t GetShdefScannerRange(SHDEF *lpshdef, int16_t iplr, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal);                                                   /* MEMORY_UTIL:0x50d0 */
void ValidateWaypoints(void);                                                                                                                                              /* MEMORY_UTIL:0x68c6 */
int32_t ChgPopFromPlanet(PLANET *lppl, int16_t fUpdate);                                                                                                                   /* MEMORY_UTIL:0x7082 */
int16_t FFleetCanJumpgate(FLEET *lpfl);                                                                                                                                    /* MEMORY_UTIL:0x7960 */
int32_t CalcPlayerScore(int16_t iPlr, SCORE *pscore);                                                                                                                      /* MEMORY_UTIL:0x58a6 */
int16_t FLookupPlanet(int16_t iPlanet, PLANET *ppl);                                                                                                                       /* MEMORY_UTIL:0x04a6 */
FLEET *LpflNewSplit(FLEET *pfl); /* RETFAR */                                                                                                                              /* MEMORY_UTIL:0x3372 */
uint16_t WFromLpfl(FLEET *lpfl);                                                                                                                                           /* MEMORY_UTIL:0x2b10 */
int16_t FLookupObject(GrobjClass grobj, int16_t id, void *pobj);                                                                                                           /* MEMORY_UTIL:0x24a0 */
int16_t GetFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal);                                                                    /* MEMORY_UTIL:0x4fb8 */
int16_t FFindNearestObject(POINT pt, GrobjClass grobj, SCAN *pscan);                                                                                                       /* MEMORY_UTIL:0x4070 */

#ifdef _WIN32

int16_t CchGetETA(HDC hdc, FLEET *lpfl, char *sz, int16_t iwp, int16_t fSmall); /* MEMORY_UTIL:0x3bc8 */

// randomly draws stores if screen colors < 8! :)
void DrawABunchOfStars(HDC hdc, RECT *prc);                            /* MEMORY_UTIL:0x5fe2 */
void DrawPlanetPrintDot(HDC hdc, int16_t x, int16_t y, int16_t iSize); /* MEMORY_UTIL:0x7e44 */

#endif /* _WIN32 */

#endif /* UTIL_H_ */
