#ifndef SAVE_H_
#define SAVE_H_

#include "file.h"
#include "globals.h"
#include "types.h"

/* functions */
void    WriteRt(int16_t rt, int16_t cb, void *rg);                            /* MEMORY_IO:0x947c */
void    WriteRtString(char *lpsz);                                            /* MEMORY_IO:0x87b4 */
void    WriteBOF(int16_t iPlayer, int16_t dt, int16_t fMulti);                /* MEMORY_IO:0x8ea4 */
void    WriteRtShDef(SHDEF *lpshdef, uint8_t **ppbStore);                     /* MEMORY_IO:0x574e */
void    WriteBattles(int16_t iPlayer);                                        /* MEMORY_IO:0x709c */
void    WriteFleet(FLEET *lpfl);                                              /* MEMORY_IO:0x81c6 */
void    WriteOrders(FLEET *lpfl);                                             /* MEMORY_IO:0x547e */
void    RgToStream(const void *rg, uint16_t cb);                                    /* MEMORY_IO:0x9554 */
void    SetSzWorkFromDt(DtFileType dt, int16_t iPlayer);                      /* MEMORY_IO:0x8cfe */
int16_t FMarkFile(DtFileType dt, int16_t iPlayer, int16_t mdMark, int16_t f); /* MEMORY_IO:0x904a */
void    SetVisPFInit(int16_t iPlr);                                           /* MEMORY_IO:0x9654 */
void    WriteBattlePlan(BTLPLAN *lpbtlplan, int16_t fLog);                    /* MEMORY_IO:0x89b8 */
int16_t FWriteDataFile(char *pszFileBase, int16_t iPlayer, int16_t fAppend);  /* MEMORY_IO:0x5964 */
int16_t FAppendFile(int16_t iPlayer);                                         /* MEMORY_IO:0x704e */
void    SetVisPFFinish(int16_t iPlr);                                         /* MEMORY_IO:0xc41c */
int16_t FCreateFile(DtFileType dt, int16_t iPlayer, char *szForceName);       /* MEMORY_IO:0x8e16 */
void    SetVisPFPlanets(int16_t iPlr);                                        /* MEMORY_IO:0xabde */
void    SetVisPFFleets(int16_t iPlr);                                         /* MEMORY_IO:0xa100 */
void    WritePlanet(PLANET *lppl, int16_t rt, int16_t fHistory);              /* MEMORY_IO:0x7a6a */
void    MarkFleet(FLEET *lpfl, int16_t det);                                  /* MEMORY_IO:0x885e */
void    MarkPlanet(PLANET *lppl, int16_t iPlr, uint16_t det);                 /* MEMORY_IO:0x8adc */
void    SetVisPFThings(int16_t iPlr);                                         /* MEMORY_IO:0xb9ee */
void    WriteRtPlr(PLAYER *pplr, uint8_t *pbStore);                           /* MEMORY_IO:0x551c */
void    SetVisiblePlanFleet(int16_t iPlr);                                    /* MEMORY_IO:0x95bc */

#endif /* SAVE_H_ */
