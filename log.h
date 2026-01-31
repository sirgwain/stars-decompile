#ifndef LOG_H_
#define LOG_H_

#include "types.h"

/* functions */
void    WriteMemRt(int16_t rt, int16_t cb, void *rg);                                                       /* MEMORY_PLANET:0xa130 */
int16_t FWriteLogFile(char *pszFileBase, int16_t iPlayer);                                                  /* MEMORY_PLANET:0xcdf6 */
void    LogMergeFleet(int16_t id);                                                                          /* MEMORY_PLANET:0x8b6c */
int16_t FLoadLogFile(char *pszLog);                                                                         /* MEMORY_PLANET:0xc7a2 */
void    DirtyGame(int16_t fDirty);                                                                          /* MEMORY_PLANET:0xa228 */
void    LogSplitFleet(int16_t id);                                                                          /* MEMORY_PLANET:0x8b0e */
int16_t FWriteTutorialMFile(int16_t iTurn);                                                                 /* MEMORY_PLANET:0xd058 */
void    EnumLogRts(int16_t (*pfn)(void *, int16_t, int16_t, void *, int16_t), void *lpPass, int16_t iPass); /* MEMORY_PLANET:0xd6e0 */
int16_t FGetPrevLogRt(HDR *phdr, uint8_t *pb);                                                              /* MEMORY_PLANET:0xa25e */
void    LogChangeThing(THING *lpth, THING *pthNew);                                                         /* MEMORY_PLANET:0x9908 */
void    LogChangePlanet(PLANET *ppl, PLANET *pplNew);                                                       /* MEMORY_PLANET:0x9420 */
int16_t FCheckLogFile(int16_t iplr, int16_t *pfError);                                                      /* MEMORY_PLANET:0xcccc */
void    LogChangeBtlplan(BTLPLAN *pbtlplan);                                                                /* MEMORY_PLANET:0x93d0 */
void    LogChangeRelations(void);                                                                           /* MEMORY_PLANET:0x9340 */
int16_t FRunLogRecord(int16_t rt, int16_t cb, uint8_t *lpb);                                                /* MEMORY_PLANET:0xa38c */
int16_t FWriteHistFile(int16_t iPlayer);                                                                    /* MEMORY_PLANET:0xd29e */
void    CancelMemRt(int16_t rt);                                                                            /* MEMORY_PLANET:0xa108 */
void    LogMakeValidXferf(LOGXFERF *plxf1, LOGXFERF *plxf2);                                                /* MEMORY_PLANET:0x9fa6 */
int16_t FRunLogFile(void);                                                                                  /* MEMORY_PLANET:0xa2d6 */
void    LogMakeValidXfer(LOGXFER *plx1, LOGXFER *plx2);                                                     /* MEMORY_PLANET:0x99f6 */
void    LogChangeFleet(FLEET *pfl, FLEET *pflNew);                                                          /* MEMORY_PLANET:0x8ebe */
void    LogChangeName(GrobjClass grobj, int16_t id, char *szName);                                          /* MEMORY_PLANET:0x8d5a */
void    LogChangeShDef(SHDEF *lpshdefNew);                                                                  /* MEMORY_PLANET:0x8c28 */

#endif /* LOG_H_ */
