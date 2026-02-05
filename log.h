#ifndef LOG_H_
#define LOG_H_

#include "types.h"

/* functions */
void    WriteMemRt(RecordType rt, int16_t cb, void *rg);
int16_t FWriteLogFile(char *pszFileBase, int16_t iPlayer);
void    LogMergeFleet(int16_t id);
int16_t FLoadLogFile(char *pszLog);
void    DirtyGame(int16_t fDirty);
void    LogSplitFleet(int16_t id);
int16_t FWriteTutorialMFile(int16_t iTurn);
void    EnumLogRts(int16_t (*pfn)(void *, int16_t, int16_t, void *, int16_t), void *lpPass, int16_t iPass);
int16_t FGetPrevLogRt(HDR *phdr, uint8_t *pb);
void    LogChangeThing(THING *lpth, THING *pthNew);
void    LogChangePlanet(PLANET *ppl, PLANET *pplNew);
int16_t FCheckLogFile(int16_t iplr, int16_t *pfError);
void    LogChangeBtlplan(BTLPLAN *pbtlplan);
void    LogChangeRelations(void);
int16_t FRunLogRecord(RecordType rt, int16_t cb, uint8_t *lpb);
int16_t FWriteHistFile(int16_t iPlayer);
void    CancelMemRt(RecordType rt);
void    LogMakeValidXferf(LOGXFERF *plxf1, LOGXFERF *plxf2);
int16_t FRunLogFile(void);
void    LogMakeValidXfer(LOGXFER *plx1, LOGXFER *plx2);
void    LogChangeFleet(FLEET *pfl, FLEET *pflNew);
void    LogChangeName(GrobjClass grobj, int16_t id, char *szName);
void    LogChangeShDef(SHDEF *lpshdefNew);

#endif /* LOG_H_ */
