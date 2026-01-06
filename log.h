#ifndef LOG_H_
#define LOG_H_


#include "types.h"

/* functions */
void WriteMemRt(int16_t, int16_t, void *);  /* MEMORY_PLANET:0xa130 */
int16_t FWriteLogFile(char *, int16_t);  /* MEMORY_PLANET:0xcdf6 */
void LogMergeFleet(int16_t);  /* MEMORY_PLANET:0x8b6c */
int16_t FLoadLogFile(char *);  /* MEMORY_PLANET:0xc7a2 */
void DirtyGame(int16_t);  /* MEMORY_PLANET:0xa228 */
void LogSplitFleet(int16_t);  /* MEMORY_PLANET:0x8b0e */
int16_t FWriteTutorialMFile(int16_t);  /* MEMORY_PLANET:0xd058 */
void EnumLogRts(int16_t (*)(void *, int16_t, int16_t, void *, int16_t), void *, int16_t);  /* MEMORY_PLANET:0xd6e0 */
int16_t FGetPrevLogRt(HDR *, uint8_t *);  /* MEMORY_PLANET:0xa25e */
void LogChangeThing(THING *, THING *);  /* MEMORY_PLANET:0x9908 */
void LogChangePlanet(PLANET *, PLANET *);  /* MEMORY_PLANET:0x9420 */
int16_t FCheckLogFile(int16_t, int16_t *);  /* MEMORY_PLANET:0xcccc */
void LogChangeBtlplan(BTLPLAN *);  /* MEMORY_PLANET:0x93d0 */
void LogChangeRelations(void);  /* MEMORY_PLANET:0x9340 */
int16_t FRunLogRecord(int16_t, int16_t, uint8_t *);  /* MEMORY_PLANET:0xa38c */
int16_t FWriteHistFile(int16_t);  /* MEMORY_PLANET:0xd29e */
void CancelMemRt(int16_t);  /* MEMORY_PLANET:0xa108 */
void LogMakeValidXferf(LOGXFERF *, LOGXFERF *);  /* MEMORY_PLANET:0x9fa6 */
int16_t FRunLogFile(void);  /* MEMORY_PLANET:0xa2d6 */
void LogMakeValidXfer(LOGXFER *, LOGXFER *);  /* MEMORY_PLANET:0x99f6 */
void LogChangeFleet(FLEET *, FLEET *);  /* MEMORY_PLANET:0x8ebe */
void LogChangeName(int16_t, int16_t, char *);  /* MEMORY_PLANET:0x8d5a */
void LogChangeShDef(SHDEF *);  /* MEMORY_PLANET:0x8c28 */

#endif /* LOG_H_ */
