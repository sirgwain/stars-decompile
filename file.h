#ifndef FILE_H_
#define FILE_H_


#include "types.h"

/* functions */
void FileError(int16_t);  /* MEMORY_IO:0x4a10 */
void StreamOpen(char *, int16_t);  /* MEMORY_IO:0x52ae */
void UnpackBattlePlan(uint8_t *, BTLPLAN *, int16_t);  /* MEMORY_IO:0x40ce */
int16_t FBadFileError(int16_t);  /* MEMORY_IO:0x524e */
void ReadRtPlr(PLAYER *, uint8_t *);  /* MEMORY_IO:0x05e2 */
void UpdateBattleRecords(void);  /* MEMORY_IO:0x41ac */
int16_t FReadFleet(FLEET *);  /* MEMORY_IO:0x3a4c */
int16_t FLoadGame(char *, char *);  /* MEMORY_IO:0x0810 */
int16_t FReadShDef(RTSHDEF *, SHDEF *, int16_t);  /* MEMORY_IO:0x0006 */
void ReadRt(void);  /* MEMORY_IO:0x5168 */
int16_t FOpenFile(uint16_t, int16_t, int16_t);  /* MEMORY_IO:0x4ac2 */
int16_t AskSaveDialog(void);  /* PASCAL */  /* MEMORY_IO:0x432a */
void StreamClose(void);  /* MEMORY_IO:0x53cc */
int16_t FNewTurnAvail(int16_t);  /* MEMORY_IO:0x4f22 */
void GetFileStatus(int16_t, int16_t);  /* MEMORY_IO:0x4a60 */
int16_t FReadPlanet(int16_t, PLANET *, int16_t, int16_t);  /* MEMORY_IO:0x3206 */
void PromptSaveGame(void);  /* MEMORY_IO:0x43ee */
int16_t FCheckFile(uint16_t, int16_t, uint16_t);  /* MEMORY_IO:0x4fb2 */
int16_t FValidSerialLong(uint32_t);  /* MEMORY_IO:0x48c4 */
void DestroyCurGame(void);  /* MEMORY_IO:0x44b0 */
void RgFromStream(void *, uint16_t);  /* MEMORY_IO:0x53f4 */
int16_t FBogusLong(uint32_t);  /* MEMORY_IO:0x484c */

#endif /* FILE_H_ */
