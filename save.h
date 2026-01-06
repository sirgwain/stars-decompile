#ifndef SAVE_H_
#define SAVE_H_


#include "types.h"

/* functions */
void WriteRt(int16_t, int16_t, void *);  /* MEMORY_IO:0x947c */
void WriteRtString(char *);  /* MEMORY_IO:0x87b4 */
void WriteBOF(int16_t, int16_t, int16_t);  /* MEMORY_IO:0x8ea4 */
void WriteRtShDef(SHDEF *, uint8_t * *);  /* MEMORY_IO:0x574e */
void WriteBattles(int16_t);  /* MEMORY_IO:0x709c */
void WriteFleet(FLEET *);  /* MEMORY_IO:0x81c6 */
void WriteOrders(FLEET *);  /* MEMORY_IO:0x547e */
void RgToStream(void *, uint16_t);  /* MEMORY_IO:0x9554 */
void SetSzWorkFromDt(uint16_t, int16_t);  /* MEMORY_IO:0x8cfe */
int16_t FMarkFile(uint16_t, int16_t, int16_t, int16_t);  /* MEMORY_IO:0x904a */
void SetVisPFInit(int16_t);  /* MEMORY_IO:0x9654 */
void WriteBattlePlan(BTLPLAN *, int16_t);  /* MEMORY_IO:0x89b8 */
int16_t FWriteDataFile(char *, int16_t, int16_t);  /* MEMORY_IO:0x5964 */
int16_t FAppendFile(int16_t);  /* MEMORY_IO:0x704e */
void SetVisPFFinish(int16_t);  /* MEMORY_IO:0xc41c */
int16_t FCreateFile(uint16_t, int16_t, char *);  /* MEMORY_IO:0x8e16 */
void SetVisPFPlanets(int16_t);  /* MEMORY_IO:0xabde */
void SetVisPFFleets(int16_t);  /* MEMORY_IO:0xa100 */
void WritePlanet(PLANET *, int16_t, int16_t);  /* MEMORY_IO:0x7a6a */
void MarkFleet(FLEET *, int16_t);  /* MEMORY_IO:0x885e */
void MarkPlanet(PLANET *, int16_t, uint16_t);  /* MEMORY_IO:0x8adc */
void SetVisPFThings(int16_t);  /* MEMORY_IO:0xb9ee */
void WriteRtPlr(PLAYER *, uint8_t *);  /* MEMORY_IO:0x551c */
void SetVisiblePlanFleet(int16_t);  /* MEMORY_IO:0x95bc */

#endif /* SAVE_H_ */
