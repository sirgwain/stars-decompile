#ifndef STARS_H_
#define STARS_H_


#include "types.h"

/* functions */
int16_t About(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_MAIN:0x1252 */
int16_t FSetUpBatchProcessing(void);  /* MEMORY_MAIN:0x06a4 */
int16_t FGetSystemColors(void);  /* MEMORY_MAIN:0x08d2 */
int16_t OrderInfoDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_MAIN:0x151e */
int16_t IPlrAlsoCheater(int16_t);  /* MEMORY_MAIN:0x07aa */
int16_t WinMain(uint16_t, uint16_t, char *, int16_t);  /* PASCAL */  /* MEMORY_MAIN:0x0000 */
void FreeStuff(void);  /* MEMORY_MAIN:0x0bae */
int16_t FHandleKey(uint16_t, int16_t, int16_t, uint32_t);  /* MEMORY_MAIN:0x165a */
char * SzVersion(void);  /* MEMORY_MAIN:0x1212 */
int16_t FHandleChar(uint16_t, uint16_t, int32_t);  /* MEMORY_MAIN:0x15de */

#endif /* STARS_H_ */
