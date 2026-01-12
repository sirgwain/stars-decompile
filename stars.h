#ifndef STARS_H_
#define STARS_H_

#include "types.h"

/* functions */
int16_t FSetUpBatchProcessing(void);   /* MEMORY_MAIN:0x06a4 */
int16_t IPlrAlsoCheater(int16_t iplr); /* MEMORY_MAIN:0x07aa */

#ifdef _WIN32
int16_t FGetSystemColors(void);                                                                      /* MEMORY_MAIN:0x08d2 */
int16_t About(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam); /* PASCAL */        /* MEMORY_MAIN:0x1252 */
int16_t OrderInfoDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam); /* PASCAL */ /* MEMORY_MAIN:0x151e */
int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine,
                   int nShowCmd);
/* PASCAL */                                                                /* MEMORY_MAIN:0x0000 */
void FreeStuff(void);                                                       /* MEMORY_MAIN:0x0bae */
int16_t FHandleKey(uint16_t hwnd, int16_t iMsg, int16_t iKey, uint32_t dw); /* MEMORY_MAIN:0x165a */
int16_t FHandleChar(uint16_t hwnd, uint16_t ch, int32_t lParam);            /* MEMORY_MAIN:0x15de */
#endif                                                                      /* _WIN32 */
#endif                                                                      /* STARS_H_ */
