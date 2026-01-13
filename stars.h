#ifndef STARS_H_
#define STARS_H_

#include "types.h"

/* functions */
int16_t FSetUpBatchProcessing(void);   /* MEMORY_MAIN:0x06a4 */
int16_t IPlrAlsoCheater(int16_t iplr); /* MEMORY_MAIN:0x07aa */

#ifdef _WIN32

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd); /* MEMORY_MAIN:0x0000 */

INT_PTR CALLBACK About(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */        /* MEMORY_MAIN:0x1252 */
INT_PTR CALLBACK OrderInfoDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_MAIN:0x151e */

int16_t FGetSystemColors(void);                                         /* MEMORY_MAIN:0x08d2 */
void FreeStuff(void);                                                   /* MEMORY_MAIN:0x0bae */
int16_t FHandleKey(HWND hwnd, int16_t iMsg, int16_t iKey, uint32_t dw); /* MEMORY_MAIN:0x165a */
int16_t FHandleChar(HWND hwnd, uint16_t ch, LPARAM lParam);             /* MEMORY_MAIN:0x15de */

#endif /* _WIN32 */

#endif /* STARS_H_ */
