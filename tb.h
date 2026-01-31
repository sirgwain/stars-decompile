#ifndef TB_H_
#define TB_H_

#include "strings.h"
#include "types.h"

/* globals */
extern char    vrgTBBtn[29];  /* MEMORY_TB:0x0000 */
extern int16_t vrgpctZoom[9]; /* MEMORY_TB:0x0da4 */

#ifdef _WIN32

/* functions */
LRESULT CALLBACK TbWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */      /* MEMORY_TB:0x001e */
LRESULT CALLBACK FakeComboProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */  /* MEMORY_TB:0x1d72 */
LRESULT CALLBACK FakeCEProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */     /* MEMORY_TB:0x1df0 */
LRESULT CALLBACK TooltipWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_TB:0x19e4 */

void    ShowTooltip(StringId ids, RECT *prc);                             /* MEMORY_TB:0x17ea */
void    DrawToolbar(HDC hdc, RECT *prc);                                  /* MEMORY_TB:0x06f0 */
int16_t DxOfBtn(int16_t itb);                                             /* MEMORY_TB:0x0bb2 */
void    DrawBitmapButton(HDC hdc, POINT pt, int16_t ibtn, int16_t fDown); /* MEMORY_TB:0x078c */
void    ExecuteButton(int16_t itb, int16_t fDown);                        /* MEMORY_TB:0x0db6 */
int16_t FIsButtonDown(int16_t itb);                                       /* MEMORY_TB:0x0c3a */
int16_t ItbFromPpt(POINT *ppt);                                           /* MEMORY_TB:0x0b12 */
void    TerminateToolbarFocus(int16_t fCancel);                           /* MEMORY_TB:0x1680 */

#endif /* _WIN32 */

#endif /* TB_H_ */
