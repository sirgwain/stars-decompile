#ifndef POPUP_H_
#define POPUP_H_

#include "types.h"

#ifdef _WIN32

/* globals */
extern uint16_t mpimdgrbitBU[8]; /* MEMORY_POPUP:0x0138 */

/* functions */
LRESULT CALLBACK PopupWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_POPUP:0x0000 */

int16_t PopupMenu(HWND hwnd, int16_t x, int16_t y, int16_t cString, int32_t *rgids, char **rgsz, int16_t iChecked, int16_t fRightBtn); /* MEMORY_POPUP:0x136c */
void DrawPopup(HWND hwnd, HDC hdc);                                                                                                    /* MEMORY_POPUP:0x01c0 */
POINT PtDisplayResourceInfo(HDC hdc, int16_t dx, int16_t fPrint);                                                                      /* MEMORY_POPUP:0x3378 */
POINT PtDisplayPlanetStateInfo(HDC hdc, int16_t fPrint);                                                                               /* MEMORY_POPUP:0x1938 */
void Popup(HWND hwnd, int16_t x, int16_t y);                                                                                           /* MEMORY_POPUP:0x0c7c */
int16_t FIsPopupHullType(int16_t ishdef);                                                                                              /* MEMORY_POPUP:0x0148 */
POINT PtDisplayString(HDC hdc, int16_t dx, int16_t fPrint);                                                                            /* MEMORY_POPUP:0x355c */
POINT PtDisplayPlanetPopInfo(HDC hdc, int16_t fPrint);                                                                                 /* MEMORY_POPUP:0x228e */
POINT PtDisplayZipOrdInfo(HDC hdc, int16_t xCtr, int16_t fPrint);                                                                      /* MEMORY_POPUP:0x2d66 */
POINT PtDisplayFactoryMineInfo(HDC hdc, int16_t dx, int16_t fPrint);                                                                   /* MEMORY_POPUP:0x3110 */

#endif /* _WIN32 */

#endif /* POPUP_H_ */
