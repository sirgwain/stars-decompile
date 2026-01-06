#ifndef POPUP_H_
#define POPUP_H_


#include "types.h"

/* globals */
extern uint16_t mpimdgrbitBU[8];  /* MEMORY_POPUP:0x0138 */

/* functions */
int32_t PopupWndProc(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_POPUP:0x0000 */
int16_t PopupMenu(uint16_t, int16_t, int16_t, int16_t, int32_t *, char * *, int16_t, int16_t);  /* MEMORY_POPUP:0x136c */
void DrawPopup(uint16_t, uint16_t);  /* MEMORY_POPUP:0x01c0 */
POINT PtDisplayResourceInfo(uint16_t, int16_t, int16_t);  /* MEMORY_POPUP:0x3378 */
POINT PtDisplayPlanetStateInfo(uint16_t, int16_t);  /* MEMORY_POPUP:0x1938 */
void Popup(uint16_t, int16_t, int16_t);  /* MEMORY_POPUP:0x0c7c */
int16_t FIsPopupHullType(int16_t);  /* MEMORY_POPUP:0x0148 */
POINT PtDisplayString(uint16_t, int16_t, int16_t);  /* MEMORY_POPUP:0x355c */
POINT PtDisplayPlanetPopInfo(uint16_t, int16_t);  /* MEMORY_POPUP:0x228e */
POINT PtDisplayZipOrdInfo(uint16_t, int16_t, int16_t);  /* MEMORY_POPUP:0x2d66 */
POINT PtDisplayFactoryMineInfo(uint16_t, int16_t, int16_t);  /* MEMORY_POPUP:0x3110 */

#endif /* POPUP_H_ */
