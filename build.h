#ifndef BUILD_H_
#define BUILD_H_

#include "types.h"

/* globals */
extern uint16_t rghstCat[14];      /* MEMORY_BUILD:0x0000 */
extern int16_t rgidsCat[14];       /* MEMORY_BUILD:0x001c */
extern uint16_t rggrbitParts[13];  /* MEMORY_BUILD:0x0038 */
extern int16_t rgidsParts[13];     /* MEMORY_BUILD:0x0052 */
extern uint16_t rggrbitPartsSB[8]; /* MEMORY_BUILD:0x006c */
extern int16_t rgidsPartsSB[8];    /* MEMORY_BUILD:0x007c */

/* functions */
void KillQueuedMassPackets(PLANET *lppl);          /* MEMORY_BUILD:0x6a52 */
int16_t IEmptyBmpFromGrhst(HullSlotType grhst);    /* MEMORY_BUILD:0x6716 */
SHDEF *NthValidShdef(int16_t n); /* RETFAR */      /* MEMORY_BUILD:0x5c06 */
SHDEF *NthValidEnemyShdef(int16_t n); /* RETFAR */ /* MEMORY_BUILD:0x5cf4 */
int16_t PctJammerFromHul(HUL *lphul);              /* MEMORY_BUILD:0x42e6 */
void MakeNewName(char *lpsz);                      /* MEMORY_BUILD:0x694c */
void KillQueuedShips(PLANET *lppl);                /* MEMORY_BUILD:0x6c2a */

#ifdef _WIN32

INT_PTR CALLBACK SlotDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_BUILD:0x0550 */
LRESULT CALLBACK FakeListProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);         /* MEMORY_BUILD:0x6758 */

int16_t FCheckQueuedShip(HWND hwnd, SHDEF *lpshdef, int16_t fEdit);                                    /* MEMORY_BUILD:0x027c */
void DrawDlgLBEntireItem(DRAWITEMSTRUCT *lpdis, int16_t inflate);                                      /* MEMORY_BUILD:0x59f0 */
void DrawBuildSelHull(HWND hwnd, HDC hdc, int16_t iDraw, RECT *prc);                                   /* MEMORY_BUILD:0x451e */
int16_t ShipBuilder(POINT ptDlgSize);                                                                  /* MEMORY_BUILD:0x008c */
void DrawBuildSelComp(HWND hwnd, HDC hdc, int16_t iDraw);                                              /* MEMORY_BUILD:0x3ab2 */
void DrawSlotDlg(HWND hwnd, HDC hdc, RECT *prc, int16_t iDraw);                                        /* MEMORY_BUILD:0x2650 */
void ShowMainControls(HWND hwnd, int16_t sw);                                                          /* MEMORY_BUILD:0x0160 */
void FillBuildDD(HWND hwndDD, int16_t md);                                                             /* MEMORY_BUILD:0x5e80 */
int16_t IDropPart(POINT pt, HS hsSrc, int16_t iSrc, int16_t fNoModify);                                /* MEMORY_BUILD:0x5476 */
void FillBuildPartsLB(HWND hwndLB, int16_t grbit);                                                     /* MEMORY_BUILD:0x63e8 */
void UpdateSlotGlobals(void);                                                                          /* MEMORY_BUILD:0x6528 */
int16_t FTrackSlot(HWND hwnd, int16_t x, int16_t y, int16_t fkb, int16_t fListBox, int16_t fRightBtn); /* MEMORY_BUILD:0x306a */
void SetBuildSelection(int16_t iSrc);                                                                  /* MEMORY_BUILD:0x53da */

#endif /* _WIN32 */
#endif /* BUILD_H_ */
