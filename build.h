#ifndef BUILD_H_
#define BUILD_H_

#include "types.h"

/* globals */
extern uint16_t rghstCat[14];
extern int16_t  rgidsCat[14];
extern uint16_t rggrbitParts[13];
extern int16_t  rgidsParts[13];
extern uint16_t rggrbitPartsSB[8];
extern int16_t  rgidsPartsSB[8];

/* functions */
void    KillQueuedMassPackets(PLANET *lppl);
int16_t IEmptyBmpFromGrhst(HullSlotType grhst);
SHDEF  *NthValidShdef(int16_t n);      /* RETFAR */
SHDEF  *NthValidEnemyShdef(int16_t n); /* RETFAR */
int16_t PctJammerFromHul(HUL *lphul);
void    MakeNewName(char *lpsz);
void    KillQueuedShips(PLANET *lppl);

#ifdef _WIN32

INT_PTR CALLBACK SlotDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */
LRESULT CALLBACK FakeListProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

int16_t FCheckQueuedShip(HWND hwnd, SHDEF *lpshdef, int16_t fEdit);
void    DrawDlgLBEntireItem(DRAWITEMSTRUCT *lpdis, int16_t inflate);
void    DrawBuildSelHull(HWND hwnd, HDC hdc, int16_t iDraw, RECT *prc);
int16_t ShipBuilder(POINT ptDlgSize);
void    DrawBuildSelComp(HWND hwnd, HDC hdc, int16_t iDraw);
void    DrawSlotDlg(HWND hwnd, HDC hdc, RECT *prc, int16_t iDraw);
void    ShowMainControls(HWND hwnd, int16_t sw);
void    FillBuildDD(HWND hwndDD, int16_t md);
int16_t IDropPart(POINT pt, HS hsSrc, int16_t iSrc, int16_t fNoModify);
void    FillBuildPartsLB(HWND hwndLB, int16_t grbit);
void    UpdateSlotGlobals(void);
int16_t FTrackSlot(HWND hwnd, int16_t x, int16_t y, int16_t fkb, int16_t fListBox, int16_t fRightBtn);
void    SetBuildSelection(int16_t iSrc);

#endif /* _WIN32 */
#endif /* BUILD_H_ */
