#ifndef SCAN_H_
#define SCAN_H_

#include "types.h"

/* globals */
extern int16_t vrgPopRad[19]; /* MEMORY_SCAN:0x0000 */

int16_t IWarpBestForWaypoint(FLEET *lpfl, ORDER *lpord); /* MEMORY_SCAN:0x7a18 */

#ifdef _WIN32

extern COLORREF rgcrScanMine[3]; /* MEMORY_SCAN:0x0026 */

/* functions */
LRESULT CALLBACK ScannerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_SCAN:0x0032 */
INT_PTR CALLBACK FindDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);        /* MEMORY_SCAN:0x9286 */

void    DrawScannerSBar(HDC hdc, RECT *prc, SBAR *psbar, int16_t fFullRedraw);      /* MEMORY_SCAN:0x62d8 */
void    DrawRadarCircle(DRAWCIR *pdc, RECT *prc);                                   /* MEMORY_SCAN:0x4e7c */
void    SetScanScrollBars(HWND hwnd);                                               /* MEMORY_SCAN:0x6c14 */
int32_t CShipsScanVis(FLEET *lpfl);                                                 /* MEMORY_SCAN:0x4bf4 */
void    DrawShipScanPath(HDC hdc, int16_t fShow);                                   /* MEMORY_SCAN:0x540c */
void    GetScanFleetOrientation(FLEET *lpfl, POINT *ppt, POINT *pptD);              /* MEMORY_SCAN:0x978c */
int16_t PtToScan(int16_t d);                                                        /* MEMORY_SCAN:0x0efc */
int16_t ScanToPt(int16_t d);                                                        /* MEMORY_SCAN:0x0fc2 */
int16_t SetScanWp(int16_t iNew);                                                    /* MEMORY_SCAN:0x8c5a */
int16_t FAddWayPoint(POINT ptIn, SCAN *pscan);                                      /* MEMORY_SCAN:0x7504 */
int16_t FSelectSz(char *szName);                                                    /* MEMORY_SCAN:0x945a */
void    GetDxDyOrientation(int16_t dx, int16_t dy, POINT *ppt, POINT *pptD);        /* MEMORY_SCAN:0x987c */
void    ScanToLogical(POINT *ppt);                                                  /* MEMORY_SCAN:0x7490 */
void    DrawLockLight(HDC hdc, RECT *prc, int16_t fFullRedraw);                     /* MEMORY_SCAN:0x6b00 */
int16_t FGetNextObjHere(SCAN *pscan, int16_t fOnlyOurs);                            /* MEMORY_SCAN:0x909c */
int16_t FHandleMeasuringTape(SCAN *pscan, POINT pt);                                /* MEMORY_SCAN:0x9974 */
int16_t FEnsurePointOnScreen(POINT pt, int16_t fScroll);                            /* MEMORY_SCAN:0x715c */
void    ChangeScanSel(SCAN *pscan, int16_t fValidScan);                             /* MEMORY_SCAN:0x8cc4 */
void    RedrawScanSel(HDC hdc, int16_t fVis);                                       /* MEMORY_SCAN:0x6f30 */
int16_t FHandleWayPointDrag(POINT pt);                                              /* MEMORY_SCAN:0x8176 */
void    LogicalToScan(POINT *ppt);                                                  /* MEMORY_SCAN:0x744e */
int16_t FNearAWayPoint(POINT pt, int16_t fLogical);                                 /* MEMORY_SCAN:0x8074 */
void    ScrollScanner(int16_t dx, int16_t dy);                                      /* MEMORY_SCAN:0x6d30 */
void    DrawScanFleetCount(FLEET *lpfl, int16_t x, int16_t y, HDC hdc, HDC hdcMem); /* MEMORY_SCAN:0x47d2 */
int16_t DrawScanner(HDC hdc, RECT *prc);                                            /* MEMORY_SCAN:0x108a */
void    CtrPointScan(POINT pt, int16_t fScroll);                                    /* MEMORY_SCAN:0x7278 */
void    DrawScanXorLines(HDC hdc, POINT *rgpt, int16_t cpt);                        /* MEMORY_SCAN:0x8af6 */

#endif /* _WIN32 */

#endif /* SCAN_H_ */
