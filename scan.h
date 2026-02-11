#ifndef SCAN_H_
#define SCAN_H_

#include "types.h"

extern int16_t vrgPopRad[19];

int16_t IWarpBestForWaypoint(FLEET *lpfl, ORDER *lpord);
int16_t ScanToPt(int16_t d);

#ifdef _WIN32

extern COLORREF rgcrScanMine[3];

LRESULT CALLBACK ScannerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK FindDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

void    DrawScannerSBar(HDC hdc, RECT *prc, SBAR *psbar, int16_t fFullRedraw);
void    DrawRadarCircle(DRAWCIR *pdc, RECT *prc);
void    SetScanScrollBars(HWND hwnd);
int32_t CShipsScanVis(FLEET *lpfl);
void    DrawShipScanPath(HDC hdc, int16_t fShow);
void    GetScanFleetOrientation(FLEET *lpfl, POINT *ppt, POINT *pptD);
int16_t PtToScan(int16_t d);
int16_t SetScanWp(int16_t iNew);
int16_t FAddWayPoint(POINT ptIn, SCAN *pscan);
int16_t FSelectSz(char *szName);
void    GetDxDyOrientation(int16_t dx, int16_t dy, POINT *ppt, POINT *pptD);
void    ScanToLogical(POINT *ppt);
void    DrawLockLight(HDC hdc, RECT *prc, int16_t fFullRedraw);
int16_t FGetNextObjHere(SCAN *pscan, int16_t fOnlyOurs);
int16_t FHandleMeasuringTape(SCAN *pscan, POINT pt);
int16_t FEnsurePointOnScreen(POINT pt, int16_t fScroll);
void    ChangeScanSel(SCAN *pscan, int16_t fValidScan);
void    RedrawScanSel(HDC hdc, int16_t fVis);
int16_t FHandleWayPointDrag(POINT pt);
void    LogicalToScan(POINT *ppt);
int16_t FNearAWayPoint(POINT pt, int16_t fLogical);
void    ScrollScanner(int16_t dx, int16_t dy);
void    DrawScanFleetCount(FLEET *lpfl, int16_t x, int16_t y, HDC hdc, HDC hdcMem);
int16_t DrawScanner(HDC hdc, RECT *prc);
void    CtrPointScan(POINT pt, int16_t fScroll);
void    DrawScanXorLines(HDC hdc, POINT *rgpt, int16_t cpt);

#endif /* _WIN32 */

#endif /* SCAN_H_ */
