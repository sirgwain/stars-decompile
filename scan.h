#ifndef SCAN_H_
#define SCAN_H_


#include "types.h"

/* globals */
extern int16_t vrgPopRad[19];  /* MEMORY_SCAN:0x0000 */
extern uint32_t rgcrScanMine[3];  /* MEMORY_SCAN:0x0026 */

/* functions */
int16_t FindDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_SCAN:0x9286 */
void DrawScannerSBar(uint16_t, RECT *, SBAR *, int16_t);  /* MEMORY_SCAN:0x62d8 */
void DrawRadarCircle(DRAWCIR *, RECT *);  /* MEMORY_SCAN:0x4e7c */
int32_t ScannerWndProc(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_SCAN:0x0032 */
int16_t IWarpBestForWaypoint(FLEET *, ORDER *);  /* MEMORY_SCAN:0x7a18 */
void SetScanScrollBars(uint16_t);  /* MEMORY_SCAN:0x6c14 */
int32_t CShipsScanVis(FLEET *);  /* MEMORY_SCAN:0x4bf4 */
void DrawShipScanPath(uint16_t, int16_t);  /* MEMORY_SCAN:0x540c */
void GetScanFleetOrientation(FLEET *, POINT *, POINT *);  /* MEMORY_SCAN:0x978c */
int16_t PtToScan(int16_t);  /* MEMORY_SCAN:0x0efc */
int16_t ScanToPt(int16_t);  /* MEMORY_SCAN:0x0fc2 */
int16_t SetScanWp(int16_t);  /* MEMORY_SCAN:0x8c5a */
int16_t FAddWayPoint(POINT, SCAN *);  /* MEMORY_SCAN:0x7504 */
int16_t FSelectSz(char *);  /* MEMORY_SCAN:0x945a */
void GetDxDyOrientation(int16_t, int16_t, POINT *, POINT *);  /* MEMORY_SCAN:0x987c */
void ScanToLogical(POINT *);  /* MEMORY_SCAN:0x7490 */
void DrawLockLight(uint16_t, RECT *, int16_t);  /* MEMORY_SCAN:0x6b00 */
int16_t FGetNextObjHere(SCAN *, int16_t);  /* MEMORY_SCAN:0x909c */
int16_t FHandleMeasuringTape(SCAN *, POINT);  /* MEMORY_SCAN:0x9974 */
int16_t FEnsurePointOnScreen(POINT, int16_t);  /* MEMORY_SCAN:0x715c */
void ChangeScanSel(SCAN *, int16_t);  /* MEMORY_SCAN:0x8cc4 */
void RedrawScanSel(uint16_t, int16_t);  /* MEMORY_SCAN:0x6f30 */
int16_t FHandleWayPointDrag(POINT);  /* MEMORY_SCAN:0x8176 */
void LogicalToScan(POINT *);  /* MEMORY_SCAN:0x744e */
int16_t FNearAWayPoint(POINT, int16_t);  /* MEMORY_SCAN:0x8074 */
void ScrollScanner(int16_t, int16_t);  /* MEMORY_SCAN:0x6d30 */
void DrawScanFleetCount(FLEET *, int16_t, int16_t, uint16_t, uint16_t);  /* MEMORY_SCAN:0x47d2 */
int16_t DrawScanner(uint16_t, RECT *);  /* MEMORY_SCAN:0x108a */
void CtrPointScan(POINT, int16_t);  /* MEMORY_SCAN:0x7278 */
void DrawScanXorLines(uint16_t, POINT *, int16_t);  /* MEMORY_SCAN:0x8af6 */

#endif /* SCAN_H_ */
