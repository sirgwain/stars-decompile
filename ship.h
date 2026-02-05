#ifndef SHIP_H_
#define SHIP_H_

#include "types.h"

/* functions */
int32_t GetFuelFree(FLEET *lpfl);
int32_t GetCargoFree(FLEET *lpfl);
int32_t XferSupply(int16_t iSupply, int32_t cQuan);
int16_t CshQueued(int16_t ishdef, int16_t *pfProgress, int16_t fSpaceDocks);
int32_t LGetFleetStat(FLEET *lpfl, GrStat grStat);
int16_t FCanSplitAll(int32_t cBoat);
int32_t EstFuelUse(FLEET *lpfl, int16_t iOrd, int16_t iWarp, int32_t dTravel, int16_t fRangeOnly);
void    DeleteCurWayPoint(int16_t fBackup);
int16_t TransferStuff(int16_t id1, int16_t grobj1, int16_t id2, int16_t grobj2, int16_t mdXfer);
void    Merge2Fleets(FLEET *lpflDst, FLEET *lpflDel, int16_t fNoDelete);
void    FleetTransferCargoBalance(FLEET *pflNew1, FLEET *pflNew2);
void    SelectAdjFleet(int16_t dInc, int16_t idFleet);
int16_t IFindIdealWarp(FLEET *lpfl, int16_t fIgnoreScoops);
void    DeleteWpFar(FLEET *lpfl, int16_t iDel, int16_t fRecycle);
int32_t ChgCargo(GrobjClass grobj, int16_t id, int16_t iSupply, int32_t dChg, void *pobj);
int16_t FCanSplit(int32_t cBoat);
int16_t FCanMerge(FLEET *pfl);
void    DestroyAllIshdef(int16_t ishdef, int16_t iplr);
int16_t WtMaxShdefStat(const SHDEF *lpshdef, GrStat grStat);
int16_t FEnumCalcJettison(void *lprt, RecordType rt, int16_t cb, PLANET *lppl, int16_t iFleet);
void    DestroyAllIshdefSB(int16_t ishdefSB, int16_t iplr);
void    GetTruePartCost(int16_t iPlayer, PART *ppart, uint16_t rgCosts[static 4]);
void    RemoveIshdefFromAllQueues(int16_t ishdef, int16_t fSpaceDocks);
int32_t LFuelUseToWaypoint(FLEET *lpfl, int16_t iwp, int16_t fMaxCargo);
void    FleetOrdersChangeTarget(FLEET *lpflOld);

#ifdef _WIN32

INT_PTR CALLBACK TransferDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK FakeEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void             ShipCommandProc(HWND hwnd, WPARAM wParam, LPARAM lParam);

void     UpdateOrdersDDs(int16_t iLevel);
void     SetFleetDropDownSel(int16_t id);
void     FillBattleDD(int16_t iSel);
void     SetOrdersLbSel(int16_t iSel);
void     FillFleetCompLB(void);
uint16_t ClickInShipOrders(POINT pt, int16_t sks, int16_t fCursor, int16_t fRightBtn);
void     UpdateXferBtns(void);
void     FillOrdersLB(void);

void    DrawShipOrders(HDC hdc, TILE *ptile, OBJ obj);
void    DrawFleetGauge(HDC hdc, RECT *prc, FLEET *lpfl, int16_t grbit);
void    DrawFleetCargoXferSide(HDC hdc, RECT *prc, FLEET *pfl, int16_t iSupply);
void    DrawThingXferSide(HDC hdc, RECT *prc, THING *pth, int16_t iSupply);
void    DrawShipWayPtOrders(HDC hdc, TILE *ptile, OBJ obj);
void    DrawXferDlg(HWND hwnd, HDC hdc, RECT *prc, int16_t iSupply);
void    DrawFleetShipsXferSide(HDC hdc, RECT *prc, FLEET *pfl, int16_t iSupply);
void    DrawShipPlanet(HDC hdc, TILE *ptile, OBJ obj);
void    DrawFleetComp(HDC hdc, TILE *ptile, OBJ obj);
void    DrawPlanetXferSide(HDC hdc, RECT *prc, PLANET *ppl, int16_t iSupply);
int16_t FTrackXfer(HWND hwnd, int16_t x, int16_t y, int16_t fkb);
int16_t FSetupXferBtns(RECT *prc);
void DrawFleetBitmap(FLEET *lpfl, HDC hdc, int16_t x, int16_t y, int16_t fFrame, int16_t ibmp, int16_t cDiff, int16_t fShrink, int16_t ibmpRace, int16_t csh);
void DrawShipCargo(HDC hdc, TILE *ptile, OBJ obj);
void GetXferLeftRightRcs(RECT *prcWhole, RECT *prcLeft, RECT *prcRight);

#endif /* _WIN32 */

#endif /* SHIP_H_ */
