#ifndef SHIP_H_
#define SHIP_H_


#include "types.h"

/* functions */
void UpdateOrdersDDs(int16_t);  /* MEMORY_SHIP:0x93ee */
void SetFleetDropDownSel(int16_t);  /* MEMORY_SHIP:0x400e */
int32_t GetFuelFree(FLEET *);  /* MEMORY_SHIP:0x6004 */
void ShipCommandProc(uint16_t, uint16_t, int32_t);  /* MEMORY_SHIP:0x2640 */
void DrawShipOrders(uint16_t, TILE *, OBJ);  /* MEMORY_SHIP:0x0000 */
int32_t GetCargoFree(FLEET *);  /* MEMORY_SHIP:0x5f98 */
int32_t XferSupply(int16_t, int32_t);  /* MEMORY_SHIP:0x64cc */
void DrawFleetGauge(uint16_t, RECT *, FLEET *, int16_t);  /* MEMORY_SHIP:0x44b6 */
int16_t CshQueued(int16_t, int16_t *, int16_t);  /* MEMORY_SHIP:0xc82c */
int32_t LGetFleetStat(FLEET *, int16_t);  /* MEMORY_SHIP:0x40f2 */
void FillBattleDD(int16_t);  /* MEMORY_SHIP:0x9a36 */
int16_t FCanSplitAll(int32_t);  /* MEMORY_SHIP:0x24ae */
int32_t EstFuelUse(FLEET *, int16_t, int16_t, int32_t, int16_t);  /* MEMORY_SHIP:0x9fe4 */
void DeleteCurWayPoint(int16_t);  /* MEMORY_SHIP:0x9b08 */
void DrawFleetCargoXferSide(uint16_t, RECT *, FLEET *, int16_t);  /* MEMORY_SHIP:0x72de */
int32_t FakeEditProc(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_SHIP:0xa700 */
int16_t TransferStuff(int16_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_SHIP:0x4faa */
void DrawThingXferSide(uint16_t, RECT *, THING *, int16_t);  /* MEMORY_SHIP:0x7088 */
void DrawShipWayPtOrders(uint16_t, TILE *, OBJ);  /* MEMORY_SHIP:0x0912 */
void Merge2Fleets(FLEET *, FLEET *, int16_t);  /* MEMORY_SHIP:0xc9f6 */
int16_t TransferDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_SHIP:0x5686 */
void DrawXferDlg(uint16_t, uint16_t, RECT *, int16_t);  /* MEMORY_SHIP:0x6908 */
void DrawFleetShipsXferSide(uint16_t, RECT *, FLEET *, int16_t);  /* MEMORY_SHIP:0x7726 */
void DrawShipPlanet(uint16_t, TILE *, OBJ);  /* MEMORY_SHIP:0x17b6 */
void DrawFleetComp(uint16_t, TILE *, OBJ);  /* MEMORY_SHIP:0x1e72 */
void FleetTransferCargoBalance(FLEET *, FLEET *);  /* MEMORY_SHIP:0xae74 */
void SetOrdersLbSel(int16_t);  /* MEMORY_SHIP:0x9354 */
void SelectAdjFleet(int16_t, int16_t);  /* MEMORY_SHIP:0x3d32 */
int16_t IFindIdealWarp(FLEET *, int16_t);  /* MEMORY_SHIP:0xa76e */
void DrawPlanetXferSide(uint16_t, RECT *, PLANET *, int16_t);  /* MEMORY_SHIP:0x79ca */
void DeleteWpFar(FLEET *, int16_t, int16_t);  /* MEMORY_SHIP:0x9e28 */
int32_t ChgCargo(int16_t, int16_t, int16_t, int32_t, void *);  /* MEMORY_SHIP:0x6034 */
int16_t FTrackXfer(uint16_t, int16_t, int16_t, int16_t);  /* MEMORY_SHIP:0x5a16 */
int16_t FCanSplit(int32_t);  /* MEMORY_SHIP:0x245c */
int16_t FCanMerge(FLEET *);  /* MEMORY_SHIP:0x2522 */
void FillFleetCompLB(void);  /* MEMORY_SHIP:0x9166 */
uint16_t ClickInShipOrders(POINT, int16_t, int16_t, int16_t);  /* MEMORY_SHIP:0x7cda */
void DestroyAllIshdef(int16_t, int16_t);  /* MEMORY_SHIP:0xc336 */
int16_t WtMaxShdefStat(SHDEF *, int16_t);  /* MEMORY_SHIP:0x41b2 */
int16_t FEnumCalcJettison(void *, int16_t, int16_t, PLANET *, int16_t);  /* MEMORY_SHIP:0x4df4 */
void UpdateXferBtns(void);  /* MEMORY_SHIP:0x66a8 */
int16_t FSetupXferBtns(RECT *);  /* MEMORY_SHIP:0x6bea */
void DrawFleetBitmap(FLEET *, uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_SHIP:0x490e */
void DestroyAllIshdefSB(int16_t, int16_t);  /* MEMORY_SHIP:0xc280 */
void GetTruePartCost(int16_t, PART *, uint16_t *);  /* MEMORY_SHIP:0xcd00 */
void RemoveIshdefFromAllQueues(int16_t, int16_t);  /* MEMORY_SHIP:0xc5e6 */
void DrawShipCargo(uint16_t, TILE *, OBJ);  /* MEMORY_SHIP:0x1a54 */
void FillOrdersLB(void);  /* MEMORY_SHIP:0x928c */
int32_t LFuelUseToWaypoint(FLEET *, int16_t, int16_t);  /* MEMORY_SHIP:0xa9f4 */
void FleetOrdersChangeTarget(FLEET *);  /* MEMORY_SHIP:0xcafe */
void GetXferLeftRightRcs(RECT *, RECT *, RECT *);  /* MEMORY_SHIP:0x6b46 */

#endif /* SHIP_H_ */
