#ifndef PLANET_H_
#define PLANET_H_


#include "types.h"

/* functions */
void DrawPlanShip(uint16_t hdc, int16_t grbit);  /* MEMORY_PLANET:0x0d16 */
int16_t PctCloakFromHuldef(HUL *lphul, int16_t iplr, int16_t *ppctSteal);  /* MEMORY_PLANET:0x88c0 */
int16_t PctPlanetOptValue(PLANET *lppl, int16_t iPlr);  /* MEMORY_PLANET:0x6b88 */
int16_t IWarpMAFromLppl(PLANET *lppl, bool *pfTwo);  /* MEMORY_PLANET:0x7b10 */
void DrawPlanetStats(uint16_t hdc, TILE *ptile, OBJ obj);  /* MEMORY_PLANET:0x1716 */
int16_t FGetBestDefensePart(PART *ppart);  /* MEMORY_PLANET:0x21f6 */
void DrawPlanetShipList(uint16_t hdc, TILE *ptile, OBJ obj);  /* MEMORY_PLANET:0x377e */
void DrawPlanetStarbase(uint16_t hdc, TILE *ptile, OBJ obj);  /* MEMORY_PLANET:0x22cc */
int16_t PctPlanetDesirability(PLANET *lppl, int16_t iPlr);  /* MEMORY_PLANET:0x6e1e */
void DrawPlanetMinSum(uint16_t hdc, TILE *ptile, OBJ obj);  /* MEMORY_PLANET:0x12b2 */
int16_t CResourcesAtPlanet(PLANET *lppl, int16_t iplr);  /* MEMORY_PLANET:0x788e */
int16_t CMaxOperableDefenses(PLANET *lppl, int16_t iplr, int16_t fNextYear);  /* MEMORY_PLANET:0x77ae */
char * PszProductionETA(PLANET *lppl, PLPROD *lpplprod, int16_t iItem, int16_t *etaFirst, int16_t *etaLast);  /* MEMORY_PLANET:0x310c */
int16_t FCanTerraformLppl(PLANET *lppl, int16_t *rgEnvMin, int16_t *rgEnvMax, int16_t *rgEnvCost, int16_t fHelp);  /* MEMORY_PLANET:0x8022 */
void DrawCBEntireItem(DRAWITEMSTRUCT *lpdis, int16_t inflate);  /* MEMORY_PLANET:0x6128 */
char * PszCalcEnvVar(int16_t iEnv, int16_t iVar);  /* MEMORY_PLANET:0x5fcc */
int16_t CMaxOperableFactories(PLANET *lppl, int16_t iplr, int16_t fNextYear);  /* MEMORY_PLANET:0x7618 */
int16_t CMaxFactories(PLANET *lppl, int16_t iplr);  /* MEMORY_PLANET:0x755c */
void DrawMassWarpGauge(uint16_t hdc, RECT *prc, int16_t iBest, int16_t iCur);  /* MEMORY_PLANET:0x2afa */
char * PszCalcGravity(int16_t iGravity);  /* MEMORY_PLANET:0x6058 */
int16_t CMaxMines(PLANET *lppl, int16_t iplr);  /* MEMORY_PLANET:0x7248 */
int16_t FProdIsTerra(PROD *lpprod);  /* MEMORY_PLANET:0x7e9a */
int16_t CMaxDefenses(PLANET *lppl, int16_t iplr);  /* MEMORY_PLANET:0x7710 */
void DrawPlanetProduction(uint16_t hdc, TILE *ptile, OBJ obj);  /* MEMORY_PLANET:0x2c38 */
void DrawPlanShipBitmap(uint16_t hdc, TILE *ptile, OBJ obj);  /* MEMORY_PLANET:0x3336 */
int16_t FDrawTileNC(uint16_t hdc, TILE *ptile, RECT *prc, char *pszTitle);  /* MEMORY_PLANET:0x1086 */
int16_t IBestTerraform(PLANET *lppl, int16_t fHelp);  /* MEMORY_PLANET:0x5dd2 */
void SetPlanetTitleBar(uint16_t hwnd);  /* MEMORY_PLANET:0x3dec */
void HandleFocusState(DRAWITEMSTRUCT *lpdis, int16_t inflate);  /* MEMORY_PLANET:0x60e6 */
int16_t IpctCanTerraformLppl(PLANET *lppl);  /* MEMORY_PLANET:0x7f56 */
int32_t PlanetWndProc(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam);  /* PASCAL */  /* MEMORY_PLANET:0x0000 */
int16_t IdFindAdjStarbase(int16_t idPlanet, int16_t fNext);  /* MEMORY_PLANET:0x474e */
int32_t CalcPlanetMaxPop(int16_t idpl, int16_t iplr);  /* MEMORY_PLANET:0x7096 */
void FillShipDD(int16_t idSkip);  /* MEMORY_PLANET:0x42a0 */
void ChangeMainObjSel(int16_t grobjNew, int16_t iObjSel);  /* MEMORY_PLANET:0x3e7a */
void DrawProductionItem(uint16_t hdc, RECT *prc, char *psz, int16_t inflate, int16_t fSelected, int16_t fListbox);  /* MEMORY_PLANET:0x6208 */
void UninhabitPlanet(PLANET *lppl);  /* MEMORY_PLANET:0x8732 */
int16_t StargateRangeFromLppl(PLANET *lppl, int16_t iplr, int16_t ish);  /* MEMORY_PLANET:0x7cfa */
void FillPlanetProdLB(uint16_t hwnd, PLPROD *lpplprod, PLANET *lppl);  /* MEMORY_PLANET:0x6692 */
void EnsureTileSize(int16_t fSmallTiles);  /* MEMORY_PLANET:0x587e */
uint16_t ClickInPlanetOrders(POINT pt, int16_t sks, int16_t fCursor, int16_t fRightBtn);  /* MEMORY_PLANET:0x515c */
int16_t CMaxOperableMines(PLANET *lppl, int16_t iplr, int16_t fNextYear);  /* MEMORY_PLANET:0x7304 */
int16_t CMinesOperating(PLANET *lppl);  /* MEMORY_PLANET:0x73fc */
void PlanetClick(int16_t x, int16_t y, int16_t sks, int16_t fRightBtn);  /* MEMORY_PLANET:0x489e */
int16_t PctPlanetCapacity(PLANET *lppl);  /* MEMORY_PLANET:0x6aca */
void SelectAdjPlanet(int16_t dInc, int16_t idPlanet);  /* MEMORY_PLANET:0x44da */
void ReflowColumn(int16_t iCol, int16_t iTile, int16_t fRedraw);  /* MEMORY_PLANET:0x5b80 */
int16_t CFactoriesOperating(PLANET *lppl);  /* MEMORY_PLANET:0x74be */

#endif /* PLANET_H_ */
