#ifndef PLANET_H_
#define PLANET_H_


#include "types.h"

/* functions */
void DrawPlanShip(uint16_t, int16_t);  /* MEMORY_PLANET:0x0d16 */
int16_t PctCloakFromHuldef(HUL *, int16_t, int16_t *);  /* MEMORY_PLANET:0x88c0 */
int16_t PctPlanetOptValue(PLANET *, int16_t);  /* MEMORY_PLANET:0x6b88 */
int16_t IWarpMAFromLppl(PLANET *, int16_t *);  /* MEMORY_PLANET:0x7b10 */
void DrawPlanetStats(uint16_t, TILE *, OBJ);  /* MEMORY_PLANET:0x1716 */
int16_t FGetBestDefensePart(PART *);  /* MEMORY_PLANET:0x21f6 */
void DrawPlanetShipList(uint16_t, TILE *, OBJ);  /* MEMORY_PLANET:0x377e */
void DrawPlanetStarbase(uint16_t, TILE *, OBJ);  /* MEMORY_PLANET:0x22cc */
int16_t PctPlanetDesirability(PLANET *, int16_t);  /* MEMORY_PLANET:0x6e1e */
void DrawPlanetMinSum(uint16_t, TILE *, OBJ);  /* MEMORY_PLANET:0x12b2 */
int16_t CResourcesAtPlanet(PLANET *, int16_t);  /* MEMORY_PLANET:0x788e */
int16_t CMaxOperableDefenses(PLANET *, int16_t, int16_t);  /* MEMORY_PLANET:0x77ae */
char * PszProductionETA(PLANET *, PLPROD *, int16_t, int16_t *, int16_t *);  /* MEMORY_PLANET:0x310c */
int16_t FCanTerraformLppl(PLANET *, int16_t *, int16_t *, int16_t *, int16_t);  /* MEMORY_PLANET:0x8022 */
void DrawCBEntireItem(DRAWITEMSTRUCT *, int16_t);  /* MEMORY_PLANET:0x6128 */
char * PszCalcEnvVar(int16_t, int16_t);  /* MEMORY_PLANET:0x5fcc */
int16_t CMaxOperableFactories(PLANET *, int16_t, int16_t);  /* MEMORY_PLANET:0x7618 */
int16_t CMaxFactories(PLANET *, int16_t);  /* MEMORY_PLANET:0x755c */
void DrawMassWarpGauge(uint16_t, RECT *, int16_t, int16_t);  /* MEMORY_PLANET:0x2afa */
char * PszCalcGravity(int16_t);  /* MEMORY_PLANET:0x6058 */
int16_t CMaxMines(PLANET *, int16_t);  /* MEMORY_PLANET:0x7248 */
int16_t FProdIsTerra(PROD *);  /* MEMORY_PLANET:0x7e9a */
int16_t CMaxDefenses(PLANET *, int16_t);  /* MEMORY_PLANET:0x7710 */
void DrawPlanetProduction(uint16_t, TILE *, OBJ);  /* MEMORY_PLANET:0x2c38 */
void DrawPlanShipBitmap(uint16_t, TILE *, OBJ);  /* MEMORY_PLANET:0x3336 */
int16_t FDrawTileNC(uint16_t, TILE *, RECT *, char *);  /* MEMORY_PLANET:0x1086 */
int16_t IBestTerraform(PLANET *, int16_t);  /* MEMORY_PLANET:0x5dd2 */
void SetPlanetTitleBar(uint16_t);  /* MEMORY_PLANET:0x3dec */
void HandleFocusState(DRAWITEMSTRUCT *, int16_t);  /* MEMORY_PLANET:0x60e6 */
int16_t IpctCanTerraformLppl(PLANET *);  /* MEMORY_PLANET:0x7f56 */
int32_t PlanetWndProc(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_PLANET:0x0000 */
int16_t IdFindAdjStarbase(int16_t, int16_t);  /* MEMORY_PLANET:0x474e */
int32_t CalcPlanetMaxPop(int16_t, int16_t);  /* MEMORY_PLANET:0x7096 */
void FillShipDD(int16_t);  /* MEMORY_PLANET:0x42a0 */
void ChangeMainObjSel(int16_t, int16_t);  /* MEMORY_PLANET:0x3e7a */
void DrawProductionItem(uint16_t, RECT *, char *, int16_t, int16_t, int16_t);  /* MEMORY_PLANET:0x6208 */
void UninhabitPlanet(PLANET *);  /* MEMORY_PLANET:0x8732 */
int16_t StargateRangeFromLppl(PLANET *, int16_t, int16_t);  /* MEMORY_PLANET:0x7cfa */
void FillPlanetProdLB(uint16_t, PLPROD *, PLANET *);  /* MEMORY_PLANET:0x6692 */
void EnsureTileSize(int16_t);  /* MEMORY_PLANET:0x587e */
uint16_t ClickInPlanetOrders(POINT, int16_t, int16_t, int16_t);  /* MEMORY_PLANET:0x515c */
int16_t CMaxOperableMines(PLANET *, int16_t, int16_t);  /* MEMORY_PLANET:0x7304 */
int16_t CMinesOperating(PLANET *);  /* MEMORY_PLANET:0x73fc */
void PlanetClick(int16_t, int16_t, int16_t, int16_t);  /* MEMORY_PLANET:0x489e */
int16_t PctPlanetCapacity(PLANET *);  /* MEMORY_PLANET:0x6aca */
void SelectAdjPlanet(int16_t, int16_t);  /* MEMORY_PLANET:0x44da */
void ReflowColumn(int16_t, int16_t, int16_t);  /* MEMORY_PLANET:0x5b80 */
int16_t CFactoriesOperating(PLANET *);  /* MEMORY_PLANET:0x74be */

#endif /* PLANET_H_ */
