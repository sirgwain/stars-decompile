#ifndef PRODUCE_H_
#define PRODUCE_H_


#include "types.h"

/* functions */
void ProdCommandHandler(uint16_t hwnd, uint16_t wParam, int32_t lParam);  /* MEMORY_PRODUCE:0x1994 */
int16_t ChangeProduction(int16_t fClear);  /* MEMORY_PRODUCE:0x0000 */
void EnableZipProdBtns(uint16_t hwnd, int16_t iSel);  /* MEMORY_PRODUCE:0x5df0 */
int16_t ProductionDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam);  /* PASCAL */  /* MEMORY_PRODUCE:0x1204 */
int16_t ZipProdDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam);  /* PASCAL */  /* MEMORY_PRODUCE:0x5490 */
void FillProdSrcLB(uint16_t hwndLB, int16_t mdFill);  /* MEMORY_PRODUCE:0x3b00 */
char * PszNameProdItem(PROD *lpprod);  /* MEMORY_PRODUCE:0x3c92 */
void EstimateItemProdSched(PLANET *lppl, PLPROD *lpplprod, int16_t iItem, int16_t *piFirst, int16_t *piLast);  /* MEMORY_PRODUCE:0x4f40 */
void DrawProductionDlg(uint16_t hwnd, uint16_t hdc, RECT *prc, int16_t iDraw);  /* MEMORY_PRODUCE:0x35dc */
void FinishProduction(int16_t fWrite);  /* MEMORY_PRODUCE:0x1090 */
void GetProductionCosts(PLANET *lppl, PROD *lpprod, uint32_t *rgCost, int16_t iplr, int16_t fOnlyOne);  /* MEMORY_PRODUCE:0x3f20 */
void InitializeProductionDlg(uint16_t hwnd);  /* MEMORY_PRODUCE:0x3430 */
void FillZipProdLB(uint16_t hwndDlg, ZIPPRODQ *pzpq);  /* MEMORY_PRODUCE:0x5e58 */
void InitProduction(PROD *rgprod);  /* MEMORY_PRODUCE:0x015e */

/* Placeholder implementation used by file load logic. */
bool FIsAutoBuild(PROD *lpprod);

#endif /* PRODUCE_H_ */
