#ifndef PRODUCE_H_
#define PRODUCE_H_

#include "types.h"

char *PszNameProdItem(PROD *lpprod);                                                                          /* MEMORY_PRODUCE:0x3c92 */
void GetProductionCosts(PLANET *lppl, PROD *lpprod, uint32_t *rgCost, int16_t iplr, int16_t fOnlyOne);        /* MEMORY_PRODUCE:0x3f20 */
void EstimateItemProdSched(PLANET *lppl, PLPROD *lpplprod, int16_t iItem, int16_t *piFirst, int16_t *piLast); /* MEMORY_PRODUCE:0x4f40 */
void InitProduction(PROD *rgprod);                                                                            /* MEMORY_PRODUCE:0x015e */
bool FIsAutoBuild(PROD *lpprod);

#ifdef _WIN32

INT_PTR CALLBACK ProductionDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_PRODUCE:0x1204 */
INT_PTR CALLBACK ZipProdDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);    /* MEMORY_PRODUCE:0x5490 */

void ProdCommandHandler(HWND hwnd, WPARAM wParam, LPARAM lParam); /* MEMORY_PRODUCE:0x1994 */

int16_t ChangeProduction(int16_t fClear);                             /* MEMORY_PRODUCE:0x0000 */
void EnableZipProdBtns(HWND hwnd, int16_t iSel);                      /* MEMORY_PRODUCE:0x5df0 */
void FillProdSrcLB(HWND hwndLB, int16_t mdFill);                      /* MEMORY_PRODUCE:0x3b00 */
void DrawProductionDlg(HWND hwnd, HDC hdc, RECT *prc, int16_t iDraw); /* MEMORY_PRODUCE:0x35dc */
void FinishProduction(int16_t fWrite);                                /* MEMORY_PRODUCE:0x1090 */
void InitializeProductionDlg(HWND hwnd);                              /* MEMORY_PRODUCE:0x3430 */
void FillZipProdLB(HWND hwndDlg, ZIPPRODQ *pzpq);                     /* MEMORY_PRODUCE:0x5e58 */

#endif /* _WIN32 */

#endif /* PRODUCE_H_ */
