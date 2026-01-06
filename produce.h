#ifndef PRODUCE_H_
#define PRODUCE_H_


#include "types.h"

/* functions */
void ProdCommandHandler(uint16_t, uint16_t, int32_t);  /* MEMORY_PRODUCE:0x1994 */
int16_t ChangeProduction(int16_t);  /* MEMORY_PRODUCE:0x0000 */
void EnableZipProdBtns(uint16_t, int16_t);  /* MEMORY_PRODUCE:0x5df0 */
int16_t ProductionDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_PRODUCE:0x1204 */
int16_t ZipProdDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_PRODUCE:0x5490 */
void FillProdSrcLB(uint16_t, int16_t);  /* MEMORY_PRODUCE:0x3b00 */
char * PszNameProdItem(PROD *);  /* MEMORY_PRODUCE:0x3c92 */
void EstimateItemProdSched(PLANET *, PLPROD *, int16_t, int16_t *, int16_t *);  /* MEMORY_PRODUCE:0x4f40 */
void DrawProductionDlg(uint16_t, uint16_t, RECT *, int16_t);  /* MEMORY_PRODUCE:0x35dc */
void FinishProduction(int16_t);  /* MEMORY_PRODUCE:0x1090 */
void GetProductionCosts(PLANET *, PROD *, uint32_t *, int16_t, int16_t);  /* MEMORY_PRODUCE:0x3f20 */
void InitializeProductionDlg(uint16_t);  /* MEMORY_PRODUCE:0x3430 */
void FillZipProdLB(uint16_t, ZIPPRODQ *);  /* MEMORY_PRODUCE:0x5e58 */
void InitProduction(PROD *);  /* MEMORY_PRODUCE:0x015e */

#endif /* PRODUCE_H_ */
