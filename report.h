#ifndef REPORT_H_
#define REPORT_H_


#include "types.h"

/* globals */
extern uint16_t mpicolgrbitBU[12];  /* MEMORY_REPORT:0x0000 */

/* functions */
int16_t ScoreXDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_REPORT:0x0f66 */
int32_t ReportDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_REPORT:0x0018 */
int16_t PrintMapDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_REPORT:0xa1c2 */
void SetHScrollBar(void);  /* MEMORY_REPORT:0x09e8 */
void SortReportCache(int16_t, int16_t);  /* MEMORY_REPORT:0x589c */
void InitScoreDlg(uint16_t, int16_t);  /* MEMORY_REPORT:0x13b6 */
void ReportColumnPopup(POINT, int16_t, int16_t);  /* MEMORY_REPORT:0x74d4 */
int16_t FDestIsWP0(FLEET *);  /* MEMORY_REPORT:0x50b4 */
int16_t ICompReport(void *, void *);  /* MEMORY_REPORT:0x5bb8 */
void DrawReport(uint16_t, uint16_t, RECT *);  /* MEMORY_REPORT:0x0bae */
void InvalidateReport(int16_t, int16_t);  /* MEMORY_REPORT:0x7af6 */
void DumpUniverse(void);  /* MEMORY_REPORT:0x851e */
void DumpFleets(void);  /* MEMORY_REPORT:0x9530 */
int16_t DxReportColHdr(int16_t, int16_t, char *, uint16_t);  /* MEMORY_REPORT:0x305e */
void DumpPlanets(void);  /* MEMORY_REPORT:0x86e4 */
int32_t LFetchScoreXVal(SCOREX *, int16_t);  /* MEMORY_REPORT:0x2f94 */
char * PszGetETA(uint16_t, FLEET *, int16_t *);  /* MEMORY_REPORT:0x51a8 */
void ExecuteReportClick(POINT, int16_t, int16_t, int16_t);  /* MEMORY_REPORT:0x7cd6 */
void DrawVCReport(uint16_t);  /* MEMORY_REPORT:0x168e */
void DrawReportItem(uint16_t, RECT *, int16_t, int16_t, int16_t);  /* MEMORY_REPORT:0x3398 */
char * PszGetTaskName(FLEET *, int16_t *);  /* MEMORY_REPORT:0x53b8 */
char * PszGetDestName(FLEET *, uint16_t);  /* MEMORY_REPORT:0x4f60 */
void DrawMineralItem(uint16_t, int16_t, int16_t, int16_t, int32_t);  /* MEMORY_REPORT:0x4ebe */
void DrawHistoryReport(uint16_t);  /* MEMORY_REPORT:0x2494 */
void DrawScoreReport(uint16_t);  /* MEMORY_REPORT:0x1e0c */

#endif /* REPORT_H_ */
