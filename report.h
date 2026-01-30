#ifndef REPORT_H_
#define REPORT_H_

#include "types.h"

/* globals */
extern uint16_t mpicolgrbitBU[12]; /* MEMORY_REPORT:0x0000 */

void DumpUniverse(void);                                 /* MEMORY_REPORT:0x851e */
void DumpFleets(void);                                   /* MEMORY_REPORT:0x9530 */
void DumpPlanets(void);                                  /* MEMORY_REPORT:0x86e4 */
char *PszGetETA(HDC hdc, FLEET *lpfl, int16_t *pcYears); /* MEMORY_REPORT:0x51a8 */
char *PszGetTaskName(FLEET *lpfl, int16_t *picr);        /* MEMORY_REPORT:0x53b8 */
char *PszGetDestName(FLEET *lpfl, HDC hdc);              /* MEMORY_REPORT:0x4f60 */
void InvalidateReport(int16_t irpt, int16_t fReload);    /* MEMORY_REPORT:0x7af6 */

#ifdef _WIN32

INT_PTR CALLBACK ScoreXDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */   /* MEMORY_REPORT:0x0f66 */
INT_PTR CALLBACK ReportDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */   /* MEMORY_REPORT:0x0018 */
INT_PTR CALLBACK PrintMapDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_REPORT:0xa1c2 */
void SetHScrollBar(void);                                                                     /* MEMORY_REPORT:0x09e8 */
void SortReportCache(int16_t irpt, int16_t icol);                                             /* MEMORY_REPORT:0x589c */
void InitScoreDlg(HWND hwnd, int16_t fVictory);                                               /* MEMORY_REPORT:0x13b6 */
void ReportColumnPopup(POINT pt, int16_t icol, int16_t fRightBtn);                            /* MEMORY_REPORT:0x74d4 */
int16_t FDestIsWP0(FLEET *lpfl);                                                              /* MEMORY_REPORT:0x50b4 */
int16_t ICompReport(void *arg1, void *arg2);                                                  /* MEMORY_REPORT:0x5bb8 */
void DrawReport(HWND hwnd, HDC hdc, RECT *prc);                                               /* MEMORY_REPORT:0x0bae */
int16_t DxReportColHdr(int16_t irpt, int16_t iCol, char *psz, HDC hdc);                       /* MEMORY_REPORT:0x305e */
int32_t LFetchScoreXVal(SCOREX *lpsx, int16_t iVal);                                          /* MEMORY_REPORT:0x2f94 */
void ExecuteReportClick(POINT pt, int16_t irpt, int16_t icol, int16_t irow);                  /* MEMORY_REPORT:0x7cd6 */
void DrawVCReport(HDC hdc);                                                                   /* MEMORY_REPORT:0x168e */
void DrawReportItem(HDC hdc, RECT *prc, int16_t irpt, int16_t irow, int16_t icol);            /* MEMORY_REPORT:0x3398 */
void DrawMineralItem(HDC hdc, int16_t x, int16_t y, int16_t iMineral, int32_t l);             /* MEMORY_REPORT:0x4ebe */
void DrawHistoryReport(HDC hdc);                                                              /* MEMORY_REPORT:0x2494 */
void DrawScoreReport(HDC hdc);                                                                /* MEMORY_REPORT:0x1e0c */

#endif /* _WIN32 */

#endif /* REPORT_H_ */
