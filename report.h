#ifndef REPORT_H_
#define REPORT_H_

#include "types.h"

/* globals */
extern uint16_t mpicolgrbitBU[12];

void  DumpUniverse(void);
void  DumpFleets(void);
void  DumpPlanets(void);
char *PszGetETA(HDC hdc, FLEET *lpfl, int16_t *pcYears);
char *PszGetTaskName(FLEET *lpfl, int16_t *picr);
char *PszGetDestName(FLEET *lpfl, HDC hdc);
void  InvalidateReport(int16_t irpt, int16_t fReload);

#ifdef _WIN32

LRESULT CALLBACK ReportWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK ScoreXDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PrintMapDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void             SetHScrollBar(void);
void             SortReportCache(int16_t irpt, int16_t icol);
void             InitScoreDlg(HWND hwnd, int16_t fVictory);
void             ReportColumnPopup(POINT pt, int16_t icol, int16_t fRightBtn);
int16_t          FDestIsWP0(FLEET *lpfl);
int16_t          ICompReport(void *arg1, void *arg2);
void             DrawReport(HWND hwnd, HDC hdc, RECT *prc);
int16_t          DxReportColHdr(int16_t irpt, int16_t iCol, char *psz, HDC hdc);
int32_t          LFetchScoreXVal(SCOREX *lpsx, int16_t iVal);
void             ExecuteReportClick(POINT pt, int16_t irpt, int16_t icol, int16_t irow);
void             DrawVCReport(HDC hdc);
void             DrawReportItem(HDC hdc, RECT *prc, int16_t irpt, int16_t irow, int16_t icol);
void             DrawMineralItem(HDC hdc, int16_t x, int16_t y, int16_t iMineral, int32_t l);
void             DrawHistoryReport(HDC hdc);
void             DrawScoreReport(HDC hdc);

#endif /* _WIN32 */

#endif /* REPORT_H_ */
