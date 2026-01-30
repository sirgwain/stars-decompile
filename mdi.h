#ifndef MDI_H_
#define MDI_H_

#include "types.h"

/* globals */
extern uint8_t vrgbShuffleSerial[21];
extern char rgTOWidth[2][2];

/* functions */
void VerifyTurns(void);
int16_t FSerialAndEnvFromSz(int32_t *plSerial, uint8_t *pbEnv, char *pszIn);
void FormatSerialAndEnv(int32_t lSerial, const uint8_t *pbEnv, char *pszOut);
int16_t FWasRaceFile(char *szFile, int16_t fChkPass);
void EnsureAis(void);
int16_t CTurnsOutSafe(void);

#ifdef _WIN32
INT_PTR CALLBACK HostModeDialog(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */
int16_t FFindSomethingAndSelectIt(void);
int16_t CFindTurnsOutstanding(void);
LRESULT CALLBACK TitleWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */
void CommandHandler(HWND hwnd, uint16_t wParam);
LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */
void GetWindowRc(HWND hwnd, RECT *prc);
void DrawHostDialog2(HWND hwnd, HDC hdcIn);
void DrawHostOptions(HWND hwnd, HDC hdc, int16_t iDraw);
void WriteIniSettings(void);
VOID CALLBACK HostTimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime); /* PASCAL */
HMENU GetASubMenu(HWND hwnd, int16_t iMenu);
int16_t FOpenGame(HWND hwnd, int16_t fRaceOnly);
void InitializeMenu(HMENU hmenu);
uint16_t HcrsFromFrameWindowPt(POINT pt, int16_t *pgrSel);
POINT InvertPaneBorder(HDC hdc, int16_t grSel, POINT dpt, POINT *pdptPrev);
void BringUpHostDlg(void);
INT_PTR CALLBACK HostOptionsDialog(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */
int16_t InitMDIApp(void);
void CreateChildWindows(void);
void SetWindowIniString(const char *sz /*unused in the snippet*/, HWND hwnd);
void RestoreSelection(void);
void RefitFrameChildren(void);

#endif /* _WIN32 */
#endif /* MDI_H_ */
