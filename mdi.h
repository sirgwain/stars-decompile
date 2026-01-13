#ifndef MDI_H_
#define MDI_H_

#include "types.h"

/* globals */
extern uint8_t vrgbShuffleSerial[21]; /* MEMORY_MDI:0x2870 */
extern char rgTOWidth[2][2];          /* MEMORY_MDI:0x7702 */

/* functions */
void VerifyTurns(void);                                                      /* MEMORY_MDI:0x6686 */
int16_t FSerialAndEnvFromSz(int32_t *plSerial, uint8_t *pbEnv, char *pszIn); /* MEMORY_MDI:0x2aec */
void FormatSerialAndEnv(int32_t lSerial, uint8_t *pbEnv, char *pszOut);      /* MEMORY_MDI:0x2886 */
int16_t FWasRaceFile(char *szFile, int16_t fChkPass);                        /* MEMORY_MDI:0x5da8 */
void EnsureAis(void);                                                        /* MEMORY_MDI:0x56bc */
int16_t CTurnsOutSafe(void);                                                 /* MEMORY_MDI:0x6996 */

#ifdef _WIN32
INT_PTR CALLBACK HostModeDialog(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */    /* MEMORY_MDI:0x6c16 */
int16_t FFindSomethingAndSelectIt(void);                                                            /* MEMORY_MDI:0x2e1c */
int16_t CFindTurnsOutstanding(void);                                                                /* MEMORY_MDI:0x6a26 */
LRESULT CALLBACK TitleWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */      /* MEMORY_MDI:0x9126 */
void CommandHandler(HWND hwnd, uint16_t wParam);                                                    /* MEMORY_MDI:0x2f7a */
LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */      /* MEMORY_MDI:0x06d6 */
void GetWindowRc(HWND hwnd, RECT *prc);                                                             /* MEMORY_MDI:0x79ac */
void DrawHostDialog2(HWND hwnd, HDC hdcIn);                                                         /* MEMORY_MDI:0x6240 */
void DrawHostOptions(HWND hwnd, HDC hdc, int16_t iDraw);                                            /* MEMORY_MDI:0x7706 */
void WriteIniSettings(void);                                                                        /* MEMORY_MDI:0x7a76 */
VOID CALLBACK HostTimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime); /* PASCAL */     /* MEMORY_MDI:0x7716 */
uint16_t GetASubMenu(HWND hwnd, int16_t iMenu);                                                     /* MEMORY_MDI:0x589a */
int16_t FOpenGame(HWND hwnd, int16_t fRaceOnly);                                                    /* MEMORY_MDI:0x58f4 */
void InitializeMenu(uint16_t hmenu);                                                                /* MEMORY_MDI:0x5376 */
uint16_t HcrsFromFrameWindowPt(POINT pt, int16_t *pgrSel);                                          /* MEMORY_MDI:0x24b0 */
POINT InvertPaneBorder(HDC hdc, int16_t grSel, POINT dpt, POINT *pdptPrev);                         /* MEMORY_MDI:0x1e3c */
void BringUpHostDlg(void);                                                                          /* MEMORY_MDI:0x5ffc */
INT_PTR CALLBACK HostOptionsDialog(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_MDI:0x75ce */
int16_t InitMDIApp(void);                                                                           /* MEMORY_MDI:0x0000 */
void CreateChildWindows(void);                                                                      /* MEMORY_MDI:0x038c */
void SetWindowIniString(char *sz, HWND hwnd);                                                       /* MEMORY_MDI:0x79f6 */
void RestoreSelection(void);                                                                        /* MEMORY_MDI:0x2614 */
void RefitFrameChildren(void);                                                                      /* MEMORY_MDI:0x8c88 */

#endif /* _WIN32 */
#endif /* MDI_H_ */
