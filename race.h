#ifndef RACE_H_
#define RACE_H_

#include "types.h"

/* globals */
extern char    rgRaceStatMin[16];
extern char    rgRaceStatMax[16];
extern int16_t rgRacePrimaryTrait[10];
extern int16_t rgRaceAdvDisPts[14];
extern int16_t rgRaceDisEnvPts[6];

int16_t  RaMajor(int16_t iplr);
void     CreateRandomRace(PLAYER *pplr);
int32_t  LInnateRaceHabitability(PLAYER *pplr);
int16_t  GetRaceGrbit(const PLAYER *pplr, const RaceGrbit ibit);
int16_t  GetRaceStat(const PLAYER *pplr, const int16_t iStat);
void     SetRaceGrbit(PLAYER *pplr, RaceGrbit ibit, int16_t fSet);
int16_t  SetRaceStat(PLAYER *pplr, int16_t iStat, int16_t iVal);
int16_t  CAdvantagePoints(PLAYER *pplr);
int16_t  PctTrueMaxGrowth(int16_t iplr);
int16_t  FSaveRace(char *szFileSuggest, PLAYER *pplr);
uint16_t IRaceChecksum(PLAYER *pplr);
void     BoundsCheckPlayer(PLAYER *pplr);

/* functions */
#ifdef _WIN32

extern char rgRW3Spacing[7];
extern char rgRW3Width[7];
extern char rgRW3IStat[7];

int16_t RaceCreationWizard(HWND hwndParent, int16_t fReadOnly, int16_t fDontWrite);

INT_PTR CALLBACK RaceWizardDlg6(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK RaceWizardDlg5(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK RaceWizardDlg4(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK RaceWizardDlg3(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK RaceWizardDlg2(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK RaceWizardDlg1(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void             DrawRaceAdvantagePoints(HDC hdc, RECT *prc, PLAYER *pplr);
void             DrawRace3(HWND hwnd, HDC hdc, int16_t iDraw);
void             InvalidateAdvPtsRect(HWND hwnd);
void             SetRCWTitle(HWND hwnd, int16_t iStep);
void             DrawRace2(HWND hwnd, HDC hdc, int16_t iDraw);
int16_t          FTrackRaceDlg3(HWND hwnd, POINT pt, int16_t kbd);
int16_t          FTrackRaceDlg2(HWND hwnd, POINT pt, int16_t kbd);
int16_t          IrcRaceDlgHitTest(POINT pt);

#endif /* _WIN32 */

#endif /* RACE_H_ */
