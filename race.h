#ifndef RACE_H_
#define RACE_H_

#include "types.h"

/* globals */
extern char rgRaceStatMin[16];         /* MEMORY_RACE:0x30f4 */
extern char rgRaceStatMax[16];         /* MEMORY_RACE:0x3104 */
extern int16_t rgRacePrimaryTrait[10]; /* MEMORY_RACE:0x4410 */
extern int16_t rgRaceAdvDisPts[14];    /* MEMORY_RACE:0x4424 */
extern int16_t rgRaceDisEnvPts[6];     /* MEMORY_RACE:0x4440 */

int16_t RaMajor(int16_t iplr);
void CreateRandomRace(PLAYER *pplr);                            /* MEMORY_RACE:0x5b08 */
int32_t LInnateRaceHabitability(PLAYER *pplr);                  /* MEMORY_RACE:0x4c6e */
void SetRaceGrbit(PLAYER *pplr, RaceGrbit ibit, int16_t fSet);  /* MEMORY_RACE:0x31b8 */
int16_t GetRaceGrbit(PLAYER *pplr, RaceGrbit ibit);             /* MEMORY_RACE:0x3176 */
int16_t CAdvantagePoints(PLAYER *pplr);                         /* MEMORY_RACE:0x444c */
int16_t SetRaceStat(PLAYER *pplr, int16_t iStat, int16_t iVal); /* MEMORY_RACE:0x3114 */
int16_t PctTrueMaxGrowth(int16_t iplr);                         /* MEMORY_RACE:0x65d4 */
int16_t FSaveRace(char *szFileSuggest, PLAYER *pplr);           /* MEMORY_RACE:0x58d4 */
int16_t GetRaceStat(PLAYER *pplr, int16_t iStat);               /* MEMORY_RACE:0x30d2 */
uint16_t IRaceChecksum(PLAYER *pplr);                           /* MEMORY_RACE:0x5888 */
void BoundsCheckPlayer(PLAYER *pplr);                           /* MEMORY_RACE:0x40ae */

/* functions */
#ifdef _WIN32

extern char rgRW3Spacing[7]; /* MEMORY_RACE:0x2a8c */
extern char rgRW3Width[7];   /* MEMORY_RACE:0x2a94 */
extern char rgRW3IStat[7];   /* MEMORY_RACE:0x2a9c */

int16_t RaceCreationWizard(HWND hwndParent, int16_t fReadOnly, int16_t fDontWrite); /* MEMORY_RACE:0x0000 */

INT_PTR CALLBACK RaceWizardDlg6(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_RACE:0x3bae */
INT_PTR CALLBACK RaceWizardDlg5(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_RACE:0x378e */
INT_PTR CALLBACK RaceWizardDlg4(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_RACE:0x320a */
INT_PTR CALLBACK RaceWizardDlg3(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_RACE:0x2792 */
INT_PTR CALLBACK RaceWizardDlg2(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_RACE:0x1060 */
INT_PTR CALLBACK RaceWizardDlg1(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_RACE:0x03ac */
void DrawRaceAdvantagePoints(HDC hdc, RECT *prc, PLAYER *pplr);                     /* MEMORY_RACE:0x55c6 */
void DrawRace3(HWND hwnd, HDC hdc, int16_t iDraw);                                  /* MEMORY_RACE:0x2aa4 */
void InvalidateAdvPtsRect(HWND hwnd);                                               /* MEMORY_RACE:0x54d4 */
void SetRCWTitle(HWND hwnd, int16_t iStep);                                         /* MEMORY_RACE:0x5ab8 */
void DrawRace2(HWND hwnd, HDC hdc, int16_t iDraw);                                  /* MEMORY_RACE:0x179a */
int16_t FTrackRaceDlg3(HWND hwnd, POINT pt, int16_t kbd);                           /* MEMORY_RACE:0x2fb8 */
int16_t FTrackRaceDlg2(HWND hwnd, POINT pt, int16_t kbd);                           /* MEMORY_RACE:0x2204 */
int16_t IrcRaceDlgHitTest(POINT pt);                                                /* MEMORY_RACE:0x2164 */

#endif /* _WIN32 */

#endif /* RACE_H_ */
