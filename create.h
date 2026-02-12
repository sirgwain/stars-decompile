#ifndef CREATE_H_
#define CREATE_H_

#include "types.h"

extern uint8_t vrgWormholeMin[5];
extern uint8_t vrgWormholeVar[5];
extern BTLPLAN rgbtlplanT[5];
extern char    rgNG3Width[9][2];
extern PLAYER  vrgplrComp[6][4];
extern int16_t vrgvcMax[10];

int16_t CreateStartupShip(int16_t iplr, int16_t idPlanet, int16_t ishdef, int16_t fAddShdef);
int16_t GetVCCheck(GAME *pgame, VictoryCondition vc);
int16_t GetVCVal(GAME *pgame, VictoryCondition vc, int16_t fRaw);
void    SetVCCheck(GAME *pgame, VictoryCondition vc, int16_t fChecked);
int16_t SetVCVal(GAME *pgame, VictoryCondition vc, int16_t val);
void    InitBattlePlan(BTLPLAN *lpbtlplan, int16_t iplan, int16_t iplr);
void    InitNewGamePlr(int16_t iStepMaxSoFar, int16_t lvlAi);
void    CreateTutorWorld(void);
void    CreateTinyTestWorld(void);
int16_t GenerateWorld(int16_t fBatchMode);
PLAYER *LpplrComp(int16_t idAi, int16_t lvlAi); /* RETFAR */
int16_t GenNewGameFromFile(char *pszFile);

#ifdef _WIN32
int16_t          FGetNewGameName(char *szFileSuggest);
void             SetNGWTitle(HWND hwnd, int16_t iStep);
int16_t          FTrackNewGameDlg3(HWND hwnd, POINT pt, int16_t kbd);
void             NewGameWizard(HWND hwnd, int16_t fReadOnly);
INT_PTR CALLBACK NewGameDlg3(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK NewGameDlg2(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK NewGameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK SimpleNewGameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void             DrawNewGame3(HWND hwnd, HDC hdc, int16_t iDraw);
void             DrawNewGame2(HWND hwnd, HDC hdc, int16_t iDraw);
#endif /* _WIN32 */

#endif /* CREATE_H_ */
