#ifndef CREATE_H_
#define CREATE_H_

#include "types.h"

/* globals */
extern uint8_t vrgWormholeMin[5]; /* MEMORY_CREATE:0x0000 */
extern uint8_t vrgWormholeVar[5]; /* MEMORY_CREATE:0x0006 */
extern BTLPLAN rgbtlplanT[5];     /* MEMORY_CREATE:0x000c */
extern char    rgNG3Width[9][2];  /* MEMORY_CREATE:0x9d4c */
extern PLAYER  vrgplrComp[6][4];  /* MEMORY_CREATE:0xa370 */
extern int16_t vrgvcMax[10];      /* MEMORY_CREATE:0xb5a8 */

/* functions */
int16_t CreateStartupShip(int16_t iplr, int16_t idPlanet, int16_t ishdef, int16_t fAddShdef); /* MEMORY_CREATE:0x4690 */
int16_t GetVCCheck(GAME *pgame, int16_t vc);                                                  /* MEMORY_CREATE:0xb60c */
void    InitBattlePlan(BTLPLAN *lpbtlplan, int16_t iplan, int16_t iplr);                      /* MEMORY_CREATE:0x00c0 */
void    InitNewGamePlr(int16_t iStepMaxSoFar, int16_t lvlAi);                                 /* MEMORY_CREATE:0x6e44 */
int16_t GetVCVal(GAME *pgame, int16_t vc, int16_t fRaw);                                      /* MEMORY_CREATE:0xb710 */
void    SetVCCheck(GAME *pgame, int16_t vc, int16_t fChecked);                                /* MEMORY_CREATE:0xb5bc */
void    CreateTutorWorld(void);                                                               /* MEMORY_CREATE:0x5e5e */
int16_t SetVCVal(GAME *pgame, int16_t vc, int16_t val);                                       /* MEMORY_CREATE:0xb644 */
int16_t GenerateWorld(int16_t fBatchMode);                                                    /* MEMORY_CREATE:0x0136 */
PLAYER *LpplrComp(int16_t idAi, int16_t lvlAi); /* RETFAR */                                  /* MEMORY_CREATE:0xb570 */
int16_t FGetNewGameName(char *szFileSuggest);                                                 /* MEMORY_CREATE:0x7508 */
int16_t GenNewGameFromFile(char *pszFile);                                                    /* MEMORY_CREATE:0x4812 */

#ifdef _WIN32
void             SetNGWTitle(HWND hwnd, int16_t iStep);                                            /* MEMORY_CREATE:0xa320 */
int16_t          FTrackNewGameDlg3(HWND hwnd, POINT pt, int16_t kbd);                              /* MEMORY_CREATE:0xa210 */
void             NewGameWizard(HWND hwnd, int16_t fReadOnly);                                      /* MEMORY_CREATE:0x6022 */
INT_PTR CALLBACK NewGameDlg3(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */      /* MEMORY_CREATE:0x99f4 */
INT_PTR CALLBACK NewGameDlg2(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */      /* MEMORY_CREATE:0x87d2 */
INT_PTR CALLBACK NewGameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */       /* MEMORY_CREATE:0x7e92 */
INT_PTR CALLBACK SimpleNewGameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_CREATE:0x76aa */
void             DrawNewGame3(HWND hwnd, HDC hdc, int16_t iDraw);                                  /* MEMORY_CREATE:0x9d5e */
void             DrawNewGame2(HWND hwnd, HDC hdc, int16_t iDraw);                                  /* MEMORY_CREATE:0x9556 */
#endif                                                                                             /* _WIN32 */

#endif /* CREATE_H_ */
