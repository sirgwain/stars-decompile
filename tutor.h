#ifndef TUTOR_H_
#define TUTOR_H_

#include "strings.h"
#include "types.h"

/* globals */
extern ITEMACTION rgiaQuikDrop[5];
extern ITEMACTION rgiaQuikLoad[5];
extern ITEMACTION rgiaUnloadAllCol[5];
extern ITEMACTION rgiaLoadAllCol[5];
extern ZIPPRODQ1  rgzpqTut[2];

extern char mpishdefishTutor[6]; /* MEMORY_IO:0x0000 */

/* functions */

// called everywhere, must compile with linux builds
void AdvanceTutor(void);

#ifdef _WIN32

INT_PTR CALLBACK TutorDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */
INT_PTR CALLBACK PanicDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */

void    ShowTutor(int16_t fShow);
void    StartTutor(int16_t fRestart);
void    EndTutor(int16_t fClose);
void    TutorError(int16_t idsError);
void    DrawTutorText(HWND hwnd);
int16_t FAskKillTutor(void);
int16_t FOKMergeDialog(void);

int16_t FTutorialEnabledShipBuilder(int16_t itutsbAction);
int16_t FCheckCargo(FLEET *lpfl, int16_t wtMin1, int16_t wtMin2, int16_t wtMin3, int16_t wtColonists);
int16_t FCheckPlanetRoute(int16_t idpl, int16_t idplRoute);
int16_t FCheckScanner(int16_t md, int16_t iZoom);
int16_t FCheckResearch(int16_t iTech, int16_t iTechNext, int16_t pct);
int16_t FTutorTaskDone(void);
int16_t FCheckFleetName(int16_t id, int16_t ids);
int16_t FCheckZip(int16_t iZip, ITEMACTION *lpiaGoal, int16_t ids);
int16_t FCheckXferWP(uint16_t ifl, int16_t iord, int16_t id, uint16_t iWarp, ITEMACTION *lpiaGoal);
int16_t FCheckFleetWP(uint16_t ifl, int16_t iord, GrobjClass grobj, int16_t id, uint16_t grTask, uint16_t iWarp);
int16_t FCheckPatrolWP(uint16_t ifl, int16_t iord, int16_t id, uint16_t iWarp, uint16_t iPlan, uint16_t iDist);
int16_t FCheckLayingWP(uint16_t ifl, int16_t iord, int16_t id, int16_t iYears);
int16_t FCheckMessages(int16_t imsg, MessageId idm, int16_t fFilter);
int16_t FCheckQueue(int16_t ipl, int16_t iprod, GrobjClass grobj, uint16_t iItem, uint16_t cItem, uint16_t fNoResearch);
int16_t FCheckTemplate(int16_t iTemplate);
int16_t FCheckColonizeWP(uint16_t ifl, int16_t id, uint16_t iWarp);
int16_t FCheckBuilderPart(int16_t iSlot, HS *phs, uint16_t cInit);
int16_t FCheckSelection(GrobjClass grobj, int16_t id);
int16_t FCheckSummary(GrobjClass grobj, int16_t id);
int16_t FCheckBtlPlan(int16_t ibp, uint16_t imdTarget, uint16_t fSpread, uint16_t fBomb, uint16_t fDump, uint16_t mdUnarmed, uint16_t mdScout, uint16_t mdWar,
                      uint16_t mdBomber);
int16_t FCheckShipBuilder(int16_t iCategory, int16_t iShip);

void SaveGameState(void);
void RestoreGameState(void);

#endif /* _WIN32 */
#endif /* TUTOR_H_ */
