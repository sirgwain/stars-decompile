#ifndef TUTOR_H_
#define TUTOR_H_

#include "types.h"
#include "strings.h"

/* globals */
extern ITEMACTION rgiaQuikDrop[5];     /* MEMORY_TUTOR:0x0f94 */
extern ITEMACTION rgiaQuikLoad[5];     /* MEMORY_TUTOR:0x0f9e */
extern ITEMACTION rgiaUnloadAllCol[5]; /* MEMORY_TUTOR:0x0fa8 */
extern ITEMACTION rgiaLoadAllCol[5];   /* MEMORY_TUTOR:0x0fb2 */
extern ZIPPRODQ1 rgzpqTut[2];          /* MEMORY_TUTOR:0x663a */

extern char mpishdefishTutor[6]; /* MEMORY_IO:0x0000 */

/* functions */

#ifdef _WIN32

INT_PTR CALLBACK TutorDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_TUTOR:0x0000 */
INT_PTR CALLBACK PanicDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_TUTOR:0x026a */

void ShowTutor(int16_t fShow);     /* MEMORY_TUTOR:0x0374 */
void StartTutor(int16_t fRestart); /* MEMORY_TUTOR:0x06b4 */
void AdvanceTutor(void);           /* MEMORY_TUTOR:0x0a30 */
void EndTutor(int16_t fClose);     /* MEMORY_TUTOR:0x0c02 */
void TutorError(int16_t idsError); /* MEMORY_TUTOR:0x67ae */
void DrawTutorText(HWND hwnd);     /* MEMORY_TUTOR:0x03c0 */
int16_t FAskKillTutor(void);       /* MEMORY_TUTOR:0x0f36 */
int16_t FOKMergeDialog(void);      /* MEMORY_TUTOR:0x81da */

int16_t FTutorialEnabledShipBuilder(int16_t itutsbAction);                                                                                                                         /* MEMORY_TUTOR:0x79f6 */
int16_t FCheckCargo(FLEET *lpfl, int16_t wtMin1, int16_t wtMin2, int16_t wtMin3, int16_t wtColonists);                                                                             /* MEMORY_TUTOR:0x7664 */
int16_t FCheckPlanetRoute(int16_t idpl, int16_t idplRoute);                                                                                                                        /* MEMORY_TUTOR:0x6f86 */
int16_t FCheckScanner(int16_t md, int16_t iZoom);                                                                                                                                  /* MEMORY_TUTOR:0x685c */
int16_t FCheckResearch(int16_t iTech, int16_t iTechNext, int16_t pct);                                                                                                             /* MEMORY_TUTOR:0x6da4 */
int16_t FTutorTaskDone(void);                                                                                                                                                      /* MEMORY_TUTOR:0x0fbc */
int16_t FCheckFleetName(int16_t id, int16_t ids);                                                                                                                                  /* MEMORY_TUTOR:0x690a */
int16_t FCheckZip(int16_t iZip, ITEMACTION *lpiaGoal, int16_t ids);                                                                                                                /* MEMORY_TUTOR:0x6460 */
int16_t FCheckXferWP(uint16_t ifl, int16_t iord, int16_t id, uint16_t iWarp, ITEMACTION *lpiaGoal);                                                                                /* MEMORY_TUTOR:0x7280 */
int16_t FCheckFleetWP(uint16_t ifl, int16_t iord, GrobjClass grobj, int16_t id, uint16_t grTask, uint16_t iWarp);                                                                  /* MEMORY_TUTOR:0x6df4 */
int16_t FCheckPatrolWP(uint16_t ifl, int16_t iord, int16_t id, uint16_t iWarp, uint16_t iPlan, uint16_t iDist);                                                                    /* MEMORY_TUTOR:0x71ac */
int16_t FCheckLayingWP(uint16_t ifl, int16_t iord, int16_t id, int16_t iYears);                                                                                                    /* MEMORY_TUTOR:0x6ff4 */
int16_t FCheckMessages(int16_t imsg, MessageId idm, int16_t fFilter);                                                                                                              /* MEMORY_TUTOR:0x6c48 */
int16_t FCheckQueue(int16_t ipl, int16_t iprod, GrobjClass grobj, uint16_t iItem, uint16_t cItem, uint16_t fNoResearch);                                                           /* MEMORY_TUTOR:0x7442 */
int16_t FCheckTemplate(int16_t iTemplate);                                                                                                                                         /* MEMORY_TUTOR:0x666e */
int16_t FCheckColonizeWP(uint16_t ifl, int16_t id, uint16_t iWarp);                                                                                                                /* MEMORY_TUTOR:0x70c0 */
int16_t FCheckBuilderPart(int16_t iSlot, HS *phs, uint16_t cInit);                                                                                                                 /* MEMORY_TUTOR:0x77d8 */
int16_t FCheckSelection(GrobjClass grobj, int16_t id);                                                                                                                             /* MEMORY_TUTOR:0x6af4 */
int16_t FCheckSummary(GrobjClass grobj, int16_t id);                                                                                                                               /* MEMORY_TUTOR:0x69e2 */
int16_t FCheckBtlPlan(int16_t ibp, uint16_t imdTarget, uint16_t fSpread, uint16_t fBomb, uint16_t fDump, uint16_t mdUnarmed, uint16_t mdScout, uint16_t mdWar, uint16_t mdBomber); /* MEMORY_TUTOR:0x760a */
int16_t FCheckShipBuilder(int16_t iCategory, int16_t iShip);                                                                                                                       /* MEMORY_TUTOR:0x7964 */

void SaveGameState(void);    /* MEMORY_TUTOR:0x0c90 */
void RestoreGameState(void); /* MEMORY_TUTOR:0x0e1c */

#endif /* _WIN32 */
#endif /* TUTOR_H_ */
