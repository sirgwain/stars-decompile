#ifndef TUTOR_H_
#define TUTOR_H_


#include "types.h"

/* globals */
extern ITEMACTION rgiaQuikDrop[5];  /* MEMORY_TUTOR:0x0f94 */
extern ITEMACTION rgiaQuikLoad[5];  /* MEMORY_TUTOR:0x0f9e */
extern ITEMACTION rgiaUnloadAllCol[5];  /* MEMORY_TUTOR:0x0fa8 */
extern ITEMACTION rgiaLoadAllCol[5];  /* MEMORY_TUTOR:0x0fb2 */
extern ZIPPRODQ1 rgzpqTut[2];  /* MEMORY_TUTOR:0x663a */

/* functions */
void EndTutor(int16_t);  /* MEMORY_TUTOR:0x0c02 */
void DrawTutorText(uint16_t);  /* MEMORY_TUTOR:0x03c0 */
int16_t FCheckCargo(FLEET *, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_TUTOR:0x7664 */
int16_t FCheckPlanetRoute(int16_t, int16_t);  /* MEMORY_TUTOR:0x6f86 */
int16_t FCheckScanner(int16_t, int16_t);  /* MEMORY_TUTOR:0x685c */
int16_t FCheckResearch(int16_t, int16_t, int16_t);  /* MEMORY_TUTOR:0x6da4 */
int16_t FTutorTaskDone(void);  /* MEMORY_TUTOR:0x0fbc */
int16_t TutorDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_TUTOR:0x0000 */
int16_t FCheckFleetName(int16_t, int16_t);  /* MEMORY_TUTOR:0x690a */
int16_t FCheckZip(int16_t, ITEMACTION *, int16_t);  /* MEMORY_TUTOR:0x6460 */
void SaveGameState(void);  /* MEMORY_TUTOR:0x0c90 */
int16_t FCheckXferWP(uint16_t, int16_t, int16_t, uint16_t, ITEMACTION *);  /* MEMORY_TUTOR:0x7280 */
int16_t FCheckFleetWP(uint16_t, int16_t, uint16_t, int16_t, uint16_t, uint16_t);  /* MEMORY_TUTOR:0x6df4 */
void ShowTutor(int16_t);  /* MEMORY_TUTOR:0x0374 */
void RestoreGameState(void);  /* MEMORY_TUTOR:0x0e1c */
int16_t PanicDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_TUTOR:0x026a */
int16_t FCheckPatrolWP(uint16_t, int16_t, int16_t, uint16_t, uint16_t, uint16_t);  /* MEMORY_TUTOR:0x71ac */
int16_t FCheckLayingWP(uint16_t, int16_t, int16_t, int16_t);  /* MEMORY_TUTOR:0x6ff4 */
int16_t FCheckMessages(int16_t, int16_t, int16_t);  /* MEMORY_TUTOR:0x6c48 */
int16_t FCheckQueue(int16_t, int16_t, uint16_t, uint16_t, uint16_t, uint16_t);  /* MEMORY_TUTOR:0x7442 */
int16_t FTutorialEnabledShipBuilder(int16_t);  /* MEMORY_TUTOR:0x79f6 */
int16_t FCheckTemplate(int16_t);  /* MEMORY_TUTOR:0x666e */
int16_t FCheckColonizeWP(uint16_t, int16_t, uint16_t);  /* MEMORY_TUTOR:0x70c0 */
int16_t FCheckBuilderPart(int16_t, HS *, uint16_t);  /* MEMORY_TUTOR:0x77d8 */
int16_t FAskKillTutor(void);  /* MEMORY_TUTOR:0x0f36 */
void StartTutor(int16_t);  /* MEMORY_TUTOR:0x06b4 */
int16_t FCheckSelection(uint16_t, int16_t);  /* MEMORY_TUTOR:0x6af4 */
int16_t FCheckSummary(uint16_t, int16_t);  /* MEMORY_TUTOR:0x69e2 */
int16_t FOKMergeDialog(void);  /* MEMORY_TUTOR:0x81da */
int16_t FCheckBtlPlan(int16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t);  /* MEMORY_TUTOR:0x760a */
int16_t FCheckShipBuilder(int16_t, int16_t);  /* MEMORY_TUTOR:0x7964 */
void TutorError(int16_t);  /* MEMORY_TUTOR:0x67ae */
void AdvanceTutor(void);  /* MEMORY_TUTOR:0x0a30 */

#endif /* TUTOR_H_ */
