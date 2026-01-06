#ifndef RACE_H_
#define RACE_H_


#include "types.h"

/* globals */
extern char rgRW3Spacing[7];  /* MEMORY_RACE:0x2a8c */
extern char rgRW3Width[7];  /* MEMORY_RACE:0x2a94 */
extern char rgRW3IStat[7];  /* MEMORY_RACE:0x2a9c */
extern char rgRaceStatMin[16];  /* MEMORY_RACE:0x30f4 */
extern char rgRaceStatMax[16];  /* MEMORY_RACE:0x3104 */
extern int16_t rgRacePrimaryTrait[10];  /* MEMORY_RACE:0x4410 */
extern int16_t rgRaceAdvDisPts[14];  /* MEMORY_RACE:0x4424 */
extern int16_t rgRaceDisEnvPts[6];  /* MEMORY_RACE:0x4440 */

/* functions */
int16_t RaceWizardDlg6(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RACE:0x3bae */
int16_t RaceWizardDlg5(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RACE:0x378e */
int16_t RaceWizardDlg4(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RACE:0x320a */
int16_t RaceWizardDlg3(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RACE:0x2792 */
int16_t RaceWizardDlg2(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RACE:0x1060 */
int16_t RaceWizardDlg1(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RACE:0x03ac */
void SetRaceGrbit(PLAYER *, int16_t, int16_t);  /* MEMORY_RACE:0x31b8 */
int16_t GetRaceGrbit(PLAYER *, int16_t);  /* MEMORY_RACE:0x3176 */
void DrawRaceAdvantagePoints(uint16_t, RECT *, PLAYER *);  /* MEMORY_RACE:0x55c6 */
int16_t CAdvantagePoints(PLAYER *);  /* MEMORY_RACE:0x444c */
int16_t RaceCreationWizard(uint16_t, int16_t, int16_t);  /* MEMORY_RACE:0x0000 */
void DrawRace3(uint16_t, uint16_t, int16_t);  /* MEMORY_RACE:0x2aa4 */
void InvalidateAdvPtsRect(uint16_t);  /* MEMORY_RACE:0x54d4 */
int16_t SetRaceStat(PLAYER *, int16_t, int16_t);  /* MEMORY_RACE:0x3114 */
void SetRCWTitle(uint16_t, int16_t);  /* MEMORY_RACE:0x5ab8 */
void DrawRace2(uint16_t, uint16_t, int16_t);  /* MEMORY_RACE:0x179a */
int16_t FTrackRaceDlg3(uint16_t, POINT, int16_t);  /* MEMORY_RACE:0x2fb8 */
int16_t FTrackRaceDlg2(uint16_t, POINT, int16_t);  /* MEMORY_RACE:0x2204 */
int16_t PctTrueMaxGrowth(int16_t);  /* MEMORY_RACE:0x65d4 */
int16_t FSaveRace(char *, PLAYER *);  /* MEMORY_RACE:0x58d4 */
int16_t GetRaceStat(PLAYER *, int16_t);  /* MEMORY_RACE:0x30d2 */
uint16_t IRaceChecksum(PLAYER *);  /* MEMORY_RACE:0x5888 */
void BoundsCheckPlayer(PLAYER *);  /* MEMORY_RACE:0x40ae */
int16_t IrcRaceDlgHitTest(POINT);  /* MEMORY_RACE:0x2164 */
void CreateRandomRace(PLAYER *);  /* MEMORY_RACE:0x5b08 */
int32_t LInnateRaceHabitability(PLAYER *);  /* MEMORY_RACE:0x4c6e */

#endif /* RACE_H_ */
