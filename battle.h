#ifndef BATTLE_H_
#define BATTLE_H_


#include "types.h"

/* globals */
extern uint8_t rgbrcStart[136];  /* MEMORY_BATTLE:0x0000 */

/* functions */
int16_t FFleetHasTeeth(FLEET *);  /* MEMORY_BATTLE:0x1fbe */
void DropSalvage(THING * *, int32_t *, int16_t, POINT *);  /* MEMORY_BATTLE:0x24dc */
void CheckTarget(TOK *, FLEET *, int16_t);  /* MEMORY_BATTLE:0x212a */
int16_t BattlePlansDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_BATTLE:0x0652 */
int16_t NewPlanNameDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_BATTLE:0x04ce */
void CreateSalvage(FLEET *, THING * *);  /* MEMORY_BATTLE:0x7ee8 */
void DoBattles(int16_t);  /* MEMORY_BATTLE:0x3a26 */
void RandomizeTokOrder(void);  /* MEMORY_BATTLE:0x44d4 */
int16_t InitFromHuldef(HUL *, int16_t *);  /* MEMORY_BATTLE:0x3cba */
int32_t ScoreGuessBattleDamage(TOK *, uint8_t, int16_t, uint16_t);  /* MEMORY_BATTLE:0x598c */
int16_t FAttackPlayer(FLEET *, int16_t);  /* MEMORY_BATTLE:0xae06 */
void CheckInitiative(TOK *);  /* MEMORY_BATTLE:0x3e68 */
int16_t FDeleteBattlePlan(int16_t, int16_t);  /* MEMORY_BATTLE:0x1706 */
void RegenShield(TOK *);  /* MEMORY_BATTLE:0x3c16 */
int16_t FDumpCargo(FLEET *);  /* MEMORY_BATTLE:0x234a */
int32_t ScoreFromGiveAndTakeAndTactic(int32_t, int32_t, int16_t);  /* MEMORY_BATTLE:0x5e34 */
int16_t FAttack(int16_t, int16_t, BTLREC *, uint16_t);  /* MEMORY_BATTLE:0x69ac */
int16_t RelationsDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_BATTLE:0x0088 */
int16_t FHullHasTeeth(HUL *);  /* MEMORY_BATTLE:0x2072 */
int16_t FFleetHasBombs(FLEET *);  /* MEMORY_BATTLE:0x1e16 */
int16_t DxyFromSpdRound(uint16_t, int16_t);  /* MEMORY_BATTLE:0x8b28 */
int32_t CTorpHit(int32_t, TOK *, int16_t, int16_t);  /* MEMORY_BATTLE:0x6790 */
int16_t FCanKillTok(TOK *, TOK *);  /* MEMORY_BATTLE:0x391e */
int16_t FIsTargetOfMdTarget(TOK *, int16_t);  /* MEMORY_BATTLE:0x587a */
int16_t SpdOfShip(FLEET *, int16_t, TOK *, int16_t, SHDEF *);  /* MEMORY_BATTLE:0x339c */
void DoBombing(void);  /* MEMORY_BATTLE:0xaefa */
void InitializeBoard(FLEET *, int16_t, uint16_t, uint8_t *, int16_t *, int16_t *);  /* MEMORY_BATTLE:0x45b4 */
int16_t DzMoveRangeToConsider(TOK *, uint16_t, uint8_t *);  /* MEMORY_BATTLE:0x5312 */
int16_t FFuelTanker(SHDEF *);  /* MEMORY_BATTLE:0x20f6 */
int16_t FDoCoolBattle(FLEET *, int16_t, uint16_t *, uint16_t, uint16_t);  /* MEMORY_BATTLE:0x8bcc */
void CheckWeapons(TOK *, int16_t *, uint8_t *);  /* MEMORY_BATTLE:0x3ec2 */
SHDEF * LpshdefFromTok(TOK *);  /* RETFAR */  /* MEMORY_BATTLE:0x388e */
int16_t CplrBattle(FLEET *, uint16_t *, uint16_t *, uint16_t *);  /* MEMORY_BATTLE:0x2952 */
void SpankTheCheaters(void);  /* MEMORY_BATTLE:0x192a */
int16_t ITechLearnATech(int16_t, int16_t, int16_t, int16_t, uint16_t *);  /* MEMORY_BATTLE:0x9918 */
int16_t FDamageTok(TOK *, int16_t, int32_t *, int32_t, uint16_t, int16_t, int32_t *);  /* MEMORY_BATTLE:0x81d4 */
void KillShips(TOK *, int16_t, int16_t, FLEET *, int16_t);  /* MEMORY_BATTLE:0x7cde */
void SendBattleMessages(FLEET *, int16_t, int16_t, uint16_t *, int16_t, int16_t, int16_t, uint16_t);  /* MEMORY_BATTLE:0x9c0e */
int16_t FDoesPrimaryTargetTypeExist(TOK *, uint16_t);  /* MEMORY_BATTLE:0x56d8 */
int16_t DzFromBrcBrc(uint8_t, uint8_t);  /* MEMORY_BATTLE:0x4ca8 */
int32_t DpFromPtokBrcToBrc(TOK *, uint8_t, uint8_t, TOK *, int16_t);  /* MEMORY_BATTLE:0x4d2e */
int16_t DxyMoveTokTo(TOK *, int16_t, uint16_t);  /* MEMORY_BATTLE:0x5f18 */
int16_t FHullHasBombs(HUL *);  /* MEMORY_BATTLE:0x1ec2 */

#endif /* BATTLE_H_ */
