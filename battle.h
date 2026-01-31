#ifndef BATTLE_H_
#define BATTLE_H_

#include "strings.h"
#include "types.h"

/* globals */
extern uint8_t rgbrcStart[136]; /* MEMORY_BATTLE:0x0000 */

/* functions */
int16_t FFleetHasTeeth(FLEET *lpfl);                                                                                          /* MEMORY_BATTLE:0x1fbe */
void    DropSalvage(THING **plpth, int32_t *rgwtMinerals, int16_t iplr, POINT *ppt);                                          /* MEMORY_BATTLE:0x24dc */
void    CheckTarget(TOK *ptok, FLEET *lpfl, int16_t ishdef);                                                                  /* MEMORY_BATTLE:0x212a */
void    CreateSalvage(FLEET *pfl, THING **plpth);                                                                             /* MEMORY_BATTLE:0x7ee8 */
void    DoBattles(int16_t fPostMovement);                                                                                     /* MEMORY_BATTLE:0x3a26 */
void    RandomizeTokOrder(void);                                                                                              /* MEMORY_BATTLE:0x44d4 */
int16_t InitFromHuldef(HUL *lphul, int16_t *ppctBC);                                                                          /* MEMORY_BATTLE:0x3cba */
int32_t ScoreGuessBattleDamage(TOK *ptokSrc, uint8_t brc, int16_t fPrimary, uint16_t grfAttack);                              /* MEMORY_BATTLE:0x598c */
int16_t FAttackPlayer(FLEET *lpfl, int16_t iplr);                                                                             /* MEMORY_BATTLE:0xae06 */
void    CheckInitiative(TOK *ptok);                                                                                           /* MEMORY_BATTLE:0x3e68 */
int16_t FDeleteBattlePlan(int16_t iplan, int16_t fWarn);                                                                      /* MEMORY_BATTLE:0x1706 */
void    RegenShield(TOK *ptok);                                                                                               /* MEMORY_BATTLE:0x3c16 */
int16_t FDumpCargo(FLEET *lpfl);                                                                                              /* MEMORY_BATTLE:0x234a */
int32_t ScoreFromGiveAndTakeAndTactic(int32_t dpGive, int32_t dpTake, int16_t mdTactic);                                      /* MEMORY_BATTLE:0x5e34 */
int16_t FAttack(int16_t itokAttacker, int16_t init, BTLREC *lpbtlrec, uint16_t grfAttack);                                    /* MEMORY_BATTLE:0x69ac */
int16_t FHullHasTeeth(HUL *lphul);                                                                                            /* MEMORY_BATTLE:0x2072 */
int16_t FFleetHasBombs(FLEET *lpfl);                                                                                          /* MEMORY_BATTLE:0x1e16 */
int16_t DxyFromSpdRound(uint16_t spd, int16_t iRound);                                                                        /* MEMORY_BATTLE:0x8b28 */
int32_t CTorpHit(int32_t cTorpBase, TOK *ptok, int16_t pctBase, int16_t pctBC);                                               /* MEMORY_BATTLE:0x6790 */
int16_t FCanKillTok(TOK *ptok1, TOK *ptok2);                                                                                  /* MEMORY_BATTLE:0x391e */
int16_t FIsTargetOfMdTarget(TOK *ptok, int16_t mdTarget);                                                                     /* MEMORY_BATTLE:0x587a */
int16_t SpdOfShip(FLEET *lpfl, int16_t ishdef, TOK *ptok, int16_t fDumpCargo, SHDEF *lpshdef);                                /* MEMORY_BATTLE:0x339c */
void    DoBombing(void);                                                                                                      /* MEMORY_BATTLE:0xaefa */
void    InitializeBoard(FLEET *lpfl, int16_t ibrc, uint16_t grfPlayer, uint8_t *pinit, int16_t *pinitMin, int16_t *pinitMac); /* MEMORY_BATTLE:0x45b4 */
int16_t DzMoveRangeToConsider(TOK *ptok, uint16_t grfAttack, uint8_t *pbrc);                                                  /* MEMORY_BATTLE:0x5312 */
int16_t FFuelTanker(SHDEF *lpshdef);                                                                                          /* MEMORY_BATTLE:0x20f6 */
int16_t FDoCoolBattle(FLEET *lpfl, int16_t cplr, uint16_t *rggrfAttack, uint16_t grfPlayer, uint16_t grfSpectator);           /* MEMORY_BATTLE:0x8bcc */
void    CheckWeapons(TOK *ptok, int16_t *pfDampeningField, uint8_t *pinit);                                                   /* MEMORY_BATTLE:0x3ec2 */
SHDEF  *LpshdefFromTok(TOK *ptok); /* RETFAR */                                                                               /* MEMORY_BATTLE:0x388e */
int16_t CplrBattle(FLEET *lpfl, uint16_t *rggrfAttack, uint16_t *pgrfPlayer, uint16_t *pgrfSpectator);                        /* MEMORY_BATTLE:0x2952 */
void    SpankTheCheaters(void);                                                                                               /* MEMORY_BATTLE:0x192a */
int16_t ITechLearnATech(int16_t iplr, int16_t x, int16_t y, MessageId idm, uint16_t *piGoto);                                 /* MEMORY_BATTLE:0x9918 */
int16_t FDamageTok(TOK *ptok, int16_t itok, int32_t *pdpBeam, int32_t dpTorp, uint16_t grfWeapon, int16_t fShieldsOnly,
                   int32_t *pcTorp);                                                          /* MEMORY_BATTLE:0x81d4 */
void    KillShips(TOK *ptok, int16_t cshKill, int16_t ishdef, FLEET *lpfl, int16_t fFallout); /* MEMORY_BATTLE:0x7cde */
void SendBattleMessages(FLEET *lpflBtl, int16_t cplr, int16_t idBtl, uint16_t *rgPlrLosses, int16_t grfPlayer, int16_t cShipsInvolved, int16_t cShdefsInvolved,
                        uint16_t grfSpectator);                                                                /* MEMORY_BATTLE:0x9c0e */
int16_t FDoesPrimaryTargetTypeExist(TOK *ptok, uint16_t grfAttack);                                            /* MEMORY_BATTLE:0x56d8 */
int16_t DzFromBrcBrc(uint8_t brc1, uint8_t brc2);                                                              /* MEMORY_BATTLE:0x4ca8 */
int32_t DpFromPtokBrcToBrc(TOK *ptok, uint8_t brcSrc, uint8_t brcTarget, TOK *ptokTarget, int16_t fProximity); /* MEMORY_BATTLE:0x4d2e */
int16_t DxyMoveTokTo(TOK *ptok, int16_t spdMove, uint16_t grfAttack);                                          /* MEMORY_BATTLE:0x5f18 */
int16_t FHullHasBombs(HUL *lphul);                                                                             /* MEMORY_BATTLE:0x1ec2 */

#ifdef _WIN32

INT_PTR CALLBACK BattlePlansDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_BATTLE:0x0652 */
INT_PTR CALLBACK NewPlanNameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_BATTLE:0x04ce */
INT_PTR CALLBACK RelationsDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);   /* MEMORY_BATTLE:0x0088 */

#endif /* _WIN32 */

#endif /* BATTLE_H_ */
