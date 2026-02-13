
#include "globals.h"
#include "types.h"

#include "battle.h"
#include "build.h"
#include "memory.h"
#include "msg.h"
#include "parts.h"
#include "planet.h"
#include "race.h"
#include "research.h"
#include "ship.h"
#include "ship2.h"
#include "thing.h"
#include "util.h"
#include "utilgen.h"

#define BrcFromXY(x, y) ((uint8_t)((((y) & 0x0F) << 4) | ((x) & 0x0F)))
#define YFromBrc(brc)   (((uint8_t)(brc)) >> 4)
#define XFromBrc(brc)   (((uint8_t)(brc)) & 0x0F)

// MEMORY_BATTLE:0x0000
// Flat concatenation of starting BRCs by player count (n = 1..16).
// Indexing in code: base = cplr * (cplr - 1) / 2;  brc = rgbrcStart[ base + side ].
uint8_t rgbrcStart[] = {
    /* n= 1 */ BrcFromXY(4, 4),

    /* n= 2 */ BrcFromXY(1, 4),
    BrcFromXY(8, 5),

    /* n= 3 */ BrcFromXY(4, 1),
    BrcFromXY(8, 8),
    BrcFromXY(1, 8),

    /* n= 4 */ BrcFromXY(1, 1),
    BrcFromXY(8, 8),
    BrcFromXY(1, 8),
    BrcFromXY(8, 1),

    /* n= 5 */ BrcFromXY(4, 1),
    BrcFromXY(6, 8),
    BrcFromXY(1, 4),
    BrcFromXY(8, 4),
    BrcFromXY(2, 8),

    /* n= 6 */ BrcFromXY(1, 4),
    BrcFromXY(8, 5),
    BrcFromXY(2, 8),
    BrcFromXY(7, 1),
    BrcFromXY(6, 8),
    BrcFromXY(3, 1),

    /* n= 7 */ BrcFromXY(1, 1),
    BrcFromXY(1, 5),
    BrcFromXY(2, 8),
    BrcFromXY(6, 8),
    BrcFromXY(8, 6),
    BrcFromXY(8, 2),
    BrcFromXY(5, 1),

    /* n= 8 */ BrcFromXY(1, 3),
    BrcFromXY(1, 6),
    BrcFromXY(3, 8),
    BrcFromXY(6, 8),
    BrcFromXY(8, 6),
    BrcFromXY(8, 3),
    BrcFromXY(6, 1),
    BrcFromXY(3, 1),

    /* n= 9 */ BrcFromXY(1, 3),
    BrcFromXY(8, 6),
    BrcFromXY(3, 8),
    BrcFromXY(6, 1),
    BrcFromXY(1, 6),
    BrcFromXY(8, 3),
    BrcFromXY(6, 8),
    BrcFromXY(3, 1),
    BrcFromXY(4, 4),

    /* n=10 */ BrcFromXY(2, 1),
    BrcFromXY(5, 1),
    BrcFromXY(8, 1),
    BrcFromXY(1, 4),
    BrcFromXY(8, 4),
    BrcFromXY(4, 5),
    BrcFromXY(1, 7),
    BrcFromXY(8, 7),
    BrcFromXY(3, 8),
    BrcFromXY(6, 8),

    /* n=11 */ BrcFromXY(1, 3),
    BrcFromXY(8, 6),
    BrcFromXY(3, 8),
    BrcFromXY(6, 1),
    BrcFromXY(1, 6),
    BrcFromXY(8, 3),
    BrcFromXY(6, 8),
    BrcFromXY(3, 1),
    BrcFromXY(3, 4),
    BrcFromXY(6, 3),
    BrcFromXY(6, 6),

    /* n=12 */ BrcFromXY(1, 4),
    BrcFromXY(8, 5),
    BrcFromXY(2, 8),
    BrcFromXY(7, 1),
    BrcFromXY(6, 8),
    BrcFromXY(3, 1),
    BrcFromXY(1, 6),
    BrcFromXY(8, 3),
    BrcFromXY(1, 2),
    BrcFromXY(4, 8),
    BrcFromXY(5, 1),
    BrcFromXY(8, 7),

    /* n=13 */ BrcFromXY(1, 1),
    BrcFromXY(1, 3),
    BrcFromXY(1, 5),
    BrcFromXY(1, 7),
    BrcFromXY(3, 1),
    BrcFromXY(5, 1),
    BrcFromXY(7, 1),
    BrcFromXY(8, 3),
    BrcFromXY(8, 5),
    BrcFromXY(3, 8),
    BrcFromXY(5, 8),
    BrcFromXY(7, 8),
    BrcFromXY(4, 4),

    /* n=14 */ BrcFromXY(1, 1),
    BrcFromXY(1, 3),
    BrcFromXY(1, 5),
    BrcFromXY(1, 7),
    BrcFromXY(2, 8),
    BrcFromXY(4, 8),
    BrcFromXY(6, 8),
    BrcFromXY(8, 8),
    BrcFromXY(8, 6),
    BrcFromXY(8, 4),
    BrcFromXY(8, 2),
    BrcFromXY(7, 1),
    BrcFromXY(5, 1),
    BrcFromXY(3, 1),

    /* n=15 */ BrcFromXY(1, 1),
    BrcFromXY(1, 3),
    BrcFromXY(1, 5),
    BrcFromXY(1, 7),
    BrcFromXY(2, 8),
    BrcFromXY(4, 8),
    BrcFromXY(6, 8),
    BrcFromXY(8, 8),
    BrcFromXY(8, 6),
    BrcFromXY(8, 4),
    BrcFromXY(8, 2),
    BrcFromXY(7, 1),
    BrcFromXY(5, 1),
    BrcFromXY(3, 1),
    BrcFromXY(4, 4),

    /* n=16 */ BrcFromXY(1, 1),
    BrcFromXY(1, 3),
    BrcFromXY(1, 5),
    BrcFromXY(1, 7),
    BrcFromXY(2, 8),
    BrcFromXY(4, 8),
    BrcFromXY(6, 8),
    BrcFromXY(8, 8),
    BrcFromXY(8, 6),
    BrcFromXY(8, 4),
    BrcFromXY(8, 2),
    BrcFromXY(7, 1),
    BrcFromXY(5, 1),
    BrcFromXY(3, 1),
    BrcFromXY(3, 3),
    BrcFromXY(6, 6),
};

/* functions */
int16_t FFleetHasTeeth(FLEET *lpfl) {
    int16_t ishdef;

    for (ishdef = 0; ishdef <= cShdefMax; ishdef++) {
        if (lpfl->rgcsh[ishdef] != 0 && FHullHasTeeth(&rglpshdef[lpfl->iplr][ishdef].hul) != 0 && rglpshdef[lpfl->iplr][ishdef].det == detAll)
            return 1;
    }
    return 0;
}

void DropSalvage(THING **plpth, int32_t *rgwtMinerals, int16_t iplr, STARSPOINT *ppt) {
    int32_t wtTotal;
    int32_t wt;
    int16_t i;
    THING  *lpth;

    /* TODO: implement */
}

void CheckTarget(TOK *ptok, FLEET *lpfl, int16_t ishdef) {
    int16_t  iplr;
    BTLPLAN *lpbtlplan;
    int16_t  ibp;
    SHDEF   *lpshdef;

    iplr = (int16_t)(lpfl->id >> 9) & 0xf;
    lpshdef = &rglpshdef[iplr][ishdef];

    /* Classify ship type -> mdTarget0 */
    if (FHullHasTeeth(&lpshdef->hul)) {
        ptok->mdTarget0 = mdTargetArmedShips;
    } else if (FHullHasBombs(&lpshdef->hul)) {
        ptok->mdTarget0 = mdTargetBombersFreighters;
    } else if (FFuelTanker(lpshdef)) {
        ptok->mdTarget0 = mdTargetFuelTransports;
    } else if (WtMaxShdefStat(lpshdef, grStatCargo) == 0) {
        ptok->mdTarget0 = mdTargetUnarmedShips;
    } else {
        ptok->mdTarget0 = mdTargetFreighters;
    }

    /* Copy battle plan targets/tactic */
    lpbtlplan = &rglpbtlplan[iplr][lpfl->iplan];
    ptok->mdTarget1 = lpbtlplan->mdTarget1;
    ptok->mdTarget2 = lpbtlplan->mdTarget2;
    if (ptok->mdTarget0 == mdTargetArmedShips) {
        ptok->mdTactic = lpbtlplan->mdTactic;
    } else {
        ptok->mdTactic = mdTacticDisengage;
    }
    if (ptok->mdTactic == mdTacticDisengage) {
        ptok->dzDis = 7;
    }
}

void CreateSalvage(FLEET *pfl, THING **plpth) {
    int32_t wtTotal;
    SHDEF  *lpshdefT;
    PLANET *lppl;
    int16_t i;
    int32_t rgwtMinerals[3];
    int16_t j;
    int16_t fBleeding;
    SHDEF   shdefT;

    /* TODO: implement */
}

void DoBattles(int16_t fPostMovement) {
    int16_t  cplr;
    int16_t  ifl;
    FLEET   *lpfl;
    uint16_t grfSpectator;
    uint16_t grfPlayer;
    uint16_t rggrfAttack[16];

    LinkFleets(fPostMovement);
    vrgtok = LpAlloc(sizeof(TOK) * 256, htMisc);
    vlpwtCargo = LpAlloc(512, htMisc);

    FORFLEETS(lpfl, ifl) {
        lpfl->fBombed = 0;
        if (!lpfl->fDead && !lpfl->fDone && lpfl->lpflNext != NULL) {
            cplr = CplrBattle(lpfl, rggrfAttack, &grfPlayer, &grfSpectator);
            if (cplr != -1 && cplr != 0) {
                FDoCoolBattle(lpfl, cplr, rggrfAttack, grfPlayer, grfSpectator);
            }
        }
    }

    FreeLp(vlpwtCargo, htMisc);
    FreeLp(vrgtok, htMisc);
    vlpwtCargo = NULL;
    vrgtok = NULL;

    if (lpbBattleT != NULL) {
        lpbBattleT[0] = 0xff;
        lpbBattleT[1] = 0xff;
        FreeLp(lpbBattleT, htBattle);
        lpbBattleT = NULL;
    }
    if (lpbBattleCur != NULL) {
        lpbBattleCur[0] = 0xff;
        lpbBattleCur[1] = 0xff;
    }
    DoBombing();
}

void RandomizeTokOrder(void) {
    TOK     tok;
    int16_t itokSwap;
    int16_t itok;

    for (itok = 0; itok < vctok; itok++) {
        itokSwap = Random(vctok - itok) + itok;
        if (itokSwap != itok) {
            tok = vrgtok[itokSwap];
            vrgtok[itokSwap] = vrgtok[itok];
            vrgtok[itok] = tok;
        }
    }
}

int16_t InitFromHuldef(HUL *lphul, int16_t *ppctBC) {
    int16_t ihs;
    int16_t i;
    int16_t pct;
    int16_t initBase;
    int16_t cbc;
    int16_t pctBC;
    PART    part;

    pct = 0;
    cbc = 0;
    HULDEF *lphuldef = LphuldefFromId(lphul->ihuldef);

    for (ihs = 0; ihs < (int16_t)lphul->chs; ihs++) {
        part.hs = lphul->rghs[ihs];
        if (part.hs.cItem != 0) {
            if ((part.hs.grhst & hstSpecialE) == hstNone) {
                if ((part.hs.grhst & hstBeam) != hstNone && part.hs.iItem == ibeamMultiContainedMunition) {
                    for (i = 0; i < (int16_t)part.hs.cItem; i++) {
                        pct = pct + ((100 - pct) * 10) / 100;
                    }
                }
            } else {
                uint16_t iItem = part.hs.iItem;
                if (iItem == ispecialEBattleComputer || iItem == ispecialEBattleSuperComputer || iItem == ispecialEBattleNexus) {
                    FLookupPart(&part);
                    cbc = cbc + (part.hs.iItem - 4) * (int16_t)part.hs.cItem;
                    for (i = 0; i < (int16_t)part.hs.cItem; i++) {
                        pct = pct + ((100 - pct) * part.pspecial->grAbility) / 100;
                    }
                }
            }
        }
    }
    if (ppctBC != NULL) {
        *ppctBC = pct;
    }
    initBase = (int16_t)lphuldef->init + cbc;
    if (initBase > 63) {
        initBase = 63;
    }
    return initBase;
}

int32_t ScoreGuessBattleDamage(TOK *ptokSrc, uint8_t brc, int16_t fPrimary, uint16_t grfAttack) {
    int16_t iBest;
    int16_t dMoves;
    int16_t rgy[2];
    TOK    *ptok;
    int16_t yEnemy;
    int16_t dzEnemy;
    int32_t dpGivenBest;
    int32_t dpTakenBest;
    int16_t y;
    int32_t dpTakenTotal;
    int32_t dpGivenCur;
    int16_t i;
    int16_t xEnemy;
    int16_t yCur;
    int32_t dpTaken;
    int32_t scoreThemBest;
    int32_t scoreThem;
    int16_t dzCur;
    int16_t rgx[2];
    uint8_t brcEnemy;
    int32_t dpGiven;
    int16_t dMax;
    int32_t scoreUs;
    uint8_t iplrSrc;
    int16_t fWeAttack;
    int16_t xCur;
    int16_t x;
    int16_t dMin;
    int16_t itok;

    /* TODO: implement */
    return 0;
}

int16_t FAttackPlayer(FLEET *lpfl, int16_t iplr) {
    int16_t  iplrCur;
    uint16_t iplrAttack;

    iplrCur = lpfl->iPlayer;
    iplrAttack = rglpbtlplan[iplrCur][lpfl->iplan].iplrAttack;

    if (iplrAttack == iplrAttackNobody) {
        return 0;
    } else if (iplrAttack == iplrAttackEnemies) {
        return rgplr[iplrCur].rgmdRelation[iplr] == 2;
    } else if (iplrAttack == iplrAttackNeutralsEnemies) {
        return rgplr[iplrCur].rgmdRelation[iplr] != 1;
    } else if (iplrAttack == iplrAttackEveryone) {
        return 1;
    } else {
        return iplr == iplrAttack - iplrAttackPlayer;
    }
}

void CheckInitiative(TOK *ptok) {
    SHDEF  *lpshdef;
    int16_t pctBC;

    lpshdef = LpshdefFromTok(ptok);
    idPlayer = (int16_t)ptok->iplr;
    ptok->initBase = (uint8_t)InitFromHuldef(&lpshdef->hul, &pctBC);
    idPlayer = -1;
    ptok->pctBC = (uint8_t)pctBC;
}

int16_t FDeleteBattlePlan(int16_t iplan, int16_t fWarn) {
    int16_t fFoundBigger;
    int16_t iflMac;
    int16_t i;
    FLEET  *lpfl;
    char   *sz;
    int16_t result;

    fFoundBigger = false;
LCommit:
    do {
        for (iflMac = 0; iflMac < cFleet; iflMac++) {
            lpfl = rglpfl[iflMac];
            if (lpfl == NULL)
                break;
            if (lpfl->iPlayer > idPlayer)
                break;
            if (lpfl->iPlayer < idPlayer)
                continue;

            if (lpfl->iplan > (uint8_t)iplan) {
                if (fWarn == 0) {
                    lpfl->iplan--;
                } else {
                    fFoundBigger = true;
                }
            } else if (lpfl->iplan == (uint8_t)iplan) {
                if (fWarn != 0) {
                    sz = PszFormatIds(idsCurrentlyHaveFleetsUsingBattlePlanIf, NULL);
                    result = AlertSz(sz, 0x31);
                    if (result == 2)
                        return 0;
                    fWarn = 0;
                    goto LCommit;
                }
                lpfl->iplan--;
            }
        }

        if (fWarn == 0 || !fFoundBigger) {
            rgcbtlplan[idPlayer]--;
            for (i = iplan; i < (int16_t)rgcbtlplan[idPlayer]; i++) {
                rglpbtlplan[idPlayer][i] = rglpbtlplan[idPlayer][i + 1];
                rglpbtlplan[idPlayer][i].iplan = i;
            }
            return 1;
        }
        fWarn = 0;
    } while (true);
}

void RegenShield(TOK *ptok) {
    int32_t dpMax;
    int32_t dpNew;
    SHDEF  *lpshdef;

    lpshdef = LpshdefFromTok(ptok);
    dpMax = DpShieldOfShdef(lpshdef, ptok->iplr);

    if (ptok->dpShield != 0) {
        dpNew = dpMax / 10 + (uint32_t)ptok->dpShield;
        if (dpNew > dpMax)
            dpNew = dpMax;
        ptok->dpShield = (uint16_t)dpNew;
    }
}

int16_t FDumpCargo(FLEET *lpfl) {
    STARSPOINT pt;
    PLANET    *lppl;
    int16_t    i;

    /* Check if fleet has any minerals */
    for (i = 0; i < 3; i++) {
        if (lpfl->rgwtMin[i] != 0)
            break;
    }
    if (i >= 3)
        return 0;

    /* Check if battle plan says to dump cargo */
    int16_t iplr = (int16_t)(lpfl->id >> 9) & 0xf;
    if (!rglpbtlplan[iplr][lpfl->iplan].fDumpCargo)
        return 0;

    if (lpfl->idPlanet == -1) {
        pt.x = lpfl->pt.x;
        pt.y = lpfl->pt.y;
        DropSalvage(&lpthBattle, lpfl->rgwtMin, iplr, &pt);
    } else {
        lppl = LpplFromId(lpfl->idPlanet);
        for (i = 0; i < 3; i++) {
            lppl->rgwtMin[i] += lpfl->rgwtMin[i];
        }
    }
    for (i = 0; i < 3; i++) {
        lpfl->rgwtMin[i] = 0;
    }
    return 1;
}

int32_t ScoreFromGiveAndTakeAndTactic(int32_t dpGive, int32_t dpTake, BattleTactic mdTactic) {
    switch (mdTactic) {
    case mdTacticDisengage:
    case mdTacticMinDamageToSelf:
        break;
    case mdTacticDisengageIfChallenged:
    case mdTacticMaxDamage:
        dpTake = -dpGive;
        break;
    case mdTacticMaxNetDamage:
    case mdTacticMaxDamageRatio:
        if (-dpGive != 0) {
            dpTake = (int32_t)((uint32_t)(-dpGive) * 100u) / (dpTake + 1);
            if (dpTake > -1)
                dpTake = -1;
        }
        break;
    default:
        dpTake = 0;
        break;
    }
    return dpTake;
}

int16_t FAttack(int16_t itokAttacker, int16_t init, BTLREC *lpbtlrec, uint16_t grfAttack) {
    int32_t  dpShieldLeft;
    int16_t  dz;
    SHDEF   *lpshdefE;
    int32_t  dpArmorLeft;
    int32_t  dpSingle;
    int32_t  scoreBest;
    TOK     *ptok;
    int16_t  ctokDamaged;
    int16_t  itokTarget;
    int32_t  dpMain;
    int32_t  score;
    int16_t  fSetItok;
    int16_t  dxRangeCur;
    int16_t  ihs;
    int32_t  cTorpMiss;
    int32_t  cTorpFire;
    int32_t  cTorpsLeft;
    int16_t  i;
    int32_t  cTorpBase;
    uint16_t grfWeapon;
    int16_t  cItem;
    int32_t  pctHit;
    TOK     *ptokTarget;
    SHDEF   *lpshdef;
    int32_t  lValue;
    int32_t  dpT;
    HUL     *lphul;
    int32_t  cTorpHit;
    int16_t  fPrimary;
    int32_t  dp;
    int16_t  itok;
    int32_t  dpCol;
    TOK     *ptokE;
    PART     part;
    int32_t  nds;
    int32_t  dpShieldCur;
    int16_t  fCapMissile;
    int32_t  dpHitArmor;
    int32_t  nts;
    int32_t  ntk;

    ctokDamaged = 0;
    dxRangeCur = 0;
    fSetItok = 0;

    ptok = &vrgtok[itokAttacker];

    lpshdef = LpshdefFromTok(ptok);
    lphul = &lpshdef->hul;

    for (ihs = 0; ihs < lphul->chs; ihs++) {
        if (lphul->rghs[ihs].grhst & hstWeapon && lphul->rghs[ihs].cItem) {
            part.hs = lphul->rghs[ihs];
            idPlayer = (int16_t)ptok->iplr;
            FLookupPart(&part);
            idPlayer = -1;
            cItem = lphul->rghs[ihs].cItem;
            i = part.pbeam->init + ptok->initBase;
            if (i >= 64)
                i = 63;
            if (i != init)
                continue;

            dxRangeCur = part.pbeam->dRangeMax + (ptok->grobj == grobjPlanet);

            // Gattling weapons hit all
            if (part.hs.grhst == hstBeam && (part.pbeam->grfAbilities & 2)) {
                dp = (int32_t)part.pbeam->dp * (int32_t)cItem * ptok->csh;

                if (part.pbeam->dp >= 200)
                    grfWeapon = bitFBeamHigh;
                else
                    grfWeapon = bitFBeamLow;

                if (ptok->pctCap)
                    dp = dp * ptok->pctCap / 100;

                dpT = dp;

                for (ptokE = vrgtok, itok = 0; itok < vctok; ptokE++, itok++) {
                    if (!ptokE->fActive || ptokE->iplr == ptok->iplr || !(grfAttack & (1 << ptokE->iplr)))
                        continue;

                    if (DzFromBrcBrc(ptokE->brc, ptok->brc) > dxRangeCur)
                        continue;

                    if (!FIsTargetOfMdTarget(ptokE, ptok->mdTarget1) && !FIsTargetOfMdTarget(ptokE, ptok->mdTarget2))
                        continue;

                    if (ptokE->pctBeamDef < 100)
                        dp = dp * ptokE->pctBeamDef / 100L;

                    if (FDamageTok(ptokE, itok, &dp, 0, grfWeapon, part.pbeam->grfAbilities & 1, NULL)) {
                        if (!fSetItok) {
                            fSetItok = fTrue;
                            lpbtlrec->itokAttack = itok;
                        }
                        ctokDamaged++;
                    }
                    dp = dpT;
                }

                continue;
            }

            if (part.hs.grhst == hstBeam) {
                dpMain = (int32_t)part.pbeam->dp * (int32_t)cItem * ptok->csh;
                cTorpsLeft = 0;
            } else {
                dpMain = 0;
                cTorpsLeft = (int32_t)cItem * ptok->csh;
            }

        LFindAnotherTarget:
            fPrimary = fTrue;

            while (fPrimary >= 0) {
                scoreBest = 0;
                ptokTarget = NULL;

                for (ptokE = vrgtok, itok = 0; itok < vctok; ptokE++, itok++) {
                    if (!ptokE->fActive || ptokE->iplr == ptok->iplr || !(grfAttack & (1 << ptokE->iplr)))
                        continue;

                    if (DzFromBrcBrc(ptokE->brc, ptok->brc) > dxRangeCur)
                        continue;

                    if (!FIsTargetOfMdTarget(ptokE, fPrimary ? ptok->mdTarget1 : ptok->mdTarget2))
                        continue;

                    lpshdefE = LpshdefFromTok(ptokE);
                    lValue = ((int32_t)lpshdefE->hul.resCost + lpshdefE->hul.rgwtOreCost[Boranium]) * (int32_t)ptokE->csh;
                    if (lValue < 100000L)
                        lValue *= 100;
                    else
                        lValue = 10000000L;

                    dpSingle = lpshdefE->hul.dp;
                    dpShieldLeft = (int32_t)ptokE->dpShield * (int32_t)ptokE->csh;
                    dpArmorLeft = dpSingle * (int32_t)ptokE->csh;
                    if (ptokE->dv.dp)
                        dpArmorLeft -= dpSingle * (int32_t)ptokE->dv.pctDp / 10L * (int32_t)ptokE->dv.pctSh / 10L * (int32_t)ptokE->csh / 500L;
                    if (dpArmorLeft <= 0)
                        dpArmorLeft = 1;

                    switch (part.hs.grhst) {
                    default:
                        // shouldn't happen
                        Assert(0);
                    case hstBeam:
                        if (ptokE->pctBeamDef < 100)
                            lValue = lValue * (int32_t)ptokE->pctBeamDef / 100L;

                        if ((part.pbeam->grfAbilities & 1)) {
                            if (dpShieldLeft <= 0)
                                score = 0;
                            else
                                score = (lValue * 100 + dpShieldLeft - 1) / dpShieldLeft;
                        } else {
                            score = lValue * 100 / (dpArmorLeft + dpShieldLeft + 1);
                            if (score <= 0)
                                score = 1;
                        }
                        break;
                    case hstTorp:
                        pctHit = part.ptorp->dHitChance;
                        if (ptok->pctBC >= ptokE->pctJam)
                            pctHit += (100 - pctHit) * (ptok->pctBC - ptokE->pctJam) / 100;
                        else
                            pctHit -= pctHit * (ptokE->pctJam - ptok->pctBC) / 100;

                        if (pctHit > 0) {
                            int32_t nts;
                            int32_t nds;
                            int32_t ntk;
                            bool    fCapMissile = part.hs.iItem >= itorpJihadMissile && part.hs.iItem <= itorpArmageddonMissile;

                            if (dpArmorLeft < 100000L)
                                nts = dpArmorLeft * 100L * 2 / pctHit;
                            else
                                nts = dpArmorLeft / pctHit * 200L;

                            if (dpShieldLeft < 100000)
                                nds = dpShieldLeft * 100L / ((pctHit / 2) + ((100 - pctHit) / 8));
                            else
                                nds = dpShieldLeft / ((pctHit / 2) + ((100 - pctHit) / 8)) * 100L;

                            ntk = (dpArmorLeft - (nds * pctHit / 200)) * 100L / (pctHit * (1 + fCapMissile));

                            score = min(nts, nds + ntk);
                            if (score > 0) {
                                score = lValue / score;
                                if (score <= 0)
                                    score = 1;
                            } else
                                score = 0;
                        } else
                            score = 0;

                        break;
                    }

                    if (score > scoreBest) {
                        scoreBest = score;
                        ptokTarget = ptokE;
                        itokTarget = itok;
                    }
                }

                if (ptokTarget != NULL)
                    break;

                fPrimary--;
            }

            if (ptokTarget == NULL)
                continue;

            dz = DzFromBrcBrc(ptokTarget->brc, ptok->brc);

            switch (part.hs.grhst) {
            case hstBeam:
                dp = dpMain;

                if (ptok->pctCap)
                    dp = dp * ptok->pctCap / 100;

                if (ptokTarget->pctBeamDef < 100)
                    dp = dp * ptokTarget->pctBeamDef / 100L;

                if (dz > 0 && part.pbeam->dRangeMax > 0)
                    dp = dp * (100L - 10L * dz / part.pbeam->dRangeMax) / 100L;

                if (part.pbeam->dp >= 200)
                    grfWeapon = bitFBeamHigh;
                else
                    grfWeapon = bitFBeamLow;

                dpT = dp;
                if (FDamageTok(ptokTarget, itokTarget, &dp, 0, grfWeapon, part.pbeam->grfAbilities & 1, NULL)) {
                    if (!fSetItok) {
                        lpbtlrec->itokAttack = itokTarget;
                        fSetItok = fTrue;
                    }
                    ctokDamaged++;
                }

                if (dp > 0 && dpT > 0) {
                    if (dpMain < 65536L && dp < 65536L)
                        lValue = dpMain * dp / dpT;
                    else
                        lValue = (int32_t)((double)dpMain * (double)dp / dpT);

                    dpMain = min(dpMain - 1, lValue);
                } else
                    dpMain = 0;

                break;

            case hstTorp:
                if (cTorpsLeft <= 0)
                    break;

                grfWeapon = bitFTorp;
                cTorpBase = cTorpsLeft;
                cTorpHit = CTorpHit(cTorpBase, ptokTarget, part.ptorp->dHitChance, ptok->pctBC);

                lpshdefE = LpshdefFromTok(ptokTarget);
                dpSingle = lpshdefE->hul.dp;
                dpShieldLeft = (int32_t)ptokTarget->dpShield * (int32_t)ptokTarget->csh;
                dpArmorLeft = dpSingle * (int32_t)ptokTarget->csh;
                if (ptokTarget->dv.dp)
                    dpArmorLeft -= dpSingle * (int32_t)ptokTarget->dv.pctDp / 10L * (int32_t)ptokTarget->dv.pctSh / 10L * (int32_t)ptokTarget->csh / 500L;

                dp = part.ptorp->dp;

                if (part.hs.iItem >= itorpJihadMissile && part.hs.iItem <= itorpArmageddonMissile) {
                    if (dpShieldLeft <= 0)
                        dp *= 2;
                    grfWeapon |= bitFMissile;
                }

                i = ptokTarget->csh;
                if (i >= cTorpBase || cTorpHit * dp <= dpArmorLeft) // Fire them all!
                {
                    cTorpFire = cTorpHit;
                    cTorpMiss = cTorpBase - cTorpHit;
                } else {
                    for (; i <= cTorpBase; i++) {
                        int32_t dpHitArmor;
                        int32_t dpShieldCur;

                        cTorpFire = (i * cTorpHit + cTorpBase - 1) / cTorpBase;
                        cTorpMiss = i - cTorpFire;

                        dpShieldCur = dpShieldLeft - cTorpMiss * dp / 8;
                        if (dpShieldCur < 0)
                            dpShieldCur = 0;
                        dpShieldCur -= cTorpFire * dp / 2;

                        dpHitArmor = cTorpFire * dp / 2;
                        if (dpShieldCur < 0)
                            dpHitArmor -= dpShieldCur;

                        if (dpHitArmor >= dpArmorLeft)
                            break;
                    }
                }

                dpCol = cTorpMiss * dp / 8;
                if (dpCol > 0) {
                    if (FDamageTok(ptokTarget, itokTarget, &dpCol, 0, grfWeapon | bitFDeflected, fTrue, NULL))
                        ctokDamaged++;
                }

                dpT = cTorpFire * dp / 2;
                cTorpBase = cTorpFire + cTorpMiss;

                FDamageTok(ptokTarget, itokTarget, &dpT, dpT, grfWeapon, 0, &cTorpBase);
                ctokDamaged++;

                if (!fSetItok) {
                    fSetItok = fTrue;
                    lpbtlrec->itokAttack = itokTarget;
                }

                cTorpsLeft -= (cTorpFire + cTorpMiss);
                break;
            }

            if (dpMain > 0 || cTorpsLeft > 0)
                goto LFindAnotherTarget;
        }
    }

    lpbtlrec->ctok = ctokDamaged;
    return ctokDamaged != 0;
}

int16_t FHullHasTeeth(HUL *lphul) {
    HS     *lphs;
    int16_t ihs;

    lphs = lphul->rghs;
    for (ihs = 0; ihs < (int16_t)lphul->chs; ihs++) {
        if ((lphs->grhst & (hstTorp | hstBeam)) != 0 && lphs->cItem != 0) {
            return 1;
        }
        lphs++;
    }
    return 0;
}

int16_t FFleetHasBombs(FLEET *lpfl) {
    HUL    *lphul;
    int16_t ishdef;

    for (ishdef = 0; ishdef < cShdefMax; ishdef++) {
        if (lpfl->rgcsh[ishdef] != 0) {
            int16_t iplr = (int16_t)(lpfl->id >> 9) & 0xf;
            lphul = &rglpshdef[iplr][ishdef].hul;
            LphuldefFromId(lphul->ihuldef);
            if (FHullHasBombs(lphul))
                return 1;
        }
    }
    return 0;
}

int16_t DxyFromSpdRound(uint16_t spd, int16_t iRound) {
    int16_t  dxy;
    uint16_t rem;

    dxy = (int16_t)((spd + 2) / 4);
    rem = spd & 3;

    if (rem == 0) {
        dxy = (int16_t)(dxy + (int16_t)((iRound & 1) == 0));
    } else if (rem == 1) {
        dxy = (int16_t)(dxy + (int16_t)((iRound & 3) != 2));
    } else if (rem == 3) {
        dxy = (int16_t)(dxy + (int16_t)((iRound & 3) == 0));
    }

    return dxy;
}

int32_t CTorpHit(int32_t cTorpBase, TOK *ptok, int16_t pctBase, int16_t pctBC) {
    int32_t pctJam;
    int16_t i;
    int32_t pctHit;
    int32_t cTorpHit;

    if (cTorpBase == 0 || pctBase == 0)
        return 0;

    pctJam = (int32_t)ptok->pctJam;
    if (pctJam != 0 && pctBC != 0) {
        pctJam -= (int32_t)pctBC;
        if (pctJam < 0) {
            pctBC = (int16_t)(-pctJam);
            pctJam = 0;
        } else {
            pctBC = 0;
        }
    }

    if (pctBC == 0) {
        if (pctJam == 0) {
            pctHit = (int32_t)pctBase;
        } else {
            pctHit = (int32_t)pctBase * (100 - pctJam) / 100;
        }
    } else {
        pctHit = 100 - (int32_t)(100 - pctBase) * (int32_t)(100 - pctBC) / 100;
    }

    if (pctHit < 1)
        pctHit = 1;

    if (pctHit >= 100)
        return cTorpBase;

    if (cTorpBase < 201) {
        cTorpHit = 0;
        for (i = 0; i < (int16_t)cTorpBase; i++) {
            if (Random(100) < (int16_t)pctHit)
                cTorpHit++;
        }
        return cTorpHit;
    } else {
        return cTorpBase * pctHit / 100;
    }
}

int16_t FCanKillTok(TOK *ptok1, TOK *ptok2) {
    SHDEF  *lpshdef1;
    SHDEF  *lpshdef2;
    int32_t lp1;
    int32_t lp2;

    // TODO: verify this
    lpshdef1 = LpshdefFromTok(ptok1);
    lpshdef2 = LpshdefFromTok(ptok2);
    lp1 = lpshdef1->lPower;
    lp2 = lpshdef2->lPower;

    if (lp1 >= lp2) {
        if ((lp1 & 0x7fff0000) < (lp2 & 0x7fff0000) || ((lp1 & 0x7fff0000) == (lp2 & 0x7fff0000) && (lp1 & 0xf000) <= (lp2 & 0xf000))) {
            if ((lp1 & 0xff00) == (lp2 & 0xff00) && (lp1 & 0x7fff0000) == (lp2 & 0x7fff0000) && ptok2->cTarget <= ptok1->cTarget) {
                return 1;
            }
            return 0;
        }
        return 1;
    }
    return 0;
}

int16_t FIsTargetOfMdTarget(TOK *ptok, MdTarget mdTarget) {
    switch (mdTarget) {
    default:
        return 0;

    case mdTargetAny:
        return 1;

    case mdTargetStarbase:
        return ptok->grobj == grobjPlanet; /* grobjStarbase */

    case mdTargetArmedShips:
    case mdTargetFuelTransports:
    case mdTargetFreighters:
        return ptok->mdTarget0 == mdTarget;

    case mdTargetBombersFreighters:
        return ptok->mdTarget0 == mdTargetBombersFreighters || ptok->mdTarget0 == mdTargetFreighters;

    case mdTargetUnarmedShips:
        return ptok->mdTarget0 == mdTargetUnarmedShips || ptok->mdTarget0 == mdTargetFreighters || ptok->mdTarget0 == mdTargetFuelTransports;
    }
}

int16_t SpdOfShip(FLEET *lpfl, int16_t ishdef, TOK *ptok, int16_t fDumpCargo, SHDEF *lpshdef) {
    int16_t  iEngine;
    int16_t  cHalfThruster;
    int16_t  cThruster;
    int16_t  cEngineT = 0;
    int16_t  j;
    int16_t  iWarp;
    int16_t  spd;
    uint16_t wt;

    /* If SHDEF not provided, fetch from per-player ship-def table. */
    if (lpshdef == NULL) {
        lpshdef = &rglpshdef[lpfl->iPlayer][ishdef];
    }

    iEngine = -1;
    cHalfThruster = 0;
    cThruster = 0;

    /* Scan hull slots for engine/thruster components. */
    for (j = 0; j < (int16_t)lpshdef->hul.chs; j++) {
        if (lpshdef->hul.rghs[j].cItem != 0) {
            if (lpshdef->hul.rghs[j].grhst == hstEngine) {
                iEngine = (int16_t)lpshdef->hul.rghs[j].iItem;
                cEngineT = (int16_t)lpshdef->hul.rghs[j].cItem;

                if (lpshdef->hul.rghs[j].iItem == iengineEnigmaPulsar) {
                    cHalfThruster = (int16_t)(cHalfThruster + lpshdef->hul.rghs[j].cItem);
                }
            } else if (lpshdef->hul.rghs[j].grhst == hstMining) {
                if (lpshdef->hul.rghs[j].iItem == iminingAlienMiner) {
                    cHalfThruster = (int16_t)(cHalfThruster + lpshdef->hul.rghs[j].cItem);
                }
            } else if (lpshdef->hul.rghs[j].grhst == hstSpecialE) {
                if (lpshdef->hul.rghs[j].iItem == ispecialEMultiFunctionPod) {
                    cThruster = (int16_t)(cThruster + lpshdef->hul.rghs[j].cItem);
                }
            } else if (lpshdef->hul.rghs[j].grhst == hstSpecialM) {
                if (lpshdef->hul.rghs[j].iItem == ispecialMManeuveringJet) {
                    cThruster = (int16_t)(cThruster + lpshdef->hul.rghs[j].cItem);
                } else if (lpshdef->hul.rghs[j].iItem == ispecialMOverthruster) {
                    cThruster = (int16_t)(cThruster + (int16_t)(lpshdef->hul.rghs[j].cItem * 2));
                }
            }
        }
    }

    if ((iEngine == -1) || (cEngineT == 0)) {
        return 0;
    }

    ENGINE *pengine = LpengineFromId(iEngine);

    /* Determine warp (special engines cap at warp 10; others limited by fuel usage). */
    if ((iEngine == iengineInterspace10) || (iEngine == iengineEnigmaPulsar) || (iEngine == iengineTransStar10) ||
        (iEngine == iengineTransGalacticMizerScoop) || (iEngine == iengineGalaxyScoop)) {
        iWarp = 10;
    } else {
        for (iWarp = 9; (0 < iWarp) && (120 < pengine->rgcFuelUsed[iWarp]); iWarp--) {
            /* empty */
        }
    }

    spd = (int16_t)(iWarp - 4 + cThruster + (int16_t)((cHalfThruster + 1) / 2));

    if (lpfl != NULL) {
        int16_t ra = GetRaceStat(&rgplr[lpfl->iPlayer], rsMajorAdv);
        if (ra == raAttack) {
            spd = (int16_t)(spd + 2);
        }
    }

    wt = lpshdef->hul.wtEmpty;

    if (lpfl != NULL) {
        uint16_t wtCargoShdefMax = (uint16_t)WtMaxShdefStat(lpshdef, grStatCargo);

        if (wtCargoShdefMax == 0) {
            fDumpCargo = 0;
        } else {
            uint32_t lCargo = (uint32_t)LGetFleetStat(lpfl, grStatCargo);

            if (lCargo != 0) {
                uint32_t sum = (uint32_t)lpfl->rgwtMin[0] + (uint32_t)lpfl->rgwtMin[1] + (uint32_t)lpfl->rgwtMin[2] + (uint32_t)lpfl->rgwtMin[3];

                /* Unsigned 32-bit multiply/divide like __aFulmul / __aFldiv. */
                uint32_t add = (sum * (uint32_t)wtCargoShdefMax) / lCargo;
                wt = (uint16_t)(wt + (uint16_t)add);
            }
        }

        if (fDumpCargo != 0) {
            spd = (int16_t)(spd - 1);
        }

        if (ptok != NULL) {
            /* Store Random(15) into TOK bitfield */
            ptok->dwt = (uint16_t)((uint16_t)Random(15) & 15u);
        }
    }

    if (ptok != NULL) {
        ptok->wt = wt;
    }

    /* Weight penalty: (wt / 70) / engine_count_in_slot0 */
    {
        uint16_t c0 = (uint16_t)lpshdef->hul.rghs[0].cItem;
        uint32_t penalty = 0;

        if (c0 != 0) {
            penalty = ((uint32_t)wt / 70u) / (uint32_t)c0;
        }

        {
            int32_t tmp = (int32_t)spd - (int32_t)penalty;
            if (tmp > 8)
                tmp = 8;
            if (tmp < 0)
                tmp = 0;
            return (int16_t)tmp;
        }
    }
}

void DoBombing(void) {
    int16_t idmDst;
    int32_t modKill;
    int16_t fMulti;
    int32_t cKillPeople;
    int32_t dmgBombBldg;
    int32_t cKillPeopleS;
    int32_t cKillMine;
    int32_t dmgBombFloor;
    int16_t idmSrc;
    int32_t cKillDefenses;
    int32_t cKillFact;
    int32_t pctTerra;
    PLANET *lppl;
    int16_t ifl;
    FLEET  *lpfl;
    int32_t cPPE;
    int32_t dmgBombPeople;
    float   pctSmart;
    float   pctSuccess;
    int32_t dmgPeopleSmart;
    int16_t pctTot;
    int16_t dChg;
    int16_t i;
    double  pctSuccessHalf;

    /* ------------------------------------------------------------
     * asm: 10f0:aefa..af0f
     * for (ifl=0; ; ++ifl) { if (ifl>=cFleet) return; lpfl=rglpfl[ifl]; if (!lpfl) return; ... }
     * ------------------------------------------------------------ */
    for (ifl = 0; ifl < cFleet; ifl++) {
        lpfl = rglpfl[ifl];
        if (lpfl == NULL) {
            return;
        }

        /* ------------------------------------------------------------
         * asm: 10f0:af4a..af85
         * if (!lpfl->fDead && lpfl->idPlanet!=-1 && !lpfl->fBombed) ...
         * ------------------------------------------------------------ */
        if (!lpfl->fDead && lpfl->idPlanet != -1 && !lpfl->fBombed) {

            /* ------------------------------------------------------------
             * asm: 10f0:af88..afe?  (planet pointer from idPlanet)
             * lppl = lpPlanets + lpfl->idPlanet
             * ------------------------------------------------------------ */
            lppl = lpPlanets + lpfl->idPlanet;

            /* ------------------------------------------------------------
             * asm: 10f0:afa2..b027
             * if target planet owned by someone else (and inhabited), and attack allowed, and no starbase:
             *   if (!FAttackPlayer(lpfl, lppl->iPlayer)) continue;
             *   if (lppl->fStarbase) continue;
             * ------------------------------------------------------------ */
            if (lppl->iPlayer != lpfl->iPlayer && lppl->iPlayer != -1) {
                if (FAttackPlayer(lpfl, lppl->iPlayer) != 0 && !lppl->fStarbase) {

                    /* ------------------------------------------------------------
                     * asm: 10f0:af??..b01c
                     * FCalcFleetBombDamage(lpfl, &dmgBombPeople, &dmgBombFloor, &dmgPeopleSmart, &dmgBombBldg, &pctTerra, &fMulti)
                     * ------------------------------------------------------------ */
                    if (FCalcFleetBombDamage(lpfl, &dmgBombPeople, &dmgBombFloor, &dmgPeopleSmart, &dmgBombBldg, &pctTerra, &fMulti) != 0) {

                        /* ------------------------------------------------------------
                         * asm: 10f0:b02a..b03d
                         * CalcPctSurvive(lppl, &pctSuccess, &pctSmart)
                         * ------------------------------------------------------------ */
                        CalcPctSurvive(lppl, &pctSuccess, &pctSmart);

                        /* ------------------------------------------------------------
                         * asm: 10f0:b040..b14e
                         * if (pctSuccess < 1.0f) scale positive damage buckets by pctSuccess with +0.5 rounding.
                         * (the asm gates each multiply/ftol with “> 0” tests)
                         * ------------------------------------------------------------ */
                        if (pctSuccess < 1.0f) {
                            if (dmgBombPeople > 0) {
                                pctSuccessHalf = (double)pctSuccess * dmgBombPeople + 0.5;
                                dmgBombPeople = pctSuccessHalf;
                            }
                            if (dmgBombFloor > 0) {
                                pctSuccessHalf = (double)pctSuccess * dmgBombFloor + 0.5;
                                dmgBombFloor = pctSuccessHalf;
                            }
                            if (dmgPeopleSmart > 0) {
                                pctSuccessHalf = (double)pctSuccess * dmgPeopleSmart + 0.5;
                                dmgPeopleSmart = pctSuccessHalf;
                            }
                            if (dmgBombBldg > 0) {
                                pctSuccessHalf = (double)pctSuccess * dmgBombBldg + 0.5;
                                dmgBombBldg = pctSuccessHalf;
                            }
                        }

                        /* ------------------------------------------------------------
                         * asm: 10f0:b14e..b1??
                         * cPPE = (cFactories + cMines + cDefenses); zero kill tallies
                         * NOTE: convert raw rgbImp bit-twiddles to PLANET bitfields from types.h
                         * ------------------------------------------------------------ */
                        cPPE = lppl->cFactories + lppl->cMines + lppl->cDefenses;

                        cKillDefenses = 0;
                        cKillPeople = 0;
                        cKillMine = 0;
                        cKillFact = 0;

                        /* ------------------------------------------------------------
                         * asm: 10f0:b1??..b3??
                         * Building damage -> distribute across factories/defenses/mines proportional to current counts.
                         * Uses:
                         *   q = (count*dmg)/cPPE
                         *   r = (count*dmg)%cPPE
                         *   if (r>0 && Random(cPPE) < r) ++q
                         * and caps q to available count.
                         * ------------------------------------------------------------ */
                        if (dmgBombBldg > 0 && cPPE > 0) {
                            /* factories */
                            {
                                int32_t count = lppl->cFactories;
                                int32_t prod = count * dmgBombBldg;
                                modKill = prod % cPPE;
                                cKillFact = prod / cPPE;
                                if (modKill > 0) {
                                    if (Random(cPPE) < modKill) {
                                        cKillFact += 1;
                                    }
                                }
                                if (cKillFact > count) {
                                    cKillFact = count;
                                }
                            }

                            /* defenses */
                            {
                                int32_t count = lppl->cDefenses;
                                int32_t prod = count * dmgBombBldg;
                                modKill = prod % cPPE;
                                cKillDefenses = prod / cPPE;
                                if (modKill > 0) {
                                    if (Random(cPPE) < modKill) {
                                        cKillDefenses += 1;
                                    }
                                }
                                if (cKillDefenses > count) {
                                    cKillDefenses = count;
                                }
                            }

                            /* mines = remainder, then cap to available mines */
                            cKillMine = dmgBombBldg - (cKillFact + cKillDefenses);
                            if (cKillMine < 0) {
                                cKillMine = 0;
                            } else {
                                int32_t count = lppl->cMines;
                                if (cKillMine > count) {
                                    cKillMine = count;
                                }
                            }
                        }

                        /* ------------------------------------------------------------
                         * asm: 10f0:b3b6..b7d1
                         * People damage:
                         *   - smart-kill chunk: (pop * dmgPeopleSmart)/1000, capped to pop-1
                         *   - remaining pop then killed by (remaining * dmgBombPeople)/1000, remainder rounded with Random(1000) <= rem
                         *   - add smart kills, enforce minimums against dmgBombFloor and “at least 1” if dmgBombPeople>0
                         *   - cap to total pop
                         *   - subtract from planet population (rgwtMin[3])
                         * ------------------------------------------------------------ */
                        if (dmgBombPeople > 0 || dmgBombFloor > 0 || dmgPeopleSmart > 0) {
                            int32_t pop = lppl->rgwtMin[3];

                            if (pop > 0) {
                                /* smart kills */
                                cKillPeopleS = (pop * dmgPeopleSmart) / 1000;
                                if (cKillPeopleS >= pop) {
                                    cKillPeopleS = pop - 1;
                                }

                                /* remaining pop after smart kills */
                                {
                                    int32_t popRem = pop - cKillPeopleS;

                                    /* base kills from non-smart bombs */
                                    {
                                        int32_t prod = popRem * dmgBombPeople;
                                        modKill = prod % 1000;
                                        cKillPeople = prod / 1000;

                                        if (modKill > 0) {
                                            /* asm uses JBE => Random(1000) <= modKill */
                                            if (Random(1000) <= modKill) {
                                                cKillPeople += 1;
                                            }
                                        }
                                    }

                                    cKillPeople += cKillPeopleS;

                                    if (dmgBombPeople > 0 && cKillPeople < 1) {
                                        cKillPeople = 1;
                                    }
                                    if (cKillPeople < dmgBombFloor) {
                                        cKillPeople = dmgBombFloor;
                                    }

                                    if (cKillPeople > pop) {
                                        cKillPeople = pop;
                                    }
                                }
                            }

                            if (cKillPeople > 0) {
                                lppl->rgwtMin[3] -= cKillPeople;
                            }
                        }

                        /* ------------------------------------------------------------
                         * asm: 10f0:b7?? (rgbImp updates)
                         * Apply building kills to planet bitfields (types.h rgbImp union members).
                         * (replaces raw masking/shifting)
                         * ------------------------------------------------------------ */
                        if (cKillFact > 0) {
                            uint32_t v = lppl->cFactories;
                            uint32_t k = cKillFact;
                            lppl->cFactories = (v > k) ? (v - k) : 0;
                        }
                        if (cKillMine > 0) {
                            uint32_t v = lppl->cMines;
                            uint32_t k = cKillMine;
                            lppl->cMines = (v > k) ? (v - k) : 0;
                        }
                        if (cKillDefenses > 0) {
                            uint32_t v = lppl->cDefenses;
                            uint32_t k = cKillDefenses;
                            lppl->cDefenses = (v > k) ? (v - k) : 0;
                        }

                        /* ------------------------------------------------------------
                         * asm: 10f0:b7d1..b9d4  (terraform undo)
                         * if (pctTerra>0 && (cKillPeople>0)) {
                         *   pctTerra -= ftol(((1.0 - pctSuccess) * pctTerra) / 2.0);
                         *   if (pctTerra > 500) pctTerra = 500;
                         *   for i=0..2: move rgEnvVar[i] toward rgEnvVarOrig[i] by up to pctTerra
                         *   accumulate absolute change in dChg; if dChg>0 send messages to both players
                         * }
                         * ------------------------------------------------------------ */
                        if (cKillPeople > 0 && pctTerra > 0) {
                            pctSuccessHalf = ((1.0 - pctSuccess) * pctTerra) / 2.0;
                            pctTerra -= pctSuccessHalf;
                            if (pctTerra > 500) {
                                pctTerra = 500;
                            }

                            dChg = 0;
                            for (i = 0; i < 3; i++) {
                                int16_t envOrig = lppl->rgEnvVarOrig[i];
                                int16_t envCur = lppl->rgEnvVar[i];
                                int16_t delta = envCur - envOrig;

                                if (delta > 0) {
                                    int16_t amt = delta;
                                    if (amt > pctTerra) {
                                        amt = pctTerra;
                                    }
                                    lppl->rgEnvVar[i] = envCur - amt;
                                    dChg += amt;
                                } else if (delta < 0) {
                                    int16_t amt = -delta;
                                    if (amt > pctTerra) {
                                        amt = pctTerra;
                                    }
                                    lppl->rgEnvVar[i] = envCur + amt;
                                    dChg += amt;
                                }
                            }

                            if (dChg > 0) {
                                if (fMulti == 0) {
                                    idmSrc = idmHasRetroBombedUndoingTerraforming;
                                } else {
                                    idmSrc = idmFleetsHaveRetroBombedUndoingTerraforming;
                                }
                                FSendPlrMsg(lpfl->iPlayer, idmSrc, lpfl->id | 0x8000, lpfl->id, lppl->id, dChg, 0, 0, 0, 0);

                                if (fMulti == 0) {
                                    idmDst = idmHasRetroBombedUndoingTerraforming;
                                } else {
                                    idmDst = idmFleetsHaveRetroBombedUndoingTerraforming2;
                                }
                                FSendPlrMsg(lppl->iPlayer, idmDst, lppl->id, lpfl->id, lppl->id, dChg, 0, 0, 0, 0);
                            }
                        }

                        /* ------------------------------------------------------------
                         * asm: 10f0:b9d4..ba95
                         * cPPE = cKillFact + cKillDefenses + cKillMine (total structures destroyed)
                         * choose message ids based on whether planet had population at time of bombing
                         * and whether multiple fleets involved (fMulti).
                         * ------------------------------------------------------------ */
                        cPPE = cKillDefenses + cKillFact + cKillMine;

                        if (cPPE >= 1) {
                            if (lppl->rgwtMin[3] > 0) {
                                if (fMulti != 0) {
                                    idmSrc = idmFleetsHaveBombedKillingColonistsDestroyingOne;
                                    idmDst = idmFleetsHaveBombedKillingColonistsDestroyingOne3;
                                } else {
                                    idmSrc = idmHasBombedKillingColonistsDestroyingOneInstallati;
                                    idmDst = idmHasBombedKillingColonistsDestroyingOneInstallati3;
                                }

                                if (cPPE > 1) {
                                    idmSrc = idmSrc + 1;
                                    idmDst = idmDst + 1;
                                }
                            } else {
                                if (fMulti != 0) {
                                    idmSrc = idmFleetsHaveBombedKillingOffEnemyColonists;
                                    idmDst = idmFleetsHaveBombedKillingColonists3;
                                } else {
                                    idmSrc = idmHasBombedKillingOffEnemyColonists;
                                    idmDst = idmHasBombedKillingColonists3;
                                }
                            }

                            /* --------------------------------------------------------
                             * asm: 10f0:ba98..bc07
                             * If (cKillPeople>0) and pctSuccess != 1.0 => “percent destroyed” variant (+5) and pass pctTot
                             * Else => GenericBombMsg (no percent arg)
                             * -------------------------------------------------------- */
                            if (cKillPeople > 0) {
                                if (pctSuccess == 1.0f) {
                                    /* BATTLE::GenericBombMsg @ 10f0:bac4 */
                                    FSendPlrMsg(lpfl->iPlayer, idmSrc, lpfl->id | 0x8000, lpfl->id, lppl->id, cKillPeople, cPPE, 0, 0, 0);
                                    FSendPlrMsg(lppl->iPlayer, idmDst, lppl->id, lpfl->id, lppl->id, cKillPeople, cPPE, 0, 0, 0);
                                } else {
                                    /* LAB_10f0_bb47 .. bc07: add +5, compute pctTot=(1-pctSuccess)*10000 */
                                    idmSrc = idmSrc + 5;
                                    idmDst = idmDst + 5;

                                    pctTot = (1.0 - pctSuccess) * 10000.0;

                                    FSendPlrMsg(lpfl->iPlayer, idmSrc, lpfl->id | 0x8000, lpfl->id, lppl->id, cKillPeople, cPPE, pctTot, 0, 0);
                                    FSendPlrMsg(lppl->iPlayer, idmDst, lppl->id, lpfl->id, lppl->id, cKillPeople, cPPE, pctTot, 0, 0);
                                }
                            } else {
                                /* ----------------------------------------------------
                                 * asm: 10f0:bc0a..bd5e
                                 * “no people killed” variants: subtract 2 from ids, and choose whether to include percent destroyed
                                 * ---------------------------------------------------- */
                                idmSrc = idmSrc - 2;
                                idmDst = idmDst - 2;

                                if (pctSuccess == 1.0f) {
                                    FSendPlrMsg(lpfl->iPlayer, idmSrc, lpfl->id | 0x8000, lpfl->id, lppl->id, cPPE, 0, 0, 0, 0);
                                    FSendPlrMsg(lppl->iPlayer, idmDst, lppl->id, lpfl->id, lppl->id, cPPE, 0, 0, 0, 0);
                                } else {
                                    idmSrc = idmSrc + 5;
                                    idmDst = idmDst + 5;

                                    pctTot = (1.0 - pctSuccess) * 10000.0;

                                    FSendPlrMsg(lpfl->iPlayer, idmSrc, lpfl->id | 0x8000, lpfl->id, lppl->id, cPPE, pctTot, 0, 0, 0);
                                    FSendPlrMsg(lppl->iPlayer, idmDst, lppl->id, lpfl->id, lppl->id, cPPE, pctTot, 0, 0, 0);
                                }
                            }
                        } else {
                            /* --------------------------------------------------------
                             * asm: 10f0:bd61.. (no structures destroyed)
                             * If people killed, send “killed people” only messages, choosing ids based on whether pop hit zero.
                             * -------------------------------------------------------- */
                            if (cKillPeople > 0) {
                                if (lppl->rgwtMin[3] <= 0) {
                                    if (fMulti == 0) {
                                        idmSrc = 0x8f;
                                        idmDst = 0x90;
                                    } else {
                                        idmSrc = 0x17c;
                                        idmDst = 0x17d;
                                    }
                                } else {
                                    if (fMulti == 0) {
                                        idmSrc = 0x60;
                                        idmDst = 0x6a;
                                    } else {
                                        idmSrc = 0x166;
                                        idmDst = 0x170;
                                    }
                                }

                                FSendPlrMsg(lpfl->iPlayer, idmSrc, lpfl->id | 0x8000, lpfl->id, lppl->id, cKillPeople, 0, 0, 0, 0);
                                FSendPlrMsg(lppl->iPlayer, idmDst, lppl->id, lpfl->id, lppl->id, cKillPeople, 0, 0, 0, 0);
                            }
                        }

                        /* ------------------------------------------------------------
                         * asm: 10f0:be??..be8d
                         * If planet now uninhabited (pop == 0) then UninhabitPlanet(lppl)
                         * ------------------------------------------------------------ */
                        if (lppl->rgwtMin[3] == 0) {
                            UninhabitPlanet(lppl);
                        }
                    }
                }
            }
        }
    }
}

void InitializeBoard(FLEET *lpfl, int16_t ibrc, uint16_t grfPlayer, uint8_t *pinit, int16_t *pinitMin, int16_t *pinitMac) {
    int16_t   iplr;
    FLEET    *lpflCur;
    TOK      *ptok;
    int16_t   initMac;
    PLANET   *lppl;
    int16_t   fDampeningField;
    int16_t   initMin;
    uint16_t *lpwtCargoCur; /* stack overlap in asm: used only as a segment helper for REP MOVS */
    TOK      *ptokT;
    uint8_t   mpiplrdibrc[16];
    int16_t   fDumpCargo;
    int16_t   ishdef;
    uint8_t   rgfTorp[16];

    /* debug symbols */
    /* label LTooManyTokens @ MEMORY_BATTLE:0x4a8f */

    /* ------------------------------------------------------------
     * asm: 10f0:45b4..4641
     * init locals; build mpiplrdibrc[] (player->side index) and clear rgfTorp[]
     */
    initMin = -1;
    initMac = -1;
    fDampeningField = 0;
    ishdef = 0;

    memset(mpiplrdibrc, 0xFF, sizeof(mpiplrdibrc));
    for (iplr = 0; iplr < game.cPlayer; iplr++) {
        if ((grfPlayer & (1u << (iplr & 0x1F))) != 0) {
            mpiplrdibrc[iplr] = (uint8_t)ishdef;
            ishdef++;
        }
    }

    memset(rgfTorp, 0, sizeof(rgfTorp));

    /* ------------------------------------------------------------
     * asm: 10f0:4644..485a
     * init token pointer; optional starbase token from lpfl->idPlanet
     */
    lpflCur = lpfl;
    ptok = vrgtok;

    if (lpfl->idPlanet != -1) {
        lppl = LpplFromId(lpfl->idPlanet);
        iplr = lppl->iPlayer;

        if (iplr != -1 && lppl->fStarbase && ((grfPlayer & (1u << (iplr & 0x1F))) != 0)) {
            /* tok->grobj = 1 (starbase) */
            ptok->grobj = 1;

            /* planet.lStarbase high-word bit: fNoHeal (asm: AND 0xBFFF; OR 0x4000) */
            lppl->fNoHeal = 1;

            /* starting board position: rgbrcStart[ibrc + sideIndex] (table is in CS in asm) */
            ptok->brc = rgbrcStart[ibrc + mpiplrdibrc[iplr]];

            ptok->id = lppl->id;
            ptok->iplr = (uint8_t)iplr;
            ptok->csh = 1;

            /* tok->ishdef = (lppl->isb & 0xF) + 0x10 */
            ptok->ishdef = lppl->isb + 0x10;

            CheckInitiative(ptok);
            CheckWeapons(ptok, &fDampeningField, pinit);

            rgfTorp[iplr] |= ptok->fTorp;

            /* asm: if initBase==0xFF mdTarget0=5 else mdTarget0=3 */
            if (ptok->initBase == 0xFF) {
                ptok->mdTarget0 = 5;
            } else {
                ptok->mdTarget0 = 3;
            }

            /* mdTarget1=1; mdTarget2=1; mdTactic=5 */
            ptok->mdTarget1 = 1;
            ptok->mdTarget2 = 1;
            ptok->mdTactic = 5;

            /* dv.pctDp = (lppl->pctDp >>?); asm uses low-word >>4, then takes low 9 bits */
            ptok->dv.pctDp = (uint16_t)(lppl->pctDp & 0x01FF);

            /* if dv.pctDp != 0 then dv.pctSh = 100 */
            if (ptok->dv.pctDp != 0) {
                ptok->dv.pctSh = 100;
            }

            /* clear speed nibble */
            ptok->spd = 0;

            /* wt = 0xFFFF */
            ptok->wt = 0xFFFF;

            ptok++;
        }
    }

    /* ------------------------------------------------------------
     * asm: 10f0:485e..4a8c
     * iterate circular fleet list; add ship tokens; mark missed fleets
     */
    do {
        if (!lpflCur->fDead) {
            /* asm checks (dirLong >> (16+7)) & 1 */
            if ((((uint32_t)lpflCur->dirLong >> 23) & 1u) == 0) {
                if (lpflCur->fInclude) {
                    /* fleet wFlags bit: fNoHeal (asm: AND 0xBFFF; OR 0x4000) */
                    lpflCur->fNoHeal = 1;

                    iplr = lpflCur->iPlayer;
                    fDumpCargo = FDumpCargo(lpflCur);

                    for (ishdef = 0; ishdef < 16; ishdef++) {
                        if (lpflCur->rgcsh[ishdef] != 0) {
                            ptok->grobj = 2;

                            ptok->brc = rgbrcStart[ibrc + mpiplrdibrc[iplr]];

                            ptok->id = lpflCur->id;

                            /* asm derives iplr from (fleet.id >> 9) & 0xF; use bitfield */
                            ptok->iplr = (uint8_t)lpflCur->iplr;

                            ptok->ishdef = (uint8_t)ishdef;

                            ptok->csh = lpflCur->rgcsh[ishdef];
                            ptok->dv.dp = lpflCur->rgdv[ishdef].dp;

                            CheckInitiative(ptok);
                            CheckWeapons(ptok, &fDampeningField, pinit);

                            rgfTorp[iplr] |= ptok->fTorp;

                            CheckTarget(ptok, lpflCur, ishdef);

                            {
                                uint16_t spd = SpdOfShip(lpflCur, ishdef, ptok, fDumpCargo, 0);
                                ptok->spd = spd & 0xF;
                            }

                            ptok++;

                            /* asm: if ( (ptok - vrgtok)/0x1D > 0xFF ) goto LTooManyTokens */
                            if ((ptok - vrgtok) > 0xFF) {
                                goto LTooManyTokens;
                            }
                        }
                    }
                }
            } else {
                /* asm: grfMissed |= 1 << iPlayer */
                grfMissed |= 1u << (lpflCur->iPlayer & 0x1F);
            }
        }

        lpflCur = lpflCur->lpflNext;
    } while (lpflCur != lpfl);

LTooManyTokens:
    /* ------------------------------------------------------------
     * asm: 10f0:4a8f..4ac1
     * finalize token count and randomize order
     */
    vctok = (int16_t)(ptok - vrgtok);
    RandomizeTokOrder();

    /* ------------------------------------------------------------
     * asm: 10f0:4ac4..4c8c
     * per-token postprocessing, dampening-speed adjust, copy to lpbBattleCur,
     * and compute initMin/initMac across tokens (ignoring 0xFF).
     */
    ptokT = vrgtok;
    while (ptokT < ptok) {
        /* set moved + active bits in TOK.wFlags */
        ptokT->fMoved = 1;
        ptokT->fActive = 1;

        /* if initMin==0xFF then clear mdTarget1 nibble */
        if (ptokT->initMin == 0xFF) {
            ptokT->mdTarget1 = 0;
        }

        /* fRegen depends on dpShield and race flag ibitRaceRegeneratingShields */
        if (ptokT->dpShield == 0 || GetRaceGrbit((PLAYER *)rgplr + ptokT->iplr, ibitRaceRegeneratingShields) == 0) {
            ptokT->fRegen = 0;
        } else {
            ptokT->fRegen = 1;
        }

        /* dampening field speed penalty for non-starbase tokens */
        if (fDampeningField != 0 && ptokT->grobj != 1) {
            uint16_t spd = ptokT->spd;
            if ((int16_t)(spd - 4) < 1) {
                spd = 0;
            } else {
                spd = (uint16_t)(spd - 4);
            }
            ptokT->spd = (uint16_t)(spd & 0xF);
        }

        /* asm uses REP MOVSW/MOVSB of 0x1D bytes into lpbBattleCur */
        memcpy(lpbBattleCur, ptokT, sizeof(TOK));
        lpbBattleCur += sizeof(TOK);

        /* track initMin (minimum) */
        if (ptokT->initMin != 0xFF && (initMin == -1 || ptokT->initMin < initMin)) {
            initMin = ptokT->initMin;
        }

        /* track initMac (maximum) */
        if (ptokT->initMac != 0xFF && (initMac == -1 || initMac < ptokT->initMac)) {
            initMac = ptokT->initMac;
        }

        ptokT++;
    }

    /* ------------------------------------------------------------
     * asm: 10f0:4c8c..4ca7
     * return initMin/initMac (low byte)
     */
    *pinitMin = initMin & 0xFF;
    *pinitMac = initMac & 0xFF;
}

int16_t DzMoveRangeToConsider(TOK *ptok, uint16_t grfAttack, uint8_t *pbrc) {
    int16_t  dzNonSapper;
    uint8_t  dz;
    int16_t  iplr;
    uint16_t mdTarget;
    uint8_t  dzBest;
    int16_t  itokLook;
    int16_t  iplrTarget;
    TOK     *ptokTarget;
    int16_t  dzMax;
    uint8_t  brcCur;
    int16_t  ihs;
    SHDEF   *lpshdef;
    HUL     *lphul;
    PART     part;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x53a7 */

    /* TODO: implement */
    return 0;
}

int16_t FFuelTanker(SHDEF *lpshdef) {
    if (lpshdef->hul.ihuldef == ihuldefFuelTransport || lpshdef->hul.ihuldef == ihuldefSuperFuelXport) {
        return 1;
    }
    return 0;
}

int16_t FDoCoolBattle(FLEET *lpfl, int16_t cplr, uint16_t *rggrfAttack, uint16_t grfPlayer, uint16_t grfSpectator) {
    int16_t  cShipsInvolved;   /* bp-0x0006 */
    uint8_t *lpbMax;           /* bp-0x000a (computed, mostly for parity) */
    TOK     *ptok;             /* bp-0x000e */
    uint16_t wt;               /* bp-0x0010 */
    int16_t  cShdefsInvolved;  /* bp-0x0012 */
    uint8_t *lpbSav;           /* bp-0x0016 */
    int16_t  initMac;          /* bp-0x0018 */
    int16_t  init;             /* bp-0x001a */
    uint16_t wtT;              /* bp-0x001c */
    uint16_t grplrLeft;        /* bp-0x001e */
    int16_t  i;                /* bp-0x0020 */
    int16_t  j;                /* bp-0x0022 */
    int16_t  initMin;          /* bp-0x0024 */
    BTLREC  *lpbtlrec;         /* bp-0x0028 */
    int16_t  iRound;           /* bp-0x002a */
    FLEET   *lpflT;            /* bp-0x002e */
    uint16_t brcOrig;          /* bp-0x0030 */
    BTLDATA *lpbtldata;        /* bp-0x0034 */
    uint8_t  rgfInit[64];      /* bp-0x0074 */
    uint16_t rgPlrLosses[256]; /* bp-0x0274 */
    uint16_t wtNext;           /* bp-0x0276 */
    int16_t  itok;             /* bp-0x0278 */
    PLANET  *lppl;             /* bp-0x027a (overlaps with lwt in NB09 blocks) */
    int32_t  lwt;              /* bp-0x027a (overlaps with lppl in NB09 blocks) */
    MemJump  env;              /* bp-0x0288-ish (NB09 calls it int16_t[9]) */
    MemJump *penvMemSav;       /* bp-0x028a-ish */

    /* --------------------------------------------------------------------
     * asm: 10f0:8bcc..8c3e
     * if (lpbBattleLog == NULL) { setjmp guard; alloc battle log; }
     * -------------------------------------------------------------------- */
    penvMemSav = penvMem;
    if (lpbBattleLog == NULL) {
        penvMem = &env;
        if (setjmp(env.env) != 0) {
            /* asm: 10f0:8c0a..8c16 -> error path */
            penvMem = penvMemSav;
            /* common epilogue restores globals below */
            lpbBattleCur = (uint8_t *)lpbBattleCur; /* keep flow parity */
            lpbBattleT = (uint8_t *)lpbBattleT;
            lpbBattleLog = (uint8_t *)lpbBattleLog;
            return -1;
        }

        lpbBattleLog = (uint8_t *)LpAlloc(0xffc8, htBattle);
        lpbBattleCur = lpbBattleLog;
    }

    /* --------------------------------------------------------------------
     * asm: 10f0:8c3e..8c8f
     * ensure temp buffer (lpbBattleT) exists; set lpbMax; reset cursors
     * -------------------------------------------------------------------- */
    penvMemSav = penvMem;
    lpbSav = lpbBattleCur;

    if (lpbBattleT == NULL) {
        penvMem = &env;
        if (setjmp(env.env) != 0) {
            /* asm: second setjmp failure path merges to common return -1 */
            penvMem = penvMemSav;
            lpbBattleCur = (uint8_t *)lpbBattleCur;
            lpbBattleT = (uint8_t *)lpbBattleT;
            lpbBattleLog = (uint8_t *)lpbBattleLog;
            return -1;
        }

        lpbBattleT = (uint8_t *)LpAlloc(0xffc8, htBattle);
        /* lpbSav already holds old lpbBattleCur (per asm flow) */
    }

    lpbMax = lpbBattleT - 0x48; /* asm: lpbMax = lpbBattleT + -0x48 */
    lpbBattleCur = lpbBattleT;

    /* --------------------------------------------------------------------
     * asm: 10f0:8c8f..8cf4
     * zero losses/init arrays; clear vrgtok; init globals for battle
     * -------------------------------------------------------------------- */
    memset(rgPlrLosses, 0, sizeof(rgPlrLosses));
    vrgPlrLosses = rgPlrLosses;

    memset(rgfInit, 0, sizeof(rgfInit));

    /* asm uses memset(vrgtok, 0, 0x1d00) */
    memset(vrgtok, 0, 0x1d00);

    lpbtldata = (BTLDATA *)lpbBattleCur;
    lpbBattleCur += 0x0e; /* sizeof(BTLDATA header through pt) */

    vctok = 0;

    memset((uint8_t *)rgTechBattle, 0, 6);
    memset((uint8_t *)rgTechTrader, 0, 0x0d);

    lpthBattle = NULL;

    cShdefsInvolved = 0;
    cShipsInvolved = 0;

    fStarbaseDied = 0;
    fStarbaseDamaged = 0;

    /* --------------------------------------------------------------------
     * asm: 10f0:8cf4..8d70
     * scan fleet ring: count ships, mark involved player/shipdef slots
     * -------------------------------------------------------------------- */
    lpflT = lpfl;
    do {
        if (!lpflT->fDead) {
            for (i = 0; i < 16; i++) {
                if (lpflT->rgcsh[i] > 0) {
                    cShipsInvolved = (int16_t)(cShipsInvolved + lpflT->rgcsh[i]);
                    rgPlrLosses[(int16_t)(lpflT->iPlayer * 16 + i)] = 0x8000;
                }
            }
        }
        lpflT = lpflT->lpflNext;
    } while (lpflT != lpfl && lpflT != NULL);

    for (i = 0; i < 256; i++) {
        if (rgPlrLosses[i] != 0) {
            rgPlrLosses[i] = 0;
            cShdefsInvolved = (int16_t)(cShdefsInvolved + 1);
        }
    }

    /* --------------------------------------------------------------------
     * asm: 10f0:8d70..8dd3
     * optional starbase involvement if battle at planet and visible to grfPlayer
     * -------------------------------------------------------------------- */
    if (lpfl->idPlanet != -1) {
        lppl = LpplFromId(lpfl->idPlanet);
        if (lppl != NULL) {
            if (lppl->fStarbase && ((uint16_t)(1u << (lppl->iPlayer & 0x1f)) & grfPlayer) != 0) {
                cShdefsInvolved = (int16_t)(cShdefsInvolved + 1);
                cShipsInvolved = (int16_t)(cShipsInvolved + 1);

                /* asm: *(uint16_t *)((uint8_t *)&lppl->lStarbase + 2) = (hi & 0xbfff) | 0x4000 */
                ((uint16_t *)&lppl->lStarbase)[1] = (uint16_t)(((uint16_t *)&lppl->lStarbase)[1] & 0xbfffu) | 0x4000u;
            }
        }
    }

    /* --------------------------------------------------------------------
     * asm: 10f0:8dd3..8e1f
     * InitializeBoard(...); write BTLDATA header fields; bump idBattle
     * -------------------------------------------------------------------- */
    InitializeBoard(lpfl, (int16_t)(((cplr - 1) * cplr) / 2), grfPlayer, rgfInit, &initMin, &initMac);

    lpbtldata->cplr = (uint8_t)cplr;
    lpbtldata->ctok = (uint8_t)vctok;
    lpbtldata->idPlanet = (uint16_t)lpfl->idPlanet;
    lpbtldata->pt.x = lpfl->pt.x;
    lpbtldata->pt.y = lpfl->pt.y;

    lpbtldata->id = (uint16_t)idBattle;
    idBattle = (int16_t)(idBattle + 1);

    /* --------------------------------------------------------------------
     * asm: 10f0:8e1f..9824
     * 16 rounds: regen shields; per-round movement bits; 3 move phases; attack phases by init
     * -------------------------------------------------------------------- */
    for (iRound = 0; iRound < 16; iRound++) {
        /* build active-player mask; regen shields after round 0 when applicable */
        grplrLeft = 0;
        for (itok = 0; itok < vctok; itok++) {
            if (vrgtok[itok].fActive) {
                grplrLeft |= (uint16_t)(1u << (vrgtok[itok].iplr & 0x1f));

                if (iRound > 0 && vrgtok[itok].dpShield != 0 && vrgtok[itok].fActive) {
                    if (GetRaceGrbit((PLAYER *)(rgplr + vrgtok[itok].iplr), ibitRaceRegeneratingShields) != 0) {
                        RegenShield(&vrgtok[itok]);
                    }
                }
            }
        }
        if ((uint16_t)((grplrLeft - 1) & grplrLeft) == 0)
            break;

        /* per-round: set dMovesLeft based on DxyFromSpdRound unless grobj==1 then clear */
        ptok = vrgtok;
        for (itok = 0; itok < vctok; itok++, ptok++) {
            if (ptok->fActive) {
                if (ptok->grobj == grobjPlanet) {
                    /* asm: wFlags &= 0x3fff */
                    ptok->dMovesLeft = 0;
                } else {
                    int16_t dxy = DxyFromSpdRound((int16_t)ptok->spd, iRound);
                    /* asm: wFlags = (wFlags & 0x3fff) | (dxy << 14) */
                    ptok->dMovesLeft = (uint16_t)dxy;
                }
            }
        }

        /* 3 movement phases, decreasing j from 3..1 */
        for (j = 3; j > 0; j--) {
            wt = 30000;
            i = vctok; /* asm keeps a countdown of “done” toks */

            do {
                wtNext = 0;
                ptok = vrgtok;

                for (itok = 0; itok < vctok; itok++, ptok++) {
                    if (!ptok->fActive || ptok->wt == 0xffff) {
                        i = (int16_t)(i - 1);
                        continue;
                    }

                    /* asm: wtT = wt + wt * (((1 << (dwt-7)) * 2) / 100) with gating via DxyFromSpdRound!=0 */
                    {
                        int16_t  dwt = (int16_t)ptok->dwt;
                        int32_t  sh = (int32_t)(dwt - 7);
                        uint32_t mul = (uint32_t)((uint32_t)1u << (uint32_t)sh) * 2u;
                        lwt = (int32_t)(((uint32_t)ptok->wt * mul) / 100u);
                        wtT = (uint16_t)(ptok->wt + (uint16_t)lwt);

                        if (wtNext < wtT && wtT < wt) {
                            if (DxyFromSpdRound((int16_t)ptok->spd, iRound) != 0) {
                                wtNext = wtT;
                            }
                        }
                    }

                    if (wtT == wt) {
                        i = (int16_t)(i - 1);

                        if (j <= (int16_t)ptok->dMovesLeft) {
                            /* allocate BTLREC at current cursor */
                            lpbtlrec = (BTLREC *)lpbBattleCur;
                            lpbBattleCur += 6;

                            lpbtlrec->itok = (uint8_t)itok;
                            lpbtlrec->brcDest = 0;
                            lpbtlrec->ctok = 0;

                            lpbtlrec->itokAttack = (uint16_t)itok;
                            lpbtlrec->iRound = (uint16_t)iRound;

                            /* store (tok dzDis low4) into rec dzDis; keep full dzDis in a temp like asm local_27e */
                            {
                                uint16_t dz = (uint16_t)ptok->dzDis; /* 0..31 */
                                uint16_t dzLow4 = (uint16_t)(dz & 0x0fu);
                                lpbtlrec->dzDis = dzLow4;
                            }

                            brcOrig = ptok->brc;

                            /* if mdTactic == 0: special-case */
                            if (ptok->mdTactic == 0) {
                                brcOrig = 0xff;

                                if (ptok->dzDis == 0) {
                                    lpbtlrec->brcDest = 0xff;
                                    ptok->fActive = 0; /* asm: wFlags &= 0xfffe */
                                    continue;
                                }

                                /* asm adjusts dzDis field group by subtracting 1 from 5-bit dzDis and reinsert */
                                ptok->dzDis = (uint16_t)(ptok->dzDis - 1);
                            }

                            /* move token */
                            DxyMoveTokTo(ptok, j, rggrfAttack[ptok->iplr]);

                            /* asm: preserve top two bits (dMovesLeft) then clear and OR back; net effect = no change */
                            /* (kept as-is for flow parity; no-op in bitfield form) */

                            if (ptok->grobj == grobjPlanet || (brcOrig == ptok->brc && ptok->initMin != 0xff)) {
                                lpbBattleCur -= 6; /* undo record */
                            } else {
                                lpbtlrec->brcDest = ptok->brc;
                            }
                        }
                    }
                }

                wt = wtNext;
            } while (wtNext != 0);
        }

        /* randomize dzDis high bits area (asm writes random nibble into bits 10..13 of wFlags) */
        grplrLeft = 0;
        for (i = 0; i < vctok; i++) {
            if (vrgtok[i].fActive) {
                uint16_t r = (uint16_t)Random(15);
                /* asm: wFlags = (wFlags & 0xc3ff) | ((r&0xf) << 10) */
                vrgtok[i].dwt = (uint16_t)(r & 0x0f);
                grplrLeft |= (uint16_t)(1u << (vrgtok[i].iplr & 0x1f));
            }
        }

        /* prune players that have no attack relationships */
        for (i = 0; i < game.cPlayer; i++) {
            if (((uint16_t)(1u << (i & 0x1f)) & grplrLeft) != 0) {
                if ((grplrLeft & rggrfAttack[i]) == 0) {
                    grplrLeft = (uint16_t)(grplrLeft & ~(uint16_t)(1u << (i & 0x1f)));
                }
            }
        }

        if ((uint16_t)((grplrLeft - 1) & grplrLeft) == 0)
            break;

        /* init-based attack passes */
        for (init = initMac; initMin <= init; init--) {
            if (rgfInit[init] != 0) {
                int16_t itokScan = (int16_t)(vctok - 1);

                while (itokScan >= 0) {
                    /* only if this tok participates in this init bucket */
                    if ((int16_t)vrgtok[itokScan].initMin <= init && init <= (int16_t)vrgtok[itokScan].initMac) {
                        grplrLeft = 0;
                        for (i = 0; i < vctok; i++) {
                            if (vrgtok[i].fActive) {
                                grplrLeft |= (uint16_t)(1u << (vrgtok[i].iplr & 0x1f));
                            }
                        }
                        if ((uint16_t)((grplrLeft - 1) & grplrLeft) == 0)
                            break;

                        ptok = &vrgtok[itokScan];
                        if (ptok->fActive) {
                            lpbtlrec = (BTLREC *)lpbBattleCur;
                            lpbBattleCur += 6;

                            lpbtlrec->itok = (uint8_t)itokScan;
                            lpbtlrec->brcDest = 0;
                            lpbtlrec->ctok = 0;

                            lpbtlrec->iRound = (uint16_t)iRound;
                            lpbtlrec->brcDest = ptok->brc;
                            lpbtlrec->itokAttack = (uint16_t)itokScan;
                            lpbtlrec->dzDis = (uint16_t)(ptok->dzDis & 0x0f);

                            if (FAttack(itokScan, init, lpbtlrec, rggrfAttack[ptok->iplr]) == 0) {
                                lpbBattleCur -= 6;
                            } else {
                                ptok->fMoved = 0; /* asm: wFlags &= 0xffef */
                            }
                        }
                    }

                    itokScan--;
                }
            }
        }

        if ((uint16_t)((grplrLeft - 1) & grplrLeft) == 0)
            break;
    }

    /* --------------------------------------------------------------------
     * asm: 10f0:9824..987b
     * finalize cbData; SendBattleMessages; store grfPlayer
     * -------------------------------------------------------------------- */
    lpbtldata->cbData = (uint16_t)(lpbBattleCur - (uint8_t *)lpbtldata);

    SendBattleMessages(lpfl, cplr, lpbtldata->id, rgPlrLosses, grfPlayer, cShipsInvolved, cShdefsInvolved, grfSpectator);

    lpbtldata->grfPlr = grfSpectator; /* asm stores param at +0x4 after SendBattleMessages */

    /* --------------------------------------------------------------------
     * asm: 10f0:987f..990b
     * copy temp battle data into log at saved cursor if room; else write 0xFFFF sentinel and drop lpbBattleT
     *
     * IMPORTANT: The original uses 16-bit “offset within battle log block” arithmetic.
     * In modern flat memory we reproduce that by measuring the offset from lpbBattleLog.
     * -------------------------------------------------------------------- */
    {
        uint16_t offSav = (uint16_t)(uintptr_t)(lpbSav - lpbBattleLog);
        uint16_t avail = (uint16_t)(0xffc8u - offSav);

        if (avail < lpbtldata->cbData) {
            /* asm: *(uint16_t*)lpbSav = 0xffff; lpbBattleT = 0; */
            *(uint16_t *)lpbSav = 0xffffu;
            lpbBattleT = NULL;
        } else {
            memmove(lpbSav, (uint8_t *)lpbtldata, lpbtldata->cbData);
            lpbBattleCur = lpbSav + lpbtldata->cbData;
        }
    }

    /* --------------------------------------------------------------------
     * asm: 10f0:990b..9916
     * success return
     * -------------------------------------------------------------------- */
    (void)lpbMax; /* suppress unused if your build doesn’t use it elsewhere */
    return 1;
}

void CheckWeapons(TOK *ptok, int16_t *pfDampeningField, uint8_t *pinit) {
    int16_t pctJam;
    int32_t ldp;
    int32_t pctBeamDef;
    int16_t ihs;
    int16_t initMac;
    int16_t init;
    int16_t dxyMax;
    int16_t i;
    int32_t pctCap;
    int16_t initMin;
    int32_t pctHit;
    SHDEF  *lpshdef;
    int16_t dxyLim;
    int16_t initBase;
    HUL    *lphul;
    int16_t dxyPart;
    PART    part;

    /* ---- prologue ---- */
    pctCap = 1000;
    pctBeamDef = 1000;
    pctHit = 10000;

    initBase = ptok->initBase;

    initMin = -1;
    initMac = -1;
    dxyMax = -1;
    dxyLim = -1;

    lpshdef = LpshdefFromTok(ptok);
    ldp = DpShieldOfShdef(lpshdef, ptok->iplr);

    lphul = &lpshdef->hul;

    /* ---- iterate hull slots ---- */
    for (ihs = 0; ihs < lphul->chs; ihs++) {
        HS *hs = &lphul->rghs[ihs];

        if ((hs->grhst & (hstSpecialM | hstSpecialE | hstMining | hstTorp | hstBeam | hstArmor | hstShield | hstScanner)) != hstNone && hs->cItem != 0) {

            pctJam = 100;
            dxyPart = -1;
            part.hs = *hs;

            /* ---- init for weapons ---- */
            if ((part.hs.grhst & hstWeapon) == hstNone) {
                init = -1;
            } else {
                idPlayer = ptok->iplr;
                FLookupPart(&part);
                idPlayer = -1;

                if (part.hs.grhst == hstBeam)
                    init = initBase + part.pbeam->init;
                else
                    init = initBase + part.ptorp->init;

                if (init > 63)
                    init = 63;
            }

            /* ---- per-slot handling ---- */
            switch (part.hs.grhst) {

            case hstShield:
                if (part.hs.iItem == ishieldLangstonShell)
                    pctJam = 95;
                break;

            case hstArmor:
                if (part.hs.iItem == iarmorMegaPolyShell)
                    pctJam = 80;
                break;

            case hstBeam:
                idPlayer = ptok->iplr;
                FLookupPart(&part);
                idPlayer = -1;
                dxyPart = part.pbeam->dRangeMax;
                break;

            case hstTorp:
                ptok->fTorp = 1;
                idPlayer = ptok->iplr;
                FLookupPart(&part);
                idPlayer = -1;
                dxyPart = part.ptorp->dRangeMax;
                break;

            case hstMining:
                if (part.hs.iItem == iminingAlienMiner)
                    pctJam = 70;
                break;

            case hstSpecialE: {
                switch (part.hs.iItem) {

                case ispecialEMultiFunctionPod:
                    pctJam = 90;
                    break;

                case ispecialEJammer10:
                case ispecialEJammer20:
                case ispecialEJammer30:
                case ispecialEJammer50:
                    idPlayer = ptok->iplr;
                    FLookupPart(&part);
                    idPlayer = -1;
                    pctJam = 100 - part.pspecial->grAbility;
                    break;

                case ispecialEEnergyCapacitor:
                case ispecialEFluxCapacitor:
                    idPlayer = ptok->iplr;
                    FLookupPart(&part);
                    idPlayer = -1;

                    for (i = part.hs.cItem; i > 0; i--) {
                        int32_t factor = part.pspecial->grAbility + 100;
                        pctCap = (int32_t)((uint64_t)pctCap * factor / 100);
                    }
                    break;

                case ispecialEEnergyDampener:
                    *pfDampeningField = 1;
                    break;

                case ispecialETachyonDetector:
                    ptok->fDetector = 1;
                    break;
                }
                break;
            }

            case hstSpecialM:
                if (part.hs.iItem == ispecialMBeamDeflector) {
                    idPlayer = ptok->iplr;
                    FLookupPart(&part);
                    idPlayer = -1;

                    for (i = part.hs.cItem; i > 0; i--) {
                        int32_t factor = 100 - part.pspecial->grAbility;
                        pctBeamDef = (int32_t)((uint64_t)pctBeamDef * factor / 100);
                    }
                }
                break;
            }

            /* ---- apply jam multiplier ---- */
            if (pctJam < 100) {
                for (i = part.hs.cItem; i > 0; i--) {
                    pctHit = (int32_t)((uint64_t)pctHit * pctJam / 100);
                }
            }

            /* ---- range + initiative tracking ---- */
            if (dxyPart != -1) {
                if (ptok->grobj == 1)
                    dxyPart++;

                if (dxyMax < 0 || dxyPart < dxyMax)
                    dxyMax = dxyPart;

                if (dxyLim < dxyPart)
                    dxyLim = dxyPart;

                pinit[init] = 1;

                if (initMin == -1 || init < initMin)
                    initMin = init;

                if (initMac < init)
                    initMac = init;
            }
        }
    }

    /* ---- finalize pctJam ---- */
    if (pctHit == 10000) {
        ptok->pctJam = 0;
    } else {
        uint32_t q = (pctHit + 50) / 100;
        uint32_t v = 100 - q;
        ptok->pctJam = v;

        if (ptok->pctJam > 0x5f)
            ptok->pctJam = 0x5f;
    }

    if (ptok->grobj == 1)
        ptok->pctJam -= ptok->pctJam / 4;

    /* ---- finalize cap / beam def ---- */
    if (pctCap != 1000) {
        if (pctCap > 0x9f6)
            pctCap = 0x9f6;

        ptok->pctCap = pctCap / 10;
    }

    ptok->pctBeamDef = pctBeamDef / 10;

    /* ---- store nibble fields + init range ---- */
    ptok->dxyMax = dxyMax & 0xF;
    ptok->dxyLim = dxyLim & 0xF;
    ptok->initMin = initMin;
    ptok->initMac = initMac;

    /* ---- shield clamp ---- */
    if ((uint32_t)ldp >> 16 == 0)
        ptok->dpShield = ldp;
    else
        ptok->dpShield = 0xffff;
}

SHDEF *LpshdefFromTok(TOK *ptok) {
    /* Uses ptok->iplr (byte at +2) and ptok->ishdef (byte at +4). */
    uint8_t iplr = ptok->iplr;
    uint8_t ishdef = ptok->ishdef;

    if (ishdef < ishdefMax) {
        return &rglpshdef[iplr][ishdef];
    } else {
        return &rglpshdefSB[iplr][ishdef];
    }
}

int16_t CplrBattle(FLEET *lpfl, uint16_t *rggrfAttack, uint16_t *pgrfPlayer, uint16_t *pgrfSpectator) {
    int16_t  iplrStarbase;
    FLEET   *lpflCur;
    int32_t  rgcsh[16];
    uint16_t grPlr;
    int16_t  iplrCur;
    PLANET  *lppl;
    int16_t  cplr;
    int16_t  i;
    int16_t  mdRel;
    uint8_t  rgctok[16];
    int16_t  fChange;
    uint16_t iplrAttack;
    int16_t  fAttack;
    int16_t  cshdef;
    int16_t  ishdef;
    int16_t  cflTotal;  /* NOTE: used as 16-bit bitmask in asm (participants mask) */
    uint16_t grfPlayer; /* NOTE: used as 16-bit counter in asm (token total) */
    int16_t  ctokNew;
    int16_t  ctokFleet;

    /* ------------------------------------------------------------
     * asm: 10f0:2952..29a4  prolog/zero init
     * ------------------------------------------------------------ */
    iplrStarbase = -1;
    cflTotal = 0;
    fAttack = 0;
    grfMissed = 0;
    *pgrfSpectator = 0;
    memset(rggrfAttack, 0, 0x20);
    memset(rgcsh, 0, 0x40);

    /* ------------------------------------------------------------
     * asm: 10f0:29a4..2b38  optional planet/starbase pre-pass
     * ------------------------------------------------------------ */
    if (lpfl->idPlanet != -1) {
        PLANET *lpplT = LpplFromId(lpfl->idPlanet);

        /* types.h: PLANET.fStarbase is bit 9 of wFlags_0x4 in the ghidra dump */
        if (lpplT->fStarbase == 0) {
            if (lpplT->iPlayer != -1) {
                *pgrfSpectator |= (uint16_t)(1u << ((uint8_t)lpplT->iPlayer & 0x1f));
            }
        } else {
            /* starbase owner becomes a participant */
            iplrStarbase = lpplT->iPlayer;
            cflTotal = (int16_t)(1u << ((uint8_t)iplrStarbase & 0x1f));

            /* BTLPLAN.wRaw_0002 bitfields (types.h): iplrAttack is bits 8..12 */
            {
                BTLPLAN *pbtl = ((BTLPLAN **)rglpbtlplan)[iplrStarbase];

                /* pick the starbase design index from low 4 bits of lStarbase (asm AND 0x000F) */
                uint16_t isb = (uint16_t)(lpplT->lStarbase & 0x000Fu);
                SHDEF   *pshdefSB = (SHDEF *)((uint8_t *)rglpshdefSB[iplrStarbase] + (uint32_t)isb * (uint32_t)sizeof(SHDEF));

                /* asm calls FHullHasTeeth(&pshdefSB->hul) */
                if (FHullHasTeeth(&pshdefSB->hul) != 0 && pbtl->iplrAttack != 0) {
                    uint16_t iAttackT = pbtl->iplrAttack;

                    if (iAttackT == 1 || iAttackT == 2) {
                        for (i = 0; i < game.cPlayer; i++) {
                            if (i != iplrStarbase) {
                                /* PLAYER.rgmdRelation[16] at +0x70 (types.h PLAYER) */
                                mdRel = (int16_t)(int8_t)rgplr[iplrStarbase].rgmdRelation[i];
                                if (mdRel == 2 || (mdRel == 0 && iAttackT == 2)) {
                                    rggrfAttack[iplrStarbase] |= (uint16_t)(1u << ((uint8_t)i & 0x1f));
                                }
                            }
                        }
                    } else if (iAttackT == 3) {
                        /* asm writes to rggrfAttack[iplrStarbase] effectively as ~(1<<iplrStarbase) */
                        rggrfAttack[iplrStarbase] = (uint16_t)~(uint16_t)(1u << ((uint8_t)iplrStarbase & 0x1f));
                    } else {
                        rggrfAttack[iplrStarbase] |= (uint16_t)(1u << ((uint8_t)((uint16_t)iAttackT - 4u) & 0x1f));
                    }
                }
            }
        }
    }

    /* ------------------------------------------------------------
     * asm: 10f0:2b38..2da3  first fleet ring pass: collect participants + initial attack sets
     * label BATTLE::LNextFleet @ 10f0:2d7c
     * ------------------------------------------------------------ */
    lpflCur = lpfl;
    do {
        if (lpflCur->fDead == 0) { /* types.h FLEET.fDead is bit 10 of wFlags_0x4 */
            grPlr = lpflCur->iPlayer;
            cflTotal = (int16_t)((uint16_t)cflTotal | (uint16_t)(1u << ((uint8_t)grPlr & 0x1f)));

            /* if this fleet has a plan with teeth + nonzero attack mode, build rggrfAttack[iplr] */
            {
                uint16_t iplr = lpflCur->iPlayer;

                /* BTLPLAN is size 0x24; asm does iplan * 0x24 then reads word at +2 (wRaw_0002). */
                BTLPLAN *pbtl = rglpbtlplan[lpflCur->iplr];
                BTLPLAN *pbtlPlan = &pbtl[lpflCur->iplan];

                if (pbtlPlan->mdTarget2 != mdTargetNone && pbtlPlan->iplrAttack != iplrAttackNobody && FFleetHasTeeth(lpflCur)) {
                    fAttack = fTrue;

                    iplrAttack = pbtlPlan->iplrAttack;
                    if (pbtlPlan->mdTarget2 == mdTargetNone) {
                        iplrAttack = iplrAttackNobody;
                    }

                    if (iplrAttack != iplrAttackNobody) {
                        if (iplrAttack == iplrAttackEnemies || iplrAttack == iplrAttackNeutralsEnemies) {
                            for (i = 0; i < game.cPlayer; i++) {
                                if (i != (int16_t)iplr) {
                                    mdRel = (int16_t)(int8_t)rgplr[iplr].rgmdRelation[i];
                                    if (mdRel == 2 || (mdRel == 0 && iplrAttack == iplrAttackNeutralsEnemies)) {
                                        rggrfAttack[iplr] |= (uint16_t)(1u << ((uint8_t)i & 0x1f));
                                    }
                                }
                            }
                        } else if (iplrAttack == iplrAttackEveryone) {
                            rggrfAttack[iplr] = (uint16_t)~(uint16_t)(1u << ((uint8_t)iplr & 0x1f));
                        } else {
                            rggrfAttack[iplr] |= (uint16_t)(1u << ((uint8_t)((uint16_t)iplrAttack - 4u) & 0x1f));
                        }
                    }
                }
            }

            /* asm: set fDone=1 and fInclude=1 */
            lpflCur->fDone = 1;
            lpflCur->fInclude = 1;
        }

        lpflCur = lpflCur->lpflNext;
    } while (lpflCur != lpfl);

    /* ------------------------------------------------------------
     * asm: 10f0:2da3..3395  main solve
     * ------------------------------------------------------------ */
    if (fAttack == 0) {
        return 0;
    }

    /* 10f0:2db2..2df5  build initial “attack closure seed” in fChange (word) */
    fChange = 0;
    for (cplr = 0; cplr < game.cPlayer; cplr++) {
        if (pgrfPlayer[cplr] != 0) {
            fChange = (int16_t)((uint16_t)fChange | ((uint16_t)cflTotal & pgrfPlayer[cplr]));
        }
    }
    if (fChange == 0) {
        return 0;
    }

    /* 10f0:2e04..2e9d  transitive closure over pgrfPlayer rows (bit propagation) */
    for (cplr = 0; cplr < game.cPlayer; cplr++) {
        if ((pgrfPlayer[cplr] & (uint16_t)fChange) != 0) {
            fChange = (int16_t)((uint16_t)fChange | (uint16_t)(1u << ((uint8_t)cplr & 0x1f)));
        }

        if (((uint16_t)fChange & (uint16_t)(1u << ((uint8_t)cplr & 0x1f))) != 0) {
            for (grPlr = 0; grPlr < (uint16_t)game.cPlayer; grPlr++) {
                if ((pgrfPlayer[grPlr] & (uint16_t)(1u << ((uint8_t)cplr & 0x1f))) != 0) {
                    pgrfPlayer[cplr] = (uint16_t)(pgrfPlayer[cplr] | (uint16_t)(1u << ((uint8_t)grPlr & 0x1f)));
                }
            }
        }
    }

    /* ------------------------------------------------------------
     * asm: 10f0:2e9d..3027  prune unattached neutrals using relations + rggrfAttack propagation
     * (matches the ghidra “do { ... } while (fChange||lpfl!=lpflCur)” loop)
     * ------------------------------------------------------------ */
    lpflCur = lpfl;
    rgctok[0] = 0;
    do {
        /* if we wrapped, clear change */
        if (lpflCur == lpfl) {
            fChange = 0;
        }

        grPlr = lpflCur->iPlayer;
        {
            uint16_t bitPlr = (uint16_t)(1u << ((uint8_t)grPlr & 0x1f));

            if ((((uint16_t)cflTotal & bitPlr) != 0) && (((uint16_t)fChange & bitPlr) == 0)) {
                rggrfAttack[grPlr] = 0;

                for (i = 0; i < game.cPlayer; i++) {
                    if (i != (int16_t)grPlr) {
                        /* mdRel == 1 (“friend”) gate, and only if i is in fChange */
                        if ((int8_t)rgplr[grPlr].rgmdRelation[i] == 1 && (((uint16_t)fChange & (uint16_t)(1u << ((uint8_t)i & 0x1f))) != 0)) {

                            if ((rggrfAttack[grPlr] & (uint16_t)(1u << ((uint8_t)i & 0x1f))) != 0) {
                                rggrfAttack[grPlr] = 0;
                                break;
                            }

                            rggrfAttack[grPlr] |= rggrfAttack[i];
                        }
                    }
                }

                if (rggrfAttack[grPlr] == 0) {
                    cflTotal = (int16_t)((uint16_t)cflTotal & (uint16_t)~bitPlr);
                } else {
                    fChange = (int16_t)((uint16_t)fChange | bitPlr);
                }

                fChange = 1;
            }
        }

        lpflCur = lpflCur->lpflNext;
    } while (fChange != 0 || lpflCur != lpfl);

    /* 10f0:2fec..301d  if starbase present + still in mask, seed rgcsh[iplrStarbase]=1 and set fAttack=1 */
    if (iplrStarbase != -1) {
        uint16_t bitSB = (uint16_t)(1u << ((uint8_t)iplrStarbase & 0x1f));
        if (((uint16_t)cflTotal & bitSB) != 0) {
            rgcsh[iplrStarbase] = 1;
            fAttack = fTrue;
        }
    }

    /* ------------------------------------------------------------
     * asm: 10f0:3027..312b  build per-player “combat ship count” rgcsh[] and mark spectators (clear include)
     * ------------------------------------------------------------ */
    lpflCur = lpfl;
    rgctok[0] = 0;
    do {
        grPlr = lpflCur->iPlayer;
        {
            uint16_t bitPlr = (uint16_t)(1u << ((uint8_t)grPlr & 0x1f));

            if (((uint16_t)cflTotal & bitPlr) == 0) {
                *pgrfSpectator |= bitPlr;
                lpflCur->fInclude = 0;
            } else {
                for (cshdef = 0; cshdef < 16; cshdef++) {
                    if (lpflCur->rgcsh[cshdef] != 0) {
                        /* types.h: SHDEF.hul is at +0 and sizeof(SHDEF)=0x93 as in asm */
                        HullDef hookup = *(HullDef *)((uint8_t *)rglpshdef[grPlr] + (uint32_t)cshdef * (uint32_t)sizeof(SHDEF));
                        HULDEF *lphuldef = LphuldefFromId(hookup);

                        /* HULDEF.wFlags_0x7b >> 6 & 0xF in ghidra; types.h: HULDEF.imdAttack */
                        if (lphuldef->imdAttack != 0) {
                            uint16_t add = lpflCur->rgcsh[cshdef];
                            rgcsh[grPlr] += (int32_t)add;
                        }
                        fAttack = (int16_t)(fAttack + 1);
                    }
                }
            }
        }

        lpflCur = lpflCur->lpflNext;
    } while (lpflCur != lpfl);

    /* ------------------------------------------------------------
     * asm: 10f0:312b..3154  popcount(fChange) into low word of lppl slot (stack overlap!)
     *   NOTE: nb09 says lppl is PLANET*; asm reuses its low 16 bits as an int counter/divisor.
     * ------------------------------------------------------------ */
    *(int16_t *)&lppl = 0;
    while (fChange != 0) {
        if ((fChange & 1) != 0) {
            *(int16_t *)&lppl = (int16_t)(*(int16_t *)&lppl + 1);
        }
        fChange = (int16_t)((uint16_t)fChange >> 1);
    }

    /* ------------------------------------------------------------
     * asm: 10f0:3154..3378  “token budget” reduction when fAttack > 0xFF
     * ------------------------------------------------------------ */
    if (fAttack > 0xff) {
        grfPlayer = 0;                              /* token total */
        cplr = (int16_t)(0xff / *(int16_t *)&lppl); /* IDIV */

        /* if starbase in participants, add 1 token (asm: grfPlayer += 1) */
        if (iplrStarbase != -1) {
            uint16_t bitSB = (uint16_t)(1u << ((uint8_t)iplrStarbase & 0x1f));
            if (((uint16_t)cflTotal & bitSB) != 0) {
                grfPlayer = (uint16_t)(grfPlayer + 1);
            }
        }

        memset(rgctok, 0, sizeof(rgctok));

        /* pass 1: if a player’s token usage would exceed per-player budget, exclude fleet + mark bombed + set highword bit7 */
        lpflCur = lpfl;
        do {
            if (lpflCur->fInclude != 0) {
                ctokNew = 0;
                grPlr = lpflCur->iPlayer;

                for (cshdef = 0; cshdef < 16; cshdef++) {
                    if (lpflCur->rgcsh[cshdef] != 0) {
                        ctokNew++;
                    }
                }

                if ((int16_t)((uint16_t)rgctok[grPlr] + (uint16_t)ctokNew) > cplr) {
                    lpflCur->fInclude = 0;
                    lpflCur->fBombed = 1;

                    lpflCur->fSkipped = 1;
                } else {
                    rgctok[grPlr] = (uint8_t)(rgctok[grPlr] + (uint8_t)ctokNew);
                    grfPlayer = (uint16_t)(grfPlayer + (uint16_t)ctokNew);
                }
            }

            lpflCur = lpflCur->lpflNext;
        } while (lpflCur != lpfl);

        /* pass 2: if we’re still under 0xFF total, re-include some marked fleets (those with dirLong-hi bit7) */
        if (grfPlayer < 0xff) {
            lpflCur = lpfl;
            do {
                if (lpflCur->fSkipped != 0) {
                    ctokNew = 0;
                    grPlr = lpflCur->iPlayer;

                    for (cshdef = 0; cshdef < 16; cshdef++) {
                        if (lpflCur->rgcsh[cshdef] != 0) {
                            ctokNew++;
                        }
                    }

                    if (grfPlayer + ctokNew < 0x100) {
                        lpflCur->fInclude = 1;
                        lpflCur->fBombed = 0;
                        lpflCur->fSkipped = 0;

                        rgctok[grPlr] = (uint8_t)(rgctok[grPlr] + ctokNew);
                        grfPlayer = (uint16_t)(grfPlayer + ctokNew);
                    }
                }

                lpflCur = lpflCur->lpflNext;
            } while (lpflCur != lpfl);
        }
    }

    /* ------------------------------------------------------------
     * asm: 10f0:3378..3395  epilog/return selection
     * ------------------------------------------------------------ */
    *pgrfSpectator = cflTotal;

    /* asm tests word at [BP+rgctok] (first two bytes of rgctok array as a flag) */
    if (*(uint16_t *)&rgctok[0] != 0) {
        return (int16_t)0xffff;
    }

    return *(int16_t *)&lppl; /* lppl low word holds the popcount/divisor counter */
}

void SpankTheCheaters(void) {
    int32_t lSell;
    PLANET *lppl;
    FLEET  *lpfl;
    int16_t ifl;
    int16_t i;
    int32_t pctSell;
    int16_t fCheater;
    int16_t fSellOff;
    char    rgfCheater[16];
    PLANET *lpplMac;

    fCheater = 0;

    for (i = 0; i < game.cPlayer; i++) {
        if ((rgfCheater[i] = (uint16_t)rgplr[i].fCheater) != 0)
            fCheater = fTrue;
    }

    if (!fCheater || game.turn < 10)
        return;

    FORFLEETS(lpfl, ifl) {
        if (!lpfl->fDead && rgfCheater[lpfl->iPlayer]) {
            if (Random(12) == 0) {
                lpfl->fDead = fTrue;
                FSendPlrMsg2(lpfl->iPlayer, idmHasDefectedRanksDueInabilityProjectLegitimate, -5, lpfl->id, 0);
            } else {
                fSellOff = 0;
                for (i = 0; i <= 3; i++)
                    if (lpfl->rgwtMin[i] > 0) {
                        if (!fSellOff) {
                            pctSell = 10 + Random(11);
                            fSellOff = fTrue;
                        }
                        lSell = lpfl->rgwtMin[i] * pctSell / 100;
                        if (lSell == 0)
                            lSell = 1;
                        lpfl->rgwtMin[i] -= lSell;
                    }
                if (fSellOff)
                    FSendPlrMsg2(lpfl->iPlayer, idmCrewHasSoldOffCargoBlackMarket, -5, lpfl->id, LOWORD(pctSell));
            }
        }
    }

    FORPLANETS(lppl, lpplMac) {
        if (lppl->iPlayer != -1 && rgfCheater[lppl->iPlayer]) {
            if (lppl->cMines > 0 && Random(8) == 0) {
                pctSell = 5 + Random(31);
                lSell = (int32_t)lppl->cMines * pctSell / 100;
                if (lSell <= 0)
                    lSell = 1;
                lppl->cMines -= (unsigned)lSell;
                FSendPlrMsg2(lppl->iPlayer, idmFreedomFightersHaveStolenKtStockpilesPress, -5, lppl->id, LOWORD(lSell));
            } else if (Random(15) == 0) {
                i = Random(3);
                pctSell = 5 + Random(41);
                lSell = lppl->rgwtMin[i] * pctSell / 100;
                if (lSell > 0) {
                    if (lSell > 30000)
                        lSell = 30000;
                    lppl->rgwtMin[i] -= lSell;

                    FSendPlrMsg(lppl->iPlayer, idmFreedomFightersHaveAttackedDestroyedMinesPress, -5, lppl->id, LOWORD(lSell), i + 1, 0, 0, 0, 0);
                }
            }
        }
    }
}

int16_t ITechLearnATech(int16_t iplr, int16_t x, int16_t y, MessageId idm, uint16_t *piGoto) {
    uint16_t iGoto;
    int16_t  fBattle;
    int16_t  i;
    int16_t  iTech;
    int32_t  l;

    if (!rgplr[iplr].fLearned && Random(100) > 49) {
        for (i = 0; i < 13; i++) {
            iTech = Random(13);
            if (rgTechTrader[iTech] != 0 && ((1 << iTech) & rgplr[iplr].grbitTrader) == 0 && Random(100) < rgTechTrader[iTech]) {

                fBattle = IdmGiveTraderPart(1 << iTech, iplr, &iGoto);
                if (idm != 0xFFFF) {
                    FSendPlrMsg2(iplr, fBattle + idmStarbaseHasBuiltNew, iGoto, x, y);
                } else if (piGoto != NULL) {
                    *piGoto = iGoto;
                }
                rgplr[iplr].fLearned = 1;
                return -(iTech + 1);
            }
        }
        for (i = 0; i < 6; i++) {
            iTech = Random(6);
            if ((int16_t)rgplr[iplr].rgTech[iTech] < (int16_t)(uint16_t)rgTechBattle[iTech]) {
                l = GetTechLevelCost(iTech, rgplr[iplr].rgTech[iTech] + 1, iplr);
                if (game.fSlowTech) {
                    l >>= 1;
                }
                rgplr[iplr].rgResSpent[iTech] += l;
                if (idm != ~idmColonistsDroppedMassacredGroundTroops) {
                    if (game.fSlowTech) {
                        l <<= 1;
                    }
                    FSendPlrMsg(iplr, idm, -2, x, y, iTech, (int16_t)l, (int16_t)((uint32_t)l >> 16), 0, 0);
                } else if (piGoto != NULL) {
                    *piGoto = 0xfffe;
                }
                rgplr[iplr].fLearned = 1;
                return iTech + 1;
            }
        }
    }
    return 0;
}

int16_t FDamageTok(TOK *ptok, int16_t itok, int32_t *pdpBeam, int32_t dpTorp, uint16_t grfWeapon, int16_t fShieldsOnly, int32_t *pcTorp) {
    int16_t   pctSh;
    DV        dv;
    uint16_t *pwLosses;
    int16_t   cshOrigDamaged;
    int32_t   dpShdef;
    int32_t   ddpOrig;
    int32_t   dpOrig;
    PLANET   *lppl;
    int16_t   i;
    int16_t   cshOrig;
    FLEET    *lpfl;
    int32_t   cKillMax;
    int16_t   csh;
    int32_t   dpT;
    int16_t   pctDp;
    int16_t   ishdef;
    int32_t   dp;
    uint16_t  pctDpNew;

    /* ------------------------------------------------------------
     * asm: 10f0:81d4..8217
     * prolog, dp = *pdpBeam, init battle record (8 bytes)
     * ------------------------------------------------------------ */
    dp = *pdpBeam;

    memset(lpbBattleCur, 0, 8);
    lpbBattleCur[0] = itok;
    lpbBattleCur[1] = grfWeapon;

    /* ------------------------------------------------------------
     * asm: 10f0:8218..8303
     * apply beam damage to shields first (ptok->dpShield is per-ship; total shield = dpShield * csh)
     * record absorbed shield damage into battlecur+4 (packed)
     * ------------------------------------------------------------ */
    if (ptok->dpShield == 0) {
        if (fShieldsOnly != 0) {
            return 0;
        }
    } else {
        /* dpOrig = total shield points across the stack */
        dpOrig = (int32_t)((uint32_t)ptok->dpShield * (uint32_t)ptok->csh);

        if ((uint32_t)dp < (uint32_t)dpOrig) {
            /* some shields remain */
            *(uint16_t *)(lpbBattleCur + 4) = WPackLong(dp);

            /* new per-ship shield = (totalShield - dp) / csh */
            ptok->dpShield = (uint16_t)(((uint32_t)dpOrig - (uint32_t)dp) / (uint32_t)ptok->csh);

            dp = 0;
        } else {
            /* shields exhausted */
            dp -= dpOrig;

            *(uint16_t *)(lpbBattleCur + 4) = WPackLong(dpOrig);
            ptok->dpShield = 0;
        }
    }

    /* ------------------------------------------------------------
     * asm: 10f0:8304..838d
     * early-out record if nothing left to do (or shields-only) and no torps
     * also: if weapon has bit 2 set, OR in 0xC0 into battlecur[1]
     * ------------------------------------------------------------ */
    if (((dp == 0) || (fShieldsOnly != 0)) && (dpTorp == 0)) {
        *(uint16_t *)(lpbBattleCur + 6) = ptok->dv.dp;
        *pdpBeam = dp;

        if ((lpbBattleCur[1] & bitFTorp) != 0) {
            lpbBattleCur[1] = (uint8_t)(lpbBattleCur[1] | 0xC0u);
        }

        lpbBattleCur += 8;
    } else {
        /* --------------------------------------------------------
         * asm: 10f0:838e..83c7
         * cKillMax = *pcTorp if provided, else INT32_MAX
         * dpT = total incoming damage (beam+torp) tracked as dpT
         * -------------------------------------------------------- */
        if (pcTorp == NULL) {
            cKillMax = 0x7fffffffL;
        } else {
            cKillMax = *pcTorp;
        }

        dpT = dp + dpTorp;

        ishdef = ptok->ishdef;
        dpShdef = (int32_t)(uint32_t)LpshdefFromTok(ptok)->hul.dp;
        dv.dp = ptok->dv.dp;

        /* --------------------------------------------------------
         * asm: 10f0:83c8..856c
         * starbase token path (ptok->grobj == 1)
         * -------------------------------------------------------- */
        if (ptok->grobj == grobjPlanet) {
            lppl = LpplFromId(ptok->id);

            /* if already damaged (dv.pctDp != 0), add “extra” effective DP: dpShdef * pctDp / 500 */
            if (dv.pctDp != 0) {
                dpT += (int32_t)(((uint32_t)dpShdef * dv.pctDp) / 500u);
            }

            dp = dpT;

            /* if dp < dpShdef (also preserves the asm’s “(dp < 0) || (dp < 0x10000 && lo(dp) < dpShdef)” shape) */
            if ((dp < 0) || ((dp < 0x10000L) && ((uint32_t)dp < (uint32_t)dpShdef))) {
                /* compute new planet starbase pctDp = ceil(dp*500 / dpShdef) with “must-change” tweak */
                pctDpNew = (uint16_t)(((uint32_t)dp * 500u) / (uint32_t)dpShdef);

                if (lppl->pctDp == pctDpNew) {
                    /* ensure visible change: increment stored pctDp by 1 (fits the asm’s +0x10 in lStarbase high bits) */
                    lppl->pctDp = (uint16_t)(lppl->pctDp + 1);
                } else {
                    lppl->pctDp = pctDpNew;
                }

                /* record updated dp% into battlecur dv (keep pctSh low 7 bits, set pctDp high 9 bits) */
                *(uint16_t *)(lpbBattleCur + 6) = (uint16_t)((*(uint16_t *)(lpbBattleCur + 6) & 0x007Fu) | (uint16_t)(lppl->pctDp << 7));

                fStarbaseDamaged = 1;
            } else {
                /* starbase destroyed: set pctDp=500 (=> 500<<7 == 64000) */
                *(uint16_t *)(lpbBattleCur + 6) = (uint16_t)((*(uint16_t *)(lpbBattleCur + 6) & 0x007Fu) | 64000u);

                /* mark token dead */
                lpbBattleCur[2] = 1;
                lpbBattleCur[3] = 0;

                ptok->wFlags &= (uint16_t)~1u; /* clear fActive */
                ptok->csh = 0;

                fStarbaseDied = 1;

                if (GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) != raMacintosh) {
                    /* clear planet fStarbase */
                    lppl->fStarbase = 0;
                    KillQueuedShips(lppl);
                    KillQueuedMassPackets(lppl);
                }
            }

            /* if pctDp != 0 in the recorded dv, force it to 100 and copy into ptok->dv */
            if ((*(uint16_t *)(lpbBattleCur + 6) >> 7) != 0) {
                *(uint16_t *)(lpbBattleCur + 6) = (uint16_t)((*(uint16_t *)(lpbBattleCur + 6) & 0xFF80u) | 100u);
                ptok->dv.dp = *(uint16_t *)(lpbBattleCur + 6);
            }

            *pdpBeam = 0;
            lpbBattleCur += 8;
        } else {
            /* --------------------------------------------------------
             * asm: 10f0:856d.. (ship token path)
             * -------------------------------------------------------- */

            /* if mdTactic == 1: clear it and update wFlags */
            if (ptok->mdTactic == 1) {
                ptok->mdTactic = 0;
                ptok->wFlags = (uint16_t)((ptok->wFlags & 0xFC1Fu) | 0x00E0u);
            }

            lpfl = LpflFromId(ptok->id);
            cshOrig = ptok->csh;

            /* cshOrigDamaged and ddpOrig derive from dv.{pctSh,pctDp} */
            if (dv.pctDp == 0) {
                cshOrigDamaged = 0;
                ddpOrig = 0;
            } else {
                /* cshOrigDamaged = ceil(cshOrig * pctSh / 100), but if result==0 => 1 */
                cshOrigDamaged = (int16_t)(((uint32_t)cshOrig * dv.pctSh) / 100u);
                if (cshOrigDamaged == 0) {
                    cshOrigDamaged = 1;
                }

                /* ddpOrig = ceil(dpShdef * pctDp / 500), but if result==0 => 1 */
                ddpOrig = (int32_t)(((uint32_t)dpShdef * dv.pctDp) / 500u);
                if (ddpOrig == 0) {
                    ddpOrig = 1;
                }
            }

            /* pwLosses = vrgPlrLosses + iplr*16 + ishdef; set 0x8000 */
            pwLosses = vrgPlrLosses + (uint16_t)ptok->iplr * 16u + (uint16_t)ptok->ishdef;
            *pwLosses = (uint16_t)(*pwLosses | 0x8000u);

            csh = cshOrig;

            /* --------------------------------------------------------
             * asm: “kill damaged ships first” loop
             * cost per kill = dpShdef - ddpOrig (can be <= dpShdef)
             * -------------------------------------------------------- */
            if (cshOrigDamaged != 0) {
                int16_t cshDamagedStart = cshOrigDamaged;
                int32_t dpPerKillDamaged = dpShdef - ddpOrig;

                csh = cshOrigDamaged;
                while ((dpPerKillDamaged <= dpT) && (csh != 0) && (cKillMax != 0)) {
                    dpT -= dpPerKillDamaged;
                    csh--;

                    cKillMax--;

                    if ((*pwLosses & 0x1FFFu) < 0x1FFFu) {
                        (*pwLosses)++;
                    }
                }

                /* dpPerKillNormal = ddpOrig + (dpShdef - ddpOrig) == dpShdef */
                ddpOrig += dpPerKillDamaged;

                cshOrigDamaged = csh;

                /* restore total remaining ship count: remaining damaged + undamaged */
                csh = csh + (cshOrig - cshDamagedStart);
            }

            /* --------------------------------------------------------
             * asm: “kill remaining ships” loop using dpShdef cost
             * -------------------------------------------------------- */
            while ((ddpOrig <= dpT) && (csh != 0) && (cKillMax != 0)) {
                dpT -= ddpOrig;
                csh--;

                cKillMax--;

                if ((*pwLosses & 0x1FFFu) < 0x1FFFu) {
                    (*pwLosses)++;
                }
            }

            if (cKillMax <= 0) {
                dpT = 0;
            }

            /* --------------------------------------------------------
             * asm: compute new pctSh / pctDp depending on leftover dpT and remaining ships
             * -------------------------------------------------------- */
            if ((dpT == 0) || (csh == 0)) {
                if (cshOrigDamaged == 0) {
                    pctSh = 0;
                    pctDp = 0;
                } else {
                    /* pctSh = ceil(cshOrigDamaged*100 / csh) */
                    pctSh = (int16_t)(((uint32_t)cshOrigDamaged * 100u + (uint32_t)csh - 1u) / (uint32_t)csh);
                    pctDp = dv.pctDp;
                }
            } else {
                /* average remaining dp per ship: ceil((dpT + ddpOrig*cshOrigDamaged) / csh) with +csh-1 bias */
                if (cshOrigDamaged != 0) {
                    dpT += (int32_t)((uint32_t)ddpOrig * (uint32_t)cshOrigDamaged);
                    dpT += (csh - 1);
                }

                dpT = (int32_t)((uint32_t)dpT / (uint32_t)csh);
                if (dpT == 0) {
                    dpT = 1;
                }

                /* pctDp = ceil(dpT*500 / dpShdef), min 1 */
                pctDp = (int16_t)(((uint32_t)dpT * 500u + (uint32_t)dpShdef - 1u) / (uint32_t)dpShdef);
                if (pctDp == 0) {
                    pctDp = 1;
                }

                pctSh = 100;
            }

            /* --------------------------------------------------------
             * asm: record kills, apply KillShips, update dv + fleet dv, compute leftover beam dp
             * -------------------------------------------------------- */
            *(uint16_t *)(lpbBattleCur + 2) = (uint16_t)(ptok->csh - csh);
            if (csh != ptok->csh) {
                KillShips(ptok, *(int16_t *)(lpbBattleCur + 2), ptok->ishdef, lpfl, 1);
            }

            if (csh != 0) {
                if (pctDp > 499) {
                    pctDp = 499;
                }

                ptok->dv.pctDp = pctDp;
                ptok->dv.pctSh = pctSh;

                /* this was the decompiler’s “rgcsh[ishdef+0x10] = dv.dp” alias; real target is rgdv[].dp */
                lpfl->rgdv[ptok->ishdef].dp = ptok->dv.dp;

                dpT = 0;
            }

            if (dpTorp < dpT) {
                *pdpBeam = dpT - dpTorp;
            } else {
                *pdpBeam = 0;
            }

            *(uint16_t *)(lpbBattleCur + 6) = ptok->dv.dp;
            lpbBattleCur += 8;

            if (pcTorp != NULL) {
                *pcTorp = cKillMax;
            }
        }
    }

    /* asm: function returns 1 on non-early-exit path */
    return 1;
}

void KillShips(TOK *ptok, int16_t cshKill, int16_t ishdef, FLEET *lpfl, int16_t fFallout) {
    FLEET    flDead;
    int16_t  i;
    FLEET    flSrc;
    SHDEF   *lpshdef;
    uint16_t csh;

    if (cshKill == 0)
        return;

    if (fFallout) {
        lpshdef = LpshdefFromTok(ptok);
        MarkTechsSeen(&lpshdef->hul, (uint16_t)ptok->iplr);
    }

    flSrc = *lpfl;
    memset(&flDead, 0, sizeof(FLEET));

    csh = flSrc.rgcsh[ishdef] - cshKill;
    flDead.rgcsh[ishdef] = cshKill;
    flSrc.rgcsh[ishdef] = csh;
    ptok->csh = csh;

    if (csh == 0) {
        ptok->fActive = 0;
        for (ishdef = 0; ishdef < cShdefMax && flSrc.rgcsh[ishdef] == 0; ishdef++)
            ;
        if (ishdef == cShdefMax) {
            lpfl->fDead = 1;
            if (fFallout) {
                for (i = 0; i < 3; i++)
                    flDead.rgwtMin[i] = flSrc.rgwtMin[i];
            }
        }
    }

    if (!lpfl->fDead) {
        flDead.iPlayer = flSrc.iPlayer;
        // Mark the dead fleet as dead
        flDead.det = 7;
        flDead.fDead = 1;
        FleetTransferCargoBalance(&flSrc, &flDead);
    }

    if (fFallout) {
        flDead.iPlayer = flSrc.iPlayer;
        flDead.pt.x = flSrc.pt.x;
        flDead.pt.y = flSrc.pt.y;
        flDead.idPlanet = flSrc.idPlanet;
        CreateSalvage(&flDead, &lpthBattle);
    }

    if (!lpfl->fDead) {
        *lpfl = flSrc;
    }
}

void SendBattleMessages(FLEET *lpflBtl, int16_t cplr, int16_t idBtl, uint16_t *rgPlrLosses, int16_t grfPlayer, int16_t cShipsInvolved, int16_t cShdefsInvolved,
                        uint16_t grfSpectator) {
    int16_t   iplrStarbase;
    int16_t   iplr;
    uint8_t   rgcfl[16];
    int32_t   lpopStarbase;
    uint16_t *pw;
    int16_t   isb;
    PLANET   *lppl;
    uint16_t *pwThem;
    int16_t   fAlive;
    int16_t   cUs;
    int16_t   y;
    FLEET    *lpfl;
    int16_t   cThemDead;
    int16_t   i;
    int16_t   idm;
    int16_t   j;
    FLEET    *lpflT;
    int16_t   cUsDead;
    int16_t   iThem;
    uint16_t *pwUs;
    int16_t   cThem;
    int16_t   x;

    /* debug symbols */
    /* label IndecisiveXWay @ MEMORY_BATTLE:0xaa8f */
    /* label CommonCountingCode @ MEMORY_BATTLE:0xa4a1 */

    /* ------------------------------------------------------------
     * asm: 10f0:9c0e..9c46
     * prologue, init locals, clear rgcfl, determine (x,y) and lppl/isb/iplrStarbase
     * ------------------------------------------------------------ */
    iplrStarbase = -1;
    lppl = NULL;
    isb = 0;
    memset(rgcfl, 0, sizeof(rgcfl));

    if (lpflBtl->idPlanet == -1) {
        /* battle in deep space */
        x = lpflBtl->pt.x;
        y = lpflBtl->pt.y;
    } else {
        /* battle in orbit */
        x = -1;
        y = lpflBtl->idPlanet;
        lppl = LpplFromId(y);

        iThem = lppl->iPlayer;
        if (iThem != -1) {
            /* planet has an owner; note starbase if present or if starbase died this battle */
            if (lppl->fStarbase || (fStarbaseDied != 0)) {
                isb = lppl->isb; /* PLANET.lStarbase union bitfield */
                iplrStarbase = iThem;
            }

            /* if a Macintosh starbase died, planet gets uninhabited after caching pop */
            if ((fStarbaseDied != 0) && (GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) == raMacintosh)) {
                lpopStarbase = lppl->rgwtMin[3];
                UninhabitPlanet(lppl);
            }
        }
    }

    /* ------------------------------------------------------------
     * asm: 10f0:9d01..9d47
     * mark designs that were present in any non-dead fleet: rgPlrLosses[iplr*16+ishdef] |= 0x4000
     * ------------------------------------------------------------ */
    lpfl = lpflBtl;
    do {
        if (!lpfl->fDead) {
            for (i = 0; i < 16; i++) {
                if (lpfl->rgcsh[i] > 0) {
                    rgPlrLosses[lpfl->iPlayer * 16 + i] |= 0x4000;
                }
            }
        }
        lpfl = lpfl->lpflNext;
    } while (lpfl != NULL && lpfl != lpflBtl);

    /* ------------------------------------------------------------
     * asm: 10f0:9d48..ad?? (main loop)
     * per-player message generation
     * ------------------------------------------------------------ */
    for (iplr = 0; iplr < game.cPlayer; iplr++) {

        /* --------------------------------------------------------
         * asm: 10f0:9d55..9e2d
         * if player did NOT participate (not in grfPlayer), send “battle took place” if colony owner / spectator
         * -------------------------------------------------------- */
        if ((((uint16_t)grfPlayer >> (iplr & 15)) & 1u) == 0) {

            /* colony owner gets a different message */
            if (lppl != NULL && lppl->iPlayer == iplr) {
                FSendPlrMsg2(iplr, idmColonyReportsBattleTookPlaceOrbitForces, lppl->id, lppl->id, 0);
                ITechLearnATech(iplr, x, y, idmFleetFoundWreckageBattleWhichHasBoosted, 0);
            } else {
                /* spectators: only if allowed and they have a fleet present */
                if (((grfSpectator >> (iplr & 15)) & 1u) != 0) {
                    lpflT = lpflBtl;
                    while (lpflT != NULL) {
                        if (lpflT->iPlayer == iplr) {
                            break;
                        }
                        lpflT = lpflT->lpflNext;
                        if (lpflT == lpflBtl) {
                            lpflT = NULL;
                            break;
                        }
                    }

                    if (lpflT != NULL && lpflT->iPlayer == iplr) {
                        FSendPlrMsg(iplr, idmReportsBattleTookPlaceForcesInvolved, lpflT->id | 0x8000, lpflT->id, lpflT->pt.x, lpflT->pt.y, 0, 0, 0, 0);
                        ITechLearnATech(iplr, x, y, idmWreckageBattleOccurredOrbitHasBoostedResearch, 0);
                    }
                }
            }

            /* --------------------------------------------------------
             * asm: 10f0:ad23..ad?? (label in decompile)
             * if player “missed” the battle, and they had a skipped fleet, send maneuvering message
             * -------------------------------------------------------- */
            if (((grfMissed >> (iplr & 15)) & 1u) != 0) {
                lpflT = lpflBtl;
                while (lpflT != NULL) {
                    if (lpflT->iPlayer == iplr) {
                        if ((((uint32_t)lpflT->dirLong >> (16 + 7)) & 1u) != 0) {
                            break;
                        }
                    }
                    lpflT = lpflT->lpflNext;
                    if (lpflT == lpflBtl) {
                        lpflT = NULL;
                        break;
                    }
                }

                if (lpflT != NULL && lpflT->iPlayer == iplr && (((uint32_t)lpflT->dirLong >> (16 + 7)) & 1u) != 0) {
                    FSendPlrMsg2(iplr, idmDueExcessiveFleetManeuveringBattleAreaFleets, lpflT->id | 0x8000, x, y);
                }
            }

            continue;
        }

        /* --------------------------------------------------------
         * asm: 10f0:9e2e..9eb5
         * Macintosh special post-starbase-died narrative
         * -------------------------------------------------------- */
        fAlive = 1;
        if (fStarbaseDied != 0 && GetRaceStat(&rgplr[iplrStarbase], rsMajorAdv) == raMacintosh) {

            if (iplr == iplrStarbase) {
                /* compare lpopStarbase against 1001 with sign-aware split (matches asm’s 32-bit compares) */
                if (lpopStarbase < 1001) {
                    idm = idmBattleTookPlaceDestroyedColonistsHaveJoined;
                } else {
                    idm = idmBattleTookPlaceDestroyedScreamsColonistsEcho;
                }
            } else {
                idm = idmBattleTookPlaceDestroyedKillingColonistsBargain;
            }

            j = (int16_t)((iplrStarbase << 5) | (isb + 0x10u));

            /* pack lpopStarbase high/low like asm’s __aFulshr path */
            FSendPlrMsg(iplr, idm, idBtl | 0x4000, x, y, j, (int16_t)(uint16_t)lpopStarbase, (int16_t)((uint32_t)lpopStarbase >> 16), 0, 0);
            continue;
        }

        /* --------------------------------------------------------
         * asm: 10f0:9eb8..a39? (two-player special cases then common counting)
         * -------------------------------------------------------- */
        if (cplr == 2) {

            /* ----------------------------------------------------
             * asm: 10f0:9f??..a1?? (case: two ships involved)
             * picks pwUs/pwThem by scanning for any nonzero cell
             * ---------------------------------------------------- */
            if (cShipsInvolved == 2) {
                pwThem = NULL;
                pwUs = NULL;
                pw = rgPlrLosses;

                for (i = 0; i < 16; i++) {
                    for (j = 0; j < 16; j++) {
                        if (*pw != 0) {
                            if (i == iplr) {
                                pwUs = pw;
                            } else {
                                pwThem = pw;
                            }
                        }
                        pw++;
                    }
                }

                if (((pwUs == NULL) && (fStarbaseDied != 0)) || (pwUs != NULL && ((*pwUs & 0x3fff) != 0))) {
                    if (((pwThem == NULL) && (fStarbaseDamaged != 0)) || (pwThem != NULL && ((*pwThem & 0x8000) != 0))) {
                        idm = idmBattleTookPlaceDestroyedWhichDamagedFray;
                    } else {
                        idm = idmBattleTookPlaceDestroyedWhichTookDamage;
                    }
                    fAlive = 0;
                } else if (((pwThem == NULL) && (fStarbaseDied != 0)) || (pwThem != NULL && ((*pwThem & 0x3fff) != 0))) {
                    if (((pwUs == NULL) && (fStarbaseDamaged != 0)) || (pwUs != NULL && ((*pwUs & 0x8000) != 0))) {
                        idm = idmBattleTookPlaceDestroyedHoweverTookDamage;
                    } else {
                        idm = idmBattleTookPlaceDestroyedTakingDamage;
                    }
                } else {
                    idm = idmBattleTookPlaceNeitherNorDestroyedIncident;
                }

                if (pwUs == NULL) {
                    i = (int16_t)((iplrStarbase << 5) | (isb + 0x10u));
                } else {
                    int16_t  idx = (int16_t)(pwUs - rgPlrLosses);
                    uint16_t u = idx;
                    i = (int16_t)(((u & 0xf0u) << 1) | (u & 0x0fu));
                }

                if (pwThem == NULL) {
                    j = (int16_t)((iplrStarbase << 5) | (isb + 0x10u));
                } else {
                    int16_t  idx = (int16_t)(pwThem - rgPlrLosses);
                    uint16_t u = idx;
                    j = (int16_t)(((u & 0xf0u) << 1) | (u & 0x0fu));
                }

                FSendPlrMsg(iplr, idm, idBtl | 0x4000, x, y, i, j, 0, 0, 0);

                if (fAlive && (lppl == NULL || lppl->iPlayer == -1 || iplr == lppl->iPlayer)) {
                    ITechLearnATech(iplr, x, y, idmWreckageDiscoveredBattleHasBoostedResearchResour, 0);
                }
                goto CommonCountingCode; /* falls through to missed-battle check in asm layout */
            }

            /* ----------------------------------------------------
             * asm: 10f0:a251..a3?? (case: two shdefs involved)
             * counts per-side totals using rgcsh across fleets
             * ---------------------------------------------------- */
            if (cShdefsInvolved == 2) {
                pwThem = NULL;
                pwUs = NULL;
                pw = rgPlrLosses;

                for (i = 0; i < 16; i++) {
                    for (j = 0; j < 16; j++) {
                        if (*pw != 0) {
                            if (i == iplr) {
                                pwUs = pw;
                            } else {
                                pwThem = pw;
                            }
                        }
                        pw++;
                    }
                }

                if (((pwUs == NULL) && (fStarbaseDied != 0)) || (pwUs != NULL && ((*pwUs & 0x4000) == 0))) {
                    if (((pwThem == NULL) && (fStarbaseDamaged != 0)) || (pwThem != NULL && ((*pwThem & 0x8000) != 0))) {
                        idm = idmBattleTookPlaceDestroyedWhichDamagedFray2;
                    } else {
                        idm = idmBattleTookPlaceDestroyedWhichTookDamage2;
                    }
                    fAlive = 0;
                } else if (((pwThem == NULL) && (fStarbaseDied != 0)) || (pwThem != NULL && ((*pwThem & 0x4000) == 0))) {
                    if (((pwUs == NULL) && (fStarbaseDamaged != 0)) || (pwUs != NULL && ((*pwUs & 0x8000) != 0))) {
                        idm = idmBattleTookPlaceDestroyedHoweverTookDamage2;
                    } else {
                        idm = idmBattleTookPlaceDestroyedTakingDamage2;
                    }
                } else {
                    idm = idmBattleTookPlaceNeitherNorCompletelyDestroyed;
                }

                cUs = (pwUs == NULL) ? 1 : (*pwUs & 0x1fff);
                cThem = (pwThem == NULL) ? 1 : (*pwThem & 0x1fff);

                lpflT = lpflBtl;
                do {
                    if (!lpflT->fDead) {
                        if (lpflT->iPlayer == iplr) {
                            if (pwUs != NULL) {
                                int16_t idx = (int16_t)(pwUs - rgPlrLosses);
                                cUs = (int16_t)(cUs + lpflT->rgcsh[(idx - (int16_t)(lpflT->iPlayer * 16)) & 15]);
                            }
                        } else {
                            if (pwThem != NULL) {
                                int16_t idx = (int16_t)(pwThem - rgPlrLosses);
                                cThem = (int16_t)(cThem + lpflT->rgcsh[(idx - (int16_t)(lpflT->iPlayer * 16)) & 15]);
                            }
                        }
                    }
                    lpflT = lpflT->lpflNext;
                } while (lpflT != NULL && lpflT != lpflBtl);

                if (pwUs == NULL) {
                    i = (int16_t)((iplrStarbase << 5) | (isb + 0x10u));
                } else {
                    uint16_t u = (uint16_t)(int16_t)(pwUs - rgPlrLosses);
                    i = (int16_t)(((u & 0xf0u) << 1) | (u & 0x0fu));
                }

                if (pwThem == NULL) {
                    j = (int16_t)((iplrStarbase << 5) | (isb + 0x10u));
                } else {
                    uint16_t u = (uint16_t)(int16_t)(pwThem - rgPlrLosses);
                    j = (int16_t)(((u & 0xf0u) << 1) | (u & 0x0fu));
                }

                FSendPlrMsg(iplr, idm, idBtl | 0x4000, x, y, i, cUs, j, cThem, 0);

                if (fAlive && (lppl == NULL || lppl->iPlayer == -1 || iplr == lppl->iPlayer)) {
                    ITechLearnATech(iplr, x, y, idmWreckageDiscoveredBattleHasBoostedResearchResour, 0);
                }
                goto CommonCountingCode;
            }
        }

    CommonCountingCode:
        /* --------------------------------------------------------
         * asm: 10f0:a4a1..a?? (label CommonCountingCode)
         * general case: count ships lost (dead) and ships involved (alive+dead) for us vs them (+ starbase)
         * -------------------------------------------------------- */
        cThem = 0;
        cUs = 0;
        pwUs = NULL;
        pwThem = NULL;
        iThem = 0;

        pw = rgPlrLosses;
        for (i = 0; i < 16; i++) {
            for (j = 0; j < 16; j++) {
                if (*pw != 0) {
                    if (i == iplr) {
                        pwUs = pw;
                        cUs = (int16_t)(cUs + (*pw & 0x1fff));
                    } else {
                        pwThem = pw;
                        cThem = (int16_t)(cThem + (*pw & 0x1fff));
                        iThem = i;
                    }
                }
                pw++;
            }
        }

        iThem = (int16_t)(iThem | 0x30);
        cUsDead = cUs;
        cThemDead = cThem;

        if (fStarbaseDied != 0) {
            if (iplrStarbase == iplr) {
                cUsDead = (int16_t)(cUs + 1);
            } else if (iplrStarbase != -1) {
                cThemDead = (int16_t)(cThem + 1);
            }
        }

        lpflT = lpflBtl;
        do {
            if (!lpflT->fDead) {
                if (lpflT->iPlayer == iplr) {
                    for (i = 0; i < 16; i++) {
                        cUs = (int16_t)(cUs + lpflT->rgcsh[i]);
                    }
                } else {
                    for (i = 0; i < 16; i++) {
                        cThem = (int16_t)(cThem + lpflT->rgcsh[i]);
                    }
                }
            }
            lpflT = lpflT->lpflNext;
        } while (lpflT != NULL && lpflT != lpflBtl);

        if (iplrStarbase == iplr) {
            cUs = (int16_t)(cUs + 1);
        } else if (iplrStarbase != -1) {
            cThem = (int16_t)(cThem + 1);
            iThem = (int16_t)(iplrStarbase | 0x30);
        }

        /* --------------------------------------------------------
         * asm: 10f0:a7??..ac?? (multi-player vs 2-player message selection)
         * -------------------------------------------------------- */
        if (cplr != 2) {

            if (cUsDead == 0) {
                if (cThem == cThemDead) {
                    FSendPlrMsg(iplr, idmBattleTookPlaceInvolvingRacesForcesDestroyed, idBtl | 0x4000, x, y, cplr, cUs, 0, 0, 0);
                } else {
                    /* label IndecisiveXWay */
                    FSendPlrMsg(iplr, idmBattleTookPlaceInvolvingRacesLostForces2, idBtl | 0x4000, x, y, cplr, cUsDead, cUs, cThemDead, cThem);
                }
            } else if (cThemDead == 0) {
                if (cUs != cUsDead) {
                    /* label IndecisiveXWay */
                    FSendPlrMsg(iplr, idmBattleTookPlaceInvolvingRacesLostForces2, idBtl | 0x4000, x, y, cplr, cUsDead, cUs, cThemDead, cThem);
                } else {
                    FSendPlrMsg(iplr, idmBattleTookPlaceInvolvingRacesEntireArmada, idBtl | 0x4000, x, y, cplr, cUs, cThem, 0, 0);
                }
            } else if (cThemDead == cThem) {
                FSendPlrMsg(iplr, idmBattleTookPlaceInvolvingRacesLostForces, idBtl | 0x4000, x, y, cplr, cUsDead, cUs, 0, 0);
            } else if (cUsDead == cUs) {
                FSendPlrMsg(iplr, idmBattleTookPlaceInvolvingRacesEntireArmada2, idBtl | 0x4000, x, y, cplr, cUs, cThem, cThemDead, 0);
            } else {
                FSendPlrMsg2(iplr, idmBattleTookPlacePressGotoButtonView, idBtl | 0x4000, x, y);
            }

            if (lppl == NULL || lppl->iPlayer == -1 || iplr == lppl->iPlayer) {
                ITechLearnATech(iplr, x, y, idmWreckageDiscoveredBattleHasBoostedResearchResour, 0);
            }

        } else {
            /* ----------------------------------------------------
             * asm: 10f0:ac??..ad?? (two-player “against” message selection)
             * ---------------------------------------------------- */
            if (cThem == 1) {
                if ((iThem & 0x0f) == iplrStarbase) {
                    j = (int16_t)((iplrStarbase << 5) | (isb + 0x10u));
                } else {
                    uint16_t u = (uint16_t)(int16_t)(pwThem - rgPlrLosses);
                    j = (int16_t)(((u & 0xf0u) << 1) | (u & 0x0fu));
                }
            }

            if (cUs == 1) {
                if (iplr == iplrStarbase) {
                    i = (int16_t)((iplrStarbase << 5) | (isb + 0x10u));
                } else {
                    uint16_t u = (uint16_t)(int16_t)(pwUs - rgPlrLosses);
                    i = (int16_t)(((u & 0xf0u) << 1) | (u & 0x0fu));
                }
            }

            if (cThemDead == cThem) {
                if (cThemDead == 1) {
                    if (cUsDead == 0) {
                        FSendPlrMsg(iplr, idmBattleTookPlaceAgainstForcesDestroyedTaking, idBtl | 0x4000, x, y, iThem, cUs, j, 0, 0);
                    } else {
                        FSendPlrMsg(iplr, idmBattleTookPlaceAgainstForcesDestroyedHowever, idBtl | 0x4000, x, y, iThem, cUs, j, cUsDead, 0);
                    }
                } else if (cUsDead == 0) {
                    if (cUs == 1) {
                        FSendPlrMsg(iplr, idmBattleTookPlaceAgainstDestroyedEnemyForces, idBtl | 0x4000, x, y, iThem, i, cThemDead, 0, 0);
                    } else {
                        FSendPlrMsg(iplr, idmBattleTookPlaceAgainstForcesDestroyedEnemy, idBtl | 0x4000, x, y, iThem, cUs, 0, 0, 0);
                    }
                } else {
                    FSendPlrMsg(iplr, idmBattleTookPlaceAgainstForcesDestroyedEnemy2, idBtl | 0x4000, x, y, iThem, cUs, cUsDead, 0, 0);
                }
            } else if (cUsDead == cUs) {
                if (cUsDead == 1) {
                    if (cThemDead == 0) {
                        FSendPlrMsg(iplr, idmBattleTookPlaceAgainstDestroyedEnemysForces, idBtl | 0x4000, x, y, iThem, i, cThem, 0, 0);
                    } else {
                        FSendPlrMsg(iplr, idmBattleTookPlaceAgainstDestroyedEnemysForces2, idBtl | 0x4000, x, y, iThem, i, cThem, cThemDead, 0);
                    }
                } else if (cThemDead == 0) {
                    if (cThem == 1) {
                        FSendPlrMsg(iplr, idmBattleTookPlaceAgainstForcesDestroyed, idBtl | 0x4000, x, y, iThem, cUsDead, j, 0, 0);
                    } else {
                        FSendPlrMsg(iplr, idmBattleTookPlaceAgainstForcesDestroyedEnemys, idBtl | 0x4000, x, y, iThem, cThem, 0, 0, 0);
                    }
                } else {
                    FSendPlrMsg(iplr, idmBattleTookPlaceAgainstForcesDestroyedEnemys2, idBtl | 0x4000, x, y, iThem, cThem, cThemDead, 0, 0);
                }
            } else if (cUs == 1) {
                FSendPlrMsg(iplr, idmBattleTookPlaceAgainstNeitherNorEnemys, idBtl | 0x4000, x, y, iThem, i, cThem, cThemDead, 0);
            } else if (cThem == 1) {
                FSendPlrMsg(iplr, idmBattleTookPlaceAgainstNeitherForcesNor2, idBtl | 0x4000, x, y, iThem, cUs, j, cUsDead, 0);
            } else {
                FSendPlrMsg(iplr, idmBattleTookPlaceAgainstNeitherForcesNor, idBtl | 0x4000, x, y, iThem, cUs, cThem, cUsDead, cThemDead);
            }

            if ((cUsDead != cUs) && (lppl == NULL || lppl->iPlayer == -1 || iplr == lppl->iPlayer)) {
                ITechLearnATech(iplr, x, y, idmWreckageDiscoveredBattleHasBoostedResearchResour, 0);
            }
        }

        /* --------------------------------------------------------
         * asm: 10f0:ad23..ad?? (missed-battle message; shared tail)
         * -------------------------------------------------------- */
        if (((grfMissed >> (iplr & 15)) & 1u) != 0) {
            lpflT = lpflBtl;
            while (lpflT != NULL) {
                if (lpflT->iPlayer == iplr) {
                    if ((((uint32_t)lpflT->dirLong >> (16 + 7)) & 1u) != 0) {
                        break;
                    }
                }
                lpflT = lpflT->lpflNext;
                if (lpflT == lpflBtl) {
                    lpflT = NULL;
                    break;
                }
            }

            if (lpflT != NULL && lpflT->iPlayer == iplr && (((uint32_t)lpflT->dirLong >> (16 + 7)) & 1u) != 0) {
                FSendPlrMsg2(iplr, idmDueExcessiveFleetManeuveringBattleAreaFleets, lpflT->id | 0x8000, x, y);
            }
        }
    }
}

int16_t FDoesPrimaryTargetTypeExist(TOK *ptok, uint16_t grfAttack) {
    uint16_t mdTarget;
    TOK      tok;
    int16_t  itokLook;

    mdTarget = ptok->mdTarget1;
    if (mdTarget == mdTargetNone)
        return 0;

    for (itokLook = 0; itokLook < vctok; itokLook++) {
        if (vrgtok[itokLook].iplr == ptok->iplr)
            continue;
        if (((1 << (vrgtok[itokLook].iplr & 0x1F)) & grfAttack) == 0)
            continue;

        tok = vrgtok[itokLook];
        if (!tok.fActive)
            continue;

        switch (mdTarget) {
        case mdTargetAny:
            return 1;
        case mdTargetStarbase:
            if (tok.grobj == grobjPlanet)
                return 1;
            break;
        case mdTargetArmedShips:
            if (tok.mdTarget0 == mdTargetArmedShips)
                return 1;
            break;
        case mdTargetBombersFreighters:
            if (tok.mdTarget0 == mdTargetBombersFreighters || tok.mdTarget0 == mdTargetFreighters)
                return 1;
            break;
        case mdTargetUnarmedShips:
            if (tok.mdTarget0 > mdTargetBombersFreighters)
                return 1;
            break;
        case mdTargetFuelTransports:
            if (tok.mdTarget0 == mdTargetFuelTransports)
                return 1;
            break;
        case mdTargetFreighters:
            if (tok.mdTarget0 == mdTargetFreighters)
                return 1;
            break;
        }
    }
    return 0;
}

/*
 * DzFromBrcBrc - Chebyshev distance between two battle grid squares.
 *
 * A BRC (Battle Row/Column) packs an (x, y) coordinate into one byte:
 *   low nibble  (bits 0-3) = x column (0-9)
 *   high nibble (bits 4-7) = y row    (0-9)
 *
 * Returns the Chebyshev (chessboard) distance: max(|dx|, |dy|).
 * This is the number of moves needed when diagonal movement costs 1,
 * which matches the battle board's 8-directional movement rules.
 */
int16_t DzFromBrcBrc(uint8_t brc1, uint8_t brc2) {
    int16_t dx;
    int16_t dy;

    dx = abs((int16_t)(brc1 & 0x0F) - (int16_t)(brc2 & 0x0F));
    dy = abs((int16_t)(brc1 >> 4) - (int16_t)(brc2 >> 4));

    if (dx <= dy) {
        return dy;
    }
    return dx;
}

int32_t DpFromPtokBrcToBrc(TOK *ptok, uint8_t brcSrc, uint8_t brcTarget, TOK *ptokTarget, int16_t fProximity) {
    int16_t dz;
    int32_t dpMax;
    int32_t dpShdef;
    int16_t ihs;
    int32_t cTorpBase;
    int32_t dpTotal;
    int16_t fOutOfRange;
    int32_t dRange;
    HUL    *lphul;
    int32_t cTorpHit;
    int32_t dp;
    PART    part;
    int32_t dpShieldsLeft;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x4fb1 */

    /* TODO: implement */
    return 0;
}

int16_t DxyMoveTokTo(TOK *ptok, int16_t spdMove, uint16_t grfAttack) {
    uint16_t   iplr;
    int16_t    xMax;
    int16_t    dz;
    int32_t    scoreBest;
    uint8_t    brc;
    int32_t    rgscoreNear[3][3];
    int32_t    score;
    int16_t    cBest;
    int16_t    yMin;
    int16_t    dy;
    int16_t    mdTactic;
    int16_t    y;
    uint8_t    brcOOR;
    int16_t    i;
    int16_t    yCur;
    uint8_t    brcBest;
    int16_t    dzAwayBest;
    int16_t    yMax;
    int16_t    dx;
    int16_t    xCur;
    int16_t    fPrimary;
    int32_t    dp;
    int16_t    dzAway;
    int16_t    x;
    int16_t    fXMajor;
    int32_t    lLow;
    int16_t    cLow;
    STARSPOINT rgptDeltas[2];

    iplr = ptok->iplr;
    dp = 0;

    xCur = XFromBrc(ptok->brc);
    yCur = YFromBrc(ptok->brc);

    if (ptok->grobj == grobjPlanet || spdMove == 0)
        goto LReturnDxy;

    scoreBest = 30000000;

    mdTactic = ptok->mdTactic;
    fPrimary = FDoesPrimaryTargetTypeExist(ptok, grfAttack);

    for (x = 0; x < 3; x++)
        for (y = 0; y < 3; y++)
            rgscoreNear[x][y] = 30000000;

    dz = DzMoveRangeToConsider(ptok, grfAttack, &brcOOR);
    x = xCur - dz;
    if (x < 0)
        x = 0;

    yMin = yCur - dz;
    if (yMin < 0)
        yMin = 0;

    xMax = xCur + dz;
    if (xMax >= 10)
        xMax = 9;

    yMax = yCur + dz;
    if (yMax >= 10)
        yMax = 9;

    for (; x <= xMax; x++)
        for (y = yMin; y <= yMax; y++) {
            brc = BrcFromXY(x, y);

            dx = xCur - x;
            dy = yCur - y;
            dx = abs(dx);
            dy = abs(dy);

            score = ScoreGuessBattleDamage(ptok, brc, fPrimary, grfAttack);

            if (mdTactic == mdTacticDisengage) {
                for (i = 0; i < vctok; i++)
                    if (vrgtok[i].brc == brc && vrgtok[i].iplr == iplr)
                        score += 2;

                if (brc == ptok->brc)
                    score -= 1;
            }

            dzAway = DzFromBrcBrc(ptok->brc, brc);
            if (dzAway <= 1)
                rgscoreNear[x - xCur + 1][y - yCur + 1] = score;

            if (score < scoreBest || score == scoreBest && dzAway <= dzAwayBest) {
                if (score == scoreBest && dzAway == dzAwayBest) {
                    cBest++;
                    if (Random(cBest) == 0)
                        goto LTakeSquare;
                } else {
                    cBest = 1;

                    scoreBest = score;
                    dzAwayBest = dzAway;
                LTakeSquare:
                    brcBest = brc;
                }
            }
        }

    if (brcOOR != 0xff)
        brcBest = brcOOR;

    dzAway = DzFromBrcBrc(ptok->brc, brcBest);
    if (dzAway > 1) {
        dx = XFromBrc(brcBest) - xCur;
        dy = YFromBrc(brcBest) - yCur;

        if (abs(dx) == abs(dy)) {
            if (dx > 0)
                xCur++;
            else
                xCur--;

            if (dy > 0)
                yCur++;
            else
                yCur--;
        } else if (dx == 0) {
            int32_t lLow = 300000000;
            int16_t cLow = 0;

            dy = (dy < 0) ? 0 : 2;
            yCur += (dy - 1);

            for (i = 0; i < 3; i++) {
                if (rgscoreNear[i][dy] <= lLow) {
                    if (rgscoreNear[i][dy] < lLow) {
                        lLow = rgscoreNear[i][dy];
                        cLow = 1;
                    } else
                        cLow++;
                }
            }

            x = Random(cLow);
            for (i = 0; i < 3; i++)
                if (rgscoreNear[i][dy] == lLow)
                    if (x-- == 0)
                        break;

            xCur += (i - 1);
        } else if (dy == 0) {
            int32_t lLow = 300000000;
            int16_t cLow = 0;

            dx = (dx < 0) ? 0 : 2;
            xCur += (dx - 1);

            for (i = 0; i < 3; i++) {
                if (rgscoreNear[dx][i] <= lLow) {
                    if (rgscoreNear[dx][i] < lLow) {
                        lLow = rgscoreNear[dx][i];
                        cLow = 1;
                    } else
                        cLow++;
                }
            }

            x = Random(cLow);
            for (i = 0; i < 3; i++)
                if (rgscoreNear[dx][i] == lLow)
                    if (x-- == 0)
                        break;

            yCur += (i - 1);
        } else {
            STARSPOINT rgptDeltas[2];
            bool       fXMajor = abs(dx) > abs(dy);

            dx = (dx > 0) ? 2 : 0;
            dy = (dy > 0) ? 2 : 0;

            rgptDeltas[0].x = dx;
            rgptDeltas[0].y = dy;

            if (fXMajor) {
                rgptDeltas[1].x = dx;
                rgptDeltas[1].y = 1;
            } else {
                rgptDeltas[1].x = 1;
                rgptDeltas[1].y = dy;
            }

            if (rgscoreNear[rgptDeltas[0].x][rgptDeltas[0].y] < rgscoreNear[rgptDeltas[1].x][rgptDeltas[1].y] ||
                (rgscoreNear[rgptDeltas[0].x][rgptDeltas[0].y] == rgscoreNear[rgptDeltas[1].x][rgptDeltas[1].y] && Random(2) == 0))
                i = 0;
            else
                i = 1;

            xCur += (rgptDeltas[i].x - 1);
            yCur += (rgptDeltas[i].y - 1);
        }

        brcBest = BrcFromXY(xCur, yCur);
    }

    if (scoreBest != 30000000) {
        if (XFromBrc(brcBest) > 9 || YFromBrc(brcBest) > 9)
            brcBest = ptok->brc;
        ptok->brc = brcBest;
    }

LReturnDxy:
    ptok->fMoved = fTrue;

    return 1;
}

int16_t FHullHasBombs(HUL *lphul) {
    HS     *lphs;
    int16_t ihs;

    lphs = lphul->rghs;
    for (ihs = 0; ihs < (int16_t)lphul->chs; ihs++) {
        if (lphs->grhst == hstBomb && lphs->cItem != 0) {
            return 1;
        }
        if (lphs->grhst == hstBeam && lphs->iItem == ibeamMultiContainedMunition && lphs->cItem != 0) {
            return 1;
        }
        if (lphs->grhst == hstSpecialM && lphs->iItem == ispecialMOrbitalConstructionModule && lphs->cItem != 0) {
            return 1;
        }
        lphs++;
    }
    return 0;
}

#ifdef _WIN32

INT_PTR CALLBACK BattlePlansDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t (*lpProc)(void);
    int16_t idc;
    int16_t i;
    int16_t fRet;
    RECT    rc;
    int16_t cLen;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x113e */
    /* label LSelectName @ MEMORY_BATTLE:0x14a5 */
    /* label LRename @ MEMORY_BATTLE:0x0f9c */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK NewPlanNameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RECT rc;

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RelationsDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HDC         hdc;
    int16_t     mdSBase;
    PAINTSTRUCT ps;
    RECT        rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x019f */
    /* block (block) @ MEMORY_BATTLE:0x0464 */

    /* TODO: implement */
    return 0;
}
#endif /* _WIN32 */