
#include "globals.h"
#include "types.h"

#include "ship2.h"

#include "msg.h"
#include "parts.h"
#include "race.h"
#include "ship.h"
#include "util.h"
#include "utilgen.h"

/* functions */
int16_t FScout(FLEET *lpfl) {
    int16_t i;

    for (i = 0; i < ishdefMax; i++) {
        if (lpfl->rgcsh[i] != 0) {
            /* original: (__aFlshl(wFlags,1) & 0x70) != 0
               equivalent: (wFlags & 0x38) != 0
               SHDEF overlay: det bits 3..5 */
            if ((rgshdef[i].det & 0x38u) != 0)
                return 1;
        }
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * FStargateJump
 *
 * Resolve and apply stargate “mis-jump” damage for a fleet attempting to jump.
 *
 * Inputs:
 *   lpfl     Fleet attempting to use a stargate (updated in-place on success/failure).
 *   isbsSrc  Source starbase index/id (passed through to MdCalcStargateDamage).
 *   isbsDst  Destination starbase index/id (passed through to MdCalcStargateDamage).
 *   dDist    Jump distance (passed through to MdCalcStargateDamage).
 *
 * High-level flow:
 *   1) Make a working copy of the fleet (flSrc) and clear per-design damage percentages (rgpct[]).
 *
 *   2) Determine the destination planet id used for messaging:
 *      - Look at lpfl->lpplord->rgord[1]. If it targets a planet (grobjPlanet), use rgord[1].id.
 *      - Otherwise interpret rgord[1].pt as a coordinate and scan rgptPlan[] to find a matching
 *        planet index (0..game.cPlanMax-1). (If no match, id ends up == game.cPlanMax.)
 *
 *   3) For each ship design slot ishdef that has ships in the fleet:
 *      - Accumulate total ship count (cshOrig).
 *      - Call MdCalcStargateDamage(isbsSrc, isbsDst, dDist, wtEmpty, &rgpct[ishdef]) to compute
 *        a per-design damage percentage and an overall status:
 *          * -2: jump not possible due to ship(s) -> send idmAttemptedUseStargateReachCouldBecauseShips, return 0
 *          * -1: jump not possible due to destination -> send idmAttemptedUseStargateReachCouldBecauseDestination, return 0
 *          *  0: design unaffected (doesn’t count toward “survivors”)
 *          *  1: design affected and marks flSrc.fNoHeal (no healing)
 *          *  >0: design affected
 *        Track how many distinct designs are “in play” (cshdef).
 *
 *   4) If no designs survive/are eligible (cshdef == 0):
 *      - Mark the original fleet dead (lpfl->fDead = 1),
 *      - Send idmHeedlessDangerAttemptedUseStargateReachFleet,
 *      - Return 0.
 *
 *   5) Otherwise, compute ship losses and updated damage state per affected design:
 *      - If rgpct[ishdef] == 100: all ships of that design are destroyed.
 *      - Else:
 *          * Compute a per-ship random kill chance pctKill (rgpct/3), except races with raStargate
 *            take no random-kill chance.
 *          * Track “already damaged” ships using flSrc.rgdv[ishdef].pctDp (old damage %), and update
 *            (pctDp,pctSh) based on weighted old/new damage-per-ship (dpPerShdefOld/dpPerShdefNew)
 *            derived from hull dp and damage percentages.
 *          * Update ship counts, clear DV if a design is wiped out, and accumulate total ships killed
 *            (cshKill). Record per-design killed counts into flDead.rgcsh[] for cargo balancing.
 *
 *   6) If the process kills every remaining design (cshdef becomes 0), fall back to the same
 *      “killed them all” handling as step (4).
 *
 *   7) If any ships were lost (cshKill != 0):
 *      - Choose and send an appropriate “lost ships in jump” message based on magnitude of losses
 *        versus cshOrig (including a special “unbelievable” path when cshKill doesn’t fit in 16 bits).
 *      - Prepare a “dead fleet” record (flDead: detAll, fInclude=1, fDead=1, etc.) and call
 *        FleetTransferCargoBalance(&flSrc, &flDead) to proportionally shed cargo corresponding
 *        to destroyed ships.
 *
 *   8) Copy the modified working fleet back to *lpfl and return 1 (jump proceeds with updated fleet).
 *
 * Returns:
 *   1 if the jump proceeds (fleet updated in-place, possibly with losses/damage),
 *   0 if the jump is aborted or the fleet is destroyed (and an appropriate message is sent).
 * -------------------------------------------------------------------------- */
int16_t FStargateJump(FLEET *lpfl, int16_t isbsSrc, int16_t isbsDst, int16_t dDist) {
    int16_t    dpPerShdefNew;
    int16_t    dpShdef;
    STARSPOINT pt;
    int16_t    id;
    FLEET      flSrc;
    int16_t    cshT;
    uint8_t    pctKill;
    int16_t    i;
    int32_t    cshOrig;
    int16_t    idm;
    int32_t    cshKill;
    int16_t    pct;
    int16_t    rgpct[16];
    int16_t    cshdef;
    int16_t    ishdef;
    int32_t    dp;
    int16_t    dpPerShdefOld;
    int16_t    cshDamagedOld;
    FLEET      flDead;

    /* debug symbols */
    /* label LKilledEmAll @ MEMORY_SHIP2:0x0f06 */

    /* ------------------------------------------------------------
     * asm: 1080:0d07..0d37
     * ------------------------------------------------------------ */
    cshdef = 0;
    cshKill = 0;
    cshOrig = 0;
    memset(rgpct, 0, sizeof(rgpct));

    /* ------------------------------------------------------------
     * asm: 1080:0d3a..0d4e  (MOVSW.REP 0x3e words)
     * ------------------------------------------------------------ */
    memcpy(&flSrc, lpfl, sizeof(FLEET));

    /* ------------------------------------------------------------
     * asm: 1080:0d53..0dc4  (resolve destination planet id)
     *   If ((*(word*)(lpplord+0x1c) >> 8) & 0xF) == 1:
     *       id = *(word*)(lpplord+0x1a)
     *   else:
     *       find id by matching coords *(word*)(+0x16),(+0x18) against rgptPlan[]
     * ------------------------------------------------------------ */
    {
        PLORD *plord = flSrc.lpplord;
        ORDER *wp1 = &plord->rgord[1];

        /* asm: (word at +0x1c >> 8) & 0xF == 1  ==> wp1->grobj == 1 */
        if (wp1->grobj == grobjPlanet) {
            /* asm: id = word at +0x1a ==> wp1->id */
            id = wp1->id;
        } else {
            /* asm: pt = words at +0x16/+0x18 ==> wp1->pt */
            pt = wp1->pt;

            id = 0;
            while (id < game.cPlanMax) {
                if (rgptPlan[id].x == pt.x && rgptPlan[id].y == pt.y)
                    break;
                id++;
            }
        }
    }

    /* ------------------------------------------------------------
     * asm: 1080:0dc4..0efc  (scan designs, compute rgpct via MdCalcStargateDamage)
     * ------------------------------------------------------------ */
    ishdef = 0;
    while (ishdef < cShdefMax) {
        if (flSrc.rgcsh[ishdef] != 0) {
            int16_t cshdefTry = (int16_t)(cshdef + 1);
            cshOrig += (int32_t)flSrc.rgcsh[ishdef];

            uint16_t wt = rglpshdef[flSrc.iPlayer][ishdef].hul.wtEmpty;

            {
                int16_t md = MdCalcStargateDamage(isbsSrc, isbsDst, dDist, wt, &rgpct[ishdef]);

                if (md == -2) {
                    FSendPlrMsg(flSrc.iPlayer, idmAttemptedUseStargateReachCouldBecauseShips, flSrc.id | 0x8000, flSrc.id, flSrc.idPlanet, id, ishdef, 0, 0, 0);
                    return 0;
                }
                if (md == -1) {
                    FSendPlrMsg(flSrc.iPlayer, idmAttemptedUseStargateReachCouldBecauseDestination, flSrc.id | 0x8000, flSrc.id, flSrc.idPlanet, id, 0, 0, 0,
                                0);
                    return 0;
                }
                if (md == 0) {
                    cshdef = cshdefTry - 1;
                } else {
                    cshdef = cshdefTry;
                    if (md == 1) {
                        /* asm: flSrc.wFlags_0x4 = (.. &0xbfff) | 0x4000 */
                        flSrc.fNoHeal = 1;
                    }
                }
            }
        }

        ishdef = ishdef + 1;
    }

    /* ------------------------------------------------------------
     * asm: 1080:0efc..0f50  LKilledEmAll case (no eligible ship designs)
     * ------------------------------------------------------------ */
    if (cshdef == 0) {
    LKilledEmAll:
        /* asm: lpfl->wFlags_0x4 = (.. &0xfbff) | 0x0400 */
        lpfl->fDead = 1;

        FSendPlrMsg(flSrc.iPlayer, idmHeedlessDangerAttemptedUseStargateReachFleet, flSrc.id | 0x8000, flSrc.id, flSrc.idPlanet, id, 0, 0, 0, 0);
        return 0;
    }

    /* ------------------------------------------------------------
     * asm: 1080:0f53..0f65
     * ------------------------------------------------------------ */
    memset(&flDead, 0, sizeof(FLEET));

    /* ------------------------------------------------------------
     * asm: 1080:0f68..139a  (apply losses/damage per design)
     * ------------------------------------------------------------ */
    for (ishdef = 0; ishdef < cShdefMax; ishdef = ishdef + 1) {
        if (flSrc.rgcsh[ishdef] == 0)
            continue;
        if (rgpct[ishdef] == 0)
            continue;

        if (rgpct[ishdef] == 100) {
            cshKill += (int32_t)flSrc.rgcsh[ishdef];
            flSrc.rgcsh[ishdef] = 0;
            flSrc.rgdv[ishdef].dp = 0;
            cshdef = (int16_t)(cshdef - 1);
        } else {
            cshT = flSrc.rgcsh[ishdef];

            /* pctKill = (rgpct/3) unless RA=Stargate then 0 */
            {
                int16_t ra = GetRaceStat((PLAYER *)rgplr + lpfl->iPlayer, rsMajorAdv);
                if (ra == raStargate) {
                    pctKill = 0;
                } else {
                    pctKill = (uint8_t)(rgpct[ishdef] / 3);
                }
            }

            /* dpShdef := shdef[ishdef].(word+0x38) (asm reads +0x38) */
            dpShdef = rglpshdef[lpfl->iPlayer][ishdef].hul.dp;

            /* cshDamagedOld = (cshT * pctDp)/100, min 1 if nonzero pctDp */
            if (flSrc.rgdv[ishdef].pctDp == 0) {
                cshDamagedOld = 0;
            } else {
                cshDamagedOld = (int16_t)(((int32_t)cshT * (int32_t)flSrc.rgdv[ishdef].pctDp) / 100);
                if (cshDamagedOld == 0)
                    cshDamagedOld = 1;
            }

            /* kill-loop */
            if (pctKill != 0) {
                for (i = 0; i < flSrc.rgcsh[ishdef]; i = (int16_t)(i + 1)) {
                    int16_t r = Random(100);
                    if (r < (int16_t)pctKill) {
                        cshT = (int16_t)(cshT - 1);

                        if (cshDamagedOld != 0) {
                            uint16_t r2 = (uint16_t)Random(500);
                            if (r2 < (uint16_t)flSrc.rgdv[ishdef].pctDp) {
                                cshDamagedOld = (int16_t)(cshDamagedOld - 1);
                            }
                        }
                    }
                }

                cshKill += (int32_t)(flSrc.rgcsh[ishdef] - cshT);
            }

            if (cshT != 0) {
                /* dpPerShdefOld = (dpShdef * pctDp)/500, min 1 if nonzero pctDp */
                if (flSrc.rgdv[ishdef].pctDp == 0) {
                    dpPerShdefOld = 0;
                } else {
                    dpPerShdefOld = (int16_t)(((int32_t)dpShdef * (int32_t)flSrc.rgdv[ishdef].pctDp) / 500);
                    if (dpPerShdefOld == 0)
                        dpPerShdefOld = 1;
                }

                /* dpPerShdefNew = (dpShdef * rgpct)/100, min 1 */
                dpPerShdefNew = (int16_t)(((int32_t)dpShdef * (int32_t)rgpct[ishdef]) / 100);
                if (dpPerShdefNew == 0)
                    dpPerShdefNew = 1;

                /* if damaged ships exist and dpShdef <= dpPerShdefNew+dpPerShdefOld, kill damaged ships outright */
                if (cshDamagedOld != 0) {
                    if (dpShdef <= (int16_t)(dpPerShdefNew + dpPerShdefOld)) {
                        cshKill += (int32_t)cshDamagedOld;
                        cshT = (int16_t)(cshT - cshDamagedOld);
                    }
                }

                if (cshT != 0) {
                    /* recompute pctDp; set pctSh=100 */
                    dp = (int32_t)dpPerShdefOld * (int32_t)cshDamagedOld + (int32_t)dpPerShdefNew * (int32_t)cshT;

                    pct = (int16_t)((((dp / (int32_t)cshT) * 500) / (int32_t)dpShdef));
                    if (pct == 0)
                        pct = 1;

                    flSrc.rgdv[ishdef].pctDp = (uint16_t)pct;
                    flSrc.rgdv[ishdef].pctSh = 100;
                }
            }

            flSrc.rgcsh[ishdef] = cshT;
            if (cshT == 0) {
                flSrc.rgdv[ishdef].dp = 0;
                cshdef = (int16_t)(cshdef - 1);
            }
        }

        /* flDead.rgcsh[ishdef] = orig - new */
        flDead.rgcsh[ishdef] = (int16_t)(lpfl->rgcsh[ishdef] - flSrc.rgcsh[ishdef]);
    }

    /* ------------------------------------------------------------
     * asm: 1080:139a..150c  (messages, cargo transfer, write-back)
     * ------------------------------------------------------------ */
    if (cshdef == 0) {
        goto LKilledEmAll;
    }

    if (cshKill != 0) {
        /* choose message id based on cshOrig>>2 and cshKill */
        if ((cshKill >> 16) != 0) {
            /* asm uses 0xeb when count is “unbelievable” (needs highword) */
            FSendPlrMsg(lpfl->iPlayer, idmUsedStargateReachLosingUnbelievableShipsJump, lpfl->id | 0x8000, lpfl->id, lpfl->idPlanet, id, (uint16_t)cshKill,
                        (int16_t)((uint32_t)cshKill >> 16), 0, 0);
        } else {
            int32_t thr2 = (cshOrig >> 2);
            if (thr2 < 0 || (thr2 < 0x10000 && (uint16_t)thr2 <= (uint16_t)cshKill)) {
                int32_t thr1 = (cshOrig >> 1);
                if (thr1 < 0x10000 && (thr1 < 0 || (uint16_t)thr1 < (uint16_t)cshKill)) {
                    idm = idmUsedStargateReachUnfortunatelyLosingShipsGreat;
                } else {
                    idm = idmUsedStargateReachLosingShipsUnforgivingVoid;
                }
            } else {
                idm = idmUsedStargateReachLosingShipsTreacherousVoid;
            }

            FSendPlrMsg(lpfl->iPlayer, idm, lpfl->id | 0x8000, lpfl->id, lpfl->idPlanet, id, (uint16_t)cshKill, 0, 0, 0);
        }

        flDead.iPlayer = flSrc.iPlayer;

        /* asm:
         *   flDead.wFlags_0x4 = (flDead.wFlags_0x4 & 0xfb00) | 0x0407;
         * => det=7, fInclude=1, fDead=1, rest 0
         */
        flDead.det = detAll;
        flDead.fInclude = 1;
        flDead.fDead = 1;
        flDead.fRepOrders = 0;
        flDead.fDone = 0;
        flDead.fBombed = 0;
        flDead.fHereAllTurn = 0;
        flDead.fNoHeal = 0;
        flDead.fMark = 0;

        FleetTransferCargoBalance(&flSrc, &flDead);
    }

    memcpy(lpfl, &flSrc, sizeof(FLEET));
    return 1;
}

int32_t PctTerraFromLpfl(FLEET *lpfl) {
    int16_t j;
    int32_t pctTot;
    int16_t i;
    int32_t pct;
    HUL    *lphuldef;
    int16_t chs;
    HS     *lphs;

    pctTot = 0;
    for (i = 0; i < cShdefMax; i++) {
        if (lpfl->rgcsh[i] > 0) {
            lphuldef = &rglpshdef[lpfl->iPlayer][i].hul;
            pct = 0;
            lphs = lphuldef->rghs;
            for (j = 0; j < (int16_t)lphuldef->chs; j++) {
                if (lphs->grhst == hstMining && lphs->iItem == iminingOrbitalAdjuster) {
                    pct += lphs->cItem;
                }
                lphs++;
            }
            pctTot += (uint32_t)pct * (int32_t)lpfl->rgcsh[i];
        }
    }
    return pctTot;
}

void AutoFleetOrder(FLEET *lpfl, PLANET *lppl) {
    int32_t cMine;
    int16_t ifl;
    ORDER  *lpord;
    FLEET  *lpflT;
    int16_t fFoundFleet;

    fFoundFleet = false;
    lpord = lpfl->lpplord->rgord;
    if ((lppl->iPlayer == -1 || (GetRaceStat(&rgplr[lpfl->iPlayer], rsMajorAdv) == raMacintosh && lppl->iPlayer == lpfl->iPlayer)) &&
        CMineFromLpfl(lpfl) != 0) {
        if (lppl->iPlayer == iNoPlayer) {
            for (ifl = 0; ifl < cFleet; ifl++) {
                lpflT = rglpfl[ifl];
                if (lpflT == NULL)
                    break;
                if (lpfl->iPlayer <= lpflT->iPlayer && !lpflT->fDead && lpfl != lpflT) {
                    if (lpfl->iPlayer < lpflT->iPlayer)
                        break;
                    if (lpflT->pt.x == lpfl->pt.x && lpflT->pt.y == lpfl->pt.y && CMineFromLpfl(lpflT) > 0 && CMineFromLpfl(lpflT) < 4000) {
                        fFoundFleet = true;
                        break;
                    }
                }
            }
        }
        if (fFoundFleet) {
            lpord->grTask = 4; // remote mining?
            lpord->grobj = grobjFleet;
            lpord->id = lpflT->id;
        } else {
            lpord->grTask = 3;
        }
    }
    lpfl->iplan = 0;
}

int32_t CMineSweepFromLphul(HUL *lphul) {
    int16_t chs;
    HS     *lphs;
    int32_t lRange;
    int16_t j;
    int32_t lPow;
    PART    part;
    BEAM   *pbeam;

    lPow = 0;
    for (j = 0, lphs = lphul->rghs; j < lphul->chs; j++, lphs++) {
        if (lphs->grhst != hstBeam)
            continue;
        part.hs = *lphs;
        FLookupPart(&part);
        pbeam = part.pbeam;
        if (pbeam->grfAbilities & 1)
            continue;
        if (pbeam->grfAbilities & 2) {
            lRange = 4;
        } else {
            lRange = (int32_t)pbeam->dRangeMax;
        }
        if (lphul->ihuldef >= ihuldefCount) {
            lRange += 1;
        }
        lPow += (uint32_t)(lRange * lRange) * (uint32_t)lphs->cItem * (uint32_t)pbeam->dp;
    }
    if (lPow < 1)
        lPow = 0;
    return lPow;
}

int16_t MdCalcStargateDamage(int16_t isbsSrc, int16_t isbsDst, int16_t dDist, int16_t wt, int16_t *ppctDmg) {
    int32_t dBaseDistance;
    PART    partDst;
    PART    partSrc;
    int32_t pctSurviveT;
    int32_t pctSurvive;
    int32_t massLimitSrc;
    int32_t massLimitDst;

    pctSurvive = 10000;
    partDst.hs.grhst = hstSpecialSB;
    partSrc.hs.grhst = hstSpecialSB;
    partSrc.hs.iItem = isbsSrc & 0xff;
    partDst.hs.iItem = isbsDst & 0xff;
    FLookupPart(&partSrc);
    FLookupPart(&partDst);
    dBaseDistance = (int32_t)partSrc.pspecialsb->grAbility2;
    if (dBaseDistance == -1)
        dBaseDistance = 10000;
    if ((int32_t)dDist > dBaseDistance * 5)
        return -1;
    massLimitSrc = (int32_t)partSrc.pspecialsb->grAbility;
    if (massLimitSrc > 0 && (int32_t)wt > massLimitSrc * 5)
        return -2;
    massLimitDst = (int32_t)partDst.pspecialsb->grAbility;
    if (massLimitDst > 0 && (int32_t)wt > massLimitDst * 5)
        return -2;
    if ((int32_t)dDist > dBaseDistance) {
        pctSurvive = (dBaseDistance * 5 - (int32_t)dDist) * 2500 / dBaseDistance;
        if (pctSurvive < 1)
            goto TotalDeath;
    }
    if (massLimitSrc < (int32_t)wt && massLimitSrc > 0) {
        pctSurviveT = (massLimitSrc * 5 - (int32_t)wt) * 2500 / massLimitSrc;
        if (pctSurviveT < 1)
            goto TotalDeath;
        pctSurvive = pctSurvive * pctSurviveT / 10000;
    }
    if (massLimitDst < (int32_t)wt && massLimitDst > 0) {
        pctSurviveT = (massLimitDst * 5 - (int32_t)wt) * 2500 / massLimitDst;
        if (pctSurviveT < 1)
            goto TotalDeath;
        pctSurvive = pctSurvive * pctSurviveT / 10000;
    }
    *ppctDmg = (int16_t)((10000 - pctSurvive) / 100);
    return 1;
TotalDeath:
    *ppctDmg = 100;
    return 0;
}

int16_t PctCloakFromLpfl(FLEET *lpfl) {
    int16_t j;
    double  dcPts;
    double  dwtFleet;
    int16_t i;
    int32_t cPtsCur;
    int16_t fUseFloat;
    HUL    *lphul;
    int32_t wtFleet;
    int16_t cScore;
    int32_t cPts;
    int32_t wtFleetCur;
    int16_t chs;
    HS     *lphs;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x2dbb */

    /* TODO: implement */
    return 0;
}

void NoAutoTrackFleet(FLEET *lpflTarget) {
    int16_t iplr;
    int16_t idTarget;
    int16_t i;
    ORDER  *lpord;
    int16_t ifl;
    FLEET  *lpfl;

    iplr = lpflTarget->iPlayer;
    idTarget = lpflTarget->id;

    FORFLEETS(lpfl, ifl) {
        if (lpfl->iPlayer != iplr && lpfl->cord > 1) {
            lpord = &lpfl->lpplord->rgord[1];
            for (i = 1; i < lpfl->cord; i++) {
                if (lpord->grobj == grobjFleet && lpord->id == idTarget) {
                    lpord->fNoAutoTrack = 1;
                    lpord->pt = lpflTarget->pt;
                }
                lpord++;
            }
        }
    }
}

int32_t CLayMinesFromLpfl(FLEET *lpfl, int16_t iType, int16_t ishdef) {
    uint16_t iMin;
    uint16_t iMax;
    int32_t  cMine;
    int16_t  j;
    int16_t  i;
    HUL     *lphul;
    PART     part;
    int32_t  cMineTot;
    int16_t  chs;
    HS      *lphs;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x291e */

    cMineTot = 0;

    if (iType == 0) {
        iMin = iminesMineDispenser40;
        iMax = iminesMineDispenser130;
    } else if (iType == 1) {
        iMin = iminesHeavyDispenser50;
        iMax = iminesHeavyDispenser200;
    } else if (iType == 2) {
        iMin = iminesSpeedTrap20;
        iMax = iminesSpeedTrap50;
    } else {
        iMin = 0;
        iMax = 9;
    }

    for (i = 0; i < cShdefMax; i++) {
        if (lpfl->rgcsh[i] <= 0 || (ishdef != -1 && i != ishdef))
            continue;

        lphul = &rglpshdef[lpfl->iPlayer][i].hul;
        cMine = 0;
        for (j = 0, lphs = lphul->rghs; j < lphul->chs; j++, lphs++) {
            if (lphs->grhst == hstMines && lphs->iItem >= iMin && lphs->iItem <= iMax) {
                part.hs = *lphs;
                FLookupPart(&part);
                cMine += (uint32_t)lphs->cItem * (uint32_t)part.pmines->grAbility;
            } else if (iType < 1 && lphs->grhst == hstBeam && lphs->iItem == ibeamMultiContainedMunition) {
                cMine += (uint32_t)lphs->cItem << 2;
            }
        }

        if (lphul->ihuldef == ihuldefMiniMineLayer || lphul->ihuldef == ihuldefSuperMineLayer)
            cMine <<= 1;

        cMine *= (int32_t)lpfl->rgcsh[i];
        cMineTot += cMine;
    }

    if (cMineTot < 10000001)
        cMineTot *= 10;
    else
        cMineTot = 100000000;

    return cMineTot;
}

int16_t FColonizer(FLEET *lpfl) {
    int16_t i;

    for (i = 0; i < ishdefMax; i++) {
        if (lpfl->rgcsh[i] != 0) {
            /* decompile: (__aFlshl(x,1) & 0xC000) != 0
               equivalent: (x & 0x6000) != 0
               SHDEF overlay: wFlags bits 13..14 == ishdef bits 3..4 */
            if (((uint16_t)rgshdef[i].ishdef & 0x0018u) != 0)
                return 1;
        }
    }

    return 0;
}

void AutoRouteFleet(FLEET *lpfl, PLANET *lppl) {
    int32_t dTravel;
    int16_t iWarp;
    int16_t pctDmg;
    int16_t wtBig;
    int32_t cTurns;
    int32_t cTurnsPrev;
    int16_t i;
    ORDER  *lpord;
    PLANET *lpplRoute;
    int16_t isbsDst;
    int16_t ishdef;
    int16_t isbsSrc;
    int16_t idRoute;
    HULDEF *lphuldef;

    lpfl->cord = 2;
    lpfl->lpplord->iordMac = 2;
    lpord = &lpfl->lpplord->rgord[1];
    lpord->grTask = 8;
    lpord->grobj = grobjPlanet;
    idRoute = (lppl->wRouting & 0x3ff) - 1;
    lpord->id = idRoute;
    lpplRoute = LpplFromId(idRoute);
    lpord->pt = rgptPlan[idRoute];
    lpord->fValidTask = 1;
    iWarp = IFindIdealWarp(lpfl, 0);
    dTravel = (int32_t)DGetDistance(lpfl->pt.x, lpfl->pt.y, lpord->pt.x, lpord->pt.y);
    if (lppl->iPlayer == lpplRoute->iPlayer && lppl->fStarbase && lpplRoute->fStarbase) {
        isbsDst = IStargateFromLppl(lpplRoute);
        isbsSrc = IStargateFromLppl(lppl);
        for (i = 0; i < 4 && lpfl->rgwtMin[i] == 0; i++)
            ;
        if (i == 4 && isbsDst != -1 && isbsSrc != -1) {
            wtBig = 0;
            for (ishdef = 0; ishdef < 0x10; ishdef++) {
                if (lpfl->rgcsh[ishdef] != 0 && rglpshdef[lpfl->iPlayer][ishdef].hul.wtEmpty > wtBig) {
                    wtBig = rglpshdef[lpfl->iPlayer][ishdef].hul.wtEmpty;
                }
            }
            if (MdCalcStargateDamage(isbsSrc, isbsDst, (int16_t)dTravel, wtBig, &pctDmg) == 1 && pctDmg == 0) {
                iWarp = iWarpStargate;
            }
        }
        if (iWarp < 9) {
            lphuldef = LphuldefFromId((HullDef)rglpshdefSB[lpplRoute->iPlayer][lpplRoute->isb].hul.ihuldef);
            if (lphuldef->hul.wtCargoMax != 0) {
                for (iWarp = 9; iWarp > 0; iWarp--) {
                    if (dTravel <= EstFuelUse(lpfl, 0, iWarp, -1, 1))
                        break;
                }
                lpord->iWarp = iWarp & 0xf;
            }
        }
    }
    if (iWarp < 11 && iWarp != 0) {
        cTurns = dTravel / (int32_t)iWarp / (int32_t)iWarp;
        while (iWarp >= 3) {
            cTurnsPrev = dTravel / (int32_t)(iWarp - 1) / (int32_t)(iWarp - 1);
            if (cTurnsPrev > cTurns)
                break;
            iWarp--;
        }
        iWarp++;
        while (iWarp > 0) {
            if (EstFuelUse(lpfl, 0, iWarp, dTravel, 0) <= lpfl->rgwtMin[4])
                break;
            iWarp--;
        }
    }
    lpord->iWarp = iWarp & 0xf;
}

void KillUsedWaypoints(void) {
    int16_t j;
    int16_t i;
    FLEET  *lpfl;
    int16_t fRep;
    PLANET *lppl;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x1c89 */
    /* label NoOrdFixupYet @ MEMORY_SHIP2:0x1bfb */

    /* TODO: implement */
}

int32_t CMineFromLpfl(FLEET *lpfl) {
    int32_t cMine;
    HUL    *lphuldef;
    PART    part;
    int32_t cMineTot;
    int16_t chs;
    HS     *lphs;

    cMineTot = 0;
    for (int i = 0; i < ishdefMax; i++) {
        if (lpfl->rgcsh[i] > 0) {
            lphuldef = &rglpshdef[lpfl->iPlayer][i].hul;
            chs = lphuldef->chs;
            lphs = lphuldef->rghs;
            cMine = 0;
            for (int j = 0; j < chs; j++) {
                if ((lphs->grhst == hstMining) && (lphs->iItem < iminingOrbitalAdjuster)) {
                    part.hs.grhst = lphs->grhst;
                    part.hs.iItem = lphs->iItem;
                    part.hs.cItem = lphs->cItem;
                    FLookupPart(&part);
                    cMine += (uint32_t)lphs->cItem * (uint32_t)part.pmining->grAbility;
                }
                lphs++;
            }
            cMineTot += cMine * lpfl->rgcsh[i];
        }
    }
    if (cMineTot > 3999) {
        cMineTot = 4000;
    }
    return cMineTot;
}

void MarkTechsSeen(HUL *lphul, int16_t iplr) {
    int16_t iplrSav;
    int16_t iTech;
    int16_t ihs;
    PART    part;

    iplrSav = idPlayer;
    idPlayer = iplr;

    /* Look up hull part techs */
    part.hs.grhst = hstHull;
    part.hs.iItem = (uint8_t)lphul->ihuldef;
    FLookupPart(&part);
    for (iTech = 0; iTech < 6; iTech++) {
        if (part.phul->rgTech[iTech] > (uint8_t)rgTechBattle[iTech])
            rgTechBattle[iTech] = part.phul->rgTech[iTech];
    }

    for (ihs = 0; ihs < (int16_t)(uint16_t)lphul->chs; ihs++) {
        if (lphul->rghs[ihs].cItem == 0)
            continue;

        part.hs = lphul->rghs[ihs];
        FLookupPart(&part);

        for (iTech = 0; iTech < 6; iTech++) {
            if (part.phul->rgTech[iTech] > (uint8_t)rgTechBattle[iTech])
                rgTechBattle[iTech] = part.phul->rgTech[iTech];
        }

        iTech = -1;
        if (part.hs.grhst == hstEngine) {
            if (part.hs.iItem == iengineEnigmaPulsar)
                iTech = 9;
        } else if (part.hs.grhst == hstShield) {
            if (part.hs.iItem == ishieldLangstonShell)
                iTech = 2;
        } else if (part.hs.grhst == hstArmor) {
            if (part.hs.iItem == iarmorMegaPolyShell)
                iTech = 3;
        } else if (part.hs.grhst == hstBeam) {
            if (part.hs.iItem == ibeamMultiContainedMunition)
                iTech = 7;
        } else if (part.hs.grhst == hstTorp) {
            if (part.hs.iItem == itorpAntiMatterTorpedo)
                iTech = 6;
        } else if (part.hs.grhst == hstBomb) {
            if (part.hs.iItem == ibombHushABoom)
                iTech = 5;
        } else if (part.hs.grhst == hstMining) {
            if (part.hs.iItem == iminingAlienMiner)
                iTech = 4;
        } else if (part.hs.grhst == hstSpecialE) {
            if (part.hs.iItem == ispecialEMultiFunctionPod)
                iTech = 1;
        } else if (part.hs.grhst == hstSpecialM) {
            if (part.hs.iItem == ispecialMMultiCargoPod)
                iTech = 0;
            else if (part.hs.iItem == ispecialMJumpGate)
                iTech = 11;
        }

        if (iTech != -1 && rgTechTrader[iTech] < 25) {
            rgTechTrader[iTech] += part.hs.cItem;
            if (rgTechTrader[iTech] > 25)
                rgTechTrader[iTech] = 25;
        }
    }

    idPlayer = iplrSav;
}

int16_t CPtsCloakFromLphs(HS *lphs) {
    int16_t cPts;
    PART    part;

    cPts = 0;

    if (lphs->cItem == 0)
        return 0;

    switch (lphs->grhst) {
    case hstEngine:
        if (lphs->iItem == iengineEnigmaPulsar)
            cPts = 20;
        break;

    case hstScanner:
        if (lphs->iItem == iscannerChameleonScanner)
            cPts = 40;
        break;

    case hstShield:
        if (lphs->iItem == ishieldShadowShield)
            cPts = 70;
        else if (lphs->iItem == ishieldLangstonShell)
            cPts = 20;
        break;

    case hstArmor:
        if (lphs->iItem == iarmorDepletedNeutronium)
            cPts = 50;
        else if (lphs->iItem == iarmorMegaPolyShell)
            cPts = 40;
        break;

    case hstBeam:
        if (lphs->iItem == ibeamMultiContainedMunition)
            cPts = 20;
        break;

    case hstMining:
        if (lphs->iItem == iminingAlienMiner)
            cPts = 60;
        else if (lphs->iItem == iminingOrbitalAdjuster)
            cPts = 50;
        break;

    case hstSpecialE:
        if (lphs->iItem <= ispecialEUltraStealthCloak) { /* 0..4 are the cloaking/pod group */
            part.hs = *lphs;
            FLookupPart(&part);
            cPts = part.pspecial->grAbility;
        }
        break;

    case hstSpecialM:
        if (lphs->iItem == ispecialMMultiCargoPod)
            cPts = 20;
        break;

    default:
        break;
    }

    if (lphs->cItem > 1)
        cPts = (int16_t)(cPts * lphs->cItem);

    return cPts;
}

int32_t CMineSweepFromLpfl(FLEET *lpfl) {
    int32_t lPowTot;
    int16_t i;
    int32_t lPow;

    lPowTot = 0;
    for (i = 0; i < cShdefMax; i++) {
        if (lpfl->rgcsh[i] > 0) {
            lPow = CMineSweepFromLphul(&rglpshdef[lpfl->iPlayer][i].hul);
            lPowTot += (uint32_t)lPow * (int32_t)lpfl->rgcsh[i];
        }
    }
    if (lPowTot < 1)
        lPowTot = 0;
    return lPowTot;
}

#ifdef _WIN32

INT_PTR CALLBACK RenameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RECT    rc;
    int32_t lSel;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x0c0c */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK MergeFleetsDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t i;
    RECT    rc;
    char    szT[80];
    char   *psz;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x33a0 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK ZipOrderDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    int16_t     i;
    PAINTSTRUCT ps;
    RECT        rc;
    HWND        hwndRad;
    char       *psz;
    int16_t (*lpProc)(void);
    char   *pszT;
    RECT    rcGBox;
    int16_t cch;
    int16_t xCtr;
    int16_t iAction;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x000f */
    /* block (block) @ MEMORY_SHIP2:0x0092 */
    /* block (block) @ MEMORY_SHIP2:0x0202 */
    /* block (block) @ MEMORY_SHIP2:0x031e */
    /* block (block) @ MEMORY_SHIP2:0x033f */
    /* block (block) @ MEMORY_SHIP2:0x055f */
    /* block (block) @ MEMORY_SHIP2:0x05f7 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RenameZipDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t ids;
    RECT    rc;

    /* TODO: implement */
    return 0;
}

void EnableZipBtns(HWND hwnd, int16_t iSel) {
    int16_t fEnabled;

    // TODO: replace with constants
    fEnabled = (int16_t)(vrgZip[iSel].fValid != 0);
    EnableWindow(GetDlgItem(hwnd, 0x0817), fEnabled);
    EnableWindow(GetDlgItem(hwnd, 0x041b), fEnabled);
}

#endif /* _WIN32 */
