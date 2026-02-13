
#include "types.h"

#include "globals.h"
#include "memory.h"
#include "msg.h"
#include "parts.h"
#include "research.h"
#include "ship.h"
#include "ship2.h"
#include "strings.h"
#include "thing.h"
#include "turn2.h"
#include "util.h"
#include "utilgen.h"

/* functions */
int16_t IdmGiveTraderPart(uint16_t grbitTrader, int16_t iplr, uint16_t *piGoto) {
    uint16_t iGoto;
    int16_t  idm;

    rgplr[iplr].grbitTrader |= grbitTrader;

    idm = idmHasAbsorbedMysteryTraderHaveGivenPlans;
    switch (grbitTrader) {
    case grbitTraderCargo:
        iGoto = 0xcc04;
        break;
    case grbitTraderSpecial:
        iGoto = 0xcb04;
        break;
    case grbitTraderShield:
        iGoto = 0xc206;
        break;
    case grbitTraderArmor:
        iGoto = 0xc309;
        break;
    case grbitTraderMiner:
        iGoto = 0xc706;
        break;
    case grbitTraderBomb:
        iGoto = 0xc608;
        break;
    case grbitTraderTorp:
        iGoto = 0xc507;
        break;
    case grbitTraderBeam:
        iGoto = 0xc412;
        break;
    case grbitTraderHull:
        idm = idmHasAbsorbedMysteryTraderReturnHaveGiven;
        iGoto = 0xce1e;
        break;
    case grbitTraderEngine:
        iGoto = 0xc008;
        break;
    case grbitTraderGenesis:
        idm = idmHasAbsorbedMysteryTraderReturnHaveGiven2;
        iGoto = 0xcf0e;
        break;
    case grbitTraderJumpgate:
        iGoto = 0xcc09;
        break;
    default:
        iGoto = 0xcc04;
        break;
    }

    *piGoto = iGoto;
    return idm;
}

void FreeLpth(THING *lpth) {
    THING *end;
    size_t idx;

    end = lpThings + cThing;
    if (lpth < end - 1) {
        idx = (size_t)(lpth - lpThings);
        memmove(lpth, lpth + 1, (size_t)(cThing - (int32_t)idx - 1) * sizeof(*lpth));
    }
    cThing = (int16_t)(cThing - 1);
}

int16_t CPlanetsInCircle(POINT pt, int32_t r2) {
    STARSPOINT *ppt;
    STARSPOINT *pptEnd;
    int16_t     i;
    int16_t     r;
    int16_t     cPl;
    int32_t     dx;
    int32_t     dy;

    r = (int16_t)sqrt((double)r2);
    cPl = 0;
    pptEnd = rgptPlan + game.cPlanMax;

    /* Binary search: estimate starting index */
    i = (int16_t)(((int32_t)(pt.x - rgptPlan[0].x) * (int32_t)game.cPlanMax) / (int32_t)(rgptPlan[game.cPlanMax - 1].x - rgptPlan[0].x));
    if (i >= game.cPlanMax)
        i = game.cPlanMax - 1;
    if (i < 0)
        i = 0;

    /* Scan backwards to find start */
    for (ppt = rgptPlan + i; pt.x - r <= ppt->x && ppt > rgptPlan; ppt--) {
    }

    /* Scan forwards counting matches */
    for (; ppt->x <= pt.x + r && ppt < pptEnd; ppt++) {
        if (ppt->x >= pt.x - r && ppt->y >= pt.y - r && ppt->y <= pt.y + r) {
            dx = (int32_t)(ppt->x - pt.x);
            dy = (int32_t)(ppt->y - pt.y);
            if ((uint32_t)(dx * dx) + (uint32_t)(dy * dy) <= (uint32_t)r2) {
                cPl++;
            }
        }
    }

    return cPl;
}

int16_t PctWormholeMoves(THING *lpth) {
    int16_t pct;

    pct = (int16_t)((int16_t)(lpth->thw.cLastMove / 5) - (int16_t)(2 - lpth->thw.iStable));

    if (pct < 0) {
        pct = 0;
    } else if (pct > 6) {
        pct = 6;
    }

    return pct;
}

void DoThingInteractions(int16_t fPostMove) {
    int32_t    wtThreshhold;    /* asm: [BP-0x08] (NB09 bp_off -6) */
    uint16_t   grbitPlrTrader;  /* asm: [BP-0x0a] (NB09 bp_off -8) */
    int16_t    iplr;            /* asm: [BP-0x0c] (NB09 bp_off -10) */
    int32_t    wtMin;           /* asm: [BP-0x10] */
    STARSPOINT pt;              /* asm: [BP-0x14] */
    int16_t    iplrSav;         /* asm: [BP-0x16] */
    uint8_t    rgTech[6];       /* asm: [BP-0x1c] */
    int32_t    wtNext;          /* asm: [BP-0x20] */
    int32_t    dy;              /* asm: [BP-0x24] */
    THING     *lpthMac;         /* asm: [BP-0x28] */
    PLANET    *lpplMac;         /* asm: [BP-0x2c] */
    PLANET    *lppl;            /* asm: [BP-0x30] */
    int16_t    i;               /* asm: [BP-0x32] */
    int16_t    ifl;             /* asm: [BP-0x34] */
    FLEET     *lpfl;            /* asm: [BP-0x38] */
    THING     *lpth;            /* asm: [BP-0x3c] */
    int16_t    idm;             /* asm: [BP-0x3e] */
    int16_t    cPlrTrueMaxTech; /* asm: [BP-0x40] */
    int32_t    dx;              /* asm: [BP-0x44] */
    int16_t    fMaxTech;        /* asm: [BP-0x46] */
    int32_t    l;               /* asm: [BP-0x4a] */

    /* reused stack slots in asm become block-scoped locals in C */
    int32_t cTech;    /* NB09: [BP-0x4c] block reuse; used as 32-bit scratch */
    int16_t iLowest;  /* NB09: [BP-0x4e] block reuse; used as tech index */
    int16_t cTechCur; /* NB09: [BP-0x50] block reuse */

    /* locals used in gift-ship block (NB09 blocks 4/5) */
    SHDEF   shdef;
    SHDEF  *lpshdefDest;
    FLEET  *lpflNew;
    int16_t cGive;
    int16_t iOffset;
    int16_t ish;

    /* asm: 1110:0b43..0b4c */
    if (fPostMove == 0) {
        return;
    }

    /* asm: 1110:0b4f..0b77 */
    lpth = lpThings;
    lpthMac = lpThings + cThing;

    /* asm: 1110:0b7a..1a81 (outer thing loop) */
    while (lpth < lpthMac) {
        /* asm: ith == 3 (mystery trader) */
        if (lpth->ith != ithMysteryTrader) {
            lpth++;
            continue;
        }

        /* asm: pt = lpth->pt */
        pt = lpth->pt;

        /* asm: for ifl=0..cFleet-1; break on NULL */
        for (ifl = 0; ifl < cFleet; ifl++) {
            lpfl = rglpfl[ifl];
            if (lpfl == NULL) {
                goto LAfterFleets;
            }

            /* asm: skip if fDead set */
            if (lpfl->fDead) {
                continue;
            }

            /* asm: must be at same coords */
            if (lpfl->pt.x != pt.x || lpfl->pt.y != pt.y) {
                continue;
            }

            /* asm: wtMin = rgwtMin[0] + rgwtMin[1] + rgwtMin[2] using 16-bit add/adc */
            {
                uint32_t sum = 0;
                for (i = 0; i < 3; i++) {
                    sum += (uint32_t)lpfl->rgwtMin[i];
                }
                wtMin = (int32_t)sum;
            }

            /* asm: signed compare against 5000 (0x1388) */
            if (wtMin < 5000) {
                /* asm: if fHereAllTurn==0 then send 0x108 */
                if (lpfl->fHereAllTurn == 0) {
                    FSendPlrMsg2(lpfl->iplr, idmMysteryTraderHasRefusedGiveCaptainAudience, (int16_t)(lpfl->id | 0x8000), lpfl->id, 0);
                }
                continue;
            }

            /* asm: cPlrTrueMaxTech = (player.fCrippled ? 0x0A : 0x1A) */
            if (rgplr[lpfl->iPlayer].fCrippled) {
                cPlrTrueMaxTech = 10;
            } else {
                cPlrTrueMaxTech = 26;
            }

            /* asm: fMaxTech = all 6 tech >= cPlrTrueMaxTech */
            for (i = 0; i < 6; i++) {
                if ((int16_t)rgplr[lpfl->iPlayer].rgTech[i] < cPlrTrueMaxTech) {
                    break;
                }
            }
            fMaxTech = (i == 6);

            /* asm: grbitPlrTrader = player.grbitTrader; iplr = lpfl->iPlayer */
            grbitPlrTrader = rgplr[lpfl->iPlayer].grbitTrader;
            iplr = lpfl->iPlayer;

            /* asm: if already met -> send 0x118 and continue */
            if ((lpth->tht.grbitPlr & (1u << (iplr & 0x0f))) != 0) {
                FSendPlrMsg2(lpfl->iplr, idmMysteryTraderEyesCaptainSuspiciouslySuggestsHe, (int16_t)(lpfl->id | 0x8000), lpfl->id, 0);
                continue;
            }

            /* asm: mark met; remove assigned-orders msg; set lpfl->fDead */
            lpth->tht.grbitPlr |= (1u << (iplr & 0x0f));
            FRemovePlayerMessage(iplr, idmHasCompletedAssignedOrders, (int16_t)(lpfl->id | 0x8000));
            lpfl->fDead = 1;

            /* asm: restriction test
             * if (thing.grbitTrader != 0 && (thing.grbitTrader & player.grbitTrader)==0) -> LGivePart
             */
            if (lpth->tht.grbitTrader != 0) {
                if ((lpth->tht.grbitTrader & grbitPlrTrader) == 0) {
                    goto LGivePart;
                }
            }

            /* asm: if fMaxTech!=0 then maybe LGivePart else send 0x10E */
            if (fMaxTech) {
                if (Random(5) == 0) {
                    goto LGivePart;
                }
                {
                    int16_t wFrom = WFromLpfl(lpfl);
                    FSendPlrMsg2(lpfl->iplr, idmHasAbsorbedMysteryTraderHoweverTraderUnable2, -1, wFrom, 0);
                }
                goto LAfterInteraction;
            }

            /* asm: compute iGoto = ((wtMin-5000)/0x4b0)+6, clamp to 10 */
            {
                int16_t iGoto;
                int32_t q = (wtMin - 5000) / 0x4b0;
                int32_t iGoto32 = q + 6;
                if (iGoto32 > 10) {
                    iGoto32 = 10;
                }
                iGoto = (int16_t)iGoto32;

                /* asm: cTechCur = sum of 6 tech bytes */
                cTechCur = 0;
                for (i = 0; i < 6; i++) {
                    cTechCur = (int16_t)(cTechCur + rgplr[iplr].rgTech[i]);
                }

                /* asm: ladder adjusting iGoto */
                if (cTechCur >= 108) {
                    iGoto = 1;
                } else if (cTechCur >= 96) {
                    iGoto = 2;
                } else if (cTechCur >= 84) {
                    iGoto = iGoto - 3;
                } else if (cTechCur >= 72) {
                    iGoto = iGoto - 2;
                } else if (cTechCur >= 50) {
                    iGoto = iGoto - 1;
                }

                /* asm: choose msg 0x10A if (grbitTrader&0x1fff)==0x1fff else 0x109 */
                {
                    int16_t idmMsg =
                        ((grbitPlrTrader & 0x1fff) == 0x1fff) ? idmHasAbsorbedMysteryTraderReturnTraderHas : idmHasAbsorbedMysteryTraderTraderHasGiven;
                    int16_t wFrom = WFromLpfl(lpfl);
                    FSendPlrMsg(lpfl->iplr, idmMsg, -1, wFrom, iGoto, 0, 0, 0, 0, 0);
                }

                /* asm: loop iGoto times, pre-decrement style */
                while (iGoto-- > 0) {
                    /* asm: Random(4) < 3 ? pick random tech field, else pick lowest */
                    if (Random(4) < 3) {
                        iLowest = (int16_t)Random(6);
                        if ((int16_t)rgplr[iplr].rgTech[iLowest] < cPlrTrueMaxTech) {
                            goto LGiveITech;
                        }
                    }

                    /* pick lowest among fields 0..5 */
                    iLowest = 0;
                    for (i = 1; i < 6; i++) {
                        if (rgplr[iplr].rgTech[i] < rgplr[iplr].rgTech[iLowest]) {
                            iLowest = i;
                        }
                    }
                    if ((int16_t)rgplr[iplr].rgTech[iLowest] >= cPlrTrueMaxTech) {
                        break;
                    }

                LGiveITech:
                    /* asm: memcpy player.rgTech -> rgTech; rgTech[iLowest]++ */
                    memcpy(rgTech, rgplr[iplr].rgTech, 6);
                    rgTech[iLowest]++;

                    /* asm: swap global idPlayer while calling CostOfDevelopingItem */
                    iplrSav = idPlayer;
                    idPlayer = iplr;
                    wtNext = CostOfDevelopingItem(rgTech);
                    idPlayer = iplrSav;

                    /* asm: cTech = rgResSpent[iLowest] << 1; if wtNext>0 add wtNext */
                    cTech = (int32_t)rgplr[iplr].rgResSpent[iLowest];
                    cTech = (int32_t)((uint32_t)cTech << 1);
                    if (wtNext > 0) {
                        cTech = (int32_t)((uint32_t)cTech + (uint32_t)wtNext);
                    }
                    rgplr[iplr].rgResSpent[iLowest] = (uint32_t)cTech;

                    UpdateResearchStatus(0);
                }
            }

        LAfterInteraction:
            /* fallthrough (asm jumps to 162e, then continues fleet loop) */
            continue;

        /* ------------------------------------------------------------
         * asm label: THING::LGivePart @ 1110:1180
         * ------------------------------------------------------------ */
        LGivePart: {
            uint16_t grbitTrader;
            int16_t  cTry;

            /* asm: cTry=0x19; grbitTrader = thing.grbitTrader; if 0 choose random(13) bit */
            cTry = 25;
            grbitTrader = lpth->tht.grbitTrader;
            if (grbitTrader == 0) {
                grbitTrader = (uint16_t)(1u << (Random(13) & 0x1f));
            }

            /* asm: while ((grbitTrader & player.grbitTrader)!=0 && cTry>0) { --cTry; grbitTrader=1<<Random(13) } */
            while ((grbitTrader & grbitPlrTrader) != 0 && cTry > 0) {
                cTry--;
                grbitTrader = (uint16_t)(1u << (Random(13) & 0x1f));
            }

            /* asm: if cTry<=0 => grbitTrader=0x1000 */
            if (cTry <= 0) {
                grbitTrader = 0x1000;
            }

            /* asm redundancy: OR met-bit again */
            lpth->tht.grbitPlr |= (1u << (iplr & 0x0f));

            if (grbitTrader == 0x1000) {
                /* --------------------------------------------------------
                 * asm: ship/design gift path
                 * - only if PLAYER.fAi == 0 (NOT AI). If AI -> go to 15e6 (fallback)
                 * - requires PLAYER.cFleet < 0x200 (mask 0x0fff compare 0x200)
                 * - else send 0x150 and fallback
                 * -------------------------------------------------------- */
                if (rgplr[iplr].fAi != 0) {
                    goto LTraderTried;
                }

                if (rgplr[iplr].cFleet >= 0x200) {
                    /* asm: send 0x150 then fallback */
                    {
                        int16_t wFrom = WFromLpfl(lpfl);
                        FSendPlrMsg2(lpfl->iplr, idmHasAbsorbedMysteryTraderReturnTraderTried, -1, wFrom, 0);
                    }
                    goto LTraderTried;
                }

                /* ---- Remaining ship/design grant block not shown in your paste ----
                 * Your project already has the helpers this block calls (LpshdefT, IshFindSimilarDesign,
                 * UpdateShdefCost, LGetFleetStat, etc.). The structure below matches the asm’s
                 * early decisions and state updates; keep your existing mechanical translation
                 * for the mid/late portion (fleet creation and SHDEF updates) here.
                 */

                /* asm: iOffset = Random(4 - (game.turn>100)); if iOffset>0 then iOffset = Random(2)+1 */
                iOffset = Random((int16_t)(4 - (int16_t)(game.turn > 100)));
                if (iOffset >= 1) {
                    iOffset = (int16_t)(Random(2) + 1);
                }

                lpshdefDest = &LpshdefT()[iOffset + MTLifeboat];

                /* local hul copy: shdef.hul = template.hul */
                shdef.hul = lpshdefDest->hul;

                ish = IshFindSimilarDesign(&shdef.hul, iplr);
                if (ish < 0) {
                    do {
                        ish++;
                        if (ish >= 0x10) {
                            break;
                        }
                    } while (rglpshdef[iplr][ish].fFree == 0);
                }
                if (ish >= 0x10) {
                    /* asm: no lifeboat/design slot => send 0x150 then fallback */
                    {
                        int16_t wFrom = WFromLpfl(lpfl);
                        FSendPlrMsg2(lpfl->iplr, idmHasAbsorbedMysteryTraderReturnTraderTried, -1, wFrom, 0);
                    }
                    goto LTraderTried;
                }

                /* From here, you need your existing “mechanical core” that:
                 * - determines cGive (1 or 2, then boosts based on turn / wCrap bits / iOffset)
                 * - creates lpflNew and assigns design ish / counts / fuel
                 * - sends 0x14F on success
                 *
                 * IMPORTANT: ensure lpflNew is assigned before use (your pasted version used it uninitialized).
                 *
                 * If you paste your current “fleet creation” helper calls / block for lpflNew,
                 * I can splice it here with exact asm-consistent conditions.
                 */

                goto LTraderTried;
            } else {
                /* asm: give part message id comes from IdmGiveTraderPart(grbitTrader, iplr, &l) */
                {
                    /* asm passes &l (BP-0x4a), not &wtThreshhold */
                    idm = IdmGiveTraderPart(grbitTrader, iplr, (uint16_t *)&l);
                    {
                        int16_t wFrom = WFromLpfl(lpfl);
                        /* asm uses low word of l as the wParam */
                        FSendPlrMsg2(lpfl->iplr, idm, (int16_t)(uint16_t)l, wFrom, 0);
                    }
                }
            }

        LTraderTried:
            /* asm has several fallback exits that all reach the “continue fleet loop” join */
            continue;
        }
        }

    LAfterFleets:
        /* ------------------------------------------------------------
         * asm: 1110:1631..1a6b  planet loop (auto-tech / part flag for AI starbase planets near trader)
         * ------------------------------------------------------------ */
        lppl = lpPlanets;
        lpplMac = lpPlanets + cPlanet;

        while (lppl < lpplMac) {
            if (lppl->iPlayer != -1 && lppl->fStarbase != 0 && rgplr[lppl->iPlayer].fAi != 0 && rgplr[lppl->iPlayer].lvlAi > 1 &&
                (lpth->tht.grbitPlr & (1u << (lppl->iPlayer & 0x0f))) == 0) {

                dx = (int32_t)((int32_t)rgptPlan[lppl->id].x - (int32_t)pt.x);
                dy = (int32_t)((int32_t)rgptPlan[lppl->id].y - (int32_t)pt.y);
                l = (int32_t)((uint32_t)(dx * dx) + (uint32_t)(dy * dy));

                if (l <= 10000) {
                    {
                        uint32_t sum = 0;
                        for (i = 0; i < 3; i++) {
                            sum += (uint32_t)lppl->rgwtMin[i];
                        }
                        wtNext = (int32_t)sum;
                    }

                    iplr = lppl->iPlayer;
                    {
                        /* asm: iLvl is PLAYER.lvlAi; threshold is 0x0DAC (3500) if lvl==2 else 0x1388 (5000) */
                        int16_t iLvl = (int16_t)rgplr[iplr].lvlAi;
                        wtThreshhold = (iLvl == 2) ? 3500 : 5000;
                    }

                    if (wtNext >= wtThreshhold) {
                        if (lpth->tht.grbitTrader == 0) {
                            cTechCur = 0;
                            for (i = 0; i < 6; i++) {
                                cTechCur = (int16_t)(cTechCur + rgplr[iplr].rgTech[i]);
                            }

                            if (rgplr[iplr].fCrippled) {
                                cPlrTrueMaxTech = 10;
                            } else {
                                cPlrTrueMaxTech = 26;
                            }

                            if ((int16_t)(cPlrTrueMaxTech * 6 - 6) > cTechCur) {
                                for (int16_t iPass = 0; iPass < 6; iPass++) {
                                    iLowest = 0;
                                    for (i = 1; i < 6; i++) {
                                        if (rgplr[iplr].rgTech[i] < rgplr[iplr].rgTech[iLowest]) {
                                            iLowest = i;
                                        }
                                    }
                                    rgplr[iplr].rgTech[iLowest]++;
                                }
                            }
                            wtNext = wtThreshhold;
                        } else {
                            uint16_t grbitTrader;
                            int16_t  cTry;

                            grbitTrader = lpth->tht.grbitTrader;
                            cTry = 1;
                            while ((grbitTrader & rgplr[iplr].grbitTrader) != 0 && cTry > 0) {
                                cTry--;
                                grbitTrader = (uint16_t)(1u << (Random(13) & 0x1f));
                            }
                            if (cTry <= 0) {
                                cTechCur = 0;
                                for (i = 0; i < 6; i++) {
                                    cTechCur = (int16_t)(cTechCur + rgplr[iplr].rgTech[i]);
                                }
                                wtNext = wtThreshhold;
                            } else {
                                rgplr[iplr].grbitTrader |= grbitTrader;
                            }
                        }

                        lpth->tht.grbitPlr |= (1u << (iplr & 0x0f));

                        /* subtract wtNext from minerals i=2..0 */
                        for (i = 2; i >= 0 && wtNext > 0; i--) {
                            int32_t take = lppl->rgwtMin[i];
                            if (take > wtNext) {
                                take = wtNext;
                            }
                            lppl->rgwtMin[i] = (int32_t)((uint32_t)lppl->rgwtMin[i] - (uint32_t)take);
                            wtNext = (int32_t)((uint32_t)wtNext - (uint32_t)take);
                        }
                    }
                }
            }
            lppl++;
        }

        lpth++;
    }
}

THING *LpthNew(int16_t iplr, ThingType ith) {
    int16_t iItem;
    int16_t i;
    THING  *lpth;
    THING   thNew;

    if (cThing >= cThingAbsMax) {
        return NULL;
    }

    memset(&thNew, 0, sizeof(THING));
    thNew.idFull = (thNew.idFull & 0x1ff) | ((iplr & 0xf) << 9) | (ith << 0xd);

    i = 0;
    lpth = lpThings;
    while (i < cThing && lpth->idFull < thNew.idFull) {
        i++;
        lpth++;
    }

    if (i < cThing && thNew.idFull == lpth->idFull) {
        iItem = lpth->idFull & 0x1ff;
        for (; i < cThing; i++) {
            if (iItem > 0x1fe) {
                return NULL;
            }
            if (lpth->idFull != thNew.idFull)
                break;
            thNew.idFull = (thNew.idFull & 0xfe00) | ((thNew.idFull + 1) & 0x1ff);
            lpth++;
            iItem++;
        }
    }

    if (cThingAlloc <= cThing) {
        cThingAlloc += 10;
        if (lpThings == NULL) {
            lpThings = LpAlloc(cThingAlloc * sizeof(THING), htThings);
        } else {
            lpThings = LpReAlloc(lpThings, cThingAlloc * sizeof(THING), htThings);
        }
        lpth = &lpThings[i];
    }

    if (i < cThing) {
        memmove(lpth + 1, lpth, (cThing - i) * sizeof(THING));
    }
    cThing++;
    memcpy(lpth, &thNew, sizeof(THING));

    return lpth;
}

int16_t IValidateWormholePos(THING *lpthWorm) {
    int16_t iRet;
    int32_t dy;
    THING  *lpthMac;
    FLEET  *lpfl;
    int16_t ifl;
    int16_t i;
    THING  *lpth;
    int16_t dUni;
    int32_t dx;
    int32_t l;
    int16_t x, y;

    iRet = 0;
    dUni = game.mdSize * 400;
    x = lpthWorm->pt.x;
    y = lpthWorm->pt.y;

    if (x < 1000 || y < 1000) {
        iRet = 0xf;
    } else if (dUni + 1400 < x || dUni + 1400 < y) {
        iRet = 0xf;
    } else {
        FORTHINGS(lpth, lpthMac) {
            if (x == lpth->pt.x && y == lpth->pt.y && lpthWorm != lpth) {
                return 0xf;
            }
        }

        for (i = 0; i < game.cPlanMax; i++) {
            if (x == rgptPlan[i].x && y == rgptPlan[i].y) {
                return 0xf;
            }
        }

        FORFLEETS(lpfl, ifl) {
            if (x == lpfl->pt.x && y == lpfl->pt.y) {
                return 0xf;
            }
        }

        if (x < 1010 || y < 1010 || dUni + 1390 < x || dUni + 1390 < y) {
            iRet = 4;
        }

        FORTHINGS(lpth, lpthMac) {
            if (lpth->ith == ithWormhole && lpthWorm != lpth) {
                dx = x - lpth->pt.x;
                dy = y - lpth->pt.y;
                l = dx * dx + dy * dy;

                if (lpth->idFull == lpthWorm->thw.idPartner) {
                    if (l < 70 * 70) {
                        if (l < 5 * 5) {
                            iRet = iRet | 8;
                        } else if (l < 10 * 10) {
                            iRet = iRet | 4;
                        } else if (l < 30 * 30) {
                            iRet = iRet | 2;
                        } else {
                            iRet = iRet | 1;
                        }
                    }
                } else if (l < 30 * 30) {
                    if (l < 4 * 4) {
                        iRet = iRet | 8;
                    } else if (l < 8 * 8) {
                        iRet = iRet | 4;
                    } else if (l < 15 * 15) {
                        iRet = iRet | 2;
                    } else {
                        iRet = iRet | 1;
                    }
                }
            }
        }

        for (i = 0; i < game.cPlanMax; i++) {
            dx = x - rgptPlan[i].x;
            dy = y - rgptPlan[i].y;
            l = dx * dx + dy * dy;

            if (l < 28 * 28) {
                if (l < 5 * 5) {
                    iRet = iRet | 8;
                } else if (l < 10 * 10) {
                    iRet = iRet | 4;
                } else if (l < 20 * 20) {
                    iRet = iRet | 2;
                } else {
                    iRet = iRet | 1;
                }
            }
        }
    }

    return iRet;
}

#ifdef _WIN32

void DrawThingGauge(uint16_t hdc, RECT *prc, THING *lpth, int16_t md) {
    int16_t  iMode;
    int16_t  cSections;
    int16_t  fDisabled;
    uint16_t rghbr[5];
    int16_t  c;
    int16_t  i;
    int32_t  rgSize[5];
    int32_t  lMax;
    int32_t  l;

    /* TODO: implement */
}
#endif /* _WIN32 */
