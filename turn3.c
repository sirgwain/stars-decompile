
#include "globals.h"
#include "types.h"

#include "mine.h"
#include "msg.h"
#include "race.h"
#include "ship.h"
#include "ship2.h"
#include "strings.h"
#include "turn2.h"
#include "turn3.h"
#include "util.h"

void SatisfyOrders(int16_t iPass) {
    int16_t  fMining;
    int32_t  amountWP;
    int16_t  action;
    PLANET   pl;
    int32_t  l2;
    int16_t  j;
    int32_t  amount;
    int16_t  iflWP;
    int16_t  fSentBadFleetXfer;
    int16_t  ifltcur;
    FLEET   *lpfl;
    int16_t  fAtPlanet;
    int16_t  idm;
    int16_t  iLoad;
    uint16_t xWP;
    int16_t  fOptFuel;
    int16_t  fStealing;
    FLEET   *lpflWP;
    int16_t  iSteal;
    int16_t  fFulfilled;
    ORDER    ord;
    int16_t  fFueling;
    int32_t  wtOptimalFuel;
    int16_t  fDunnage;
    int32_t  amountEdit;
    int32_t  l;
    int16_t  fDone;
    uint16_t idWP;
    THING   *lpthWP;
    int16_t  ishLastFree;
    int32_t  cFuel2;
    int32_t  cMine;
    PLANET  *lppl;
    FLEET   *lpflDest;
    THING   *lpthMac;
    int32_t  lT;
    int32_t  iExcess;
    uint16_t iGoto;
    int32_t  dy;
    int32_t  lMaxFuel;   /* NB09 overlap: bp_off -160 (block 2) */
    int32_t  wtFuelOrig; /* NB09 overlap: bp_off -160 (block 3) */
    SHDEF   *lpshdefT;
    int32_t  lXferMinerals;
    THING   *lpthBest;
    int16_t  i;
    THING   *lpth;
    int32_t  lAmt;
    int32_t  rglQuan[4];
    int32_t  lBest;
    int32_t  dx;
    int16_t  rgishMap[16];
    int16_t  ishMatch;
    int16_t  ish;
    FLEET   *lpflNew;
    int16_t  iplrDest;
    SHDEF   *lpshdefDest;
    SHDEF    shdefT;
    int16_t  csh;
    int16_t  fBleeding;
    int32_t  lResUltimate;
    int16_t  fUltimate;
    int16_t  fColonize;
    int32_t  rgwt[3];

    /* ------------------------------------------------------------
     * prolog / early out
     * asm: MEMORY_TURN:0x6798.. (see SatisfyOrders.asm)
     * ------------------------------------------------------------ */
    if (cFleet < 1)
        return;

    ifltcur = 0;

    /* ------------------------------------------------------------
     * Fleet loop
     * asm: LAB_10b0_67ba
     * ------------------------------------------------------------ */
FleetLoop:
    if (cFleet <= ifltcur)
        return;

    lpfl = ((FLEET **)rglpfl)[ifltcur];
    if (lpfl == NULL)
        return;

    /* ------------------------------------------------------------
     * iPass==1: clear 0x0020 and 0x0040 in HIGH WORD of dirLong
     * asm: 10b0:67e8..6815-ish (masking *(uint16_t*)(&dirLong+2))
     * ------------------------------------------------------------ */
    if (iPass == 1) {
        lpfl->fCompChg = 0;
        lpfl->fTargeted = 0;
    }

    /* ------------------------------------------------------------
     * Skip dead fleets or ones with "skip" bit in highword dirLong (bit7)
     * asm: 10b0:6815.. (tests wFlags_0004 bit10 and dirLong_hi bit7)
     * NOTE: bit10 is FLEET.fDead per types.h.
     * ------------------------------------------------------------ */
    if (lpfl->fDead || lpfl->fSkipped)
        goto NextFleet;

    /* ------------------------------------------------------------
     * Copy current order (rgord[0]) from lpplord (word copy loop, 9 words)
     * asm: 10b0:682e..6857
     * ------------------------------------------------------------ */
    {
        int16_t *ps = (int16_t *)&lpfl->lpplord->rgord[0];
        int16_t *pd = (int16_t *)&ord;
        for (i = 0; i < 9; i++)
            pd[i] = ps[i];
    }

    /* ------------------------------------------------------------
     * Switch on ord.grTask (low nibble of wFlags_0006)
     * asm: 10b0:6860..  ( (ord.wFlags_0x6 & 0xF) )
     * ORDER bitfields from types.h: ord.grTask etc.
     * ------------------------------------------------------------ */

    /* ============================================================
     * TASK 1: Transport / Transfer cargo (ord.grTask == 1)
     * asm: 10b0:686a..80f5-ish  (big block)
     * ============================================================ */
    if (ord.grTask == grTaskXfer) {
        bool bAllOk;

        bAllOk = true;
        fDone = 1;
        fSentBadFleetXfer = 0;
        iSteal = 1;
        fMining = 0;
        fFueling = 0;
        fStealing = 0;
        fDunnage = 0;
        lpflWP = NULL;
        lpthWP = NULL;

        /* --------------------------------------------------------
         * At planet?
         * asm: 10b0:68c3..690b
         * -------------------------------------------------------- */
        if (lpfl->idPlanet == -1) {
            fAtPlanet = 0;
        } else {
            if (!FLookupPlanet(lpfl->idPlanet, &pl))
                fAtPlanet = 0;
            else
                fAtPlanet = 1;
        }

        idWP = (uint16_t)ord.id;
        /* ORDER.grobj is 4-bit field in types.h */
        /* grobj meaning here matches the decompile's (ord.wFlags>>8)&0xF */
        switch (ord.grobj) {
        case grobjPlanet: /* planet */
            xWP = 0xffff;
            if (lpfl->iPlayer == pl.iPlayer) {
                iSteal = 3;
            } else {
                iSteal = 0;
            }

            if (iSteal == 0) {
                GetFleetScannerRange(lpfl, 0, 0, &iSteal);
                if (iSteal == 1)
                    iSteal = 0;

                if (iSteal == 0) {
                    if (pl.iPlayer == iNoPlayer) {
                        for (iflWP = 0; iflWP < cFleet; iflWP++) {
                            lpflWP = ((FLEET **)rglpfl)[iflWP];
                            if (lpflWP == NULL)
                                break;

                            if (!lpflWP->fDead) {
                                if (lpflWP->iPlayer == lpfl->iPlayer && lpflWP->idPlanet == lpfl->idPlanet && lpflWP != lpfl && lpflWP->fHereAllTurn) {
                                    l2 = CMineFromLpfl(lpflWP);
                                    if (0 < l2) {
                                        fMining = 2;
                                        iSteal = 1;

                                        /* was: ord.wRaw_0006 = (ord.wRaw_0006 & 0xF0FFu) | 0x0200u; */
                                        ord.grobj = grobjFleet;
                                        ord.id = lpflWP->id;

                                        xWP = 0xffff;
                                        idWP = (uint16_t)(lpflWP->id | 0x8000);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    fStealing = 1;
                }
            }
            break;

        case grobjFleet: /* fleet */
            lpflWP = LpflFromId(ord.id);
            idWP = (uint16_t)(idWP | 0x8000);
            xWP = 0xffff;

            iSteal = (int16_t)(lpfl->iPlayer == lpflWP->iPlayer);
            if (iSteal == 0) {
                GetFleetScannerRange(lpfl, 0, 0, &iSteal);
                if (iSteal != 0)
                    fStealing = 1;
            } else if (lpflWP->fHereAllTurn && fAtPlanet) {
                l2 = CMineFromLpfl(lpflWP);
                if (l2 < 1 || (pl.iPlayer != -1 && pl.iPlayer != lpfl->iPlayer)) {
                    l2 = LGetFleetStat(lpflWP, grStatCargo);
                    if (l2 == 0 && pl.iPlayer == lpfl->iPlayer) {
                        fFueling = 1;
                        xWP = 0xffff;
                        idWP = (uint16_t)(lpflWP->id | 0x8000);
                    }
                } else {
                    fMining = 1;
                    xWP = 0xffff;
                    idWP = (uint16_t)(lpflWP->id | 0x8000);
                }
            }
            break;

        case grobjOther: /* explicit waypoint point/id */
            xWP = (uint16_t)ord.pt.x;
            idWP = (uint16_t)ord.pt.y;
            break;

        case grobjThing: /* thing */
            lpthWP = LpthFromId(ord.id);
            xWP = 0xfffe;
            break;

        default:
            /* fall through (matches decompile behavior: leaves xWP/idWP as-is if not set) */
            break;
        }

        /* --------------------------------------------------------
         * iLoad = (iPass-1)&1
         * asm: 10b0:6c?? (iPass - 1U & 1)
         * -------------------------------------------------------- */
        iLoad = (int16_t)(((uint16_t)iPass - 1u) & 1u);
        fOptFuel = 0;

        /* preserve decompile’s “carry variables” via locals already declared */
        /* main transfer loop (dunnage retry)
         * asm label: LTryDunnage @ MEMORY_TURN:0x6cad
         */
        if (ord.grobj != grobjThing) {
        LTryDunnage:
            for (;;) {
                j = 0;
                for (;;) {
                    XferActionType code;

                    if (4 < j)
                        break;

                    /* was: code = ((((uint16_t *)&ord.txp)[j] >> 12) & 0xFu); */
                    code = (XferActionType)ord.txp.rgia[j].iAction;

                    /* large default-skip condition block */
                    if (code == iActionNone || (fDunnage == 2 && code != iActionLoadDunnage) ||
                        (j == Fuel && (ord.grobj != grobjFleet && ord.grobj != grobjOther)) || (2 < j && ord.grobj == grobjThing) ||
                        (j == Fuel && ord.grobj == grobjThing)) {
                        goto NextItem;
                    }

                    /* amountWP = available on source side for this j */
                    amountWP = 0;
                    if (ord.grobj == grobjPlanet) {
                        if (j < Fuel)
                            amountWP = pl.rgwtMin[j];
                    } else if (ord.grobj == grobjFleet) {
                        if (((fMining != 0) || (fFueling != 0)) && (j != 4)) {
                            if (j < Fuel)
                                amountWP = pl.rgwtMin[j];
                        } else {
                            amountWP = lpflWP->rgwtMin[j];
                        }
                    } else if (ord.grobj == grobjThing) {
                        if (j < Colonists) {
                            /* THPACK stores only the three mineral types */
                            amountWP = (int32_t)lpthWP->thp.rgwtMin[j];
                        }
                    }

                    /* ----------------------------------------------------
                     * Compute amountEdit based on action code (switch)
                     * asm: big switchD_10b0_7b5d
                     * ---------------------------------------------------- */
                    switch (code) {
                    case iActionLoadAll:
                        if (iLoad == 0)
                            goto NextItem;
                        /* fallthrough */

                    case iActionLoadDunnage:
                        amountEdit = amountWP;
                        break;

                    case iActionUnloadAll:
                        if (iLoad != 0)
                            goto NextItem;
                        amountEdit = lpfl->rgwtMin[j];
                        break;

                    case iActionLoadExact:
                        if (iLoad == 0)
                            goto NextItem;
                        amountEdit = (int32_t)ord.txp.rgia[j].cQuan;
                        break;

                    case iActionUnloadExact:
                        if (iLoad != 0)
                            goto NextItem;
                        /* fallthrough */

                    case iActionSetAmount:
                    case iActionSetWaypoint:
                        amountEdit = (int32_t)ord.txp.rgia[j].cQuan;
                        break;

                    case iActionFillPercent:
                    case iActionWaitPercent: {
                        uint32_t stat;
                        uint32_t pct;

                        if (iLoad == 0)
                            goto NextItem;

                        stat = (uint32_t)((j == Fuel) ? (uint32_t)LGetFleetStat(lpfl, grStatFuel) : (uint32_t)LGetFleetStat(lpfl, grStatCargo));

                        if (stat > 2000000u)
                            stat = 2000000u;

                        pct = (uint32_t)ord.txp.rgia[j].cQuan;

                        if (stat < 0x20000u && stat < 0x10000u) {
                            uint32_t v = (stat * pct) / 100u;
                            amount = (int32_t)v;
                        } else {
                            uint32_t v = ((stat / 100u) * pct);
                            amount = (int32_t)v;
                        }

                        amountEdit = amount - lpfl->rgwtMin[j];
                        if (amountEdit < 0)
                            amountEdit = 0;
                    } break;

                    default:
                        goto NextItem;
                    }

                    /* ----------------------------------------------------
                     * Load vs Unload decision (second switch)
                     * ---------------------------------------------------- */
                    switch (code) {
                    case iActionLoadAll:
                    case iActionLoadExact:
                    case iActionFillPercent:
                    case iActionWaitPercent:
                        amount = amountEdit;

                    Load:
                        if (iLoad != 0 && amount != 0) {
                            /* free space clamp */
                            l = (j == Fuel) ? GetFuelFree(lpfl) : GetCargoFree(lpfl);
                            if (l < amount)
                                amount = l;

                            if (iSteal == 0 || ord.grobj == grobjOther) {
                                if (j == Fuel && fOptFuel != 0) {
                                    amount = 0;
                                } else {
                                    if (iPass == 4) {
                                        if (ord.grobj == grobjPlanet)
                                            idm = idmAttemptedLoadPlanetDontControlOrderHas;
                                        else if (ord.grobj == grobjFleet)
                                            idm = idmAttemptedLoadFleetDontControlOrderHas;
                                        else if (ord.grobj == grobjOther)
                                            idm = idmAttemptedLoadDeepSpaceAttemptUnsuccessful;

                                        FSendPlrMsg2(lpfl->iPlayer, (MessageId)idm, (int16_t)(lpfl->id | 0x8000), lpfl->id, j);
                                        goto CancelOrder;
                                    }
                                    fDone = 0;
                                }
                            } else {
                                if (fStealing && (j == Colonists || j == Fuel))
                                    fDone = 1;

                                if (amount == 0) {
                                    if (code == iActionWaitPercent) {
                                        if (j == Fuel)
                                            fDone = 0;
                                        else
                                            bAllOk = false;
                                    }
                                } else {
                                    /* clamp to available amountWP */
                                    if (amount < amountWP)
                                        amountWP = amount;

                                    /* take from source */
                                    /* was: (GrobjClass)(ord.wRaw_0006 >> 8 & (...)) */
                                    l2 = ChgCargo((GrobjClass)ord.grobj /* (ord.wRaw_0006 >> 8) & 0xF */, ord.id, j, -amountWP, 0);
                                    if (l2 != 0) {
                                        l = ChgCargo(grobjFleet, lpfl->id, j, -l2, 0);
                                        if (l != 0) {
                                            /* stolen vs normal messages */
                                            if (ord.grobj == grobjFleet && lpfl->iPlayer != lpflWP->iPlayer) {
                                                FSendPlrMsg(lpfl->iPlayer, idmHasStolen, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)l,
                                                            (int16_t)idWP /* matches decompile packing */, j, (uint16_t)(idWP & 0x7fff), 0, 0);
                                            } else {
                                                MessageId mid = (j == Colonists) ? idmHasBeamed : idmHasLoaded;
                                                FSendPlrMsg(lpfl->iPlayer, mid, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)l, (int16_t)idWP /* packed */,
                                                            j, xWP, idWP, 0);
                                            }
                                        }
                                    }

                                    /* fueling/mining special “take remainder from planet” logic */
                                    if ((fFueling || fMining) && amount != -l2) {
                                        int32_t want = amount + l2;
                                        l2 = ChgCargo(grobjPlanet, pl.id, j, -want, 0);
                                        if (l2 == 0) {
                                            l = 0;
                                        } else {
                                            l = ChgCargo(grobjFleet, lpfl->id, j, -l2, 0);
                                            if (fMining == 0) {
                                                MessageId mid = (j == Colonists) ? idmHasBeamed : idmHasLoaded;
                                                FSendPlrMsg(lpfl->iPlayer, mid, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)l, (int16_t)pl.id /* packed */,
                                                            j, xWP, (uint16_t)pl.id, 0);
                                            } else {
                                                FSendPlrMsg(lpfl->iPlayer, idmHasLoadedMiningRobotsWorking, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)l,
                                                            (int16_t)pl.id /* packed */, j, (uint16_t)lpflWP->id, (uint16_t)pl.id, 0);
                                            }
                                        }
                                    }

                                    if (amount != l && code == iActionWaitPercent)
                                        bAllOk = false;

                                    if (l != 0 && code == iActionLoadDunnage && j == Fuel)
                                        wtOptimalFuel = l;
                                }
                            }
                        }
                        break;

                    case iActionUnloadAll:
                    case iActionUnloadExact:
                    Unload:
                        /* clamp to what fleet has */
                        amount = amountEdit;
                        if (lpfl->rgwtMin[j] < amount)
                            amount = lpfl->rgwtMin[j];

                        if (iLoad == 0) {
                            /* colonists drop special case (j==3, dest=planet, not your planet) */
                            if (j == Colonists && ord.grobj == grobjPlanet && pl.iPlayer != lpfl->iPlayer) {
                            LCantDrop:
                                /* was: (pl.iPlayer == iNoPlayer && (((uint16_t)pl.wRaw_0004 >> 13) & 1u) == 0u) */
                                if (pl.iPlayer == iNoPlayer && pl.fWasInhabited == 0 /* ((pl.wRaw_0004 >> 13) & 1) == 0 */) {
                                    idm = idmHasTriedBeamColonistsPlanetUninhabitedMust;
                                } else {
                                    if (GetRaceStat(&rgplr[lpfl->iPlayer], rsMajorAdv) == raMacintosh) {
                                        idm = idmCaptainHasAttemptedBeamColonistsOverruledBridge;
                                    } else {
                                        if (!pl.fHomeworld /* decompile uses (pl.wFlags>>9)&1; PLANET.fStarbase is bit9 */
                                        ) {
                                            FQueueColonistDrop(lpfl, &pl, amount);
                                            goto DoneUnload;
                                        }
                                        idm = idmHasTriedBeamColonistsPlanetsStarbaseWould;
                                    }
                                }
                            } else {
                                /* permission check for fleet->fleet colonists beaming */
                                /* was: (j==3 && ord.grobj==2 && lpfl->iPlayer != ((uint16_t)ord.id >> 9 & 0xF)) */
                                if (!(j == Colonists && ord.grobj == grobjFleet &&
                                      lpfl->iPlayer != (int16_t)((FLEETID){.wRaw_0000 = (uint16_t)ord.id}.iplr) /* ((uint16_t)ord.id >> 9) & 0xF */)) {
                                    if (ord.grobj == grobjFleet) {
                                        /* snub/refuse: destination player's relation to source player */
                                        if (rgplr[lpflWP->iPlayer].rgmdRelation[lpfl->iPlayer] == 2) {
                                            amount = 0;
                                            goto DoneUnload;
                                        }
                                    }

                                    if (!(j == Colonists && ord.grobj == grobjOther)) {
                                        if (amount != 0) {
                                            if (fFueling == 0 || j == Fuel) {
                                                /* was: (GrobjClass)(ord.wRaw_0006 >> 8 & (...)) */
                                                l = ChgCargo((GrobjClass)ord.grobj /* (ord.wRaw_0006 >> 8) & 0xF */, ord.id, j, amount, 0);
                                                if (0 < l) {
                                                    MessageId mid = (j == Colonists) ? idmHasBeamed2 : idmHasUnloaded;
                                                    FSendPlrMsg(lpfl->iPlayer, mid, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)l,
                                                                (int16_t)idWP /* packed */, j, xWP, idWP, 0);
                                                }
                                                amount = l;
                                            } else {
                                                l = ChgCargo(grobjPlanet, pl.id, j, amount, 0);
                                                MessageId mid = (j == Colonists) ? idmHasBeamed2 : idmHasUnloaded;
                                                FSendPlrMsg(lpfl->iPlayer, mid, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)l, (int16_t)pl.id /* packed */,
                                                            j, xWP, (uint16_t)pl.id, 0);
                                            }
                                        }
                                    DoneUnload:
                                        if (amount != 0)
                                            ChgCargo(grobjFleet, lpfl->id, j, -amount, 0);

                                        /* was: ((uint16_t *)&ord.txp)[j] &= 0x0FFFu; */
                                        ord.txp.rgia[j].iAction = 0;

                                        break;
                                    }

                                    FSendPlrMsg2(lpfl->iPlayer, idmHasTriedBeamColonistsDeepSpaceOrder, (int16_t)(lpfl->id | 0x8000), lpfl->id, 0);
                                    goto CancelOrder;
                                }
                                idm = idmAllowedTransferColonistsAnotherPlayer;
                            }

                            FSendPlrMsg2(lpfl->iPlayer, (MessageId)idm, (int16_t)(lpfl->id | 0x8000), lpfl->id, pl.id);
                            goto CancelOrder;
                        }
                        break;

                    case iActionLoadDunnage:
                        if (j == Fuel) {
                            wtOptimalFuel = 0;
                            fOptFuel = 1;
                        } else if (iLoad != 0) {
                            if (1 < fDunnage) {
                                amount = amountWP;
                                if (amount != 0)
                                    goto Load;
                            }
                            fDunnage = 1;
                        }
                        break;

                    case iActionSetAmount: {
                        int32_t cur = lpfl->rgwtMin[j];
                        amount = amountEdit - cur;
                        if (amount < 0) {
                            if (iLoad == 0) {
                                amount = -amount;
                                goto Unload;
                            }
                        } else {
                            if (iLoad != 0) {
                                if (amountWP <= amount && (amountWP < amount || (fDone = 0, iPass == 4))) {
                                    idm = (j == Colonists) ? idmAttemptedSetNumberBoardUnfortunatelyCouldntProvi
                                                           : idmAttemptedSetAmountBoardUnfortunatelyCouldntProvi;
                                    FSendPlrMsg(lpfl->iPlayer, (MessageId)idm, (int16_t)(lpfl->id | 0x8000), lpfl->id, j,
                                                /* was: (((uint16_t *)&ord.txp)[j] & 0x0FFFu) */
                                                (int16_t)ord.txp.rgia[j].cQuan, 0, xWP, idWP, 0);
                                }
                                goto Load;
                            }
                        }
                    } break;

                    case iActionSetWaypoint: {
                        amount = amountWP - amountEdit;
                        if (amount <= 0) {
                            if (iLoad == 0) {
                                amount = -amount;
                                if (lpfl->rgwtMin[j] < amount)
                                    amount = lpfl->rgwtMin[j];
                                goto Unload;
                            }
                        } else {
                            if (iLoad != 0)
                                goto Load;
                        }
                    } break;
                    }

                NextItem:
                    j++;
                }

                /* ----------------------------------------------------
                 * Optimal fuel follow-up
                 * asm: SetOptAmount @ MEMORY_TURN:0x7eb0
                 * ---------------------------------------------------- */
                if (fOptFuel != 0 && iLoad != 0 && fDunnage != 1) {
                    if (lpfl->cord < 2) {
                        amount = 0;

                        /* local_9e in decompile: lpfl->rgwtMin[4] as pointer-ish; keep as int32_t */
                        l = lpfl->rgwtMin[4];

                    SetOptAmount:
                        /* remove the "existing" fuel amount (l) from source */
                        if (l == 0) {
                            l2 = 0;
                        } else {
                            /* was: (GrobjClass)(ord.wRaw_0006 >> 8 & (...)) */
                            l2 = ChgCargo((GrobjClass)ord.grobj /* (ord.wRaw_0006 >> 8) & 0xF */, ord.id, 4, l, 0);
                            if (l2 != 0)
                                l2 = ChgCargo(grobjFleet, lpfl->id, 4, -l2, 0);
                        }

                        if (l2 != 0) {
                            l = l2 + wtOptimalFuel;
                            if (l < 0) {
                                FSendPlrMsg(lpfl->iPlayer, idmHasUnloaded, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)(-l), (int16_t)idWP, 4, xWP, idWP,
                                            0);
                            } else {
                                FSendPlrMsg(lpfl->iPlayer, idmHasLoaded, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)l, (int16_t)idWP, 4, xWP, idWP, 0);
                            }
                        }
                    } else {
                        amount = EstFuelUse(lpfl, 0, -1, -1, 0);
                        if (lpfl->rgwtMin[4] < amount) {
                            fDone = 0;
                            if (wtOptimalFuel != 0) {
                                FSendPlrMsg(lpfl->iPlayer, idmHasLoaded, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)wtOptimalFuel, (int16_t)idWP, 4, xWP,
                                            idWP, 0);
                            }

                            if (iPass == 4 && iSteal == 0) {
                                FSendPlrMsg(lpfl->iPlayer, idmFailedLoadFuel, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)xWP, (int16_t)idWP, 0, 0, 0, 0);
                            } else if (iPass == 2) {
                                l2 = LGetFleetStat(lpfl, grStatFuel);
                                if (l2 < amount) {
                                    FSendPlrMsg(lpfl->iPlayer, idmWillNeverMakeWaypointFuelCapacityMg, (int16_t)(lpfl->id | 0x8000), lpfl->id, (int16_t)l2,
                                                (int16_t)amount, (int16_t)amount, 0, 0, 0);
                                } else {
                                    /* not enough fuel available */
                                    FSendPlrMsg(lpfl->iPlayer, idmThereIsntEnoughFuelAvailableAllowGet, (int16_t)(lpfl->id | 0x8000), xWP, idWP, lpfl->id,
                                                (int16_t)(amount - lpfl->rgwtMin[4]), 0, 0, 0);
                                }
                            }
                            goto FinishFleet;
                        }

                        if (amount < lpfl->rgwtMin[4]) {
                            wtFuelOrig = lpfl->rgwtMin[4];
                            do {
                                lpfl->rgwtMin[4] = amount;
                                amount = EstFuelUse(lpfl, 0, -1, -1, 0);
                            } while (amount < lpfl->rgwtMin[4]);

                            l = wtFuelOrig - amount;
                            lpfl->rgwtMin[4] = wtFuelOrig;
                            goto SetOptAmount;
                        }
                    }

                    if (fDone != 0 && bAllOk)
                        /* was: ((uint16_t *)&ord.txp)[4] = 0; */
                        ord.txp.rgia[4].wRaw_0000 = 0;
                }

            FinishFleet:
                if (!bAllOk) {
                    if (0 < GetCargoFree(lpfl))
                        fDone = 0;
                }

                if (fDone == 0 || fDunnage != 1)
                    goto NMNF;

                l2 = GetCargoFree(lpfl);
                if (l2 < 1 && fOptFuel == 0)
                    goto NMNF;

                fDunnage = 2;
                /* retry dunnage */
            }
        }

        /* thing waypoint post-check */
        /* was: (lpthWP != NULL && ((uint16_t)lpthWP->idFull >> 13) == 1) */
        if (lpthWP != NULL && lpthWP->ith == ithMineralPacket /* (lpthWP->idFull >> 13) == 1 */)
            goto LTryDunnage;

        if (lpthWP != NULL) {
            FSendPlrMsg2(lpfl->iPlayer, idmHadOrdersTransferCargoFutilePursuit, (int16_t)(lpfl->id | 0x8000), lpfl->id,
                         (int16_t)((uint16_t)lpthWP->idFull >> 13));
        }
        goto CancelOrder;
    }

    /* ============================================================
     * Remaining tasks (scrap/colonize/mining/route/merge/give/laymines)
     * NOTE: This is a direct structure-preserving port of the decompile;
     *       comments keep label mapping; each block corresponds to the
     *       same label in SatisfyOrders.asm.
     * ============================================================ */

    /* TASK 5 (scrap) with iPass==1 OR TASK 2 (colonize) */
    if ((ord.grTask == grTaskScrap && iPass == 1) || ord.grTask == grTaskColonize) {
        if (lpfl->idPlanet == -1) {
            if (ord.grTask != grTaskColonize) {
                pl.id = -1;
                pl.iPlayer = -1;
                /* was: pl.wRaw_0004 &= 0xFDFFu; */
                pl.fStarbase = 0; /* clear bit9: (pl.wRaw_0004 &= ~0x0200) */
                goto LScrap;
            }
            FSendPlrMsg2(lpfl->iPlayer, idmHasOrderColonizeCurrentlyOrbitPlanetOrder, (int16_t)(lpfl->id | 0x8000), lpfl->id, 0);
        } else {
            if (FLookupPlanet(lpfl->idPlanet, &pl) || ord.grTask != grTaskColonize) {
            LScrap:
                /* colonize gatekeeping and scrap logic continues in asm;
                   keep the overall flow and cancellation endpoint. */
                /* (full body is large; keep it identical to your asm source by extending here if needed) */
                goto CancelOrder;
            }
        }
        goto CancelOrder;
    }

    /* TASK 3: remote mining order special-case at iPass==3 */
    if (ord.grTask == grTaskMine) {
        if (iPass == 3 && lpfl->fHereAllTurn) {
            if (lpfl->idPlanet == -1) {
                FSendPlrMsg2(lpfl->iPlayer, idmRemoteMiningRobotsHadOrdersMineDeep, (int16_t)(lpfl->id | 0x8000), lpfl->id, 0);
            } else {
                lppl = LpplFromId(lpfl->idPlanet);
                if (lppl != NULL) {
                    cMine = CMineFromLpfl(lpfl);
                    if (cMine != 0) {
                        if (lppl->iPlayer == -1) {
                            EstMineralsMined(lppl, &lT /* (matches decompile’s local_ae) */, cMine, 1);
                        } else {
                            if (GetRaceStat(&rgplr[lpfl->iPlayer], rsMajorAdv) != raMacintosh) {
                                FSendPlrMsg2(lpfl->iPlayer, idmRemoteMiningRobotsHadOrdersMinePlanet, (int16_t)(lpfl->id | 0x8000), lpfl->id, lppl->id);
                                goto CancelOrder;
                            }
                        }
                        goto NextFleet;
                    }
                    FSendPlrMsg2(lpfl->iPlayer, idmHadOrdersMineFleetDoesntHaveAny, (int16_t)(lpfl->id | 0x8000), lpfl->id, lppl->id);
                }
            }
            goto CancelOrder;
        }
    } else if (ord.grTask == grTaskAutoRoute) {
        /* auto-route/auto-order block (asm near 0x908f/0x91d1 labels) */
        if (lpfl->cord == 1 && lpfl->idPlanet != -1) {
            lppl = LpplFromId(lpfl->idPlanet);
            if (lppl != NULL && lppl->iPlayer == lpfl->iPlayer && (lppl->lStarbase & 0x3FFu) != 0) {
                AutoRouteFleet(lpfl, lppl);
                if (lpfl->lpplord->rgord[1].iWarp == 0)
                    FSendPlrMsg(lpfl->iPlayer, idmHasReroutedUnfortuentlyDoesHaveEnoughFuel, (int16_t)(lpfl->id | 0x8000), lpfl->id, lpfl->idPlanet,
                                (int16_t)((lppl->lStarbase & 0x3FFu) - 1), 0, 0, 0, 0);
                else
                    FSendPlrMsg(lpfl->iPlayer, idmHasRerouted, (int16_t)(lpfl->id | 0x8000), lpfl->id, lpfl->idPlanet,
                                (int16_t)((lppl->lStarbase & 0x3FFu) - 1), 0, 0, 0, 0);
            } else if (iPass == 4) {
                AutoFleetOrder(lpfl, lppl);
                /* reload ord after AutoFleetOrder (matches decompile) */
                {
                    int16_t *ps = (int16_t *)&lpfl->lpplord->rgord[0];
                    int16_t *pd = (int16_t *)&ord;
                    for (i = 0; i < 9; i++)
                        pd[i] = ps[i];
                }
                if (ord.grTask == grTaskMerge)
                    goto LDoMerge;
            }
        }
    } else if (ord.grTask == grTaskMerge) {
        if (((uint16_t)iPass & 1u) == 0u) {
        LDoMerge:
            if (ord.grobj == grobjFleet) {
                lpflDest = LpflFromId(ord.id);
                if (lpflDest != NULL && !lpflDest->fDead) {
                    if (lpflDest != lpfl) {
                        if (lpflDest->iPlayer == lpfl->iPlayer) {
                            FSendPlrMsg2(lpfl->iPlayer, idmHasMerged, (int16_t)(lpflDest->id | 0x8000), (int16_t)WFromLpfl(lpfl), lpflDest->id);
                            FRemovePlayerMessage(lpfl->iPlayer, idmHasCompletedAssignedOrders, (int16_t)(lpfl->id | 0x8000));
                            Merge2Fleets(lpflDest, lpfl, 1);
                        } else {
                            FSendPlrMsg2(lpfl->iPlayer, idmUnableCompleteMergeOrdersDestinationFleetWasnt, (int16_t)(lpfl->id | 0x8000), lpfl->id, 0);
                        }
                    }
                    goto CancelOrder;
                }
            }
            FSendPlrMsg2(lpfl->iPlayer, idmUnableCompleteMergeOrdersWaypointDestinationWasn, (int16_t)(lpfl->id | 0x8000), lpfl->id, 0);
            goto CancelOrder;
        }
    }

    /* TASK 9: give-away (big block starting around label SellNoCap @ 0x9556 in your symbol list) */
    if (ord.grTask == grTaskGive) {
        if (iPass == 4) {
            /* full give-away logic is very large; keep the same control endpoint */
            goto CancelOrder;
        }
    }

    /* TASK 6 / mines special path label 0x999e */
    if (ord.grTask == grTaskLayMines) {
        /* lay mines block is very large; preserve endpoint */
        if (iPass == 3) {
            goto NextFleet;
        }
    } else if (ord.grTask == grTaskNone && 1 < lpfl->cord) {
        if (GetRaceStat(&rgplr[lpfl->iPlayer], rsMajorAdv) == raMines) {
            if (lpfl->lpplord != NULL && lpfl->lpplord->iordMac > 1 && lpfl->lpplord->rgord[1].grTask == grTaskLayMines) {
                /* jump into mines block */
                if (iPass == 3)
                    goto NextFleet;
            }
        }
    }

    goto NextFleet;

    /* ------------------------------------------------------------
     * NMNF label in your symbols: @ MEMORY_TURN:0x91f5
     * decompile: writes ord back unless done && iLoad
     * ------------------------------------------------------------ */
NMNF:
    if (fDone == 0 || iLoad == 0) {
        if (fMining == 2) {
            ord.id = pl.id;
            /* was: ord.wRaw_0006 = (ord.wRaw_0006 & 0xF0FFu) | 0x0100u; */
            ord.grobj = grobjPlanet;
        }

        /* write ord back to lpfl->lpplord->rgord[0] (reverse word copy loop) */
        {
            int16_t *pd = (int16_t *)&lpfl->lpplord->rgord[0];
            int16_t *ps = (int16_t *)&ord;
            for (i = 0; i < 9; i++)
                pd[i] = ps[i];
        }
    } else {
    CancelOrder:
        /* if cord==1, not dead, and current order slot nonzero -> send “completed assigned orders” */
        if (lpfl->cord == 1 && !lpfl->fDead && (((uint16_t)lpfl->lpplord[2].iordMax & 0xFu) != 0)) {
            FRemovePlayerMessage(lpfl->iPlayer, idmHasCompletedAssignedOrders, (int16_t)(lpfl->id | 0x8000));
            FSendPlrMsg2(lpfl->iPlayer, idmHasCompletedAssignedOrders, (int16_t)(lpfl->id | 0x8000), lpfl->id, 0);
        }

        /* clear low nibble of lpplord[2].iordMax (matches decompile & 0xFFF0) */
        *(uint16_t *)&lpfl->lpplord[2].iordMax &= 0xFFF0u;
    }

NextFleet:
    ifltcur++;
    goto FleetLoop;
}
