
#include "types.h"

#include "build.h"
#include "globals.h"
#include "memory.h"
#include "parts.h"
#include "planet.h"
#include "race.h"
#include "report.h"
#include "scan.h"
#include "ship.h"
#include "util.h"
#include "utilgen.h"

/* functions */

int32_t GetFuelFree(FLEET *lpfl) {
    int32_t lCapacity;

    lCapacity = LGetFleetStat(lpfl, grStatFuel);
    return lCapacity - lpfl->rgwtMin[4];
}

int32_t GetCargoFree(FLEET *lpfl) {
    int32_t cHave;
    int32_t lCapacity;

    cHave = 0;
    for (int i = 0; i < 4; i++) {
        cHave += lpfl->rgwtMin[i];
    }
    lCapacity = LGetFleetStat(lpfl, grStatCargo);
    return lCapacity - cHave;
}

int32_t XferSupply(int16_t iSupply, int32_t cQuan) {
    int16_t iSrc;
    int16_t iDst;
    int32_t cAvailable;
    int32_t lRemainder;

    if (cQuan == 0)
        return 0;

    iSrc = (0 < cQuan);
    if (!iSrc)
        cQuan = -cQuan;

    cAvailable = ChgCargo(pxfer[iSrc].grobj, pxfer[iSrc].id, iSupply, 0, &pxfer[iSrc].fl);
    if (cAvailable < cQuan)
        cQuan = cAvailable;

    if (cQuan == 0)
        return 0;

    iDst = !iSrc;
    lRemainder = ChgCargo(pxfer[iDst].grobj, pxfer[iDst].id, iSupply, cQuan, &pxfer[iDst].fl);
    if (lRemainder != 0) {
        ChgCargo(pxfer[iSrc].grobj, pxfer[iSrc].id, iSupply, -lRemainder, &pxfer[iSrc].fl);
    }
    return lRemainder;
}

int16_t CshQueued(int16_t ishdef, int16_t *pfProgress, int16_t fSpaceDocks) {
    int16_t iprod;
    PLANET *lppl;
    int16_t csh;
    PLANET *lpplMac;
    PROD   *lpprod;

    csh = 0;
    *pfProgress = 0;
    FORPLANETS(lppl, lpplMac) {
        if (lppl->lpplprod != NULL && lppl->lpplprod->iprodMac != 0 && lppl->iPlayer == idPlayer && lppl->fStarbase &&
            (fSpaceDocks == 0 || rglpshdefSB[idPlayer][lppl->isb].hul.ihuldef == (ihuldefCount + ihuldefSBSpaceDock))) {
            lpprod = lppl->lpplprod->rgprod;
            for (iprod = 0; iprod < (int16_t)lppl->lpplprod->iprodMac; iprod++) {
                if (lpprod->grobj == grobjFleet && lpprod->iItem == ishdef) {
                    csh += lpprod->cItem;
                    if (lpprod->pct != 0) {
                        *pfProgress = 1;
                    }
                }
                lpprod++;
            }
        }
    }
    return csh;
}

int32_t LGetFleetStat(FLEET *lpfl, GrStat grStat) {
    uint32_t acc = 0;
    int16_t  i;

    /* det==7 means a “normal” fleet we can score from its ship counts.
       Otherwise the original returns the sentinel 32000. */
    if (lpfl->det == detAll) {
        SHDEF *lpshdefBase = rglpshdef[lpfl->iPlayer]; /* far pointer in Win16, normal 32-bit pointer here */

        for (i = 0; i < cShdefMax; i++) {
            int16_t csh = lpfl->rgcsh[i];
            if (csh != 0) {
                int16_t wt = WtMaxShdefStat(&lpshdefBase[i], grStat);

                /* One cast to force unsigned 32-bit multiply */
                acc += (uint32_t)csh * (uint32_t)wt;
            }
        }
        return (int32_t)acc;
    }

    return 32000;
}

int16_t FCanSplitAll(int32_t cBoat) {
    if ((int32_t)(cBoat - 1 + (uint32_t)rgplr[idPlayer].cFleet) > cFleetAbsMax) {
        return 0;
    }
    if (cBoat < 2) {
        return 0;
    }
    return 1;
}

int32_t EstFuelUse(FLEET *lpfl, int16_t iOrd, int16_t iWarp, int32_t dTravel, int16_t fRangeOnly) {
    int32_t iEffNext;
    int32_t lT;
    int16_t fEfficient;
    double  d;
    int32_t iEffCur;
    int32_t wtCargoT;
    int32_t lFuel;
    ORDER  *lpord;
    int16_t i;
    SHDEF  *lpshdef;
    int32_t wtCargo;
    int16_t j;
    int32_t wtMass;
    int32_t rgieff[16];

    if (lpfl == NULL || lpfl->lpplord == NULL) {
        return 0;
    }

    /* Clear the "radiating engine" flag bit (set later if needed). */
    gd.fRadiatingEngine = 0;

    /* If warp not provided, use the next waypoint's warp setting. */
    if (iWarp == -1) {
        if (iOrd + 1 < lpfl->lpplord->iordMac) {
            iWarp = (int16_t)lpfl->lpplord->rgord[iOrd + 1].iWarp;
        } else {
            iWarp = 0;
        }
    }

    /*
     * Race attribute bit 0 is used here as an efficiency toggle in the
     * original code path.
     */
    fEfficient = GetRaceGrbit(&rgplr[lpfl->iPlayer], 0);

    /* Build per-design "efficiency" values (engine fuel use at this warp). */
    {
        SHDEF *base = rglpshdef[lpfl->iPlayer];
        for (i = 0; i < 16; i++) {
            if (lpfl->rgcsh[i] <= 0) {
                rgieff[i] = 0;
                continue;
            }

            lpshdef = (SHDEF *)((uint8_t *)base + (int32_t)i * 0x93);

            /* Find the first non-destroyed hull slot (status != 1). */
            for (j = 0; j < (int16_t)lpshdef->hul.chs; j++) {
                if (lpshdef->hul.rghs[j].grhst != 1) {
                    break;
                }
            }

            /* If no usable engine slot, treat as "very inefficient". */
            if (j >= (int16_t)lpshdef->hul.chs) {
                rgieff[i] = 99999;
                continue;
            }

            /* Use the engine in slot j. */
            {
                uint8_t engineId = (uint8_t)lpshdef->hul.rghs[j].iItem;
                ENGINE *lpeng = LpengineFromId(engineId);

                /* Engine fuel use table is indexed by warp (0..11). */
                int32_t eff = (int32_t)lpeng->rgcFuelUsed[iWarp];

                /* Apply the "efficient" race bonus (15% reduction). */
                if (fEfficient) {
                    eff -= (eff * 15) / 100;
                }

                rgieff[i] = eff;

                /* Engine id 10 toggles the global radiating-engine flag. */
                if (engineId == 10) {
                    gd.fRadiatingEngine = 1;
                }
            }
        }
    }

    /* Sum cargo weight (first 4 cargo buckets; the 5th is fuel). */
    wtCargo = 0;
    for (i = 0; i < 4; i++) {
        wtCargo += lpfl->rgwtMin[i];
    }

    /* Determine travel distance if requested. */
    if (dTravel == -1) {
        if (fRangeOnly == 0) {
            if (iOrd + 1 < lpfl->lpplord->iordMac) {
                lpord = &lpfl->lpplord->rgord[iOrd];
                dTravel = (int32_t)(DGetDistance(lpord[0].pt.x, lpord[0].pt.y, lpord[1].pt.x, lpord[1].pt.y) + 0.0);
            } else {
                dTravel = 0;
            }
        } else {
            /* Range-only mode uses a fixed nominal distance. */
            dTravel = 1000;
        }
    }

    /*
     * Original algorithm processes ship designs by increasing efficiency
     * buckets, allocating cargo as it goes.
     */
    lFuel = 0;
    iEffCur = 0;
    while (1) {
        iEffNext = 0x000f423f; /* 999999 as a sentinel "none" */

        for (i = 0; i < 16; i++) {
            int16_t csh = lpfl->rgcsh[i];
            if (csh <= 0) {
                continue;
            }

            if (rgieff[i] == iEffCur) {
                /* Cargo allocation for this design. */
                int16_t capPerShip = WtMaxShdefStat((SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)i * 0x93), 2);
                int32_t capTotal = (int32_t)csh * (int32_t)capPerShip;
                wtCargoT = (wtCargo < capTotal) ? wtCargo : capTotal;
                wtCargo -= wtCargoT;

                /* Empty mass = count * wtEmpty. */
                wtMass = wtCargoT + (int32_t)csh * (int32_t)((SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)i * 0x93))->hul.wtEmpty;

                /* lT = iEffCur * dTravel (32-bit signed in original helpers). */
                lT = (int32_t)((int64_t)iEffCur * (int64_t)dTravel);

                /* Fuel used is roughly wtMass*lT/2000 (with float fallback in Win16). */
                if (wtMass <= 0 || lT <= 0) {
                    /* no-op */
                } else {
                    int64_t num = (int64_t)wtMass * (int64_t)lT;
                    int32_t add;

                    /* Preserve the original "use double when huge" behavior, but
                     * still compute with correct math.
                     */
                    if (num > (int64_t)INT32_MAX * 2000LL) {
                        d = ((double)wtMass * (double)lT) / 2000.0;
                        add = (int32_t)d;
                    } else {
                        add = (int32_t)(num / 2000LL);
                    }

                    lFuel += add;
                }
            } else if (rgieff[i] > iEffCur) {
                if (rgieff[i] < iEffNext) {
                    iEffNext = rgieff[i];
                }
            }
        }

        if (iEffNext == 0x000f423f) {
            break;
        }
        iEffCur = iEffNext;
    }

    /* Convert internal 1/10 units to whole fuel units. */
    if (fRangeOnly == 0) {
        lFuel += 9;
    }
    lFuel = lFuel / 10;

    if (fRangeOnly != 0) {
        /* Range = (fuel_on_board * 1000) / fuel_per_1000_distance. */
        if (lFuel == 0) {
            return (int32_t)0xca00; /* "infinite" sentinel used by original */
        }

        if (lFuel < 100001) {
            int64_t num = (int64_t)lpfl->rgwtMin[4] * 1000LL;
            return (int32_t)(num / (int64_t)lFuel);
        }

        /* Avoid overflow by scaling fuel use first (mirrors original). */
        {
            int32_t scaled = lFuel / 1000;
            if (scaled <= 0) {
                return (int32_t)0xca00;
            }
            return lpfl->rgwtMin[4] / scaled;
        }
    }

    return lFuel;
}

void DeleteCurWayPoint(int16_t fBackup) {
    int16_t    cpt;
    STARSPOINT pt;
    POINT      rgpt[3];
    SCAN       scan;
    int16_t    ipt;
    RECT       rc;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x9dce */

    if (sel.fl.cord < 2 || sel.iwpAct == 0) {
#ifdef _WIN32
        MessageBeep(0x40);
#endif
        return;
    }

    if ((grbitScan & 0x80) != 0) {
        PLORD *lpplord = sel.fl.lpplord;
        rgpt[0].x = lpplord->rgord[sel.iwpAct].pt.x;
        rgpt[0].y = lpplord->rgord[sel.iwpAct].pt.y;
        rgpt[1].x = lpplord->rgord[sel.iwpAct - 1].pt.x;
        rgpt[1].y = lpplord->rgord[sel.iwpAct - 1].pt.y;
        if (sel.iwpAct < sel.fl.cord - 1) {
            cpt = 3;
            rgpt[2].x = lpplord->rgord[sel.iwpAct + 1].pt.x;
            rgpt[2].y = lpplord->rgord[sel.iwpAct + 1].pt.y;
        } else {
            cpt = 2;
        }
    }

#ifdef _WIN32
    RedrawScanSel(0, 0);
#endif

    /* Remove current waypoint by shifting orders down */
    memmove(&sel.fl.lpplord->rgord[sel.iwpAct], &sel.fl.lpplord->rgord[sel.iwpAct + 1], (sel.fl.cord - sel.iwpAct - 1) * sizeof(ORDER));
    sel.fl.cord--;
    sel.fl.lpplord->iordMac--;

    int16_t iVar2 = sel.iwpAct - 1;

    /* Check for duplicate adjacent waypoints and remove */
    if (iVar2 < sel.fl.cord - 1) {
        STARSPOINT *ptPrev = &sel.fl.lpplord->rgord[iVar2].pt;
        STARSPOINT *ptNext = &sel.fl.lpplord->rgord[sel.iwpAct].pt;
        if (ptPrev->x == ptNext->x && ptPrev->y == ptNext->y) {
            int16_t iNext = sel.iwpAct + 1;
            int16_t iCur = sel.iwpAct;
            sel.iwpAct = iVar2;
            memmove(&sel.fl.lpplord->rgord[iCur], &sel.fl.lpplord->rgord[iNext], (sel.fl.cord - iVar2 - 2) * sizeof(ORDER));
            sel.fl.cord--;
            sel.fl.lpplord->iordMac--;
            iVar2 = sel.iwpAct;
        }
    }

    sel.iwpAct = iVar2;
    if (fBackup == 0 && sel.iwpAct < sel.fl.cord - 1)
        sel.iwpAct++;

#ifdef _WIN32
    RedrawScanSel(0, 0);
#endif
    FLookupFleet(-1, (FLEET *)&sel.fl);

#ifdef _WIN32
    STARSPOINT ptWp = sel.fl.lpplord->rgord[sel.iwpAct].pt;
    FFindNearestObject(ptWp, 0x8f, &scan);
    sel.iwpAct = -2;
    ChangeScanSel(&scan, 1);
#endif

#ifdef _WIN32
    if ((grbitScan & 0x80) != 0) {
        for (ipt = 0; ipt < cpt; ipt++)
            LogicalToScan(&rgpt[ipt]);
        BoundPoints(&rc, rgpt, cpt);
        InvalidateRect(hwndScanner, &rc, 1);
    }
#endif
}

int16_t TransferStuff(int16_t id1, int16_t grobj1, int16_t id2, int16_t grobj2, int16_t mdXfer) {
    XFER xfer[2];
    int16_t (*lpProcXfer)(void);
    int16_t rgValidHull[16];
    int32_t lPopPrev;
    int16_t iDelFleet;
    int16_t i;
    FLEET  *lpfl;
    int16_t fSuccess;
    int16_t grbit;
    int16_t j;
    BTN     rgbtn[32];
    POINT   pt;
    RECT    rc;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x55c8 */
    /* label CancelSplit @ MEMORY_SHIP:0x5654 */
    /* label LInvalScanPlan @ MEMORY_SHIP:0x55c8 */

    /* TODO: implement */
    return 0;
}

void Merge2Fleets(FLEET *lpflDst, FLEET *lpflDel, int16_t fNoDelete) {
    FLEET   rgfl[2];
    int16_t i;

    memcpy(&rgfl[0], lpflDst, sizeof(FLEET));
    memcpy(&rgfl[1], lpflDel, sizeof(FLEET));
    for (i = 0; i < cShdefMax; i++) {
        rgfl[0].rgcsh[i] = rgfl[0].rgcsh[i] + rgfl[1].rgcsh[i];
        rgfl[1].rgcsh[i] = 0;
    }
    FleetTransferCargoBalance(&rgfl[0], &rgfl[1]);
    for (i = 0; i < 2; i++) {
        FLookupFleet(-1, &rgfl[i]);
    }
    if (fNoDelete == 0) {
        FDeleteFleet(rgfl[1].id, 2, rgfl[0].id);
        InvalidateReport(1, 2);
    } else {
        lpflDel->fDone = 1;
    }
}

void FleetTransferCargoBalance(FLEET *pflNew1, FLEET *pflNew2) {
    int16_t iplr;
    int32_t rgCargoCapLoss[2];
    int32_t wtCargoXfer;
    int16_t fDeadFleet;
    int32_t wtCargoTot;
    int16_t rgrgcshLoss[2][16];
    int32_t rgrgCargoDelta[2][5];
    int32_t rgFuelCapacity[2];
    FLEET  *rgpflNew[2];
    int16_t wtCargoMax;
    int16_t wtFuelMax;
    int16_t i;
    int32_t lChg;
    int32_t rgFuelCapLoss[2];
    FLEET   rgflCur[2];
    int16_t j;
    SHDEF  *lpshdef;
    int32_t rgCargoCapacity[2];
    int16_t ishdef;
    int32_t l;
    int32_t cshDmgDst;
    int32_t cshDmgSrc;
    int16_t iSrc;
    int32_t cshDmgMoved;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0xb227 */
    /* block (block) @ MEMORY_SHIP:0xb3c2 */
    /* block (block) @ MEMORY_SHIP:0xb81c */
    /* block (block) @ MEMORY_SHIP:0xbb73 */

    /* ------------------------------------------------------------ */
    /* asm: 1050:ae7d..afbd  (init, load old fleets if not dead)     */
    /* ------------------------------------------------------------ */

    wtCargoXfer = 0;
    rgpflNew[0] = pflNew1;
    rgpflNew[1] = pflNew2;

    iplr = pflNew2->iPlayer; /* asm: 1050:ae90..ae96 (iPlayer -> [BP-4]) */
    fDeadFleet = 0;

    for (i = 0; i < 2; i++) {
        if (rgpflNew[i]->fDead == 0) {
            /* asm: 1050:aefc..af1f */
            FLookupFleet(rgpflNew[i]->id, &rgflCur[i]);
        } else {
            /* asm: 1050:aec3..aef9 */
            fDeadFleet = 1;
            memset(&rgflCur[i], 0, 0x7c);
            rgflCur[i].iPlayer = iplr;
        }

        /* asm: 1050:af22..af75 (zero per-side accumulators) */
        rgCargoCapLoss[i] = 0;
        rgCargoCapacity[i] = 0;
        rgFuelCapLoss[i] = 0;
        rgFuelCapacity[i] = 0;

        /* asm: 1050:af77..afae (zero deltas [2][5]) */
        for (j = 0; j < 5; j++) {
            rgrgCargoDelta[i][j] = 0;
        }
    }

    /* ------------------------------------------------------------ */
    /* asm: 1050:afbd..bd05  (capacity + loss accumulation per shdef)*/
    /* ------------------------------------------------------------ */

    for (ishdef = 0; ishdef < cShdefMax; ishdef++) {
        /* asm: 1050:afc6..afeb (skip if neither side has this shdef) */
        if (rgflCur[0].rgcsh[ishdef] == 0 && rgflCur[1].rgcsh[ishdef] == 0)
            continue;

        /* asm: 1050:afee..b03a (lpshdef = rglpshdef[iplr] + ishdef*0x93; stats) */
        lpshdef = &rglpshdef[iplr][ishdef];
        wtFuelMax = WtMaxShdefStat(lpshdef, grStatFuel);
        wtCargoMax = WtMaxShdefStat(lpshdef, grStatCargo);

        /* asm: 1050:b03e..b1e0 (per-side accumulate capacities and losses) */
        for (i = 0; i < 2; i++) {
            rgrgcshLoss[i][ishdef] = (int16_t)(rgflCur[i].rgcsh[ishdef] - rgpflNew[i]->rgcsh[ishdef]);

            if (rgflCur[i].rgcsh[ishdef] != 0) {
                rgFuelCapacity[i] += (int32_t)rgflCur[i].rgcsh[ishdef] * wtFuelMax;
                rgCargoCapacity[i] += (int32_t)rgflCur[i].rgcsh[ishdef] * wtCargoMax;

                if (rgrgcshLoss[i][ishdef] > 0) {
                    rgFuelCapLoss[i] += (int32_t)rgrgcshLoss[i][ishdef] * wtFuelMax;
                    rgCargoCapLoss[i] += (int32_t)rgrgcshLoss[i][ishdef] * wtCargoMax;
                }
            }
        }

        /* ------------------------------------------------------------ */
        /* asm: 1050:b2..bcf4  (damage % rebalance when exact ship swap) */
        /*  uses rgdv[ishdef].pctSh (low 7) and .pctDp (high 9)          */
        /* ------------------------------------------------------------ */
        if (fDeadFleet == 0 && rgrgcshLoss[0][ishdef] == (int16_t)-rgrgcshLoss[1][ishdef] && rgrgcshLoss[0][ishdef] != 0) {

            /* asm: 1050:??  (uVar10 = (rgrgcshLoss[0] < 0)) */
            iSrc = (rgrgcshLoss[0][ishdef] < 0) ? 1 : 0; /* side losing ships */

            /* asm: 1050:??  (cshDmg = pctSh * csh / 100, guarded on csh<1) */
            if (rgflCur[iSrc].rgcsh[ishdef] < 1) {
                cshDmgSrc = 0;
            } else {
                cshDmgSrc = ((int32_t)rgflCur[iSrc].rgdv[ishdef].pctSh * (int32_t)rgflCur[iSrc].rgcsh[ishdef]) / 100;
            }

            if (rgflCur[iSrc ^ 1].rgcsh[ishdef] < 1) {
                cshDmgDst = 0;
            } else {
                cshDmgDst = ((int32_t)rgflCur[iSrc ^ 1].rgdv[ishdef].pctSh * (int32_t)rgflCur[iSrc ^ 1].rgcsh[ishdef]) / 100;
            }

            if (cshDmgSrc == 0 || cshDmgDst == 0) {
                if (cshDmgSrc == 0) {
                    if (cshDmgDst == 0) {
                        /* asm: clear pctSh */
                        rgpflNew[iSrc ^ 1]->rgdv[ishdef].pctSh = 0;
                    } else {
                        /* asm: pctNew = ceil(cshDmgDst*100 / csh) */
                        int32_t pctNew = (cshDmgDst * 100 + rgpflNew[iSrc ^ 1]->rgcsh[ishdef] - 1) / rgpflNew[iSrc ^ 1]->rgcsh[ishdef];
                        rgpflNew[iSrc ^ 1]->rgdv[ishdef].pctSh = pctNew;
                    }
                } else {
                    /* asm: move some damaged “mass”; copy pctDp bits from src -> dst */
                    cshDmgMoved = cshDmgSrc;
                    if (rgrgcshLoss[iSrc][ishdef] < cshDmgMoved)
                        cshDmgMoved = rgrgcshLoss[iSrc][ishdef];

                    rgpflNew[iSrc ^ 1]->rgdv[ishdef].pctDp = rgpflNew[iSrc]->rgdv[ishdef].pctDp;

                    {
                        /* block 2/3 overlap locals in NB09: pctNew + cshDmgMoved */
                        int32_t pctNew = (cshDmgMoved * 100 + rgpflNew[iSrc ^ 1]->rgcsh[ishdef] - 1) / rgpflNew[iSrc ^ 1]->rgcsh[ishdef];
                        rgpflNew[iSrc ^ 1]->rgdv[ishdef].pctSh = pctNew;
                    }

                    if (cshDmgMoved == cshDmgSrc) {
                        rgpflNew[iSrc]->rgdv[ishdef].pctSh = 0;
                    } else {
                        int32_t pctNew = ((cshDmgSrc - cshDmgMoved) * 100 + rgpflNew[iSrc]->rgcsh[ishdef] - 1) / rgpflNew[iSrc]->rgcsh[ishdef];
                        rgpflNew[iSrc]->rgdv[ishdef].pctSh = pctNew;
                    }
                }
            } else {
                /* asm: both sides have dmg -> weighted pctDp merge + pctSh recompute */
                cshDmgMoved = cshDmgSrc;
                if (rgrgcshLoss[iSrc][ishdef] < cshDmgMoved)
                    cshDmgMoved = rgrgcshLoss[iSrc][ishdef];

                {
                    int32_t num = cshDmgMoved * (int32_t)rgflCur[iSrc].rgdv[ishdef].pctDp + cshDmgDst * (int32_t)rgflCur[iSrc ^ 1].rgdv[ishdef].pctDp +
                                  rgpflNew[iSrc ^ 1]->rgcsh[ishdef] - 1;
                    int32_t den = rgpflNew[iSrc ^ 1]->rgcsh[ishdef];
                    rgpflNew[iSrc ^ 1]->rgdv[ishdef].pctDp = num / den;
                }

                {
                    int32_t pctNew = ((cshDmgDst + cshDmgMoved) * 100 + rgpflNew[iSrc ^ 1]->rgcsh[ishdef] - 1) / rgpflNew[iSrc ^ 1]->rgcsh[ishdef];
                    rgpflNew[iSrc ^ 1]->rgdv[ishdef].pctSh = pctNew;
                }

                if (cshDmgMoved == cshDmgSrc) {
                    rgpflNew[iSrc]->rgdv[ishdef].pctSh = 0;
                } else {
                    int32_t pctNew = ((cshDmgSrc - cshDmgMoved) * 100 + rgpflNew[iSrc]->rgcsh[ishdef] - 1) / rgpflNew[iSrc]->rgcsh[ishdef];
                    rgpflNew[iSrc]->rgdv[ishdef].pctSh = pctNew;
                }
            }
        }
    }

    /* ------------------------------------------------------------ */
    /* asm: 1050:bd05..c1a7  (compute cargo/fuel deltas per side)     */
    /* ------------------------------------------------------------ */

    i = 0;
    while (1) {
        if (i > 1) {
            /* ------------------------------------------------------------ */
            /* asm: 1050:c1??.. (apply deltas: + to i, - to other)           */
            /* ------------------------------------------------------------ */
            for (i = 0; i < 2; i++) {
                for (j = 0; j < 5; j++) {
                    rgpflNew[i]->rgwtMin[j] += rgrgCargoDelta[i][j];
                    rgpflNew[i ^ 1]->rgwtMin[j] -= rgrgCargoDelta[i][j];
                }
            }
            return;
        }

        /* ------------------------------------------------------------ */
        /* asm: 1050:bd0e..be2c  (fuel delta = fuel * fuelCapLoss / fuelCap) */
        /* overflow-avoid with FPU path when values exceed 45000-ish         */
        /* ------------------------------------------------------------ */
        if (rgFuelCapacity[i] != 0) {
            int32_t fuel = rgpflNew[i]->rgwtMin[4];

            if (fuel < 45001 && rgFuelCapLoss[i] >= 0 && rgFuelCapLoss[i] <= 45000) {
                l = (int32_t)(((int64_t)fuel * rgFuelCapLoss[i]) / rgFuelCapacity[i]);
            } else {
                /* asm: 1050:bd86..bdbd (FILD fuel; FILD loss; FMUL; FILD cap; FDIV; __ftol) */
                l = (int32_t)((double)fuel * (double)rgFuelCapLoss[i] / (double)rgFuelCapacity[i]);
            }

            lChg = l;
            rgrgCargoDelta[i][4] -= lChg;
        }

        /* ------------------------------------------------------------ */
        /* asm: 1050:be2c..c1a2  (cargo delta spread across 4 bins)       */
        /* ------------------------------------------------------------ */
        if (rgCargoCapacity[i] != 0) {
            wtCargoTot = 0;
            for (j = 0; j < 4; j++) {
                wtCargoTot += rgpflNew[i]->rgwtMin[j];
            }

            if (wtCargoTot != 0) {
                if (wtCargoTot < 45001 && rgCargoCapLoss[i] >= 0 && rgCargoCapLoss[i] <= 45000) {
                    wtCargoXfer = (int32_t)(((int64_t)wtCargoTot * rgCargoCapLoss[i]) / rgCargoCapacity[i]);
                } else {
                    /* asm: 1050:bed1..bf06 (FILD wtCargoTot; FILD loss; FMUL; FILD cap; FDIV; __ftol) */
                    wtCargoXfer = (int32_t)((double)wtCargoTot * (double)rgCargoCapLoss[i] / (double)rgCargoCapacity[i]);
                }

                if (wtCargoXfer != 0) {
                    int32_t wtLeft = wtCargoXfer;

                    /* proportional subtract across 4 cargo bins */
                    for (j = 0; j < 4; j++) {
                        int32_t part;

                        if (rgpflNew[i]->rgwtMin[j] < 45001 && wtCargoTot < 45001 && wtLeft < 45001) {
                            part = (int32_t)(((int64_t)rgpflNew[i]->rgwtMin[j] * wtCargoXfer) / wtCargoTot);
                        } else {
                            /* asm: (FILD item; FILD wtCargoXfer; FMUL; FILD tot; FDIV; __ftol) */
                            part = (int32_t)((double)rgpflNew[i]->rgwtMin[j] * (double)wtCargoXfer / (double)wtCargoTot);
                        }

                        /* clamp to remaining */
                        if (part > wtLeft)
                            part = wtLeft;

                        rgrgCargoDelta[i][j] -= part;
                        wtLeft -= part;
                    }

                    /* ------------------------------------------------------------ */
                    /* asm: 1050:c0??  (distribute any remainder by -1 steps)       */
                    /* ------------------------------------------------------------ */
                    if (wtLeft > 0) {
                        j = 0;
                        while (j < 4 && wtLeft > 0) {
                            /* asm condition: if (rgwtMin[j] + delta[j] > 0) then delta-- and wtLeft-- */
                            if (rgpflNew[i]->rgwtMin[j] + rgrgCargoDelta[i][j] > 0) {
                                rgrgCargoDelta[i][j] -= 1;
                                wtLeft -= 1;
                            }
                            j++;
                        }
                    }
                }
            }
        }

        i++;
    }
}

void SelectAdjFleet(int16_t dInc, int16_t idFleet) {
    POINT   pt;
    int16_t idOld;
    int16_t i;
    FLEET  *lpfl;
    int16_t idNew;
    FLEET  *lpflT;
    SCAN    scan;

    /* debug symbols */
    /* label FinishUp @ MEMORY_SHIP:0x3fa9 */

    /* TODO: implement */
}

int16_t IFindIdealWarp(FLEET *lpfl, int16_t fIgnoreScoops) {
    int16_t  i;
    int16_t  j;
    int16_t  iWorst;
    ENGINE  *lpengine;
    uint16_t id;
    SHDEF   *lpshdef;

    iWorst = 10;
    if (lpfl == NULL) {
        lpfl = &sel.fl;
    }
    for (i = 0; i <= 0xf; i++) {
        if (lpfl->rgcsh[i] > 0) {
            lpshdef = &rglpshdef[lpfl->iPlayer][i];
            for (j = 0; j < (int16_t)lpshdef->hul.chs && lpshdef->hul.rghs[j].grhst != hstEngine; j++)
                ;
            if (j == (int16_t)lpshdef->hul.chs) {
                return 0;
            }
            id = lpshdef->hul.rghs[j].iItem;
            lpengine = LpengineFromId(id);
            for (; iWorst > 0; iWorst--) {
                if (lpengine->rgcFuelUsed[iWorst] < 121) {
                    if (lpengine->rgcFuelUsed[iWorst] > 0 && fIgnoreScoops == 0 && id != iengineTransGalacticMizerScoop && id != iengineGalaxyScoop) {
                        if (iWorst >= 5 && lpengine->rgcFuelUsed[iWorst - 1] == 0) {
                            iWorst--;
                        } else if (iWorst >= 6 && lpengine->rgcFuelUsed[iWorst - 2] == 0) {
                            iWorst -= 2;
                        } else if (iWorst > 6 && lpengine->rgcFuelUsed[iWorst - 3] == 0) {
                            iWorst -= 3;
                        }
                    }
                    if (iWorst == 10 && id != iengineInterspace10 && id != iengineEnigmaPulsar && id != iengineTransStar10 &&
                        id != iengineTransGalacticMizerScoop && id != iengineGalaxyScoop) {
                        iWorst = 9;
                    }
                    break;
                }
            }
        }
    }
    return iWorst;
}

void DeleteWpFar(FLEET *lpfl, int16_t iDel, int16_t fRecycle) {
    ORDER ord;

    // TODO: re-check this decompile
    if (fRecycle) {
        if (iDel != 0x56 && lpfl->cord != 2) {
            ORDER *pordDel = &lpfl->lpplord->rgord[iDel];
            ORDER *pordLast = &lpfl->lpplord->rgord[lpfl->cord - 1];
            if (pordLast->pt.x != pordDel->pt.x || pordLast->pt.y != pordDel->pt.y) {
                ord = *pordDel;
                goto do_memmove;
            }
        }
        fRecycle = 0;
    }

do_memmove:
    memmove(&lpfl->lpplord->rgord[iDel], &lpfl->lpplord->rgord[iDel + 1], (lpfl->cord - iDel - 1) * sizeof(ORDER));

    if (!fRecycle) {
        lpfl->cord--;
        lpfl->lpplord->iordMac--;
    } else {
        lpfl->lpplord->rgord[lpfl->cord - 1] = ord;
    }
}

int32_t ChgCargo(GrobjClass grobj, int16_t id, int16_t iSupply, int32_t dChg, void *pobj) {
    uint32_t *pLo;
    uint32_t  loOld;
    int32_t   hiSum;
    uint32_t  capTimes10;
    int32_t   wtFree;
    PLANET   *ppl;
    FLEET    *pfl;
    int16_t   i;
    XFER      xfer;
    THING    *pth;

    if ((grobj == grobjPlanet) || (grobj == grobjOther)) {
        if (pobj == NULL) {
            if (grobj == grobjPlanet) {
                FLookupPlanet(id, &xfer.pl);
                ppl = &xfer.pl;
            } else {
                memset(&xfer.pl, 0, sizeof(PLANET));
                ppl = &xfer.pl;
            }
        } else {
            ppl = pobj;
        }

        if (iSupply < 5) {
            if (iSupply == 4) {
                dChg = 0;
                goto Done;
            }

            if (dChg == 0) {
                dChg = ppl->rgwtMin[iSupply];
                goto Done;
            }

            /* replicate: high(min)+high(dChg)+carry(low) */
            {
                uint32_t minLo = (uint32_t)ppl->rgwtMin[iSupply];
                uint32_t chgLo = (uint32_t)dChg;
                uint32_t carry = (minLo + chgLo) < minLo;
                hiSum = (int32_t)(minLo >> 16) + (int32_t)(chgLo >> 16) + (int32_t)carry;
            }

            if ((hiSum < 1) && (hiSum < 0)) {
                dChg = -ppl->rgwtMin[iSupply];
            }

            pLo = (uint32_t *)&ppl->rgwtMin[iSupply];
            loOld = *pLo;
            *pLo = loOld + (uint32_t)dChg;
            ((uint32_t *)&ppl->rgwtMin[iSupply])[1] = ((uint32_t *)&ppl->rgwtMin[iSupply])[1] + ((uint32_t)dChg >> 16) + (uint32_t)((*pLo) < loOld);
        }

        if ((dChg != 0) && (pobj == NULL) && (grobj != grobjOther)) {
            FLookupPlanet(-1, &xfer.pl);
        }
    } else if (grobj == grobjThing) {
        if (pobj == NULL) {
            FLookupThing(id, &xfer.th);
            pth = &xfer.th;
        } else {
            pth = pobj;
        }

        /* Packets only: 3 cargo slots (0..2). */
        if (2 < iSupply) {
            dChg = 0;
            goto Done;
        }

        if (iSupply < 5) {
            int16_t *pwt = &pth->thp.rgwtMin[iSupply];

            if (dChg == 0) {
                /* decompile sign-extends the 16-bit slot into a 32-bit long */
                dChg = (int32_t)*pwt;
                goto Done;
            }

            /* compute "high word" after add: sign(cur16) + high(dChg) + carry(low16) */
            {
                uint16_t curLo = (uint16_t)*pwt;
                uint16_t chgLo = (uint16_t)dChg;
                uint32_t carry = (uint16_t)(curLo + chgLo) < curLo;

                hiSum = ((int32_t)*pwt >> 15) + (int32_t)((uint32_t)dChg >> 16) + (int32_t)carry;
            }

            if ((hiSum < 1) && (hiSum < 0)) {
                /* clamp so we don't go negative: dChg = -current */
                dChg = -(int32_t)*pwt;
            }

            /* uVar4 = ( (thp.wRaw_0008 & 0x3fff) * 10 ) == (wtMax * 10) */
            capTimes10 = (uint32_t)(pth->thp.wtMax) * 10U;

            i = 0;
            while (true) {
                wtFree = (int32_t)capTimes10;
                if (2 < i)
                    break;

                capTimes10 = capTimes10 - (uint32_t)(int32_t)pth->thp.rgwtMin[i];
                i++;
            }

            /* if (wtFree <= dChg) then clamp dChg to remaining free (uVar4/capTimes10) */
            if ((wtFree <= dChg) && ((wtFree < dChg) || ((uint32_t)wtFree < (uint32_t)dChg))) {
                dChg = (int32_t)capTimes10;
            }

            *pwt = (int16_t)((int32_t)*pwt + (int16_t)dChg);
        }

        if ((dChg != 0) && (pobj == NULL)) {
            FLookupThing(-1, pth);
        }
    } else {
        if (pobj == NULL) {
            FLookupFleet(id, &xfer.fl);
            pfl = &xfer.fl;
        } else {
            pfl = pobj;
        }

        if (iSupply < 5) {
            if (dChg == 0) {
                dChg = pfl->rgwtMin[iSupply];
                goto Done;
            }

            {
                uint32_t minLo = (uint32_t)pfl->rgwtMin[iSupply];
                uint32_t chgLo = (uint32_t)dChg;
                uint32_t carry = (minLo + chgLo) < minLo;
                hiSum = (int32_t)(minLo >> 16) + (int32_t)(chgLo >> 16) + (int32_t)carry;
            }

            if ((hiSum < 1) && (hiSum < 0)) {
                dChg = -pfl->rgwtMin[iSupply];
            }

            /* bitfield: det (types.h) */
            if ((iSupply == 3) && (pfl->det != 7)) {
                dChg = 0;
            }

            /* clamp to free space (original flow) */
            {
                int32_t freeSpace = (iSupply == 4) ? GetFuelFree(pfl) : GetCargoFree(pfl);
                int32_t freeHi = (int32_t)((uint32_t)freeSpace >> 16);

                if ((freeHi < (int32_t)((uint32_t)dChg >> 16)) || ((freeHi == (int32_t)((uint32_t)dChg >> 16)) && ((uint32_t)freeSpace <= (uint32_t)dChg))) {
                    dChg = freeSpace;
                }
            }

            pLo = (uint32_t *)&pfl->rgwtMin[iSupply];
            loOld = *pLo;
            *pLo = loOld + (uint32_t)dChg;
            ((uint32_t *)&pfl->rgwtMin[iSupply])[1] = ((uint32_t *)&pfl->rgwtMin[iSupply])[1] + ((uint32_t)dChg >> 16) + (uint32_t)((*pLo) < loOld);
        }

        if ((dChg != 0) && (pobj == NULL)) {
            FLookupFleet(-1, pfl);
        }
    }

Done:
    return dChg;
}

int16_t FCanSplit(int32_t cBoat) {
    /* If player already has max fleets (0x200 = 512), can't split */
    if (rgplr[idPlayer].cFleet == cFleetAbsMax) {
        return 0;
    }
    /* Need at least 2 boats to split */
    if (cBoat < 2) {
        return 0;
    }
    return 1;
}

int16_t FCanMerge(FLEET *pfl) {
    int16_t i;
    FLEET  *lpfl;
    int32_t csh;
    int16_t cfl;
    int16_t ishdef;

    cfl = 0;
    csh = 0;
    FORFLEETS(lpfl, i) {
        if (lpfl->iPlayer == pfl->iPlayer && lpfl->pt.x == sel.fl.pt.x && lpfl->pt.y == sel.fl.pt.y) {
            cfl++;
            for (ishdef = 0; ishdef < cShdefMax; ishdef++) {
                csh += lpfl->rgcsh[ishdef];
            }
        }
    }
    if (cfl == 1 || csh > 0x7ffe - ((int16_t)rgplr[pfl->iPlayer].cFleet - 1))
        return 0;
    return 1;
}

void DestroyAllIshdef(int16_t ishdef, int16_t iplr) {
    FLEET   flDead;
    int16_t cKill;
    FLEET  *lpfl;
    int16_t i;
    int16_t grbit;
    int16_t j;
    int16_t cDel;
    FLEET   flNew;

    /* debug symbols */
    /* label IncrementI @ MEMORY_SHIP:0xc5b8 */

    /* TODO: implement */
}

int16_t WtMaxShdefStat(const SHDEF *lpshdef, GrStat grStat) {
    int16_t wt;
    int16_t j;
    HUL    *lphul;

    if (lpshdef == NULL) {
        return 0;
    }

    /* Base stats come from the hull definition. */
    {
        HULDEF *lphuldef = LphuldefFromId(lpshdef->hul.ihuldef);
        if (lphuldef == NULL) {
            return 0;
        }
        lphul = &lphuldef->hul;
    }

    if (grStat == grStatFuel) {
        /* Fuel capacity. */
        wt = lphul->wtFuelMax;

        /* Add-ons from certain hull slots. */
        for (j = 0; j < (int16_t)lpshdef->hul.chs; j++) {
            const HS *hs = &lpshdef->hul.rghs[j];
            if (hs->grhst == hstSpecialM) {
                if (hs->iItem == ispecialMFuelTank) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 250);
                } else if (hs->iItem == ispecialMSuperFuelTank) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 500);
                }
            } else if (hs->grhst == hstSpecialE) {
                if (hs->iItem == ispecialEAntiMatterGenerator) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 200);
                }
            }
        }
        return wt;
    }

    if (grStat == grStatCargo) {
        /* Cargo capacity. */
        wt = lphul->wtCargoMax;

        for (j = 0; j < (int16_t)lpshdef->hul.chs; j++) {
            const HS *hs = &lpshdef->hul.rghs[j];
            if (hs->grhst == hstSpecialM) {
                if (hs->iItem == ispecialMCargoPod) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 50);
                } else if (hs->iItem == ispecialMSuperCargoPod) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 100);
                } else if (hs->iItem == ispecialMMultiCargoPod) {
                    wt = (int16_t)(wt + (int16_t)hs->cItem * 250);
                }
            }
        }
        return wt;
    }

    return 0;
}

int16_t FEnumCalcJettison(void *lprt, RecordType rt, int16_t cb, PLANET *lppl, int16_t iFleet) {
    int16_t  i;
    int16_t  grbit;
    FLEET    fl;
    int16_t  j;
    RTXFER  *prtxfer;
    RTXFERX *prtxferx;

    if (rt == rtLogCargoXfer8 || rt == rtLogCargoXfer16) {
        prtxfer = (RTXFER *)lprt;
        if ((prtxfer->grobj1 == grobjFleet) && (prtxfer->grobj2 == grobjOther)) {
            int16_t ptx, pty;
            if (!FLookupFleet(iFleet, &fl))
                return 1;
            ptx = fl.pt.x;
            pty = fl.pt.y;
            if (!FLookupFleet(prtxfer->id1, &fl))
                return 1;
            if (fl.pt.x != ptx || fl.pt.y != pty)
                return 1;

            grbit = (int16_t)prtxfer->grbitItems;
            prtxferx = (RTXFERX *)lprt;
            j = 0;
            for (i = 0; i < 5; i++) {
                if (grbit & 1) {
                    int32_t qty;
                    if (rt == rtLogCargoXfer8) {
                        qty = (int32_t)prtxfer->rgcQuan[j];
                    } else {
                        qty = (int32_t)prtxferx->rgcQuan[j];
                    }
                    lppl->rgwtMin[i] -= qty;
                    j++;
                }
                grbit >>= 1;
            }
        }
    }
    return 1;
}

void DestroyAllIshdefSB(int16_t ishdefSB, int16_t iplr) {
    PLANET *lppl;
    PLANET *lpplMac;

    FORPLANETS(lppl, lpplMac) {
        if (lppl->iPlayer == iplr && lppl->fStarbase && lppl->isb == ishdefSB) {
            lppl->fStarbase = 0;
            KillQueuedShips(lppl);
            KillQueuedMassPackets(lppl);
        }
    }
}

void GetTruePartCost(int16_t iPlayer, PART *ppart, uint16_t rgCosts[static 4]) {
    const COMPART *lpcom = ppart->pcom;

    // 1) Base costs
    rgCosts[Ironium] = lpcom->rgwtOreCost[Ironium];
    rgCosts[Boranium] = lpcom->rgwtOreCost[Boranium];
    rgCosts[Germanium] = lpcom->rgwtOreCost[Germanium];
    rgCosts[Resources] = lpcom->resCost;

    if (iPlayer == -1) {
        // No player context → raw costs only
        return;
    }

    PLAYER *plr = &rgplr[iPlayer];

    /* 2) Tech-based discount */
    HullSlotType grhst = ppart->hs.grhst;
    uint8_t      iItem = ppart->hs.iItem;

    bool allowTechDiscount =
        ((grhst & hstTerra) == hstNone) && (((grhst & hstPlanetary) == hstNone) || (iItem >= iplanetarySDI && iItem <= iplanetaryNeutronShield));

    int16_t cExcess = 0; /* mirrors decompile’s later use (cExcess < 1) */

    if (allowTechDiscount) {
        cExcess = 100;

        /* Find smallest gap (have - req) among req > 0 */
        for (int t = 0; t < 6; t++) {
            int req = (int8_t)lpcom->rgTech[t];
            int have = (int8_t)plr->rgTech[t];
            int gap = have - req;

            if (req > 0 && gap < cExcess) {
                cExcess = (int16_t)gap;
            }
        }

        /* If no req > 0, use min(have) */
        if (cExcess == 100) {
            for (int t = 0; t < 6; t++) {
                int have = (int8_t)plr->rgTech[t];
                if (have < cExcess)
                    cExcess = (int16_t)have;
            }
        }

        if (cExcess > 0) {
            if (cExcess > 0x13)
                cExcess = 0x13;

            if (GetRaceGrbit(plr, ibitRaceBleedingEdgeTech) == 0) {
                cExcess = (int16_t)(cExcess << 2);
                if (cExcess > 0x4b)
                    cExcess = 0x4b;
            } else {
                cExcess = (int16_t)(cExcess * 5);
                if (cExcess > 0x50)
                    cExcess = 0x50;
            }

            for (int k = 0; k < 4; k++) {
                if (rgCosts[k] != 0) {
                    /* Decompile uses MulDiv for rounding */
                    int16_t cut = (int16_t)MulDiv((int32_t)rgCosts[k], (int32_t)cExcess, 100);
                    rgCosts[k] = (uint16_t)(rgCosts[k] - (uint16_t)cut);
                    if (rgCosts[k] == 0)
                        rgCosts[k] = 1;
                }
            }
        }
    }

    /* 4) Bleeding Edge Tech surcharge (matches decompile gating) */
    if (cExcess < 1 && GetRaceGrbit(plr, ibitRaceBleedingEdgeTech) != 0 && !gd.fDontCalcBleed) {

        int t;
        for (t = 0; t < 6 && (int8_t)lpcom->rgTech[t] < 1; t++) {
        }

        if (t < 6) {
            gd.fBleedingEdge = 1;
            for (int k = 0; k < 4; k++) {
                rgCosts[k] <<= 1;
            }
        } else {
            gd.fBleedingEdge = 0;
        }
    } else {
        gd.fBleedingEdge = 0;
    }
}

void RemoveIshdefFromAllQueues(int16_t ishdef, int16_t fSpaceDocks) {
    int16_t iprod;
    PLANET *lppl;
    int16_t iDst;
    PLANET *lpplMac;
    PROD   *lpprod;

    FORPLANETS(lppl, lpplMac) {
        if (lppl->lpplprod != NULL && lppl->lpplprod->iprodMac != 0 && lppl->iPlayer == idPlayer && lppl->fStarbase &&
            (!fSpaceDocks || rglpshdefSB[idPlayer][lppl->isb].hul.ihuldef == (ihuldefSBSpaceDock + ihuldefCount))) {

            iDst = 0;
            FORPROD(lppl->lpplprod, lpprod, iprod) {
                if (lpprod->grobj != grobjFleet || lpprod->iItem != ishdef) {
                    if (iDst != iprod) {
                        lppl->lpplprod->rgprod[iDst].dwRaw_0000 = lpprod->dwRaw_0000;
                    }
                    iDst++;
                }
            }

            if (iDst == 0) {
                FreePl((PL *)lppl->lpplprod);
                lppl->lpplprod = NULL;
            } else if (iDst != iprod) {
                lppl->lpplprod->iprodMac = (uint8_t)iDst;
            }
        }
    }

    if (sel.grobj == grobjPlanet && sel.pl.lpplprod != NULL) {
        FLookupPlanet(sel.pl.id, &sel.pl);
#ifdef _WIN32
        FillPlanetProdLB(hwndPlanetProdLB, sel.pl.lpplprod, NULL);
#endif
    }
}

int32_t LFuelUseToWaypoint(FLEET *lpfl, int16_t iwp, int16_t fMaxCargo) {
    int32_t lCur;
    int16_t iWarp;
    int16_t dist;
    PLANET *lppl;
    int16_t i;
    int32_t lTot;
    ORDER  *lpord;
    int16_t cYears;
    SHDEF  *lpshdef;
    int16_t j;
    double  dbl;
    int32_t l;
    int32_t lOneYearUse;
    int32_t lFuelGain;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0xab6d */

    (void)fMaxCargo; /* not used by the original logic in this build */

    if (lpfl == NULL || lpfl->lpplord == NULL) {
        return 0;
    }

    lTot = 0; /* max running total */
    lCur = 0; /* current running total */

    /*
     * Sum fuel required leg-by-leg up to (but not including) waypoint iwp,
     * tracking the maximum running total (worst case) and resetting at friendly
     * starbases that can refuel.
     */
    for (i = 0; i < iwp; i++) {
        int32_t legUse = 0;
        int32_t minUse = 0;

        /* Warp is stored on the destination waypoint. */
        lpord = &lpfl->lpplord->rgord[i];
        iWarp = (int16_t)lpord[1].iWarp;

        if (iWarp <= 0 || iWarp > 10) {
            cYears = 1;
            dist = 0;
            legUse = 0;
        } else {
            /* Distance between waypoints (integer). */
            dbl = DGetDistance(lpord[0].pt.x, lpord[0].pt.y, lpord[1].pt.x, lpord[1].pt.y);
            dist = (int16_t)dbl;

            /* Years required at this warp: ceil(dist / (warp*warp)). */
            {
                int32_t w2 = (int32_t)iWarp * (int32_t)iWarp;
                if (w2 <= 0) {
                    cYears = 1;
                } else {
                    cYears = (int16_t)((dist + w2 - 1) / w2);
                    if (cYears < 1) {
                        cYears = 1;
                    }
                }
            }

            /* Fuel for a one-year (single-step) move. */
            minUse = EstFuelUse(lpfl, i, iWarp, -1, 0);
            legUse = minUse;
        }

        if (cYears > 1) {
            /* Fuel for a full year's travel at this warp (distance = warp^2). */
            int32_t w2 = (int32_t)iWarp * (int32_t)iWarp;
            lOneYearUse = EstFuelUse(lpfl, i, iWarp, w2, 0);

            /* Total for (cYears-1) full years plus remainder distance. */
            {
                int32_t fullYears = (int32_t)(cYears - 1);
                int32_t rem = (int32_t)dist - w2 * fullYears;
                if (rem < 0) {
                    rem = 0;
                }
                legUse = (int32_t)((int64_t)lOneYearUse * (int64_t)fullYears);
                legUse += EstFuelUse(lpfl, i, iWarp, rem, 0);
            }

            /* Ensure we never estimate less than the basic one-year use. */
            if (legUse < minUse) {
                legUse = minUse;
            }

            /* Potential fuel gain from ram scoops (and certain tanker hulls). */
            lFuelGain = LCalcFuelGainFromRamScoops(lpfl, iWarp, w2);
            for (j = 0; j < 16; j++) {
                int16_t csh = lpfl->rgcsh[j];
                if (csh <= 0) {
                    continue;
                }
                lpshdef = (SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)j * 0x93);
                if (lpshdef->hul.ihuldef == 0x19 || lpshdef->hul.ihuldef == 0x1a) {
                    /* Tankers add a fixed "gain" per ship (200 in original). */
                    lFuelGain += (int32_t)csh * 200;
                }
            }

            /* If gains reduce per-year usage, apply to the full-years portion. */
            if (lFuelGain > 0 && lFuelGain < lOneYearUse) {
                int32_t fullYears = (int32_t)(cYears - 1);
                int32_t reducedYear = lOneYearUse - lFuelGain;
                int32_t alt = (int32_t)((int64_t)reducedYear * (int64_t)fullYears) + lOneYearUse;
                if (alt < legUse) {
                    legUse = alt;
                }
            }
        }

        lCur += legUse;
        if (lCur > lTot) {
            lTot = lCur;
        }

        /* Refuel reset at friendly starbases (grobj == 1 for planet). */
        if ((int16_t)lpord[1].grobj == 1) {
            lppl = LpplFromId(lpord[1].id);
            if (lppl != NULL && lppl->iPlayer == lpfl->iPlayer && lppl->fStarbase) {
                /* Check the starbase design hull for "has capacity". */
                SHDEF  *sb = rglpshdefSB[lpfl->iPlayer];
                int16_t isb = (int16_t)lppl->isb;
                if (sb != NULL && isb >= 0) {
                    SHDEF  *sbdef = (SHDEF *)((uint8_t *)sb + (int32_t)isb * 0x93);
                    HULDEF *huldef = LphuldefFromId(sbdef->hul.ihuldef);
                    if (huldef != NULL && huldef->hul.wtCargoMax != 0) {
                        lCur = 0;
                    }
                }
            }
        }
    }

    return lTot;
}

void FleetOrdersChangeTarget(FLEET *lpflOld) {
    int16_t    id;
    STARSPOINT pt;
    FLEET     *lpfl;
    int16_t    iord;
    int16_t    iflMac;
    SCAN       scan;
    int16_t    grobj;

    for (iflMac = 0; iflMac < cFleet; iflMac++) {
        lpfl = rglpfl[iflMac];
        if (lpfl == NULL)
            return;
        if (lpfl->lpplord != NULL) {
            for (iord = lpfl->cord - 1; iord >= 0; iord--) {
                ORDER *pord = &lpfl->lpplord->rgord[iord];
                if (pord->grobj == grobjFleet && pord->id == lpflOld->id) {
                    pt.x = lpflOld->pt.x;
                    pt.y = lpflOld->pt.y;
                    lpflOld->pt.x++;
                    if (!FFindNearestObject(pt, 0x83, &scan)) {
                        grobj = 4;
                        id = iord;
                    } else if ((scan.grobjFull & grobjFleet) == grobjNone) {
                        grobj = grobjPlanet;
                        id = scan.idpl;
                    } else {
                        grobj = grobjFleet;
                        id = rglpfl[scan.ifl]->id;
                    }
                    lpflOld->pt.x--;
                    pord->id = id;
                    pord->grobj = grobj;
                }
            }
        }
    }
}

#ifdef _WIN32

INT_PTR CALLBACK TransferDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    int16_t     dyMore;
    PAINTSTRUCT ps;
    POINT       pt;
    HWND        hwndBtn;
    RECT        rcBtn;
    int16_t     dx;
    RECT        rc;

    /* TODO: implement */
    return 0;
}

LRESULT CALLBACK FakeEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if ((msg == WM_CHAR) && (((wParam < (WPARAM)'0') || ((WPARAM)'9' < wParam)) && (wParam != (WPARAM)8))) {
        return 0;
    }

    /* In the original, this called the previously-subclassed edit proc. */
    return CallWindowProc(lpfnRealEditProc, hwnd, msg, wParam, lParam);
}

void ShipCommandProc(HWND hwnd, WPARAM wParam, LPARAM lParam) {
    int16_t fPercent;
    int16_t (*lpProc)(void);
    int32_t lSel;
    XFER    xf;
    char    szT[34];
    int32_t lMin;
    int16_t ishdef;
    int16_t grbit;
    int16_t ifl;
    int16_t ish;
    FLEET  *lpfl;
    char    rgb[8];
    int16_t ishPrimary;
    int16_t i;
    int16_t iInit;
    FLEET  *lpflBest;
    int16_t rgifl[512];

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x2a13 */
    /* block (block) @ MEMORY_SHIP:0x2e7c */
    /* block (block) @ MEMORY_SHIP:0x2f05 */
    /* block (block) @ MEMORY_SHIP:0x3505 */
    /* block (block) @ MEMORY_SHIP:0x3b00 */

    /* TODO: implement */
}

void DrawXferDlg(HWND hwnd, HDC hdc, RECT *prc, int16_t iSupply) {
    RECT    rgrc[2];
    int16_t fCreatedDC;
    int16_t i;
    int16_t dxCtr;

    /* debug symbols */
    /* label RelDC @ MEMORY_SHIP:0x6b2b */

    /* TODO: implement */
}

void DrawFleetShipsXferSide(HDC hdc, RECT *prc, FLEET *pfl, int16_t iSupply) {
    int16_t yTop;
    int16_t fOtherPlr;
    int16_t c;
    int16_t i;
    int16_t xRight;
    FLEET   fl;
    int16_t xLeft;
    RECT    rc;

    /* TODO: implement */
}

void DrawShipPlanet(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t yTop;
    int16_t dy;
    int16_t i;
    int16_t xRight;
    char   *psz;
    int16_t dx;
    int16_t xLeft;
    RECT    rc;
    THING  *lpth;
    THING  *lpthMac;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x1923 */

    /* TODO: implement */
}

void DrawFleetComp(HDC hdc, TILE *ptile, OBJ obj) {
    int32_t cBoat;
    int16_t swp;
    int16_t dxRight;
    int16_t yTop;
    RECT    rcT;
    int16_t dyWrong;
    int16_t c;
    int16_t i;
    FLEET  *pfl;
    int16_t xStart;
    int16_t xRight;
    int16_t dxLabel;
    int16_t xLeft;
    int32_t l;
    RECT    rc;

    /* TODO: implement */
}

void UpdateOrdersDDs(int16_t iLevel) {
    int32_t rglSel[3];
    int16_t iMin;
    int16_t i;
    char   *psz;
    int16_t iSel;
    int16_t iMax;
    char    szT[80];

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x9496 */
    /* block (block) @ MEMORY_SHIP:0x969e */
    /* label DoMinerals @ MEMORY_SHIP:0x946b */

    /* TODO: implement */
}

void SetFleetDropDownSel(int16_t id) {
    int16_t idSkip;
    int16_t i;
    FLEET  *lpfl;
    int16_t iOffset;

    /* TODO: implement */
}
void FillBattleDD(int16_t iSel) {
    int16_t i;

    /* TODO: implement */
}

void SetOrdersLbSel(int16_t iSel) { /* TODO: implement */ }

void FillFleetCompLB(void) {
    int16_t i;
    int32_t pctDmg;

    /* TODO: implement */
}

uint16_t ClickInShipOrders(POINT pt, int16_t sks, int16_t fCursor, int16_t fRightBtn) {
    int32_t    lCur;
    HDC        hdc;
    PLANET     pl;
    int16_t    iWarp;
    POINT      ptOld;
    int16_t    idPlan;
    int32_t    lMax;
    int32_t    lSel;
    int16_t    iSkip;
    int32_t    xRnd;
    int16_t    grbit;
    XFER       xf;
    int32_t    lNew;
    int16_t    irc;
    int32_t    dx;
    int32_t    lTempMin;
    int16_t    fFirst;
    int16_t    fTwoMAs;
    int32_t    lTempMax;
    int16_t    cMax;
    int16_t    fSep;
    char       sz255[2];
    int16_t    i;
    THING     *lpth;
    int16_t    c;
    THING     *lpthMac;
    ORDER     *lpord;
    FLEET     *lpfl;
    char      *rgszZip[1];
    TASKXPORT *lptxp;
    ZIPORDER   rgzo[4];
    int16_t (*lpProc)(void);
    int16_t fRet;
    int32_t rgid[100];
    int16_t iChecked;
    SCAN    scan;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x7d37 */
    /* block (block) @ MEMORY_SHIP:0x7e50 */
    /* block (block) @ MEMORY_SHIP:0x7f96 */
    /* block (block) @ MEMORY_SHIP:0x826c */
    /* block (block) @ MEMORY_SHIP:0x894f */
    /* block (block) @ MEMORY_SHIP:0x8a3b */
    /* label LWriteZip @ MEMORY_SHIP:0x81f0 */
    /* label FixMinWin @ MEMORY_SHIP:0x9006 */

    /* TODO: implement */
    return 0;
}

void UpdateXferBtns(void) {
    int16_t iSide;
    int16_t i;
    int16_t iLastButton;
    int16_t iVal;
    int32_t lLeft;

    /* TODO: implement */
}

int16_t FSetupXferBtns(RECT *prc) {
    int16_t cBtn;
    int16_t iMax;
    int16_t dy;
    int16_t iMin;
    int16_t i;
    int16_t fThingXfer;
    int16_t j;
    int16_t dxCtr;
    RECT    rcRight;
    int16_t dxLabels;
    RECT    rcBtn;
    RECT    rcLeft;
    RECT    rc;

    /* debug symbols */
    /* label NoGauges @ MEMORY_SHIP:0x7070 */

    /* TODO: implement */
    return 0;
}

void DrawFleetBitmap(FLEET *lpfl, HDC hdc, int16_t x, int16_t y, int16_t fFrame, int16_t ibmp, int16_t cDiff, int16_t fShrink, int16_t ibmpRace, int16_t csh) {
    int16_t dxyPlus;
    int16_t yCur;
    int16_t c;
    int16_t i;
    int16_t dxy;
    int16_t dx;
    int16_t xCur;
    int16_t dxyPlusWidth;
    HBRUSH  hbrSav;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x4920 */

    /* TODO: implement */
}

void DrawShipOrders(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t swp;
    int16_t dxRight;
    int16_t iWarp;
    int16_t yTop;
    POINT   pt;
    RECT    rcT;
    int16_t dWrong;
    int32_t lTot;
    int16_t c;
    FLEET  *pfl;
    int16_t xRight;
    int16_t iScanActual;
    RECT    rcGauge;
    char   *psz;
    int16_t xLeft;
    ORDER   ord;
    int32_t l;
    RECT    rc;

    /* debug symbols */
    /* label DoDistance @ MEMORY_SHIP:0x04aa */
    /* label DoCheckBox @ MEMORY_SHIP:0x0884 */

    /* TODO: implement */
}

void DrawFleetGauge(HDC hdc, RECT *prc, FLEET *lpfl, int16_t grbit) {
    uint16_t rghbr[5];
    int32_t  lMax;
    int16_t  c;
    int16_t  i;
    int32_t  rgSize[5];
    int16_t  iMode;
    int16_t  cSections;
    int32_t  l;

    /* TODO: implement */
}

void DrawFleetCargoXferSide(HDC hdc, RECT *prc, FLEET *pfl, int16_t iSupply) {
    int16_t yTop;
    int16_t fOtherPlr;
    int16_t c;
    int16_t i;
    int16_t xRight;
    FLEET   fl;
    int16_t dxLabels;
    RECT    rcGauge;
    int16_t xLeft;
    RECT    rc;
    int16_t iMap;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x74a2 */

    /* TODO: implement */
}

void DrawThingXferSide(HDC hdc, RECT *prc, THING *pth, int16_t iSupply) {
    int16_t yTop;
    int16_t i;
    int16_t xRight;
    int16_t dxLabels;
    RECT    rcGauge;
    int16_t xLeft;
    RECT    rc;

    /* TODO: implement */
}

void DrawShipWayPtOrders(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t  dxKt;
    int16_t  dxT;
    int16_t  swp;
    int16_t  dxRight;
    int16_t  yTop;
    int16_t  yTopMsg;
    int16_t  ids;
    int16_t  edWid;
    PLANET  *lppl;
    ORDER   *lpord;
    FLEET   *pfl;
    int16_t  i;
    int16_t  fActive;
    int16_t  xRight;
    uint16_t grtask;
    char     szT[8];
    int16_t  yBot;
    int16_t  dxRight2;
    char    *psz;
    int16_t  cch;
    int16_t  xLeft;
    int32_t  l;
    RECT     rc;
    char    *pszT;
    int16_t  j;
    int32_t  cMine;
    RECT     rcT;
    int16_t  dyCur;
    int16_t  c;
    int32_t  rgl[4];

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP:0x0d93 */
    /* block (block) @ MEMORY_SHIP:0x0dfa */
    /* block (block) @ MEMORY_SHIP:0x1324 */
    /* block (block) @ MEMORY_SHIP:0x1363 */
    /* block (block) @ MEMORY_SHIP:0x153c */
    /* block (block) @ MEMORY_SHIP:0x15b7 */
    /* label LDisplayMsg2 @ MEMORY_SHIP:0x14af */
    /* label FoundColony @ MEMORY_SHIP:0x146f */
    /* label ShowString @ MEMORY_SHIP:0x172b */
    /* label DoneMine @ MEMORY_SHIP:0x179f */
    /* label LDisplayMsg @ MEMORY_SHIP:0x14a1 */

    /* TODO: implement */
}

void DrawPlanetXferSide(HDC hdc, RECT *prc, PLANET *ppl, int16_t iSupply) {
    PLANET  pl;
    int16_t yTop;
    int16_t c;
    int16_t i;
    int16_t xRight;
    char   *psz;
    int16_t xLeft;
    RECT    rc;

    /* TODO: implement */
}
void DrawShipCargo(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t dxRight;
    int32_t l2;
    int16_t yTop;
    int16_t i;
    int16_t c;
    FLEET  *pfl;
    int16_t xRight;
    RECT    rcGauge;
    int16_t xLeft;
    int32_t l;
    RECT    rc;

    /* TODO: implement */
}

void FillOrdersLB(void) {
    int16_t i;
    char   *psz;
    ORDER   ord;

    /* TODO: implement */
}

void GetXferLeftRightRcs(RECT *prcWhole, RECT *prcLeft, RECT *prcRight) { /* TODO: implement */ }

int16_t FTrackXfer(HWND hwnd, int16_t x, int16_t y, int16_t fkb) {
    POINT   ptOld;
    POINT   pt;
    int32_t dChg;
    BTNT    btnt;
    int32_t cCur;
    int16_t i;
    int16_t iBtn;
    int16_t iVal;
    BTN     btn;
    int32_t cNew;
    RECT    rc;

    /* debug symbols */
    /* label FinishUp @ MEMORY_SHIP:0x5f70 */

    /* TODO: implement */
    return 0;
}

#endif /* _WIN32 */
