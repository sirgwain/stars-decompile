
#include "types.h"

#include "build.h"
#include "globals.h"
#include "memory.h"
#include "mine.h"
#include "msg.h"
#include "parts.h"
#include "planet.h"
#include "port.h"
#include "produce.h"
#include "race.h"
#include "research.h"
#include "ship.h"
#include "ship2.h"
#include "thing.h"
#include "turn2.h"
#include "util.h"
#include "utilgen.h"

/* functions */
void Produce(void) {
    int32_t lResCur;
    int16_t cMax;
    int32_t rgResAvail[4];
    int16_t iprodCur;
    int16_t mdStatus;
    int16_t cBuilt;
    int16_t fNoResearch;
    PLANET *lppl;
    int16_t i;
    int16_t idm;
    PROD    prodPartial;
    int16_t fPrevProdIsAlch;
    int16_t fAutoBuildDone;
    int32_t lResearchTake;
    PROD   *lpprod;
    PLANET *lpplMac;
    int16_t cMax2; /* NB09 shows overlaps; single var reused across blocks. */

    /* --------------------------------------------------------------------
     * Prologue + TURN2::MineMinerals
     * asm: 10b8:0000..000d
     * -------------------------------------------------------------------- */
    MineMinerals();

    /* --------------------------------------------------------------------
     * Zero rgplr[i].lResLastYear for all players
     * asm: 10b8:000e..003c
     * -------------------------------------------------------------------- */
    for (i = 0; i < game.cPlayer; i++) {
        rgplr[i].lResLastYear = 0;
    }

    /* --------------------------------------------------------------------
     * Setup lppl iteration bounds: lppl = lpPlanets; lpplMac = lpPlanets + cPlanet
     * asm: 10b8:003d..0065
     * NOTE: Win16 segment temporaries in asm land in NB09 locals (stack overlap);
     *       in 32-bit C we just keep flat pointers.
     * -------------------------------------------------------------------- */
    lppl = lpPlanets;
    lpplMac = lpPlanets + cPlanet;

    /* ====================================================================
     * Planet loop
     * asm: top at 10b8:0c55 (condition), body starts 0068
     * ==================================================================== */
    while (true) {
        /* ----------------------------------------------------------------
         * Loop end: update populations/research, maybe random events, return
         * decompile tail; asm at end-of-loop block (see below near 0c51/0c55)
         * ---------------------------------------------------------------- */
        if (lppl >= lpplMac) {
            UpdatePopulations();
            UpdateResearchStatus(1);
            if (!game.fNoRandom) {
                RandomEvents();
            }
            return;
        }

        /* ----------------------------------------------------------------
         * If lppl->lpplprod == NULL: send queue-empty msg; add resources to lResLastYear.
         * asm: 10b8:0068..016b
         * decompile: first big if-block
         * ---------------------------------------------------------------- */
        if (lppl->lpplprod == NULL) {
            if (lppl->iPlayer != -1) {
                /* idmProductionQueueEmpty == 0x3f in asm at 009c */
                FSendPlrMsg2(lppl->iPlayer, idmProductionQueueEmpty, lppl->id, lppl->id, 0);

                lResCur = CResourcesAtPlanet(lppl, lppl->iPlayer);

                /* Apply planet extra resources if any (vrgPlanResExtra[plid] != 0):
                 * asm: 00dd..014d does:
                 *   lResCur += (lResCur * extra) / (extra + lResCur)
                 * using unsigned mul/div helpers.
                 */
                if (lResCur != 0) {
                    uint16_t extra = vrgPlanResExtra[lppl->id];
                    if (extra != 0) {
                        /* unsigned math to match __aFulmul/__aFldiv behavior, without UB */
                        uint32_t res_u = (uint32_t)lResCur;
                        uint32_t denom = res_u + (uint32_t)extra;
                        uint32_t add = 0;
                        if (denom != 0) {
                            add = (res_u * (uint32_t)extra) / denom;
                        }
                        lResCur = (int32_t)(res_u + add);
                    }
                }

                rgplr[lppl->iPlayer].lResLastYear += lResCur;
            }

            /* asm jumps to loop increment (0c51) */
            lppl++;
            continue;
        }

        /* ----------------------------------------------------------------
         * Else: if owned and has production entries (iprodMac != 0), do production.
         * asm: 10b8:016e.. (large)
         * decompile: else-if with (((PLPROD*)lppl->lpplprod)->iprodMac != 0)
         * ---------------------------------------------------------------- */
        if (lppl->iPlayer == -1 || ((PLPROD *)lppl->lpplprod)->iprodMac == 0) {
            lppl++;
            continue;
        }

        /* ----------------------------------------------------------------
         * Copy minerals (rgwtMin[0..2]) into rgResAvail[0..2]
         * asm: 01b8..01e6 (loop)
         * ---------------------------------------------------------------- */
        for (i = 0; i < 3; i++) {
            rgResAvail[i] = lppl->rgwtMin[i];
        }

        /* ----------------------------------------------------------------
         * rgResAvail[3] = resources at planet (+ extra formula as above)
         * asm: after mineral copy; matches decompile second CResourcesAtPlanet block
         * ---------------------------------------------------------------- */

        rgResAvail[3] = CResourcesAtPlanet(lppl, lppl->iPlayer);
        if (rgResAvail[3] != 0) {
            uint16_t extra = vrgPlanResExtra[lppl->id];
            if (extra != 0) {
                uint32_t res_u = (uint32_t)rgResAvail[3];
                uint32_t denom = res_u + (uint32_t)extra;
                uint32_t add = 0;
                if (denom != 0) {
                    add = (res_u * (uint32_t)extra) / denom;
                }
                rgResAvail[3] = (int32_t)(res_u + add);
            }
        }

        /* ----------------------------------------------------------------
         * If player is "cheater" (bit2 of wFlags in decompile), force resources?
         * decompile: if ((rgplr[i].wFlags >> 2 & 1) != 0) rgResAvail[3] = ...
         *
         * asm for this block is later; decompile’s helper noise made it unreadable.
         * The intent is: if fCheater set, cap production resources harshly.
         * We preserve the *bitfield* meaning (bit2) and keep the computed value
         * exactly as decompile’s arithmetic implies: (5 << 5) / 5 == 32.
         * ---------------------------------------------------------------- */
        if (rgplr[lppl->iPlayer].fCheater) {
            rgResAvail[3] = 32;
        }
        /* ----------------------------------------------------------------
         * Research skim:
         * decompile: if ((uVar14 & 1) == 0) take pctResearch% of rgResAvail[3]
         *
         * uVar14 comes from a bit in lppl->rgbImp[4..7] (second dword),
         * asm: 0194..01ad does (dword_at_rgbImp+4 >> 23) & 1 into local.
         * That bit is PLANET bitfield fNoResearch (see types.h overlay).
         * NOTE: NB09 locals overlap; we store into fNoResearch for clarity.
         * ---------------------------------------------------------------- */
        fNoResearch = (int16_t)(lppl->fNoResearch != 0);

        if (rgResAvail[3] != 0) {
            if (!fNoResearch) {
                /* keep unsigned intermediate to avoid signed-overflow UB and match helper semantics */
                uint32_t pct = (uint32_t)(uint8_t)rgplr[lppl->iPlayer].pctResearch;
                lResearchTake = (int32_t)(((uint32_t)rgResAvail[3] * pct) / 100u);
                rgResAvail[3] -= lResearchTake;
                rgplr[lppl->iPlayer].lResLastYear += lResearchTake;
            } else {
                lResearchTake = 0;
            }

            /* bVar4 in decompile: indicates “we had some resources and didn’t no-research”
             * We store into fAutoBuildDone as a 0/1 flag (NB09 naming overlap).
             */
            fAutoBuildDone = 1;

            /* ============================================================
             * TURN2_TopOfQueue:
             * decompile label TopOfQueue @ 10b8:0371
             * ============================================================ */
        TopOfQueue:
            fPrevProdIsAlch = 0;
            iprodCur = 0;

            while (true) {
                /* --------------------------------------------------------
                 * If queue empty OR iprodCur >= iprodMac:
                 *   possibly send “completed orders / queue empty”
                 *   write minerals back to planet, add leftover resources to lResLastYear, break
                 * decompile: LAB_10b8_0b9a block
                 * -------------------------------------------------------- */
                if (lppl->lpplprod == NULL || (int16_t)((PLPROD *)lppl->lpplprod)->iprodMac <= iprodCur) {
                    if (lppl->lpplprod == NULL || (((PLPROD *)lppl->lpplprod)->iprodMac <= (uint8_t)iprodCur && fAutoBuildDone)) {
                        FSendPlrMsg2(lppl->iPlayer, idmHasCompletedOrdersProductionQueueEmpty, lppl->id, lppl->id, 0);
                    }

                    for (i = 0; i < 3; i++) {
                        lppl->rgwtMin[i] = rgResAvail[i];
                    }
                    rgplr[lppl->iPlayer].lResLastYear += rgResAvail[3];
                    break;
                }

                /* --------------------------------------------------------
                 * lpprod = &lppl->lpplprod->rgprod[iprodCur]
                 * decompile uses pointer arithmetic (+4 + iprodCur*4)
                 * -------------------------------------------------------- */
                lpprod = &((PLPROD *)lppl->lpplprod)->rgprod[iprodCur];

                /* If lpprod->cItem == 0 -> remove from queue */
                if (lpprod->cItem == 0) {
                RemoveFromQueue:
                    if (((PLPROD *)lppl->lpplprod)->iprodMac == (uint8_t)(fPrevProdIsAlch + 1)) {
                        FreePl((PL *)lppl->lpplprod);
                        lppl->lpplprod = NULL;
                        break; /* then falls into the “queue empty” handling above on next loop */
                    }

                    if (iprodCur < (int16_t)(((PLPROD *)lppl->lpplprod)->iprodMac - 1)) {
                        memmove(&((PLPROD *)lppl->lpplprod)->rgprod[iprodCur - fPrevProdIsAlch], &((PLPROD *)lppl->lpplprod)->rgprod[iprodCur + 1],
                                (uint16_t)((((PLPROD *)lppl->lpplprod)->iprodMac - iprodCur) - 1) * 4);
                    }

                    ((PLPROD *)lppl->lpplprod)->iprodMac = (uint8_t)(((PLPROD *)lppl->lpplprod)->iprodMac - (uint8_t)(fPrevProdIsAlch + 1));
                    iprodCur = (int16_t)(iprodCur - (fPrevProdIsAlch + 1));

                    /* decompile: iprodCur++; fPrevProdIsAlch=0; continue */
                    iprodCur++;
                    fPrevProdIsAlch = 0;
                    continue;
                }

                /* --------------------------------------------------------
                 * “Can’t build” / validation logic keyed off (lpprod->grobj/iItem)
                 * -------------------------------------------------------- */
                if (lpprod->grobj == grobjPlanet) {
                    if (lpprod->iItem < iobjPlanetaryScannerFirst || lpprod->iItem > iobjPlanetaryScannerLast) {
                        if (lpprod->iItem == iobjPlanetaryScanner) {
                            /* ok */
                        } else if (lpprod->iItem >= iobjPacketIron && lpprod->iItem <= iobjPacketMixed) {
                            if (IWarpMAFromLppl(lppl, false) == 0 || lppl->idFling == 0) {
                                FSendPlrMsg2(lppl->iPlayer, idmHasOrdersBuildMineralPacketEitherDoesnt, lppl->id, lppl->id, 0);
                                goto RemoveFromQueue;
                            }
                        } else if (lpprod->iItem == mdIdleFactory) {
                            cMax = CMaxFactories(lppl, lppl->iPlayer);
                            cMax2 = CMaxOperableFactories(lppl, lppl->iPlayer, 1);
                            if (cMax2 > cMax)
                                cMax = cMax2;
                            cMax = (int16_t)(cMax - (int16_t)lppl->cFactories);
                            idm = idmHasOrdersBuildPlanetaryInstallationsBeyondMaximu;
                            if (cMax < (int16_t)lpprod->cItem) {
                                FSendPlrMsg2(lppl->iPlayer, idm, lppl->id, lppl->id, 0);
                                if (cMax < 1)
                                    goto RemoveFromQueue;
                                lpprod->cItem = (uint32_t)cMax;
                            }
                        } else if (lpprod->iItem == mdIdleMine) {
                            cMax = CMaxMines(lppl, lppl->iPlayer);
                            cMax2 = CMaxOperableMines(lppl, lppl->iPlayer, 1);
                            if (cMax2 > cMax)
                                cMax = cMax2;
                            cMax = (int16_t)(cMax - (int16_t)lppl->cMines);
                            idm = idmHasOrdersBuildPlanetaryInstallationsBeyondMaximu;
                            if (cMax < (int16_t)lpprod->cItem) {
                                FSendPlrMsg2(lppl->iPlayer, idm, lppl->id, lppl->id, 0);
                                if (cMax < 1)
                                    goto RemoveFromQueue;
                                lpprod->cItem = (uint32_t)cMax;
                            }
                        } else if (lpprod->iItem == mdIdleDefense) {
                            cMax = CMaxDefenses(lppl, lppl->iPlayer);
                            cMax2 = CMaxOperableDefenses(lppl, lppl->iPlayer, 1);
                            if (cMax2 > cMax)
                                cMax = cMax2;
                            cMax = (int16_t)(cMax - (int16_t)lppl->cDefenses);
                            idm = idmHasOrdersBuildPlanetaryInstallationsBeyondMaximu;
                            if (cMax < (int16_t)lpprod->cItem) {
                                FSendPlrMsg2(lppl->iPlayer, idm, lppl->id, lppl->id, 0);
                                if (cMax < 1)
                                    goto RemoveFromQueue;
                                lpprod->cItem = (uint32_t)cMax;
                            }
                        } else if (lpprod->iItem == mdIdleTerraform) {
                            cMax = IpctCanTerraformLppl(lppl);
                            idm = idmHasOrdersTerraformBeyondMaximumAllowedOrders;
                            if (cMax < (int16_t)lpprod->cItem) {
                                FSendPlrMsg2(lppl->iPlayer, idm, lppl->id, lppl->id, 0);
                                if (cMax < 1)
                                    goto RemoveFromQueue;
                                lpprod->cItem = (uint32_t)cMax;
                            }
                        }
                    } else {
                        if (lpprod->iItem != iobjUnknown) {
                            FSendPlrMsg2(lppl->iPlayer, idmOrderBuildScannerCanceledAlreadyHaveScanner, lppl->id, lppl->id, 0);
                            goto RemoveFromQueue;
                        }
                    }
                }

                /* --------------------------------------------------------
                 * Build attempt
                 * -------------------------------------------------------- */
                prodPartial.cItem = 0;

                cBuilt = CBuildProdItem(lppl, lpprod, &prodPartial, rgResAvail, fPrevProdIsAlch, &mdStatus, 0);

                /* decompile: if (bVar4) && (mdStatus==3||mdStatus==4) bVar4=false;
                 * We reuse fAutoBuildDone as the “bVar4” flag.
                 */
                if (fAutoBuildDone && (mdStatus == 3 || mdStatus == 4)) {
                    fAutoBuildDone = 0;
                }

                if (cBuilt > 0) {
                    int16_t    iItemLow = (int16_t)(cBuilt & 0x7f);
                    GrobjClass grobj = (GrobjClass)((uint16_t)cBuilt >> 7);
                    cBuilt = FBuildObject(lppl, (int16_t)grobj, iItemLow, cBuilt, rgResAvail);

                    if (cBuilt == 0) {
                        lpprod->cItem = 0;
                    }
                }

                /* --------------------------------------------------------
                 * FIX: match decompile LAB_10b8_09a0 -> TURN2_TopOfQueue
                 * If the build attempt caused the planet to become unowned AND
                 * the production queue pointer to be cleared, restart the queue
                 * engine from a clean state.
                 * -------------------------------------------------------- */
                if (lppl->iPlayer == -1 && lppl->lpplprod == NULL) {
                    goto TopOfQueue;
                }

                /* --------------------------------------------------------
                 * Post-build status handling
                 * -------------------------------------------------------- */
                if (mdStatus == 0) {
                    goto RemoveFromQueue;
                }

                if (mdStatus > 4) {
                    if (prodPartial.cItem != 0) {
                        if (((PLPROD *)lppl->lpplprod)->iprodMac == ((PLPROD *)lppl->lpplprod)->iprodMax) {
                            lppl->lpplprod = (PLPROD *)LpplReAlloc((PL *)lppl->lpplprod, (uint16_t)(((PLPROD *)lppl->lpplprod)->iprodMac + 1));
                        }

                        memmove(&((PLPROD *)lppl->lpplprod)->rgprod[1], &((PLPROD *)lppl->lpplprod)->rgprod[0],
                                (uint16_t)((PLPROD *)lppl->lpplprod)->iprodMac << 2);

                        ((PLPROD *)lppl->lpplprod)->rgprod[0] = prodPartial;
                        ((PLPROD *)lppl->lpplprod)->iprodMac++;
                    }

                    /* then go do the “queue empty / store minerals / add leftover” path */
                    continue;
                }

                /* alchemy special-case: if current prod is alch and another item exists, set fPrevProdIsAlch and skip */
                if (lpprod->grobj == grobjPlanet && lpprod->iItem == 3 && (int16_t)(((PLPROD *)lppl->lpplprod)->iprodMac - 1) > iprodCur) {
                    fPrevProdIsAlch = 1;
                    iprodCur++;
                    continue;
                }

                /* otherwise just advance */
                iprodCur++;
                fPrevProdIsAlch = 0;
            }
        }

        /* loop increment (asm: 0c51) */
        lppl++;
    }
}

void CreateBackupDir(void) {
    char  *pchT;
    char  *p1;
    char  *p2;
    size_t cap;

    /* szBackup = szBase (but safe even if something weird happens) */
    snprintf(szBackup, sizeof(szBackup), "%s", szBase);

    /* Find last path separator (accept either '\\' or '/' in szBase) */
    p1 = strrchr(szBackup, '\\');
    p2 = strrchr(szBackup, '/');
    if (p2 && (!p1 || p2 > p1))
        p1 = p2;

    /* Point at filename portion; then truncate so szBackup is directory prefix */
    pchT = (p1 == NULL) ? szBackup : (p1 + 1);
    *pchT = '\0';

    /* Build backup dir name into remaining space */
    cap = sizeof(szBackup) - (size_t)(pchT - szBackup);
    if (cap == 0)
        return;

    if (vcBackupDirs < 2) {
        snprintf(pchT, cap, "backup");
    } else if (vcBackupDirs < 100) {
        unsigned v = (unsigned)((uint32_t)game.turn % (uint32_t)vcBackupDirs);
        snprintf(pchT, cap, "backup%u", v);
    } else {
        unsigned v = (unsigned)((uint32_t)game.turn % (uint32_t)vcBackupDirs);
        snprintf(pchT, cap, "backup.%03u", v);
    }

    /* Create the directory (and any parents) */
    (void)Stars_EnsureDirRecursive(szBackup);

    /* Append "<sep>*" like the original code path did for later globbing */
    {
        size_t used = strlen(szBackup);
        if (used + 2 < sizeof(szBackup)) {
            if (used > 0 && szBackup[used - 1] != '\\' && szBackup[used - 1] != '/') {
                szBackup[used++] = Stars_PathSepChar();
                szBackup[used] = '\0';
            }
            strncat(szBackup, "*", sizeof(szBackup) - strlen(szBackup) - 1);
        }
    }
}

void ThingDecay(void) {
    THING   *lpthMac;
    int32_t  pctDecay;
    int16_t  i;
    int16_t  ifl;
    FLEET   *lpfl;
    THING   *lpth;
    uint16_t wDecay;
    int32_t  lDecay;
    int16_t  fMineExpert;
    int32_t  dy;
    int32_t  dx;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x7346 */
    /* block (block) @ MEMORY_TURN2:0x7391 */
    /* label LFixUpLpth @ MEMORY_TURN2:0x72ca */

    /* TODO: implement */
}

void DropColonists(void) {
    COLDROP *lpcdLook;
    int16_t  fTie;
    int32_t  cMax;
    PLANET   pl;
    int32_t  lDefensePower;
    int32_t  cPowerTot;
    COLDROP *lpcdCur;
    int16_t  iMax;
    int16_t  idPlanet;
    int16_t  iplrOldOwner;
    int32_t  cColTot;
    int32_t  lOldPop;
    int32_t  c2nd;
    int16_t  i;
    int32_t  rgcPower[16];
    int16_t  cSides;
    float    pctSurvive;
    int32_t  rgcCol[16];
    int32_t  lPower;
    COLDROP *lpcdMax;
    int16_t  cpq;
    int16_t  iTech;
    int16_t  iDst;
    int16_t  iBonus;
    PROD     prod;
    int16_t  ipq;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x3ebb */
    /* block (block) @ MEMORY_TURN2:0x3f27 */
    /* block (block) @ MEMORY_TURN2:0x4329 */
    /* label IncCur @ MEMORY_TURN2:0x442b */
    /* label WritePlanet @ MEMORY_TURN2:0x42fc */

    /* TODO: implement */
}

void TossNonAutoBuildItems(PLANET *lppl) {
    int16_t iDst;
    int16_t iSrc;

    if (lppl->lpplprod != NULL) {
        iDst = 0;
        for (iSrc = 0; iSrc < (int16_t)lppl->lpplprod->iprodMac; iSrc++) {
            if (lppl->lpplprod->rgprod[iSrc].grobj == grobjPlanet && lppl->lpplprod->rgprod[iSrc].iItem < 7) {
                if (iDst < iSrc) {
                    lppl->lpplprod->rgprod[iDst] = lppl->lpplprod->rgprod[iSrc];
                }
                iDst++;
            }
        }
        if (iDst < 1) {
            FreePl((PL *)lppl->lpplprod);
            lppl->lpplprod = NULL;
        } else {
            lppl->lpplprod->iprodMac = (uint8_t)iDst;
        }
    }
}

void UpdateResearchStatus(int16_t fUsePool) {
    int16_t  iTechCur;
    int16_t  fUsePoolOrig;
    int16_t  iTechNext;
    int16_t  iT;
    int16_t  iItem;
    int16_t  fGeneral;
    int16_t  i;
    int16_t  ibitCur;
    int32_t  rglFieldSpent[6];
    uint16_t grbitCur;
    int16_t  cPlrAlive;
    int32_t  lSpent;
    PART     part;
    int16_t  iTechNext2;
    int16_t  iGoto;
    int16_t  idm;

    fUsePoolOrig = fUsePool;
    cPlrAlive = 0;

    if (fUsePool) {
        for (i = 0; i < 6; i++)
            rglFieldSpent[i] = 0;
    }

    i = 0;
    do {
        if (i >= game.cPlayer) {
            /* Post-loop: Super Stealth intelligence gathering */
            idPlayer = -1;
            bool bGotSteal = false;
            if (fUsePoolOrig && cPlrAlive > 1) {
                for (i = 0; i < game.cPlayer; i++) {
                    if (GetRaceStat(&rgplr[i], rsMajorAdv) == raStealth) {
                        for (iT = 0; iT < 6; iT++) {
                            if (rglFieldSpent[iT] > 0) {
                                lSpent = rglFieldSpent[iT] / cPlrAlive / 2;
                                if (lSpent > 1) {
                                    bGotSteal = true;
                                    FSendPlrMsg2(i, idmIntelligenceGatheringActivitiesCombinedSynergist, -2, iT, (int16_t)lSpent);
                                    if (game.fSlowTech)
                                        lSpent /= 2;
                                    rgplr[i].rgResSpent[iT] += (uint32_t)lSpent;
                                }
                            }
                        }
                    }
                }
                if (bGotSteal)
                    UpdateResearchStatus(0);
            }
            return;
        }

        fGeneral = GetRaceGrbit(&rgplr[i], ibitRaceGeneralizedResearch);
        iTechCur = rgplr[i].iTechCur & 0xf;
        iTechNext = rgplr[i].iTechCur >> 4;
        idPlayer = i;
        fUsePool = fUsePoolOrig;

        if (!rgplr[i].fDead)
            cPlrAlive++;

        /* RedoItAll */
        bool bRedoFields;
        do {
            bRedoFields = false;
            for (iT = 0; iT < 6; iT++) {
                int32_t lResearch = (int32_t)rgplr[i].rgResSpent[iT];
                bool    bChangedField = false;

                if (game.fSlowTech)
                    lResearch /= 2;

                /* Add current year's research to primary field */
                if (iT == iTechCur && fUsePool && fGeneral < 2) {
                    if (fGeneral == 0) {
                        /* All research goes to current field */
                        lResearch += rgplr[i].lResLastYear;
                        rglFieldSpent[iT] += rgplr[i].lResLastYear;
                    } else {
                        /* Generalized: 50% to primary, 15% to each other */
                        bRedoFields = true;
                        fGeneral = 2;
                        int32_t lHalf = (rgplr[i].lResLastYear + 1) / 2;
                        lResearch += lHalf;
                        rglFieldSpent[iT] += lHalf;

                        for (int16_t j = 0; j < 6; j++) {
                            if (j != iT) {
                                int32_t l15pct = ((int32_t)((uint32_t)rgplr[i].lResLastYear * 3) + 19) / 20;
                                if (!game.fSlowTech) {
                                    rgplr[i].rgResSpent[j] += (uint32_t)l15pct;
                                } else {
                                    rgplr[i].rgResSpent[j] += (uint32_t)(l15pct / 2);
                                }
                                rglFieldSpent[j] += l15pct;
                            }
                        }
                    }
                }

                /* CheckForBreakthrough - check for tech level advancement */
                do {
                    if (rgplr[i].rgTech[iT] > 25)
                        goto NextField;
                    if ((rgplr[i].fCrippled || rgplr[i].fCheater) && rgplr[i].rgTech[iT] > 9)
                        goto NextField;

                    int32_t lCost = GetTechLevelCost(iT, rgplr[i].rgTech[iT] + 1, i);
                    if (lResearch < lCost) {
                        if (game.fSlowTech)
                            lResearch *= 2;
                        rgplr[i].rgResSpent[iT] = (uint32_t)lResearch;
                        goto NextField;
                    }

                    iTechNext2 = iTechCur;
                    lResearch -= lCost;
                    rgplr[i].rgTech[iT]++;
                    int8_t techLevel = rgplr[i].rgTech[iT];

                    if (techLevel == 26 && iTechNext == 6)
                        iTechNext = 7;

                    if (iTechCur == iT && iTechNext != 6) {
                        if (iTechNext == 7) {
                            iTechNext2 = 0;
                            for (int16_t j = 1; j < 6; j++) {
                                if (rgplr[i].rgTech[j] < rgplr[i].rgTech[iTechNext2])
                                    iTechNext2 = j;
                            }
                        } else {
                            iTechNext2 = iTechNext;
                        }
                        bChangedField = true;
                    }

                    MessageId iMsg;
                    if (fGeneral == 0)
                        iMsg = idmScientistsHaveCompletedResearchTechLevelWill;
                    else
                        iMsg = idmScientistsHaveCompletedResearchTechLevelPrimary;
                    FSendPlrMsg(i, iMsg, -2, (int16_t)techLevel, iT, iTechNext2, 0, 0, 0, 0);

                    /* Scan for newly available parts */
                    ibitCur = 0;
                    for (grbitCur = 1; grbitCur != 0; grbitCur <<= 1) {
                        iItem = 0;
                    ScanNextItem:
                        do {
                            part.hs.grhst = grbitCur;
                            part.hs.iItem = iItem;
                            int16_t sResult = FLookupPart(&part);
                            if (sResult == 0)
                                break;
                            if (sResult == 1 && rgplr[i].rgTech[iT] == part.pcom->rgTech[iT]) {
                                if (grbitCur == hstSBHull) {
                                    idm = idmRecentBreakthroughHasAlsoGivenHullDesign;
                                    iGoto = -3;
                                } else if (grbitCur == hstHull) {
                                    idm = idmRecentBreakthroughHasAlsoGivenHullType;
                                    iGoto = -3;
                                } else {
                                    if (grbitCur == hstTerra && GetRaceGrbit(&rgplr[i], ibitRaceTT) && (iItem == 8 || iItem == 0xc || iItem == 0x10)) {
                                        iItem++;
                                        goto ScanNextItem;
                                    }
                                    if (grbitCur == hstPlanetary && iItem > 8 && iItem < 14) {
                                        idm = idmRecentBreakthroughHasAlsoTaughtHowBuild;
                                    } else if (grbitCur == hstPlanetary && iItem >= 0 && iItem < 9) {
                                        idm = idmRecentBreakthroughHasAlsoTaughtHowBuild2;
                                    } else {
                                        idm = idmRecentBreakthroughHasAlsoGivenBenefit;
                                    }
                                    iGoto = (ibitCur << 8) | 0xc000 | iItem;
                                }
                                FSendPlrMsg(i, idm, iGoto, iT, grbitCur, iItem, 0, 0, 0, 0);
                            }
                            iItem++;
                        } while (true);
                        ibitCur++;
                    }
                } while ((fUsePool == 0 && !bChangedField && iTechNext != 7) || (iTechNext == 6 || iT != iTechCur));

                /* Field change handling */
                if (iTechNext == 7) {
                    iTechNext = 0;
                    for (int16_t j = 1; j < 6; j++) {
                        if (rgplr[i].rgTech[j] < rgplr[i].rgTech[iTechNext])
                            iTechNext = j;
                    }
                    rgplr[i].iTechCur = (rgplr[i].iTechCur & 0xf0) | (uint8_t)iTechNext;
                    rgplr[i].rgResSpent[iT] = 0;
                    iTechCur = iTechNext;
                    iTechNext = 7;
                } else {
                    rgplr[i].iTechCur = 0x60 | (uint8_t)iTechNext;
                    rgplr[i].rgResSpent[iT] = 0;
                    iTechCur = iTechNext;
                    iTechNext = 6;
                }

                /* Transfer remaining research to new primary field */
                if (game.fSlowTech)
                    lResearch *= 2;
                rgplr[i].rgResSpent[iTechCur] += (uint32_t)lResearch;
                fUsePool = 0;
                bRedoFields = true;

            NextField:;
            }
        } while (bRedoFields);

        i++;
    } while (true);
}

void RemoteTerraforming(void) {
    int16_t fHelp;
    int16_t iBest;
    int16_t pctCur;
    PLANET *lppl;
    int16_t ifl;
    FLEET  *lpfl;
    int16_t cDone;
    int16_t iEnv;
    int16_t cAllowed;
    int32_t ipct;
    int16_t pctNew;

    /* TODO: implement */
}

void UpdatePopulations(void) {
    int32_t lPopChg; /* bp-0x06 (overlaps in asm with far seg temp; keep as 32-bit in C) */
    PLANET *lppl;    /* bp-0x0a */
    PLANET *lpplMac; /* bp-0x0e */
    int16_t fMac;    /* bp-0x10 (block 2 in NB09) */
    int32_t lPopOld; /* bp-0x12 */

    /* ------------------------------
     * Prologue / init (asm 50a9..50d1)
     *   lppl = lpPlanets;
     *   lpplMac = lpPlanets + cPlanet;
     * Notes:
     *   - asm builds the end pointer by adding (cPlanet * 0x38) bytes.
     *   - far-pointer segment bookkeeping lives in stack overlap in asm; in modern C we keep only flat pointers.
     * ------------------------------ */

    /* loop while (lppl < lpplMac) (asm 5318..5323) */
    FORPLANETS(lppl, lpplMac) {
        /* ------------------------------------------------------------
         * Gate 1 (asm 50d4..50f8)
         *   if (owned) and (rgwtMin[3] != 0) then do pop change logic.
         * ------------------------------------------------------------ */
        if (lppl->iPlayer != -1) {
            if (lppl->rgwtMin[3] != 0) {
                /* --------------------------------------------------------
                 * lPopChg = ChgPopFromPlanet(lppl, 1) (asm 50fb..510d)
                 * -------------------------------------------------------- */
                lPopChg = ChgPopFromPlanet(lppl, 1);

                /* --------------------------------------------------------
                 * Message path gate (asm 5113..5158)
                 * Conditions derived from exact flag tests:
                 *   - if lPopChg == 0 -> NextPlanet
                 *   - if lPopChg > 0  -> NextPlanet
                 *   - if lPopChg < 0  -> continue
                 *   - if rgwtMin[3] <= 0 -> NextPlanet
                 * -------------------------------------------------------- */
                if (lPopChg != 0) {
                    if (lPopChg < 0) {
                        if (lppl->rgwtMin[3] > 0) {
                            /* ----------------------------------------------------
                             * Compute lPopOld = rgwtMin[3] - lPopChg (asm 515b..516f)
                             *
                             * IMPORTANT:
                             * The original x86 uses SUB/SBB on a 32-bit value,
                             * which is wrap-preserving two’s-complement arithmetic.
                             * In C, signed overflow is undefined, so we do the
                             * subtraction in uint32_t to exactly preserve the
                             * CPU’s modulo-2^32 behavior, then reinterpret as
                             * int32_t.
                             * ---------------------------------------------------- */
                            {
                                uint32_t uPop = (uint32_t)lppl->rgwtMin[3];
                                uint32_t uChg = (uint32_t)lPopChg;
                                lPopOld = (int32_t)(uPop - uChg);
                            }

                            /* desirability = PctPlanetDesirability(lppl, iPlayer) (asm 5172..5187) */
                            if (PctPlanetDesirability(lppl, lppl->iPlayer) < 0) {
                                /* ------------------------------------------------
                                 * Message 0x25 (asm 518f..51f8)
                                 * Push layout (10 words total):
                                 *   iPlayer, 0x25, id, id,
                                 *   lPopOld.lo, lPopOld.hi,
                                 *   pop.lo, pop.hi,
                                 *   0, 0
                                 * Note: __aFulshr(., 0x10) is logical >>16, so use uint32_t.
                                 * ------------------------------------------------ */
                                uint32_t uPop = (uint32_t)lppl->rgwtMin[3];
                                uint32_t uNew = (uint32_t)lPopOld;

                                FSendPlrMsg(lppl->iPlayer, idmPopulationHasDecreased, lppl->id, lppl->id, (int16_t)(uNew & 0xFFFF), (int16_t)(uNew >> 16),
                                            (int16_t)(uPop & 0xFFFF), (int16_t)(uPop >> 16), 0, 0);
                            } else {
                                /* ------------------------------------------------
                                 * Message 0x26 (asm 51fb..5251)
                                 * Push layout (10 words total):
                                 *   iPlayer, 0x26, id, id,
                                 *   abs(lPopChg).lo, abs(lPopChg).hi,
                                 *   0, 0, 0, 0
                                 * abs computed with two's-complement wrap (NEG/ADC/NEG),
                                 * so do it in uint32_t to avoid signed overflow UB.
                                 * ------------------------------------------------ */
                                uint32_t uAbs = 0u - (uint32_t)lPopChg;

                                FSendPlrMsg(lppl->iPlayer, idmPopulationHasDecreasedColonistsDueOvercrowding, lppl->id, lppl->id, (int16_t)(uAbs & 0xFFFF),
                                            (int16_t)(uAbs >> 16), 0, 0, 0, 0);
                            }
                        }
                    }
                }
            }
        }

        /* ------------------------------------------------------------
         * Uninhabited-by-pop block (asm 5254..52f6)
         *   if (owned) and (rgwtMin[3] == 0) => send msg2 and UninhabitPlanet
         * Notes:
         *   - asm uses GetRaceStat(plr, rsMajorAdv) and compares to raMacintosh.
         *   - message id is (0x23 or 0x40) + fMac, where 0x23 chosen when lPopChg < 0 else 0x40.
         *   - the lPopChg sign test here is the same 32-bit signed compare sequence as earlier (52b8..52d5).
         * ------------------------------------------------------------ */
        if (lppl->iPlayer != -1 && lppl->rgwtMin[3] == 0) {
            fMac = (GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) == raMacintosh) ? 1 : 0;

            /* pick base id (asm 52b8..52d5): 0x23 if lPopChg < 0 else 0x40 */
            {
                int16_t idBase = (lPopChg < 0) ? idmColonistsHaveDiedOffLongerControlPlanet : idmColonistsHaveJumpedShipLongerControlPlanet;

                FSendPlrMsg2(lppl->iPlayer, (int16_t)(idBase + fMac), lppl->id, lppl->id, 0);
            }

            UninhabitPlanet(lppl);
        }

        /* ------------------------------------------------------------
         * Uninhabit if no owner (asm 52f9..5311)
         * ------------------------------------------------------------ */
        if (lppl->iPlayer == -1) {
            UninhabitPlanet(lppl);
        }
    }
}

void SweepForMines(void) {
    int16_t  iplr;
    THING   *lpthMac;
    POINT    pt;
    int32_t  dy;
    int32_t  lCur;
    PLANET  *lppl;
    int16_t  ifl;
    FLEET   *lpfl;
    THING   *lpth;
    int32_t  cMineCur;
    int32_t  dx;
    int32_t  cMine;
    uint16_t grbitPlr;
    PLANET  *lpplMac;

    /* TODO: implement */
}

void UpdatePlayerScores(void) {
    int32_t  lScoreTot;
    int16_t  cFirst;
    SCORE    score;
    int16_t  cDead;
    int16_t  c;
    int16_t  i;
    uint8_t  rgcCond[16];
    uint16_t wWinners2;
    int32_t  rglScore[16];
    int16_t  iScoreMax;
    int16_t  j;
    uint16_t wWinners;
    int16_t  imsg;
    int32_t  lScore2nd;
    int32_t  lScoreMax;

    /* TODO: implement */
}

void UpdateGuesses(void) {
    PLANET *lppl;
    float   pct;
    PLANET *lpplMac;
    int32_t l;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x5377 */

    /* TODO: implement */
}

void MysteryTrader(void) {
    int16_t iSrc;
    int16_t cRand;
    int16_t i;
    THING  *lpth;
    int16_t grbitTrader;
    int16_t rgC[4];
    int16_t sVar;
    int16_t mapSize;

    if (game.turn <= 39)
        return;
    if (game.turn % 100 == 71)
        cRand = 2;
    else if (game.turn % 100 == 33)
        cRand = 3;
    else if ((game.turn & 0x7f) == 49)
        cRand = 4;
    else {
        if ((game.turn & 1) != 0)
            return;
        cRand = 7;
    }
    if (Random(cRand) != 0)
        return;
    lpth = LpthNew(0, ithMysteryTrader);
    if (lpth == NULL)
        return;
    mapSize = game.mdSize * 400;
    sVar = Random(5);
    lpth->tht.iWarp = (sVar + 8) & 0xf;
    for (i = 0; i < 4; i += 2) {
        rgC[i] = Random(mapSize + 361) + 1020;
    }
    if (Random(2) == 0) {
        rgC[1] = 1020;
        rgC[3] = mapSize + 1380;
    } else {
        rgC[1] = mapSize + 1380;
        rgC[3] = 1020;
    }
    sVar = Random(2);
    lpth->pt.x = rgC[sVar];
    lpth->pt.y = rgC[sVar == 0];
    lpth->tht.ptDest.x = rgC[sVar + 2];
    lpth->tht.ptDest.y = rgC[(sVar == 0) + 2];
    if (game.turn < 100)
        cRand = 5;
    else if (game.turn < 250)
        cRand = 3;
    else
        cRand = 2;
    if (lpth->tht.iWarp < 10)
        cRand++;
    else if (lpth->tht.iWarp > 10)
        cRand--;
    if (Random(10) < cRand) {
        if (Random(6) == 0)
            lpth->tht.grbitTrader = 0x1000;
        else
            lpth->tht.grbitTrader = 0;
    } else {
        sVar = Random(0xd);
        grbitTrader = 1 << (sVar & 0x1f);
        if (grbitTrader == 0x40 || grbitTrader == 0x80 || grbitTrader == 0x400 || grbitTrader == 0x800) {
            sVar = Random(0xd);
            grbitTrader = 1 << (sVar & 0x1f);
            if (((game.turn < 120 && grbitTrader == 0x80) || (game.turn < 0x96 && grbitTrader == 0x400) || (game.turn < 0xb4 && grbitTrader == 0x800)) &&
                Random(2) != 0) {
                grbitTrader = 0;
            }
        }
        lpth->tht.grbitTrader = grbitTrader;
    }
    for (i = 0; i < game.cPlayer; i++) {
        FSendPlrMsg2(i, idmMysteriousTradingVesselBroadcastingProposalHasDe, -6, lpth->idFull, 0);
    }
}

int16_t FQueueColonistDrop(FLEET *lpfl, PLANET *lppl, int32_t cColonists) {
    int16_t  iColDrop;
    COLDROP *lpcdT;

    /* TODO: implement */
    return 0;
}

int16_t CBuildProdItem(PLANET *lppl, PROD *lpprod, PROD *pprodPartial, int32_t *rgRes, int16_t fAlchemy, int16_t *pmdStatus, int16_t fCalcOnly) {
    int32_t  pctT;
    int16_t  cMax;
    int32_t  cCanBuild;
    int32_t  lMinNeeded;
    int32_t  lAlchCost;
    PROD     prod;
    int16_t  fAutoBuild;
    int16_t  cBuilt;
    int16_t  cAlchemy;
    int32_t  rgCostPaid[4];
    int16_t  i;
    int16_t  fResourceBlocked;
    int32_t  pctTooBig;
    int32_t  pct;
    uint32_t rgCost[4];
    int16_t  fMineralBlocked;
    int32_t  addCost;
    uint16_t iItemOrig;

    cAlchemy = 0;
    iItemOrig = lpprod->iItem;
    prod.dwRaw_0000 = lpprod->dwRaw_0000;

    GetProductionCosts(lppl, lpprod, rgCost, lppl->iPlayer, 1);

    cBuilt = 0;

    if (lpprod->grobj == grobjPlanet && lpprod->iItem < 7) {
        fAutoBuild = 1;
    } else {
        fAutoBuild = 0;
    }

    if (fAutoBuild) {
        cMax = 1000;

        switch (lpprod->iItem) {
        case iobjMine:
            cMax = CMaxOperableMines(lppl, lppl->iPlayer, 1) - (int16_t)lppl->cMines;
            break;
        case iobjFactory:
            cMax = CMaxOperableFactories(lppl, lppl->iPlayer, 1) - (int16_t)lppl->cFactories;
            break;
        case iobjDefense:
            cMax = CMaxOperableDefenses(lppl, lppl->iPlayer, 1) - (int16_t)lppl->cDefenses;
            break;
        case iobjAlchemy:
            break;
        case iobjMinTerraform:
        case iobjMaxTerraform:
            cMax = IpctCanTerraformLppl(lppl);
            if (cMax > 0 && lpprod->iItem == iobjMinTerraform && ChgPopFromPlanet(lppl, 0) >= 0 && PctPlanetDesirability(lppl, lppl->iPlayer) > 0) {
                cMax = 0;
            }
            break;
        case iobjPacket:
            if (IWarpMAFromLppl(lppl, NULL) == 0 || lppl->idFling == 0) {
                cMax = 0;
            }
            break;
        }

        if (cMax < 0)
            cMax = 0;

        if ((cMax >= 0 && (uint16_t)cMax < prod.cItem) || lpprod->iItem == iobjAlchemy) {
            prod.cItem = cMax;
        }
    }

    for (i = 0; i < 4; i++) {
        rgCostPaid[i] = (int32_t)rgCost[i] * prod.pct / 100;
    }

    for (;;) {
        if (prod.cItem == 0)
            goto LDone;

        for (i = 0; i < 4; i++) {
            if (rgRes[i] < (int32_t)rgCost[i] - rgCostPaid[i])
                break;
        }

        if (i > 3) {
            cBuilt++;
            prod.cItem--;
            prod.pct = 0;
            for (i = 0; i < 4; i++) {
                rgRes[i] -= ((int32_t)rgCost[i] - rgCostPaid[i]);
                rgCostPaid[i] = 0;
            }
            continue;
        }

        fMineralBlocked = 0;
        fResourceBlocked = 0;
        pct = 100;
        lMinNeeded = 0;

        for (i = 0; i < 4; i++) {
            if ((int32_t)rgCost[i] > 0) {
                if (rgRes[i] < (int32_t)rgCost[i]) {
                    pctT = (rgRes[i] + rgCostPaid[i]) * 100 / (int32_t)rgCost[i];
                    pctTooBig = (rgRes[i] + rgCostPaid[i] + 1) * 100 / (int32_t)rgCost[i];
                    if (pctT <= pctTooBig - 1)
                        pctT = pctTooBig - 1;
                } else {
                    pctT = 100;
                }
                if (pctT < pct) {
                    lMinNeeded = ((int32_t)rgCost[i] - rgCostPaid[i]) - rgRes[i];
                    pct = pctT;
                    if (i == 3)
                        fResourceBlocked = 1;
                    else
                        fMineralBlocked = 1;
                }
            }
        }

        if (fMineralBlocked && fAutoBuild != 0) {
            if (fAlchemy == 0) {
                fAutoBuild = 2;
                goto LDone;
            }
        } else {
            for (i = 0; i < 4; i++) {
                addCost = (int32_t)rgCost[i] * pct / 100 - rgCostPaid[i];
                rgRes[i] -= addCost;
                rgCostPaid[i] += addCost;
            }
            prod.pct = (uint32_t)pct;

            if (fAlchemy == 0 || fResourceBlocked)
                goto LDone;
        }

        /* LAlchemize */
        lAlchCost = (GetRaceGrbit(&rgplr[lppl->iPlayer], ibitRaceMineralAlchemy) != 0) ? 25 : 100;

        cCanBuild = rgRes[3] / lAlchCost;
        if (cCanBuild > lMinNeeded)
            cCanBuild = lMinNeeded;

        if (cCanBuild > 0) {
            for (i = 0; i < 3; i++)
                rgRes[i] += cCanBuild;
            rgRes[3] -= cCanBuild * lAlchCost;
            cAlchemy += (int16_t)cCanBuild;
        }

        if (cCanBuild != lMinNeeded) {
            if (rgRes[3] > 0 && pprodPartial != NULL) {
                memset(pprodPartial, 0, sizeof(PROD));
                pprodPartial->grobj = grobjPlanet;
                pprodPartial->iItem = mdIdleAlchemy;
                pprodPartial->cItem = 1;

                pctT = rgRes[3] * 100 / lAlchCost;
                pctTooBig = (rgRes[3] + 1) * 100 / lAlchCost;
                if (pctT <= pctTooBig - 1)
                    pctT = pctTooBig - 1;
                pprodPartial->pct = (uint32_t)pctT;

                addCost = pctT * lAlchCost / 100;
                rgRes[3] -= addCost;
            }
            goto LDone;
        }
    }

LDone:
    if (cBuilt > 0 && lpprod->grobj == grobjPlanet && (lpprod->iItem == mdIdleAlchemy || lpprod->iItem == iobjAlchemy)) {
        cAlchemy += cBuilt;
        for (i = 0; i < 3; i++) {
            rgRes[i] += (int32_t)cBuilt;
        }
    }

    if (cAlchemy != 0 && fCalcOnly == 0 && gd.fGeneratingTurn) {
        FSendPlrMsg2(lppl->iPlayer, idmScientistsHaveTransmutedCommonMaterialsKtEach, lppl->id, lppl->id, cAlchemy);
    }

    if (pmdStatus != NULL) {
        if (fAutoBuild == 2) {
            *pmdStatus = (cBuilt < 1) ? mdProdStatNoneAuto : mdProdStatSomeAuto;
        } else if (fAutoBuild == 0 || prod.cItem != 0) {
            if (cBuilt == 0) {
                *pmdStatus = (iItemOrig == lpprod->iItem) ? mdProdStatBlockedSame : mdProdStatBlockedDiff;
            } else if (prod.cItem == 0) {
                *pmdStatus = mdProdStatComplete;
            } else {
                *pmdStatus = mdProdStatSome;
            }
        } else {
            *pmdStatus = (cBuilt < 1) ? mdProdStatSkippedAuto : mdProdStatCompleteAuto;
        }
    }

    if (fCalcOnly == 0 && fAutoBuild == 0) {
        lpprod->dwRaw_0000 = prod.dwRaw_0000;
    }

    if (fAutoBuild != 0 && pprodPartial != NULL && pprodPartial->cItem == 0 && lpprod->iItem != iobjMine) {
        pprodPartial->dwRaw_0000 = prod.dwRaw_0000;
        pprodPartial->cItem = 1;
    }

    return cBuilt;
}

void AutoTerraform(void) {
    int16_t rgMax[3];
    int16_t rgp[16];
    PLANET *lppl;
    int16_t i;
    int16_t rgMin[3];
    int16_t rgCost[3];
    PLANET *lpplMac;
    bool    fAnyTerra;
    int16_t iEnv;
    int16_t pctDesire;

    fAnyTerra = false;
    for (i = 0; i < game.cPlayer; i++) {
        rgp[i] = (GetRaceStat(&rgplr[i], rsMajorAdv) == raTerra);
        if (rgp[i] != 0) {
            fAnyTerra = true;
        }
    }
    if (!fAnyTerra)
        return;

    lpplMac = lpPlanets + cPlanet;
    for (lppl = lpPlanets; lppl < lpplMac; lppl++) {
        if (lppl->iPlayer == -1 || rgp[lppl->iPlayer] == 0)
            continue;

        if (lppl->fStarbase && lppl->iPlayer == -1) {
            lppl->fStarbase = 0;
        }

        iEnv = Random(3);
        if (rgplr[lppl->iPlayer].rgEnvVar[iEnv] != -1 && rgplr[lppl->iPlayer].rgEnvVar[iEnv] != (int8_t)lppl->rgEnvVarOrig[iEnv] && Random(10) == 0 &&
            (lppl->rgwtMin[3] > 999 || Random(1000) < (int16_t)lppl->rgwtMin[3])) {

            if (rgplr[lppl->iPlayer].rgEnvVar[iEnv] < (int8_t)lppl->rgEnvVarOrig[iEnv]) {
                lppl->rgEnvVarOrig[iEnv]--;
            } else {
                lppl->rgEnvVarOrig[iEnv]++;
            }
            FSendPlrMsg2(lppl->iPlayer, idmEngineersHaveManagedImproveUnderlying1, lppl->id, lppl->id, iEnv);
        }

        if (FCanTerraformLppl(lppl, rgMin, rgMax, rgCost, 1)) {
            for (i = 0; i < 3; i++) {
                if (rgMin[i] == -1) {
                    if (rgMax[i] != -1) {
                        lppl->rgEnvVar[i] = (uint8_t)rgMax[i];
                    }
                } else {
                    lppl->rgEnvVar[i] = (uint8_t)rgMin[i];
                }
            }
            pctDesire = PctPlanetDesirability(lppl, lppl->iPlayer);
            FSendPlrMsg2(lppl->iPlayer, idmHasAutoTerraformedValue, lppl->id, lppl->id, pctDesire);
        }
    }
}

int16_t FPacketDecay(THING *lpth, int16_t pctRate) {
    uint16_t iRateMin;
    int16_t  iRate;
    int16_t  i;
    uint16_t wDecay;
    int32_t  lDecay;

    /* TODO: implement */
    return 0;
}

void TransferToOthers(void) {
    int32_t   l2;
    int16_t   idDst;
    XFER      rgxf[2];
    int16_t   idSrc;
    int16_t   i;
    int16_t   idm;
    XFERFULL *lpxfMax;
    XFERFULL *lpxfCur;
    int32_t   l;

    /* debug symbols */
    /* label DoNext @ MEMORY_TURN2:0x34c6 */

    /* TODO: implement */
}

void MineMinerals(void) {
    int32_t rglQuan[3];
    PLANET *lppl;
    PLANET *lpplMac;

    lpplMac = lpPlanets + cPlanet;
    for (lppl = lpPlanets; lppl < lpplMac; lppl++) {
        EstMineralsMined(lppl, rglQuan, -1, 1);
    }
}

int16_t FBuildObject(PLANET *lppl, GrobjClass grobj, int16_t iItem, int16_t cBuilt, int32_t *rgMinerals) {
    int16_t  iWarp;
    int16_t  i;
    FLEET   *lpfl;
    int16_t  idm;
    bool     fTwoMAs;
    SHDEF   *lpshdef;
    int16_t  cAllowed;
    int16_t  iEnv;
    int16_t  cshDamaged;
    int16_t  cshOrig;
    PART     part;
    uint16_t dpShdef;
    THING   *lpth;
    THING   *lpthMac;
    int16_t  raMajor;
    int16_t  iWarpAsked;
    int16_t  cSize;
    int16_t  rgwt[3];
    int16_t  iDecayRate;

    if (grobj == grobjFleet) {
        if (iItem >= cShdefMax) {
            /* Build starbase */
            uint16_t isbNew = iItem - cShdefMax;
            lpshdef = &rglpshdefSB[lppl->iPlayer][isbNew];

            if (lpshdef->fFree || !FCanBuildShdef(lpshdef, lppl->iPlayer))
                return 0;

            /* Determine message type based on cargo capacity */
            idm = idmHasBuiltNew;
            if (lpshdef->hul.wtCargoMax != 0) {
                idm = idmHasBuiltNewShipsKtTotalHull;
                if (lpshdef->hul.wtCargoMax == (uint16_t)-1)
                    idm = idmHasBuiltNewShipsAnySizeCan;
            }

            HULDEF *phuldef = LphuldefFromId(lpshdef->hul.ihuldef);
            FSendPlrMsg(lppl->iPlayer, idm, lppl->id, lppl->id, lppl->iPlayer << 5 | iItem, phuldef->hul.wtCargoMax, 0, 0, 0, 0);

            /* If replacing an existing starbase, check if new one is smaller */
            if (lppl->fStarbase) {
                SHDEF *lpshdefOld = &rglpshdefSB[lppl->iPlayer][lppl->isb];
                if (lpshdef->hul.ihuldef < lpshdefOld->hul.ihuldef)
                    KillQueuedShips(lppl);
            }

            iWarp = IWarpMAFromLppl(lppl, &fTwoMAs);

            if (!lppl->fStarbase) {
                lppl->fStarbase = 1;
            } else {
                /* Decrement old starbase's cExist */
                SHDEF *lpshdefOld = &rglpshdefSB[lppl->iPlayer][lppl->isb];
                lpshdefOld->cExist--;
            }

            lppl->isb = isbNew & 0xf;

            if (iWarp < 1) {
                iWarp = IWarpMAFromLppl(lppl, &fTwoMAs);
                if (iWarp < 1) {
                    /* Lost mass accelerator capability */
                    uint16_t hiWord = (uint16_t)((uint32_t)lppl->lStarbase >> 16);
                    hiWord &= 0xc3ff; /* clear iWarpFling */
                    hiWord &= 0xfc00; /* clear idTarget */
                    lppl->lStarbase = (lppl->lStarbase & 0xffff) | ((int32_t)hiWord << 16);
                    KillQueuedMassPackets(lppl);
                } else {
                    uint16_t hiWord = (uint16_t)((uint32_t)lppl->lStarbase >> 16);
                    hiWord = (hiWord & 0xc3ff) | (((iWarp + fTwoMAs - 4) & 0xf) << 10);
                    lppl->lStarbase = (lppl->lStarbase & 0xffff) | ((int32_t)hiWord << 16);
                }
            }

            lpshdef->cBuilt++;
            lpshdef->cExist++;
            return 1;
        }

        /* Build regular ship (iItem < 0x10) */
        if (!lppl->fStarbase || iItem > 0xf)
            return 0;

        lpshdef = &rglpshdef[lppl->iPlayer][iItem];
        if (lpshdef->fFree || !FCanBuildShdef(lpshdef, lppl->iPlayer)) {
            FSendPlrMsg2(lppl->iPlayer, idmStarbaseFailedBuildNewShipTypeBecause, lppl->id, iItem + 1, 0);
            return 0;
        }

        if (rgplr[lppl->iPlayer].cFleet != 0x200) {
            /* Can create a new fleet */
            lpfl = LpflNew(lppl->iPlayer, lppl->id);
            CreateShip(lppl->iPlayer, lpfl, iItem, cBuilt);
            int32_t lFuel = LGetFleetStat(lpfl, grStatFuel);
            lpfl->rgwtMin[4] = lFuel;

            if ((lppl->wRouting & 0x3ff) != 0) {
                AutoRouteFleet(lpfl, lppl);
                if (cBuilt != 1) {
                    if (lpfl->lpplord->rgord[1].iWarp == 0)
                        idm = idmStarbaseHasBuiltNewShipsWhichWill;
                    else
                        idm = idmStarbaseHasBuiltNewShipsWhichRouted;
                    FSendPlrMsg(lppl->iPlayer, idm, lpfl->id | 0x8000, lppl->id, cBuilt, lppl->iPlayer << 5 | iItem, (lppl->wRouting & 0x3ff) - 1, 0, 0, 0);
                    return 1;
                }
                if (lpfl->lpplord->rgord[1].iWarp == 0)
                    idm = idmStarbaseHasBuiltNewWhichWillRouted;
                else
                    idm = idmStarbaseHasBuiltNewWhichRouted;
                FSendPlrMsg(lppl->iPlayer, idm, lpfl->id | 0x8000, lppl->id, lppl->iPlayer << 5 | iItem, (lppl->wRouting & 0x3ff) - 1, 0, 0, 0, 0);
                return 1;
            }

            AutoFleetOrder(lpfl, lppl);
            if (cBuilt != 1) {
                FSendPlrMsg(lppl->iPlayer, idmStarbaseHasBuiltNewShips, lpfl->id | 0x8000, lppl->id, cBuilt, lppl->iPlayer << 5 | iItem, 0, 0, 0, 0);
                return 1;
            }
            FSendPlrMsg2(lppl->iPlayer, idmStarbaseHasBuiltNew, lpfl->id | 0x8000, lppl->id, lppl->iPlayer << 5 | iItem);
            return 1;
        }

        /* Fleet limit reached - try to merge with existing fleet at same location */
        for (i = 0; i < cFleet; i++) {
            lpfl = rglpfl[i];
            if (lpfl == NULL || lppl->iPlayer < lpfl->iPlayer)
                break;
            if (lppl->iPlayer == lpfl->iPlayer && lpfl->lpplord->rgord[0].pt.x == rgptPlan[lppl->id].x &&
                lpfl->lpplord->rgord[0].pt.y == rgptPlan[lppl->id].y && lpfl->rgcsh[iItem] < 0x7ffe - cBuilt) {

                /* Recalculate damage percentages when merging */
                if (lpfl->rgcsh[iItem] == 0 || lpfl->rgdv[iItem].pctDp == 0) {
                    lpfl->rgdv[iItem].dp = 0;
                } else {
                    dpShdef = rglpshdef[lpfl->iPlayer][iItem].hul.dp;
                    cshOrig = lpfl->rgcsh[iItem];
                    uint16_t pctSh = lpfl->rgdv[iItem].pctSh;

                    /* Calculate number of damaged ships */
                    cshDamaged = (int16_t)((uint32_t)pctSh * (uint32_t)cshOrig / 100);
                    if (cshDamaged == 0)
                        cshDamaged = 1;

                    /* Calculate total decay amount */
                    uint16_t pctDp = lpfl->rgdv[iItem].pctDp;
                    int32_t  totalDecay = (int32_t)((uint32_t)dpShdef * (uint32_t)pctDp / 10) * (int32_t)cshDamaged / 50;

                    /* Recalculate pctSh for merged fleet */
                    int16_t newPctSh = (int16_t)((int32_t)cshDamaged * 100 / (cshOrig + cBuilt));
                    if (newPctSh == 0)
                        newPctSh = 1;
                    lpfl->rgdv[iItem].pctSh = newPctSh;

                    /* Verify damaged count with new percentage */
                    cshDamaged = (int16_t)((uint32_t)(lpfl->rgdv[iItem].pctSh) * (uint32_t)(cshOrig + cBuilt) / 100);
                    if (cshDamaged == 0)
                        cshDamaged = 1;

                    /* Recalculate pctDp */
                    int32_t newPctDp = (int32_t)((uint32_t)totalDecay * 5 / (uint32_t)cshDamaged * 100 / (uint32_t)dpShdef);
                    lpfl->rgdv[iItem].pctDp = (uint16_t)newPctDp;
                }

                CreateShip(lppl->iPlayer, lpfl, iItem, cBuilt);
                FSendPlrMsg(lppl->iPlayer, idmStarbaseBuiltNewSDueLack27b, lpfl->id | 0x8000, lppl->id, cBuilt, lppl->iPlayer << 5 | iItem, lpfl->id, 0, 0, 0);
                return 1;
            }
        }

        /* No fleet found to merge with */
        FSendPlrMsg(lppl->iPlayer, idmStarbaseBuiltNewShipSTypeLost, lppl->id, lppl->id, cBuilt, lppl->iPlayer << 5 | iItem, 0, 0, 0, 0);
        return 0;
    }

    if (grobj != grobjPlanet)
        return 0;

    switch (iItem) {
    case iobjMine: /* mines */
    case mdIdleMine:
        cAllowed = CMaxMines(lppl, lppl->iPlayer) - (int16_t)lppl->cMines;
        if (cAllowed <= cBuilt)
            cBuilt = cAllowed;
        if (cBuilt < 1)
            return 0;
        lppl->cMines += cBuilt;
        idm = idmHaveBuiltMine;
        goto SendMsgFactMine;

    case iobjFactory: /* factories */
    case mdIdleFactory:
        cAllowed = CMaxFactories(lppl, lppl->iPlayer) - (int16_t)lppl->cFactories;
        if (cAllowed <= cBuilt)
            cBuilt = cAllowed;
        if (cBuilt < 1)
            return 0;
        lppl->cFactories += cBuilt;
        idm = idmHaveBuiltFactory;
        goto SendMsgFactMine;

    case iobjDefense: /* defenses */
    case mdIdleDefense:
        cAllowed = CMaxDefenses(lppl, lppl->iPlayer) - (int16_t)lppl->cDefenses;
        if (cAllowed <= cBuilt)
            cBuilt = cAllowed;
        if (cBuilt < 1)
            return 0;
        lppl->cDefenses += cBuilt;
        idm = idmHaveBuiltDefenseOutpost;

    SendMsgFactMine: {
        int16_t prevBuilt = FRemovePlayerMessage(lppl->iPlayer, idm, lppl->id);
        if (cBuilt + prevBuilt < 2)
            FSendPlrMsg2(lppl->iPlayer, idm, lppl->id, lppl->id, 0);
        else
            FSendPlrMsg2(lppl->iPlayer, idm + 1, lppl->id, cBuilt + prevBuilt, lppl->id);
        break;
    }

    case iobjAlchemy: /* alchemy */
    case mdIdleAlchemy:
        break;

    case iobjMinTerraform: /* terraform */
    case iobjMaxTerraform:
    case mdIdleTerraform:
        while (cBuilt-- > 0) {
            i = IBestTerraform(lppl, 1);
            if (i != 0) {
                iEnv = abs(i) - 1;
                int16_t dir = (i < 1) ? -1 : 1;
                int16_t envVal = (int16_t)lppl->rgEnvVar[iEnv] + dir;
                if (envVal > 99)
                    envVal = 99;
                if (envVal < 1)
                    envVal = 1;
                lppl->rgEnvVar[iEnv] = (uint8_t)envVal;
                FSendPlrMsg(lppl->iPlayer, idmTerraformingEffortsHave, lppl->id, lppl->id, (uint16_t)(i > 0), iEnv, envVal + iEnv * 0x100, 0, 0, 0);
            }
        }
        break;

    case iobjPacket: /* mass packet (auto-route) */
    case iobjPacketIron:
    case iobjPacketBor:
    case iobjPacketGerm:
    case iobjPacketMixed: {
        raMajor = GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv);
        int16_t iWarpMA = IWarpMAFromLppl(lppl, &fTwoMAs);

        if (iWarpMA == 0) {
            FSendPlrMsg2(lppl->iPlayer, idmMineralPacketFormedHasDisintegratedBecausePlanet, lppl->id, lppl->id, 0);
            return 0;
        }

        if (lppl->idFling == 0) {
            FSendPlrMsg2(lppl->iPlayer, idmMineralPacketFormedHasDisintegratedBecauseDidnt, lppl->id, lppl->id, 0);
            return 0;
        }

        if (iItem == iobjPacket)
            iItem = iobjPacketMixed; /* auto-packet → mixed */

        if (iItem == iobjPacketMixed) {
            cSize = (raMajor == raMassAccel) ? 25 : 40;
        } else {
            cSize = (raMajor == raMassAccel) ? 70 : 100;
        }

        for (i = 0; i < 3; i++) {
            if (i == iItem - 0xe || iItem == 0x11) {
                int32_t wt = (int32_t)cSize * (int32_t)cBuilt;
                if (wt > 32760)
                    wt = 32760;
                rgwt[i] = (int16_t)wt;
            } else {
                rgwt[i] = 0;
            }
        }

        iWarpAsked = lppl->iWarpFling + 4;
        if (iWarpAsked < 5 || iWarpAsked > iWarpMA + 3)
            iWarpAsked = iWarpMA + fTwoMAs;
        if (iWarpAsked > iWarpMA + fTwoMAs)
            iDecayRate = (iWarpAsked - iWarpMA) - fTwoMAs;
        else
            iDecayRate = 0;

        if (raMajor == raStargate && iDecayRate < 3)
            iDecayRate++;

        int16_t iWarpPkt = iWarpAsked - 4;

        /* Search for existing matching mineral packet */
        lpth = lpThings;
        lpthMac = lpThings + cThing;
        while (lpth < lpthMac) {
            // TODO: verify this lpth->thp.idPlanet == lppl->idFling - 1 condition. I think it's correct... not sure about the -1
            if (lpth->iplr == lppl->iPlayer && lpth->ith == ithMineralPacket && lpth->pt.x == rgptPlan[lppl->id].x && lpth->pt.y == rgptPlan[lppl->id].y &&
                lpth->thp.iWarp == (uint16_t)iWarpPkt && lpth->thp.idPlanet == lppl->idFling - 1 && lpth->thp.iDecayRate == (uint16_t)iDecayRate &&
                lpth->thp.wtMax < 1630)
                break;
            lpth++;
        }

        if (lpth >= lpthMac) {
            /* Create new mineral packet THING */
            THING *lpthNew = LpthNew(lppl->iPlayer, ithMineralPacket);
            if (lpthNew == NULL) {
                FSendPlrMsg2(lppl->iPlayer, idmHasOrdersBuildMineralPacketEitherDoesnt, lppl->id, lppl->id, 0);
            } else {
                uint16_t wtAccum = 0;
                for (i = 0; i < 3; i++) {
                    lpthNew->thp.rgwtMin[i] = rgwt[i];
                    wtAccum += (rgwt[i] + 9) / 10;
                }
                lpthNew->thp.iWarp = iWarpPkt & 0xf;
                lpthNew->thp.wtMax = wtAccum;
                lpthNew->thp.iDecayRate = iDecayRate;
                lpthNew->thp.idPlanet = lppl->idFling - 1;
                lpthNew->pt.x = rgptPlan[lppl->id].x;
                lpthNew->pt.y = rgptPlan[lppl->id].y;
                FSendPlrMsg2(lppl->iPlayer, idmHasProducedMineralPacketWhichHasDestination, lppl->id, lppl->id, lppl->idFling - 1);
            }
        } else {
            /* Merge into existing packet */
            lpth->thp.wtMax = 0;
            for (i = 0; i < 3; i++) {
                lpth->thp.rgwtMin[i] += rgwt[i];
                if (lpth->thp.rgwtMin[i] < 0)
                    lpth->thp.rgwtMin[i] = 32760;
                lpth->thp.wtMax += (lpth->thp.rgwtMin[i] + 9) / 10;
            }
            FSendPlrMsg2(lppl->iPlayer, idmHasProducedMineralPacketWhichHasCombined, lppl->id, lppl->id, lppl->idFling - 1);
        }
        break;
    }

    case 10:
        break;

    case iobjGenesis: {
        /* Genesis - planet rebirth */
        for (i = 0; i < game.cPlayer; i++)
            FSendPlrMsg2(i, idmStrongFundamentalForcesHaveRebirthed, lppl->id, lppl->id, 0);

        raMajor = GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv);
        if (raMajor != raMacintosh) {
            /* Reset installations */
            lppl->cFactories = 0;
            lppl->cMines = 0;
            lppl->cDefenses = 0;
            lppl->iScanner = iNoScanner;
            lppl->fArtifact = 1;
        }

        /* Reset minerals, environment, concentrations */
        for (i = 0; i < 3; i++) {
            lppl->rgwtMin[i] = 0;
            int16_t r1 = Random(50);
            int16_t r2 = Random(50);
            int8_t  env = (int8_t)(r1 + r2 + 1);
            lppl->rgEnvVarOrig[i] = env;
            lppl->rgEnvVar[i] = env;
            r1 = Random(40);
            r2 = Random(40);
            lppl->rgMinConc[i] = (uint8_t)(r1 + r2 + 25);
        }
        break;
    }

    case iobjPlanetaryScanner: {
        /* Best planetary scanner */
        idPlayer = lppl->iPlayer;
        LookupBestPlanetaryScanner(&part);
        idPlayer = -1;
        iItem = (part.hs.iItem) + iobjPlanetaryScannerFirst;
    }
    /* fall through */
    case iobjPlanetaryScannerViewer50:
    case iobjPlanetaryScannerViewer90:
    case iobjPlanetaryScannerScoper150:
    case iobjPlanetaryScannerScoper220:
    case iobjPlanetaryScannerScoper280:
    case iobjPlanetaryScannerSnooper320X:
    case iobjPlanetaryScannerSnooper400X:
    case iobjPlanetaryScannerSnooper500X:
    case iobjPlanetaryScannerSnooper620X:
        /* Build planetary installation */
        FSendPlrMsg(lppl->iPlayer, idmHasBuiltNewPlanetaryScanner, lppl->id, lppl->id, (int16_t)0x8000, iItem - 0x12, 0, 0, 0, 0);
        lppl->iScanner = iItem - 0x12;
        break;

    default:
        return 0;
    }

    return 1;
}

int16_t IBestRemoteTerra(PLANET *lppl, int16_t iplr, int16_t fHelp) {
    int16_t iBest;
    int16_t i;
    PLAYER  plrSav;

    /* TODO: implement */
    return 0;
}

void PlanetaryClimateChange(void) {
    int16_t iT;
    PLANET *lppl;
    int16_t i;
    int16_t j;

    if (Random(20) == 0) {
        lppl = (PLANET *)lpPlanets + Random(cPlanet);
        if (lppl->iPlayer == -1 || lppl->rgwtMin[3] < 51 || game.turn > 19) {
            i = Random(3);
            if (lppl->iPlayer != -1) {
                FSendPlrMsg2(lppl->iPlayer, idmFundamentalChangesEnvironmentHavePermanentlyAlte, lppl->id, lppl->id, i);
            }
            iT = Random(3) + 3;
            if (iT == 3) {
                iT = Random(3) + 6;
            }
            if (Random(2) != 0) {
                iT = -iT;
            }
            j = lppl->rgEnvVar[i] + iT;
            if (j < 1)
                j = 1;
            else if (j > 99)
                j = 99;
            lppl->rgEnvVar[i] = (uint8_t)j;
            j = lppl->rgEnvVarOrig[i] + iT;
            if (j < 1)
                j = 1;
            else if (j > 99)
                j = 99;
            lppl->rgEnvVarOrig[i] = (uint8_t)j;
            TossNonAutoBuildItems(lppl);
        }
    }
}

void DiscoverNewMinerals(void) {
    PLANET *lppl;
    int16_t iMin;
    int16_t bonus;

    if (Random(15 - game.mdSize) == 0) {
        lppl = (PLANET *)lpPlanets + Random(cPlanet);
        if (game.turn > 9) {
            iMin = Random(3);
            if (lppl->iPlayer != -1) {
                FSendPlrMsg(lppl->iPlayer, idmSurveyorsHaveDiscoveredPreviouslyUnknownDepositS, lppl->id, lppl->id, iMin, 0, 0, 0, 0, 0);
            }
            if (lppl->rgMinConc[iMin] < 180) {
                bonus = Random(15);
                lppl->rgMinConc[iMin] += (uint8_t)(bonus + 5);
            }
        }
    }
}

void MeteorStrike(void) {
    int16_t rgEnv[3];
    int16_t iT;
    int32_t rgQuan[4];
    int16_t iSize;
    PLANET *lppl;
    int16_t rgAffect[3];
    int16_t i;
    int16_t iConc;
    int16_t j;
    int16_t idm;
    int32_t lKill;

    if (Random(20) != 0)
        return;
    lppl = (PLANET *)lpPlanets + Random(cPlanet);
    if (!((lppl->iPlayer == -1 || lppl->rgwtMin[3] < 51 || game.turn > 19) && game.turn > 9))
        return;

    iSize = Random(4);
    for (i = 0; i < 3; i++)
        rgEnv[i] = i;
    for (i = 0; i < 3; i++) {
        j = Random(3);
        iT = rgEnv[i];
        rgEnv[i] = rgEnv[j];
        rgEnv[j] = iT;
    }
    for (i = 0; i < 3; i++) {
        rgAffect[i] = i;
        rgQuan[i] = (int32_t)(Random(250) + 50);
    }
    for (i = 0; i < 2; i++) {
        j = Random(3 - i) + i;
        iT = rgAffect[i];
        rgAffect[i] = rgAffect[j];
        rgAffect[j] = iT;
    }
    for (i = 0; i < game.cPlayer; i++) {
        if (i == lppl->iPlayer && GetRaceStat(&rgplr[i], rsMajorAdv) != raMacintosh)
            idm = idmSmallCometHasCrashedPlanetKilling25 + iSize;
        else
            idm = idmSmallCometHasCrashedBringingNewMinerals + iSize;
        FSendPlrMsg(i, idm, lppl->id, lppl->id, rgEnv[0], rgEnv[1], rgEnv[2], 0, 0, 0);
    }
    if (lppl->iPlayer != -1 && GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) != raMacintosh) {
        lKill = lppl->rgwtMin[3] * (int32_t)(iSize * 20 + 25) / 100;
        lppl->rgwtMin[3] -= lKill;
    }
    for (i = 0; i <= iSize && i < 3; i++) {
        rgQuan[rgAffect[i]] += (int32_t)(Random(17000) + 3000);
        iConc = (int16_t)lppl->rgMinConc[rgAffect[i]] + Random(50) + 50;
        if (iSize == 3) {
            iConc += Random(15) + 15;
        }
        if (iConc > 200)
            iConc = 200;
        lppl->rgMinConc[rgAffect[i]] = (uint8_t)iConc;
    }
    for (i = 0; i < 3; i++) {
        lppl->rgwtMin[i] += rgQuan[i];
    }
    for (i = 0; i < 3 && i <= iSize; i++) {
        iT = Random(3) + 3;
        if (iSize == 3)
            iT += Random(3) + 3;
        if (Random(2) != 0)
            iT = -iT;
        j = lppl->rgEnvVar[i] + iT;
        if (j < 1)
            j = 1;
        else if (j > 99)
            j = 99;
        lppl->rgEnvVar[i] = (uint8_t)j;
        j = lppl->rgEnvVarOrig[i] + iT;
        if (j < 1)
            j = 1;
        else if (j > 99)
            j = 99;
        lppl->rgEnvVarOrig[i] = (uint8_t)j;
    }
    TossNonAutoBuildItems(lppl);
}

void HealShips(void) {
    int16_t pctShipHeal;
    int16_t dpHeal;
    PLANET *lppl;
    int16_t i;
    FLEET  *lpfl;
    SHDEF  *lpshdef;
    int16_t pct;
    int16_t ishdef;
    PLANET *lpplMac;

    /* TODO: implement */
}

void CreateShip(int16_t iPlr, FLEET *lpfl, int16_t ishdef, int16_t cShip) {
    SHDEF *lpshdef;

    lpfl->rgcsh[ishdef] += cShip;
    lpshdef = &rglpshdef[iPlr][ishdef];
    lpshdef->cExist += cShip;
    lpshdef->cBuilt += cShip;
}

void BreedColonistsInTransit(void) {
    int16_t fNoBreeders;
    char    grfBreeder[16];
    int32_t lColGain;
    PLANET *lppl;
    int16_t ifl;
    FLEET  *lpfl;
    int16_t i;
    int32_t lColGainAct;

    /* TODO: implement */
}

void RandomEvents(void) {
    MeteorStrike();
    PlanetaryClimateChange();
    DiscoverNewMinerals();
    MysteryTrader();
    return;
}

void UnmarkMineFields(void) {
    THING *lpth;
    THING *end;

    end = lpThings + cThing;
    for (lpth = lpThings; lpth < end; lpth++) {
        if (lpth->ith == 0) {
            lpth->thm.grbitPlrNow = 0;
        }
    }
}
