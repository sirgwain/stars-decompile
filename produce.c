
#include "debuglog.h"
#include "globals.h"
#include "types.h"

#include "produce.h"

#include "memory.h"
#include "mine.h"
#include "parts.h"
#include "planet.h"
#include "race.h"
#include "resource.h"
#include "ship.h"
#include "turn2.h"
#include "util.h"

char *PszNameProdItem(PROD *lpprod) {
    uint32_t iItem;
    int16_t  iDelta;

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x3d94 */
    /* label LBogus @ MEMORY_PRODUCE:0x3d3b */

    /* TODO: implement */
    return NULL;
}

void GetProductionCosts(PLANET *lppl, PROD *lpprod, uint32_t *rgCost, int16_t iplr, int16_t fOnlyOne) {
    uint16_t rgCostsCur[4];
    uint16_t iItem;
    uint16_t rgCosts[4];
    int      i;
    int      j;
    SHDEF   *lpshdef;
    int16_t  raMajor;
    bool     fStarbase;
    PART     part;
    HUL     *lphulNew;
    HUL     *lphulCur;
    int16_t  rgCostsPartCur[4];
    int16_t  rgCostsPartNew[4];
    int16_t  costDiff;
    uint16_t costSub;

    raMajor = GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv);
    iItem = lpprod->iItem;

    if (lpprod->grobj == grobjFleet) {
        /* Ship or starbase production */
        fStarbase = iItem > 15;
        if (fStarbase) {
            lpshdef = rglpshdefSB[iplr];
            iItem = iItem - 16;
        } else {
            lpshdef = rglpshdef[iplr];
        }

        /* Check if design is marked as free */
        if (lpshdef[iItem].fFree) {
            for (i = 0; i < 4; i++) {
                rgCost[i] = 0;
            }
            return;
        }

        GetTrueHullCost(iplr, &lpshdef[iItem].hul, rgCosts);

        /* Starbase upgrade cost calculation */
        if (fStarbase && lppl->fStarbase) {
            lphulCur = &rglpshdefSB[iplr][lppl->isb].hul;
            lphulNew = &lpshdef[iItem].hul;

            GetTrueHullCost(iplr, lphulCur, rgCostsCur);

            if (lphulCur->ihuldef == lphulNew->ihuldef) {
                /* Same hull type - calculate part-by-part upgrade costs */
                part.parmor = (ARMOR *)LphuldefFromId(lphulCur->ihuldef);
                part.hs.grhst = hstNone;
                GetTruePartCost(iplr, &part, (uint16_t *)rgCostsPartCur);

                for (i = 0; i < 4; i++) {
                    rgCosts[i] = rgCosts[i] - rgCostsPartCur[i];
                }

                for (int i = 0; i < lphulCur->chs; i++) {
                    if (lphulCur->rghs[i].cItem != 0 && lphulNew->rghs[i].cItem != 0) {
                        /* Get current slot part cost */
                        part.hs.grhst = lphulCur->rghs[i].grhst;
                        part.hs.wRaw_0002 = lphulCur->rghs[i].wRaw_0002;
                        FLookupPart(&part);
                        GetTruePartCost(iplr, &part, (uint16_t *)rgCostsPartCur);

                        /* Get new slot part cost */
                        part.hs.grhst = lphulNew->rghs[i].grhst;
                        part.hs.wRaw_0002 = lphulNew->rghs[i].wRaw_0002;
                        FLookupPart(&part);
                        GetTruePartCost(iplr, &part, (uint16_t *)rgCostsPartNew);

                        if (lphulCur->rghs[i].grhst == lphulNew->rghs[i].grhst) {
                            if (lphulCur->rghs[i].iItem == lphulNew->rghs[i].iItem) {
                                /* Same part type and item - full credit for matching parts */
                                for (j = 0; j < 4; j++) {
                                    rgCostsPartCur[j] = rgCostsPartCur[j] * lphulCur->rghs[i].cItem;
                                    rgCostsPartNew[j] = rgCostsPartNew[j] * lphulNew->rghs[i].cItem;
                                    if ((uint16_t)(rgCostsPartNew[j] - rgCostsPartCur[j]) < 0x8000) {
                                        costDiff = rgCostsPartNew[j] - rgCostsPartCur[j];
                                    } else {
                                        costDiff = 0;
                                    }
                                    if (rgCosts[j] < (uint16_t)(rgCostsPartNew[j] - costDiff)) {
                                        costSub = rgCosts[j];
                                    } else {
                                        costSub = rgCostsPartNew[j] - costDiff;
                                    }
                                    rgCosts[j] = rgCosts[j] - costSub;
                                }
                            } else {
                                /* Same part type, different item - 80% credit */
                                for (j = 0; j < 4; j++) {
                                    rgCostsPartCur[j] = rgCostsPartCur[j] * lphulCur->rghs[i].cItem;
                                    rgCostsPartNew[j] = rgCostsPartNew[j] * lphulNew->rghs[i].cItem;
                                    if (rgCostsPartNew[j] - (rgCostsPartCur[j] * 8) / 10 < (rgCostsPartNew[j] * 2) / 10) {
                                        costDiff = (rgCostsPartNew[j] * 2) / 10;
                                    } else {
                                        costDiff = rgCostsPartNew[j] - (rgCostsPartCur[j] * 8) / 10;
                                    }
                                    if (rgCosts[j] < (uint16_t)(rgCostsPartNew[j] - costDiff)) {
                                        costSub = rgCosts[j];
                                    } else {
                                        costSub = rgCostsPartNew[j] - costDiff;
                                    }
                                    rgCosts[j] = rgCosts[j] - costSub;
                                }
                            }
                        } else {
                            /* Different part type - 70% credit */
                            for (j = 0; j < 4; j++) {
                                rgCostsPartCur[j] = rgCostsPartCur[j] * lphulCur->rghs[i].cItem;
                                rgCostsPartNew[j] = rgCostsPartNew[j] * lphulNew->rghs[i].cItem;
                                if (rgCostsPartNew[j] - (rgCostsPartCur[j] * 7) / 10 < (rgCostsPartNew[j] * 3) / 10) {
                                    costDiff = (rgCostsPartNew[j] * 3) / 10;
                                } else {
                                    costDiff = rgCostsPartNew[j] - (rgCostsPartCur[j] * 7) / 10;
                                }
                                if (rgCosts[j] < (uint16_t)(rgCostsPartNew[j] - costDiff)) {
                                    costSub = rgCosts[j];
                                } else {
                                    costSub = rgCostsPartNew[j] - costDiff;
                                }
                                rgCosts[j] = rgCosts[j] - costSub;
                            }
                        }
                    }
                }
            } else {
                /* Different hull type - 50% credit */
                for (i = 0; i < 4; i++) {
                    costSub = rgCosts[i] - (int16_t)rgCostsCur[i] / 2;
                    if ((int16_t)costSub < (int16_t)(rgCosts[i] / 2)) {
                        rgCosts[i] = rgCosts[i] / 2;
                    } else {
                        rgCosts[i] = costSub;
                    }
                }
            }
        }

        /* ISB (Improved Starbases) or AR bonus - 20% discount */
        if (fStarbase && (GetRaceGrbit(&rgplr[iplr], ibitRaceISB) != 0 || GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh)) {
            for (i = 0; i < 4; i++) {
                rgCosts[i] = rgCosts[i] - rgCosts[i] / 5;
            }
        }

        /* Starbase costs are halved (resources counted per year) */
        if (fStarbase) {
            for (i = 0; i < 4; i++) {
                rgCost[i] = (rgCosts[i] + 1) / 2;
            }
        } else {
            for (i = 0; i < 4; i++) {
                rgCost[i] = rgCosts[i];
            }
        }
        goto LMultiply;
    }

    /* Non-ship production items */
    if (iItem == iobjMine) {
    LMine:
        /* Mine */
        for (i = 0; i < 3; i++) {
            rgCost[i] = 0;
        }
        rgCost[3] = GetRaceStat(&rgplr[iplr], rsMineBuild);
        goto LMultiply;
    }

    if (iItem == iobjFactory) {
    LFactory:
        /* Factory */
        if (GetRaceGrbit(&rgplr[iplr], ibitRaceCheapFact) != 0) {
            costDiff = 1;
        } else {
            costDiff = 0;
        }

        if (!gd.fTutorial) {
            rgCost[0] = 0;
            rgCost[1] = 0;
            rgCost[2] = 4 - costDiff;
        } else {
            for (i = 0; i < 3; i++) {
                rgCost[i] = 2 - costDiff;
            }
        }
        rgCost[3] = GetRaceStat(&rgplr[iplr], rsFactBuild);
        goto LMultiply;
    }

    if (iItem == iobjDefense) {
    LDefense:
        /* Defense */
        part.hs.grhst = hstPlanetary;
        part.hs.iItem = 9; /* iplanetaryDefense */
        FLookupPart(&part);

        for (i = 0; i < 3; i++) {
            rgCost[i] = part.pplanetary->rgwtOreCost[i];
        }
        rgCost[3] = part.pplanetary->resCost;

        if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raDefend) {
            /* IS (Inner Strength) gets 60% defense cost */
            for (i = 0; i < 4; i++) {
                rgCost[i] = (uint32_t)((int32_t)rgCost[i] * 3) / 5;
            }
        }
        goto LMultiply;
    }

    if (iItem == iobjAlchemy) {
    LAlchemy:
        /* Mineral Alchemy */
        for (i = 0; i < 3; i++) {
            rgCost[i] = 0;
        }
        if (GetRaceGrbit(&rgplr[iplr], ibitRaceMineralAlchemy) != 0) {
            rgCost[3] = 25;
        } else {
            rgCost[3] = 100;
        }
        goto LMultiply;
    }

    if (iItem == iobjTerraform || iItem == iobjTerraform2) {
    LTerraform:
        /* Terraform */
        rgCost[0] = 0;
        rgCost[1] = 0;
        rgCost[2] = 0;
        if (GetRaceGrbit(&rgplr[iplr], ibitRaceTT) != 0) {
            rgCost[3] = 70;
        } else {
            rgCost[3] = 100;
        }
        if (raMajor == 3) { /* raTerra / CA */
            rgCost[3] = rgCost[3] / 2;
        }
        goto LMultiply;
    }

    if (iItem == iobjPacket || iItem == iobjGenesis) {
        /* Packet or MT Genesis */
        if (raMajor == 6) { /* raMassAccel / PP */
            costSub = 25;
        } else if (raMajor == 7) { /* raStargate / IT */
            costSub = 48;
        } else {
            costSub = 44;
        }
        for (i = 0; i < 3; i++) {
            rgCost[i] = costSub;
        }
        if (raMajor == 6) {
            rgCost[i] = 5;
        } else {
            rgCost[i] = 10;
        }
        goto LMultiply;
    }

    if (iItem == mdIdleFactory) {
        goto LFactory;
    }
    if (iItem == mdIdleMine) {
        goto LMine;
    }
    if (iItem == mdIdleDefense) {
        goto LDefense;
    }
    if (iItem == mdIdleAlchemy) {
        goto LAlchemy;
    }
    if (iItem == mdIdleTerraform) {
        goto LTerraform;
    }

    if (iItem == iobjScanner) {
        /* Scanner */
        part.hs.grhst = hstPlanetary;
        part.hs.iItem = 14; /* iplanetaryScanner */
        FLookupPart(&part);
        GetTruePartCost(iplr, &part, rgCosts);
        for (i = 0; i < 4; i++) {
            rgCost[i] = rgCosts[i];
        }
        goto LMultiply;
    }

    if (iItem == iobjPacketIron || iItem == iobjPacketBor || iItem == iobjPacketGerm) {
        /* Single mineral packet (Iron/Bor/Germ) */
        if (raMajor == 6) { /* raMassAccel / PP */
            costSub = 70;
        } else if (raMajor == 7) { /* raStargate / IT */
            costSub = 120;
        } else {
            costSub = 110;
        }
        for (i = 0; i < 3; i++) {
            if (iItem - iobjPacketIron == i && iItem >= iobjPacketIron) {
                rgCost[i] = costSub;
            } else {
                rgCost[i] = 0;
            }
        }
        if (raMajor == 6) {
            rgCost[i] = 5;
        } else {
            rgCost[i] = 10;
        }
        goto LMultiply;
    }

    /* Planetary installations (stargate, mass driver, etc.) */
    if (iItem >= iobjPlanetaryFirst && iItem <= iobjPlanetaryLast) {
        part.hs.grhst = hstPlanetary;
        part.hs.iItem = (iItem - iobjPlanetaryFirst) & 0xff;
        FLookupPart(&part);
        GetTruePartCost(iplr, &part, rgCosts);
        for (i = 0; i < 4; i++) {
            rgCost[i] = rgCosts[i];
        }
        goto LMultiply;
    }

    if (iItem == iobjStargateAlt) {
        /* Stargate (alternate index) */
        part.hs.grhst = hstPlanetary;
        part.hs.iItem = 0;
        FLookupPart(&part);
        GetTruePartCost(iplr, &part, rgCosts);
        for (i = 0; i < 4; i++) {
            rgCost[i] = rgCosts[i];
        }
        goto LMultiply;
    }

LMultiply:
    if (fOnlyOne == 0) {
        for (i = 0; i < 4; i++) {
            rgCost[i] = rgCost[i] * lpprod->cItem;
        }
    }
}

void EstimateItemProdSched(PLANET *lppl, PLPROD *lpplprod, int16_t iItem, int16_t *piFirst, int16_t *piLast) {
    int32_t cResearch;
    PLANET  pl;
    int32_t rglQuan[3];
    int16_t cBuilt;
    PROD    prodPartial;
    int16_t mdStatus;
    int16_t i;
    int16_t j;
    int16_t iPass;
    int16_t fAlchemy;
    int16_t iMac;
    int32_t rgRes[4];
    PROD   *lpprod;

    if (lpplprod == NULL)
        lpplprod = lppl->lpplprod;

    Assert(lpplprod && iItem < lpplprod->iprodMac);

    pl = *lppl;
    pl.lpplprod = (PLPROD *)LpplAlloc(sizeof(PROD), lpplprod->iprodMax, htOrd);
    memcpy(&pl.lpplprod->rgprod[0], &lpplprod->rgprod[0], lpplprod->iprodMac * sizeof(PROD));
    iMac = pl.lpplprod->iprodMac = lpplprod->iprodMac;

    prodPartial.cItem = 0;
    *piFirst = *piLast = 0;

    for (iPass = 1; iPass < 100; iPass++) {
        EstMineralsMined(&pl, rglQuan, -1, fTrue);

        for (j = 0; j < 3; j++)
            rgRes[j] = pl.rgwtMin[j];

        rgRes[3] = CResourcesAtPlanet(&pl, lppl->iPlayer);

        if (!pl.fNoResearch) {
            cResearch = rgRes[3] * (int32_t)rgplr[lppl->iPlayer].pctResearch / 100;
            rgRes[3] -= cResearch;
        } else
            cResearch = 0;

        fAlchemy = fFalse;

        for (i = -1; i < iMac; i++) {
            if (i == -1)
                lpprod = &prodPartial;
            else
                lpprod = &pl.lpplprod->rgprod[i];

            if (lpprod->cItem == 0)
                continue;

            if (lpprod->iItem == mdIdleAlchemy && lpprod->grobj == grobjPlanet) {
                if (i < iMac - 1) {
                    if (i == iItem) {
                        *piFirst = *piLast = -1;
                        goto LCleanUp;
                    }

                    fAlchemy = fTrue;
                    continue;
                }
                lpprod->cItem = 1020;
            }

            cBuilt = CBuildProdItem(&pl, lpprod, (i == -1) ? NULL : &prodPartial, rgRes, fAlchemy, &mdStatus, fFalse);

            if (iItem == i) {
                if (cBuilt > 0 && *piFirst == 0)
                    *piFirst = iPass;

                if (mdStatus == mdProdStatSkippedAuto) {
                    if (*piFirst)
                        *piLast = iPass - 1;
                    goto LCleanUp;
                }

                if (mdStatus == mdProdStatComplete || mdStatus == mdProdStatCompleteAuto) {
                    *piLast = iPass;
                    goto LCleanUp;
                }
            }

            fAlchemy = fFalse;

            if (lpprod->grobj == grobjPlanet) {
                switch (lpprod->iItem) {
                case iobjMine:
                case mdIdleMine:
                    pl.cMines += (int32_t)cBuilt;
                    break;
                case iobjFactory:
                case mdIdleFactory:
                    pl.cFactories += (int32_t)cBuilt;
                    break;
                }
            }

            if (mdStatus >= mdProdStatSome)
                break;
        }

        if (iItem < 0) {
            *piFirst = (int16_t)rgRes[3];
            if (iItem == -1)
                *piFirst += (int16_t)(cResearch);
            goto LCleanUp;
        }

        for (j = 0; j < 3; j++)
            pl.rgwtMin[j] = rgRes[j];
        ChgPopFromPlanet(&pl, fTrue);
    }

    if (*piFirst == 0)
        *piFirst = 100;
    *piLast = 100;

LCleanUp:
    if (pl.lpplprod)
        FreePl((PL *)pl.lpplprod);
}

void InitProduction(PROD *rgprod) {
    int16_t  iWarp;
    int16_t  iSrc;
    uint16_t u;
    int16_t  i;
    int16_t  ipl;
    PART     part;
    PROD    *lpprod;

    /* TODO: implement */
}

bool FIsAutoBuild(PROD *lpprod) {
    DBG_LOGW("FIsAutoBuild not implemented");

    (void)lpprod;
    /* TODO: when production queue formats are fully understood, detect the
     * auto-build sentinel items.
     */
    return false;
}

#ifdef _WIN32

void ProdCommandHandler(HWND hwnd, WPARAM wParam, LPARAM lParam) {
    int32_t lSel;
    int16_t iSrc;
    HWND    hwndLB;
    int16_t c;
    int16_t iDst;
    PROD    prodLast;
    int16_t ipl;
    int16_t fRefillSrc;
    int16_t iMac;
    RECT    rc;
    PROD   *lpprod;
    PROD    prod;
    int16_t cMax;
    PLPROD *lpplprodT;

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x28cd */
    /* label RingItUp @ MEMORY_PRODUCE:0x1dc4 */
    /* label FixedUp @ MEMORY_PRODUCE:0x215e */
    /* label RedrawText @ MEMORY_PRODUCE:0x2e12 */
    /* label RemoveItem @ MEMORY_PRODUCE:0x21ec */
    /* label AddItem @ MEMORY_PRODUCE:0x19a3 */

    /* TODO: implement */
}

int16_t ChangeProduction(int16_t fClear) {
    MemJump  env;
    MemJump *penvMemSav;
    int16_t (*lpProcProd)(void);
    PROD    rgprod[64];
    int16_t fSuccess;

    /* debug symbols */
    /* label LWriteProdQ @ MEMORY_PRODUCE:0x011b */

    /* TODO: implement */
    return 0;
}

void EnableZipProdBtns(HWND hwnd, int16_t iSel) {
    int16_t fEnabled;

    if (iSel >= 1 && vrgZipProd[iSel].fValid)
        fEnabled = 1;
    else
        fEnabled = 0;

    EnableWindow(GetDlgItem(hwnd, IDC_DELETE), fEnabled);
    EnableWindow(GetDlgItem(hwnd, IDC_RENAME), fEnabled);
}

INT_PTR CALLBACK ProductionDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC                hdc;
    PAINTSTRUCT        ps;
    RECT               rc;
    int16_t            dxPBtn;
    int16_t            dy;
    DRAWITEMSTRUCT    *lpdis;
    MEASUREITEMSTRUCT *lpmis;
    POINT              pt;
    int16_t            cMax;
    uint16_t           hcs;
    char               sz255[2];
    int16_t            i;
    RECT               rcT;
    int16_t            xCtr;
    int16_t            dx;
    int16_t            dyLB;
    char              *rgszZip[1];
    int16_t            rgidProdBtns[10];
    ZIPPRODQ           rgzp[4];
    int16_t (*lpProc)(void);
    int16_t fRet;

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x1213 */
    /* block (block) @ MEMORY_PRODUCE:0x1563 */
    /* block (block) @ MEMORY_PRODUCE:0x15d4 */
    /* block (block) @ MEMORY_PRODUCE:0x166f */
    /* block (block) @ MEMORY_PRODUCE:0x16e9 */
    /* block (block) @ MEMORY_PRODUCE:0x17a3 */
    /* block (block) @ MEMORY_PRODUCE:0x1881 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK ZipProdDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    PAINTSTRUCT ps;
    int16_t     i;
    int16_t     iBase;
    RECT        rc;
    int16_t     dy;
    int16_t (*lpProc)(void);
    char   *psz;
    RECT    rcGBox;
    char   *pszT;
    RECT    rc2;
    int16_t cch;
    int16_t cpq;
    HWND    hwndRad;

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x549f */
    /* block (block) @ MEMORY_PRODUCE:0x55b4 */
    /* block (block) @ MEMORY_PRODUCE:0x571a */
    /* block (block) @ MEMORY_PRODUCE:0x5967 */
    /* block (block) @ MEMORY_PRODUCE:0x5a07 */
    /* block (block) @ MEMORY_PRODUCE:0x5abb */
    /* label LDontRename @ MEMORY_PRODUCE:0x5ab1 */

    /* TODO: implement */
    return 0;
}

void FillProdSrcLB(HWND hwndLB, int16_t mdFill) {
    char    szT[80];
    int16_t i;
    char   *psz;

    /* TODO: implement */
}

void DrawProductionDlg(HWND hwnd, HDC hdc, RECT *prc, int16_t iDraw) {
    int32_t lSel;
    int16_t iSrc;
    int16_t idc;
    int16_t fCreatedDC;
    int16_t i;
    int16_t c;
    int32_t rgCost[4];
    int16_t dxkT;
    int16_t k;
    RECT    rc;
    PROD    prod;
    char    szT[100];

    /* debug symbols */
    /* block (block) @ MEMORY_PRODUCE:0x3964 */

    /* TODO: implement */
}

void FinishProduction(int16_t fWrite) { /* TODO: implement */ }

void InitializeProductionDlg(HWND hwnd) {
    char    rgch[86];
    int16_t i;
    int16_t iSel;
    PROD   *lpprod;

    /* TODO: implement */
}

void FillZipProdLB(HWND hwndDlg, ZIPPRODQ *pzpq) {
    int16_t i;
    HWND    hwndLB;
    char    szAuto[40];
    char    szFormat[15];
    RECT    rc;

    /* TODO: implement */
}

#endif /* _WIN32 */
