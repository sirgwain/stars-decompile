
#include "globals.h"
#include "types.h"

#include "memory.h"
#include "parts.h"
#include "planet.h"
#include "produce.h"
#include "race.h"
#include "report.h"
#include "ship.h"
#include "ship2.h"
#include "tutor.h"
#include "util.h"
#include "utilgen.h"

#include <math.h>

/* functions */

int32_t PopFromLppl(PLANET *lppl) { return lppl->rgwtMin[3]; }

int16_t PctCloakFromHuldef(HUL *lphul, int16_t iplr, int16_t *ppctSteal) {
    uint8_t chs;
    HS     *lphs;
    int32_t cPts;
    int16_t pctCloak;
    int16_t j;

    chs = lphul->chs;
    if (iplr == -1 || lphul->ihuldef < ihuldefCount || GetRaceGrbit(&rgplr[iplr], ibitRaceISB) == 0) {
        cPts = 0;
    } else {
        // starbases get default cloaking
        cPts = 40;
    }
    if (iplr != -1 && GetRaceStat(&rgplr[iplr], rsMajorAdv) == raStealth) {
        cPts += 300;
    }
    if (ppctSteal != NULL) {
        *ppctSteal = 0;
    }
    lphs = lphul->rghs;
    for (j = 0; j < (int16_t)chs; j = j + 1) {
        cPts += (int32_t)CPtsCloakFromLphs(lphs);
        if (lphs->grhst == hstScanner && ppctSteal != NULL) {
            if (lphs->iItem == iscannerPickPocketScanner) {
                if (*ppctSteal < 70) {
                    *ppctSteal = 70;
                }
            } else if (lphs->iItem == iscannerRobberBaronScanner && *ppctSteal < 80) {
                *ppctSteal = 80;
            }
        }
        lphs = lphs + 1;
    }
    if (cPts == 0) {
        pctCloak = 0;
    } else if (cPts < 0 || cPts > 25000) {
        pctCloak = 0;
    } else if (cPts < 101) {
        pctCloak = (int16_t)cPts >> 1;
    } else if (cPts - 100 < 201) {
        pctCloak = (int16_t)(cPts - 100) / 8 + 50;
    } else if (cPts - 300 < 0x139) {
        pctCloak = (int16_t)(cPts - 300) / 24 + 75;
    } else {
        int16_t rem = (int16_t)(cPts - 612);
        if (rem < 513) {
            pctCloak = (rem >> 6) + 88;
        } else if (rem < 1000) {
            pctCloak = (767 < rem) + 96;
        } else {
            pctCloak = 98;
        }
    }
    return pctCloak;
}

int16_t PctPlanetOptValue(PLANET *lppl, int16_t iPlr) {
    int16_t canTerraform;
    int16_t newEnvVal;
    int16_t savedEnvVar[3];
    int16_t terraformCost[3];
    int16_t rgMin[3];
    int16_t rgMax[3];
    int16_t i;

    canTerraform = FCanTerraformLppl(lppl, rgMin, rgMax, terraformCost, 1);
    if (canTerraform == 0) {
        canTerraform = PctPlanetDesirability(lppl, iPlr);
    } else {
        for (i = 0; i < 3; i = i + 1) {
            int16_t curEnv = lppl->rgEnvVar[i];
            int16_t plrEnv = rgplr[iPlr].rgEnvVar[i];
            int16_t plrMin = rgplr[iPlr].rgEnvVarMin[i];

            savedEnvVar[i] = curEnv;

            if ((plrMin != -1) && (curEnv != plrEnv)) {
                newEnvVal = -1;

                if (curEnv < plrEnv) {
                    if (curEnv < rgMax[i]) {
                        if (plrEnv < rgMax[i]) {
                            newEnvVal = plrEnv;
                        } else {
                            newEnvVal = rgMax[i];
                        }
                    }
                } else if ((rgMin[i] != -1) && (rgMin[i] < curEnv)) {
                    if (rgMin[i] < plrEnv) {
                        newEnvVal = plrEnv;
                    } else {
                        newEnvVal = rgMin[i];
                    }
                }

                if (newEnvVal != -1) {
                    lppl->rgEnvVar[i] = (int8_t)newEnvVal;
                }
            }
        }

        canTerraform = PctPlanetDesirability(lppl, iPlr);

        for (i = 0; i < 3; i = i + 1) {
            lppl->rgEnvVar[i] = (int8_t)savedEnvVar[i];
        }
    }

    return canTerraform;
}

// Returns the highest warp speed of any Mass Accelerator on the planet's starbase
// that the caller is allowed to see. If there are at least two MAs at that warp,
// sets *fTwo = true so the caller can add +1 warp. Returns 0 if no MA or no access.
int16_t IWarpMAFromLppl(PLANET *lppl, bool *pfTwo) {
    int  iWarp = 0;
    bool fTwo = false;

    if (pfTwo)
        *pfTwo = false;

    // must be owned and have a starbase
    if (lppl && lppl->iPlayer != -1 && lppl->fStarbase) {
        const int owner = lppl->iPlayer;

        // pick this player's SB design table and the planet's SB design index (low 4 bits)
        SHDEF *tab = rglpshdefSB[owner];
        if (!tab)
            return 0;

        SHDEF *sb = &tab[lppl->isb & 0x0F];

        // visibility: owner, omniscient (-1), or det == 7 (matches ES:[+0x7B] == 7)
        if (owner == idPlayer || idPlayer == -1 || sb->det == detAll) {

            // iterate hull slots: rghs starts at old +0x3A, count is chs at old +0x7A
            const int cSlots = sb->hul.chs;
            for (int i = 0; i < cSlots; ++i) {
                const HS *hs = &sb->hul.rghs[i];

                if (hs->grhst == hstSpecialSB) {           // Mass Accelerator bucket
                    uint8_t warpCode = (uint8_t)hs->iItem; // low byte
                    uint8_t count = (uint8_t)hs->cItem;    // high byte

                    // #define ispecialSBMassDriver5    7
                    // #define ispecialSBMassDriver6    8
                    // #define ispecialSBMassDriver7    9
                    // #define ispecialSBSuperDriver8   10
                    // #define ispecialSBSuperDriver9   11
                    // #define ispecialSBUltraDriver10  12
                    // #define ispecialSBUltraDriver11  13
                    // #define ispecialSBUltraDriver12  14
                    // #define ispecialSBUltraDriver13  15
                    if (count != 0 && warpCode > 6 && warpCode < 16) {
                        int w = (int)warpCode - 2; // 7..15 -> Warp 5..13
                        if (w > iWarp) {
                            iWarp = w;
                            fTwo = false;
                        } else if (w == iWarp) {
                            fTwo = true; // two MAs at top warp → caller adds +1
                        }
                    }
                }
            }

            if (pfTwo)
                *pfTwo = fTwo;
            return iWarp;
        }
    }

    return 0;
}

int16_t FGetBestDefensePart(PART *ppart) {
    int16_t fRet;
    int16_t i;
    PART    part;

    part.hs.grhst = hstPlanetary;
    part.hs.iItem = iplanetarySDI;
    i = 0;
    while (i < 5 && FLookupPart(&part) == LookupOk) {
        i = i + 1;
        part.hs.iItem = (part.hs.iItem + 1) & 0xff;
    }
    fRet = (0 < i);
    if (fRet) {
        i = i - 1;
    }
    part.hs.iItem = (i + iplanetarySDI) & 0xff;
    FLookupPart(&part);
    ppart->hs = part.hs;
    ppart->pplanetary = part.pplanetary;
    return fRet;
}

int16_t PctPlanetDesirability(PLANET *lppl, int16_t iPlr) {
    /* pctPos accumulates 0..10000 per env var (squared “percent ideal”). */
    int32_t pctPos = 0;

    /* pctNeg accumulates up to 15 per env var if outside acceptable range. */
    int32_t pctNeg = 0;

    /* pctMod is a scaling factor in 1/10000ths (starts at 100%). */
    int32_t pctMod = 10000;

    for (int16_t i = 0; i < 3; i++) {
        /* Planet current env (-??..?? stored as signed char). */
        int32_t iPlanet = (int32_t)lppl->rgEnvVar[i];

        /* Player environment prefs/ranges (signed char). */
        int32_t iPref = (int32_t)rgplr[iPlr].rgEnvVar[i]; /* “ideal” / preferred */
        int32_t iMin = (int32_t)rgplr[iPlr].rgEnvVarMin[i];
        int32_t iMax = (int32_t)rgplr[iPlr].rgEnvVarMax[i];

        /* Special case: “immune” / no-penalty axis (original checked iMax < 0). */
        if (iMax < 0) {
            pctPos += 10000;
            continue;
        }

        /* Outside range => negative penalty by distance to nearest bound, capped at 15. */
        if (iPlanet < iMin || iPlanet > iMax) {
            int32_t delta = (iPlanet < iMin) ? (iMin - iPlanet) : (iPlanet - iMax);
            if (delta > 15)
                delta = 15;
            pctNeg += delta;
            continue;
        }

        /* In range: compute squared “percent ideal” contribution, plus a modifier penalty
           when you’re more than halfway from ideal toward the nearer edge. */
        int32_t absdiff = iPlanet - iPref;
        if (absdiff < 0)
            absdiff = -absdiff;

        int32_t d;        /* range from ideal to nearest edge in the direction of iPlanet */
        int32_t dPenalty; /* (2*absdiff - d) */
        if (iPlanet < iPref) {
            d = iPref - iMin;
            dPenalty = (iPref - iPlanet) * 2 - d;
        } else {
            d = iMax - iPref;
            dPenalty = (iPlanet - iPref) * 2 - d;
        }

        /* pctVar = floor(absdiff * 100 / d); pctIdeal = 100 - pctVar */
        int32_t pctVar = (d != 0) ? (absdiff * 100) / d : 100;
        int32_t pctIdeal = 100 - pctVar;

        /* Add squared contribution (0..10000). */
        pctPos += pctIdeal * pctIdeal;

        /* If dPenalty > 0, reduce pctMod by:
              pctMod = floor(pctMod * (2*d - dPenalty) / (2*d))
           (matches the original mul/div helper behavior, using truncating integer division).
        */
        if (dPenalty > 0 && d > 0) {
            int32_t denom = d * 2;
            int32_t numer_factor = denom - dPenalty; /* (2*d - dPenalty) */
            pctMod = (int32_t)((pctMod * (int32_t)numer_factor) / (int32_t)denom);
        }
    }

    /* If any env var was out of range, result is a negative penalty (sum of capped deltas). */
    if (pctNeg != 0) {
        return (int16_t)(-pctNeg);
    }

    /* Otherwise:
         base = floor(sqrt(pctPos / 3.0))
         result = floor(base * pctMod / 10000)
       DAT_1120_1d2e in the original is the divisor used to average the 3 axes; 3.0 matches
       the intended “mean of 3 squared contributions” behavior.
    */
    {
        double  avg = (double)pctPos / 3.0;
        int32_t base = (int32_t)(sqrt(avg) + 0.9);
        int32_t result = (base * pctMod) / 10000;
        return (int16_t)result;
    }
}

int16_t CResourcesAtPlanet(PLANET *lppl, int16_t iPlr) {
    if (!lppl)
        return 0;

    // must have population to generate any resources
    if (PopFromLppl(lppl) == 0)
        return 0;

    int16_t iEffRes = GetRaceStat(&rgplr[iPlr], rsResGen);

    int64_t pop = PopFromLppl(lppl);
    int64_t popMax = CalcPlanetMaxPop(lppl->id, iPlr);

    if (pop > popMax) {
        pop = popMax + (pop - popMax) / 2;
        if (pop > 2 * popMax)
            pop = 2 * popMax;
    }

    int16_t cRes;

    if (RaMajor(iPlr) == raMacintosh) {
        // Macint16_tosh special formula
        int16_t iEnergy = rgplr[iPlr].rgTech[iEnergy];
        int16_t pctVal = PctPlanetDesirability(lppl, iPlr);

        if (iEnergy < 1)
            iEnergy = 1;
        if (pctVal < 25)
            pctVal = 25;

        // ceil-like behavior via +0.999
        double val = sqrt((double)pop * (double)iEnergy / (double)iEffRes) * (double)pctVal / 10.0;
        cRes = (int16_t)(val + 0.999);
    } else {
        // baseline: resources from population
        cRes = (int16_t)(pop / iEffRes);

        // add factory output up to operable cap
        int16_t cFact = CMaxOperableFactories(lppl, iPlr, /*assumeMaxPop*/ false);
        if ((int16_t)lppl->cFactories < cFact)
            cFact = (int16_t)lppl->cFactories;

        int16_t iEffFact = GetRaceStat(&rgplr[iPlr], rsFactProd);
        // ((cFact * iEffFact) + 9) / 10  → int16_teger divide w/ rounding
        cRes += (int16_t)(((int64_t)cFact * (int64_t)iEffFact + 9LL) / 10LL);
    }

    if (cRes == 0)
        cRes = 1;
    return cRes;
}

int16_t CMaxOperableDefenses(PLANET *lppl, int16_t iplr, int16_t fNextYear) {
    int16_t cMax = CMaxDefenses(lppl, iplr);

    /* rgwtMin[3] is population (int32_t) */
    int32_t lPop = lppl->rgwtMin[3];

    if (fNextYear)
        lPop += ChgPopFromPlanet(lppl, 0);

    /*
     * decompile: (lPop + 0x18) / 0x19, capped at 1000, then min with cMax.
     * 0x18=24, 0x19=25
     */
    int32_t cCur = (lPop + 24) / 25;
    if (cCur > 1000)
        cCur = 1000;

    if (cCur < cMax)
        cMax = (int16_t)cCur;

    /* redundant with CMaxDefenses but preserved from original flow */
    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh)
        cMax = 0;

    return cMax;
}

char *PszProductionETA(PLANET *lppl, PLPROD *lpplprod, int16_t iItem, int16_t *etaFirst, int16_t *etaLast) {
    int16_t iTurnEnd;
    int16_t iTurnBegin;
    int16_t ids;
    int16_t len;
    char   *psz;

    if (lpplprod == NULL) {
        lpplprod = lppl->lpplprod;
    }
    EstimateItemProdSched(lppl, lpplprod, iItem, &iTurnBegin, &iTurnEnd);
    if (iTurnBegin == 100) {
        if (lpplprod == NULL || lpplprod->iprodMac <= iItem || lpplprod->rgprod[iItem].grobj != grobjPlanet || lpplprod->rgprod[iItem].iItem > iobjPacket) {
            ids = idsNever;
        } else {
            ids = idsUnknown2;
        }
        CchGetString(ids, szWork);
    } else if (iTurnEnd == 100) {
        psz = PszGetCompressedString(idsDYears);
        wsprintf(szWork, psz, iTurnBegin);
    } else if (iTurnBegin == iTurnEnd) {
        if (iTurnBegin == 0) {
            CchGetString(idsSkipped, szWork);
        } else if (iTurnBegin == -1) {
            CchGetString(idsNeeded, szWork);
        } else {
            psz = PszGetCompressedString(idsDYear);
            len = wsprintf(szWork, psz, iTurnBegin);
            if (iTurnBegin != 1) {
                szWork[len] = 's';
                szWork[len + 1] = '\0';
            }
        }
    } else {
        psz = PszGetCompressedString(idsDDYears);
        wsprintf(szWork, psz, iTurnBegin, iTurnEnd);
    }
    if (etaFirst != NULL) {
        *etaFirst = iTurnBegin;
    }
    if (etaLast != NULL) {
        *etaLast = iTurnEnd;
    }
    return szWork;
}

int16_t FCanTerraformLppl(PLANET *lppl, int16_t *rgEnvMin, int16_t *rgEnvMax, int16_t *rgEnvCost, int16_t fHelp) {
    int16_t fRet;
    int     i;
    int16_t rgMove[3];
    int16_t iPlrSav;
    PART    part;
    int16_t dMin;
    int16_t dMax;
    int16_t dCur;
    int16_t ienvIdeal;

    iPlrSav = idPlayer;
    if (idPlayer == -1) {
        idPlayer = lppl->iPlayer;
    }

    part.hs.grhst = hstTerra;

    /* Find best "base" terra part in slots 0..7 (search descending). */
    for (i = iterraTotalTerraform30; i >= iterraTotalTerraform3; i = i - 1) {
        part.hs.iItem = i;
        fRet = FLookupPart(&part);
        if (fRet == 1) {
            break;
        }
    }

    if (i < 0) {
        fRet = 0;
        for (i = 0; i < 3; i = i + 1) {
            rgMove[i] = 0;
        }
    } else {
        fRet = 1;
        for (i = 0; i < 3; i = i + 1) {
            rgMove[i] = part.pterra->grAbility;
            rgEnvCost[i] = part.pterra->resCost;
        }
    }

    /* Check slots 8..11, potentially improving move[0] and cost[0]. */
    for (i = 3; i >= 0; i = i - 1) {
        part.hs.iItem = i + iterraGravityTerraform3;
        dCur = FLookupPart(&part);
        if (dCur == 1) {
            break;
        }
    }
    if (i >= 0) {
        if (rgMove[0] < part.pterra->grAbility) {
            fRet = 1;
            rgMove[0] = part.pterra->grAbility;
            rgEnvCost[0] = part.pterra->resCost;
        }
    }

    /* Check slots 12..15, potentially improving move[1] and cost[1]. */
    for (i = 3; i >= 0; i = i - 1) {
        part.hs.iItem = i + iterraTempTerraform3;
        dCur = FLookupPart(&part);
        if (dCur == 1) {
            break;
        }
    }
    if (i >= 0) {
        if (rgMove[1] < part.pterra->grAbility) {
            fRet = 1;
            rgMove[1] = part.pterra->grAbility;
            rgEnvCost[1] = part.pterra->resCost;
        }
    }

    /* Check slots 16..19, potentially improving move[2] and cost[2]. */
    for (i = 3; i >= 0; i = i - 1) {
        part.hs.iItem = i + iterraRadiationTerraform3;
        dCur = FLookupPart(&part);
        if (dCur == 1) {
            break;
        }
    }
    if (i >= 0) {
        if (rgMove[2] < part.pterra->grAbility) {
            fRet = 1;
            rgMove[2] = part.pterra->grAbility;
            rgEnvCost[2] = part.pterra->resCost;
        }
    }

    if (fRet) {
        for (i = 0; i < 3; i = i + 1) {
            /* Decompile: (rgMove[i] == 0) || (player->rgEnvVarMin[i] == -1) */
            if ((rgMove[i] == 0) || (rgplr[idPlayer].rgEnvVarMin[i] == -1)) {
                rgEnvMax[i] = -1;
                rgEnvMin[i] = -1;
            } else {
                /* Compute candidate min/max reach around original env. */
                rgEnvMin[i] = (int16_t)(lppl->rgEnvVarOrig[i] - rgMove[i]);
                rgEnvMax[i] = (int16_t)(lppl->rgEnvVarOrig[i] + rgMove[i]);

                /* Clamp min side vs current env var. */
                if (rgEnvMin[i] < lppl->rgEnvVar[i]) {
                    rgEnvMin[i] = (rgEnvMin[i] < 1) ? 1 : rgEnvMin[i];
                } else {
                    rgEnvMin[i] = -1;
                }

                /* Clamp max side vs current env var. */
                if (lppl->rgEnvVar[i] < rgEnvMax[i]) {
                    rgEnvMax[i] = (rgEnvMax[i] < 100) ? rgEnvMax[i] : 99;
                } else {
                    rgEnvMax[i] = -1;
                }

                /*
                 * Normalize to int once to avoid a pile of (uint8_t)/(int8_t) casts.
                 * This keeps the decompile’s signed/unsigned intent while staying clean.
                 */
                {
                    int envCur = lppl->rgEnvVar[i];
                    int envIdeal = rgplr[idPlayer].rgEnvVar[i];

                    if (fHelp == 0) {
                        dCur = (int16_t)abs(envCur - envIdeal);

                        if (rgEnvMin[i] == -1) {
                            dMin = 0;
                        } else {
                            dMin = (int16_t)abs((int)rgEnvMin[i] - envIdeal);
                        }

                        if (rgEnvMax[i] == -1) {
                            dMax = 0;
                        } else {
                            dMax = (int16_t)abs((int)rgEnvMax[i] - envIdeal);
                        }

                        if ((dCur < dMin) || (dCur < dMax)) {
                            if (dMin < dMax) {
                                rgEnvMin[i] = -1;
                            } else {
                                rgEnvMax[i] = -1;
                            }
                        } else {
                            rgEnvMax[i] = -1;
                            rgEnvMin[i] = -1;
                        }
                    } else if (envCur == envIdeal) {
                        rgEnvMax[i] = -1;
                        rgEnvMin[i] = -1;
                    } else if (envIdeal < envCur) {
                        rgEnvMax[i] = -1;
                        if (rgEnvMin[i] != -1) {
                            /* rgEnvMin = max(rgEnvMin, envIdeal) */
                            rgEnvMin[i] = ((int)rgEnvMin[i] < envIdeal) ? (int16_t)envIdeal : rgEnvMin[i];
                        }
                    } else {
                        rgEnvMin[i] = -1;
                        if (rgEnvMax[i] != -1) {
                            /* rgEnvMax = min(rgEnvMax, envIdeal) */
                            rgEnvMax[i] = (rgEnvMax[i] < envIdeal) ? rgEnvMax[i] : (int16_t)envIdeal;
                        }
                    }
                }
            }
        }

        for (i = 0; (i < 3) && (rgEnvMax[i] == -1) && (rgEnvMin[i] == -1); i = i + 1) {
        }
        dCur = (int16_t)(i != 3);
    } else {
        dCur = 0;
    }

    idPlayer = iPlrSav;
    return dCur;
}

char *PszCalcEnvVar(int16_t iEnv, int16_t iVar) {
    switch (iEnv) {
    case 0: /* gravity */
        return PszCalcGravity(iVar);

    case 1: { /* temperature */
        /* original format: "%d%cC" with 186 (0xBA) degree symbol in the codepage */
        const int deg = 186;
        snprintf(szWork, sizeof(szWork), "%d%cC", (int)(iVar * 4 - 200), (char)deg);
        return szWork;
    }

    case 2: /* radiation */
        /* original format: "%dmR" */
        snprintf(szWork, sizeof(szWork), "%dmR", (int)iVar);
        return szWork;

    default: /* fallback behaved like env==0 */
        return PszCalcGravity(iVar);
    }
}

int16_t CMaxOperableFactories(PLANET *lppl, int16_t iplr, int16_t fNextYear) {
    int16_t cMax;
    int32_t lPop;
    int16_t iEffOperate;
    int16_t cMaxByRule;

    cMaxByRule = CMaxFactories(lppl, iplr);
    iEffOperate = GetRaceStat(&rgplr[iplr], rsFactOperate);

    lPop = PopFromLppl(lppl);
    if (fNextYear)
        lPop += ChgPopFromPlanet(lppl, 0);

    /* floor(lPop * iEffOperate / 100) */
    cMax = (int16_t)((lPop * (int32_t)iEffOperate) / 100);

    if (cMaxByRule < cMax)
        cMax = cMaxByRule;

    if (cMax < 1)
        cMax = 1;

    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh)
        cMax = 0;

    return cMax;
}

int16_t CMaxFactories(PLANET *lppl, int16_t iplr) {
    int32_t lPopMax;
    int32_t cMax;

    /* base max population */
    lPopMax = CalcPlanetMaxPop(lppl->id, iplr);

    /* factories operable per 100 population */
    int16_t eff = GetRaceStat(&rgplr[iplr], rsFactOperate);
    cMax = (lPopMax * eff) / 100;

    /* minimum of 10 */
    if (cMax < 10)
        cMax = 10;

    /* Macintosh major advantage: no factories */
    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh)
        cMax = 0;

    return (int16_t)cMax;
}

/*
 * Original semantics:
 *  - iGravity is in the 0–100-ish Stars! gravity scale
 *  - Result is a percentage-like value with two decimals
 *  - Uses asymmetric scaling around 50
 */
char *PszCalcGravity(int16_t iGravity) {
    int16_t d = (int16_t)abs(iGravity - 50);
    int16_t iVal;

    if (d < 26) {
        iVal = d * 4 + 100;
    } else {
        iVal = (d - 25) * 24 + 200;
    }

    if (iGravity < 50) {
        /* integer division, matches original long divide */
        iVal = 10000 / iVal;
    }

    /* equivalent to wsprintf(szWork, "%d.%02d", ...) */
    snprintf(szWork, sizeof(szWork), "%d.%02d", iVal / 100, abs(iVal % 100));

    return szWork;
}

int16_t CMaxMines(PLANET *lppl, int16_t iplr) {
    int32_t lPopMax;
    int32_t cMax;

    /* base max population */
    lPopMax = CalcPlanetMaxPop(lppl->id, iplr);

    /* mines operable per 100 population */
    {
        int16_t eff = GetRaceStat(&rgplr[iplr], rsMineOperate);
        cMax = (lPopMax * eff) / 100;
    }

    /* minimum of 10 */
    if (cMax < 10)
        cMax = 10;

    /* Macintosh major advantage: no mines */
    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh)
        cMax = 0;

    return (int16_t)cMax;
}

int16_t FProdIsTerra(PROD *lpprod) {
    if (lpprod->grobj == grobjPlanet && (lpprod->iItem == mdIdleTerraform || lpprod->iItem == iobjMinTerraform || lpprod->iItem == iobjMaxTerraform)) {
        return 1;
    }
    return 0;
}

int16_t CMaxDefenses(PLANET *lppl, int16_t iplr) {
    int16_t pctDesire = PctPlanetDesirability(lppl, iplr);

    /* decompile boils down to: cMax = clamp(pctDesire*4, 10, 100) */
    int32_t cMax = (int32_t)pctDesire * 4;

    if (cMax < 10)
        cMax = 10;
    else if (cMax > 100)
        cMax = 100;

    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh)
        cMax = 0;

    return (int16_t)cMax;
}

int16_t IBestTerraform(PLANET *lppl, int16_t fHelp) {
    int16_t iSave;
    int16_t rgMax[3];
    int16_t pctT;
    int16_t i;
    int16_t iPlr;
    int16_t iEnv;
    int16_t pctCur;
    int16_t rgMin[3];
    int16_t rgpctBest[3];
    int16_t rgCost[3];
    int16_t iPlrSav;
    uint8_t envSav;
    int16_t pctNew;

    iPlrSav = idPlayer;
    iPlr = lppl->iPlayer;
    if (iPlr == -1) {
        idPlayer = iPlrSav;
        return 0;
    }
    idPlayer = iPlr;
    if (!FCanTerraformLppl(lppl, rgMin, rgMax, rgCost, fHelp)) {
        idPlayer = iPlrSav;
        return 0;
    }
    pctCur = PctPlanetDesirability(lppl, iPlr);
    for (i = 0; i < 3; i++) {
        if (rgMin[i] == -1) {
            if (rgMax[i] != -1) {
                iEnv = rgMax[i];
            } else {
                rgpctBest[i] = 0;
                continue;
            }
        } else {
            iEnv = rgMin[i];
        }
        envSav = lppl->rgEnvVar[i];
        lppl->rgEnvVar[i] = (uint8_t)iEnv;
        pctNew = PctPlanetDesirability(lppl, iPlr);
        pctT = pctNew - pctCur;
        if (pctT < 0)
            pctT = -pctT;
        rgpctBest[i] = (pctT * 100) / abs((int8_t)envSav - iEnv) + 1;
        lppl->rgEnvVar[i] = envSav;
    }
    iSave = 0;
    for (i = 1; i < 3; i++) {
        if (rgpctBest[iSave] < rgpctBest[i]) {
            iSave = i;
        }
    }
    idPlayer = iPlrSav;
    if (rgMin[iSave] == -1) {
        return iSave + 1;
    } else {
        return -(iSave + 1);
    }
}

int16_t IpctCanTerraformLppl(PLANET *lppl) {
    int16_t fCanTerraform;
    int16_t rgMax[3];
    int16_t i;
    int16_t rgMin[3];
    int16_t rgCost[3];
    int16_t ipct;

    fCanTerraform = FCanTerraformLppl(lppl, rgMin, rgMax, rgCost, 1);
    if (fCanTerraform == 0) {
        ipct = 0;
    } else {
        ipct = 0;
        for (i = 0; i < 3; i++) {
            if (rgMin[i] != -1) {
                ipct = ipct + (lppl->rgEnvVar[i] - rgMin[i]);
            }
            if (rgMax[i] != -1) {
                ipct = ipct + (rgMax[i] - lppl->rgEnvVar[i]);
            }
        }
    }
    return ipct;
}

int32_t CalcPlanetMaxPop(int16_t idpl, int16_t iplr) {
    PLANET  pl;
    int32_t lMaxPop;

    FLookupPlanet(idpl, &pl);

    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh) {
        /* Macintosh: max pop is driven by SB hull class; only if owned and has SB */
        if (pl.iPlayer != iplr || !pl.fStarbase)
            return 0;

        SHDEF *tab = rglpshdefSB[iplr];
        SHDEF *sb = &tab[pl.isb];

        /* rglPopMac is indexed by starbase hulldef, starting at huldef 0x20 (32). */
        int16_t ihuldef = sb->hul.ihuldef;
        int16_t i = (int16_t)(ihuldef - ihuldefCount);
        if (i < 0)
            return 0;
        lMaxPop = rglPopMac[i];
    } else {
        int16_t pctDesire = PctPlanetDesirability(&pl, iplr);

        if (pctDesire < 5)
            lMaxPop = 500;
        else
            lMaxPop = (int32_t)pctDesire * 100;

        {
            int16_t ra = GetRaceStat(&rgplr[iplr], rsMajorAdv);
            if (ra == raCheapCol) {
                lMaxPop -= lMaxPop / 2;
            } else if (ra == raNone) {
                lMaxPop += lMaxPop / 5;
            }
        }
    }

    if (GetRaceGrbit(&rgplr[iplr], ibitRaceOBRM))
        lMaxPop += lMaxPop / 10;

    return lMaxPop;
}

void UninhabitPlanet(PLANET *lppl) {
    int16_t i;

    if (lppl->iPlayer != -1 && GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) == raTerra) {
        for (i = 0; i < 3; i++) {
            lppl->rgEnvVar[i] = lppl->rgEnvVarOrig[i];
        }
    }
    lppl->iPlayer = iNoPlayer;
    lppl->rgwtMin[3] = 0;
    if (lppl->lpplprod != NULL) {
        FreePl((PL *)((PLANET *)lpPlanets)[lppl->id].lpplprod);
        ((PLANET *)lpPlanets)[lppl->id].lpplprod = NULL;
        lppl->lpplprod = NULL;
    }
    lppl->fNoResearch = 0;
    lppl->fStarbase = 0;
    lppl->cDefenses = 0;
    lppl->iScanner = iNoScanner;
    lppl->lStarbase = 0;
}

int16_t StargateRangeFromLppl(PLANET *lppl, int16_t iplr, int16_t ish) {
    int16_t i;
    HUL    *lphul;
    PART    part;

    if (lppl == NULL) {
        lphul = &rglpshdefSB[iplr][ish].hul;
    } else {
        if (lppl->iPlayer == iNoPlayer || !lppl->fStarbase) {
            return 0;
        }
        lphul = &rglpshdefSB[lppl->iPlayer][lppl->isb].hul;
    }
    i = 0;
    while (true) {
        if (lphul->chs <= i) {
            return 0;
        }
        if (lphul->rghs[i].grhst == hstSpecialSB && lphul->rghs[i].cItem != 0 && lphul->rghs[i].iItem <= ispecialSBStargateAnyAny)
            break;
        i = i + 1;
    }
    part.hs = lphul->rghs[i];
    FLookupPart(&part);
    if (part.pspecialsb->grAbility2 != -1) {
        return part.pspecialsb->grAbility2;
    }
    return 10000;
}

int16_t CMaxOperableMines(PLANET *lppl, int16_t iplr, int16_t fNextYear) {
    int16_t cMax;
    int32_t lPop;
    int16_t iEffOperate;
    int16_t cMaxByRule;

    cMaxByRule = CMaxMines(lppl, iplr);
    iEffOperate = GetRaceStat(&rgplr[iplr], rsMineOperate);

    lPop = PopFromLppl(lppl);
    if (fNextYear)
        lPop += ChgPopFromPlanet(lppl, 0);

    cMax = (int16_t)((lPop * (int32_t)iEffOperate) / 100);

    if (cMaxByRule < cMax)
        cMax = cMaxByRule;

    if (cMax < 1)
        cMax = 1;

    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh)
        cMax = 0;

    return cMax;
}

int16_t CMinesOperating(PLANET *lppl) {
    if (!lppl || lppl->iPlayer == -1)
        return 0;

    int16_t iplr = lppl->iPlayer;

    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh) {
        /* Macintosh: operating mines = floor(sqrt(population)) */
        int32_t lPop = PopFromLppl(lppl);
        if (lPop <= 0)
            return 0;
        return (int16_t)(sqrt((double)lPop));
    }

    {
        int16_t cMines = (int16_t)lppl->cMines;
        int16_t cMinesOp = CMaxOperableMines(lppl, iplr, 0);
        return (cMines <= cMinesOp) ? cMines : cMinesOp;
    }
}

int16_t PctPlanetCapacity(PLANET *lppl) {
    int32_t lPopMax;
    int16_t pctCap;

    lPopMax = CalcPlanetMaxPop(lppl->id, idPlayer);
    if (lPopMax < 1) {
        pctCap = 0;
    } else {
        int32_t halfPop = lPopMax / 2;
        int32_t result = ((uint32_t)lppl->rgwtMin[3] * 100 + halfPop) / lPopMax;
        pctCap = (int16_t)result;
        if (result > 999) {
            pctCap = 999;
        }
    }
    return pctCap;
}

int16_t CFactoriesOperating(PLANET *lppl) {
    int16_t iplr;
    int16_t cFacts;
    int16_t cFactsOp;

    iplr = lppl->iPlayer;
    if (iplr == -1)
        return 0;

    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raMacintosh)
        return 0;

    cFacts = (int16_t)lppl->cFactories;
    cFactsOp = CMaxOperableFactories(lppl, iplr, 0);

    if (cFacts <= cFactsOp)
        return cFacts;

    return cFactsOp;
}

#ifdef _WIN32

LRESULT CALLBACK PlanetWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC                hdc;
    PAINTSTRUCT        ps;
    XFER               xf;
    int16_t            i;
    char              *psz;
    int32_t            lSel;
    RECT               rc;
    POINT              pt;
    DRAWITEMSTRUCT    *lpdis;
    MEASUREITEMSTRUCT *lpmis;
    PLANET            *lpplMac;
    uint16_t           hcs;
    PLANET            *lppl;
    FLEET             *lpfl;

    switch (msg) {
    case WM_CREATE:
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC         hdc = BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        /* if you paint the whole client yourself, returning 1 avoids flicker */
        return 0;

    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);

    /* TODO: implement */
    return 0;
}

void DrawPlanShip(HDC hdc, int16_t grbit) {
    uint16_t hfontSav;
    OBJ      objNull;
    int16_t  ctile;
    COLORREF crFore;
    OBJ      obj;
    int16_t  fMin;
    int16_t  i;
    COLORREF crBack;
    int16_t  fErase;
    TILE    *ptile;
    int16_t  fDC;
    RECT     rc;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x0e3a */

    /* TODO: implement */
}

void DrawPlanetStats(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t dxRight;
    int32_t l2;
    int16_t yTop;
    int16_t xRight;
    int16_t c;
    int16_t cRes;
    int16_t dRangeP;
    float   pct;
    int16_t cResAvail;
    int16_t dRange;
    char   *psz;
    int16_t xLeft;
    HBRUSH  hbrSav;
    int32_t l;
    RECT    rc;
    PART    part;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x1ca1 */
    /* block (block) @ MEMORY_PLANET:0x2034 */

    /* TODO: implement */
}

void DrawPlanetShipList(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t swp;
    int16_t fDoneDrawing;
    int32_t l2;
    int16_t yTop;
    int16_t fObjIsThing;
    int16_t fUnknown;
    int16_t idSkip;
    int16_t xStart;
    int16_t xRight;
    int16_t i;
    int16_t c;
    RECT    rcGauge;
    XFER    xf;
    FLEET  *pfl;
    int32_t lSel;
    int16_t xLeft;
    int32_t l;
    RECT    rc;

    /* TODO: implement */
}

void DrawPlanetStarbase(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t  fTwo;
    int16_t  dxRight;
    int16_t  iWarp;
    int16_t  bt;
    int16_t  yTop;
    int16_t  xRight;
    int16_t  c;
    SHDEF   *lpshdef;
    COLORREF crForeSav;
    uint16_t w;
    char    *psz;
    int16_t  xLeft;
    HBRUSH   hbrSav;
    int32_t  l;
    RECT     rc;

    /* TODO: implement */
}

void DrawPlanetMinSum(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t dxRight;
    int16_t yTop;
    int16_t xRight;
    int16_t c;
    int16_t i;
    int16_t xLeft;
    HBRUSH  hbrSav;
    PLANET *ppl;
    RECT    rc;

    /* TODO: implement */
}
void DrawCBEntireItem(DRAWITEMSTRUCT *lpdis, int16_t inflate) {
    int16_t fListbox;
    int16_t fSelected;
    RECT    rc;

    /* TODO: implement */
}

void DrawMassWarpGauge(HDC hdc, RECT *prc, int16_t iBest, int16_t iCur) {
    int32_t lMax;
    int16_t c;
    int16_t fTwoMAs;
    int16_t iMode;
    HBRUSH  hbr;
    int32_t lCur;
    int32_t l;

    /* TODO: implement */
}

void DrawPlanetProduction(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t swp;
    int16_t dxRight;
    int16_t yTop;
    int16_t xStart;
    int16_t xRight;
    char    szT[40];
    int16_t i;
    int16_t c;
    int16_t dyWrong;
    char   *psz;
    int16_t iSel;
    int16_t cch;
    int16_t xLeft;
    RECT    rcT;
    PLANET *ppl;
    RECT    rc;

    /* TODO: implement */
}

void DrawPlanShipBitmap(HDC hdc, TILE *ptile, OBJ obj) {
    int16_t yTop;
    int16_t dy;
    int16_t xRight;
    int16_t i;
    char   *psz;
    int16_t dx;
    int16_t xLeft;
    HBRUSH  hbrSav;
    int16_t iOffset;
    RECT    rc;

    /* debug symbols */
    /* label DoBtns @ MEMORY_PLANET:0x368d */

    /* TODO: implement */
}

int16_t FDrawTileNC(HDC hdc, TILE *ptile, RECT *prc, char *pszTitle) {
    int16_t bt;
    RECT    rcT;

    /* debug symbols */
    /* label FinishUp @ MEMORY_PLANET:0x128f */

    /* TODO: implement */
    return 0;
}

void SetPlanetTitleBar(HWND hwnd) {
    char  szTitle[30];
    char *psz;

    /* TODO: implement */
}

void HandleFocusState(DRAWITEMSTRUCT *lpdis, int16_t inflate) {
    (void)inflate;

    if (lpdis->itemState & ODS_FOCUS) {
        FrameRect(lpdis->hDC, &lpdis->rcItem, hbr50Screen);
    }
}

int16_t IdFindAdjStarbase(int16_t idPlanet, int16_t fNext) {
    PLANET *lpplMac;
    int16_t idLast;
    int16_t idFirst;
    PLANET *lppl;
    int16_t idAfter;
    int16_t idBefore;

    /* TODO: implement */
    return 0;
}

void FillShipDD(int16_t idSkip) {
    THING  *lpthMac;
    int16_t i;
    THING  *lpth;
    FLEET  *lpfl;
    POINT   ptSel;

    /* TODO: implement */
}

void ChangeMainObjSel(int16_t grobjNew, int16_t iObjSel) {
    int16_t fSameType;
    int16_t idSkip;
    int16_t i;
    FLEET  *lpfl;

    idSkip = -1;
    fSameType = (grobjNew == sel.grobj);

    if (fAi && fSameType && iObjSel == sel.id)
        return;

    InvalidateReport(sel.grobj != grobjPlanet, 0);

    if (grobjNew == grobjPlanet) {
        InvalidateReport(0, 0);
        if (!FLookupPlanet(iObjSel, &sel.pl))
            return;

        sel.pt.x = rgptPlan[iObjSel].x;
        sel.pt.y = rgptPlan[iObjSel].y;
        sel.scan.iwp = -1;
        sel.iwpAct = -1;

        for (i = 0; i < cFleet; i++) {
            lpfl = rglpfl[i];
            if (lpfl == NULL || (lpfl->idPlanet == iObjSel && lpfl->iPlayer == idPlayer))
                break;
        }

        if (i == cFleet) {
            sel.fl.id = -1;
            sel.grobjFull = grobjPlanet;
        } else {
            FDupFleet(lpfl, &sel.fl);
            sel.grobjFull = grobjFleet | grobjPlanet;
        }

        if (!fAi) {
            FillPlanetProdLB(0, 0, 0);
            SendMessage(hwndPlanetProdLB, CB_GETCURSEL, 0, 0);
        }
    } else {
        InvalidateReport(1, 0);
        if (!FLookupFleet(iObjSel, &sel.fl))
            return;

        sel.pt.x = sel.fl.pt.x;
        sel.pt.y = sel.fl.pt.y;

        if (sel.fl.idPlanet == -1 || (sel.fl.idPlanet != sel.pl.id && !FLookupPlanet(sel.fl.idPlanet, &sel.pl))) {
            sel.pl.id = -1;
        }

        sel.grobjFull = (sel.pl.id != -1) | grobjFleet;
        sel.iwpAct = 0;

        if (!fAi) {
            FillOrdersLB();
            FillFleetCompLB();
            FillBattleDD(sel.fl.iplan + 1);
            idSkip = iObjSel;
            SendMessage(rghwndOrderDD[0], CB_SETCURSEL, sel.fl.lpplord[2].iordMax & 0xf, 0);
        }
    }

    sel.grobj = grobjNew;
    sel.id = iObjSel;
    gd.fSetMassMode = 0;
    gd.fSetRouteMode = 0;

    if (!fAi) {
        if (!fSameType) {
            for (i = 0; i < 13; i++)
                ShowWindow(rghwndBtn[i], 0);
            for (i = 0; i < 3; i++)
                ShowWindow(rghwndOrderDD[i], 0);
            ShowWindow(hwndOrderED, 0);
            ShowWindow(hwndShipDD, 0);
            ShowWindow(hwndBattleDD, 0);
            ShowWindow(hwndShipLB, 0);
            ShowWindow(hwndFleetCompLB, 0);
            ShowWindow(hwndPlanetProdLB, 0);
            ShowWindow(hwndRepCB, 0);
            for (i = 0; i < 19; i++) {
                rgrcRef[i].bottom = -6;
                rgrcRef[i].top = -5;
            }
        }

        FillShipDD(idSkip);

        if (!fSameType) {
            InvalidateRect(hwndPlanet, NULL, TRUE);
            if ((grbitScan & 0x10) && sel.grobj == grobjPlanet) {
                grbitScan &= ~0x10;
                InvalidateRect(hwndTb, NULL, TRUE);
            }
        } else {
            DrawPlanShip(0, 0x4fff);
        }

        SetPlanetTitleBar(hwndPlanet);

        if (gd.fTutorial)
            AdvanceTutor();
    }
}

void DrawProductionItem(HDC hdc, RECT *prc, char *psz, int16_t inflate, int16_t fSelected, int16_t fListbox) {
    HFONT    hfntSav;
    char    *pch;
    int16_t  ichT;
    COLORREF cr;
    int16_t  pctDmg;
    char     szT[20];
    RECT     rcIn;
    int16_t  ich;
    int16_t  fDoubleDraw;
    COLORREF crForeSav;
    int16_t  fFleet;
    RECT     rcDraw;
    int16_t  dx;
    HBRUSH   hbr;
    int16_t  fItalic;
    int16_t  cch;
    int16_t  bkSav;
    RECT     rc;

    /* debug symbols */
    /* label LDefCase @ MEMORY_PLANET:0x6269 */
    /* label LDefCaseSel @ MEMORY_PLANET:0x6337 */
    /* label LRightOut @ MEMORY_PLANET:0x6657 */

    /* TODO: implement */
}

void FillPlanetProdLB(HWND hwnd, PLPROD *lpplprod, PLANET *lppl) {
    bool    fMinimal;
    int16_t i;
    char    szTemp[80];
    char   *psz;
    char    ch;
    PROD   *lpprod;
    int16_t etaLast;
    int16_t etaFirst;

    fMinimal = (lppl != NULL);
    if (!fMinimal) {
        lppl = &sel.pl;
        if (hwnd == 0)
            hwnd = hwndPlanetProdLB;
        SendMessage(hwnd, LB_RESETCONTENT, 0, 0);
    }
    if (lpplprod == NULL)
        lpplprod = lppl->lpplprod;
    if (lpplprod == NULL || lpplprod->iprodMac == 0) {
        psz = PszGetCompressedString(idsQueueEmpty);
    } else {
        if (hwndProdDlg == 0)
            goto NoMsg;
        psz = PszGetCompressedString(idsTopQueue);
    }
    if (fMinimal) {
        if (psz != szWork)
            strcpy(szWork, psz);
    } else {
        SendMessage(hwnd, LB_ADDSTRING, 0, (LPARAM)psz);
    }
NoMsg:
    if (lpplprod != NULL) {
        lpprod = lpplprod->rgprod;
        for (i = 0; i < (int16_t)lpplprod->iprodMac; i++) {
            psz = PszNameProdItem(lpprod);
            EstimateItemProdSched(lppl, lpplprod, i, &etaFirst, &etaLast);
            if ((etaFirst == 0 && etaLast == 0) || (etaFirst == -1 && etaLast == -1)) {
                ch = '&';
            } else {
                if ((etaFirst < 2 || etaFirst > 99) && !(etaFirst == 100 && lpprod->grobj == grobjPlanet && lpprod->iItem <= 6)) {
                    if (etaFirst == 1 && etaLast == 1)
                        ch = '*';
                    else if (etaFirst < 100)
                        ch = '#';
                    else
                        ch = '!';
                } else {
                    ch = ' ';
                }
            }
            sprintf(szTemp, "%c%5d%s", ch, (int)lpprod->cItem, psz);
            if (lpprod->grobj == grobjPlanet && lpprod->iItem < 7) {
                szTemp[1] += 2;
                if (lpprod->iItem == iobjAlchemy)
                    szTemp[5] = '*';
            }
            if (lpprod->grobj == grobjPlanet && (lpprod->iItem == mdIdleTerraform || lpprod->iItem == iobjMinTerraform || lpprod->iItem == iobjMaxTerraform)) {
                szTemp[1] += 1;
            }
            if (fMinimal) {
                strcpy(szWork, szTemp);
                return;
            }
            SendMessage(hwnd, LB_ADDSTRING, 0, (LPARAM)szTemp);
            lpprod++;
        }
        if (fMinimal) {
            CchGetString(idsQueueEmpty, szWork);
        }
    }
}

void EnsureTileSize(int16_t fSmallTiles) {
    int16_t iMul;
    int16_t i;
    int16_t grobjSav;

    /* TODO: implement */
}

uint16_t ClickInPlanetOrders(POINT pt, int16_t sks, int16_t fCursor, int16_t fRightBtn) {
    int16_t i;
    int32_t rglQuan[3];
    int16_t iWarp;
    BTNT    btnt;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x55c5 */
    /* block (block) @ MEMORY_PLANET:0x5715 */
    /* block (block) @ MEMORY_PLANET:0x57e4 */

    /* TODO: implement */
    return 0;
}

void PlanetClick(int16_t x, int16_t y, int16_t sks, int16_t fRightBtn) {
    int16_t  bt;
    POINT    pt;
    int16_t  ctile;
    int16_t  dy;
    RECT     rcTitle;
    int16_t  i;
    int16_t  xRel;
    uint16_t iCol;
    int16_t  iCur;
    TILE    *prgtile;
    RECT     rc;
    HDC      hdc;
    TILE     tile;
    POINT    ptNew;
    BTNT     btnt;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x4a90 */
    /* block (block) @ MEMORY_PLANET:0x4bb8 */

    /* TODO: implement */
}
void SelectAdjPlanet(int16_t dInc, int16_t idPlanet) {
    PLANET *lpPlT;
    int16_t i;
    PLANET *lpPl;
    SCAN    scan;
    int16_t fWrap;

    /* debug symbols */
    /* label FinishUp @ MEMORY_PLANET:0x46f3 */

    /* TODO: implement */
}

void ReflowColumn(int16_t iCol, int16_t iTile, int16_t fRedraw) {
    HDC     hdc;
    int16_t yTop;
    int16_t ctile;
    int16_t i;
    int16_t grbit;
    TILE   *ptile;
    RECT    rc;

    /* TODO: implement */
}

#endif /* _WIN32 */
