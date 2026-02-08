
#include "globals.h"
#include "types.h"

#include "planet.h"
#include "race.h"
#include "save.h"
#include "strings.h"
#include "utilgen.h"
#include "msg.h"

/* globals */
int16_t rgRaceAdvDisPts[14] = {-235, -25, -159, -201, 40, -240, -155, 160, 240, 255, 325, 180, 70, 30};
int16_t rgRaceDisEnvPts[6] = {150, 330, 540, 780, 1050, 1380};
int16_t rgRacePrimaryTrait[10] = {40, 95, 45, 10, -100, -150, 120, 180, 90, -66};
char    rgRaceStatMax[16] = {25, 15, 25, 25, 25, 15, 25, 6, 2, 2, 2, 2, 2, 2, 9, 0};
char    rgRaceStatMin[16] = {7, 5, 5, 5, 5, 2, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0};

#ifdef _WIN32

char rgRW3IStat[7] = {0, 1, 2, 3, 4, 5, 6};
char rgRW3Spacing[7] = {4, 3, 3, 3, 3, 3, 3};
char rgRW3Width[7] = {-2, 2, 2, 2, -2, 2, 2};

#endif /* _WIN32 */

/* functions */

void SetRaceGrbit(PLAYER *pplr, RaceGrbit ibit, int16_t fSet) {
    uint32_t grMask;

    if (pplr == NULL) {
        return;
    }
    if (ibit < 0 || ibit >= 32) {
        /* The original code used a 32-bit mask here (16-bit helpers made it
         * look like a wider operation). */
        return;
    }
    grMask = (uint32_t)1u << (uint32_t)ibit;
    if (fSet) {
        pplr->grbitAttr |= grMask;
    } else {
        pplr->grbitAttr &= ~grMask;
    }
}

int16_t GetRaceGrbit(const PLAYER *pplr, const RaceGrbit ibit) {
    uint32_t grMask;

    if (pplr == NULL) {
        return 0;
    }
    if (ibit < 0 || ibit >= 32) {
        return 0;
    }
    grMask = (uint32_t)1u << (uint32_t)ibit;
    return (pplr->grbitAttr & grMask) ? 1 : 0;
}

int16_t CAdvantagePoints(PLAYER *pplr) {
    int     i;
    int16_t rgi[3];
    int32_t cPoints = 0;
    int16_t iSpread;
    int32_t lInnate;
    int16_t cCur;
    int16_t cGood;
    int16_t cBad;
    int16_t pctGrowth;
    int16_t raMajor;

    /* Decompile initializes cPoints to 0x672 (1650), which is 550*3. */
    cPoints = 550 * 3;

    BoundsCheckPlayer(pplr);
    raMajor = GetRaceStat(pplr, rsMajorAdv);

    /* Decompile: lInnate = LInnateRaceHabitability(pplr) / 2000 (via __aFldiv). */
    lInnate = LInnateRaceHabitability(pplr) / 2000;

    /*
     * Clamp pctIdealGrowth into [1, 20] per decompile:
     *  - values < 1 become 1
     *  - values > 20 become 20
     * If the stored value was out of range, decompile forces pctIdealGrowth to 1 and
     * sets the "hacker" flag (wFlags bit 0x10: wFlags = (wFlags & 0xffef) | 0x10).
     */
    iSpread = max(1, min(pctIdealGrowthMax, pplr->pctIdealGrowth));
    if (iSpread != pplr->pctIdealGrowth) {
        pplr->pctIdealGrowth = iSpread = 1;
        pplr->fHacker = fTrue;
    }

    /* Decompile keeps an unmodified copy of iSpread in sVar9 (used later as pctGrowth). */
    pctGrowth = iSpread;

    /*
     * Growth/“spread” point adjustments and iSpread remapping follow the decompile’s
     * three-tier structure:
     *  - iSpread < 6: add (6 - iSpread) * 0x1068 (4200) to cPoints (plus base 0x672).
     *  - 6 <= iSpread < 14: optional cPoints bump for iSpread in {6,7,8,9}, then
     *    remap iSpread: 5 + (iSpread - 5) * 2.
     *  - 14 <= iSpread < 20: remap iSpread: 0x15 + (iSpread - 13) * 3.
     *  - iSpread >= 20: remap iSpread to 0x2d (45).
     */
    if (iSpread > 5) {
        if (iSpread > 13) {
            if (iSpread < 20)
                iSpread = 5 + 8 * 2 + (iSpread - 13) * 3;
            else
                iSpread = 5 + 8 * 2 + 18 + 6;
        } else {
            if (iSpread == 6)
                cPoints += 1200L * 3;
            else if (iSpread == 7)
                cPoints += 750L * 3;
            else if (iSpread == 8)
                cPoints += 200L * 3;
            else if (iSpread == 9)
                cPoints += 75L * 3;

            iSpread = 5 + (iSpread - 5) * 2;
        }
    } else {
        /* Decompile: cPoints += (6 - iSpread) * 0x1068 when iSpread < 6. */
        cPoints += 1400L * 3 * (6 - iSpread);
    }

    /*
     * Decompile scales the habitability term by iSpread and divides by 24:
     *   lInnate = (lInnate * iSpread) / 24 (mul/div via helpers).
     * Then subtracts this from cPoints.
     */
    lInnate = lInnate * iSpread / 24;
    cPoints -= lInnate;

    /*
     * Decompile counts "immune" env axes as those with rgEnvVar[i] < 0.
     * For non-immune axes, it adds abs(rgEnvVar[i] - 50) * 4 to cPoints.
     */
    cGood = 0;
    for (i = 0; i < 3; i++) {
        if (pplr->rgEnvVar[i] >= 0)
            cPoints += abs(pplr->rgEnvVar[i] - 50) * 4;
        else
            cGood++;
    }

    /*
     * Decompile: if cGood > 1, subtract 0x96 (150) from cPoints.
     * (Comment in older source often describes this as 50 points per extra immunity.)
     */
    if (cGood > 1)
        cPoints -= 150;

    /*
     * Decompile applies an additional penalty when either rsFactOperate or rsFactProd > 10.
     * It uses:
     *   cOperate = max(1, rsFactOperate - 9)
     *   cProduce = max(1, rsFactProd - 9)
     * and multiplies cProduce by 3 for raCheapCol, else by 2.
     * Then subtracts either:
     *   (cOperate * (cProduce) * pctGrowth) / 2   if cGood >= 2
     *   (cOperate * (cProduce) * pctGrowth) / 9   otherwise
     */
    {
        int16_t cOperate = GetRaceStat(pplr, rsFactOperate);
        int16_t cProduce = GetRaceStat(pplr, rsFactProd);

        if (cOperate > 10 || cProduce > 10) {
            cOperate = max(1, cOperate - 9);
            cProduce = max(1, cProduce - 9);
            cProduce *= (raMajor == raCheapCol) ? 3 : 2;

            if (cGood >= 2)
                cPoints -= (int32_t)cOperate * (int32_t)cProduce * (int32_t)pctGrowth / 2;
            else
                cPoints -= (int32_t)cOperate * (int32_t)cProduce * (int32_t)pctGrowth / 9;
        }
    }

    /*
     * Resource generation (rsResGen) contribution per decompile:
     * clamp to max 25, then:
     *   <=7:  cPoints -= 2400
     *   ==8:  cPoints -= 1260
     *   ==9:  cPoints -= 600
     *   >10:  cPoints += 120 * (i - 10)
     */
    i = GetRaceStat(pplr, rsResGen);
    i = min(i, 25);
    if (i <= 7)
        cPoints -= 2400;
    else if (i == 8)
        cPoints -= 1260;
    else if (i == 9)
        cPoints -= 600;
    else if (i > 10)
        cPoints += 120 * (i - 10);

    /*
     * Decompile has a special-case for raMacintosh:
     *   add 0xd2 (210) to cPoints and skip the factory/mine efficiency blocks.
     */
    if (raMajor != raMacintosh) {
        /*
         * Factory efficiency block (rsFactProd/rsFactBuild/rsFactOperate):
         * decompile computes rgi[*] = 10 - stat and then forms cCur with a mix of
         * linear/quadratic terms, clamps/compresses high values, and adds extra
         * costs for very low iVar8 (high ColOp) and very low iVar7 (high FactProd).
         */
        rgi[0] = 10 - GetRaceStat(pplr, rsFactProd);
        rgi[1] = 10 - GetRaceStat(pplr, rsFactBuild);
        rgi[2] = 10 - GetRaceStat(pplr, rsFactOperate);

        cCur = 0;
        if (rgi[0] > 0)
            cCur += rgi[0] * 100;
        else
            cCur += rgi[0] * 121;

        if (rgi[1] < 0)
            cCur -= rgi[1] * 55;
        else
            cCur -= rgi[1] * rgi[1] * 60;

        if (rgi[2] > 0)
            cCur += rgi[2] * 40;
        else
            cCur += rgi[2] * 35;

        if (cCur > 700)
            cCur = 700 + (cCur - 700) / 3;

        /* Additional cCur adjustments when rgi[2] <= -7, matching the decompile tiers. */
        if (rgi[2] <= -7) {
            if (rgi[2] >= -11)
                cCur -= 30 * (-6 - rgi[2]);
            else if (rgi[2] >= -14)
                cCur -= 75 * 3 + 45 * (-12 - rgi[2]);
            else
                cCur -= 120 * 3;
        }

        /* Additional adjustment when rgi[0] <= -3 (high FactProd), per decompile. */
        if (rgi[0] <= -3)
            cCur -= (-2 - rgi[0]) * 20 * 3;

        cPoints += cCur;

        /* Decompile: if ibitRaceCheapFact set, subtract 175. */
        if (GetRaceGrbit(pplr, ibitRaceCheapFact))
            cPoints -= 175;

        /*
         * Mine efficiency block:
         * rgi = { 10 - MineProd, 3 - MineBuild, 10 - MineOperate }
         * and cCur is built with piecewise formulas matching the decompile.
         */
        rgi[0] = 10 - GetRaceStat(pplr, rsMineProd);
        rgi[1] = 3 - GetRaceStat(pplr, rsMineBuild);
        rgi[2] = 10 - GetRaceStat(pplr, rsMineOperate);

        cCur = 0;
        if (rgi[0] > 0)
            cCur += rgi[0] * 100;
        else
            cCur += rgi[0] * 169;

        if (rgi[1] <= 0)
            cCur -= -80 + rgi[1] * 65;
        else
            cCur -= 360;

        if (rgi[2] > 0)
            cCur += rgi[2] * 40;
        else
            cCur += rgi[2] * 35;

        cPoints += cCur;
    } else {
        cPoints += 210;
    }

    /* Primary racial trait cost: subtract rgRacePrimaryTrait[raMajor] (decompile uses (short*) indexing). */
    cPoints -= rgRacePrimaryTrait[raMajor];

    /*
     * Advantage/disadvantage traits:
     * decompile iterates i = 0..13 (i < 0xe), checks GetRaceGrbit(pplr, i),
     * tracks counts of negative vs non-negative rgRaceAdvDisPts[i], and adds
     * rgRaceAdvDisPts[i] into cPoints.
     */
    cGood = cBad = 0;
    for (i = 0; i <= ibitRaceLast; i++)
        if (GetRaceGrbit(pplr, i)) {
            if (rgRaceAdvDisPts[i] < 0)
                cBad++;
            else
                cGood++;
            cPoints += rgRaceAdvDisPts[i];
        }

    /* If total traits > 4: subtract (total * 10) * (total - 4), matching the decompile. */
    if (cBad + cGood > 4)
        cPoints -= ((cBad + cGood) * 10) * (cBad + cGood - 4);

    /* If (cGood - cBad) > 3: subtract 60 * ((cGood - cBad) - 3), per decompile. */
    if (cGood - cBad > 3)
        cPoints -= 60 * (cGood - cBad - 3);

    /* If (cBad - cGood) > 3: subtract 40 * ((cBad - cGood) - 3), per decompile. */
    if (cBad - cGood > 3)
        cPoints -= 40 * (cBad - cGood - 3);

    /*
     * No-advanced-scanner adjustment depends on raMajor:
     * raMassAccel: -280
     * raStealth:   -200
     * raNone:      -40
     */
    if (GetRaceGrbit(pplr, ibitRaceNoAdvScanner)) {
        if (raMajor == raMassAccel)
            cPoints -= 280;
        else if (raMajor == raStealth)
            cPoints -= 200;
        else if (raMajor == raNone)
            cPoints -= 40;
    }

    /* Tech bonus fields: decompile sums (GetRaceStat(pplr, rsTechBonusN) - 1) for N=1..6. */
    cCur = 0;
    for (i = rsTechBonus1; i <= rsTechBonus6; i++)
        cCur += (GetRaceStat(pplr, i) - 1);

    /*
     * If cCur > 0: subtract cCur*cCur*130 (0x82) and then apply special-case add-backs
     * for cCur == 6 and cCur == 5 per decompile constants.
     * If cCur < 0: add rgRaceDisEnvPts[-cCur - 1], and if (-cCur > 4) and rsResGen < 10,
     * subtract 190.
     */
    if (cCur > 0) {
        cPoints -= cCur * cCur * 130;
        if (cCur == 6)
            cPoints += (36 - 25) * 130;
        else if (cCur == 5)
            cPoints += (25 - 21) * 130;
    } else if (cCur < 0) {
        cPoints += rgRaceDisEnvPts[-cCur - 1];
        if (-cCur > 4 && GetRaceStat(pplr, rsResGen) < 10)
            cPoints -= 190;
    }

    /* Decompile: if ibitRaceTech3 set, subtract 180. */
    if (GetRaceGrbit(pplr, ibitRaceTech3))
        cPoints -= 180;

    /* Decompile: if raMajor == raMacintosh and rsTechBonus1 == 2, subtract 100. */
    if (raMajor == raMacintosh && GetRaceStat(pplr, rsTechBonus1) == 2)
        cPoints -= 100;

    /* Decompile returns cPoints / 3 (via __aFldiv). */
    return (int16_t)(cPoints / 3);
}

int16_t SetRaceStat(PLAYER *pplr, int16_t iStat, int16_t iVal) {
    int16_t min = (int16_t)(int8_t)rgRaceStatMin[iStat];
    int16_t max = (int16_t)(int8_t)rgRaceStatMax[iStat];

    if (iVal < min)
        iVal = min;
    if (iVal > max)
        iVal = max;

    pplr->rgAttr[iStat] = (int8_t)iVal;
    return iVal;
}

int16_t PctTrueMaxGrowth(int16_t iplr) {
    int16_t ideal = (int16_t)rgplr[iplr].pctIdealGrowth;

    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == raCheapCol) {
        /* Cheap Colonists: double the ideal growth (matches `<< 1` in original) */
        return ideal * 2;
    }

    return ideal;
}

int16_t GetRaceStat(const PLAYER *pplr, const int16_t iStat) { return pplr->rgAttr[iStat]; }

uint16_t IRaceChecksum(PLAYER *pplr) {
    uint16_t        ick = 0;
    const uint16_t *p = (const uint16_t *)pplr;

#define PLAYER_CHECKSUM_BYTES 192

    for (int i = 0; i < PLAYER_CHECKSUM_BYTES / 2; i++)
        ick ^= p[i];

    return ick;
}

void BoundsCheckPlayer(PLAYER *pplr) {
    int i;

    for (i = 0; i < 3; i++) {
        /* Immune axis: min == -1 forces max == -1 and ideal == -1 */
        if (pplr->rgEnvVarMin[i] == -1) {
            if (pplr->rgEnvVarMax[i] != -1 || pplr->rgEnvVar[i] != -1) {
                pplr->rgEnvVar[i] = -1;
                pplr->rgEnvVarMax[i] = -1;
                pplr->fHacker = 1;
            }
            continue;
        }

        /* Clamp min/max into [0..100] */
        if (pplr->rgEnvVarMin[i] < 0) {
            pplr->rgEnvVarMin[i] = 0;
            pplr->fHacker = 1;
        }
        if (pplr->rgEnvVarMin[i] > 100) {
            pplr->rgEnvVarMin[i] = 100;
            pplr->fHacker = 1;
        }
        if (pplr->rgEnvVarMax[i] > 100) {
            pplr->rgEnvVarMax[i] = 100;
            pplr->fHacker = 1;
        }

        /* Ensure max >= min */
        if (pplr->rgEnvVarMax[i] < pplr->rgEnvVarMin[i]) {
            pplr->rgEnvVarMax[i] = pplr->rgEnvVarMin[i];
            pplr->fHacker = 1;
        }

        /* Force ideal to midpoint: min + (max - min) / 2 */
        {
            int minv = pplr->rgEnvVarMin[i];
            int maxv = pplr->rgEnvVarMax[i];
            int mid = minv + (maxv - minv) / 2;

            if (pplr->rgEnvVar[i] != mid) {
                pplr->rgEnvVar[i] = mid;
                pplr->fHacker = 1;
            }
        }
    }

    /* Cap pctIdealGrowth at 20 */
    if (pplr->pctIdealGrowth > pctIdealGrowthMax) {
        pplr->pctIdealGrowth = pctIdealGrowthMax;
        pplr->fHacker = 1;
    }

    /* Clamp race attributes to per-stat min/max tables */
    for (i = 0; i < 16; i++) {
        int minv = rgRaceStatMin[i];
        int maxv = rgRaceStatMax[i];

        if (pplr->rgAttr[i] < minv) {
            pplr->rgAttr[i] = minv;
            pplr->fHacker = 1;
        }
        if (pplr->rgAttr[i] > maxv) {
            pplr->rgAttr[i] = maxv;
            pplr->fHacker = 1;
        }
    }
}

void CreateRandomRace(PLAYER *pplr) {
    int16_t cPts;
    int16_t i;
    int16_t cPass;
    int16_t j;
    int16_t iVal;
    int16_t dAwayNew;
    int16_t dAwayCur;
    int16_t k;
    PLAYER  plrT;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x60a0 */
    /* block (block) @ MEMORY_RACE:0x6539 */

    /* TODO: implement */
}

int32_t LInnateRaceHabitability(PLAYER *pplr) {
    int16_t hasTT;
    int16_t pctTerra;
    int16_t iTerra;
    int16_t i;
    int16_t j;
    int16_t k;
    int16_t iTry;
    int16_t iDelta;
    int16_t rgBase[3];
    int16_t rgInc[3];
    int16_t rgSteps[3];
    int16_t rgDelta[3];
    PLANET  pl;
    PLAYER  plrT;

    /* matches initial MOVSW.REP (copy rgplr[0] into plrT) */
    plrT = rgplr[0];

    /* lInnate = 0.0 via FILD 0 / FSTP */
    double lInnate = 0.0;

    /* hasTT = GetRaceGrbit(pplr, ibitRaceTT) (asm pushes 1) */
    hasTT = GetRaceGrbit(pplr, ibitRaceTT);

    /* matches MOVSW.REP (copy *pplr into rgplr[0]) */
    rgplr[0] = *pplr;

    /* rgDelta[0..2] = 0 */
    rgDelta[0] = 0;
    rgDelta[1] = 0;
    rgDelta[2] = 0;

    for (iTerra = 0; iTerra < 3; iTerra = (int16_t)(iTerra + 1)) {
        /* pctTerra selection matches the branch chain at 4cde..4d2c */
        if (iTerra == 0) {
            pctTerra = 0;
        } else if (iTerra == 1) {
            pctTerra = (hasTT != 0) ? 8 : 5;
        } else {
            pctTerra = (hasTT != 0) ? 17 : 15;
        }

        /* for each env axis, validate and compute base/inc/steps */
        for (i = 0; i < 3; i = (int16_t)(i + 1)) {
            /* matches the three “>100” checks and three “<0” checks, then the “all == -1?” gate */
            if ((pplr->rgEnvVar[i] > 100) || (pplr->rgEnvVarMin[i] > 100) || (pplr->rgEnvVarMax[i] > 100) || (pplr->rgEnvVar[i] < 0) ||
                (pplr->rgEnvVarMin[i] < 0) || (pplr->rgEnvVarMax[i] < 0)) {

                if (!((pplr->rgEnvVar[i] == -1) && (pplr->rgEnvVarMin[i] == -1) && (pplr->rgEnvVarMax[i] == -1))) {
                    /* set all three to -1 (asm writes 0xFF to +0x16/+0x13/+0x10) */
                    pplr->rgEnvVarMax[i] = -1;
                    pplr->rgEnvVarMin[i] = -1;
                    pplr->rgEnvVar[i] = -1;

                    /* was: (wFlags & 0xFFEF) | 0x0010 */
                    pplr->fHacker = 1;

                    /* matches the subsequent MOVSW.REP pplr -> rgplr[0] */
                    rgplr[0] = *pplr;
                }
            }

            if (pplr->rgEnvVar[i] < 0) {
                rgBase[i] = 50;
                rgInc[i] = 11;
                rgSteps[i] = 1;
            } else {
                rgBase[i] = (int16_t)(pplr->rgEnvVarMin[i] - pctTerra);
                if (rgBase[i] < 0) {
                    rgBase[i] = 0;
                }

                iTry = (int16_t)(pplr->rgEnvVarMax[i] + pctTerra);
                if (iTry > 100) {
                    iTry = 100;
                }

                rgInc[i] = (int16_t)(iTry - rgBase[i]);
                rgSteps[i] = 11;
            }
        }

        /* per-iTerra accumulator (bp+fed0 in asm) */
        double terraSum = 0.0;

        for (i = 0; i < rgSteps[0]; i = (int16_t)(i + 1)) {
            if ((i == 0) || (rgSteps[0] <= 1)) {
                iTry = rgBase[0];
            } else {
                iTry = (int16_t)((i * rgInc[0]) / (rgSteps[0] - 1) + rgBase[0]);
            }

            /* delta adjust for axis0 when iTerra != 0 and envVar0 >= 0 */
            if ((iTerra != 0) && (pplr->rgEnvVar[0] >= 0)) {
                iDelta = (int16_t)(pplr->rgEnvVar[0] - iTry);

                if ((int16_t)abs((int)iDelta) <= pctTerra) {
                    iDelta = 0;
                } else if (iDelta < 0) {
                    iDelta = (int16_t)(iDelta + pctTerra);
                } else {
                    iDelta = (int16_t)(iDelta - pctTerra);
                }

                rgDelta[0] = iDelta;
                iTry = (int16_t)(pplr->rgEnvVar[0] - iDelta);
            }

            pl.rgEnvVar[0] = (uint8_t)iTry;

            /* per-i accumulator (this is l2 in asm) */
            double iSum = 0.0;

            for (j = 0; j < rgSteps[1]; j = (int16_t)(j + 1)) {
                if ((j == 0) || (rgSteps[1] <= 1)) {
                    iTry = rgBase[1];
                } else {
                    iTry = (int16_t)((j * rgInc[1]) / (rgSteps[1] - 1) + rgBase[1]);
                }

                /* delta adjust for axis1 when iTerra != 0 and envVar1 >= 0 */
                if ((iTerra != 0) && (pplr->rgEnvVar[1] >= 0)) {
                    iDelta = (int16_t)(pplr->rgEnvVar[1] - iTry);

                    if ((int16_t)abs((int)iDelta) <= pctTerra) {
                        iDelta = 0;
                    } else if (iDelta < 0) {
                        iDelta = (int16_t)(iDelta + pctTerra);
                    } else {
                        iDelta = (int16_t)(iDelta - pctTerra);
                    }

                    rgDelta[1] = iDelta;
                    iTry = (int16_t)(pplr->rgEnvVar[1] - iDelta);
                }

                pl.rgEnvVar[1] = (uint8_t)iTry;

                /* 32-bit accumulator of weighted squares (bp+fede/fee0 in asm) */
                uint32_t acc = 0;

                for (k = 0; k < rgSteps[2]; k = (int16_t)(k + 1)) {
                    if ((k == 0) || (rgSteps[2] <= 1)) {
                        iTry = rgBase[2];
                    } else {
                        iTry = (int16_t)((k * rgInc[2]) / (rgSteps[2] - 1) + rgBase[2]);
                    }

                    /* delta adjust for axis2 when iTerra != 0 and envVar2 >= 0 */
                    if ((iTerra != 0) && (pplr->rgEnvVar[2] >= 0)) {
                        iDelta = (int16_t)(pplr->rgEnvVar[2] - iTry);

                        if ((int16_t)abs((int)iDelta) <= pctTerra) {
                            iDelta = 0;
                        } else if (iDelta < 0) {
                            iDelta = (int16_t)(iDelta + pctTerra);
                        } else {
                            iDelta = (int16_t)(iDelta - pctTerra);
                        }

                        rgDelta[2] = iDelta;
                        iTry = (int16_t)(pplr->rgEnvVar[2] - iDelta);
                    }

                    pl.rgEnvVar[2] = (uint8_t)iTry;

                    /* pctDesire is sign-extended short in DX:AX (CWD after call) */
                    int32_t pctDesire = (int16_t)PctPlanetDesirability(&pl, 0);

                    /* deltaSum and optional subtraction (matches 5227..527a) */
                    {
                        int16_t deltaSum = (int16_t)(rgDelta[0] + rgDelta[1] + rgDelta[2]);
                        if (deltaSum > pctTerra) {
                            int16_t sub = (int16_t)(deltaSum - pctTerra);
                            pctDesire -= (int32_t)sub;
                            if (pctDesire < 0) {
                                pctDesire = 0;
                            }
                        }
                    }

                    /* square via __aFulmul(low32) */
                    {
                        uint32_t u = (uint32_t)pctDesire;
                        uint32_t sq = (uint32_t)((uint64_t)u * (uint64_t)u);

                        uint32_t w;
                        if (iTerra == 0) {
                            w = (uint32_t)((uint64_t)sq * 7u);
                        } else if (iTerra == 1) {
                            w = (uint32_t)((uint64_t)sq * 5u);
                        } else {
                            w = (uint32_t)((uint64_t)sq * 6u);
                        }

                        acc = (uint32_t)(acc + w);
                    }
                }

                /* post-k scaling of acc into l1 (matches 531b..5375 then FILD+add into iSum) */
                {
                    int32_t l1;
                    if (pplr->rgEnvVar[2] >= 0) {
                        /* l1 = (__aFulmul(acc, rgInc[2]) low32) / 100 (signed trunc) */
                        uint32_t prod = (uint32_t)((uint64_t)acc * (uint16_t)rgInc[2]);
                        l1 = (int32_t)prod;
                        l1 = (int32_t)(l1 / 100);
                    } else {
                        /* l1 = __aFulmul(acc, 11) low32 */
                        l1 = (int32_t)(uint32_t)((uint64_t)acc * 11u);
                    }
                    iSum += (double)l1;
                }
            }

            /* after j loop: scale iSum by axis1 rule (matches 538d..53f6) */
            if (pplr->rgEnvVar[1] >= 0) {
                iSum = iSum * (double)rgInc[1] / 100.0;
            } else {
                iSum = iSum * 11.0;
            }

            terraSum += iSum;
        }

        /* after i loop: scale terraSum by axis0 rule (matches 5409..5476) */
        if (pplr->rgEnvVar[0] >= 0) {
            terraSum = terraSum * (double)rgInc[0] / 100.0;
        } else {
            terraSum = terraSum * 11.0;
        }

        lInnate += terraSum;
    }

    /* restore rgplr[0] if caller wasn't already passing &rgplr[0] (matches 5496..54b1) */
    if (pplr != &rgplr[0]) {
        rgplr[0] = plrT;
    }

    /* return __ftol(lInnate/10.0 + 0.5) (matches 54b1..54c6) */
    return (int32_t)floor(lInnate / 10.0 + 0.5);
}

int16_t RaMajor(int16_t iplr) {
    /* rsMajorAdv encodes the primary race attribute (HE/SS/WM/... in Stars!). */
    return GetRaceStat(&rgplr[iplr], rsMajorAdv);
}

#ifdef _WIN32

INT_PTR CALLBACK RaceWizardDlg6(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HDC         hdc;
    PAINTSTRUCT ps;
    int16_t     cch;
    RECT        rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x3dd9 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg5(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HWND        hwndCtl;
    HDC         hdc;
    PAINTSTRUCT ps;
    int16_t     cch;
    RECT        rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x379d */
    /* block (block) @ MEMORY_RACE:0x38e5 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg4(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HDC         hdc;
    char        szT[600];
    int16_t     ids;
    PAINTSTRUCT ps;
    int16_t     cch;
    RECT        rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x3338 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg3(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HDC         hdc;
    POINT       pt;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x28ac */
    /* block (block) @ MEMORY_RACE:0x28ef */
    /* block (block) @ MEMORY_RACE:0x2927 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg2(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    HDC         hdc;
    int16_t     iVar;
    int16_t     yTop;
    POINT       pt;
    int16_t     dy;
    int16_t     dxMiddle;
    int16_t     dxLabel;
    int16_t     cch;
    char        szTemp[20];
    HFONT       hfontSav;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x106f */
    /* block (block) @ MEMORY_RACE:0x155e */
    /* block (block) @ MEMORY_RACE:0x159d */
    /* block (block) @ MEMORY_RACE:0x15e0 */
    /* block (block) @ MEMORY_RACE:0x16ac */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg1(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    int16_t     i;
    RECT        rc;
    int16_t     iPlrBmp;
    int16_t     iOffset;
    PLAYER     *pplr;
    HWND        hwndCB;
    POINT       pt;
    HDC         hdc;
    int16_t     j;
    char       *psz;
    uint8_t     k;
    BTNT        btnt;
    int16_t     bt;
    RECT       *prc;
    char        szBuf[32];
    int16_t     iDir;
    int16_t     iCur;
    PAINTSTRUCT ps;
    int16_t     cch;
    RECT        rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x03bb */
    /* block (block) @ MEMORY_RACE:0x0699 */
    /* block (block) @ MEMORY_RACE:0x06f7 */
    /* block (block) @ MEMORY_RACE:0x08ef */
    /* block (block) @ MEMORY_RACE:0x0937 */
    /* block (block) @ MEMORY_RACE:0x0c31 */
    /* block (block) @ MEMORY_RACE:0x0c76 */
    /* block (block) @ MEMORY_RACE:0x0daa */
    /* block (block) @ MEMORY_RACE:0x0e66 */

    /* TODO: implement */
    return 0;
}

void DrawRaceAdvantagePoints(HDC hdc, RECT *prc, PLAYER *pplr) {
    TEXTMETRIC tm;
    LOGFONT   *plf;
    COLORREF   crBkSav;
    int16_t    bkMode;
    int16_t    dyBig;
    char       szAdvantage[32];
    int16_t    c;
    COLORREF   crSav;
    HFONT      hfont;
    int16_t    dx;
    int16_t    iPts;
    int16_t    cch;
    RECT       rc;
    HFONT      hfontSav;

    /* TODO: implement */
}
int16_t RaceCreationWizard(HWND hwndParent, int16_t fReadOnly, int16_t fDontWrite) {
    int16_t mdRet;
    int16_t (*lpProc)(void);
    RECT    rgrcStack[17];
    int16_t cpts;

    /* debug symbols */
    /* label Step2 @ MEMORY_RACE:0x007d */
    /* label Step3 @ MEMORY_RACE:0x00ea */
    /* label Step4 @ MEMORY_RACE:0x0157 */
    /* label Step5 @ MEMORY_RACE:0x01c4 */
    /* label Step6 @ MEMORY_RACE:0x0231 */
    /* label Step1 @ MEMORY_RACE:0x001c */
    /* label Finish @ MEMORY_RACE:0x029e */

    /* TODO: implement */
    return 0;
}

void DrawRace3(HWND hwnd, HDC hdc, int16_t iDraw) {
    int16_t  dxItem;
    int16_t  idsT;
    int16_t  fMacintosh;
    int16_t  yTop;
    int16_t  bt;
    int16_t  ids;
    COLORREF crBkSav;
    int16_t  bkMode;
    int16_t  fCreatedDC;
    int16_t  dxkT;
    int16_t  i;
    int16_t  irc;
    int16_t  dxDig;
    int16_t  dx;
    int16_t  cch;
    RECT     rc;

    /* TODO: implement */
}

void InvalidateAdvPtsRect(HWND hwnd) {
    HDC        hdc;
    TEXTMETRIC tm;
    LOGFONT   *plf;
    int16_t    dyBig;
    HFONT      hfont;
    int16_t    dx;
    RECT       rc;
    HFONT      hfontSav;

    /* TODO: implement */
}

void SetRCWTitle(HWND hwnd, int16_t iStep) {
    char    szBuf[50];
    int16_t cch;

    /* TODO: implement */
}

void DrawRace2(HWND hwnd, HDC hdc, int16_t iDraw) {
    int16_t iPit;
    int16_t bt;
    int16_t iMax;
    char    szT[32];
    int16_t dy;
    int16_t iMin;
    int16_t bkMode;
    int16_t fCreatedDC;
    int16_t xRLabel;
    int16_t i;
    int16_t iMod;
    char   *psz;
    int16_t dx;
    int16_t cch;
    int16_t bt1;
    RECT    rc;
    int32_t l2;
    int16_t iStore;
    int32_t l;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x1d2d */
    /* block (block) @ MEMORY_RACE:0x1e61 */

    /* TODO: implement */
}

int16_t FTrackRaceDlg3(HWND hwnd, POINT pt, int16_t kbd) {
    BTNT    btnt;
    int16_t bt;
    int16_t dShift;
    int16_t i;
    int16_t irc;
    int16_t iMod;
    int16_t iStat;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x3073 */

    /* TODO: implement */
    return 0;
}

int16_t FTrackRaceDlg2(HWND hwnd, POINT pt, int16_t kbd) {
    BTNT    btnt;
    int16_t bt;
    int16_t dShift;
    char    iMax;
    char    iMin;
    int16_t i;
    int16_t irc;
    int16_t iMod;
    char   *psz;
    int16_t dWidth;
    int16_t dx;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x252b */

    /* TODO: implement */
    return 0;
}

int16_t IrcRaceDlgHitTest(POINT pt) {
    int16_t i;

    /* TODO: implement */
    return 0;
}

int16_t FSaveRace(char *szFileSuggest, PLAYER *pplr) {
    int16_t       fRet;
    char         *sz;
    OPENFILENAMEA ofn;
    char          szFile[256];
    uint16_t      i;
    char          szFilter[256];
    char          szDirName[256];
    char          szFileTitle[256];
    uint16_t      icksum;

    if (szFileSuggest == NULL) {
        szFile[0] = '\0';
    } else {
        strcpy(szFile, szFileSuggest);
    }

    szDirName[0] = '\0';

    CchGetString(idsStarsRaceFilesR, szFilter);
    for (i = 0; szFilter[i] != '\0'; i++) {
        if (szFilter[i] == '|') {
            szFilter[i] = '\0';
        }
    }

    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwndRaceParent;
    ofn.lpstrFilter = szFilter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = (uint32_t)sizeof(szFile);
    ofn.lpstrFileTitle = szFileTitle;
    ofn.nMaxFileTitle = (uint32_t)sizeof(szFileTitle);
    ofn.lpstrInitialDir = szDirName;
    ofn.lpstrDefExt = "r1";
    ofn.Flags = 0x00008806;

    if (GetSaveFileNameA(&ofn) == 0) {
        fRet = 0;
    } else {
        fRet = FCreateFile(dtRace, -1, szFile);
        if (fRet == 0) {
            Error(idsStarsUnableSaveRaceDataFilePlease);
            fRet = 0;
        } else {
            WriteRtPlr(pplr, NULL);
            icksum = IRaceChecksum(pplr);
            WriteRt(rtEOF, 2, &icksum);
            StreamClose();
            strcpy((char *)szRaceFile, szFile + ofn.nFileOffset);
            fRet = 1;
        }
    }

    return fRet;
}

#endif /* _WIN32 */
