/**
 * race_advantage_cleaned.c - Stars! Race Advantage Points Calculator (Cleaned)
 *
 * Cleaned decompilation from stars.exe 2.60j RC3
 * Original function: RACE::CAdvantagePoints @ 10e0:444c
 *
 * This function calculates the "advantage points" for a race configuration.
 * A valid race must have at least 500 points (after division by 3).
 * If a race has fewer points, it indicates the race file was illegally modified.
 *
 * The race wizard shows this as "Leftover Advantage Points" which must be >= 0.
 * Internally: AdvantagePoints = (RawPoints / 3) - 500, shown to user as >= 0.
 */

#include "punishment_cleaned.h"

/* ============================================================================
 * RACE STAT INDICES (rsXxx)
 * ============================================================================
 * These index into the player's race statistics array via GetRaceStat()
 */

#define rsResGen        0   /* Colonists per resource (1000 = 1000 colonists/resource) */
#define rsFactProd      1   /* Factory production (10 = 10 resources per 10 factories) */
#define rsFactBuild     2   /* Factory build cost (in resources) */
#define rsFactOperate   3   /* Factories operable per 10k colonists */
#define rsMineProd      4   /* Mine production (10 = 10 kT per 10 mines) */
#define rsMineBuild     5   /* Mine build cost (in resources) */
#define rsMineOperate   6   /* Mines operable per 10k colonists */
/* indices 8-13 are tech levels */
#define rsTechEnergy    8
#define rsTechWeapons   9
#define rsTechPropulsion 10
#define rsTechConstruction 11
#define rsTechElectronics 12
#define rsTechBiotech   13
#define rsMajorAdv      14  /* Primary Racial Trait (PRT) */
#define rsTechBonus1    15  /* Tech bonus field 1 */

/* ============================================================================
 * PRIMARY RACIAL TRAITS (PRT) - rsMajorAdv values
 * ============================================================================ */

#define PRT_HE   0   /* Hyper Expansion */
#define PRT_SS   1   /* Super Stealth */
#define PRT_WM   2   /* War Monger */
#define PRT_CA   3   /* Claim Adjuster */
#define PRT_IS   4   /* Inner Strength */
#define PRT_SD   5   /* Space Demolition */
#define PRT_PP   6   /* Packet Physics */
#define PRT_IT   7   /* Interstellar Traveler */
#define PRT_AR   8   /* Alternate Reality */
#define PRT_JOAT 9   /* Jack of All Trades */

/* ============================================================================
 * LESSER RACIAL TRAITS (LRT) - bit indices for GetRaceGrbit()
 * ============================================================================ */

#define ibitRaceIFE          0   /* Improved Fuel Efficiency */
#define ibitRaceTT           1   /* Total Terraforming */
#define ibitRaceARM          2   /* Advanced Remote Mining */
#define ibitRaceISB          3   /* Improved Starbases */
#define ibitRaceGR           4   /* Generalized Research */
#define ibitRaceUR           5   /* Ultimate Recycling */
#define ibitRaceNRSE         6   /* No Ram Scoop Engines */
#define ibitRaceCE           7   /* Cheap Engines */
#define ibitRaceOBRM         8   /* Only Basic Remote Mining */
#define ibitRaceNAS          9   /* No Advanced Scanners */
#define ibitRaceLSP          10  /* Low Starting Population */
#define ibitRaceBET          11  /* Bleeding Edge Technology */
#define ibitRaceRS           12  /* Regenerating Shields */
#define ibitRaceCheapFact    13  /* Cheap Factories (from factory efficiency) */

/* Aliases used in code */
#define ibitRaceNoAdvScanner  ibitRaceNAS
#define ibitRaceTech3         ibitRaceBET  /* 3% tech cost increase per level */

/* ============================================================================
 * POINT CONSTANTS
 * ============================================================================ */

#define BASE_POINTS           1650   /* 0x672 - Starting points */
#define MIN_VALID_POINTS      500    /* Minimum for valid race (after /3) */
#define IMMUNE_ENV_PENALTY    150    /* 0x96 - Penalty for 2+ immune environments */

/* Growth rate point multiplier for low growth */
#define GROWTH_POINT_MULTIPLIER  4200  /* 0x1068 */

/* Growth rate base points lookup (for rates 6-9) */
static const int16_t growthBasePoints[] = {
    1650,   /* growth 5 (base, not used) */
    1650,   /* growth 6: actually computed differently */
    3900,   /* growth 7: 0xF3C */
    2250,   /* growth 8: 0x8CA */
    1875    /* growth 9: 0x753 */
};

/* ============================================================================
 * EXTERNAL FUNCTIONS
 * ============================================================================ */

extern int16_t GetRaceStat(PLAYER *pplr, int16_t stat);
extern int16_t GetRaceGrbit(PLAYER *pplr, int16_t bit);
extern int16_t LInnateRaceHabitability(PLAYER *pplr);
extern void    BoundsCheckPlayer(PLAYER *pplr);
extern int16_t _abs(int16_t val);

/* External point tables */
extern int16_t rgPRTCosts[];       /* PRT point costs */
extern int16_t rgLRTCosts[];       /* LRT point costs (positive = good, negative = bad) */
extern int16_t rgTechBonusTable[]; /* Tech level bonus point table */

/* ============================================================================
 * CAdvantagePoints - Calculate race advantage points
 * ============================================================================
 *
 * @param pplr  Pointer to player structure containing race data
 * @return      Advantage points (must be >= 500 for valid race)
 *
 * The calculation considers:
 *   1. Growth rate (lower = more points to spend elsewhere)
 *   2. Habitability (narrower range = more points)
 *   3. Factory efficiency (production, cost, operability)
 *   4. Mine efficiency (production, cost, operability)
 *   5. Resource generation rate
 *   6. Primary Racial Trait (PRT) cost
 *   7. Lesser Racial Traits (LRT) costs/bonuses
 *   8. Starting tech levels
 */
int16_t CAdvantagePoints(PLAYER *pplr)
{
    int32_t points;
    int16_t prt;              /* Primary Racial Trait */
    int16_t growthRate;       /* Growth rate percentage (1-20) */
    int16_t spreadIndex;      /* Growth spread index for habitability calc */
    int16_t immuneCount;      /* Number of immune environment variables */
    int16_t i;

    /* Factory/mine stats relative to baseline of 10 */
    int16_t factProdDelta;    /* 10 - factory production */
    int16_t factBuildDelta;   /* 10 - factory build cost */
    int16_t factOperateDelta; /* 10 - factories operable */
    int16_t mineProdDelta;
    int16_t mineBuildStat;
    int16_t mineOperateDelta;

    int16_t factoryPoints;
    int16_t minePoints;
    int16_t resGen;

    int16_t goodTraits, badTraits;  /* LRT counts */
    int16_t techSum;                /* Sum of starting tech levels */

    /* Validate player pointer */
    BoundsCheckPlayer(pplr);

    /* Get Primary Racial Trait */
    prt = GetRaceStat(pplr, rsMajorAdv);

    /* -----------------------------------------------------------------
     * SECTION 1: Growth Rate Points
     * -----------------------------------------------------------------
     * Lower growth rates give more points to spend elsewhere.
     * Growth rate is capped at 1-20%.
     */
    growthRate = pplr->pctIdealGrowth;

    /* Cap growth rate to valid range */
    if (growthRate > 20) {
        growthRate = 20;
    }
    if (growthRate < 1) {
        growthRate = 1;
    }

    /* Check if growth rate was modified (hacker detection) */
    if (growthRate != pplr->pctIdealGrowth) {
        /* Force to minimum and set hacker flag */
        growthRate = 1;
        pplr->pctIdealGrowth = 1;
        pplr->flags43 = (pplr->flags43 & ~PLAYER_FLAG_HACKER) | PLAYER_FLAG_HACKER;
    }

    /* Calculate base points from growth rate */
    if (growthRate < 6) {
        /* Very low growth: bonus points */
        points = BASE_POINTS + (int32_t)(6 - growthRate) * GROWTH_POINT_MULTIPLIER;
        spreadIndex = growthRate;
    }
    else if (growthRate < 14) {
        /* Medium growth: lookup table for base points */
        if (growthRate == 6) {
            points = 1655;  /* Special case */
        }
        else if (growthRate == 7) {
            points = 3900;
        }
        else if (growthRate == 8) {
            points = 2250;
        }
        else if (growthRate == 9) {
            points = 1875;
        }
        else {
            points = BASE_POINTS;  /* Default for 10-13 */
        }
        /* Spread index calculation for medium growth */
        spreadIndex = (growthRate - 5) * 2 + 5;
    }
    else if (growthRate < 20) {
        /* High growth: reduced points */
        points = BASE_POINTS;
        spreadIndex = (growthRate - 13) * 3 + 21;
    }
    else {
        /* Maximum growth (20%) */
        points = BASE_POINTS;
        spreadIndex = 45;
    }

    /* -----------------------------------------------------------------
     * SECTION 2: Habitability Points
     * -----------------------------------------------------------------
     * Calculate innate habitability and adjust points based on
     * how narrow/wide the habitability range is.
     */
    int32_t innateHab = LInnateRaceHabitability(pplr);
    innateHab = innateHab / 2000;  /* Scale down */

    /* Subtract habitability cost based on spread */
    points -= (innateHab * spreadIndex) / 24;

    /* Count immune environments and adjust for non-immune ranges */
    immuneCount = 0;
    for (i = 0; i < 3; i++) {
        if (pplr->rgEnvVar[i] < 0) {
            /* Immune to this environment */
            immuneCount++;
        }
        else {
            /* Not immune - narrower range = more points */
            int16_t deviation = _abs(pplr->rgEnvVar[i] - 50);
            points += deviation * 4;
        }
    }

    /* Penalty for multiple immunities */
    if (immuneCount > 1) {
        points -= IMMUNE_ENV_PENALTY;
    }

    /* -----------------------------------------------------------------
     * SECTION 3: Factory Efficiency Points
     * -----------------------------------------------------------------
     * Higher than baseline factory stats cost points.
     */
    int16_t factOperate = GetRaceStat(pplr, rsFactOperate);
    int16_t factProd = GetRaceStat(pplr, rsFactProd);

    if (factOperate > 10 || factProd > 10) {
        /* Calculate excess over baseline */
        factOperateDelta = (factOperate > 10) ? factOperate - 9 : 1;
        factProdDelta = (factProd > 10) ? factProd - 9 : 1;

        /* Multiplier based on PRT */
        int16_t prtMult = (prt == 0) ? 3 : 2;

        /* Cost based on immunities */
        int32_t factCost;
        if (immuneCount < 2) {
            factCost = ((int32_t)factOperateDelta * prtMult * factProdDelta * growthRate) / 9;
        }
        else {
            factCost = ((int32_t)factOperateDelta * prtMult * factProdDelta * growthRate) / 2;
        }
        points -= factCost;
    }

    /* -----------------------------------------------------------------
     * SECTION 4: Resource Generation Points
     * -----------------------------------------------------------------
     */
    resGen = GetRaceStat(pplr, rsResGen);
    if (resGen > 24) {
        resGen = 25;  /* Cap at 25 */
    }

    if (resGen < 8) {
        points -= 2400;  /* 0x960 - Heavy penalty for very low */
    }
    else if (resGen == 8) {
        points -= 1260;  /* 0x4EC */
    }
    else if (resGen == 9) {
        points -= 600;
    }
    else if (resGen > 10) {
        points += (resGen - 10) * 120;  /* 0x78 = 120 */
    }

    /* -----------------------------------------------------------------
     * SECTION 5: Factory/Mine Detailed Stats (non-AR races)
     * -----------------------------------------------------------------
     */
    if (prt == PRT_AR) {
        /* Alternate Reality gets a fixed bonus */
        points += 210;  /* 0xD2 */
    }
    else {
        /* Calculate factory stat costs */
        factProd = GetRaceStat(pplr, rsFactProd);
        factProdDelta = 10 - factProd;

        int16_t factBuild = GetRaceStat(pplr, rsFactBuild);
        factBuildDelta = 10 - factBuild;

        factOperate = GetRaceStat(pplr, rsFactOperate);
        factOperateDelta = 10 - factOperate;

        /* Factory production cost */
        if (factProdDelta < 1) {
            factoryPoints = factProdDelta * 121;  /* 0x79 - better than baseline costs more */
        }
        else {
            factoryPoints = factProdDelta * 100;  /* worse than baseline gives points */
        }

        /* Factory build cost adjustment */
        if (factBuildDelta < 0) {
            factoryPoints += factBuildDelta * -55;  /* 0x37 */
        }
        else {
            factoryPoints += factBuildDelta * factBuildDelta * -60;  /* 0x3C */
        }

        /* Factory operability adjustment */
        if (factOperateDelta < 1) {
            factoryPoints += factOperateDelta * 35;  /* 0x23 */
        }
        else {
            factoryPoints += factOperateDelta * 40;  /* 0x28 */
        }

        /* Cap factory points bonus */
        if (factoryPoints > 700) {
            factoryPoints = (factoryPoints - 700) / 3 + 700;
        }

        /* Extra penalties for very high operability */
        if (factOperateDelta < -6) {
            if (factOperateDelta < -11) {
                if (factOperateDelta < -14) {
                    factoryPoints -= 360;  /* 0x168 */
                }
                else {
                    factoryPoints -= ((-12 - factOperateDelta) * 45 + 225);
                }
            }
            else {
                factoryPoints += (-6 - factOperateDelta) * -30;
            }
        }

        /* Extra penalty for high production */
        if (factProdDelta < -2) {
            factoryPoints += (-2 - factProdDelta) * -60;
        }

        points += factoryPoints;

        /* Check for cheap factories LRT */
        if (GetRaceGrbit(pplr, ibitRaceCheapFact)) {
            points -= 175;  /* 0xAF */
        }

        /* -----------------------------------------------------------------
         * SECTION 6: Mine Stats
         * ----------------------------------------------------------------- */
        int16_t mineProd = GetRaceStat(pplr, rsMineProd);
        mineProdDelta = 10 - mineProd;

        mineBuildStat = GetRaceStat(pplr, rsMineBuild);

        int16_t mineOperate = GetRaceStat(pplr, rsMineOperate);
        mineOperateDelta = 10 - mineOperate;

        /* Mine production cost */
        if (mineProdDelta < 1) {
            minePoints = mineProdDelta * 169;  /* 0xA9 */
        }
        else {
            minePoints = mineProdDelta * 100;
        }

        /* Mine build cost (baseline is 3, not 10) */
        if (3 - mineBuildStat < 1) {
            minePoints -= (3 - mineBuildStat) * 65 - 80;  /* 0x41, 0x50 */
        }
        else {
            minePoints -= 360;  /* 0x168 */
        }

        /* Mine operability */
        if (mineOperateDelta < 1) {
            minePoints += mineOperateDelta * 35;
        }
        else {
            minePoints += mineOperateDelta * 40;
        }

        points += minePoints;
    }

    /* -----------------------------------------------------------------
     * SECTION 7: Primary Racial Trait Cost
     * ----------------------------------------------------------------- */
    points -= rgPRTCosts[prt];

    /* -----------------------------------------------------------------
     * SECTION 8: Lesser Racial Traits
     * ----------------------------------------------------------------- */
    badTraits = 0;
    goodTraits = 0;

    for (i = 0; i < 14; i++) {
        if (GetRaceGrbit(pplr, i)) {
            if (rgLRTCosts[i] < 0) {
                badTraits++;
            }
            else {
                goodTraits++;
            }
            points += rgLRTCosts[i];
        }
    }

    /* Penalty for having too many traits */
    if (badTraits + goodTraits > 4) {
        points -= (badTraits + goodTraits) * 10 * (badTraits + goodTraits - 4);
    }

    /* Penalty for too many good traits vs bad */
    if (goodTraits - badTraits > 3) {
        points -= (goodTraits - badTraits - 3) * 60;  /* 0x3C */
    }

    /* Bonus for more bad traits than good */
    if (badTraits - goodTraits > 3) {
        points -= (badTraits - goodTraits - 3) * 40;  /* 0x28 - actually adds points */
    }

    /* -----------------------------------------------------------------
     * SECTION 9: No Advanced Scanners penalty (PRT-dependent)
     * ----------------------------------------------------------------- */
    if (GetRaceGrbit(pplr, ibitRaceNoAdvScanner)) {
        if (prt == PRT_PP) {
            points -= 280;  /* 0x118 */
        }
        else if (prt == PRT_SS) {
            points -= 200;
        }
        else if (prt == PRT_JOAT) {
            points -= 40;   /* 0x28 */
        }
    }

    /* -----------------------------------------------------------------
     * SECTION 10: Starting Tech Levels
     * ----------------------------------------------------------------- */
    techSum = 0;
    for (i = 8; i < 14; i++) {  /* Tech fields are stats 8-13 */
        techSum += GetRaceStat(pplr, i) - 1;  /* Subtract 1 since level 1 is free */
    }

    if (techSum < 0) {
        /* Starting below level 1 in some fields (gives points) */
        points += rgTechBonusTable[-1 - techSum];

        /* Extra penalty if very low tech and low resource generation */
        if (techSum != -4 && techSum < -3) {
            if (GetRaceStat(pplr, rsResGen) < 10) {
                points -= 190;  /* 0xBE */
            }
        }
    }
    else if (techSum > 0) {
        /* Starting above level 1 costs points */
        points -= techSum * techSum * 130;  /* 0x82 */

        /* Special bonuses for specific high-tech configurations */
        if (techSum == 6) {
            points += 1430;  /* 0x596 */
        }
        else if (techSum == 5) {
            points += 520;   /* 0x208 */
        }
    }

    /* -----------------------------------------------------------------
     * SECTION 11: Bleeding Edge Technology (3% extra per level)
     * ----------------------------------------------------------------- */
    if (GetRaceGrbit(pplr, ibitRaceTech3)) {
        points -= 180;  /* 0xB4 */
    }

    /* -----------------------------------------------------------------
     * SECTION 12: AR with specific tech bonus
     * ----------------------------------------------------------------- */
    if (prt == PRT_AR && GetRaceStat(pplr, rsTechBonus1) == 2) {
        points -= 100;
    }

    /* -----------------------------------------------------------------
     * FINAL: Divide by 3 and return
     * ----------------------------------------------------------------- */
    return (int16_t)(points / 3);
}


/* ============================================================================
 * SUMMARY: Race Advantage Points System
 * ============================================================================
 *
 * The advantage points system ensures races are balanced. Each race starts
 * with a pool of points (1650 base) and various choices cost or refund points:
 *
 * COSTS POINTS (making race stronger):
 *   - Higher growth rate
 *   - Wider habitability range
 *   - Better factory efficiency
 *   - Better mine efficiency
 *   - Higher resource generation
 *   - Beneficial LRTs (IFE, TT, ARM, ISB, etc.)
 *   - Higher starting tech levels
 *
 * GIVES POINTS (making race weaker):
 *   - Lower growth rate
 *   - Narrower habitability / immunities
 *   - Worse factory efficiency
 *   - Worse mine efficiency
 *   - Lower resource generation
 *   - Harmful LRTs (NRSE, OBRM, NAS, LSP, BET)
 *   - Lower starting tech levels
 *
 * A valid race must have >= 500 points after the calculation (before
 * display to user, which subtracts 500 to show "leftover" points >= 0).
 *
 * The hacker detection system calls this function and if the result is < 500,
 * it indicates the race was illegally modified to get benefits without paying
 * the appropriate point cost.
 */
