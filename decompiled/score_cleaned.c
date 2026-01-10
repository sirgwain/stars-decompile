/*
 * Player Score Calculation - Stars! 2.60j RC3
 * Cleaned up from decompiled code (score.c)
 *
 * This file contains the score calculation algorithm used by Stars!
 * The score is displayed in the player score window and determines rankings.
 *
 * SCORE STRUCTURE (20 bytes, 0x14):
 *   Offset  Size  Field
 *   0-3     4     lScore      - Total score points
 *   4-5     2     cPlanet     - Number of planets owned
 *   6-7     2     cStarbase   - Number of starbases
 *   8-11    4     cResources  - Total resources available
 *   12-13   2     cTechLevels - Sum of all tech levels
 *   14-19   6     rgcsh[3]    - Ship counts by type (packed via WPackLong)
 *                              [0] = Unarmed ships
 *                              [1] = Escort ships (power < 2000)
 *                              [2] = Capital ships (power >= 2000)
 *
 * Race Stat Indices (rsXxx constants):
 *   rsResGen      = 0   - Colonists per resource
 *   rsFactProd    = 1   - Factory production per 10 factories
 *   rsFactOperate = 3   - Factories operable per 10k colonists
 *   rsMajorAdv    = 14  - Primary Racial Trait (PRT)
 *
 * Primary Racial Traits (rsMajorAdv values):
 *   0 = Hyper Expansion (HE)    - 50% max pop penalty
 *   8 = Alternate Reality (AR)  - Energy tech for resources, orbital pop
 *   9 = Jack of All Trades (JoaT) - 20% max pop bonus
 *
 * Hull Slot Types (hstXxx constants):
 *   hstBeam     = 0x10  - Beam weapons
 *   hstTorp     = 0x20  - Torpedoes
 *   hstBomb     = 0x40  - Bombs
 *   hstSpecialE = 0x800 - Electrical (includes capacitors)
 */

#include <stdint.h>
#include <string.h>
#include <math.h>

/*-----------------------------------------------------------------------------
 * Constants
 *---------------------------------------------------------------------------*/

/* Ship type classification based on computed power */
typedef enum {
    SHIP_TYPE_DELETED = -1,  /* Design slot is empty/deleted */
    SHIP_TYPE_UNARMED = 0,   /* No weapons (power = 0) */
    SHIP_TYPE_ESCORT  = 1,   /* Armed but power < 2000 */
    SHIP_TYPE_CAPITAL = 2    /* Capital ship (power >= 2000) */
} ShipType;

/* Race stat indices */
#define rsResGen       0   /* Colonists per resource */
#define rsFactProd     1   /* Factory output per 10 factories */
#define rsFactOperate  3   /* Factories operable per 10k colonists */
#define rsMajorAdv    14   /* Primary Racial Trait (PRT) */

/* Primary Racial Traits */
#define PRT_HYPER_EXPANSION     0   /* HE */
#define PRT_ALTERNATE_REALITY   8   /* AR */
#define PRT_JOAT                9   /* Jack of All Trades */

/* LRT bit indices */
#define ibitRaceOBRM  9   /* Only Basic Remote Mining */

/* Hull slot types */
#define hstBeam     0x10   /* Beam weapons */
#define hstTorp     0x20   /* Torpedoes */
#define hstBomb     0x40   /* Bombs */
#define hstSpecialE 0x800  /* Electrical equipment */

/* Capacitor part IDs (within hstSpecialE category) */
#define PART_FLUX_CAPACITOR   0x0C
#define PART_ENERGY_CAPACITOR 0x0D


/*-----------------------------------------------------------------------------
 * CalcPlayerScore - Calculate total score for a player
 *
 * @param iPlr    Player index (0-15)
 * @param pscore  Optional output: SCORE structure to fill (20 bytes)
 * @return        Total score (low 16 bits)
 *
 * Score Formula Summary:
 *   1. Planets: min(population/1000, 6) points per planet
 *   2. Resources: totalResources / 30 points
 *   3. Starbases: 3 points each
 *   4. Tech Levels (per field, 6 fields total):
 *      - Levels 1-3:  +level points
 *      - Levels 4-6:  +(level*2 - 3) points
 *      - Levels 7-9:  +(level*3 - 9) points
 *      - Levels 10+:  +(level*4 - 18) points
 *   5. Unarmed ships: min(count, planetCount) / 2 points
 *   6. Capital ships: (planetCount^2 * capitalCount) / (planetCount + capitalCount)
 *
 * Address: 1038:58a6
 *---------------------------------------------------------------------------*/
int16_t CalcPlayerScore(int16_t iPlr, SCORE *pscore)
{
    SCORE score;
    int16_t rgType[16];        /* Ship type for each of 16 design slots */
    int32_t rgcsh[3];          /* Ship counts: [0]=unarmed, [1]=escort, [2]=capital */
    int32_t lScore;
    int16_t i;

    memset(&score, 0, sizeof(SCORE));  /* 0x14 = 20 bytes */

    /*=========================================================================
     * PHASE 1: Iterate planets - count owned, starbases, resources
     *========================================================================*/

    PLANET *lppl = lpPlanets;
    PLANET *lpplEnd = (PLANET *)((char *)lpPlanets + cPlanet * sizeof(PLANET));  /* 0x38 = 56 bytes per planet */

    while (lppl < lpplEnd) {
        if (lppl->iPlayer == iPlr) {
            score.cPlanet++;

            /* Population contribution: (pop + 999) / 1000, capped at 6 */
            int32_t population = lppl->population;  /* offset 0x28-0x2B */
            int32_t popScore = (population + 999) / 1000;
            if (popScore > 6) {
                popScore = 6;
            }
            score.lScore += popScore;

            /* Check for starbase (flags3 bit 9) */
            if (lppl->flags3 & (1 << 9)) {
                /* Get starbase hull definition */
                int16_t sbDesignIdx = lppl->flags23 & 0x0F;  /* offset 0x2C, low nibble */
                SHDEF *design = &rgplrDesigns[iPlr][sbDesignIdx];
                HULDEF *hull = LphuldefFromId(design->hullId);

                /* Only count if hull has dock capacity (offset 0x34 in HULDEF) */
                if (hull->dockCapacity != 0) {
                    score.cStarbase++;
                }
            }

            /* Add resources from this planet */
            score.cResources += CResourcesAtPlanet(lppl, iPlr);
        }
        lppl++;  /* Next planet (0x38 bytes) */
    }

    /* Calculate base score: popScore + resources/30 + starbases*3 */
    lScore = score.lScore + (score.cResources / 30) + (score.cStarbase * 3);
    score.lScore = lScore;

    /*=========================================================================
     * PHASE 2: Tech level contribution (skip if player is dead)
     *========================================================================*/

    /* Check player dead flag (flags43 bit 0) */
    if ((rgplr[iPlr].flags43 & 1) == 0) {
        for (i = 0; i < 6; i++) {
            int16_t techLevel = rgplr[iPlr].rgTech[i];  /* offset 0x59bc relative to rgplr */
            score.cTechLevels += techLevel;

            /* Tech score contribution - escalating formula:
             *   Level 1-3:  +level
             *   Level 4-6:  +level*2 - 3  (so 5,7,9 for levels 4,5,6)
             *   Level 7-9:  +level*3 - 9  (so 12,15,18 for levels 7,8,9)
             *   Level 10+:  +level*4 - 18 (so 22,26,30,34,... for 10,11,12,13,...)
             */
            int16_t techScore;
            if (techLevel < 4) {
                techScore = techLevel;
            } else if (techLevel < 7) {
                techScore = techLevel * 2 - 3;
            } else if (techLevel < 10) {
                techScore = techLevel * 3 - 9;
            } else {
                techScore = techLevel * 4 - 18;
            }
            lScore += techScore;
        }
        score.lScore = lScore;
    }

    /*=========================================================================
     * PHASE 3: Classify each ship design by combat power
     *========================================================================*/

    for (i = 0; i < 16; i++) {
        score.lScore = lScore;  /* Preserve score across loop */

        SHDEF *design = &rgplrDesigns[iPlr][i];  /* 0x93 bytes per design */

        /* Check if design is deleted (flags bit 9) */
        if (design->flags & (1 << 9)) {
            rgType[i] = SHIP_TYPE_DELETED;
            continue;
        }

        /* Compute combat power */
        int32_t power = LComputePower(design);

        if (power == 0) {
            rgType[i] = SHIP_TYPE_UNARMED;
        } else if (power < 2000) {
            rgType[i] = SHIP_TYPE_ESCORT;
        } else {
            rgType[i] = SHIP_TYPE_CAPITAL;
        }
    }

    /*=========================================================================
     * PHASE 4: Count ships by type across all fleets
     *========================================================================*/

    for (i = 0; i < 3; i++) {
        rgcsh[i] = 0;
    }

    for (int16_t ifl = 0; ifl < cFleet; ifl++) {
        FLEET *lpfl = rglpfl[ifl];
        if (lpfl == NULL) break;

        /* Only count our fleets that aren't in transit (flags bit 10) */
        if (lpfl->iPlayer != iPlr) continue;
        if (lpfl->flags & (1 << 10)) continue;

        /* Count ships of each design type */
        for (i = 0; i < 16; i++) {
            int16_t shipCount = lpfl->rgcShips[i];  /* offset 0x0C, 2 bytes each */
            if (shipCount > 0 && rgType[i] != SHIP_TYPE_DELETED) {
                rgcsh[rgType[i]] += shipCount;
            }
        }
    }

    /*=========================================================================
     * PHASE 5: Calculate ship score contributions
     *========================================================================*/

    /* Unarmed ships: count/2, but cap count at planet count first */
    int32_t unarmedCount = rgcsh[SHIP_TYPE_UNARMED];
    if (unarmedCount > score.cPlanet) {
        unarmedCount = score.cPlanet;
    }
    lScore = score.lScore + (unarmedCount / 2);
    score.lScore = lScore;

    /* Capital ships bonus (only if we have capital ships) */
    int32_t capitalCount = rgcsh[SHIP_TYPE_CAPITAL];
    if (capitalCount > 0) {
        int32_t cPlanet = score.cPlanet;
        int32_t totalWithCapital = cPlanet + capitalCount;

        /* Bonus = (cPlanet * cPlanet * capitalCount) / totalWithCapital
         * This rewards having capital ships proportional to empire size */
        int32_t bonus = (cPlanet * cPlanet * capitalCount) / totalWithCapital;
        lScore += bonus;
        score.lScore = lScore;
    }

    /*=========================================================================
     * PHASE 6: Pack ship counts and copy result
     *========================================================================*/

    for (i = 0; i < 3; i++) {
        score.rgcsh[i] = WPackLong(rgcsh[i]);
    }

    /* Copy score structure to output if provided */
    if (pscore != NULL) {
        memcpy(pscore, &score, sizeof(SCORE));
    }

    return (int16_t)score.lScore;
}


/*-----------------------------------------------------------------------------
 * LComputePower - Calculate combat power rating for a ship design
 *
 * @param lpshdef  Pointer to ship design (SHDEF, 0x93 bytes)
 * @return         Power rating (0 = unarmed, <2000 = escort, >=2000 = capital)
 *
 * Power Components:
 *   Beams:      damage * count * (range + 3) / 4
 *               (divided by 3 more if gattling/sapper flag set)
 *   Torpedoes:  damage * count * (range - 2) / 2
 *   Bombs:      (killNormal + killSmart) * count * 2
 *   Capacitors: multiply beam power by cumulative (100 + bonus)% per capacitor
 *   Speed:      beamPower * (speed - 4) / 10
 *
 * Final: bombs + beams + speedBonus + torpedoes
 *
 * Address: 1038:0b32
 *---------------------------------------------------------------------------*/
int32_t LComputePower(SHDEF *lpshdef)
{
    int32_t dpBombs = 0;
    int32_t dpBeams = 0;
    int32_t dpTorps = 0;
    int32_t pctCap = 1000;  /* Capacitor multiplier: 1000 = 100.0% */

    /* Iterate through hull slots (0x7A = slot count offset, max slots at 0x3A) */
    int16_t numSlots = lpshdef->numSlots;  /* byte at offset 0x7A */

    for (int16_t ihs = 0; ihs < numSlots; ihs++) {
        /* Each slot is 4 bytes at offset 0x3A + ihs*4 */
        HullSlotType *slot = &lpshdef->rgSlots[ihs];
        int16_t slotType = slot->grhst;      /* Slot type (hstBeam, hstTorp, etc.) */
        int16_t countAndId = slot->flags2;   /* High byte = count, low byte = part ID */
        int16_t count = countAndId >> 8;
        int16_t partId = countAndId & 0xFF;

        if (count == 0) continue;

        /* Look up the part definition */
        PART part;
        part.hs.grhst = slotType;
        part.hs.flags2 = countAndId;
        if (!FLookupPart(&part)) continue;

        PARTDEF *pcom = part.pcom;  /* Part common data */

        switch (slotType) {
            case hstBeam:  /* 0x10 - Beam weapons */
            {
                int16_t range = pcom->range;    /* offset 0x34 in PARTDEF */
                int16_t damage = pcom->damage;  /* offset 0x36 in PARTDEF */

                /* Power = damage * count * (range + 3) / 4 */
                int32_t power = (int32_t)damage * count * (range + 3) / 4;

                /* Gattling/sapper weapons (flags bit 0 at offset 0x3A) do 1/3 damage */
                if (pcom->flags & 1) {
                    power /= 3;
                }
                dpBeams += power;
                break;
            }

            case hstTorp:  /* 0x20 - Torpedoes */
            {
                int16_t range = pcom->range;
                int16_t damage = pcom->damage;

                /* Power = damage * count * (range - 2) / 2 */
                int32_t power = (int32_t)damage * count * (range - 2) / 2;
                dpTorps += power;
                break;
            }

            case hstBomb:  /* 0x40 - Bombs */
            {
                int16_t killNormal = pcom->damage;   /* offset 0x36 */
                int16_t killSmart = pcom->damage2;   /* offset 0x38 */

                /* Power = (killNormal + killSmart) * count * 2 */
                dpBombs += (killNormal + killSmart) * count * 2;
                break;
            }

            case hstSpecialE:  /* 0x800 - Electrical equipment */
            {
                /* Check for capacitors (part IDs 0x0C and 0x0D) */
                if (partId == PART_FLUX_CAPACITOR || partId == PART_ENERGY_CAPACITOR) {
                    int16_t bonus = pcom->range;  /* Capacitor bonus stored in range field */

                    /* Each capacitor multiplies by (100 + bonus)% */
                    for (int16_t j = 0; j < count; j++) {
                        pctCap = pctCap * (bonus + 100) / 100;
                    }
                }
                break;
            }
        }
    }

    /* Apply capacitor multiplier to beam weapons */
    if (pctCap != 1000) {
        pctCap /= 10;  /* Convert from 1000-base to percentage */
        if (pctCap > 255) {
            pctCap = 255;  /* Cap at 255% */
        }
        dpBeams = dpBeams * pctCap / 100;
    }

    /* Speed bonus: beamPower * (speed - 4) / 10 */
    int16_t speed = SpdOfShip(NULL, 0, NULL, 0, lpshdef);
    int32_t speedBonus = dpBeams * (speed - 4) / 10;

    /* Total power = bombs + beams + speedBonus + torpedoes */
    return dpBombs + dpBeams + speedBonus + dpTorps;
}


/*-----------------------------------------------------------------------------
 * CResourcesAtPlanet - Calculate resources available at a planet
 *
 * @param lppl  Planet pointer
 * @param iplr  Player index
 * @return      Resources available this turn
 *
 * For normal races:
 *   resources = pop/colonistsPerResource + factories*factoryOutput/10
 *
 * For Alternate Reality (AR, rsMajorAdv=8):
 *   resources = sqrt(energyTech * population / colonistsPerResource)
 *   (minimum habitability 25% applied)
 *
 * Address: 1048:788e
 *---------------------------------------------------------------------------*/
int16_t CResourcesAtPlanet(PLANET *lppl, int16_t iplr)
{
    /* No resources if unpopulated */
    if (lppl->population == 0) {
        return 0;
    }

    int16_t colonistsPerResource = GetRaceStat(&rgplr[iplr], rsResGen);
    int32_t lPop = lppl->population;

    /* If over max population, use effective population */
    int32_t maxPop = CalcPlanetMaxPop(lppl->id, iplr);
    if (lPop > maxPop) {
        /* Effective pop = maxPop + (overflow / 2) */
        int32_t overflow = lPop - maxPop;
        lPop = maxPop + (overflow / 2);
        /* Additional cap may apply */
    }

    int16_t prt = GetRaceStat(&rgplr[iplr], rsMajorAdv);
    int16_t cRes;

    if (prt == PRT_ALTERNATE_REALITY) {
        /* AR race: resources = sqrt(energyTech * pop / colonistsPerResource) */
        int16_t energyTech = rgplr[iplr].rgTech[0];  /* Energy is tech field 0 */
        if (energyTech < 1) energyTech = 1;

        int16_t pctVal = PctPlanetDesirability(lppl, iplr);
        if (pctVal < 25) pctVal = 25;  /* Minimum 25% habitability */

        double temp = (double)energyTech * (double)lPop / (double)colonistsPerResource;
        cRes = (int16_t)sqrt(temp);
    } else {
        /* Normal race: pop contribution + factory contribution */
        int32_t popResources = lPop / colonistsPerResource;

        int16_t cFact = CMaxOperableFactories(lppl, iplr, 0);
        /* Cap factories at planet's actual factory count */
        int16_t actualFactories = lppl->factories & 0xFFF;  /* 12-bit field */
        if (cFact > actualFactories) {
            cFact = actualFactories;
        }

        int16_t factoryOutput = GetRaceStat(&rgplr[iplr], rsFactProd);
        int32_t factResources = ((int32_t)cFact * factoryOutput + 9) / 10;

        cRes = (int16_t)(popResources + factResources);
    }

    /* Minimum 1 resource if populated */
    if (cRes == 0) {
        cRes = 1;
    }

    return cRes;
}


/*-----------------------------------------------------------------------------
 * CalcPlanetMaxPop - Calculate maximum population for a planet
 *
 * @param idpl  Planet ID
 * @param iplr  Player index
 * @return      Maximum population in colonists
 *
 * For AR race: orbital capacity from starbase hull
 * For others:  habitability% * 100, modified by PRT:
 *   - HE (0):   50% penalty (divide by 2)
 *   - JoaT (9): 20% bonus (multiply by 1.2)
 *   - OBRM LRT: 10% bonus
 *
 * Address: 1048:7096
 *---------------------------------------------------------------------------*/
int32_t CalcPlanetMaxPop(int16_t idpl, int16_t iplr)
{
    PLANET pl;
    FLookupPlanet(idpl, &pl);

    int16_t prt = GetRaceStat(&rgplr[iplr], rsMajorAdv);
    int32_t lMaxPop;

    if (prt == PRT_ALTERNATE_REALITY) {
        /* AR: population lives in orbitals, need our starbase */
        if (pl.iPlayer != iplr || !(pl.flags3 & (1 << 9))) {
            return 0;
        }
        /* Look up orbital capacity from starbase hull */
        int16_t sbDesignIdx = pl.flags23 & 0x0F;
        int16_t hullId = rgplrDesigns[iplr][sbDesignIdx].hullId;
        int32_t orbitalIdx = (hullId - 0x20) * 4;  /* ihullMetaMorph = 0x1F */
        lMaxPop = rgOrbitalCapacity[orbitalIdx];   /* at 0x8CC */
    } else {
        /* Normal race: based on habitability */
        int16_t habitability = PctPlanetDesirability(&pl, iplr);

        if (habitability < 5) {
            lMaxPop = 500;  /* Minimum for marginal planets */
        } else {
            lMaxPop = (int32_t)habitability * 100;
        }

        /* Apply PRT modifiers */
        if (prt == PRT_HYPER_EXPANSION) {
            lMaxPop -= lMaxPop / 2;  /* HE: 50% penalty */
        } else if (prt == PRT_JOAT) {
            lMaxPop += lMaxPop / 5;  /* JoaT: 20% bonus */
        }
    }

    /* OBRM LRT bonus: +10% */
    if (GetRaceGrbit(&rgplr[iplr], ibitRaceOBRM)) {
        lMaxPop += lMaxPop / 10;
    }

    return lMaxPop;
}


/*-----------------------------------------------------------------------------
 * PctPlanetDesirability - Calculate habitability percentage
 *
 * @param lppl  Planet pointer
 * @param iPlr  Player index
 * @return      Habitability: -45 to 100 (negative = hostile)
 *
 * Checks gravity, temperature, radiation against race preferences.
 * For each environment factor:
 *   - If immune (max < 0): full score
 *   - If outside tolerance: negative points (capped at 15 per factor)
 *   - If inside tolerance: comfort score based on distance from ideal
 *
 * Address: 1048:6e1e
 *---------------------------------------------------------------------------*/
int16_t PctPlanetDesirability(PLANET *lppl, int16_t iPlr)
{
    int32_t pctPos = 0;      /* Positive habitability score */
    int32_t pctNeg = 0;      /* Negative score (outside tolerance) */
    int32_t pctMod = 10000;  /* Modifier for edge-of-tolerance penalty */

    /* Check 3 environment factors: gravity(0), temperature(1), radiation(2) */
    for (int16_t i = 0; i < 3; i++) {
        int16_t planetVal = lppl->rgEnv[i];           /* Planet value (offset 0x0C) */
        int16_t idealVal = rgplr[iPlr].rgEnvIdeal[i]; /* Ideal (offset 0x59B2) */
        int16_t minVal = rgplr[iPlr].rgEnvMin[i];     /* Min tolerance (offset 0x59B5) */
        int16_t maxVal = rgplr[iPlr].rgEnvMax[i];     /* Max tolerance (offset 0x59B8) */

        if (maxVal < 0) {
            /* Immune to this factor - full score */
            pctPos += 10000;
        }
        else if (planetVal < minVal || planetVal > maxVal) {
            /* Outside tolerance - accumulate negative score */
            int16_t distance;
            if (planetVal < minVal) {
                distance = minVal - planetVal;
            } else {
                distance = planetVal - maxVal;
            }
            if (distance > 15) distance = 15;  /* Cap penalty contribution */
            pctNeg += distance;
        }
        else {
            /* Inside tolerance - calculate comfort score */
            int16_t distFromIdeal = abs(planetVal - idealVal);
            int16_t rangeHalf, dPenalty;

            if (planetVal < idealVal) {
                rangeHalf = idealVal - minVal;
                dPenalty = (idealVal - planetVal) * 2 - rangeHalf;
            } else {
                rangeHalf = maxVal - idealVal;
                dPenalty = (planetVal - idealVal) * 2 - rangeHalf;
            }

            /* Comfort = (100 - percentFromIdeal)^2 */
            int16_t pctVar = (distFromIdeal * 100) / rangeHalf;
            int32_t comfort = (int32_t)(100 - pctVar) * (100 - pctVar);
            pctPos += comfort;

            /* Penalty modifier for being in outer half of tolerance */
            if (dPenalty > 0) {
                pctMod = pctMod * (rangeHalf * 2 - dPenalty) / (rangeHalf * 2);
            }
        }
    }

    /* Calculate final habitability */
    if (pctNeg == 0) {
        /* Positive: sqrt(averageComfort) * modifier / 100 */
        double avgComfort = (double)pctPos / 3.0;
        int32_t baseHab = (int32_t)sqrt(avgComfort);
        return (int16_t)(baseHab * pctMod / 10000);
    } else {
        /* Negative habitability */
        return -(int16_t)pctNeg;
    }
}


/*-----------------------------------------------------------------------------
 * CMaxOperableFactories - Max factories population can operate
 *
 * @param lppl       Planet pointer
 * @param iplr       Player index
 * @param fNextYear  If true, project population growth
 * @return           Max operable factories
 *
 * Formula: min(maxFactories, population * factoriesPerColonist / 100)
 * AR race always returns 0 (no factories).
 *
 * Address: 1048:7618
 *---------------------------------------------------------------------------*/
int16_t CMaxOperableFactories(PLANET *lppl, int16_t iplr, int16_t fNextYear)
{
    int16_t maxFactories = CMaxFactories(lppl, iplr);
    int16_t factoriesPerColonist = GetRaceStat(&rgplr[iplr], rsFactOperate);

    int32_t lPop = lppl->population;

    /* Optionally project population for next year */
    if (fNextYear) {
        lPop += ChgPopFromPlanet(lppl, 0);
    }

    /* Calculate max operable: pop * efficiency / 100 */
    int16_t cMax = (int16_t)(lPop * factoriesPerColonist / 100);

    /* Cap at max factories on planet */
    if (cMax > maxFactories) {
        cMax = maxFactories;
    }

    /* Minimum 1 */
    if (cMax < 1) {
        cMax = 1;
    }

    /* AR race has no factories */
    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == PRT_ALTERNATE_REALITY) {
        cMax = 0;
    }

    return cMax;
}


/*-----------------------------------------------------------------------------
 * CMaxFactories - Maximum factories a planet can support
 *
 * @param lppl  Planet pointer
 * @param iplr  Player index
 * @return      Max factories (minimum 10, 0 for AR)
 *
 * Formula: maxPop * factoriesPerColonist / 100, minimum 10
 *
 * Address: 1048:755c
 *---------------------------------------------------------------------------*/
int16_t CMaxFactories(PLANET *lppl, int16_t iplr)
{
    int32_t maxPop = CalcPlanetMaxPop(lppl->id, iplr);
    int16_t factoriesPerColonist = GetRaceStat(&rgplr[iplr], rsFactOperate);

    int32_t cMax = maxPop * factoriesPerColonist / 100;

    if (cMax < 10) {
        cMax = 10;
    }

    /* AR race has no factories */
    if (GetRaceStat(&rgplr[iplr], rsMajorAdv) == PRT_ALTERNATE_REALITY) {
        cMax = 0;
    }

    return (int16_t)cMax;
}
