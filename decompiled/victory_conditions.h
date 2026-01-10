/*
 * Victory Conditions - Stars! 2.60j RC3
 * Decompiled from stars.exe
 *
 * Victory condition data is stored in the GAME structure's rgvc[12] array.
 * Each byte encodes:
 *   - Bit 7 (0x80): Enabled flag (condition is active)
 *   - Bits 0-6 (0x7F): Threshold index value
 *
 * The GetVCVal() function converts index to actual values using formulas.
 */

#ifndef VICTORY_CONDITIONS_H
#define VICTORY_CONDITIONS_H

#include <stdint.h>
#include <stdbool.h>

/* Victory condition indices into rgvc[] array
 * Note: Index increments sequentially through UI rows, so the tech condition
 * uses TWO indices (1 for tech level, 2 for number of fields).
 */
#define VC_OWNS_PERCENT_PLANETS     0   /* Owns % of all planets */
#define VC_ATTAINS_TECH_LEVEL       1   /* Attains tech level X */
#define VC_TECH_FIELDS              2   /* in Y tech fields (2nd value for tech condition) */
#define VC_EXCEEDS_SCORE            3   /* Exceeds score threshold */
#define VC_EXCEEDS_SECOND_PLACE     4   /* Exceeds 2nd place by % */
#define VC_PRODUCTION_CAPACITY      5   /* Production capacity (thousands) */
#define VC_OWNS_CAPITAL_SHIPS       6   /* Owns N capital ships */
#define VC_HIGHEST_SCORE_YEARS      7   /* Highest score after N years */
#define VC_MEETS_N_CRITERIA         8   /* Meets N of above criteria */
#define VC_MIN_YEARS_BEFORE_WIN     9   /* Minimum years before winner declared */

/* Maximum threshold indices from vrgvcMax[] at 1078:b5a8 */
static const int16_t vrgvcMax[10] = {
    16,  /* [0] Owns % planets: 20-100% in steps of 5 */
    18,  /* [1] Tech level: 8-26 */
    4,   /* [2] Tech fields: 2-6 fields */
    19,  /* [3] Exceeds score: 1000-20000 points */
    28,  /* [4] Exceeds 2nd place: 20-300% */
    49,  /* [5] Production capacity: 10-500 (thousands) */
    29,  /* [6] Capital ships: 10-300 */
    87,  /* [7] Highest score after N years: 30-900 */
    7,   /* [8] Meets N criteria: capped at enabled count */
    47   /* [9] Min years before winner: 30-500 */
};

/*
 * GetVCCheck - Check if a victory condition is enabled
 *
 * @param pgame  Pointer to GAME structure
 * @param ivc    Victory condition index (0-9)
 * @return       true if condition is enabled (bit 7 set)
 *
 * Address: 1078:b60c
 */
bool GetVCCheck(GAME *pgame, int16_t ivc);

/*
 * GetVCVal - Get the actual value for a victory condition
 *
 * @param pgame     Pointer to GAME structure
 * @param ivc       Victory condition index (0-9)
 * @param fRawIndex If non-zero, return raw index; if 0, compute actual value
 * @return          The threshold value (computed or raw index)
 *
 * Formulas when fRawIndex == 0:
 *   [0]: idx * 5 + 20      (20-100% owns planets)
 *   [1]: idx + 8           (8-26 tech level)
 *   [2]: idx + 2           (2-6 tech fields)
 *   [3]: idx * 1000 + 1000 (1000-20000 exceeds score)
 *   [4]: idx * 10 + 20     (20-300% exceeds 2nd place)
 *   [5]: idx * 10 + 10     (10-500 production capacity)
 *   [6]: idx * 10 + 10     (10-300 capital ships)
 *   [7]: idx * 10 + 30     (30-900 highest score after years)
 *   [8]: min(idx, enabled_count) for "meets N criteria"
 *   [9]: idx * 10 + 30     (30-500 min years before winner)
 *
 * Address: 1078:b710
 */
uint16_t GetVCVal(GAME *pgame, int16_t ivc, int16_t fRawIndex);

#endif /* VICTORY_CONDITIONS_H */
