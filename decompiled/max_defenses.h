/**
 * max_defenses.h - Stars! Maximum Defense Calculations
 *
 * Extracted from stars.exe 2.60j RC3 using Ghidra decompilation
 * Original function names preserved from Ghidra analysis
 *
 * This header defines the maximum defense calculation mechanisms:
 *   1. CMaxDefenses - Absolute maximum defenses a planet can support (habitability-based)
 *   2. CMaxOperableDefenses - Population-limited defenses that can actually operate
 */

#ifndef MAX_DEFENSES_H
#define MAX_DEFENSES_H

#include <stdint.h>

/* Forward declarations */
typedef struct _PLANET PLANET;
typedef struct _PLAYER PLAYER;

/* ============================================================================
 * PRIMARY RACE TRAIT (PRT) CONSTANTS
 * ============================================================================ */

#define PRT_ALTERNATE_REALITY  8   /* AR race - no planetary defenses */

/* ============================================================================
 * DEFENSE CONSTANTS
 * ============================================================================ */

#define MIN_MAX_DEFENSES       10    /* Minimum CMaxDefenses (even for 0% habitability) */
#define MAX_MAX_DEFENSES       100   /* Maximum CMaxDefenses (for 25%+ habitability) */
#define MAX_OPERABLE_DEFENSES  1000  /* Hard cap on CMaxOperableDefenses */
#define DEFENSE_DIVISOR        25    /* Population divisor for operable defenses */

/* ============================================================================
 * FUNCTION DECLARATIONS
 * ============================================================================ */

/**
 * PLANET::CMaxDefenses - Calculate absolute maximum defenses for a planet
 *
 * Computes the maximum number of defenses a planet can support based on
 * habitability. This is an absolute limit regardless of population.
 *
 * Formula: PctPlanetDesirability * 4, clamped to [10, 100]
 *
 * Address: 1048:5714 (FUN_1048_5714)
 * Location: all_funcs.c:26540-26559
 *
 * @param param_1  Unknown (passed to PctPlanetDesirability)
 * @param param_2  Unknown (passed to PctPlanetDesirability)
 * @param param_3  Player index
 * @return         Maximum defenses [10-100], or 0 for AR race
 */
int CMaxDefenses(int16_t param_1, int16_t param_2, int param_3);

/**
 * PLANET::CMaxOperableDefenses - Calculate population-limited operable defenses
 *
 * Computes how many defenses can actually operate based on population.
 * Limited by both CMaxDefenses and population capacity.
 *
 * Formula: min(CMaxDefenses, min(1000, (population + 24) / 25))
 *
 * Address: 1048:5768 (FUN_1048_5768)
 * Location: all_funcs.c:26571-26608
 *
 * @param param_1  Planet data (32-bit, contains coordinates)
 * @param param_3  Player index
 * @param param_4  fNextYear flag (1 = include population growth projection)
 * @return         Maximum operable defenses, or 0 for AR race
 */
int CMaxOperableDefenses(uint32_t param_1, int param_3, int param_4);

/**
 * PLANET::PctPlanetDesirability - Calculate planet habitability percentage
 *
 * Returns the habitability percentage for a planet (0-100 for habitable,
 * negative for uninhabitable).
 *
 * Address: 1048:5080 (FUN_1048_5080)
 *
 * @param param_1  Unknown
 * @param param_2  Unknown
 * @param param_3  Player index
 * @return         Habitability percentage
 */
int PctPlanetDesirability(int16_t param_1, int16_t param_2, int param_3);

/**
 * PLANET::ChgPopFromPlanet - Calculate population change for next turn
 *
 * Returns the projected population change (growth or decline) for the planet.
 *
 * Address: 1038:4b42 (FUN_1038_4b42)
 *
 * @param param_1  Planet pointer
 * @param param_2  Unknown
 * @param param_3  Unknown
 * @return         Population change (can be negative)
 */
int16_t ChgPopFromPlanet(int param_1, int16_t param_2, int param_3);

/**
 * Get PRT (Primary Race Trait) for a player
 *
 * Address: 10e0:253a (FUN_10e0_253a)
 *
 * @param player_offset  Offset into player array
 * @param field_offset   Field offset (0x0e for PRT)
 * @return               PRT value (8 = Alternate Reality)
 */
int GetPlayerPRT(int player_offset, int field_offset);

/* ============================================================================
 * REFERENCED HELPER FUNCTIONS
 * ============================================================================ */

/**
 * 32-bit division helper
 *
 * Address: 1118:0c28 (FUN_1118_0c28)
 *
 * @param dividend_low   Low 16 bits of dividend
 * @param dividend_high  High 16 bits of dividend
 * @param divisor_low    Low 16 bits of divisor
 * @param divisor_high   High 16 bits of divisor
 * @return               Quotient as 32-bit value
 */
long DivLong(uint16_t dividend_low, int16_t dividend_high,
             uint16_t divisor_low, int16_t divisor_high);

/* ============================================================================
 * CALCULATION SUMMARY
 * ============================================================================
 *
 * CMaxDefenses:
 *   habitability = PctPlanetDesirability(planet, player)
 *   max_defenses = habitability * 4
 *   if (max_defenses < 10) max_defenses = 10
 *   if (max_defenses > 100) max_defenses = 100
 *   if (player.PRT == AR) max_defenses = 0
 *   return max_defenses
 *
 * CMaxOperableDefenses:
 *   max_def = CMaxDefenses(planet, player)
 *   population = planet.population
 *   if (fNextYear) population += ChgPopFromPlanet(planet)
 *   pop_limit = (population + 24) / 25
 *   if (pop_limit > 1000) pop_limit = 1000
 *   result = min(max_def, pop_limit)
 *   if (player.PRT == AR) result = 0
 *   return result
 *
 * Note: AR (Alternate Reality) race has no planetary defenses.
 */

#endif /* MAX_DEFENSES_H */
