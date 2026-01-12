/**
 * max_defenses_cleaned.c - Stars! Maximum Defense Calculations (Cleaned)
 *
 * Cleaned decompilation from stars.exe 2.60j RC3
 * Original decompilation by Ghidra, cleaned for readability
 *
 * Original addresses:
 *   CMaxDefenses:          1048:5714 (all_funcs.c:26540-26559)
 *   CMaxOperableDefenses:  1048:5768 (all_funcs.c:26571-26608)
 */

#include "max_defenses_cleaned.h"

/* External references */
extern PLAYER rgplr[];  /* c_common::rgplr - Player array (192 bytes per player) */

/* ============================================================================
 * CMaxDefenses - Absolute maximum defenses based on habitability
 * Original: FUN_1048_5714
 * Address: 1048:5714
 * ============================================================================ */

int16_t CMaxDefenses(PLANET *planet, int16_t player)
{
    int16_t max_defenses;
    uint8_t prt;

    /* Get planet habitability percentage (0-100 for habitable) */
    max_defenses = PctPlanetDesirability(planet, player);

    /* Multiply by 4: a 25% hab planet can have 100 defenses */
    max_defenses = max_defenses * DEFENSE_HABITABILITY_MULTIPLIER;

    /* Clamp to minimum of 10 */
    if (max_defenses < MIN_MAX_DEFENSES) {
        max_defenses = MIN_MAX_DEFENSES;
    }

    /* Clamp to maximum of 100 */
    if (max_defenses > MAX_MAX_DEFENSES) {
        max_defenses = MAX_MAX_DEFENSES;
    }

    /* Alternate Reality race has no planetary defenses */
    prt = GetPlayerPRT(player);
    if (prt == PRT_ALTERNATE_REALITY) {
        max_defenses = 0;
    }

    return max_defenses;
}


/* ============================================================================
 * CMaxOperableDefenses - Population-limited operable defenses
 * Original: FUN_1048_5768
 * Address: 1048:5768
 * ============================================================================ */

int16_t CMaxOperableDefenses(PLANET *planet, int16_t player, int16_t fNextYear)
{
    int16_t max_def;
    int32_t population;
    int32_t pop_change;
    int32_t pop_limit;
    int16_t result;
    uint8_t prt;

    /* Get the habitability-based maximum */
    max_def = CMaxDefenses(planet, player);

    /* Get current population */
    population = planet->population;

    /* If projecting next year, add expected population growth */
    if (fNextYear != 0) {
        pop_change = ChgPopFromPlanet(planet);
        population = population + pop_change;
    }

    /* Calculate population-based limit: (population + 24) / 25 */
    pop_limit = (population + DEFENSE_POPULATION_OFFSET) / DEFENSE_POPULATION_DIVISOR;

    /* Cap population limit at 1000 */
    if (pop_limit > MAX_OPERABLE_DEFENSES_CAP) {
        pop_limit = MAX_OPERABLE_DEFENSES_CAP;
    }

    /* Take the minimum of population limit and habitability limit */
    result = (int16_t)pop_limit;
    if (max_def < pop_limit) {
        result = max_def;
    }

    /* Alternate Reality race has no planetary defenses */
    prt = GetPlayerPRT(player);
    if (prt == PRT_ALTERNATE_REALITY) {
        result = 0;
    }

    return result;
}


/* ============================================================================
 * COMPARISON WITH FACTORIES/MINES
 * ============================================================================
 *
 * Defense calculations follow a similar pattern to factories and mines:
 *
 * CMaxOperableFactories (FUN_1048_5652):
 *   max_factories = cMaxOperFactories_perPop * population / 10000
 *   (where cMaxOperFactories_perPop comes from race trait, typically 10-25)
 *
 * CMaxOperableMines (FUN_1048_54f0):
 *   max_mines = cMaxOperMines_perPop * population / 10000
 *   (where cMaxOperMines_perPop comes from race trait, typically 10-25)
 *
 * CMaxOperableDefenses:
 *   max_defenses = (population + 24) / 25
 *   (fixed rate, not affected by race traits except AR which gets 0)
 *
 * Key difference: Defenses use a fixed population ratio (1 defense per 25 pop),
 * while factories/mines use race-specific efficiency multipliers.
 */


/* ============================================================================
 * STUB IMPLEMENTATIONS (actual implementations in other files)
 * ============================================================================ */

/*
 * PctPlanetDesirability - Get habitability percentage
 * Implementation: all_funcs.c FUN_1048_5080
 *
 * int16_t PctPlanetDesirability(PLANET *planet, int16_t player) {
 *     // Calculates habitability based on:
 *     // - Temperature range vs player preferences
 *     // - Gravity range vs player preferences
 *     // - Radiation range vs player preferences
 *     // Returns 0-100 for habitable, negative for red planets
 * }
 */

/*
 * ChgPopFromPlanet - Get population growth/decline
 * Implementation: all_funcs.c FUN_1038_4b42
 *
 * int32_t ChgPopFromPlanet(PLANET *planet) {
 *     // Calculates population change based on:
 *     // - Current population
 *     // - Planet capacity
 *     // - Habitability
 *     // - Growth rate from race traits
 *     // Can be negative for overcrowded or hostile planets
 * }
 */

/*
 * GetPlayerPRT - Get Primary Race Trait
 * Implementation: all_funcs.c FUN_10e0_253a
 *
 * uint8_t GetPlayerPRT(int16_t player) {
 *     return rgplr[player].prt;  // Byte at offset 0x0E in player structure
 * }
 */
