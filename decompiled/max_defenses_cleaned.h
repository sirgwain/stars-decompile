/**
 * max_defenses_cleaned.h - Stars! Maximum Defense Calculations (Cleaned)
 *
 * Cleaned decompilation from stars.exe 2.60j RC3
 * Original decompilation by Ghidra, cleaned for readability
 */

#ifndef MAX_DEFENSES_CLEANED_H
#define MAX_DEFENSES_CLEANED_H

#include <stdint.h>

/* ============================================================================
 * TYPE DEFINITIONS
 * ============================================================================ */

/* Planet structure (partial - defense-relevant fields) */
typedef struct _PLANET {
    int16_t  id;            /* +0x00: Planet ID */
    int16_t  iplrOwner;     /* +0x02: Owning player index */
    uint8_t  reserved1[0x24]; /* +0x04-0x27: Various fields */
    uint32_t population;    /* +0x28: Population (32-bit) */
    uint8_t  reserved2[0x0C]; /* +0x2C-0x37: Various fields */
} PLANET;  /* Total size: 0x38 (56 bytes) */

/* Player structure (partial - defense-relevant fields) */
typedef struct _PLAYER {
    uint8_t  reserved1[0x0E]; /* +0x00-0x0D: Various fields */
    uint8_t  prt;             /* +0x0E: Primary Race Trait */
    uint8_t  reserved2[0xB1]; /* +0x0F-0xBF: Various fields */
} PLAYER;  /* Total size: 0xC0 (192 bytes) */

/* ============================================================================
 * PRIMARY RACE TRAIT (PRT) CONSTANTS
 * ============================================================================ */

#define PRT_HYPER_EXPANSION      0   /* HE - Hyper Expansion */
#define PRT_SUPER_STEALTH        1   /* SS - Super Stealth */
#define PRT_WAR_MONGER           2   /* WM - War Monger */
#define PRT_CLAIM_ADJUSTER       3   /* CA - Claim Adjuster */
#define PRT_INNER_STRENGTH       4   /* IS - Inner Strength */
#define PRT_SPACE_DEMOLITION     5   /* SD - Space Demolition */
#define PRT_PACKET_PHYSICS       6   /* PP - Packet Physics */
#define PRT_INTERSTELLAR_TRAVELER 7  /* IT - Interstellar Traveler */
#define PRT_ALTERNATE_REALITY    8   /* AR - Alternate Reality */
#define PRT_JACK_OF_ALL_TRADES   9   /* JoaT - Jack of All Trades */

/* ============================================================================
 * DEFENSE CALCULATION CONSTANTS
 * ============================================================================ */

#define DEFENSE_HABITABILITY_MULTIPLIER  4     /* Multiply habitability% by 4 */
#define MIN_MAX_DEFENSES                 10    /* Minimum CMaxDefenses */
#define MAX_MAX_DEFENSES                 100   /* Maximum CMaxDefenses */
#define MAX_OPERABLE_DEFENSES_CAP        1000  /* Hard cap on CMaxOperableDefenses */
#define DEFENSE_POPULATION_DIVISOR       25    /* Population divided by 25 */
#define DEFENSE_POPULATION_OFFSET        24    /* Added to population before division */

/* ============================================================================
 * FUNCTION DECLARATIONS
 * ============================================================================ */

/**
 * Calculate absolute maximum defenses a planet can support
 *
 * Based on planet habitability:
 *   max_defenses = habitability% * 4
 *   Clamped to range [10, 100]
 *   Returns 0 for Alternate Reality (AR) race
 *
 * @param planet  Pointer to planet structure
 * @param player  Player index (0-15)
 * @return        Maximum defenses [10-100], or 0 for AR
 */
int16_t CMaxDefenses(PLANET *planet, int16_t player);

/**
 * Calculate maximum operable defenses based on population
 *
 * Formula: min(CMaxDefenses, min(1000, (population + 24) / 25))
 *   - First gets the habitability-based CMaxDefenses
 *   - Then calculates population capacity: (pop + 24) / 25
 *   - Population capacity capped at 1000
 *   - Returns the minimum of both values
 *   - Returns 0 for Alternate Reality (AR) race
 *
 * @param planet    Pointer to planet structure
 * @param player    Player index (0-15)
 * @param fNextYear If true, include projected population growth
 * @return          Maximum operable defenses, or 0 for AR
 */
int16_t CMaxOperableDefenses(PLANET *planet, int16_t player, int16_t fNextYear);

/**
 * Get planet habitability percentage for a player
 *
 * Returns 0-100 for habitable planets (100 = ideal)
 * Returns negative for uninhabitable planets
 *
 * @param planet  Pointer to planet structure
 * @param player  Player index
 * @return        Habitability percentage
 */
int16_t PctPlanetDesirability(PLANET *planet, int16_t player);

/**
 * Get projected population change for next turn
 *
 * @param planet  Pointer to planet structure
 * @return        Population delta (can be negative for decline)
 */
int32_t ChgPopFromPlanet(PLANET *planet);

/**
 * Get a player's Primary Race Trait (PRT)
 *
 * @param player  Player index
 * @return        PRT value (0-9, see PRT_* constants)
 */
uint8_t GetPlayerPRT(int16_t player);

/* ============================================================================
 * CALCULATION EXAMPLES
 * ============================================================================
 *
 * Example 1: 100% habitability planet, 10000 colonists
 *   CMaxDefenses = 100% * 4 = 400 -> clamped to 100
 *   pop_limit = (10000 + 24) / 25 = 400
 *   CMaxOperableDefenses = min(100, min(1000, 400)) = 100
 *
 * Example 2: 15% habitability planet, 50000 colonists
 *   CMaxDefenses = 15% * 4 = 60
 *   pop_limit = (50000 + 24) / 25 = 2001 -> capped to 1000
 *   CMaxOperableDefenses = min(60, 1000) = 60
 *
 * Example 3: 0% habitability planet (terraformed), 5000 colonists
 *   CMaxDefenses = 0% * 4 = 0 -> clamped to 10
 *   pop_limit = (5000 + 24) / 25 = 200
 *   CMaxOperableDefenses = min(10, 200) = 10
 *
 * Example 4: Any planet owned by AR race
 *   CMaxDefenses = 0 (AR has no planetary defenses)
 *   CMaxOperableDefenses = 0
 *
 * Note: "10000 colonists" in game units is stored as 10000*100 = 1,000,000
 * internally, representing 1,000,000 population units.
 */

#endif /* MAX_DEFENSES_CLEANED_H */
