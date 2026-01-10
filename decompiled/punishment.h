/**
 * punishment.h - Stars! Anti-Cheat and Punishment System
 *
 * Extracted from stars.exe 2.60j RC3 using Ghidra decompilation
 * Original function names preserved from Ghidra analysis
 *
 * This header defines the anti-cheat detection and punishment mechanisms:
 *   1. File sharing detection (fCheater flag) - detects shared .m files
 *   2. Race hacking detection (fHacker flag) - detects modified race files
 *   3. Punishment application - economic and military penalties
 */

#ifndef PUNISHMENT_H
#define PUNISHMENT_H

#include <stdint.h>

/* Forward declarations */
typedef struct _PLAYER PLAYER;
typedef struct _FLEET FLEET;
typedef struct _PLANET PLANET;
typedef struct _PROD PROD;
typedef uint16_t MessageId;

/* ============================================================================
 * PLAYER FLAGS (offset 0x43 in PLAYER structure = flags43)
 * ============================================================================
 * These flags are stored at c_common::rgplr[i].flags43
 * Player structure size: 0xC0 (192 bytes)
 */

#define PLAYER_FLAG_DEAD      0x0002  /* Bit 1: Player has been eliminated */
#define PLAYER_FLAG_CHEATER   0x0004  /* Bit 2: File sharing detected */
#define PLAYER_FLAG_LEARNED   0x0008  /* Bit 3: Has learned from battle */
#define PLAYER_FLAG_HACKER    0x0010  /* Bit 4: Race file modification detected */

/* ============================================================================
 * PUNISHMENT CONSTANTS
 * ============================================================================ */

#define TECH_CAP_NORMAL       25      /* 0x19 - Max tech level for normal players */
#define TECH_CAP_PUNISHED     9       /* 0x09 - Max tech level for cheaters */
#define RACE_VALUE_MINIMUM    500     /* Minimum valid race advantage points */
#define CHEATER_PRODUCTION_DIVISOR 5  /* Production divided by 5 (80% penalty) */

/* ============================================================================
 * MESSAGE IDs FOR PUNISHMENT NOTIFICATIONS
 * ============================================================================ */

/* Cheater detection messages */
#define idmPopulationSuspectsUsurperProductivityOff20Growth  0x0179  /* Base cheater message */
/* Note: +1 added if matching cheater found */

/* Fleet punishment messages */
#define idmFleetCaptainsHaveStagedStrikeDemandFree           0x0180  /* Extra punishment every 8 turns */
#define idmHasDefectedRanksDueInabilityProjectLegitimate     0x0181  /* Fleet defection (1/12 chance) */
#define idmCrewHasSoldOffCargoBlackMarket                    0x0182  /* Cargo sold (10-20% loss) */

/* Planet punishment messages */
#define idmFreedomFightersHaveStolenKtStockpilesPress        0x0183  /* Mineral theft (5-45% loss) */
#define idmFreedomFightersHaveAttackedDestroyedMinesPress    0x0184  /* Mine destruction (5-36% pop loss) */

/* ============================================================================
 * FUNCTION DECLARATIONS
 * ============================================================================ */

/**
 * MAIN::IPlrAlsoCheater - Find another cheater with matching homeworld
 *
 * Searches for a player who is already flagged as cheater AND has the same
 * homeworld coordinates as the given player. Used to link cheaters who
 * shared save files with each other.
 *
 * Address: 1018:07aa
 *
 * @param iplr  Player index to check against
 * @return      Player index of matching cheater, or -1 if none found
 */
short IPlrAlsoCheater(short iplr);

/**
 * BATTLE::SpankTheCheaters - Apply turn-based penalties to cheaters
 *
 * Called during turn generation. Applies random penalties to cheaters:
 *   - Fleet defection (1/12 chance): Fleet abandons player
 *   - Cargo theft (11/12 chance): 10-20% of minerals sold on black market
 *   - Planet mineral theft: 5-45% of random mineral type stolen
 *   - Mine destruction: 5-36% of population equivalent mines destroyed
 *
 * Only activates after turn 10.
 *
 * Address: 10f0:192a
 */
void SpankTheCheaters(void);

/**
 * RACE::CAdvantagePoints - Calculate race advantage points
 *
 * Computes the "point value" of a race configuration. A valid race must
 * have at least 500 advantage points. If a race has fewer points, it
 * indicates the race file was illegally modified.
 *
 * Address: 10e0:444c
 *
 * @param pplr  Pointer to player structure
 * @return      Race advantage points (< 500 = invalid/hacked race)
 */
short CAdvantagePoints(PLAYER *pplr);

/**
 * MSG::FSendPlrMsg - Send a message to a player
 *
 * Packages and sends a message to a specific player. Messages are stored
 * in a buffer and included in the player's turn file.
 *
 * Address: 1030:7ee8
 *
 * @param iPlr  Player index to send message to
 * @param iMsg  Message ID
 * @param iObj  Object ID (planet/fleet ID for context)
 * @param p1-p7 Message parameters (substituted into message template)
 * @return      1 on success, 0 on failure
 */
short FSendPlrMsg(short iPlr, MessageId iMsg, short iObj,
                  short p1, short p2, short p3, short p4,
                  short p5, short p6, short p7);

/**
 * MSG::FSendPlrMsg2 - Send a simple message to a player
 *
 * Wrapper around FSendPlrMsg with only 2 parameters.
 *
 * Address: 1030:7eaa
 */
short FSendPlrMsg2(short iPlr, MessageId iMsg, short iObj, short p1, short p2);

/**
 * MSG::PackageUpMsg - Package a message for sending
 *
 * Builds a message packet with variable-length parameters.
 *
 * Address: 1030:802a
 *
 * @param pb    Output buffer
 * @param iPlr  Player index
 * @param iMsg  Message ID
 * @param iObj  Object ID
 * @param p1-p7 Parameters
 * @return      Message length in bytes, or -1 on failure
 */
short PackageUpMsg(uint8_t *pb, short iPlr, MessageId iMsg, short iObj,
                   short p1, short p2, short p3, short p4,
                   short p5, short p6, short p7);

/**
 * TURN2::Produce - Main production processing
 *
 * Processes planet production for a turn. Contains cheater production
 * penalty code that reduces production output by 20% (divides by 5,
 * multiplies by 4) for players with fCheater flag set.
 *
 * Address: 10b8:0000
 */
void Produce(void);

/**
 * UTILGEN::Random - Generate random number
 *
 * Returns a random number in range [0, max).
 *
 * Address: 1040:16d2
 *
 * @param max  Upper bound (exclusive)
 * @return     Random value 0 <= result < max
 */
short Random(short max);

/* ============================================================================
 * CHEATER DETECTION LOGIC (from FGenerateTurn)
 * ============================================================================
 *
 * Cheater detection occurs in TURN::FGenerateTurn (10b0:0000) during turn
 * generation. The logic:
 *
 * 1. For each player pair (i, j) where i > j:
 *    - Skip if either player is dead (flags43 bit 1) or AI (flags4 bit 9)
 *    - Compare homeworld coordinates from vrgts (turn serial data)
 *    - If coordinates match AND memcmp of bytes 4-14 differs:
 *      - Set fCheater (bit 2) on BOTH players
 *
 * 2. For each player with fCheater set:
 *    - Call IPlrAlsoCheater to find the matching cheater
 *    - Send cheater notification message
 *    - Every 8 turns (when turn % 8 == player_id % 8):
 *      - Send extra punishment message (strike demand)
 *
 * 3. SpankTheCheaters is called later to apply economic penalties
 */

#endif /* PUNISHMENT_H */
