/**
 * punishment_cleaned.h - Stars! Anti-Cheat and Punishment System (Cleaned)
 *
 * Cleaned decompilation from stars.exe 2.60j RC3
 * Original decompilation by Ghidra, cleaned for readability
 */

#ifndef PUNISHMENT_CLEANED_H
#define PUNISHMENT_CLEANED_H

#include <stdint.h>

/* ============================================================================
 * TYPE DEFINITIONS
 * ============================================================================ */

typedef uint16_t MessageId;

/* Turn serial data - contains registration serial and hardware fingerprint for piracy detection */
typedef struct _TURNSERIAL {
    uint8_t data[16];      /* Bytes 0-3: lSerial (registration); Bytes 4-14: pbEnv (hardware fingerprint) */
} TURNSERIAL;

/* Game state structure */
typedef struct _GAME {
    int32_t  lid;           /* +0x00: Game ID */
    int16_t  mdSize;        /* +0x04: Universe size */
    int16_t  mdDensity;     /* +0x06: Planet density */
    int16_t  cPlayer;       /* +0x08: Number of players */
    int16_t  cPlanMax;      /* +0x0A: Max planets */
    int16_t  mdStartDist;   /* +0x0C: Starting distance */
    int16_t  fDirty;        /* +0x0E: Dirty flag */
    uint16_t flags9;        /* +0x10: Game flags */
    uint16_t turn;          /* +0x12: Current turn number */
    uint8_t  rgvc[12];      /* +0x14: Victory conditions */
    char     szName[32];    /* +0x20: Game name */
} GAME;

/* Player structure (partial - punishment-relevant fields) */
typedef struct _PLAYER {
    uint8_t  reserved1[0x43];   /* +0x00-0x42: Various fields */
    uint16_t flags43;           /* +0x43: Player state flags */
    uint8_t  reserved2[0x0B];   /* +0x45-0x4F: Various fields */
    uint16_t flags4;            /* +0x50: More flags (AI status, etc.) */
    uint8_t  reserved3[0x19];   /* +0x52-0x6A: Various fields */
    char     pctIdealGrowth;    /* +0x6B: Growth rate (for hacker detection) */
    char     rgEnvVar[3];       /* +0x6C-0x6E: Environment variables */
    uint8_t  reserved4[0x51];   /* +0x6F-0xBF: Various fields */
} PLAYER;  /* Total size: 0xC0 (192 bytes) */

/* Fleet structure (partial) */
typedef struct _FLEET {
    int16_t  id;            /* +0x00: Fleet ID */
    int16_t  iplrOwner;     /* +0x02: Owning player index */
    uint16_t flags;         /* +0x04: Fleet flags */
    uint8_t  reserved1[0x46]; /* +0x06-0x4B */
    int32_t  rgCargo[3];    /* +0x4C: Cargo (iron, bor, germ) */
    uint8_t  reserved2[0x18]; /* +0x58-0x6F: Various fields */
} FLEET;

/* Planet structure (partial) */
typedef struct _PLANET {
    int16_t  id;            /* +0x00: Planet ID */
    int16_t  iplrOwner;     /* +0x02: Owning player index (-1 = unowned) */
    uint8_t  reserved1[0x10]; /* +0x04-0x13 */
    uint16_t popMinesLow;   /* +0x14: Population/mines (packed) */
    uint16_t popMinesHigh;  /* +0x16: Population/mines high bits */
    uint8_t  reserved2[0x04]; /* +0x18-0x1B */
    int32_t  rgMinerals[3]; /* +0x1C: Surface minerals (iron, bor, germ) */
    uint8_t  reserved3[0x10]; /* +0x28-0x37 */
} PLANET;  /* Total size: 0x38 (56 bytes) */

/* ============================================================================
 * PLAYER FLAGS (at offset 0x43 = flags43)
 * ============================================================================ */

#define PLAYER_FLAG_DEAD      0x0002  /* Bit 1: Player eliminated */
#define PLAYER_FLAG_CHEATER   0x0004  /* Bit 2: File sharing detected */
#define PLAYER_FLAG_LEARNED   0x0008  /* Bit 3: Has learned from battle */
#define PLAYER_FLAG_HACKER    0x0010  /* Bit 4: Race file modified */

/* ============================================================================
 * FLEET FLAGS (at offset 0x04)
 * ============================================================================ */

#define FLEET_FLAG_PUNISHED   0x0400  /* Bit 10: Already punished this turn */

/* ============================================================================
 * PLANET MACROS
 * ============================================================================ */

/* Population is stored in bits 8-19 of popMines fields */
#define PLANET_GET_POPULATION(lppl) \
    ((((lppl)->popMinesHigh & 0x0F) << 8) | (((lppl)->popMinesLow >> 8) & 0xFF))

#define PLANET_SET_POPULATION(lppl, pop) do { \
    (lppl)->popMinesLow = ((lppl)->popMinesLow & 0x00FF) | (((pop) & 0xFF) << 8); \
    (lppl)->popMinesHigh = ((lppl)->popMinesHigh & 0xFFF0) | (((pop) >> 8) & 0x0F); \
} while(0)

/* Mines stored in bits 8-19 similarly (different encoding) */
#define PLANET_GET_MINES(lppl) \
    ((((lppl)->popMinesLow >> 8) & 0xFF) | (((lppl)->popMinesHigh & 0x0F) << 8))

#define PLANET_SET_MINES(lppl, mines) do { \
    (lppl)->popMinesLow = ((lppl)->popMinesLow & 0x00FF) | (((mines) & 0xFF) << 8); \
    (lppl)->popMinesHigh = ((lppl)->popMinesHigh & 0xFFF0) | (((mines) >> 8) & 0x0F); \
} while(0)

/* ============================================================================
 * MESSAGE IDs
 * ============================================================================ */

/* Cheater-related messages */
#define idmPopulationSuspectsUsurperProductivityOff20Growth  0x0179
#define idmFleetCaptainsHaveStagedStrikeDemandFree           0x0180
#define idmHasDefectedRanksDueInabilityProjectLegitimate     0x0181
#define idmCrewHasSoldOffCargoBlackMarket                    0x0182
#define idmFreedomFightersHaveStolenKtStockpilesPress        0x0183
#define idmFreedomFightersHaveAttackedDestroyedMinesPress    0x0184

/* Other message IDs referenced in code */
#define idmHasBombedKillingOffEnemyColonists                 0x00A1
#define idmHaveAttackedFirstRateStormTroopersThough          0x00A2
#define idmColonistsHaveDiedOffLongerControlPlanet           0x00A3
#define idmColonistsHaveJumpedShipLongerControlPlanet        0x00A4

/* ============================================================================
 * PUNISHMENT CONSTANTS
 * ============================================================================ */

#define TECH_CAP_NORMAL               25    /* Max tech for normal players */
#define TECH_CAP_PUNISHED             9     /* Max tech for cheaters */
#define RACE_VALUE_MINIMUM            500   /* Min valid race points */
#define CHEATER_PRODUCTION_PERCENT    80    /* Production reduced to 80% */
#define MIN_TURN_FOR_PUNISHMENT       10    /* Punishments start after turn 10 */

/* SpankTheCheaters probabilities */
#define PROB_FLEET_DEFECTION          12    /* 1/12 chance = 8.3% */
#define PROB_MINE_DESTRUCTION         8     /* 1/8 chance = 12.5% */
#define PROB_MINERAL_THEFT            15    /* 1/15 chance = 6.7% */

/* Cargo theft percentages */
#define MIN_CARGO_THEFT_PERCENT       10
#define MAX_CARGO_THEFT_PERCENT       20    /* 10 + Random(11) */

/* Mineral theft percentages */
#define MIN_MINERAL_THEFT_PERCENT     5
#define MAX_MINERAL_THEFT_PERCENT     45    /* 5 + Random(41) */
#define MAX_MINERAL_THEFT_AMOUNT      30000

/* Mine destruction percentages */
#define MIN_MINE_DESTROY_PERCENT      5
#define MAX_MINE_DESTROY_PERCENT      36    /* 5 + Random(31) */

/* ============================================================================
 * FUNCTION DECLARATIONS
 * ============================================================================ */

/**
 * Find another cheater with matching homeworld coordinates
 *
 * @param iplr  Player index to check
 * @return      Index of matching cheater, or -1 if none
 */
int16_t IPlrAlsoCheater(int16_t iplr);

/**
 * Apply turn-based penalties to all cheaters
 * Called during turn generation after turn 10
 */
void SpankTheCheaters(void);

/**
 * Send a message to a player (10 params version)
 */
int16_t FSendPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj,
                    int16_t p1, int16_t p2, int16_t p3, int16_t p4,
                    int16_t p5, int16_t p6, int16_t p7);

/**
 * Send a message to a player (2 params version)
 */
int16_t FSendPlrMsg2(int16_t iPlr, MessageId iMsg, int16_t iObj,
                     int16_t p1, int16_t p2);

/**
 * Package a message into buffer
 *
 * @return  Message length, 0 if skipped, -1 if buffer full
 */
int16_t PackageUpMsg(uint8_t *pb, int16_t iPlr, MessageId iMsg, int16_t iObj,
                     int16_t p1, int16_t p2, int16_t p3, int16_t p4,
                     int16_t p5, int16_t p6, int16_t p7);

/**
 * Get number of parameters for a message type
 * (Looks up in message parameter count table)
 */
int16_t GetMessageParamCount(MessageId iMsg);

/* ============================================================================
 * DETECTION/PENALTY SUMMARY
 * ============================================================================
 *
 * DETECTION (in FGenerateTurn):
 *   - Compare homeworld coordinates between all player pairs
 *   - If coords match but serial data differs -> both players flagged
 *
 * PENALTIES (in SpankTheCheaters, after turn 10):
 *
 *   FLEET PENALTIES (per fleet):
 *   +------------------+--------+--------------------------------+
 *   | Penalty          | Chance | Effect                         |
 *   +------------------+--------+--------------------------------+
 *   | Defection        | 8.3%   | Fleet abandons player          |
 *   | Cargo theft      | 91.7%  | 10-20% of each mineral sold    |
 *   +------------------+--------+--------------------------------+
 *
 *   PLANET PENALTIES (per planet):
 *   +------------------+--------+--------------------------------+
 *   | Penalty          | Chance | Effect                         |
 *   +------------------+--------+--------------------------------+
 *   | Mine destruction | 12.5%  | 5-36% mines destroyed          |
 *   | Mineral theft    | 5.8%   | 5-45% of one mineral stolen    |
 *   +------------------+--------+--------------------------------+
 *
 *   PRODUCTION PENALTY (in Produce):
 *   - All resource generation reduced to 80%
 *
 *   TECH PENALTY (in tech advancement):
 *   - Tech level capped at 9 (vs 25 normal)
 *
 *   MESSAGE PENALTY (every 8 turns):
 *   - Extra threatening message sent
 */

#endif /* PUNISHMENT_CLEANED_H */
