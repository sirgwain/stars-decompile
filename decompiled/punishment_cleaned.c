/**
 * punishment_cleaned.c - Stars! Anti-Cheat and Punishment System (Cleaned)
 *
 * Cleaned decompilation from stars.exe 2.60j RC3
 * Original decompilation by Ghidra, cleaned for readability
 *
 * This file contains the anti-cheat detection and punishment mechanisms.
 */

#include "punishment_cleaned.h"
#include <string.h>

/* ============================================================================
 * External references (from game data structures)
 * ============================================================================ */

extern GAME        game;              /* Game settings and state */
extern PLAYER      rgplr[16];         /* Array of player structures */
extern FLEET      *rglpfl[];          /* Array of fleet pointers */
extern PLANET     *lpPlanets;         /* Pointer to planet array */
extern TURNSERIAL *vrgts;             /* Turn serial data (homeworld coords) */
extern int16_t     cFleet;            /* Number of fleets */
extern int16_t     cPlanet;           /* Number of planets */
extern uint8_t    *lpMsg;             /* Message buffer */
extern int16_t     imemMsgCur;        /* Current message buffer position */
extern int16_t     cMsg;              /* Message count */

/* External function declarations */
extern int16_t FValidSerialLong(uint32_t serial);
extern int16_t Random(int16_t max);
extern void    fmemmove(void *dst, void *src, uint16_t len);
extern int16_t fmemcmp(void *p1, void *p2, uint16_t len);


/* ============================================================================
 * IPlrAlsoCheater - Find another cheater with matching homeworld
 * ============================================================================
 * Address: 1018:07aa
 *
 * Searches for a player who:
 *   1. Is already flagged as cheater (fCheater bit set)
 *   2. Has the same homeworld coordinates as the given player
 *
 * This is used to identify which two players shared save files.
 *
 * @param iplr  Player index to check against
 * @return      Index of matching cheater, or -1 if none found
 */
int16_t IPlrAlsoCheater(int16_t iplr)
{
    TURNSERIAL *mySerial;
    TURNSERIAL *otherSerial;
    int16_t i;

    /* Get this player's turn serial data (contains homeworld coordinates) */
    mySerial = &vrgts[iplr];

    /* Validate that this player has a valid serial number */
    if (!FValidSerialLong(*(uint32_t *)mySerial)) {
        return -1;
    }

    /* Search all players for a matching cheater */
    for (i = 0; i < game.cPlayer; i++) {
        /* Skip self */
        if (i == iplr) {
            continue;
        }

        /* Check if this player is flagged as cheater */
        if (!(rgplr[i].flags43 & PLAYER_FLAG_CHEATER)) {
            continue;
        }

        otherSerial = &vrgts[i];

        /* Compare homeworld coordinates (first 4 bytes = X,Y) */
        if (*(uint32_t *)mySerial != *(uint32_t *)otherSerial) {
            continue;
        }

        /* Coordinates match - compare additional 11 bytes of serial data */
        /* If memcmp returns non-zero, the data differs (confirming different players) */
        if (fmemcmp(&mySerial->data[4], &otherSerial->data[4], 11) != 0) {
            return i;  /* Found matching cheater */
        }
    }

    return -1;  /* No matching cheater found */
}


/* ============================================================================
 * SpankTheCheaters - Apply turn-based penalties to cheating players
 * ============================================================================
 * Address: 10f0:192a
 *
 * Called during turn generation (after turn 10). Applies random penalties:
 *
 * For each FLEET owned by a cheater:
 *   - 1/12 chance: Fleet defects (abandons the player)
 *   - 11/12 chance: Cargo theft (10-20% of each mineral type sold)
 *
 * For each PLANET owned by a cheater:
 *   - 1/8 chance (special condition): Mine destruction
 *   - Otherwise 1/15 chance: Mineral theft (5-45% of one mineral type)
 */
void SpankTheCheaters(void)
{
    uint8_t rgfCheater[16];   /* Cached cheater flags for each player */
    int16_t hasCheater;       /* True if any player is a cheater */
    int16_t i, ifl;
    int16_t iplrOwner;
    FLEET  *lpfl;
    PLANET *lppl;

    /* -----------------------------------------------------------------
     * Phase 1: Build cache of cheater flags
     * ----------------------------------------------------------------- */
    hasCheater = 0;
    for (i = 0; i < game.cPlayer; i++) {
        rgfCheater[i] = (rgplr[i].flags43 & PLAYER_FLAG_CHEATER) ? 1 : 0;
        if (rgfCheater[i]) {
            hasCheater = 1;
        }
    }

    /* Only apply penalties after turn 10 and if there are cheaters */
    if (!hasCheater || game.turn <= 9) {
        return;
    }

    /* -----------------------------------------------------------------
     * Phase 2: Fleet penalties
     * ----------------------------------------------------------------- */
    for (ifl = 0; ifl < cFleet; ifl++) {
        lpfl = rglpfl[ifl];

        /* End of fleet list */
        if (lpfl == NULL) {
            break;
        }

        iplrOwner = lpfl->iplrOwner;

        /* Skip if fleet already punished this turn (bit 10 set) */
        if (lpfl->flags & FLEET_FLAG_PUNISHED) {
            continue;
        }

        /* Skip if owner is not a cheater */
        if (!rgfCheater[iplrOwner]) {
            continue;
        }

        /* Roll for punishment type */
        if (Random(12) == 0) {
            /*
             * FLEET DEFECTION (1/12 chance)
             * The fleet abandons the cheating player
             */
            lpfl->flags |= FLEET_FLAG_PUNISHED;
            FSendPlrMsg2(iplrOwner, idmHasDefectedRanksDueInabilityProjectLegitimate,
                         -5, lpfl->id, 0);
        }
        else {
            /*
             * CARGO THEFT (11/12 chance)
             * 10-20% of each mineral type is "sold on black market"
             */
            int16_t pctSell = 0;
            int16_t soldSomething = 0;

            for (i = 0; i < 3; i++) {  /* 3 mineral types: iron, bor, germ */
                int32_t cargo = lpfl->rgCargo[i];

                if (cargo <= 0) {
                    continue;
                }

                /* Calculate percentage to sell (10-20%) */
                if (!soldSomething) {
                    pctSell = Random(11) + 10;  /* 10-20% */
                    soldSomething = 1;
                }

                /* Calculate amount to steal */
                int32_t amountStolen = (cargo * pctSell) / 100;
                if (amountStolen == 0) {
                    amountStolen = 1;
                }

                /* Subtract from cargo */
                lpfl->rgCargo[i] -= amountStolen;
            }

            if (soldSomething) {
                FSendPlrMsg2(iplrOwner, idmCrewHasSoldOffCargoBlackMarket,
                             -5, lpfl->id, pctSell);
            }
        }
    }

    /* -----------------------------------------------------------------
     * Phase 3: Planet penalties
     * ----------------------------------------------------------------- */
    for (lppl = lpPlanets; lppl < lpPlanets + cPlanet; lppl++) {
        iplrOwner = lppl->iplrOwner;

        /* Skip unowned planets */
        if (iplrOwner == -1) {
            continue;
        }

        /* Skip if owner is not a cheater */
        if (!rgfCheater[iplrOwner]) {
            continue;
        }

        /* Special condition check (planet ID based) */
        int16_t specialCondition = ((lppl->id & 0xFFF) == 0);

        if (!specialCondition && Random(8) == 0) {
            /*
             * MINE DESTRUCTION (1/8 chance when special condition)
             * 5-36% of population equivalent in mines destroyed
             */
            int16_t pctDestroy = Random(31) + 5;  /* 5-36% */

            /* Calculate mines to destroy based on population */
            int32_t population = PLANET_GET_POPULATION(lppl);
            int32_t minesToDestroy = (population * pctDestroy) / 100;
            if (minesToDestroy < 1) {
                minesToDestroy = 1;
            }

            /* Reduce mine count */
            int16_t currentMines = PLANET_GET_MINES(lppl);
            PLANET_SET_MINES(lppl, currentMines - (int16_t)minesToDestroy);

            FSendPlrMsg2(iplrOwner, idmFreedomFightersHaveAttackedDestroyedMinesPress,
                         -5, lppl->id, (int16_t)minesToDestroy);
        }
        else if (Random(15) == 0) {
            /*
             * MINERAL THEFT (1/15 chance)
             * 5-45% of one random mineral type stolen
             */
            int16_t mineralType = Random(3);        /* 0=iron, 1=bor, 2=germ */
            int16_t pctSteal = Random(41) + 5;      /* 5-45% */

            int32_t mineralAmount = lppl->rgMinerals[mineralType];
            int32_t amountStolen = (mineralAmount * pctSteal) / 100;

            if (amountStolen > 0) {
                /* Cap at 30000 kT */
                if (amountStolen > 30000) {
                    amountStolen = 30000;
                }

                lppl->rgMinerals[mineralType] -= amountStolen;

                FSendPlrMsg(iplrOwner, idmFreedomFightersHaveStolenKtStockpilesPress,
                            -5, lppl->id, (int16_t)amountStolen, mineralType + 1,
                            0, 0, 0, 0);
            }
        }
    }
}


/* ============================================================================
 * FSendPlrMsg2 - Send a simple message to a player (2 params)
 * ============================================================================
 * Address: 1030:7eaa
 *
 * Wrapper around FSendPlrMsg with only 2 parameters.
 */
int16_t FSendPlrMsg2(int16_t iPlr, MessageId iMsg, int16_t iObj,
                     int16_t p1, int16_t p2)
{
    return FSendPlrMsg(iPlr, iMsg, iObj, p1, p2, 0, 0, 0, 0, 0);
}


/* ============================================================================
 * FSendPlrMsg - Send a message to a player
 * ============================================================================
 * Address: 1030:7ee8
 *
 * Packages and sends a message to a specific player. Messages are queued
 * in a buffer and included in the player's turn file.
 *
 * @param iPlr  Player index to send message to
 * @param iMsg  Message ID (from MessageId enum)
 * @param iObj  Object ID (planet/fleet for context, -5 for general)
 * @param p1-p7 Message parameters (substituted into message template)
 * @return      1 on success, 0 if skipped or failed
 */
int16_t FSendPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj,
                    int16_t p1, int16_t p2, int16_t p3, int16_t p4,
                    int16_t p5, int16_t p6, int16_t p7)
{
    uint8_t rgbWork[40];
    int16_t cbMsg;

    /* Package the message */
    cbMsg = PackageUpMsg(rgbWork, iPlr, iMsg, iObj, p1, p2, p3, p4, p5, p6, p7);

    if (cbMsg < 1) {
        /* Message was skipped (player is AI, etc.) or failed */
        return (cbMsg == 0) ? 1 : 0;
    }

    /* Append to message buffer */
    fmemmove(lpMsg + imemMsgCur, rgbWork, cbMsg);
    imemMsgCur += cbMsg;
    cMsg++;

    return 1;
}


/* ============================================================================
 * PackageUpMsg - Package a message for sending
 * ============================================================================
 * Address: 1030:802a
 *
 * Builds a variable-length message packet. Messages are skipped for AI
 * players unless they are certain important message types.
 *
 * Message format:
 *   Byte 0:     [param_size:4][player_id:4]
 *   Bytes 1-2:  [param_flags:7][message_id:9]
 *   Bytes 3-4:  object_id
 *   Bytes 5+:   parameters (1 or 2 bytes each based on flags)
 *
 * @return  Message length in bytes, 0 if skipped, -1 if buffer full
 */
int16_t PackageUpMsg(uint8_t *pb, int16_t iPlr, MessageId iMsg, int16_t iObj,
                     int16_t p1, int16_t p2, int16_t p3, int16_t p4,
                     int16_t p5, int16_t p6, int16_t p7)
{
    int16_t params[7];
    uint8_t *lpb;
    uint16_t grbit;
    int16_t i, numParams;

    /* Skip if no player specified */
    if (iPlr == -1) {
        return 0;
    }

    /* Check if player should receive messages */
    /* Skip AI players (bit 9 of flags4) unless special conditions */
    int isAI = (rgplr[iPlr].flags4 >> 9) & 1;
    int aiRace = (rgplr[iPlr].flags4 >> 13) & 7;

    if (isAI && aiRace != 7) {
        /* AI player - check for important message types that should be sent */
        if (iMsg != idmHasBombedKillingOffEnemyColonists &&
            iMsg != idmHaveAttackedFirstRateStormTroopersThough &&
            iMsg != idmColonistsHaveDiedOffLongerControlPlanet &&
            iMsg != idmColonistsHaveJumpedShipLongerControlPlanet) {
            return 0;  /* Skip this message */
        }
    }

    /* Check for buffer space */
    if (imemMsgCur + 20 >= 0xFFC9) {
        return -1;  /* Buffer full */
    }

    /* Build message header */
    pb[0] = (pb[0] & 0xF0) | (iPlr & 0x0F);  /* Player ID in low nibble */

    /* Message ID in bits 0-8, param flags in bits 9-15 */
    *(uint16_t *)(pb + 1) = iMsg & 0x1FF;

    /* Object ID */
    *(int16_t *)(pb + 3) = iObj;

    /* Package parameters */
    params[0] = p1; params[1] = p2; params[2] = p3; params[3] = p4;
    params[4] = p5; params[5] = p6; params[6] = p7;

    lpb = pb + 5;
    grbit = 1;

    /* Get number of parameters for this message type from message table */
    numParams = GetMessageParamCount(iMsg);

    for (i = 0; i < numParams; i++) {
        if ((params[i] & 0xFF00) == 0) {
            /* Single byte parameter */
            *lpb++ = (uint8_t)params[i];
        }
        else {
            /* Two byte parameter - set flag bit */
            *(uint16_t *)(pb + 1) |= (grbit << 9);
            *(int16_t *)lpb = params[i];
            lpb += 2;
        }
        grbit <<= 1;
    }

    /* Store parameter data size in high nibble of byte 0 */
    pb[0] = (pb[0] & 0x0F) | (((lpb - (pb + 5)) & 0x0F) << 4);

    return (int16_t)(lpb - pb);
}


/* ============================================================================
 * CHEATER DETECTION (extracted from FGenerateTurn)
 * ============================================================================
 * Address: 10b0:0000 (within FGenerateTurn)
 *
 * This code runs during turn generation to detect file sharing.
 *
 * Pseudocode:
 *
 *   void DetectCheaters(void) {
 *       // For each player
 *       for (int i = 0; i < game.cPlayer; i++) {
 *           // Skip dead or AI players
 *           if (rgplr[i].flags43 & PLAYER_FLAG_DEAD) continue;
 *           if (rgplr[i].flags4 & PLAYER_IS_AI) continue;
 *
 *           // Clear cheater flag initially
 *           rgplr[i].flags43 &= ~PLAYER_FLAG_CHEATER;
 *
 *           // Compare against all earlier players
 *           for (int j = 0; j < i; j++) {
 *               if (rgplr[j].flags43 & PLAYER_FLAG_DEAD) continue;
 *               if (rgplr[j].flags4 & PLAYER_IS_AI) continue;
 *
 *               // Compare homeworld coordinates
 *               if (vrgts[i].x == vrgts[j].x && vrgts[i].y == vrgts[j].y) {
 *                   // Compare 11 bytes of additional serial data
 *                   if (memcmp(&vrgts[i].data[4], &vrgts[j].data[4], 11) != 0) {
 *                       // Match! Both players are cheaters
 *                       rgplr[i].flags43 |= PLAYER_FLAG_CHEATER;
 *                       rgplr[j].flags43 |= PLAYER_FLAG_CHEATER;
 *                   }
 *               }
 *           }
 *       }
 *
 *       // Send notifications to cheaters
 *       for (int i = 0; i < game.cPlayer; i++) {
 *           if (rgplr[i].flags43 & PLAYER_FLAG_CHEATER) {
 *               int partner = IPlrAlsoCheater(i);
 *               FSendPlrMsg2(i, idmCheaterDetected + (partner != -1),
 *                            -5, partner, 0);
 *
 *               // Extra punishment every 8 turns
 *               if (game.turn > 10 && (game.turn % 8) == (i % 8)) {
 *                   FSendPlrMsg2(i, idmFleetCaptainsHaveStagedStrikeDemandFree,
 *                                -5, 0, 0);
 *               }
 *           }
 *       }
 *   }
 */


/* ============================================================================
 * PRODUCTION PENALTY (extracted from Produce function)
 * ============================================================================
 * Address: 10b8:0000 (within Produce)
 *
 * When calculating planet production, cheaters receive a 20% penalty.
 *
 * Pseudocode:
 *
 *   int32_t resources = CalculatePlanetResources(lppl, iplrOwner);
 *
 *   // Apply cheater penalty
 *   if (rgplr[iplrOwner].flags43 & PLAYER_FLAG_CHEATER) {
 *       resources = (resources * 4) / 5;  // 80% of normal
 *   }
 */
