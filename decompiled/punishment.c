/**
 * punishment.c - Stars! Anti-Cheat and Punishment System
 *
 * Extracted from all_funcs.c decompilation of stars.exe 2.60j RC3
 *
 * This file contains all punishment-related code extracted from the decompilation.
 * Each section is annotated with original line numbers from all_funcs.c.
 */

#include "punishment.h"

/* ============================================================================
 * SECTION 1: CHEATER DETECTION (File Sharing)
 * ============================================================================
 *
 * When players share .m files, their homeworld coordinates will match.
 * The game detects this by comparing coordinates between all player pairs.
 *
 * Source: all_funcs.c:71947-71967
 */

/*
 * Original code (lines 71947-71967):
 *
 *     pbVar1 = (byte *)((int)&DAT_1120_59d6 + local_4 * 0xc0);
 *     *pbVar1 = *pbVar1 & 0xfb;                    // Clear fCheater initially
 *     for (fErrSav = 0; fErrSav < (int)local_4; fErrSav = fErrSav + 1) {
 *       if (((*(byte *)((int)&DAT_1120_59d6 + fErrSav * 0xc0) & 2) == 0) &&    // Not fCrippled
 *          ((*(byte *)(fErrSav * 0xc0 + 0x5989) & 2) == 0)) {                  // Other flag check
 *         uVar12 = (undefined2)((ulong)_DAT_1120_0974 >> 0x10);
 *         iVar19 = (int)_DAT_1120_0974;
 *         // Compare homeworld coordinates:
 *         if ((*(int *)(fErrSav * 0x10 + iVar19) == *(int *)(local_4 * 0x10 + iVar19)) &&
 *            ((*(int *)(fErrSav * 0x10 + iVar19 + 2) == *(int *)(local_4 * 0x10 + iVar19 + 2)
 *             && (iVar19 = FUN_1118_0ede(), iVar19 != 0)))) {
 *           // Coordinates match - flag BOTH players as cheaters
 *           pbVar1 = (byte *)((int)&DAT_1120_59d6 + fErrSav * 0xc0);
 *           *pbVar1 = *pbVar1 | 4;                 // Set fCheater on player fErrSav
 *           pbVar1 = (byte *)((int)&DAT_1120_59d6 + local_4 * 0xc0);
 *           *pbVar1 = *pbVar1 | 4;                 // Set fCheater on player local_4
 *         }
 *       }
 *     }
 *
 * PSEUDOCODE:
 *
 *     void detect_file_sharing(void) {
 *         for (int player = 0; player < player_count; player++) {
 *             player_flags[player] &= ~PLAYER_FLAG_CHEATER;  // Clear initially
 *
 *             for (int other = 0; other < player; other++) {
 *                 if (!(player_flags[other] & PLAYER_FLAG_CRIPPLED) &&
 *                     !is_player_eliminated(other)) {
 *
 *                     if (homeworld_coords_match(player, other)) {
 *                         player_flags[player] |= PLAYER_FLAG_CHEATER;
 *                         player_flags[other] |= PLAYER_FLAG_CHEATER;
 *                     }
 *                 }
 *             }
 *         }
 *     }
 */


/* ============================================================================
 * SECTION 2: FIND MATCHING CHEATER FUNCTION
 * ============================================================================
 *
 * FUN_1018_050e: Searches for another cheater with matching homeworld.
 * Used after flagging a player to find their "partner in crime".
 *
 * Source: all_funcs.c:2366-2396
 */

/*
 * Original code (lines 2366-2396):
 *
 * int __cdecl16far FUN_1018_050e(int param_1)
 * {
 *   int iVar1;
 *   int iVar2;
 *   int iVar3;
 *   undefined2 uVar4;
 *   int local_4;
 *
 *   uVar4 = (undefined2)((ulong)_DAT_1120_0974 >> 0x10);
 *   iVar1 = FUN_1070_2ff6(*(undefined2 *)(param_1 * 0x10 + (int)_DAT_1120_0974),
 *                         *(undefined2 *)(param_1 * 0x10 + (int)_DAT_1120_0974 + 2));
 *   if (iVar1 != 0) {
 *     for (local_4 = 0; local_4 < DAT_1120_0078; local_4 = local_4 + 1) {
 *       // Check if other player is a cheater
 *       if ((local_4 != param_1) && ((*(byte *)((int)&DAT_1120_59d6 + local_4 * 0xc0) & 4) != 0)) {
 *         iVar1 = local_4 * 0x10;
 *         uVar4 = (undefined2)((ulong)_DAT_1120_0974 >> 0x10);
 *         iVar3 = (int)_DAT_1120_0974;
 *         iVar2 = param_1 * 0x10;
 *         // Compare homeworld coordinates (X,Y)
 *         if ((*(int *)(iVar1 + iVar3) == *(int *)(iVar2 + iVar3)) &&
 *            (*(int *)(iVar1 + iVar3 + 2) == *(int *)(iVar2 + iVar3 + 2))) {
 *           // FUN_1118_0ede compares 11 bytes of additional data
 *           iVar1 = FUN_1118_0ede(iVar2 + iVar3 + 4,uVar4,iVar1 + iVar3 + 4,uVar4,0xb);
 *           if (iVar1 != 0) {
 *             return local_4;  // Found matching cheater
 *           }
 *         }
 *       }
 *     }
 *   }
 *   return -1;  // No match found
 * }
 *
 * PSEUDOCODE:
 *
 *     int find_matching_cheater(int player_id) {
 *         if (!has_valid_homeworld(player_id)) return -1;
 *
 *         for (int i = 0; i < player_count; i++) {
 *             if (i == player_id) continue;
 *             if (!(player_flags[i] & PLAYER_FLAG_CHEATER)) continue;
 *
 *             if (homeworld_x[i] == homeworld_x[player_id] &&
 *                 homeworld_y[i] == homeworld_y[player_id] &&
 *                 memcmp(&homeworld_data[i][4], &homeworld_data[player_id][4], 11) != 0) {
 *                 return i;  // Found matching cheater partner
 *             }
 *         }
 *         return -1;
 *     }
 */


/* ============================================================================
 * SECTION 3: HACKER DETECTION (Race File Modification)
 * ============================================================================
 *
 * When a race file is modified to gain illegal advantages, the race value
 * calculation will return < 500. The game detects this and:
 *   1. Sets fHacker flag
 *   2. Tries to increase tech (0x59C0) to make race valid - WRONG OFFSET?
 *   3. Decreases growth rate (0x599B) until valid or minimum reached
 *   4. If still invalid, zeros tech levels 8-13
 *
 * Source: all_funcs.c:72141-72177
 */

/*
 * Original code (lines 72141-72177):
 *
 *     // Check if fHacker flag changed state
 *     uStack_166 = (*(byte *)((int)&DAT_1120_59d6 + local_4 * 0xc0) & 0x10) >> 4;
 *     iVar19 = FUN_10e0_3356((int)&c_common::vtickTooltip1stVis + local_4 * 0xc0);
 *     uStack_16a = CONCAT22(uStack_16a._2_2_,iVar19);
 *
 *     if (((iVar19 < 0) ||
 *         ((*(byte *)((int)&DAT_1120_59d6 + local_4 * 0xc0) & 0x10) >> 4 != uStack_166)) &&
 *        ((*(byte *)(local_4 * 0xc0 + 0x5989) & 2) == 0)) {
 *
 *       // Send notification messages
 *       FUN_1030_766a();  // Message to hacker
 *       for (uStack_166 = 0; (int)uStack_166 < DAT_1120_0078; uStack_166 = uStack_166 + 1) {
 *         if ((uStack_166 != local_4) && ((*(byte *)(local_4 * 0xc0 + 0x5989) & 2) == 0)) {
 *           FUN_1030_766a();  // Message to other players
 *         }
 *       }
 *
 *       // Set fHacker flag
 *       pbVar1 = (byte *)((int)&DAT_1120_59d6 + local_4 * 0xc0);
 *       *pbVar1 = *pbVar1 | 0x10;
 *
 *       iVar19 = (uint)uStack_16a;
 *
 *       // First try: Increase tech levels until race is valid
 *       // (offset 0x59C0 - 0x5982 = 0x3E = tech levels)
 *       while ((iVar19 < 500 && (*(char *)(local_4 * 0xc0 + 0x59c0) < '\x19'))) {
 *         pcVar2 = (char *)(local_4 * 0xc0 + 0x59c0);
 *         *pcVar2 = *pcVar2 + '\x01';  // Increase tech by 1
 *         iVar19 = FUN_10e0_3356((int)&c_common::vtickTooltip1stVis + local_4 * 0xc0);
 *         uStack_16a = CONCAT22(uStack_16a._2_2_,iVar19);
 *       }
 *
 *       iVar19 = (uint)uStack_16a;
 *
 *       // Second try: Decrease growth rate until race is valid
 *       // (offset 0x599B - 0x5982 = 0x19 = growth rate)
 *       while ((iVar19 < 500 && ('\x01' < *(char *)(local_4 * 0xc0 + 0x599b)))) {
 *         pcVar2 = (char *)(local_4 * 0xc0 + 0x599b);
 *         *pcVar2 = *pcVar2 + -1;  // DECREASE growth rate by 1
 *         iVar19 = FUN_10e0_3356((int)&c_common::vtickTooltip1stVis + local_4 * 0xc0);
 *         uStack_16a = CONCAT22(uStack_16a._2_2_,iVar19);
 *       }
 *
 *       // Last resort: Zero out tech levels 8-13
 *       if ((int)(uint)uStack_16a < 500) {
 *         for (uStack_166 = 8; (int)uStack_166 < 0xe; uStack_166 = uStack_166 + 1) {
 *           *(undefined *)(uStack_166 + local_4 * 0xc0 + 0x59c0) = 0;
 *           iVar19 = FUN_10e0_3356((int)&c_common::vtickTooltip1stVis + local_4 * 0xc0);
 *           uStack_16a = CONCAT22(uStack_16a._2_2_,iVar19);
 *           if (499 < iVar19) break;
 *         }
 *       }
 *     }
 *
 * PSEUDOCODE:
 *
 *     void handle_hacked_race(int player_id) {
 *         int old_hacker_flag = (player_flags[player_id] & PLAYER_FLAG_HACKER) >> 4;
 *         int race_value = calculate_race_value(&players[player_id]);
 *
 *         // If race is invalid or hacker status changed
 *         if ((race_value < 0 || hacker_flag_changed) && !is_eliminated(player_id)) {
 *
 *             // Notify all players
 *             send_hacker_message(player_id);
 *             for (int i = 0; i < player_count; i++) {
 *                 if (i != player_id) send_hacker_notification(i, player_id);
 *             }
 *
 *             // Set hacker flag
 *             player_flags[player_id] |= PLAYER_FLAG_HACKER;
 *
 *             // Try increasing some tech value (purpose unclear)
 *             while (race_value < 500 && players[player_id].tech_something < 25) {
 *                 players[player_id].tech_something++;
 *                 race_value = calculate_race_value(&players[player_id]);
 *             }
 *
 *             // Decrease growth rate as punishment
 *             while (race_value < 500 && players[player_id].growth_rate > 1) {
 *                 players[player_id].growth_rate--;
 *                 race_value = calculate_race_value(&players[player_id]);
 *             }
 *
 *             // Zero out tech levels 8-13 if still invalid
 *             if (race_value < 500) {
 *                 for (int tech = 8; tech < 14; tech++) {
 *                     players[player_id].tech_levels[tech] = 0;
 *                     race_value = calculate_race_value(&players[player_id]);
 *                     if (race_value >= 500) break;
 *                 }
 *             }
 *         }
 *     }
 */


/* ============================================================================
 * SECTION 4: CHEATER PUNISHMENT LOOP
 * ============================================================================
 *
 * After detecting cheaters, this code applies additional punishment:
 *   1. Finds matching cheater partner
 *   2. Sends notification message
 *   3. Every 8 turns (when player_id mod 8 == turn mod 8), extra punishment
 *
 * Source: all_funcs.c:71974-71984
 */

/*
 * Original code (lines 71974-71984):
 *
 *     for (local_4 = 0; (int)local_4 < DAT_1120_0078; local_4 = local_4 + 1) {
 *       if ((*(byte *)((int)&DAT_1120_59d6 + local_4 * 0xc0) & 4) != 0) {
 *         FUN_1018_050e(local_4);      // Find matching cheater
 *         FUN_1030_766a();             // Send notification message
 *         if (10 < DAT_1120_0082) {    // If turn > 10
 *           if (((byte)local_4 & 7) == ((byte)DAT_1120_0082 & 7)) {
 *             FUN_1030_766a();         // Extra punishment message every 8 turns
 *           }
 *         }
 *       }
 *     }
 *
 * PSEUDOCODE:
 *
 *     void apply_cheater_punishment(void) {
 *         for (int player = 0; player < player_count; player++) {
 *             if (player_flags[player] & PLAYER_FLAG_CHEATER) {
 *                 find_matching_cheater(player);
 *                 send_cheater_notification();
 *
 *                 // Extra punishment every 8 turns (staggered by player ID)
 *                 if (current_turn > 10 && (player % 8) == (current_turn % 8)) {
 *                     send_extra_punishment_message();
 *                 }
 *             }
 *         }
 *     }
 */


/* ============================================================================
 * SECTION 5: TECH LEVEL CAP
 * ============================================================================
 *
 * Technology advancement is capped based on player status:
 *   - Normal players: Max tech level 25 (0x19)
 *   - fCrippled OR fCheater: Max tech level 9 (0x09)
 *
 * NOTE: fHacker does NOT trigger this cap (only growth degradation)
 *
 * Source: all_funcs.c:81620-81622
 */

/*
 * Original code (lines 81620-81622):
 *
 *     if ((('\x19' < *pcVar8) ||                                                // tech > 25
 *         (((*(byte *)((int)&DAT_1120_59d6 + local_14) & 2) != 0 &&             // fCrippled
 *           ('\t' < *pcVar8)))) ||                                              // AND tech > 9
 *        (((*(byte *)((int)&DAT_1120_59d6 + local_14) & 4) != 0 &&              // fCheater
 *          ('\t' < *pcVar8))))                                                  // AND tech > 9
 *       goto LAB_10b8_598f;  // Block tech advancement
 *
 * PSEUDOCODE:
 *
 *     bool is_tech_capped(int player_id, int tech_level) {
 *         // All players capped at 25
 *         if (tech_level > 25) return true;
 *
 *         // Crippled or Cheater players capped at 9
 *         if ((player_flags[player_id] & PLAYER_FLAG_CRIPPLED) && tech_level > 9) {
 *             return true;
 *         }
 *         if ((player_flags[player_id] & PLAYER_FLAG_CHEATER) && tech_level > 9) {
 *             return true;
 *         }
 *
 *         return false;
 *     }
 */


/* ============================================================================
 * SECTION 6: PRODUCTION PENALTY (80%)
 * ============================================================================
 *
 * Cheaters receive a 20% production penalty: output *= 4/5
 *
 * Source: all_funcs.c:77292-77298
 */

/*
 * Original code (lines 77292-77298):
 *
 *     if ((*(byte *)((int)&DAT_1120_59d6 + *(int *)(iVar8 + 2) * 0xc0) & 4) != 0) {
 *       _fPrevProdIsAlch = lVar17;
 *       lVar17 = FUN_1118_0c28(idm * 4,
 *                              (i * 2 + (uint)CARRY2(idm,idm)) * 2 +
 *                              (uint)CARRY2(idm * 2,idm * 2),
 *                              5,
 *                              0);  // Multiply by 4, divide by 5 = 80%
 *       fPrevProdIsAlch = (short)lVar17;
 *       prodPartial.flags1 = (short)((ulong)lVar17 >> 0x10);
 *     }
 *
 * PSEUDOCODE:
 *
 *     int apply_production_penalty(int player_id, int production) {
 *         if (player_flags[player_id] & PLAYER_FLAG_CHEATER) {
 *             // Reduce production to 80%
 *             production = (production * 4) / 5;
 *         }
 *         return production;
 *     }
 */


/* ============================================================================
 * SECTION 7: PRODUCTION PENALTY (50%)
 * ============================================================================
 *
 * Under certain conditions (DAT_1120_078a & 2), cheaters have production halved.
 *
 * Source: all_funcs.c:17879-17882
 */

/*
 * Original code (lines 17879-17882):
 *
 *     if (((DAT_1120_078a & 2) != 0) &&
 *        ((*(byte *)((int)&DAT_1120_59d6 + *(int *)(iVar12 + 2) * 0xc0) & 4) != 0)) {
 *       local_a = local_a >> 1 | (uint)((uVar9 & 1) != 0) << 0xf;
 *       // ^ Right shift by 1 = divide by 2 = 50% penalty
 *     }
 *
 * PSEUDOCODE:
 *
 *     int apply_conditional_production_penalty(int player_id, int value, int flags) {
 *         if ((game_flags & 0x02) && (player_flags[player_id] & PLAYER_FLAG_CHEATER)) {
 *             value = value / 2;  // 50% penalty
 *         }
 *         return value;
 *     }
 */


/* ============================================================================
 * SECTION 8: RANDOM EVENT PUNISHMENT
 * ============================================================================
 *
 * Cheaters face additional random negative events triggered probabilistically
 * based on turn number and player ID.
 *
 * Source: all_funcs.c:73342-73358
 */

/*
 * Original code (lines 73342-73358):
 *
 *     if ((*(byte *)((int)&DAT_1120_59d6 + *(int *)(uVar16 + 2) * 0xc0) & 4) != 0) {
 *       // Timing check: only punish if turn < 11 OR player_id mod 8 != turn mod 8
 *       if ((DAT_1120_0082 < 0xb) ||
 *          ((*(byte *)(uVar16 + 2) & 7) != ((byte)DAT_1120_0082 & 7))) {
 *         iVar11 = FUN_1040_1676(4);  // Random check with threshold 4
 *         if (iVar11 != 0) goto LAB_10b0_2312;  // Skip punishment if random passes
 *         // ... send punishment message (0x102 = message ID) ...
 *         FUN_1030_766a(*(undefined2 *)(iVar11 + 2), 0x102, 0xfffb, uVar16, 0);
 *       }
 *       goto LAB_10b0_2236;
 *     }
 *
 * PSEUDOCODE:
 *
 *     void apply_random_event_punishment(int player_id, ...) {
 *         if (!(player_flags[player_id] & PLAYER_FLAG_CHEATER)) {
 *             return;  // Normal players exempt
 *         }
 *
 *         // Stagger punishment timing by player ID
 *         if (current_turn >= 11 && (player_id % 8) == (current_turn % 8)) {
 *             return;  // Skip this turn for this player
 *         }
 *
 *         // 1 in 4 chance to avoid punishment
 *         if (random_check(4) != 0) {
 *             return;  // Lucky, no punishment this time
 *         }
 *
 *         // Apply random negative event
 *         send_punishment_event(player_id, EVENT_CHEATER_PENALTY);
 *     }
 */


/* ============================================================================
 * SECTION 9: MESSAGE STRINGS
 * ============================================================================
 *
 * From strings_uncompressed.c - punishment notification messages:
 *
 * 0x015a: "\\s has degraded \\p from a value of \\i% to \\i%."
 *         - Sent when race value degradation occurs (growth rate reduction)
 *
 * 0x015b: "\\s is currently unable to degrade the value of \\p beyond \\i%."
 *         - Sent when degradation cannot continue (minimum reached)
 *
 * 0x0182: "Hacked race discovered. \\L race statistics have been altered to a
 *          legal configuration. Your race now has a growth rate of \\i%, with
 *          the following extra leftover points: \\n\\L ..."
 *         - Detailed notification sent to the hacking player
 */


/* ============================================================================
 * SUMMARY: PUNISHMENT MECHANISM OVERVIEW
 * ============================================================================
 *
 * DETECTION:
 * ----------
 * 1. fCheater (0x04): Set when two players have matching homeworld coordinates
 *    - Detects save file sharing between players
 *    - Both players get flagged simultaneously
 *
 * 2. fHacker (0x10): Set when race value calculation returns < 500
 *    - Detects modified/hacked race files with illegal advantages
 *    - Player receives notification about "altered race statistics"
 *
 * 3. fCrippled (0x02): DEPRECATED - never set in Stars! 2.60j RC3
 *    - Legacy flag checked for backward compatibility with old saves
 *    - Was likely used in earlier versions of the game
 *
 * PUNISHMENTS:
 * ------------
 * A. For fCheater:
 *    - Tech level capped at 9 (vs 25 normal)
 *    - Production reduced to 80% (multiply by 4/5)
 *    - Production halved (50%) under certain conditions
 *    - Random negative events with probability ~75%
 *    - Extra punishment messages every 8 turns
 *
 * B. For fHacker:
 *    - Growth rate degraded until race value >= 500 (or minimum 1%)
 *    - Tech levels may be zeroed (indices 8-13) as last resort
 *    - NO tech level cap (unlike fCheater)
 *    - All players receive notification about the hack
 *
 * C. For fCrippled (legacy):
 *    - Tech level capped at 9 (same as fCheater)
 *    - Checked but never triggered in current version
 *
 * EVOLUTION:
 * ----------
 * The punishment system appears to have evolved:
 * - OLD: fCrippled -> tech cap at 9 (legacy, no longer set)
 * - NEW: fHacker -> growth rate degradation (current)
 * - ADDED: fCheater -> tech cap at 9 + production penalties (file sharing)
 */
