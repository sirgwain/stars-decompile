#include "globals.h"
#include "types.h"

#include "battle.h"
#include "file.h"
#include "log.h"
#include "memory.h"
#include "mine.h"
#include "msg.h"
#include "planet.h"
#include "port.h"
#include "race.h"
#include "save.h"
#include "ship.h"
#include "stars.h"
#include "strings.h"
#include "thing.h"
#include "turn.h"
#include "turn2.h"
#include "util.h"
#include "utilgen.h"

/* globals */
int16_t rgiWarpSafe[3] = {4, 6, 5};
int16_t rgpctMineHit[3] = {3, 10, 35};
int16_t rgrgdmgMine[3][2] = {{100, 125}, {500, 600}, {0, 0}};
int16_t rgrgdmgMinMine[3][2] = {{500, 600}, {2000, 2500}, {0, 0}};

/* functions */
void DoOrders(int16_t fPostMovement) {
    PLANET *lppl;
    PLANET *lpplMac;

    /* TODO: implement */
}

void FuelFleets(void) {
    int16_t j;
    int32_t cPods;
    PLANET *lppl;
    int16_t i;
    int16_t ifl;
    FLEET  *lpfl;
    SHDEF  *lpshdef;
    int32_t csh;
    HUL    *lphul;

    /* debug symbols */
    /* label LChkFuelTransport @ MEMORY_TURN:0x306e */

    /* TODO: implement */
}

int16_t FGenerateTurn(void) {
    int16_t idCur;
    int16_t fSuccess = 0;
    int16_t fFileErrSaved;
    int16_t sjRet;

    int16_t i, j, ish, ifl;

    /* longjmp environment */
    MemJump  env;
    MemJump *penvMemSaved = penvMem;

    /* per-turn allocations */
    COLDROP  *lpcd = NULL;
    XFERFULL *lpxf = NULL;

    /* misc locals */
    uint8_t mpiplr2[16];
    uint8_t rgfNoXFile[16];
    char    szT[256];
    char   *pchBak;
    char   *pchExt;
    int16_t fFollow;
    int16_t fDone;

    /* ------------------------------------------------------------ */
    /* Prologue                                                     */
    /* ------------------------------------------------------------ */

    idCur = idPlayer;

#ifdef WIN32
    HCURSOR hcurSav;
    hcurSav = SetCursor(LoadCursor(NULL, IDC_WAIT));
#endif
    DestroyCurGame();

    if (gd.fTutorial)
        Randomize(1234567890);

    /* ------------------------------------------------------------ */
    /* Load host file                                               */
    /* ------------------------------------------------------------ */

    fFileErrSaved = fFileErrSilent;
    fFileErrSilent = 1;

    UpdateProgressGauge(360);

    if (!FLoadGame(szBase, "hst")) {
        fFileErrSilent = fFileErrSaved;
#ifdef WIN32
        SetCursor(hcurSav);
#endif
        TurnLog(idsCantFindHostFile);
        goto FreeStuffUp;
    }

    TurnLog(idsGeneratingYearD);
    fFileErrSilent = fFileErrSaved;

    /* ------------------------------------------------------------ */
    /* Version migration hack                                      */
    /* ------------------------------------------------------------ */

    if ((wVersFile >> 12) == 0) {
        for (i = 0; i < game.cPlayer; i++) {
            if (rgplr[i].mdPlayer != 0)
                break;
        }
        if (i == game.cPlayer) {
            for (i = 0; i < game.cPlayer; i++)
                rgplr[i].mdPlayer = (uint8_t)i;
        }
    }

    /* ------------------------------------------------------------ */
    /* setjmp guard                                                 */
    /* ------------------------------------------------------------ */

    penvMem = &env;
    if (setjmp(env.env) != 0)
        goto FreeStuffUp;

    /* ------------------------------------------------------------ */
    /* Allocate working buffers                                    */
    /* ------------------------------------------------------------ */

    lpcd = LpAlloc(12000, htMisc);
    lpxf = LpAlloc(25000, htMisc);

    vrgPlanResExtra = LpAlloc(game.cPlanMax * sizeof(uint16_t), htMisc);
    memset(vrgPlanResExtra, 0, game.cPlanMax * sizeof(uint16_t));

    vrgts = LpAlloc(game.cPlayer * sizeof(TURNSERIAL), htMisc);
    UpdateProgressGauge(370);

    cColDrop = 0;
    cXferFull = 0;
    imemMsgCur = 0;

    gd.fGeneratingTurn = 1;
    gd.fRetryOpens = 1;

    /* ------------------------------------------------------------ */
    /* Shuffle player order                                        */
    /* ------------------------------------------------------------ */

    for (i = 0; i < game.cPlayer; i++)
        mpiplr2[i] = (uint8_t)i;

    for (i = 0; i < game.cPlayer; i++) {
        int     r = i + Random(game.cPlayer - i);
        uint8_t tmp = mpiplr2[i];
        mpiplr2[i] = mpiplr2[r];
        mpiplr2[r] = tmp;
    }

    /* ------------------------------------------------------------ */
    /* Per-player log processing                                   */
    /* ------------------------------------------------------------ */

    for (i = 0; i < game.cPlayer; i++) {
        int16_t     pl;
        TURNSERIAL *ts;

        /* pl = (uint8_t)mpiplr2[i] */
        pl = (int16_t)mpiplr2[i];

        /* _wsprintf(szWork, fmt, szBase, pl+1) */
        snprintf(szWork, sizeof(szWork), "%s.x%d", szBase, pl + 1);

        /* idPlayer = pl */
        idPlayer = pl;

        /* ts = vrgts + pl; (TURNSERIAL is 16 bytes, asm uses pl<<4) */
        ts = &vrgts[pl];

        /* ts->lSerialNumber = 0xFFFFFFFF (two 0xFFFF stores) */
        ts->lSerialNumber = -1;

        /* if (FLoadLogFile(szWork)) { if (!FRunLogFile()) { AlertSz(PszFormatIds(...),0x10); goto TURN_FreeStuffUp; } } */
        if (FLoadLogFile(szWork) != 0) {
            if (FRunLogFile() == 0) {
                AlertSz(PszFormatIds(idsPlayerLogFileAppearsCorruptUnableLoad, NULL), 0x10);
                goto FreeStuffUp;
            }
        }

        /* UpdateProgressGauge(MulDiv(0x3c, i+1, game.cPlayer) + 0x172) */
        UpdateProgressGauge((int16_t)(MulDiv(0x3c, (int16_t)(i + 1), game.cPlayer) + 0x172));
    }

    /* ------------------------------------------------------------ */
    /* Cheater detection, follow resolution, orders, simulation     */
    /* ------------------------------------------------------------ */
    idPlayer = -1;

    for (i = 0; i < game.cPlayer; i++) {

        /* Skip conditions (matches 03d2..0451): crippled OR AI OR (tutorial && i==0) */
        if (rgplr[i].fCrippled || rgplr[i].fAi || (gd.fTutorial && i == 0)) {
            rgplr[i].fCheater = 0;
            continue;
        }

        /* serial present? (matches 046b..047b and again 04f2..0502) */
        if (vrgts[i].lSerialNumber != -1) {

            /* validate serial (matches 047e..04db) */
            if (FValidSerialLong((uint32_t)vrgts[i].lSerialNumber) == 0) {
                rgplr[i].fCheater = 1;
                continue;
            }

            /* clear cheater before duplicate/config scan (matches 0505..052c) */
            rgplr[i].fCheater = 0;

            /* compare against earlier players j < i (matches 052f..0686) */
            for (j = 0; j < i; j++) {

                if (rgplr[j].fCrippled || rgplr[j].fAi)
                    continue;

                /* serial equal? (matches 0587..05b5) */
                if (vrgts[j].lSerialNumber == vrgts[i].lSerialNumber) {

                    /* config differs? memcmp(rgbConfig, 11) (matches 05b8..0601) */
                    if (memcmp(vrgts[j].rgbConfig, vrgts[i].rgbConfig, 11) != 0) {
                        rgplr[j].fCheater = 1;
                        rgplr[i].fCheater = 1;
                    }
                }
            }
        }
    }

    for (i = 0; i < game.cPlayer; i++) {
        if (rgplr[i].fCheater) { /* wFlags bit 2 */

            /* j = IPlrAlsoCheater(i); */
            j = IPlrAlsoCheater((int16_t)i);

            /* FSendPlrMsg2(i, 0x100 + (j != -1), -5, j, 0); */
            FSendPlrMsg2((int16_t)i, idmPopulationSuspectsUsurperProductivityOff20Growth + (j != -1), -5, j, 0);

            /* if (game.turn > 10 && ((game.turn & 7) == (i & 7))) */
            if ((uint16_t)game.turn > (uint16_t)10) {
                if (((uint16_t)game.turn & 7u) == ((uint16_t)i & 7u)) {

                    /* FSendPlrMsg2(i, 0x103, -5, 0, 0); */
                    FSendPlrMsg2((int16_t)i, idmFleetCaptainsHaveStagedStrikeDemandFree, -5, 0, 0);
                }
            }
        }
    }

    /* ------------------------------------------------------------
        Ensure each non-deleted ship design is in a “valid” state for
        the turn (force some fields/flags when missing).
        ------------------------------------------------------------ */

    for (i = 0; i < game.cPlayer; i++) {
        for (ish = 0; ish < cShdefMax; ish++) {
            SHDEF *pshdef = &rglpshdef[i][ish];
            HS    *phs0 = &pshdef->hul.rghs[0];

            /* if (pshdef->fFree) skip;  (asm: test bit 9 at +0x7b) */
            if (pshdef->fFree)
                continue;

            /* if (phs0->grhst == 1) skip; */
            if (phs0->grhst == hstEngine)
                continue;

            /* phs0->grhst = 1; */
            phs0->grhst = hstEngine;

            /* word at +0x3c: keep cItem, force iItem |= 1 (asm: (w & 0xFF00) | 1) */
            phs0->iItem = 1;

            /* if ((w >> 8) < 1) set bit 8 (asm sets 0x0100 when upper byte is 0) */
            if (phs0->cItem < 1) {
                phs0->cItem = 1;
            }
        }
    }

    /* ------------------------------------------------------------
        “Follow fleet” orders preprocessing:
        - Scan all fleets; mark those that are in follow mode
        - Validate basic preconditions and send warnings if needed
        ------------------------------------------------------------ */

    fFollow = 0;

    for (ifl = 0; ifl < cFleet; ifl++) {
        FLEET *fl = ((FLEET **)rglpfl)[ifl];
        if (fl == NULL)
            break;

        /* clear bit14: wFlags_0x4 &= 0xBFFF */
        fl->fNoHeal = 0;

        if (fl->cord == 1 && fl->lpplord->rgord[0].grobj == grobjFleet) {
            fFollow = 1;

            /* set bit15: wFlags_0x4 = (wFlags_0x4 & 0x7FFF) | 0x8000 */
            fl->fMark = 1;
        } else {
            /* clear bit15: wFlags_0x4 &= 0x7FFF */
            fl->fMark = 0;
        }
    }

    /* ------------------------------------------------------------
        Waypoint validation pass before movement/orders resolution.
        ------------------------------------------------------------ */
    ValidateWaypoints();

    /*
     * Follow-chain resolution:
     * Propagate follow-fleet orders by copying leader waypoints
     * into follower orders. Up to 8 passes.
     */
    if (fFollow != 0) {
        /* asm forces fFollow=1 before entering passes */
        fFollow = 1;

        for (i = 0; i < 8 && fFollow != 0; i++) {
            /* asm clears fFollow each pass; sets it again if any follow resolves */
            fFollow = 0;

            for (ifl = 0; ifl < cFleet; ifl++) {
                FLEET *follower = ((FLEET **)rglpfl)[ifl];
                if (follower == NULL)
                    break;

                /* asm: bit15 set (fMark) and cord==1 */
                if (follower->fMark == 0 || follower->cord != 1)
                    continue;

                /* local copy in asm is just to inspect grobj/id; access directly */
                if (follower->lpplord->rgord[0].grobj != grobjFleet) {
                    /* TURN::LUnmark */
                    follower->fMark = 0;
                    continue;
                }

                /* leader id comes from ORDER.id */
                FLEET *leader = LpflFromId(follower->lpplord->rgord[0].id);

                /* leader missing => warn + unmark */
                if (leader == NULL) {
                    FSendPlrMsg(follower->iPlayer, idmHadOrdersFollowFleetWhichDidntMove, (int16_t)(follower->id | 0x8000), follower->id, 0, 0, 0, 0, 0, 0);
                    follower->fMark = 0;
                    continue;
                }

                /*
                 * asm: if leader->cord==1 OR leader itself has follow-fleet grobj==2
                 * it skips copying and continues (leader not “ready” yet).
                 * The net effect: only copy when leader->cord != 1.
                 */
                if (leader->cord == 1)
                    continue;

                /* j made this pass */
                fFollow = 1;

                /* asm: if follower->lpplord->iordMax <= 1, realloc to 2 */
                if (follower->lpplord->iordMax <= 1) {
                    follower->lpplord = (PLORD *)LpplReAlloc((PL *)follower->lpplord, 2);
                }

                /* asm: copy leader order[1] (18 bytes) into follower order[1] */
                memcpy(&follower->lpplord->rgord[1], &leader->lpplord->rgord[1], sizeof(follower->lpplord->rgord[1]));

                /*
                 * asm: copy 10 bytes from follower order0 union payload (+0x08) to
                 * follower order1 union payload (+0x08).
                 *
                 * Use sizeof on the union storage via a representative member at +0x08.
                 */
                memcpy(&follower->lpplord->rgord[1].txp, &follower->lpplord->rgord[0].txp, sizeof(follower->lpplord->rgord[1].txp));

                /* asm sets cord=2 and PLORD.iordMac=2 */
                follower->cord = 2;
                follower->lpplord->iordMac = 2;
            }
        }
    }

    /* ------------------------------------------------------------
        Primary turn execution pipeline (high-level):
        - DoOrders(0) (pre-move / planning stage)
        - Validate & clamp player race settings
        - Detect race-tampering and apply penalties / notifications
        ------------------------------------------------------------ */
    UpdateProgressGauge(440);
    DoOrders(0);
    UpdateProgressGauge(530);

    for (i = 0; i < game.cPlayer; i++) {
        PLAYER *p = &rgplr[i];

        /* ------------------------------------------------------------
         * Re-assert stored race stats (may normalize/repair)
         * asm: for rs=0..15: v = GetRaceStat(p, rs); SetRaceStat(p, rs, v);
         * ------------------------------------------------------------ */
        for (int raceStat = 0; raceStat < 16; raceStat++) {
            int16_t v = GetRaceStat(p, (RaceStat)raceStat);
            SetRaceStat(p, (RaceStat)raceStat, v);
        }

        /* ------------------------------------------------------------
         * Clamp research and growth percent settings
         * pctResearch: if <0 or >100 => 15
         * pctIdealGrowth: if <0 => 1; if >20 => 20
         * asm uses signed compares via CBW.
         * ------------------------------------------------------------ */
        if ((int8_t)p->pctResearch < 0 || (int8_t)p->pctResearch > 100) {
            p->pctResearch = 15;
        }

        if ((int8_t)p->pctIdealGrowth < 0) {
            p->pctIdealGrowth = 1;
        }
        if ((int8_t)p->pctIdealGrowth > 20) {
            p->pctIdealGrowth = 20;
        }

        /* ------------------------------------------------------------
         * Advantage points / tampered race detection
         *
         * asm computes:
         *   expectedBit = (p->wFlags >> 4) & 1
         *   adv = CAdvantagePoints(p)
         *   if (adv < 0) OR ((adv != expectedBit) AND !p->fAi) => hacked path
         *
         * Note: expectedBit is literally bit0 of (wFlags>>4), i.e. wFlags bit4.
         * ------------------------------------------------------------ */
        {
            int16_t  adv = CAdvantagePoints(p);
            uint16_t expectedFlagBit = (uint16_t)p->fHacker; /* snapshot before recompute */

            if ((p->fAi == 0) && (adv < 0 || (uint16_t)p->fHacker != expectedFlagBit)) {

                /* Notify the hacked player */
                FSendPlrMsg2(i, idmRaceDefinitionHasTamperedStatisticsHaveAltered, (int16_t)-1, 0, 0);

                /*
                 * Notify all other players.
                 * asm bug/quirk: it checks (rgplr[i].fAi == 0) again (the hacked player's),
                 * not recipient's. Keep that behavior: since we’re already inside (p->fAi==0),
                 * this condition is always true for all recipients != i.
                 */
                for (j = 0; j < game.cPlayer; j++) {
                    if (j == i)
                        continue;

                    /* asm re-check is on player i, so it would never filter recipients here */
                    FSendPlrMsg2((int16_t)j, idmHackedRaceDiscoveredRaceStatisticsHaveAltered, (int16_t)-1, i, 0);
                }

                /* Mark player as flagged: wFlags = (wFlags & ~0x10) | 0x10 */
                p->fHacker = 1;

                /*
                 * Try to repair: bump rgAttr[0] (byte at +0x3e) up to < 0x19
                 * while advantage points still < 500.
                 */
                adv = CAdvantagePoints(p);
                while (adv < 500 && (int8_t)p->rgAttr[0] < 25) {
                    p->rgAttr[0] = (uint8_t)(p->rgAttr[0] + 1);
                    adv = CAdvantagePoints(p);
                }

                /*
                 * Next: decrease pctIdealGrowth down to >1 while adv < 500.
                 */
                adv = CAdvantagePoints(p);
                while (adv < 500 && (int8_t)p->pctIdealGrowth > 1) {
                    p->pctIdealGrowth = (uint8_t)(p->pctIdealGrowth - 1);
                    adv = CAdvantagePoints(p);
                }

                /*
                 * Last resort: zero attributes rgAttr[8..13] until adv >= 500 or we run out.
                 * asm iterates local_15a = 8; while <= 0x0D.
                 */
                adv = CAdvantagePoints(p);
                if (adv < 500) {
                    for (int k = 8; k <= 13; k++) {
                        p->rgAttr[k] = 0;
                        adv = CAdvantagePoints(p);
                        if (adv >= 500)
                            break;
                    }
                }
            }
        }
    }

    /* ------------------------------------------------------------
        World simulation steps (movement/production/etc):
        Order here matters; this is the meat of “advance one year”.
        ------------------------------------------------------------ */
    UnmarkMineFields();
    MoveThings(0);
    UpdateProgressGauge(550);
    MoveFleets();

    /* Clear "homeworld" flag on all planets, then set it on each player's homeworld. */
    for (PLANET *p = lpPlanets; p < lpPlanets + cPlanet; ++p) {
        /* asm: wRaw_0004 &= 0xFBFF */
        p->fHomeworld = 0;
    }

    for (i = 0; i < game.cPlayer; ++i) {
        int16_t idHome = rgplr[i].idPlanetHome;

        /* asm computes: lpPlanets + (idHome * 0x38), then:
           wRaw_0004 = (wRaw_0004 & 0xFBFF) | 0x0400 */
        lpPlanets[idHome].fHomeworld = 1;
    }

    UpdateProgressGauge(650);
    ThingDecay();
    BreedColonistsInTransit();
    UpdateProgressGauge(700);
    Produce();
    UpdateProgressGauge(750);
    MoveThings(1);
    UpdateProgressGauge(770);
    FuelFleets();
    DoOrders(1);
    SweepForMines();
    HealShips();
    AutoTerraform();
    RemoteTerraforming();
    UpdateProgressGauge(850);
    SpankTheCheaters();
    ValidateWaypoints();
    UpdateGuesses();

    /* ------------------------------------------------------------ */
    /* End-of-turn bookkeeping                                     */
    /* ------------------------------------------------------------ */

    FMarkFile(dtHost, -1, 1, 0);
    CreateBackupDir();
    game.turn++;
    UpdateProgressGauge(852);

    /* szBase: original path (may include directories)
        szBackup: backup directory/prefix (base path for backups)
        szT: temp buffer used to build full backup path
        pchCur: points at end of szBase
        pchLastSlash: points at last '\' in szBase (or NULL)
        pchBak: points at end of szT
    */

    uint16_t baseLen = (uint16_t)strlen((char *)szBase);
    char    *pchCur = (char *)szBase + baseLen;

    char *pchLastSlash = strrchr((char *)szBase, '\\');

    strcpy(szT, (char *)szBackup);

    if (pchLastSlash == NULL) {
        strcat(szT, (char *)szBase);
    } else {
        strcat(szT, pchLastSlash + 1); /* just the filename part */
    }

    uint16_t bakLen = (uint16_t)strlen(szT);
    pchBak = szT + bakLen;

    /* ------------------------------------------------------------
       Update player scores and refresh per-design cached values
       (cloak %, scanner ranges, buildability flags, etc.)
       ------------------------------------------------------------ */
    UpdateProgressGauge(854);
    UpdatePlayerScores();

    for (int16_t iplr = 0; iplr < game.cPlayer; iplr++) {

        /* ------------------------------------------------------------
           Starbase designs: cache (100 - cloakPct)^2 into lPower
           ------------------------------------------------------------ */
        for (int16_t j = 0; j < 10; j++) {
            SHDEF *sbdef = &rglpshdefSB[iplr][j];

            /* asm: (wFlags >> 9) & 1 == 0  => your fInclude == 0 */
            if (sbdef->fInclude == 0) {
                int16_t cloakPct = PctCloakFromHuldef(&sbdef->hul, iplr, NULL);
                int32_t cloakInv = (int32_t)(100 - cloakPct);

                sbdef->lPower = cloakInv;
                sbdef->lPower = (int32_t)((int64_t)sbdef->lPower * (int64_t)sbdef->lPower);
            }
        }

        /* ------------------------------------------------------------
           Ship designs: cache scanner range + detection/steal params,
           and mark unbuildable designs via wFlags high bit.
           ------------------------------------------------------------ */
        for (int16_t j = 0; j < 0x10; j++) {
            SHDEF *shdef = &rglpshdef[iplr][j];

            if (shdef->fInclude == 0) {
                int16_t dScanRange2 = 0;
                int16_t pctDetect16 = 0;
                int16_t iSteal16 = 0;

                /* asm returns AX (dScanRange) and writes:
                   - pdPlanRange -> stored into +0x8f (dScanRange2)
                   - ppctDetect  -> stored into +0x91 (pctDetect byte)
                   - piSteal     -> stored into +0x92 (iSteal byte)
                */
                int16_t dScanRange = GetShdefScannerRange(shdef, iplr, &dScanRange2, &pctDetect16, &iSteal16);

                shdef->dScanRange = (uint16_t)dScanRange;
                shdef->dScanRange2 = (uint16_t)dScanRange2;
                shdef->pctDetect = (uint8_t)pctDetect16;
                shdef->iSteal = (uint8_t)iSteal16;

                if (FCanBuildShdef(shdef, iplr) == 0) {
                    shdef->wFlags = (uint16_t)((shdef->wFlags & 0x7fff) | 0x8000);
                }
            }
        }
    }
    j = 856; /* 856 */
    fDone = 0;

    memset(rgfNoXFile, 0, sizeof(rgfNoXFile));
    i = 0;
    while (!fDone) {
        UpdateProgressGauge(j);

        /* j += 0x11 / (game.cPlayer + 1) */
        j += (int16_t)(0x11 / (game.cPlayer + 1));

        /* After last player, run one final “host/global” pass */
        if (i >= game.cPlayer) {
            i = -1;
            fDone = 1;
        }

        if (i < 0) {
            /* Host/global filenames */
            strcpy(pchCur, ".hst");
            strcpy(pchBak, ".hst");
        } else {
            /* Per-player filenames: ".xN" */
            wsprintf(pchCur, ".x%d", i + 1);
            strcpy(pchBak, pchCur);

            /* Remove any existing backup target */
            remove(szT);

            /* If base .x file missing, remember it */
            if (Stars_Access(szBase, 0) == -1) {
                rgfNoXFile[i] = 1;
            } else {
                rename(szBase, szT);
            }

            /* Convert ".xN" → ".mN" in both base and backup names */
            pchBak[1] = 'm';
            szBase[baseLen + 1] = 'm';
        }

        /* Now move or copy the final file into place */
        remove(szT);

        if (i < 0 || rgfNoXFile[i] == 0) {
            rename(szBase, szT);
        } else {
            CopyStarsFile(szBase, szT);
        }

        /* Clear extension for next iteration */
        *pchCur = '\0';

        i++;
    }

    j = 875;
    fDone = 0;
    i = 0;

    /* Randomize 3-bit generator field (was bits 9..11 of wCrap) */
    game.wGen = (uint16_t)(Random(8) & 0x7);

    while (!fDone) {
        UpdateProgressGauge(j);
        j = (int16_t)(j + (int16_t)(0x7a / (game.cPlayer + 1)));

        if (i >= game.cPlayer) {
            i = -1;
            fDone = 1;
        }

        /* Tell FWriteDataFile whether this player lacked an .x file */
        int16_t fNoX = 0;
        if (i != -1 && rgfNoXFile[i] != 0)
            fNoX = 1;

        FWriteDataFile(szBase, i, fNoX);

        i++;
    }

    /* Success epilogue */
    UpdateProgressGauge(998);
    imemLogCur = 0;
    fSuccess = 1;

FreeStuffUp:
    UpdateProgressGauge(1000);

    /* free + null global heaps */
    FreeLp(vrgPlanResExtra, htMisc);
    vrgPlanResExtra = NULL;

    FreeLp(vrgts, htMisc);
    vrgts = NULL;

    FreeLp(lpcd, htMisc);
    lpcd = NULL;

    FreeLp(lpxf, htMisc);
    lpxf = NULL;

    /* gd.grBits &= ~0x0002; (0xfffd) */
    /* gd.grBits &= ~0x0200; (0xfdff) */
    gd.fGeneratingTurn = 0;
    gd.fRetryOpens = 0;

    idPlayer = -1;

    if ((fSuccess != 0) && (((ini.wFlags >> 3) & 1) != 0)) {
        vretExitValue = 1;
    }

#ifdef WIN32
    SetCursor(hcurSav);
#endif

    /* idsFailed is a base string id; add fSuccess (0/1) */
    TurnLog((StringId)(fSuccess + idsFailed));

    /* nothing left to restore: globals were directly nulled */
    return fSuccess;
}

void MoveFleets(void) {
    int32_t dTravel;
    int16_t cPass;
    int32_t wtFuel2Dest;
    double  d;
    int16_t fGotEnufFuel;
    int16_t fRanOutOfFuel;
    ORDER  *lpord;
    POINT   ptEnd;
    int16_t ifl;
    FLEET  *lpfl;
    double  r;
    int32_t pct;
    int16_t dMineTravel;
    int32_t dRange;
    POINT   ptBeg;
    int32_t wtFuelUsed;
    int32_t dActTravel;
    int32_t lFuelGain;
    int16_t fDone;
    SCAN    scan;
    int16_t cKill;
    int16_t i;
    int16_t dy;
    int16_t iCtr;
    PLANET *lpplDst;
    int32_t cDie;
    int16_t ish;
    int16_t dx;
    int32_t lFuelGainAct;
    THING  *lpthDest;
    int32_t wtColonists;
    double  dyRound;
    THING  *lpth;
    int16_t grbitPlr;
    PLANET *lpplSrc;
    int16_t fJumpgate;
    double  dxRound;
    int16_t isbsDst;
    int16_t isbsSrc;
    POINT   ptMsg;
    int32_t wtMinerals;
    FLEET   flSrc;
    int16_t cTry;
    FLEET   flDead;
    int16_t cKillTot;
    int16_t fDead;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN:0x354f */
    /* block (block) @ MEMORY_TURN:0x3eb5 */
    /* block (block) @ MEMORY_TURN:0x3f79 */
    /* block (block) @ MEMORY_TURN:0x457f */
    /* block (block) @ MEMORY_TURN:0x4686 */
    /* block (block) @ MEMORY_TURN:0x48df */
    /* block (block) @ MEMORY_TURN:0x49ed */
    /* block (block) @ MEMORY_TURN:0x4bb6 */
    /* block (block) @ MEMORY_TURN:0x4d1e */
    /* block (block) @ MEMORY_TURN:0x4d5b */
    /* label LNoGateNeeded @ MEMORY_TURN:0x36ab */
    /* label LMakeItToDest @ MEMORY_TURN:0x4983 */
    /* label MoveUnfinishedFleets @ MEMORY_TURN:0x32e9 */
    /* label LWarp10Kill @ MEMORY_TURN:0x4122 */

    /* TODO: implement */
}

int16_t FTravelThroughMineFields(FLEET *lpfl, int16_t *pdTravel, THING *lpthHit) {
    int32_t  d2Closest;
    int16_t  rgishInc[16];
    int16_t  dTravel;
    POINT    ptAct;
    int16_t  iWarp;
    POINT    ptDst;
    int16_t  dy;
    int32_t  d2;
    int16_t  j;
    int16_t  dEnd;
    FLEET    flSrc;
    int32_t  dpsh;
    int16_t  cshT;
    int32_t  dmgReduce;
    int32_t  dmgToApply;
    int16_t  i;
    THING   *lpth;
    int16_t  dmgExtra;
    int16_t  cshDamaged;
    int16_t  fMineExpert;
    POINT    ptSrc;
    int16_t  iPlayer;
    int16_t  cFields;
    int16_t  dStart;
    FLEET    flDead;
    THING   *lpthMac;
    int32_t  csh;
    int16_t  rgi[3];
    int16_t  pct;
    int32_t  dmgTot;
    int16_t  cshDead;
    int16_t  rgcField[3];
    int16_t  raMajor;
    int16_t  dx;
    int32_t  dpShield;
    int16_t  iType;
    int16_t  rgFieldE[3][8];
    THING   *lpthClosest;
    int16_t  cishInc;
    THING   *lpthSalvage;
    int16_t  fHasRamScoop;
    int16_t  dmgPer;
    int16_t  rgFieldS[3][8];
    int16_t  cEngines;
    uint16_t ibit;
    int32_t  dmgPerShip;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN:0x590c */
    /* block (block) @ MEMORY_TURN:0x6184 */
    /* label LHitSkip2 @ MEMORY_TURN:0x57f1 */
    /* label LHitSkip1 @ MEMORY_TURN:0x5591 */
    /* label LDoNext @ MEMORY_TURN:0x676d */
    /* label LFinishHit @ MEMORY_TURN:0x5d7f */

    /* TODO: implement */
    return 0;
}

void MoveThings(int16_t fPostProd) {
    int16_t k;
    int16_t dUni;
    double  d;
    POINT   pt;
    int16_t iMax;
    POINT   ptDst;
    int16_t dLeft;
    THING  *lpth;
    int16_t fAnythingMoved;
    int16_t fMajorMove;
    int16_t idm;
    int16_t iLow;
    POINT   ptSrc;
    THING  *lpthMac;
    int16_t dRange;
    POINT   ptBase;
    int16_t iX;
    int16_t rgC[2];
    int16_t rgwtTerra[3];
    double  dyRound;
    int32_t wtTot;
    int16_t iWarp2;
    int16_t iWarp;
    int16_t fTerra;
    double  dxRound;
    PLANET *lppl;
    int16_t wtCur;
    int16_t pctMinKeep;
    double  r;
    int16_t fTwoMAs;
    int32_t lDefKilled;
    int32_t lColKilled;
    int16_t i;
    int16_t pctCaught;
    float   pct;
    int32_t dmgRaw;
    int16_t iWarpPacket;
    int16_t iWarpPacket2;
    int16_t pctRate;
    int16_t iplr;
    THING  *lpth2;
    THING  *lpth2Mac;
    int16_t rgMin[3];
    int16_t cTerraPerm;
    int16_t cTerraTemp;
    int16_t rgMax[3];
    int16_t rgCost[3];

    /* debug symbols */
    /* block (block) @ MEMORY_TURN:0x1b40 */
    /* block (block) @ MEMORY_TURN:0x1da3 */
    /* block (block) @ MEMORY_TURN:0x1db9 */
    /* block (block) @ MEMORY_TURN:0x1ea7 */
    /* block (block) @ MEMORY_TURN:0x2215 */
    /* block (block) @ MEMORY_TURN:0x2d93 */
    /* block (block) @ MEMORY_TURN:0x2e01 */
    /* label LPacketAlreadyFreed @ MEMORY_TURN:0x2d88 */
    /* label LSpeedUpOnly @ MEMORY_TURN:0x1be2 */
    /* label LRetargetFreighter @ MEMORY_TURN:0x1b5c */
    /* label LAllSafe @ MEMORY_TURN:0x2950 */
    /* label MoveTh @ MEMORY_TURN:0x1d5a */
    /* label LFreeThePacket @ MEMORY_TURN:0x2d7a */
    /* label MadeItThere @ MEMORY_TURN:0x1da3 */

    /* TODO: implement */
}
