#include "globals.h"
#include "types.h"

#include "battle.h"
#include "file.h"
#include "log.h"
#include "memory.h"
#include "mine.h"
#include "msg.h"
#include "parts.h"
#include "planet.h"
#include "port.h"
#include "race.h"
#include "save.h"
#include "ship.h"
#include "ship2.h"
#include "stars.h"
#include "strings.h"
#include "thing.h"
#include "turn.h"
#include "turn2.h"
#include "turn3.h"
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
    int16_t iPass;

    FORPLANETS(lppl, lpplMac) { lppl->fWasInhabited = (lppl->iPlayer != -1); }

    if (fPostMovement) {
        idBattle = (game.turn & 0xf) * 0x100 + 1;
        DoBattles(fPostMovement);
    }

    DoThingInteractions(fPostMovement);

    if (fPostMovement) {
        FORPLANETS(lppl, lpplMac) { lppl->turn = 0; }
    }

    if (!fPostMovement) {
        iPass = 1;
    } else {
        iPass = 3;
    }
    SatisfyOrders(iPass);

    DropColonists();
    UpdateResearchStatus(0);

    if (!fPostMovement) {
        iPass = 2;
    } else {
        iPass = 4;
    }
    SatisfyOrders(iPass);

    if (!fPostMovement) {
        TransferToOthers();
    }
}

void FuelFleets(void) {
    int16_t  j;
    int32_t  cPods;
    PLANET  *lppl;
    int16_t  i;
    int16_t  ifl;
    FLEET   *lpfl;
    SHDEF   *lpshdef;
    int32_t  csh;
    HUL     *lphul;
    int32_t  lFuelGen;
    uint32_t uFuelPods;

    /* debug symbols */
    /* label LChkFuelTransport @ MEMORY_TURN:0x306e */

    for (ifl = 0; ifl < cFleet; ifl++) {
        lpfl = rglpfl[ifl];
        if (lpfl == NULL)
            return;

        if (lpfl->fDead)
            continue;

        /* Check if orbiting a friendly starbase with fuel capacity */
        if (lpfl->idPlanet != -1 && lpPlanets[lpfl->idPlanet].fStarbase && lpPlanets[lpfl->idPlanet].iPlayer != -1 &&
            (lpfl->iPlayer == lpPlanets[lpfl->idPlanet].iPlayer || rgplr[lpPlanets[lpfl->idPlanet].iPlayer].rgmdRelation[lpfl->iPlayer] == 1)) {
            int16_t iPlanetPlr = lpPlanets[lpfl->idPlanet].iPlayer;
            HULDEF *lphuldef = LphuldefFromId(rglpshdefSB[iPlanetPlr][lpPlanets[lpfl->idPlanet].isb].hul.ihuldef);
            if (lphuldef->hul.wtCargoMax != 0) {
                /* Fill fuel to max */
                lpfl->rgwtMin[4] = LGetFleetStat(lpfl, grStatFuel);
                continue;
            }
        }

        /* Calculate fuel from fuel pods and fuel transports */
        lFuelGen = 0;
        uFuelPods = 0;
        for (i = 0; i < cShdefMax; i++) {
            if (lpfl->rgcsh[i] == 0)
                continue;

            lpshdef = rglpshdef[lpfl->iPlayer];
            SHDEF *lpsd = &lpshdef[i];
            j = (int16_t)lpsd->hul.chs;
            for (j = j - 1; j >= 0; j--) {
                if (lpsd->hul.rghs[j].grhst == hstSpecialE && lpsd->hul.rghs[j].iItem == ispecialEAntiMatterGenerator) {
                    uFuelPods += (uint32_t)lpfl->rgcsh[i] * (uint32_t)lpsd->hul.rghs[j].cItem;
                }
            }

            /* LChkFuelTransport */
            if (lpsd->hul.ihuldef == ihuldefFuelTransport || lpsd->hul.ihuldef == ihuldefSuperFuelXport) {
                lFuelGen += (uint32_t)lpfl->rgcsh[i] * 200;
            }
        }

        if (lFuelGen != 0 || uFuelPods != 0) {
            int32_t lMaxFuel = LGetFleetStat(lpfl, grStatFuel);
            int32_t lNewFuel = uFuelPods * 50 + lFuelGen + lpfl->rgwtMin[4];
            if (lNewFuel < lMaxFuel)
                lpfl->rgwtMin[4] = lNewFuel;
            else
                lpfl->rgwtMin[4] = lMaxFuel;
        }
    }
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

    lpcd = LpAlloc(sizeof(COLDROP) * cMaxSimulDrops, htMisc);
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
                Error(idsPlayerLogFileAppearsCorruptUnableLoad);
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

                sbdef->lVisible = cloakInv;
                sbdef->lVisible = (int32_t)((int64_t)sbdef->lVisible * (int64_t)sbdef->lVisible);
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
        j += (int16_t)(17 / (game.cPlayer + 1));

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
            sprintf(pchCur, ".x%d", i + 1);
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
        j = (int16_t)(j + (int16_t)(122 / (game.cPlayer + 1)));

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

    /* asm: 10b0:32d7 — dTravel (cPass counter) = 0 */
    cPass = 0;

    if (cFleet <= 0)
        goto done; /* asm: 10b0:32e1..32e6 — JLE to exit */

    /* label MoveUnfinishedFleets @ 10b0:32e9 */
MoveUnfinishedFleets:
    lFuelGain = 1; /* asm: 10b0:32e9 — reuse lFuelGain as "any fleet still moving" flag */
    ifl = 0;       /* asm: 10b0:32ee — reuse ptEnd as ifl loop counter init */

    /* asm: 10b0:32fa — inner fleet loop */
    for (;;) {
        if (ifl >= cFleet)
            goto donePass; /* asm: 10b0:3300..3302 */

        lpfl = rglpfl[ifl]; /* asm: 10b0:3305..3322 */
        if (lpfl == NULL)
            goto donePass; /* asm: 10b0:3325..3332 */

        /* asm: 10b0:3335 — first pass init */
        if (cPass == 0) {
            /* asm: 10b0:333e..335d — zero dirLong, set fHereAllTurn */
            lpfl->dirLong = 0;
            lpfl->fHereAllTurn = 1;
        }

        /* asm: 10b0:3361..3398 — skip if fDead, or (cPass>0 && fDone) */
        if (lpfl->fDead)
            goto nextFleet;
        if (cPass > 0 && lpfl->fDone)
            goto nextFleet;

        /* asm: 10b0:339b..33ab — set fDone = 1 */
        lpfl->fDone = 1;

        /* asm: 10b0:33af..33c2 — lpord = &lpfl->lpplord->rgord[0] */
        lpord = &lpfl->lpplord->rgord[0];

        /* asm: 10b0:33c5..33e9 — skip if grTask==1 (no task) or grTask==6 (patrol) */
        if (lpord->grTask == 1 || lpord->grTask == 6)
            goto nextFleet;

        /* asm: 10b0:33ec..3413 — skip if cord < 2 or next waypoint iWarp == 0 */
        if (lpfl->cord < 2)
            goto nextFleet;
        if (lpfl->lpplord->rgord[1].iWarp == 0)
            goto nextFleet;

        /* asm: 10b0:3416..3496 — cheater detection block */
        /* decompile: check rgplr[iPlayer].fCheater (wFlags bit 2) */
        if (rgplr[lpfl->iPlayer].fCheater) {
            /* asm: 10b0:3437..3458 — early turn or player mismatch: random skip */
            if (game.turn > 10 && (game.turn & 7) == (lpfl->iPlayer & 7)) {
                goto nextFleet;
            }
            /* asm: 10b0:345e..3493 — 25% chance (Random(4)==0) refuse to move */
            if (Random(4) == 0) {
                FSendPlrMsg2(lpfl->iPlayer, idmHasRefusedMoveDoubtingAuthorityRulePress, -5, lpfl->id, 0);
                goto nextFleet;
            }
        }

        /* asm: 10b0:3496..3535 — cheap engines random failure block */
        if (cPass == 0 && lpfl->lpplord->rgord[1].iWarp > 6 && lpfl->lpplord->rgord[1].iWarp != iWarpStargate) {
            /* asm: 10b0:34d3..34f4 — check CheapEngines race trait */
            if (GetRaceGrbit(&rgplr[lpfl->iPlayer], ibitRaceCheapEngines) != 0) {
                /* asm: 10b0:34f7..3532 — 10% failure (Random(10)==0) */
                if (Random(10) == 0) {
                    FSendPlrMsg2(lpfl->iPlayer, idmUnableEngageEnginesDueBalkyEquipmentEngineers, lpfl->id | 0x8000, lpfl->id, 0);
                    goto nextFleet;
                }
            }
        }

        /* asm: 10b0:3535..354a — branch: stargate (iWarp >= 0xb) vs normal warp */
        if (lpfl->lpplord->rgord[1].iWarp >= iWarpStargate) {
            /* === STARGATE PATH === */
            /* block @ MEMORY_TURN:0x354f */
            int16_t fSrcOnly;       /* pPStack_6a — flag: src gate only */
            PLANET *lpplGateSrc;    /* uStack_68/uStack_66 */
            PLANET *lpplGateDst;    /* local_64+6/scan - reused */
            int16_t isbsSrcGate;    /* local_dc+0x6e */
            int16_t isbsDstGate;    /* local_dc+0x70 */
            int16_t ptDstX, ptDstY; /* local_dc+0x6a, local_dc+0x6c */
            int32_t dDist;

            fSrcOnly = 0;

            /* asm: 10b0:3554..355d — clear fRadiatingEngine flag */
            gd.fRadiatingEngine = 0;

            /* asm: 10b0:3560..3573 — get source waypoint pt + save */
            ptDstX = lpord->pt.x;
            ptDstY = lpord->pt.y;
            ptBeg.x = lpord->pt.x;
            ptBeg.y = lpord->pt.y;

            /* asm: 10b0:3576..35ca — resolve source stargate */
            if (lpord->grobj == 1) {
                /* target is a planet */
                ptDstX = -1;
                ptDstY = lpord->id;
                lpplGateSrc = LpplFromId(lpord->id);
                isbsSrcGate = IStargateFromLppl(lpplGateSrc);
            } else {
                isbsSrcGate = -1;
            }

            /* asm: 10b0:35ca..3625 — if no src gate, check FFleetCanJumpgate */
            if (isbsSrcGate == -1) {
                if (FFleetCanJumpgate(lpfl))
                    goto LNoGateNeeded;
                /* asm: 10b0:35ec..3625 — no gate msg */
                FSendPlrMsg(lpfl->iPlayer, idmAttemptedUseStargateStargateExistsThere, lpfl->id | 0x8000, lpfl->id, ptDstX, ptDstY, 0, 0, 0, 0);
                goto nextFleet;
            }

            /* asm: 10b0:3628..36a8 — check src planet owner relation */
            if (lpplGateSrc->iPlayer != lpfl->iPlayer) {
                /* asm: 10b0:363b..364f — get relation */
                if (rgplr[lpplGateSrc->iPlayer].rgmdRelation[lpfl->iPlayer] != 1) {
                    /* asm: 10b0:3669..36a8 — enemy gate msg */
                    FSendPlrMsg(lpfl->iPlayer, idmAttemptedUseStargateCouldBecauseStarbaseOwned, lpfl->id | 0x8000, lpfl->id, lpplGateSrc->id, lpplGateSrc->id,
                                0, 0, 0, 0);
                    goto nextFleet;
                }
            }

            /* label LNoGateNeeded @ 10b0:36ab */
        LNoGateNeeded:
            /* asm: 10b0:36ab..36bf — get destination waypoint from rgord[1] */
            ptEnd.x = lpfl->lpplord->rgord[1].pt.x;
            ptEnd.y = lpfl->lpplord->rgord[1].pt.y;

            /* asm: 10b0:36c2..370e — resolve destination stargate */
            if (lpfl->lpplord->rgord[1].grobj == 1) {
                /* destination is a planet */
                ptDstX = -1;
                ptDstY = lpfl->lpplord->rgord[1].id;
                lpplGateDst = LpplFromId(lpfl->lpplord->rgord[1].id);
                isbsDstGate = IStargateFromLppl(lpplGateDst);
            } else {
                /* asm: 10b0:3711..3785 — search rgptPlan for matching coords */
                int16_t iPlan;
                for (iPlan = 0; iPlan < game.cPlanMax; iPlan++) {
                    if (ptEnd.x == rgptPlan[iPlan].x && ptEnd.y == rgptPlan[iPlan].y)
                        break;
                }
                if (iPlan >= game.cPlanMax) {
                    /* asm: 10b0:3788..37c1 — no planet at dest coords */
                    FSendPlrMsg(lpfl->iPlayer, idmAttemptedReachViaStargateCouldBecauseStargate, lpfl->id | 0x8000, lpfl->id, ptEnd.x, ptEnd.y, 0, 0, 0, 0);
                    goto nextFleet;
                }
                ptDstX = -1;
                ptDstY = iPlan;
                lpplGateDst = LpplFromId(iPlan);
                isbsDstGate = IStargateFromLppl(lpplGateDst);
            }

            /* asm: 10b0:37c4..3808 — if no dest gate, send msg */
            if (isbsDstGate == -1) {
                FSendPlrMsg(lpfl->iPlayer, idmAttemptedUseStargateReachCouldBecauseStargate, lpfl->id | 0x8000, lpfl->id, lpplGateDst->id, ptDstX, ptDstY, 0, 0,
                            0);
                goto nextFleet;
            }

            /* asm: 10b0:380b..388d — check dest planet owner relation */
            if (lpplGateDst->iPlayer != lpfl->iPlayer) {
                if (rgplr[lpplGateDst->iPlayer].rgmdRelation[lpfl->iPlayer] != 1) {
                    FSendPlrMsg(lpfl->iPlayer, idmAttemptedUseStargateReachCouldBecauseStarbase, lpfl->id | 0x8000, lpfl->id, lpplGateDst->id, lpplGateDst->id,
                                lpplGateDst->id, 0, 0, 0);
                    goto nextFleet;
                }
            }

            /* asm: 10b0:3890..38a4 — if no src gate, use dst as src */
            if (isbsSrcGate == -1) {
                fSrcOnly = 1;
                isbsSrcGate = isbsDstGate;
            }

            /* asm: 10b0:38a4..38ce — if fSrcOnly, skip Stargate race check */
            if (fSrcOnly)
                goto doStargateJump;

            /* asm: 10b0:38ad..38ce — check if player is Stargate race (raStargate=7) */
            if (GetRaceStat(&rgplr[lpfl->iPlayer], rsMajorAdv) == raStargate)
                goto doStargateJump;

            /* asm: 10b0:38d1..3929 — check colonists for non-Stargate race */
            if (lpfl->rgwtMin[3] > 0) {
                if (lpplGateSrc->iPlayer != lpfl->iPlayer) {
                    FSendPlrMsg2(lpfl->iPlayer, idmUnableUseStargateBecauseHadColonistsBoard, lpfl->id | 0x8000, lpfl->id, lpplGateSrc->id);
                    goto nextFleet;
                }
            }

            { /* block @ MEMORY_TURN:0x392c — transfer minerals to source planet */
                int32_t wtMinXfer = 0;
                int16_t iMin;

                /* asm: 10b0:3936..39e9 — transfer minerals [0..2] to planet */
                for (iMin = 0; iMin <= 2; iMin++) {
                    if (lpfl->rgwtMin[iMin] != 0) {
                        wtMinXfer += lpfl->rgwtMin[iMin];
                        lpplGateSrc->rgwtMin[iMin] += lpfl->rgwtMin[iMin];
                        lpfl->rgwtMin[iMin] = 0;
                    }
                }

                /* asm: 10b0:39f2..3a22 — transfer colonists to planet */
                wtColonists = lpfl->rgwtMin[3];
                lpplGateSrc->rgwtMin[3] += lpfl->rgwtMin[3];
                lpfl->rgwtMin[3] = 0;

                /* asm: 10b0:3a28..3bd9 — send messages about unloaded cargo */
                if (wtColonists != 0) {
                    if (wtMinXfer != 0) {
                        /* both colonists and minerals */
                        FSendPlrMsg(lpfl->iPlayer, idmHasUnloadedColonistsKtMineralsPreparationJumping, lpfl->id | 0x8000, lpfl->id, (int16_t)wtColonists,
                                    (int16_t)((uint32_t)wtColonists >> 16), (int16_t)wtMinXfer, (int16_t)((uint32_t)wtMinXfer >> 16), lpplGateSrc->id, 0);
                        if (lpfl->iPlayer != lpplGateSrc->iPlayer) {
                            FSendPlrMsg(lpplGateSrc->iPlayer, idmHasUnloadedColonistsKtMineralsPreparationJumping, lpplGateSrc->id, lpfl->id,
                                        (int16_t)wtColonists, (int16_t)((uint32_t)wtColonists >> 16), (int16_t)wtMinXfer, (int16_t)((uint32_t)wtMinXfer >> 16),
                                        lpplGateSrc->id, 0);
                        }
                    } else {
                        /* colonists only */
                        FSendPlrMsg(lpfl->iPlayer, idmHasUnloadedColonistsPreparationJumpingThroughSta, lpfl->id | 0x8000, lpfl->id, (int16_t)wtColonists,
                                    (int16_t)((uint32_t)wtColonists >> 16), wtColonists, lpplGateSrc->id, 0, 0);
                        if (lpfl->iPlayer != lpplGateSrc->iPlayer) {
                            FSendPlrMsg(lpplGateSrc->iPlayer, idmHasUnloadedColonistsPreparationJumpingThroughSta, lpplGateSrc->id, lpfl->id,
                                        (int16_t)wtColonists, (int16_t)((uint32_t)wtColonists >> 16), wtColonists, lpplGateSrc->id, 0, 0);
                        }
                    }
                } else {
                    if (wtMinXfer != 0) {
                        /* minerals only */
                        FSendPlrMsg(lpfl->iPlayer, idmHasUnloadedKtMineralsPreparationJumpingThrough, lpfl->id | 0x8000, lpfl->id, (int16_t)wtMinXfer,
                                    (int16_t)((uint32_t)wtMinXfer >> 16), wtMinXfer, lpplGateSrc->id, 0, 0);
                        if (lpfl->iPlayer != lpplGateSrc->iPlayer) {
                            FSendPlrMsg(lpplGateSrc->iPlayer, idmHasUnloadedKtMineralsPreparationJumpingThrough, lpplGateSrc->id, lpfl->id, (int16_t)wtMinXfer,
                                        (int16_t)((uint32_t)wtMinXfer >> 16), wtMinXfer, lpplGateSrc->id, 0, 0);
                        }
                    }
                }
            }

        doStargateJump:
            /* asm: 10b0:3c9f..3cb3 — DGetDistance for stargate */
            d = DGetDistance(ptBeg.x, ptBeg.y, ptEnd.x, ptEnd.y);

            /* asm: 10b0:3cb5..3cc2 — convert distance to int32 */
            dDist = (int32_t)d;

            /* asm: 10b0:3cc5..3ce8 — FStargateJump */
            if (!FStargateJump(lpfl, isbsSrcGate, isbsDstGate, (int16_t)dDist))
                goto nextFleet;

            /* asm: 10b0:3ceb..3cfb — clear fHereAllTurn */
            lpfl->fHereAllTurn = 0;

            /* asm: 10b0:3cff..3d0a — NoAutoTrackFleet */
            NoAutoTrackFleet(lpfl);

            goto LMakeItToDest; /* asm: 10b0:3d0d */

        } /* end stargate path */

        /* === NORMAL WARP PATH === */
        /* asm: 10b0:3d10..3d1e — ptBeg = fleet position */
        ptBeg.x = lpfl->pt.x;
        ptBeg.y = lpfl->pt.y;

        /* asm: 10b0:3d21..3d5b — chase fleet: update rgord[1] dest to target fleet pos */
        if (cPass > 0 && !lpfl->lpplord->rgord[1].fNoAutoTrack) {
            /* asm: 10b0:3d41..3d57 — update dest pt from chased fleet */
            lpfl->lpplord->rgord[1].pt.x = lpfl->lpflNext->pt.x;
            lpfl->lpplord->rgord[1].pt.y = lpfl->lpflNext->pt.y;
        }

        /* asm: 10b0:3d5b..3d69 — ptEnd = destination waypoint */
        ptEnd.x = lpfl->lpplord->rgord[1].pt.x;
        ptEnd.y = lpfl->lpplord->rgord[1].pt.y;

        /* asm: 10b0:3d6c..3d91 — EstFuelUse for range-only (fRangeOnly=1) */
        dRange = EstFuelUse(lpfl, 0, -1, -1, 1);

        /* asm: 10b0:3d94..3db9 — EstFuelUse for actual fuel (fRangeOnly=0) */
        wtFuel2Dest = EstFuelUse(lpfl, 0, -1, -1, 0);

        /* asm: 10b0:3dbc..3de5 — fGotEnufFuel = (fuel >= wtFuel2Dest) */
        fGotEnufFuel = (lpfl->rgwtMin[4] >= wtFuel2Dest) ? 1 : 0;

        /* asm: 10b0:3de8 */
        fRanOutOfFuel = 0;

        /* asm: 10b0:3ded..3e6c — if we have enough fuel, clamp dRange to iWarp^2 */
        if (fGotEnufFuel) {
            int16_t iWarp = lpfl->lpplord->rgord[1].iWarp;
            int32_t warpRange = (int32_t)(iWarp * iWarp);
            if (dRange <= warpRange) {
                dRange = warpRange;
            }
        }

        /* asm: 10b0:3e6c..3e72 — if not first pass, skip Macintosh/warp10 checks */
        if (cPass != 0)
            goto afterFirstPassChecks;

        /* asm: 10b0:3e75..3f5f — Macintosh colonist kill check */
        if (lpfl->rgwtMin[3] > 10) {
            /* asm: 10b0:3e91..3eb2 — check if race is Macintosh (AR) */
            if (GetRaceStat(&rgplr[lpfl->iPlayer], rsMajorAdv) == raMacintosh) {
                /* asm: 10b0:3eb5..3ee5 — calculate colonists killed */
                /* cDie = colonists * 3 / 100 + 33 (approximately) */
                /* __aFulmul(colonists, 3) then __aFldiv(result+0x21, 100) */
                int32_t mulResult = (int32_t)((uint32_t)lpfl->rgwtMin[3] * 3);
                cDie = (mulResult + 0x21) / 100;

                if (cDie > 0) {
                    /* asm: 10b0:3eff..3f5c — subtract colonists, send msg */
                    lpfl->rgwtMin[3] -= cDie;
                    FSendPlrMsg(lpfl->iPlayer, idmDueRigorsWarpAccelerationColonistsHaveDied, lpfl->id | 0x8000, (int16_t)cDie, (int16_t)((uint32_t)cDie >> 16),
                                lpfl->id, 0, 0, 0, 0);
                }
            }
        }

        /* asm: 10b0:3f5f..3f74 — warp 10 check */
        if (lpfl->lpplord->rgord[1].iWarp == 10) {
            /* block @ MEMORY_TURN:0x3f79 — warp 10 reactor accident */
            int16_t cKillTotLocal;
            int16_t fDeadLocal;
            FLEET   flSrcLocal;
            FLEET   flDeadLocal;

            /* asm: 10b0:3f79..3f8d — copy fleet to local */
            memcpy(&flSrcLocal, lpfl, sizeof(FLEET));

            fDeadLocal = 1;
            cKillTotLocal = 0;

            /* asm: 10b0:3f9e..3fb0 — zero flDead */
            memset(&flDeadLocal, 0, sizeof(FLEET));

            /* asm: 10b0:3fb3..413f — iterate ship slots */
            for (ish = 0; ish < 16; ish++) {
                if (flSrcLocal.rgcsh[ish] == 0)
                    goto LWarp10Kill;

                /* asm: 10b0:3fd1..40ad — check hull slot 0 item type for safe engines */
                {
                    SHDEF  *lpshdef = &rglpshdef[lpfl->iPlayer][ish];
                    uint8_t iItem = (uint8_t)(lpshdef->hul.rghs[0].wRaw_0002 & 0xff);
                    /* skip safe engine types: 7, 9, 0xe, 0xf, 8 */
                    if (iItem == iengineInterspace10 || iItem == iengineTransStar10 || iItem == iengineTransGalacticMizerScoop || iItem == iengineGalaxyScoop ||
                        iItem == iengineEnigmaPulsar)
                        goto LWarp10Kill;
                }

                /* asm: 10b0:40b0..4120 — roll for kills */
                {
                    int16_t cKillSlot = 0;
                    cTry = flSrcLocal.rgcsh[ish];
                    while (cTry-- > 0) {
                        if (Random(10) == 0) {
                            cKillSlot++;
                        }
                    }
                    if (cKillSlot > 0) {
                        cKillTotLocal += cKillSlot;
                        flSrcLocal.rgcsh[ish] -= cKillSlot;
                        flDeadLocal.rgcsh[ish] = cKillSlot;
                    }
                }

                /* label LWarp10Kill @ 10b0:4122 */
            LWarp10Kill:
                /* asm: 10b0:4122..413b — if any ships left in slot, not all dead */
                if (flSrcLocal.rgcsh[ish] > 0)
                    fDeadLocal = 0;
            }

            /* asm: 10b0:4148..418d — all ships destroyed */
            if (fDeadLocal) {
                lpfl->fDead = 1;
                FSendPlrMsg2(lpfl->iPlayer, idmDestroyedMassiveReactorAccidentDueUnsafeOperatin, lpfl->id | 0x8000, lpfl->id, 0);
                goto nextFleet;
            }

            /* asm: 10b0:4193..423d — some ships destroyed */
            if (cKillTotLocal > 0) {
                /* asm: 10b0:419d..41af — setup flDead for transfer */
                flDeadLocal.iPlayer = flSrcLocal.iPlayer;
                flDeadLocal.fDead = 1;
                flDeadLocal.det = 7;

                /* asm: 10b0:41c1..41d0 — FleetTransferCargoBalance */
                FleetTransferCargoBalance(&flSrcLocal, &flDeadLocal);

                /* asm: 10b0:41d3..41dd — copy back to fleet */
                memcpy(lpfl, &flSrcLocal, sizeof(FLEET));

                if (cKillTotLocal == 1) {
                    /* asm: 10b0:41ef..4213 */
                    FSendPlrMsg2(lpfl->iPlayer, idmOneShipsDestroyedWhenEnginesReactedTrying, lpfl->id | 0x8000, lpfl->id, 0);
                } else {
                    /* asm: 10b0:4219..423d */
                    FSendPlrMsg2(lpfl->iPlayer, idmShipsDestroyedDueEngineStrain, lpfl->id | 0x8000, cKillTotLocal, lpfl->id);
                }
            }
        } /* end warp 10 check */

        /* asm: 10b0:4240..426c — compute dTravel = iWarp^2 */
        {
            int16_t iWarp = lpfl->lpplord->rgord[1].iWarp;
            dTravel = (int32_t)((int16_t)(iWarp * iWarp));
        }

        /* asm: 10b0:426f..42f5 — chase fleet (grobj==2) setup */
        if (lpfl->lpplord->rgord[1].grobj == 2) {
            /* asm: 10b0:4286..4292 — resolve chase target */
            lpfl->lpflNext = LpflFromId(lpfl->lpplord->rgord[1].id);
            if (lpfl->lpflNext != NULL) {
                /* asm: 10b0:42b7..42f5 — set up for chase: mark not done, init move tracking */
                lFuelGain = 0;
                lpfl->fDone = 0;
                lpfl->dMoveLeft = (int16_t)dTravel;
                lpfl->dMoveUsed = 0;
                lpfl->lFuelUsed = 0;
                goto nextFleet;
            }
        }
        goto afterFirstPassChecks;

    afterFirstPassChecks:
        /* asm: 10b0:42fb — continuing from cPass > 0 path */
        if (cPass > 0) {
            /* asm: 10b0:42fb..4324 — chase: check if target is fDone */
            if (lpfl->lpflNext->fDone) {
                /* target fleet is done, use full remaining move */
                dTravel = (int32_t)lpfl->dMoveLeft;
            } else {
                /* asm: 10b0:4327..436c — target not done: use fraction of movement */
                int16_t avgMove = (lpfl->dMoveLeft + lpfl->dMoveUsed + 4) / 5;
                if (lpfl->dMoveLeft < avgMove) {
                    dTravel = (int32_t)lpfl->dMoveLeft;
                } else {
                    dTravel = (int32_t)avgMove;
                }
            }

            /* asm: 10b0:4373..439d — subtract used movement from range, clamp to 0 */
            dRange -= (int32_t)lpfl->dMoveUsed;
            if (dRange < 0)
                dRange = 0;
        }

        /* asm: 10b0:43a2..43bf — compute actual distance to destination */
        d = DGetDistance(ptBeg.x, ptBeg.y, ptEnd.x, ptEnd.y);

        /* asm: 10b0:43c0..4406 — clamp dTravel to ceil(d + 0.9999) */
        {
            int32_t dCeil = (int32_t)(d + 0.9999);
            if (dTravel >= dCeil) {
                /* can reach destination: use distance as travel */
            } else {
                dCeil = dTravel; /* can't reach: use full travel */
            }
            dTravel = dCeil;
        }

        /* asm: 10b0:4409..4449 — check if dTravel > dRange (ran out of fuel) */
        if (dTravel > dRange) {
            /* asm: 10b0:4424..4449 — ran out of fuel before destination */
            lpfl->rgwtMin[4] = 0;
            wtFuelUsed = 1;
            fRanOutOfFuel = 0;
            dTravel = dRange;
        } else {
            /* asm: 10b0:444c..44c4 — compute fuel used for travel */
            if (cPass > 0) {
                lpfl->rgwtMin[4] += lpfl->lFuelUsed;
                dTravel += (int32_t)lpfl->dMoveUsed;
            }
            wtFuelUsed = EstFuelUse(lpfl, 0, -1, dTravel, 0);
            if (cPass > 0) {
                lpfl->lFuelUsed = wtFuelUsed;
                dTravel -= (int32_t)lpfl->dMoveUsed;
            }

            /* asm: 10b0:44c7..4512 — subtract fuel, clamp to 0 */
            {
                int32_t fuelRemain = lpfl->rgwtMin[4] - wtFuelUsed;
                if (fuelRemain < 0)
                    fuelRemain = 0;
                lpfl->rgwtMin[4] = fuelRemain;
            }
        }

        /* asm: 10b0:4516..465d — out of fuel: find new warp speed */
        if (lpfl->rgwtMin[4] == 0 && wtFuelUsed > 0) {
            /* asm: 10b0:4544..4576 — check if dTravel < ceil(d - 0.99999) AND dRange > 0 */
            {
                int32_t dFloor = (int32_t)dTravel;
                double  dCheck = d - 0.99999;
                if (dFloor < (int32_t)dCheck) {
                    if (dRange != 0)
                        goto skipFuelSearch;
                }
            }

            /* asm: 10b0:4576..457f — check if fGotEnufFuel was set */
            if (fGotEnufFuel)
                goto skipFuelSearch;

            /* asm: 10b0:457f..465d — search for warp that uses 0 fuel */
            {
                int16_t iWarpNew = 0;
                do {
                    iWarpNew++;
                    if (EstFuelUse(lpfl, 0, iWarpNew, -1, 0) != 0)
                        break;
                } while (iWarpNew < 10);

                if (iWarpNew > 1) {
                    /* asm: 10b0:45cf..462e — reduce warp speed, send msg */
                    int16_t iWarpReduced = iWarpNew - 1;
                    lpfl->lpplord->rgord[1].iWarp = iWarpReduced & 0xf;
                    FSendPlrMsg2(lpfl->iPlayer, idmHasRunFuelFleetsSpeedHasDecreased, lpfl->id | 0x8000, lpfl->id, iWarpReduced);
                } else {
                    /* asm: 10b0:4631..4655 — completely out of fuel */
                    FSendPlrMsg2(lpfl->iPlayer, idmHasRunFuel, lpfl->id | 0x8000, lpfl->id, 0);
                }
                fRanOutOfFuel = 1;
            }
        }

    skipFuelSearch:
        /* asm: 10b0:465d..466f — if dRange == 0, skip to next fleet */
        if (dRange == 0)
            goto nextFleet;

        /* asm: 10b0:4672..4682 — clear fHereAllTurn */
        lpfl->fHereAllTurn = 0;

        /* asm: 10b0:4686..4782 — compute direction vector and store in dirFltX/dirFltY */
        {
            dx = ptEnd.x - ptBeg.x;
            dy = ptEnd.y - ptBeg.y;

            if (dx != 0 || dy != 0) {
                /* asm: 10b0:46aa..46b7 — set fdirValid */
                lpfl->fdirValid = 1;

                /* asm: 10b0:46be..46fc — scale dx/dy to fit in signed byte range */
                while (abs(dx) > 127 || abs(dy) > 127) {
                    dx /= 2;
                    dy /= 2;
                }

                /* asm: 10b0:46ff..474c — store direction */
                lpfl->dirFltX = (dx + 127) & 0xff;
                lpfl->dirFltY = (dy + 127) & 0xff;

                /* asm: 10b0:474e..4780 — store iWarp from rgord[1] */
                lpfl->iwarpFlt = lpfl->lpplord->rgord[1].iWarp & 0xf;
            }
        }

        /* asm: 10b0:4782..47c3 — compute actual travel as min(dTravel, floor(d-0.99999)) */
        dActTravel = (int32_t)(d - 0.99999);
        if (dTravel < dActTravel) {
            pct = dTravel;
        } else {
            pct = dActTravel;
        }

        /* asm: 10b0:47c6..484b — mine fields or fuel calculation path */
        if (lpfl->lpplord->rgord[1].iWarp < iWarpStargate) {
            /* asm: 10b0:47e0..47f7 — FTravelThroughMineFields */
            dMineTravel = (int16_t)pct;
            if (!FTravelThroughMineFields(lpfl, &dMineTravel, NULL)) {
                /* asm: 10b0:4802..4848 — mine field hit, stopped moving */
                lpfl->dMoveLeft = 0;
                if (lpfl->fDead)
                    goto nextFleet;
                /* asm: 10b0:4825..4845 — update dTravel if mine travel reduced it */
                if ((int32_t)dMineTravel < dActTravel) {
                    dTravel = (int32_t)dMineTravel;
                }
                goto afterFuelGain;
            }
        }

        /* asm: 10b0:484b..4951 — ram scoop fuel gain */
        if (!fRanOutOfFuel) {
            lFuelGain = GetFuelFree(lpfl);
            if (lFuelGain > 0) {
                int32_t dTravForScoop = (dTravel < dActTravel) ? dTravel : dActTravel;
                lFuelGainAct = LCalcFuelGainFromRamScoops(lpfl, lpfl->lpplord->rgord[1].iWarp, dTravForScoop);
                if (lFuelGainAct > 0) {
                    /* asm: 10b0:48df..48fc — add fuel via ChgCargo */
                    ChgCargo(grobjFleet, lpfl->id, 4, lFuelGainAct, NULL);

                    /* asm: 10b0:4905..4922 — cap for message */
                    if (lFuelGainAct > 32500)
                        lFuelGainAct = 32500;

                    /* asm: 10b0:4927..494e — send ram scoop msg */
                    FSendPlrMsg2(lpfl->iPlayer, idmSRamScoopsHaveProducedMgFuel, lpfl->id | 0x8000, lpfl->id, (int16_t)lFuelGainAct);
                }
            }
        }

    afterFuelGain:
        /* asm: 10b0:4951..4983 — check if we reached destination */
        if (dActTravel >= dTravel) {
            goto LMakeItToDest;
        }

        /* asm: 10b0:496c..49ed — check if any fuel was used */
        if (wtFuelUsed > 0) {
            goto didNotReachDest;
        }
        if (dActTravel > 0) {
            goto didNotReachDest;
        }

        /* label LMakeItToDest @ 10b0:4983 */
    LMakeItToDest:
        /* asm: 10b0:4983..4990 — move fleet to destination */
        lpfl->pt.x = ptEnd.x;
        lpfl->pt.y = ptEnd.y;

        /* asm: 10b0:4994..49bf — set idPlanet based on grobj */
        if (lpfl->lpplord->rgord[1].grobj == 1) {
            lpfl->idPlanet = lpfl->lpplord->rgord[1].id;
        } else {
            lpfl->idPlanet = -1;
        }

        /* asm: 10b0:49c5..49ea — if cPass > 0, mark chased fleet as fDone */
        if (cPass > 0) {
            lpfl->lpflNext->fDone = 1;
        }

        goto afterMovement; /* asm: 10b0:49ea -> 4b2d */

    didNotReachDest:
        /* asm: 10b0:49ed..4ace — interpolate position */
        dxRound = (ptEnd.x > ptBeg.x) ? 0.5 : -0.5;
        dyRound = (ptEnd.y > ptBeg.y) ? 0.5 : -0.5;

        /* asm: 10b0:4a31..4ace — check if distance is meaningful */
        if (d > 0.0001 || d < -0.0001) {
            r = (double)dTravel / d;
            lpfl->pt.x = (int16_t)((double)(ptEnd.x - ptBeg.x) * r + dxRound) + ptBeg.x;
            lpfl->pt.y = (int16_t)((double)(ptEnd.y - ptBeg.y) * r + dyRound) + ptBeg.y;
            lpfl->idPlanet = -1;
        }

        /* asm: 10b0:4ace..4b2d — update chase movement tracking */
        if (cPass > 0) {
            if (lpfl->dMoveLeft > 0) {
                lpfl->dMoveUsed += (int16_t)dTravel;
                lpfl->dMoveLeft -= (int16_t)dTravel;
                if (lpfl->dMoveLeft > 0 && !fRanOutOfFuel) {
                    lFuelGain = 0;
                    lpfl->fDone = 0;
                }
            }
        }

    afterMovement:
        /* asm: 10b0:4b2d..4ce4 — radiating engine colonist kill */
        if (gd.fRadiatingEngine) {
            if (lpfl->rgwtMin[3] > 0 && cPass <= 1) {
                /* asm: 10b0:4b65..4bea — compute radiation environment */
                int8_t radMax = rgplr[lpfl->iPlayer].rgEnvVarMax[2];
                int8_t radMin = rgplr[lpfl->iPlayer].rgEnvVarMin[2];
                if ((int16_t)radMin + (int16_t)radMax < 0xaa && radMax != -1) {
                    int16_t radAvg = ((int16_t)radMin + (int16_t)radMax) / 2;
                    /* asm: 10b0:4bed..4c24 — compute kill amount */
                    pct = ((int32_t)(86 - radAvg) >> 1) * (int32_t)(uint32_t)lpfl->rgwtMin[3] / 100;
                    if (pct < 1)
                        pct = 1;

                    /* asm: 10b0:4c51..4c76 — clamp to actual colonists */
                    if (pct > lpfl->rgwtMin[3])
                        pct = lpfl->rgwtMin[3];
                    if (pct < 1)
                        pct = 1;

                    /* asm: 10b0:4ca9..4ce0 — send msg and subtract */
                    FSendPlrMsg2(lpfl->iPlayer, idmEngineRadiationHasKilledColonistsTraveling, lpfl->id | 0x8000, (int16_t)pct, lpfl->id);
                    lpfl->rgwtMin[3] -= pct;
                }
            }
        }

        /* asm: 10b0:4ce4..4dd8 — wormhole traversal check */
        if (lpfl->pt.x == ptEnd.x && lpfl->pt.y == ptEnd.y) {
            if (lpfl->lpplord->rgord[1].grobj == 8) {
                /* block @ MEMORY_TURN:0x4d1e */
                lpthDest = LpthFromId(lpfl->lpplord->rgord[1].id);
                if (lpthDest != NULL && lpthDest->ith == 2) {
                    /* block @ MEMORY_TURN:0x4d5b — wormhole traversal */
                    grbitPlr = (int16_t)(1 << lpfl->iPlayer);
                    lpth = LpthFromId(lpthDest->thw.idPartner);

                    NoAutoTrackFleet(lpfl);

                    /* mark source wormhole as seen/traversed */
                    lpthDest->thw.grbitPlrTrav |= grbitPlr;
                    /* mark dest wormhole as seen/traversed */
                    lpth->thw.grbitPlrTrav |= grbitPlr;
                    lpth->thw.grbitPlr |= grbitPlr;

                    /* move fleet to dest wormhole position */
                    lpfl->pt.x = lpth->pt.x;
                    lpfl->pt.y = lpth->pt.y;

                    /* update order destination to dest wormhole */
                    lpfl->lpplord->rgord[1].pt.x = lpth->pt.x;
                    lpfl->lpplord->rgord[1].pt.y = lpth->pt.y;
                }
            }
        }

        /* asm: 10b0:4dd8..4e12 — find nearest planet if idPlanet == -1 */
        if (lpfl->idPlanet == -1) {
            if (FFindNearestObject(lpfl->pt, grobjPlanet | mdExact, &scan)) {
                lpfl->idPlanet = scan.idpl;
            }
        }

        /* asm: 10b0:4e12..4e6d — update first waypoint to current position */
        lpord->pt.x = lpfl->pt.x;
        lpord->pt.y = lpfl->pt.y;
        lpord->id = lpfl->idPlanet;

        /* asm: 10b0:4e35..4e6d — set grobj based on idPlanet */
        lpord->grobj = (lpfl->idPlanet == -1) ? 4 : 1;

        /* asm: 10b0:4e6f..4f12 — fuel reservation for next waypoint */
        if (fGotEnufFuel) {
            /* asm: 10b0:4e78..4e9d — EstFuelUse for range-only */
            wtFuel2Dest = EstFuelUse(lpfl, 0, -1, -1, 0);

            /* asm: 10b0:4ea0..4ef2 — if fuel > estimated need, reserve */
            if (wtFuel2Dest > lpfl->rgwtMin[4]) {
                /* asm: 10b0:4eba..4eee — compare with fleet fuel capacity */
                int32_t lFuelCap = LGetFleetStat(lpfl, grStatFuel);
                if (wtFuel2Dest < lFuelCap) {
                    lpfl->rgwtMin[4] = wtFuel2Dest;
                } else {
                    /* asm: 10b0:4ef5..4f0e — use max fuel capacity */
                    lpfl->rgwtMin[4] = LGetFleetStat(lpfl, grStatFuel);
                }
            }
        }

    nextFleet: /* asm: 10b0:32f6 */
        ifl++;
    } /* end fleet loop */

donePass: /* asm: 10b0:4f15 */
    /* asm: 10b0:4f15..4f2d — check if any fleet still moving (lFuelGain==0) and cPass < 10 */
    if (lFuelGain == 0) {
        if (cPass++ < 10)
            goto MoveUnfinishedFleets;
    }

    /* asm: 10b0:4f30 — KillUsedWaypoints */
    KillUsedWaypoints();

done: /* asm: 10b0:4f35 */
    return;
}

int16_t FTravelThroughMineFields(FLEET *lpfl, int16_t *pdTravel, THING *lpthHit) {
    int32_t    d2Closest;
    int16_t    rgishInc[16];
    int16_t    dTravel;
    STARSPOINT ptAct;
    int16_t    iWarp;
    STARSPOINT ptDst;
    int16_t    dy;
    int32_t    d2;
    int16_t    j;
    int16_t    dEnd;
    FLEET      flSrc;
    int32_t    dpsh;
    int16_t    cshT;
    int32_t    dmgReduce;
    int32_t    dmgToApply;
    int16_t    i;
    THING     *lpth;
    int16_t    dmgExtra;
    int16_t    cshDamaged;
    int16_t    fMineExpert;
    STARSPOINT ptSrc;
    int16_t    iPlayer;
    int16_t    cFields;
    int16_t    dStart;
    FLEET      flDead;
    THING     *lpthMac;
    int32_t    csh;
    int16_t    rgi[3];
    int16_t    pct;
    int32_t    dmgTot;
    int16_t    cshDead;
    int16_t    rgcField[3];
    int16_t    raMajor;
    int16_t    dx;
    int32_t    dpShield;
    int16_t    iType;
    int16_t    rgFieldE[3][8];
    THING     *lpthClosest;
    int16_t    cishInc;
    THING     *lpthSalvage;
    int16_t    fHasRamScoop;
    int16_t    dmgPer;
    int16_t    rgFieldS[3][8];
    int16_t    cEngines;
    uint16_t   ibit; /* stack-overlap with cEngines per NB09 (block-local in asm) */
    int32_t    dmgPerShip;

    /* ------------------------------------------------------------
     * asm: 10b0:4f60..  prologue / init locals
     * ------------------------------------------------------------ */
    lpthSalvage = NULL;
    dTravel = *pdTravel;
    cishInc = 0;

    /* owner player */
    iPlayer = lpfl->iPlayer;

    /* ------------------------------------------------------------
     * asm: 10b0:4f94..4fe3  raMajor = GetRaceStat(rgplr+iPlayer, rsMajorAdv)
     *      fMineExpert = (raMajor==raMines)*2 + (raMajor==raStealth)
     * ------------------------------------------------------------ */
    raMajor = GetRaceStat(&rgplr[iPlayer], rsMajorAdv);
    fMineExpert = (raMajor == raMines) ? 2 : 0;
    fMineExpert = fMineExpert + ((raMajor == raStealth) ? 1 : 0);

    /* ------------------------------------------------------------
     * asm: 10b0:4fe7..  branch on lpthHit
     * ------------------------------------------------------------ */
    if (lpthHit == NULL) {
        /* src/dst */
        ptSrc.x = lpfl->pt.x;
        ptSrc.y = lpfl->pt.y;

        /* NOTE: ghidra had odd PLORD indexing; real intent is first order point. */
        ptDst.x = lpfl->lpplord->rgord[0].pt.x;
        ptDst.y = lpfl->lpplord->rgord[0].pt.y;

        /* --------------------------------------------------------
         * asm: (loop) choose iWarp from dTravel
         * for (iWarp=3; iWarp<10 && iWarp*iWarp < dTravel-1; ++iWarp) {}
         * -------------------------------------------------------- */
        for (iWarp = 3; (iWarp < 10) && ((iWarp * iWarp) < (dTravel - 1)); iWarp = iWarp + 1) {
        }

        /* --------------------------------------------------------
         * asm: early out if warp too low OR no movement
         * if (iWarp <= fMineExpert+3) return 1;
         * if (ptSrc==ptDst) return 1;
         * -------------------------------------------------------- */
        if (iWarp <= (fMineExpert + 3))
            return 1;
        if (ptSrc.x == ptDst.x && ptSrc.y == ptDst.y)
            return 1;

        /* --------------------------------------------------------
         * asm: zero rgcField[0..2]
         * -------------------------------------------------------- */
        for (i = 0; i < 3; i = i + 1)
            rgcField[i] = 0;

        /* --------------------------------------------------------
         * asm: iterate THINGs; build per-type interval lists rgFieldS/E
         * - must be minefield: lpth->ith==0
         * - not owned by iPlayer
         * - not relation==1 (rgplr[owner].rgmdRelation[iPlayer] != 1)
         * - and FIntersectCircleLine(...) yields [dStart,dEnd]
         * - insert/merge interval in sorted order for that type
         * -------------------------------------------------------- */
        lpthMac = lpThings + cThing;
        for (lpth = lpThings; lpth < lpthMac; ++lpth) {
            if (lpth->iplr != iPlayer && lpth->ith == 0 && rgplr[lpth->iplr].rgmdRelation[iPlayer] != 1) {

                STARSPOINT ptL1, ptL2, ptC;
                ptL1 = ptSrc;
                ptL2 = ptDst;
                ptC.x = lpth->pt.x;
                ptC.y = lpth->pt.y;

                if (FIntersectCircleLine(ptL1, ptL2, ptC, lpth->thm.cMines, dTravel, &dStart, &dEnd)) {
                    iType = lpth->thm.iType;

                    /* find insert position by start */
                    for (i = 0; (i < rgcField[iType]) && (rgFieldE[iType][i] < dStart); i = i + 1) {
                    }

                    if (i == rgcField[iType]) {
                        if (i < 8) {
                            rgFieldS[iType][i] = dStart;
                            rgFieldE[iType][i] = dEnd;
                            rgcField[iType] = rgcField[iType] + 1;
                        }
                    } else if (dEnd < (rgFieldS[iType][i] - 1)) {
                        if (rgcField[iType] < 8) {
                            for (j = rgcField[iType]; i < j; j = j - 1) {
                                rgFieldS[iType][j] = rgFieldS[iType][j - 1];
                                rgFieldE[iType][j] = rgFieldE[iType][j - 1];
                            }
                            rgFieldS[iType][i] = dStart;
                            rgFieldE[iType][i] = dEnd;
                            rgcField[iType] = rgcField[iType] + 1;
                        }
                    } else {
                        if (dStart < rgFieldS[iType][i])
                            rgFieldS[iType][i] = dStart;

                        if (rgFieldE[iType][i] < dEnd) {
                            rgFieldE[iType][i] = dEnd;

                            for (j = i + 1; (j < rgcField[iType]) && (rgFieldS[iType][j] <= dEnd); j = j + 1) {
                            }

                            if (dEnd < rgFieldE[iType][j - 1])
                                rgFieldE[iType][i] = rgFieldE[iType][j - 1];

                            /* collapse */
                            {
                                int16_t iDst = i;
                                for (; j < rgcField[iType]; j = j + 1) {
                                    ++iDst;
                                    rgFieldS[iType][iDst] = rgFieldS[iType][j];
                                    rgFieldE[iType][iDst] = rgFieldE[iType][j];
                                }
                                rgcField[iType] = rgcField[iType] - (j - (i + 1));
                            }
                        }
                    }
                }
            }
        }

        cFields = rgcField[0] + rgcField[1] + rgcField[2];
        if (cFields == 0)
            return 1;
    } else {
        /* asm: else-path sets iWarp=0 (hit is forced / detonating minefield) */
        iWarp = 0;
    }

    /* ------------------------------------------------------------
     * asm: 10b0: (ship-count + ram-scoop detection)
     * csh = sum(rgcsh[i])
     * if any engine fuelUsed[4]==0 => fHasRamScoop=1
     * engine id lives in shdef->hul.rghs[0].iItem (matches +0x3c &0xff)
     * ------------------------------------------------------------ */
    fHasRamScoop = 0;
    csh = 0;
    for (i = 0; i < 16; i = i + 1) {
        if (lpfl->rgcsh[i] > 0) {
            SHDEF  *pshdef = &rglpshdef[iPlayer][i];
            ENGINE *pengine;

            csh += lpfl->rgcsh[i];

            pengine = LpengineFromId(pshdef->hul.rghs[0].iItem);
            if (pengine->rgcFuelUsed[4] == 0)
                fHasRamScoop = 1;
        }
    }

    /* ------------------------------------------------------------
     * asm: interval merge / probabilistic hit search (only if lpthHit==NULL)
     * chooses earliest hit distance dEnd and jumps into hit handler
     * ------------------------------------------------------------ */
    if (lpthHit == NULL) {
        rgi[0] = rgi[1] = rgi[2] = 0;

        for (; cFields > 0; cFields = cFields - 1) {
            dStart = 10000;
            iType = -1;

            for (i = 0; i < 3; i = i + 1) {
                if (rgi[i] < rgcField[i] && rgFieldS[i][rgi[i]] < dStart) {
                    dStart = rgFieldS[i][rgi[i]];
                    iType = i;
                }
            }

            dEnd = rgFieldE[iType][rgi[iType]] - rgFieldS[iType][rgi[iType]];

            if ((rgiWarpSafe[iType] + fMineExpert) < iWarp) {
                int16_t warpSafe = rgiWarpSafe[iType];
                int16_t pctHit = rgpctMineHit[iType];

                for (i = 0; i < dEnd; i = i + 1) {
                    if (Random(1000) < (((iWarp - warpSafe) - fMineExpert) * pctHit))
                        break;
                }

                if (i != dEnd) {
                    dEnd = dStart + i;
                    goto LHitSkip2; /* NB09 label */
                }
            }

            rgi[iType] = rgi[iType] + 1;
        }

        /* no hit */
        return 1;
    } else {
        iType = lpthHit->thm.iType;
        /* fallthrough */
    }

LHitSkip2:
    /* ------------------------------------------------------------
     * asm: minefield impact / apply damage (labels: LHitSkip2, LFinishHit)
     * ------------------------------------------------------------ */
    cshDead = 0;
    dmgReduce = 0;

    dmgPer = rgrgdmgMine[iType][fHasRamScoop];
    if (dmgPer != 0) {
        /* dmgExtra = rgrgdmgMinMine - dmgPer*csh ; clamped per asm conditions */
        dmgExtra = rgrgdmgMinMine[iType][fHasRamScoop] - (dmgPer * csh);
        if ((csh > 4) || (dmgExtra < 1))
            dmgExtra = 0;

        /* copy lpfl -> flSrc (asm uses REP MOVSW across 0x7c bytes) */
        flSrc = *lpfl;

        /* memset flDead, set iPlayer, set det/fDead per mask (&0xfb00|0x407) */
        memset(&flDead, 0, sizeof(flDead));
        flDead.iPlayer = flSrc.iPlayer;
        flDead.det = 7;
        flDead.fDead = 1;

        /* --------------------------------------------------------
         * asm: per-stack damage loop
         * - builds rgishInc[] list (used for raMines visibility update)
         * - kills or damages each stack updating flSrc.rgdv[i]
         * -------------------------------------------------------- */
        for (i = 0; i < 16; i = i + 1) {
            if (lpfl->rgcsh[i] <= 0)
                continue;

            /* skip some hulls when detonating own minefield (matches ghidra ihuldef==0x1b/0x1c check) */
            if (lpthHit != NULL && lpthHit->iplr == lpfl->iPlayer) {
                int16_t ihuldef = rglpshdef[iPlayer][i].hul.ihuldef;
                if (ihuldef == 0x1b || ihuldef == 0x1c)
                    continue;
            }

            cshT = lpfl->rgcsh[i];

            rgishInc[cishInc] = i;
            cishInc = cishInc + 1;

            /* engines count: HS slot0 cItem (matches +0x3c >> 8) */
            cEngines = rglpshdef[iPlayer][i].hul.rghs[0].cItem;

            /* total shield points for this stack */
            dpShield = cshT * DpShieldOfShdef(&rglpshdef[iPlayer][i], iPlayer);

            /* damage applied to this stack (scaled by engines like asm mul chain) */
            dmgToApply = cshT * dmgPer + dmgExtra;
            dmgToApply = dmgToApply * cEngines;

            dmgReduce += dmgToApply;

            /* absorb by shields */
            dpsh = dmgToApply;
            if (dpsh > dpShield)
                dpsh = dpShield;

            /* ----------------------------------------------------
             * asm: compute per-ship damage threshold using DV bits
             * (original uses dv packed in rgdv; here we use bitfields)
             * ---------------------------------------------------- */
            {
                int32_t pctSh = flSrc.rgdv[i].pctSh; /* 0..100 */
                int32_t pctDp = flSrc.rgdv[i].pctDp; /* 0..511 (packed) */
                int32_t dpBase = rglpshdef[iPlayer][i].hul.dp;

                int32_t shUnits = (cshT * pctSh) / 100;
                int32_t dpUnits = (dpBase * pctDp * shUnits) / 500;

                dmgPerShip = (dpUnits + (dmgToApply - dpsh)) / cshT;

                if ((dmgPerShip < 0) || (dmgPerShip > dpBase)) {
                    /* dead */
                    cshDead = cshDead + cshT;
                    flDead.rgcsh[i] = cshT;
                    flSrc.rgcsh[i] = 0;
                } else {
                    /* damaged */
                    flSrc.rgdv[i].pctSh = 100;
                    flSrc.rgdv[i].pctDp = (dmgPerShip * 500) / dpBase;
                    if (flSrc.rgdv[i].pctDp == 0)
                        flSrc.rgdv[i].pctDp = 1;
                }
            }

            dmgExtra = 0; /* asm zeros dmgExtra after first application */
        }

        /* asm: if detonating (lpthHit!=NULL) and no damage computed => return 0 */
        if (lpthHit != NULL && dmgReduce == 0)
            return 0;

        /* transfer cargo from survivors into flDead */
        if (cshDead != csh)
            FleetTransferCargoBalance(&flSrc, &flDead);

        /* write flSrc back */
        *lpfl = flSrc;

        /* if all dead set fDead */
        if (cshDead == csh)
            lpfl->fDead = 1;
    }

    /* ------------------------------------------------------------
     * asm: compute ptAct + salvage drop + find closest minefield of same type
     * only for non-forced (lpthHit==NULL) hits
     * ------------------------------------------------------------ */
    if (lpthHit == NULL) {
        int16_t dist;

        dx = ptDst.x - ptSrc.x;
        dy = ptDst.y - ptSrc.y;

        d2 = (int32_t)dx * dx + (int32_t)dy * dy;

        /* asm uses _sqrt(double) then __ftol */
        dist = (int16_t)(int32_t)(sqrt((double)d2));

        ptAct.x = ptSrc.x + MulDiv(dx, dEnd, dist);
        ptAct.y = ptSrc.y + MulDiv(dy, dEnd, dist);

        if (cshDead != 0) {
            /* find existing salvage packet at ptAct: ith==1 and thp.iWarp==0 */
            lpthSalvage = lpThings;
            while (lpthSalvage < lpThings + cThing) {
                if (lpthSalvage->pt.x == ptAct.x && lpthSalvage->pt.y == ptAct.y && lpthSalvage->ith == 1 && lpthSalvage->thp.iWarp == 0) {
                    break;
                }
                ++lpthSalvage;
            }
            if (lpthSalvage == lpThings + cThing)
                lpthSalvage = NULL;

            DropSalvage(&lpthSalvage, lpfl->rgwtMin, flSrc.iplr, &ptAct);
        }

        /* d2Closest = 100000000 (0x05f5e100) */
        d2Closest = 100000000L;

        lpthClosest = NULL;
        for (lpth = lpThings; lpth < lpThings + cThing; ++lpth) {
            if (lpth->iplr != iPlayer && lpth->ith == 0 && rgplr[lpth->iplr].rgmdRelation[iPlayer] != 1 && lpth->thm.iType == iType) {

                dx = lpth->pt.x - ptAct.x;
                dy = lpth->pt.y - ptAct.y;

                d2 = (int32_t)dx * dx + (int32_t)dy * dy - lpth->thm.cMines;
                if (d2 <= d2Closest) {
                    d2Closest = d2;
                    lpthClosest = lpth;
                }
            }
        }

        /* d2 = minefield.cMines / 20 (0x14), clamped per asm */
        d2 = (lpthClosest != NULL) ? (lpthClosest->thm.cMines / 20) : 0;
        if (d2 < 0x33) {
            if (d2 < 10)
                d2 = 10;
        } else {
            d2 = (lpthClosest->thm.cMines / 100);
            if (d2 < 0x32)
                d2 = 0x32;
        }
    } else {
        ptAct.x = lpthHit->pt.x;
        ptAct.y = lpthHit->pt.y;
        lpthClosest = lpthHit;
        /* d2 already set from earlier path in asm; keep as-is */
    }

    /* ------------------------------------------------------------
     * asm: if minefield owner has raMines => reveal owner bit into SHDEF.grbitPlr
     * (bit is 1<<owner)
     * ------------------------------------------------------------ */
    if (GetRaceStat(&rgplr[lpthClosest->iplr], rsMajorAdv) == raMines) {
        ibit = 1u << lpthClosest->iplr;

        if (cishInc == 0) {
            for (i = 0; i < 16; i = i + 1) {
                if (lpfl->rgcsh[i] > 0)
                    rglpshdef[iPlayer][i].grbitPlr |= ibit;
            }
        } else {
            for (i = 0; i < cishInc; i = i + 1) {
                rglpshdef[iPlayer][rgishInc[i]].grbitPlr |= ibit;
            }
        }
    }

    /* clamp dmgReduce to 0x7ff8 then dmgTot low word */
    if (dmgReduce > 0x7ff8)
        dmgReduce = 0x7ff8;
    dmgTot = (int16_t)dmgReduce;

    /* ------------------------------------------------------------
     * asm: messaging cases (exact ids preserved from decompile)
     * ------------------------------------------------------------ */
    if (dmgReduce == 0) {
        if (iPlayer != lpthClosest->iplr) {
            FSendPlrMsg(iPlayer, idmHasStoppedMineField, lpfl->id | 0x8000, lpfl->id | 0x8000, lpthClosest->iplr, iType, ptAct.x, ptAct.y, 0, 0);
        }
        FSendPlrMsg(lpthClosest->iplr, idmHasStoppedMineField2, lpfl->id | 0x8000, lpfl->id | 0x8000, iType, ptAct.x, ptAct.y, 0, 0, 0);
        dmgReduce = d2;
    } else if (cshDead == 0) {
        MessageId mid;

        if (iPlayer != lpthClosest->iplr) {
            mid = (lpthHit == NULL) ? idmHasStoppedMineFieldFleetHasTaken : idmHasDamagedDetonatingMineFieldFleetHas;
            FSendPlrMsg(iPlayer, mid, lpfl->id | 0x8000, lpfl->id | 0x8000, lpthClosest->iplr, iType, ptAct.x, ptAct.y, dmgTot, 0);
        }

        mid = (lpthHit == NULL) ? idmHasStoppedMineFieldMinesHaveInflicted : idmHasDamagedDetonatingMineFieldMinesHave;
        FSendPlrMsg(lpthClosest->iplr, mid, lpfl->id | 0x8000, lpfl->id | 0x8000, iType, ptAct.x, ptAct.y, dmgTot, 0, 0);
        dmgReduce = d2;
    } else if (cshDead >= csh) {
        /* annihilated */
        flDead.id = lpfl->id;

        if (lpthSalvage == NULL) {
            if (iPlayer != lpthClosest->iplr) {
                FSendPlrMsg(iPlayer, idmHasAnnihilatedMineField3, -1, WFromLpfl(&flDead), lpthClosest->iplr, iType, ptAct.x, ptAct.y, 0, 0);
            }
            if (iPlayer == lpthClosest->iplr) {
                FSendPlrMsg(lpthClosest->iplr, idmHasAnnihilatedMineField4, -1, WFromLpfl(&flDead), iType, ptAct.x, ptAct.y, 0, 0, 0);
                dmgReduce = d2;
            } else {
                FSendPlrMsg(lpthClosest->iplr, idmHasAnnihilatedMineField2, -6, lpthClosest->idFull, lpfl->id, iType, ptAct.x, ptAct.y, 0, 0);
                dmgReduce = d2;
            }
        } else {
            if (iPlayer != lpthClosest->iplr) {
                FSendPlrMsg(iPlayer, idmHasAnnihilatedMineField, -6, lpthSalvage->idFull, WFromLpfl(&flDead), lpthClosest->iplr, iType, ptAct.x, ptAct.y, 0);
            }
            FSendPlrMsg(lpthClosest->iplr, idmHasAnnihilatedMineField2, -6, lpthSalvage->idFull, lpfl->id, iType, ptAct.x, ptAct.y, 0, 0);
            dmgReduce = d2;
        }
    } else {
        MessageId mid;

        if (iPlayer != lpthClosest->iplr) {
            mid = (lpthHit == NULL) ? idmHasStoppedMineFieldFleetHasTaken2 : idmHasTakenDamageDetonatingMineFieldFleet;
            FSendPlrMsg(iPlayer, mid, lpfl->id | 0x8000, lpfl->id | 0x8000, lpthClosest->iplr, iType, ptAct.x, ptAct.y, dmgTot, cshDead);
        }

        mid = (lpthHit == NULL) ? idmHasStoppedMineFieldMinesHaveInflicted2 : idmHasDamagedDetonatingMineFieldMinesHave2;
        FSendPlrMsg(lpthClosest->iplr, mid, lpfl->id | 0x8000, lpfl->id | 0x8000, iType, ptAct.x, ptAct.y, dmgTot, cshDead, 0);
        dmgReduce = d2;
    }

    /* ------------------------------------------------------------
     * asm: reduce minefield size or free it; set seen bits; update *pdTravel
     * ------------------------------------------------------------ */
    if (lpthHit == NULL) {
        if (dmgReduce < lpthClosest->thm.cMines) {
            lpthClosest->thm.cMines -= dmgReduce;
            lpthClosest->thm.grbitPlrNow |= 1u << iPlayer;
            lpthClosest->thm.grbitPlr |= 1u << iPlayer;
        } else {
            dmgReduce = lpthClosest->thm.cMines;
            FreeLpth(lpthClosest);
        }
        *pdTravel = dEnd;
    }

    /* ------------------------------------------------------------
     * asm: set fleet flags: clear fMark, set fNoHeal (wRaw &0xbfff |0x4000)
     * ------------------------------------------------------------ */
    lpfl->fMark = 0;
    lpfl->fNoHeal = 1;

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

    bool fTwoMAsB;

    /* asm: 10b0:18f4..192a — init lpth, lpthMac, fAnythingMoved */
    fAnythingMoved = 0;
    lpth = lpThings;
    lpthMac = lpThings + cThing;

    /* asm: 10b0:2ed7 — main loop entry */
    for (;;) {
        if (lpth >= lpthMac) {
            /* asm: 10b0:2ee5..2ef8 — end of loop, validate and return */
            if (fAnythingMoved)
                ValidateWaypoints();
            return;
        }

        /* asm: 10b0:192d..193e — check ith == 2 (wormhole) */
        if (lpth->ith == ithWormhole && fPostProd) {
            /* asm: 10b0:194c..19f6 — wormhole movement */
            k = 0;
            ptBase.x = lpth->pt.x; /* asm: 10b0:1951..195f */
            ptBase.y = lpth->pt.y;
            iX = Random(100);                         /* asm: 10b0:1962..196e */
            fMajorMove = iX < PctWormholeMoves(lpth); /* asm: 10b0:1971..1992 */

            if (fMajorMove) {
                /* asm: 10b0:199e..19c8 — major wormhole move */
                lpth->thw.grbitPlr = 0;         /* asm: 10b0:19a1 — clear grbitPlr at +0x08 */
                dUni = game.mdSize * 400 + 400; /* asm: 10b0:19a7..19b1 */
                lpth->thw.wRaw_0000 &= 0xf003;  /* asm: 10b0:19b7..19c4 — clear cLastMove/middle bits */
            } else {
                /* asm: 10b0:19cb..19f2 — minor wormhole move: increment cLastMove */
                iX = (lpth->thw.wRaw_0000 + 4) & 0xffc; /* asm: 10b0:19ce..19d8 */
                lpth->thw.wRaw_0000 &= 0xf003;          /* asm: 10b0:19de */
                lpth->thw.wRaw_0000 |= iX;              /* asm: 10b0:19ee */
            }

            /* asm: 10b0:19f6 — iMax = 16 */
            iMax = 16;

            /* asm: 10b0:19fb..1ad7 — try up to 100 positions */
            while (k < 100) {
                k++; /* asm: 10b0:19fb..19fe — k incremented after use */
                if (fMajorMove) {
                    /* asm: 10b0:1a13..1a3d — random universe position */
                    lpth->pt.x = Random(dUni) + 1000;
                    lpth->pt.y = Random(dUni) + 1000;
                } else {
                    /* asm: 10b0:1a40..1a6e — random nearby position */
                    lpth->pt.x = Random(25) + ptBase.x - 12;
                    lpth->pt.y = Random(25) + ptBase.y - 12;
                }
                /* asm: 10b0:1a72..1a95 — check if position changed */
                if (lpth->pt.x == ptBase.x && lpth->pt.y == ptBase.y)
                    continue;
                /* asm: 10b0:1a98..1aaf — validate position */
                iLow = IValidateWormholePos(lpth);
                if (iLow == 0)
                    break; /* asm: 10b0:1ab2 — valid, done */
                /* asm: 10b0:1ab5..1ad4 — track best position */
                if (iLow < iMax) {
                    iMax = iLow;
                    pt.x = lpth->pt.x;
                    pt.y = lpth->pt.y;
                }
            }

            /* asm: 10b0:1ada..1af0 — if never found valid, use best */
            if (iLow != 0) {
                lpth->pt.x = pt.x;
                lpth->pt.y = pt.y;
            }
        } else if (lpth->ith == ithMysteryTrader && !fPostProd) {
            /* asm: 10b0:1af7..1c77 — mystery trader movement */

            /* asm: 10b0:1b16..1b27 — get trader warp speed */
            dRange = lpth->tht.iWarp;
            if (dRange > 12)
                goto LAB_1c3e; /* asm: 10b0:1b29 */

            /* asm: 10b0:1b2c..1b3d — 1/25 chance of action */
            if (Random(25) != 0)
                goto LAB_1c3e; /* asm: 10b0:1b3d */

            /* asm: 10b0:1b40..1b54 — idm = mystery trader changed course */
            idm = idmMysteryTraderHasUnexplicablyChangedHisCourse;

            /* asm: 10b0:1b48..1b59 — 1/3 chance of retarget, else speed up */
            if (Random(3) != 0)
                goto LSpeedUpOnly; /* asm: 10b0:1b59 */

        LRetargetFreighter: /* asm: 10b0:1b5c */
            /* asm: 10b0:1b5c..1bde — pick new destination */
            if (Random(2) == 0) {
                /* asm: 10b0:1b70..1b7d */
                rgC[0] = game.mdSize * 400 + 1380;
            } else {
                /* asm: 10b0:1b80 */
                rgC[0] = 1020;
            }
            /* asm: 10b0:1b85..1b9b */
            rgC[1] = Random(game.mdSize * 400 + 361) + 1020;

            /* asm: 10b0:1b9e..1bde — pick x or y randomly */
            iX = Random(2);                                      /* asm: 10b0:1baa */
            lpth->tht.ptDest.x = *(&rgC[0] + iX);                /* asm: 10b0:1bb7..1bbc */
            lpth->tht.ptDest.y = *(&rgC[0] + (iX == 0 ? 1 : 0)); /* asm: 10b0:1bc0..1bde */

        LSpeedUpOnly: /* asm: 10b0:1be2 */
            /* asm: 10b0:1be2..1c05 — increment warp and update */
            dRange++;
            lpth->tht.wRaw_0004 = (lpth->tht.wRaw_0004 & 0xfff0) | (dRange & 0xf);

            /* asm: 10b0:1c07..1c3b — send message to all players */
            for (k = 0; k < game.cPlayer; k++) {
                FSendPlrMsg2(k, idm, -6, lpth->idFull, 0);
            }

        LAB_1c3e: /* asm: 10b0:1c3e */
            /* asm: 10b0:1c3e..1c62 — compute trader speed and destination */
            dRange = lpth->tht.iWarp;
            dRange = dRange * dRange;
            ptDst.x = lpth->tht.ptDest.x;
            ptDst.y = lpth->tht.ptDest.y;

            /* asm: 10b0:1c65..1c6f — set fAnythingMoved */
            fAnythingMoved = 1;

            /* asm: 10b0:1c6a..1c74 — if idm == 0xc0, skip movement */
            if (idm == idmMysteryTraderHasDecidedMakeAnotherPass)
                goto LNext;

            goto MoveTh; /* asm: 10b0:1c77 */
        } else if (lpth->ith == ithMineralPacket && lpth->thp.iWarp != 0 && (!fPostProd || !lpth->thp.fMoved)) {
            /* asm: 10b0:1c7a..1cf4 — mineral packet movement */

            /* asm: 10b0:1ccd..1cf4 — check packet has minerals */
            if (lpth->thp.rgwtMin[0] == 0 && lpth->thp.rgwtMin[1] == 0 && lpth->thp.rgwtMin[2] == 0) {
                goto LFreeThePacket; /* asm: 10b0:1cf4 */
            }

            /* asm: 10b0:1cf7..1d07 — set fMoved, clear fInclude, keep fMoved=1 */
            lpth->thp.wRaw_0000 = (lpth->thp.wRaw_0000 & 0xbfff) | 0x4000;

            /* asm: 10b0:1d0b — fAnythingMoved = 1 */
            fAnythingMoved = 1;

            /* asm: 10b0:1d10..1d2b — compute dRange = (iWarp + 4)^2 */
            dRange = lpth->thp.iWarp + 4;
            dRange = dRange * dRange;

            /* asm: 10b0:1d2e..1d3a — if postProd, halve range */
            if (fPostProd)
                dRange >>= 1;

            /* asm: 10b0:1d3d..1d57 — get destination from planet coords */
            ptDst.x = rgptPlan[lpth->thp.idPlanet].x;
            ptDst.y = rgptPlan[lpth->thp.idPlanet].y;

        MoveTh: /* asm: 10b0:1d5a */
            /* asm: 10b0:1d5a..1d68 — save source position */
            ptSrc.x = lpth->pt.x;
            ptSrc.y = lpth->pt.y;

            /* asm: 10b0:1d6b..1d88 — compute distance */
            d = DGetDistance(ptSrc.x, ptSrc.y, ptDst.x, ptDst.y);

            /* asm: 10b0:1d8b..1d9e — check if in range */
            if ((int16_t)d <= dRange) {
                goto MadeItThere; /* asm: 10b0:1da0 */
            }

            /* asm: 10b0:2d93..2e97 — partial movement */
            {
                /* asm: 10b0:2d93..2daf — compute dxRound */
                dxRound = (ptDst.x > ptSrc.x) ? 0.5 : -0.5;
                /* asm: 10b0:2db5..2dd1 — compute dyRound */
                dyRound = (ptDst.y > ptSrc.y) ? 0.5 : -0.5;

                /* asm: 10b0:2dd7..2dfe — check if distance is essentially zero */
                if (d > 0.0001 || d < -0.0001) {
                    /* asm: 10b0:2e01..2e6a — interpolate position */
                    r = (double)dRange / d;
                    ptSrc.x = (int16_t)((double)(ptDst.x - ptSrc.x) * r + dxRound) + ptSrc.x;
                    ptSrc.y = (int16_t)((double)(ptDst.y - ptSrc.y) * r + dyRound) + ptSrc.y;

                    /* asm: 10b0:2e6d..2e83 — check if we arrived exactly */
                    if (ptSrc.x == ptDst.x && ptSrc.y == ptDst.y)
                        goto MadeItThere;

                    /* asm: 10b0:2e86..2e93 — update thing position */
                    lpth->pt.x = ptSrc.x;
                    lpth->pt.y = ptSrc.y;
                }

                /* asm: 10b0:2e97..2ed0 — post-prod packet decay */
                if (fPostProd && lpth->ith == ithMineralPacket) {
                    if (FPacketDecay(lpth, 50))
                        goto LPacketAlreadyFreed;
                }
            }
            goto LNext; /* asm: 10b0:2ed3 */

        MadeItThere: /* asm: 10b0:1da3 */
            /* asm: 10b0:1da3..1db6 — check if trader */
            if (lpth->ith == ithMysteryTrader) {
                /* asm: 10b0:1db9..1e4f — trader arrived: look for other traders */
                lpth2 = lpThings;
                lpth2Mac = lpThings + cThing;
                while (lpth2 < lpth2Mac) {
                    /* asm: 10b0:1de4..1e0d — find another trader (not self) */
                    if (lpth2->ith == 3 && lpth2 != lpth)
                        break;
                    lpth2++;
                }
                /* asm: 10b0:1e25..1e4c — if no other traders, 50% chance stay */
                if (lpth2 >= lpth2Mac) {
                    if (Random(2) != 0)
                        break; /* break from if chain to LNext — but actually this should continue the outer for loop... hmm */
                }
                goto LFreeThePacket; /* asm: 10b0:1e4f */
            }

            /* asm: 10b0:1e91..1f00 — packet arrived: decay check */
            if (lpth->ith == ithMineralPacket) {
                /* asm: 10b0:1ea7..1ef5 — compute pctRate and decay */
                pctRate = MulDiv((int16_t)d, 100, dRange);
                if (pctRate < 0)
                    pctRate = 0;
                else if (pctRate > 100)
                    pctRate = 100;
                if (fPostProd)
                    pctRate >>= 1;
                if (FPacketDecay(lpth, pctRate))
                    goto LPacketAlreadyFreed;
            }

            /* asm: 10b0:1f03..1f1f — get target planet */
            lppl = &lpPlanets[lpth->thp.idPlanet];

            /* asm: 10b0:1f22..1f34 — compute iWarpPacket */
            iWarpPacket = lpth->thp.iWarp + 4;

            /* asm: 10b0:1f37..1f49 — get MA warp */
            iWarp = IWarpMAFromLppl(lppl, &fTwoMAsB);
            fTwoMAs = fTwoMAsB;

            /* asm: 10b0:1f4c..1f55 — add 1 if two MAs */
            if (fTwoMAs)
                iWarp++;

            /* asm: 10b0:1f59..1fd6 — if MA present, mark starbase as catching */
            if (iWarp > 0) {
                /* asm: 10b0:1f62..1f8c — check if packet owner has raMassAccel */
                if (GetRaceStat(&rgplr[lpth->iplr], rsMajorAdv) == raMassAccel) {
                    /* asm: 10b0:1f8f..1fd2 — mark starbase grbitPlr */
                    uint16_t grbit = 1 << lpth->iplr;
                    rglpshdefSB[lppl->iPlayer][lppl->isb].grbitPlr |= grbit;
                }
            }

            /* asm: 10b0:1fd7..200d — fTerra = packet owner has raMassAccel? */
            fTerra = (GetRaceStat(&rgplr[lpth->iplr], rsMajorAdv) == raMassAccel) ? 1 : 0;

            /* asm: 10b0:2010..201f — compute iWarp2 and iWarpPacket2 */
            iWarp2 = iWarp * iWarp;
            iWarpPacket2 = iWarpPacket * iWarpPacket;

            /* asm: 10b0:2022..204f — if target planet owner has raStargate, halve iWarp2 */
            if (GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) == raStargate)
                iWarp2 /= 2;

            /* asm: 10b0:2052..2097 — compute pctCaught */
            if (iWarp2 >= iWarpPacket2) {
                pctCaught = 1000; /* asm: 10b0:205d */
            } else if (iWarp > 0) {
                /* asm: 10b0:206e..2094 */
                pctCaught = (int16_t)((uint32_t)iWarp2 * 1000 / (uint32_t)iWarpPacket2);
            } else {
                pctCaught = 0; /* asm: 10b0:209a */
            }

            /* asm: 10b0:209f..20a5 — pctMinKeep = 1000 - pctCaught */
            pctMinKeep = 1000 - pctCaught;

            /* asm: 10b0:20a8..20f4 — compute rgwtTerra[i] = minerals lost in transit */
            for (i = 0; i < 3; i++) {
                rgwtTerra[i] = (int16_t)((uint32_t)lpth->thp.rgwtMin[i] * (uint32_t)pctMinKeep / 1000);
            }

            /* asm: 10b0:20fd..210c — compute effective pctMinKeep for deposit */
            pctMinKeep = pctCaught + (1000 - pctCaught) / 9;

            /* asm: 10b0:210f..21ca — deposit minerals and accumulate wtTot */
            wtTot = 0;
            for (i = 0; i < 3; i++) {
                /* asm: 10b0:2121..213e — clamp negative minerals to 0 */
                if (lpth->thp.rgwtMin[i] < 0)
                    lpth->thp.rgwtMin[i] = 0;

                /* asm: 10b0:2157..2172 — accumulate wtTot */
                wtTot += (uint16_t)lpth->thp.rgwtMin[i];

                /* asm: 10b0:2175..21c2 — deposit minerals to planet */
                lppl->rgwtMin[i] += (int32_t)((uint32_t)lpth->thp.rgwtMin[i] * (uint32_t)pctMinKeep / 1000);
            }

            /* asm: 10b0:21d3..21dd — if all caught, goto LAllSafe */
            if (pctCaught == 1000)
                goto LAllSafe;

            /* asm: 10b0:21e0..2209 — compute raw damage */
            dmgRaw = (int32_t)((uint32_t)(iWarpPacket * iWarpPacket - iWarp2) * (uint32_t)wtTot / 160);

            /* asm: 10b0:220c..2212 — if sender has raMassAccel, do terraforming */
            if (fTerra) {
                /* asm: 10b0:2215..2223 — get packet owner iplr */
                iplr = lpth->iplr;

                /* asm: 10b0:2226..28d2 — terraforming loop for each mineral */
                for (i = 0; i < 3; i++) {
                    /* asm: 10b0:222e..2233 — init counters */
                    cTerraTemp = 0;
                    cTerraPerm = 0;

                    /* asm: 10b0:2238..22ae — accumulate terra hits per 100 mineral units */
                    while (rgwtTerra[i] > 0) {
                        /* asm: 10b0:224a..226e — wtCur = min(rgwtTerra[i], 100) */
                        wtCur = (rgwtTerra[i] < 100) ? rgwtTerra[i] : 100;

                        /* asm: 10b0:2271..2282 — Random(200) < wtCur? */
                        if (Random(200) < wtCur) {
                            cTerraTemp++; /* asm: 10b0:2285 */
                            /* asm: 10b0:2289..229d — 1/10 chance of permanent */
                            if (Random(10) == 0)
                                cTerraPerm++;
                        }
                        /* asm: 10b0:22a1..22ae — subtract 100 from remaining */
                        rgwtTerra[i] -= 100;
                    }

                    /* asm: 10b0:22b1..2506 — permanent terraforming */
                    if (cTerraPerm > 0) {
                        /* asm: 10b0:22ba..22d5 — check if race is immune to this env */
                        if (rgplr[iplr].rgEnvVarMin[i] < 0) {
                            /* asm: 10b0:22da..233d — immune race: clamp to orig limits */
                            if (lppl->rgEnvVarOrig[i] < 50) {
                                if (cTerraPerm >= lppl->rgEnvVarOrig[i] - 1)
                                    cTerraPerm = lppl->rgEnvVarOrig[i] - 1;
                                cTerraPerm = -cTerraPerm;
                            } else {
                                if (cTerraPerm >= 99 - lppl->rgEnvVarOrig[i])
                                    cTerraPerm = 99 - lppl->rgEnvVarOrig[i];
                            }
                        } else if (lppl->rgEnvVarOrig[i] < rgplr[iplr].rgEnvVar[i]) {
                            /* asm: 10b0:238c..243e — orig below ideal center */
                            int16_t newVal = lppl->rgEnvVarOrig[i] + cTerraPerm;
                            if (newVal > rgplr[iplr].rgEnvVar[i]) {
                                cTerraPerm = rgplr[iplr].rgEnvVar[i] - lppl->rgEnvVarOrig[i];
                            }
                        } else if (lppl->rgEnvVarOrig[i] > rgplr[iplr].rgEnvVar[i]) {
                            /* asm: 10b0:2441..24fe — orig above ideal center */
                            int16_t newVal = lppl->rgEnvVarOrig[i] - cTerraPerm;
                            if (newVal < rgplr[iplr].rgEnvVar[i]) {
                                cTerraPerm = rgplr[iplr].rgEnvVar[i] - lppl->rgEnvVarOrig[i];
                            } else {
                                cTerraPerm = -cTerraPerm;
                            }
                        } else {
                            /* asm: 10b0:2501 — exactly at ideal, no change */
                            cTerraPerm = 0;
                        }

                        /* asm: 10b0:2506..25d2 — send permanent terraform message */
                        if (cTerraPerm != 0) {
                            FSendPlrMsg(iplr, idmMineralPacketHasPermanentlyDefault, lppl->id, (cTerraPerm > 0) ? 1 : 0, i, lppl->id, abs(cTerraPerm), 0, 0, 0);
                            /* asm: 10b0:2558..25ba — send to planet owner too if different */
                            if (lppl->iPlayer != -1 && lppl->iPlayer != iplr) {
                                FSendPlrMsg(iplr, idmMineralPacketHasPermanentlyDefault2, lppl->id, (cTerraPerm > 0) ? 1 : 0, i, lppl->id, abs(cTerraPerm), 0,
                                            0, 0);
                            }
                            /* asm: 10b0:25bd..25d2 — apply permanent change */
                            lppl->rgEnvVarOrig[i] += (int8_t)cTerraPerm;
                        }
                    }

                    /* asm: 10b0:25d5..28ce — temporary terraforming */
                    if (cTerraTemp > 0) {
                        /* asm: 10b0:25de..25ff — FCanTerraformLppl */
                        idPlayer = iplr;
                        if (!FCanTerraformLppl(lppl, rgMin, rgMax, rgCost, 1)) {
                            /* asm: 10b0:260a */
                            idPlayer = -1;
                        } else {
                            /* asm: 10b0:2613 */
                            idPlayer = -1;

                            /* asm: 10b0:2619..2634 — check if immune */
                            if (rgplr[iplr].rgEnvVarMin[i] < 0) {
                                /* asm: 10b0:2639..26f4 — immune: halve and clamp */
                                cTerraTemp /= 2;
                                if (lppl->rgEnvVar[i] < 50) {
                                    if (cTerraTemp >= lppl->rgEnvVar[i] - 1)
                                        cTerraTemp = lppl->rgEnvVar[i] - 1;
                                    cTerraTemp = -cTerraTemp;
                                } else {
                                    if (cTerraTemp >= 99 - lppl->rgEnvVar[i])
                                        cTerraTemp = 99 - lppl->rgEnvVar[i];
                                }
                            } else if (rgMin[i] == -1) {
                                /* asm: 10b0:26f7..27cd — no min limit, use max */
                                if (rgMax[i] == -1) {
                                    cTerraTemp = 0;
                                } else if (cTerraTemp > rgMax[i] - lppl->rgEnvVar[i]) {
                                    cTerraTemp = rgMax[i] - lppl->rgEnvVar[i];
                                }
                            } else {
                                /* asm: 10b0:2709..2765 — has min limit */
                                if (cTerraTemp > lppl->rgEnvVar[i] - rgMin[i]) {
                                    cTerraTemp = rgMin[i] - lppl->rgEnvVar[i];
                                } else {
                                    cTerraTemp = -cTerraTemp;
                                }
                            }

                            /* asm: 10b0:27d5..28ce — send temp terraform message */
                            if (cTerraTemp != 0) {
                                lppl->rgEnvVar[i] += (int8_t)cTerraTemp;
                                FSendPlrMsg(iplr, idmMineralPacketHas, lppl->id, (cTerraTemp > 0) ? 1 : 0, i, lppl->id,
                                            (i << 8) | (int16_t)(uint8_t)lppl->rgEnvVar[i], 0, 0, 0);
                                /* asm: 10b0:2854..28cb — send to planet owner too */
                                if (lppl->iPlayer != -1 && lppl->iPlayer != iplr) {
                                    FSendPlrMsg(iplr, idmMineralPacketHas2, lppl->id, (cTerraTemp > 0) ? 1 : 0, i, lppl->id,
                                                (i << 8) | (int16_t)(uint8_t)lppl->rgEnvVar[i], 0, 0, 0);
                                }
                            }
                        }
                    }
                } /* end for i (terraforming) */
            } /* end if fTerra */

            /* asm: 10b0:28db..294d — check if planet is inhabited */
            if (lppl->iPlayer != -1) {
                /* asm: 10b0:28eb..28fe — calc survival percentage */
                CalcPctSurvive(lppl, &pct, NULL);

                /* asm: 10b0:2901..291a — scale dmgRaw by pct */
                dmgRaw = (int32_t)((double)dmgRaw * pct);

                if (dmgRaw != 0) {
                    /* asm: 10b0:292c..294d — check if planet owner is AR race */
                    if (GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) != raMacintosh) {
                        /* asm: 10b0:29b8..29c6 — get current colonist population */
                        lColKilled = lppl->rgwtMin[3];

                        /* asm: 10b0:29c9..29d8 — check if planet has colonists */
                        if (lColKilled == 0) {
                            /* asm: 10b0:2d1a..2d64 — no colonists, message and set counts */
                            FSendPlrMsg2(lppl->iPlayer, idmBombardedKtMineralPacketFortunatelyOneHome, lppl->id, lppl->id, lpth->iplr);
                            lDefKilled = lppl->cDefenses;
                            lColKilled = 0;
                        } else {
                            /* asm: 10b0:29db..2a25 — scale colonist kill by population */
                            lColKilled = (int32_t)((uint32_t)lColKilled * (uint32_t)dmgRaw / 1000);
                            if (lColKilled < dmgRaw)
                                lColKilled = dmgRaw;

                            /* asm: 10b0:2a28..2ab7 — check if all colonists killed */
                            if (lppl->rgwtMin[3] > 0 && lColKilled >= lppl->rgwtMin[3]) {
                                FSendPlrMsg2(lppl->iPlayer, idmAnnihilatedMineralPacketColonistsKilled, lppl->id, lppl->id, lpth->iplr);
                                UninhabitPlanet(lppl);
                                goto LFreeThePacket;
                            }
                            if (lppl->rgwtMin[3] <= 0 && lColKilled > 0) {
                                FSendPlrMsg2(lppl->iPlayer, idmAnnihilatedMineralPacketColonistsKilled, lppl->id, lppl->id, lpth->iplr);
                                UninhabitPlanet(lppl);
                                goto LFreeThePacket;
                            }

                            /* asm: 10b0:2aba..2ae7 — compute defense kills */
                            lDefKilled = (int32_t)((uint32_t)lppl->cDefenses * (uint32_t)dmgRaw / 1000);

                            /* asm: 10b0:2aed..2b50 — if no defenses killed, random chance */
                            if (lDefKilled == 0 && lppl->cDefenses != 0) {
                                lDefKilled = (Random(20) < dmgRaw) ? 1 : 0;
                            }

                            /* asm: 10b0:2b53..2b91 — minimum defense kill = dmgRaw/20 */
                            if (lDefKilled < dmgRaw / 20)
                                lDefKilled = dmgRaw / 20;

                            /* asm: 10b0:2b94..2bce — cap to actual defenses */
                            if (lDefKilled > (int32_t)lppl->cDefenses)
                                lDefKilled = lppl->cDefenses;

                            /* asm: 10b0:2bd1..2d13 — send damage message */
                            if (lDefKilled == 0) {
                                /* asm: 10b0:2be3..2c50 — no defenses destroyed */
                                idm = fTerra ? idmMassAcceleratorPartiallySuccessfullyCapturingKtM : idmBombardedKtMineralPacketColonistsKilledCollision;
                                FSendPlrMsg(lppl->iPlayer, idm, lppl->id, lppl->id, (int16_t)(wtTot & 0xFFFF), (int16_t)(wtTot >> 16), lpth->iplr,
                                            (int16_t)lColKilled, 0, 0);
                            } else {
                                /* asm: 10b0:2c53..2d13 — defenses destroyed */
                                idm = fTerra ? idmMassAcceleratorPartiallySuccessfullyCapturingKtM2 : idmBombardedKtMineralPacketColonistsDefensesDestroy;
                                FSendPlrMsg(lppl->iPlayer, idm, lppl->id, lppl->id, (int16_t)(wtTot & 0xFFFF), (int16_t)(wtTot >> 16), lpth->iplr,
                                            (int16_t)lColKilled, (int16_t)lDefKilled, 0);
                                /* asm: 10b0:2cc3..2d13 — reduce planet defenses */
                                lppl->cDefenses -= (uint16_t)lDefKilled;
                            }
                        }

                        /* asm: 10b0:2d69..2d76 — reduce planet population */
                        lppl->rgwtMin[3] -= lColKilled;
                        goto LFreeThePacket; /* asm: 10b0:2d7a */
                    }
                }
                goto LAllSafe; /* asm: 10b0:2929/294b */
            }

            goto LFreeThePacket; /* asm: 10b0:28e8 */

        LAllSafe: /* asm: 10b0:2950 */
            /* asm: 10b0:2950..29b5 — all safe message */
            FSendPlrMsg(lppl->iPlayer, (iWarp > 0) ? idmMassAcceleratorHasSuccessfullyCapturedPacketCont : idmBombardedPacketContainingKtMineralsHoweverPacket,
                        lppl->id, lppl->id, lpth->iplr, (int16_t)(wtTot & 0xFFFF), (int16_t)(wtTot >> 16), 0, 0, 0);
            /* fall through to LFreeThePacket */

        LFreeThePacket: /* asm: 10b0:2d7a */
            FreeLpth(lpth);

        LPacketAlreadyFreed: /* asm: 10b0:2d88 */
            /* asm: 10b0:2d88..2d90 — back up pointers since thing was removed */
            lpth--;
            lpthMac--;
        } else {
            /* asm: 10b0:1ca7/1cca — not a movable thing, skip */
        }

    LNext: /* asm: 10b0:2ed3 */
        lpth++;
    }
}
