
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "globals.h"
#include "port.h"
#include "strings.h"
#include "types.h"

#include "file.h"
#include "log.h"
#include "mdi.h"
#include "utilgen.h"

#include "dump.h"

/* ------------------------------------------------------------------------- */
/* Debug/diagnostic block dump helpers                                       */
/* ------------------------------------------------------------------------- */

static DtFileType DumpGetFileType(const char *szPath) {
    const char *dot = strrchr(szPath, '.');
    if (dot == NULL)
        return dtXY; /* default fallback */

    dot++; /* skip the dot */

    /* Case-insensitive extension check */
    if (Stars_strnicmp(dot, "xy", 2) == 0)
        return dtXY;
    if (Stars_strnicmp(dot, "hst", 3) == 0)
        return dtHost;
    if (tolower((unsigned char)dot[0]) == 'm' && isdigit((unsigned char)dot[1]))
        return dtTurn;
    if (tolower((unsigned char)dot[0]) == 'h' && isdigit((unsigned char)dot[1]))
        return dtHist;
    if (tolower((unsigned char)dot[0]) == 'x' && isdigit((unsigned char)dot[1]))
        return dtLog;

    return dtXY; /* fallback */
}

/* Log header record type (value 9) - not in RecordType enum */
#define rtLogHdr 9

static const char *DumpRecordTypeName(RecordType rt, DtFileType dt) {
    switch (rt) {
    case rtEOF:
        return "FileFooter";
    case rtLogCargoXfer8:
        return "LogCargoXfer8";
    case rtLogCargoXfer16:
        return "LogCargoXfer16";
    case rtLogFleetOrderDelete:
        return "LogFleetOrderDelete";
    case rtLogFleetOrderInsert:
        return "LogFleetOrderInsert";
    case rtLogFleetOrderUpdate:
        return "LogFleetOrderUpdate";
    case rtPlr:
        return "Player";
    case rtGame:
        return "Game";
    case rtBOF:
        return "FileHeader";
    case rtLogHdr:
        return "LogHeader";
    case rtLogFleetFlagBit9:
        return "LogFleetFlagBit9";
    case rtLogFleetOrderAttrNib:
        return "LogFleetOrderAttrNib";
    case rtMsg:
        return "Message";
    case rtPlanet:
        return "Planet";
    case rtPlanetB:
        return "PlanetB";
    case rtFleetA:
        return "FleetA";
    case rtOrderA:
        return "OrderA";
    case rtOrderB:
        return "Waypoint";
    case rtString:
        return "String";
    case rtSel:
        return "Selection";
    case rtLogFleetCargoXfer:
        return "LogFleetCargoXfer";
    case rtLogFleetSplit:
        return "LogFleetSplit";
    case rtLogCargoXfer32:
        return "LogCargoXfer32";
    case rtShDef:
        return "Ship Definition";
    case rtLogShDef:
        return "LogShDef";
    case rtProdQ:
        return "Production Queue";
    case rtLogPlanetProdQ:
        return "LogPlanetProdQ";
    case rtBtlPlan:
        return (dt == dtLog) ? "LogBattlePlan" : "BattlePlan";
    case rtBtlData:
        return "BattleData";
    case rtHistHdr:
        return "HistHeader";
    case rtMsgFilt:
        return "MsgFilter";
    case rtLogResearch:
        return "LogResearch";
    case rtLogPlanetRouting:
        return "LogPlanetRouting";
    case rtChgPassword:
        return (dt == dtLog) ? "LogPlayerSalt" : "ChgPassword";
    case rtLogFleetMerge:
        return "LogFleetMerge";
    case rtLogRelations:
        return "LogRelations";
    case rtContinue:
        return "Continue";
    case rtPlrMsg:
        return "PlayerMsg";
    case rtAiData:
        return "AiData";
    case rtLogFleetPlan:
        return "LogFleetPlan";
    case rtThing: /* also rtLogThingByteParam in log context */
        return (dt == dtLog) ? "LogThingByteParam" : "Thing";
    case rtLogFleetName:
        return "LogFleetName";
    case rtScore:
        return "Score";
    case rtLogPlayerZpq1:
        return "LogPlayerZpq1";
    default:
        return "Unknown";
    }
}

static void DumpPrintHexBytes(const uint8_t *pb, size_t cb) {
    for (size_t i = 0; i < cb; i++) {
        printf("%02x", (unsigned)pb[i]);
    }
}

static uint16_t rd_u16(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int16_t rd_i16(const uint8_t *p) {
    int16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint32_t rd_u32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int32_t rd_i32(const uint8_t *p) {
    int32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static const char *grobj_name(int grobj) {
    /* Best-effort names; the numeric values are still printed. */
    switch (grobj) {
    case 0:
        return "planet";
    case 1:
        return "fleet";
    case 2:
        return "starbase";
    case 3:
        return "thing";
    default:
        return "?";
    }
}

static void DumpVerbose_Player(const uint8_t *pb, uint16_t cb) {
    PLAYER p;
    memset(&p, 0, sizeof(p));

    if (pb == NULL) {
        printf("  (null payload)\n");
        return;
    }

    if (cb > sizeof(p))
        cb = (uint16_t)sizeof(p);
    memcpy(&p, pb, cb);

    printf("  iPlayer=%d  det=%u  ai=%d lvlAi=%u idAi=%u\n", (int)p.iPlayer, (unsigned)p.det, (int)p.fAi, (unsigned)p.lvlAi, (unsigned)p.idAi);
    printf("  counts: planets=%u fleets=%u shdef=%u sb=%u\n", (unsigned)(uint16_t)p.cPlanet, (unsigned)p.cFleet, (unsigned)(uint8_t)p.cShDef,
           (unsigned)p.cshdefSB);
    if (cb >= (uint16_t)offsetof(PLAYER, szName)) {
        printf("  name=\"%s\" plural=\"%s\"\n", (p.szName[0] ? p.szName : ""), (p.szNames[0] ? p.szNames : ""));
    }
    if (cb >= (uint16_t)offsetof(PLAYER, rgTech) + 6) {
        printf("  tech: [%d,%d,%d,%d,%d,%d]  pctResearch=%d iTechCur=%d\n", (int)p.rgTech[0], (int)p.rgTech[1], (int)p.rgTech[2], (int)p.rgTech[3],
               (int)p.rgTech[4], (int)p.rgTech[5], (int)p.pctResearch, (int)p.iTechCur);
    }
}

/* ------------------------------------------------------------------------- */
/* Public structured dumps (from already-loaded GAME/PLAYER structs)          */
/* ------------------------------------------------------------------------- */

void DumpGameStruct(const GAME *g) {
    if (g == NULL) {
        printf("Game: (null)\n");
        return;
    }

    printf("Game\n");
    printf("  lid=%" PRIu32 "\n", (uint32_t)g->lid);
    printf("  turn=%u (year %u)\n", (unsigned)g->turn, (unsigned)(2400u + (uint16_t)g->turn));
    printf("  name=\"%s\"\n", (g->szName[0] ? g->szName : ""));

    printf("  galaxy: size=%d density=%d startDist=%d planMax=%d\n", (int)g->mdSize, (int)g->mdDensity, (int)g->mdStartDist, (int)g->cPlanMax);
    printf("  players=%d\n", (int)g->cPlayer);
    printf("  fDirty=%d\n", (int)g->fDirty);

    printf("  flags:\n");
    printf("    tutorial=%d single=%d slowtech=%d extrafuel=%d visiblescores=%d norandom=%d clumping=%d\n", (int)g->fTutorial, (int)g->fSinglePlr,
           (int)g->fSlowTech, (int)g->fExtraFuel, (int)g->fVisScores, (int)g->fNoRandom, (int)g->fClumping);
    printf("    aisband=%d bbsplay=%d wGen=%u\n", (int)g->fAisBand, (int)g->fBBSPlay, (unsigned)g->wGen);

    printf("  rgvc: ");
    DumpPrintHexBytes(g->rgvc, sizeof(g->rgvc));
    printf("\n");
}

void DumpPlayerStruct(const PLAYER *p) {
    if (p == NULL) {
        printf("Player: (null)\n");
        return;
    }

    printf("    iPlayer=%d\n", (int)p->iPlayer);
    printf("    name=\"%s\" plural=\"%s\"\n", (p->szName[0] ? p->szName : ""), (p->szNames[0] ? p->szNames : ""));

    printf("    counts: planets=%u fleets=%u shdef=%u sb=%u\n", (unsigned)(uint16_t)p->cPlanet, (unsigned)p->cFleet, (unsigned)(uint8_t)p->cShDef,
           (unsigned)p->cshdefSB);

    printf("    vis: det=%u include=%d mdPlayer=%u iPlrBmp=%u\n", (unsigned)p->det, (int)p->fInclude, (unsigned)p->mdPlayer, (unsigned)p->iPlrBmp);
    printf("    ai: fAi=%d lvlAi=%u idAi=%u\n", (int)p->fAi, (unsigned)p->lvlAi, (unsigned)p->idAi);

    printf("    home: idPlanetHome=%d\n", (int)p->idPlanetHome);
    printf("    score: wScore=%u\n", (unsigned)p->wScore);
    printf("    salt: lSalt=%" PRId32 "\n", (int32_t)p->lSalt);

    printf("    env: cur=[%d,%d,%d] min=[%d,%d,%d] max=[%d,%d,%d] idealGrowth=%d\n", (int)p->rgEnvVar[0], (int)p->rgEnvVar[1], (int)p->rgEnvVar[2],
           (int)p->rgEnvVarMin[0], (int)p->rgEnvVarMin[1], (int)p->rgEnvVarMin[2], (int)p->rgEnvVarMax[0], (int)p->rgEnvVarMax[1], (int)p->rgEnvVarMax[2],
           (int)p->pctIdealGrowth);

    printf("    tech: lvl=[%d,%d,%d,%d,%d,%d] pctResearch=%d iTechCur=%d\n", (int)p->rgTech[0], (int)p->rgTech[1], (int)p->rgTech[2], (int)p->rgTech[3],
           (int)p->rgTech[4], (int)p->rgTech[5], (int)p->pctResearch, (int)p->iTechCur);

    printf("    resSpent: [");
    for (int i = 0; i < 6; i++) {
        if (i)
            printf(",");
        printf("%" PRIu32, (uint32_t)p->rgResSpent[i]);
    }
    printf("]\n");
    printf("    lResLastYear=%" PRId32 "\n", (int32_t)p->lResLastYear);

    printf("    attr: ");
    for (int i = 0; i < 16; i++) {
        if (i)
            printf(" ");
        printf("%d", (int)p->rgAttr[i]);
    }
    printf("\n");
    printf("    grbitAttr=0x%08" PRIx32 " grbitTrader=0x%04x\n", (uint32_t)p->grbitAttr, (unsigned)p->grbitTrader);
    printf("    flags: dead=%d crippled=%d cheater=%d learned=%d hacker=%d (raw=0x%04x)\n", (int)p->fDead, (int)p->fCrippled, (int)p->fCheater,
           (int)p->fLearned, (int)p->fHacker, (unsigned)p->wFlags);

    printf("    relations (mdRelation[0..15]):");
    for (int i = 0; i < 16; i++) {
        printf(" %u", (unsigned)p->rgmdRelation[i]);
    }
    printf("\n");
}

static void DumpVerbose_Game(const uint8_t *pb, uint16_t cb) {
    GAME g;
    memset(&g, 0, sizeof(g));
    if (pb == NULL) {
        printf("  (null payload)\n");
        return;
    }
    if (cb > sizeof(g))
        cb = (uint16_t)sizeof(g);
    memcpy(&g, pb, cb);

    printf("  lid=%" PRIu32 "  turn=%u (year %u)\n", (uint32_t)g.lid, (unsigned)g.turn, (unsigned)(2400u + (uint16_t)g.turn));
    printf("  players=%d  planMax=%d  size=%d  density=%d  startDist=%d\n", (int)g.cPlayer, (int)g.cPlanMax, (int)g.mdSize, (int)g.mdDensity,
           (int)g.mdStartDist);
    printf("  flags: tutorial=%d single=%d slowtech=%d extrafuel=%d visiblescores=%d norandom=%d clumping=%d\n", (int)g.fTutorial, (int)g.fSinglePlr,
           (int)g.fSlowTech, (int)g.fExtraFuel, (int)g.fVisScores, (int)g.fNoRandom, (int)g.fClumping);
    if (cb >= (uint16_t)offsetof(GAME, szName)) {
        printf("  name=\"%s\"\n", (g.szName[0] ? g.szName : ""));
    }
}

static void DumpVerbose_Message(const uint8_t *pb, uint16_t cb) {
    if (pb == NULL || cb == 0) {
        printf("  (empty message payload)\n");
        return;
    }

    if (cb >= sizeof(MSGHDR)) {
        MSGHDR mh;
        memcpy(&mh, pb, sizeof(mh));
        printf("  msghdr: iMsg=%u grWord=0x%02x wGoto=%d\n", (unsigned)mh.iMsg, (unsigned)mh.grWord, (int)mh.wGoto);
    }

    /* Many message records are MSGBIG: fixed header plus params. */
    if (cb >= sizeof(MSGBIG)) {
        MSGBIG mb;
        memcpy(&mb, pb, sizeof(mb));
        printf("  msgbig: iMsg=%d wGoto=%d params=[%d,%d,%d,%d,%d,%d,%d]\n", (int)mb.iMsg, (int)mb.wGoto, (int)mb.rgParam[0], (int)mb.rgParam[1],
               (int)mb.rgParam[2], (int)mb.rgParam[3], (int)mb.rgParam[4], (int)mb.rgParam[5], (int)mb.rgParam[6]);
    }
}

static void DumpVerbose_LogRtCargoXfer(RecordType rt, const uint8_t *pb, uint16_t cb) {
    /* Base layout: id1,u16 id2,u16 grobjnibble,u8 grbitItems,u8 then quantities. */
    uint16_t id1, id2;
    uint8_t  grobjnib;
    uint8_t  grbitItems;

    if (pb == NULL || cb < 6) {
        printf("  (short payload)\n");
        return;
    }

    id1 = rd_u16(pb + 0);
    id2 = rd_u16(pb + 2);
    grobjnib = pb[4];
    grbitItems = pb[5];

    printf("  xfer: %s(%u) -> %s(%u)  grbitItems=0x%02x\n", grobj_name(grobjnib & 0xF), (unsigned)id1, grobj_name((grobjnib >> 4) & 0xF), (unsigned)id2,
           (unsigned)grbitItems);

    printf("  items:");
    size_t off = 6;
    for (int i = 0; i < 5; i++) {
        if (((grbitItems >> i) & 1u) == 0)
            continue;

        if (rt == rtLogCargoXfer8) {
            if (off + 1 > cb)
                break;
            printf(" [%d]=%d", i, (int8_t)pb[off]);
            off += 1;
        } else if (rt == rtLogCargoXfer16) {
            if (off + 2 > cb)
                break;
            printf(" [%d]=%d", i, (int)rd_i16(pb + off));
            off += 2;
        } else {
            if (off + 4 > cb)
                break;
            printf(" [%d]=%" PRId32, i, (int32_t)rd_i32(pb + off));
            off += 4;
        }
    }
    printf("\n");
}

static void DumpVerbose_LogRtFleetName(const uint8_t *pb, uint16_t cb) {
    if (pb == NULL || cb < 4) {
        printf("  (short payload)\n");
        return;
    }

    if (cb == (uint16_t)sizeof(RTCHGNAME)) {
        RTCHGNAME rn;
        memcpy(&rn, pb, sizeof(rn));
        rn.rgb[32] = '\0';
        printf("  grobj=%d (%s) id=%d name=\"%s\"\n", (int)rn.grobj, grobj_name(rn.grobj), (int)rn.id, (char *)rn.rgb);
        return;
    }

    printf("  id=%d  (cb=%u; not RTCHGNAME)\n", (int)rd_i16(pb + 0), (unsigned)cb);
}

static void DumpVerbose_LogRecord(RecordType rt, const uint8_t *pb, uint16_t cb) {
    switch (rt) {
    case rtEOF:
        printf("  (nop)\n");
        break;
    case rtLogHdr:
        if (cb >= sizeof(RTLOGHDR)) {
            RTLOGHDR h;
            memcpy(&h, pb, sizeof(h));
            printf("  cbLog=%d serial=%" PRIu32 " config=", (int)h.cbLog, (uint32_t)h.lSerialNumber);
            DumpPrintHexBytes(h.rgbConfig, sizeof(h.rgbConfig));
            printf("\n");
        } else {
            printf("  (short log header)\n");
        }
        break;
    case rtLogCargoXfer8:
    case rtLogCargoXfer16:
    case rtLogCargoXfer32:
        DumpVerbose_LogRtCargoXfer(rt, pb, cb);
        break;
    case rtLogFleetName:
        DumpVerbose_LogRtFleetName(pb, cb);
        break;
    default:
        /* Many log record formats are not fully reverse-engineered yet. */
        if (pb != NULL && cb >= 2) {
            printf("  raw: ");
            DumpPrintHexBytes(pb, (cb <= 64u) ? cb : 64u);
            if (cb > 64u)
                printf("...");
            printf("\n");

            /* Provide a quick little-endian word view to help reverse-engineer. */
            printf("  u16:");
            for (uint16_t i = 0; i + 1 < cb && i < 16u; i += 2u) {
                uint16_t w = rd_u16(pb + i);
                printf(" %04x", (unsigned)w);
            }
            if (cb > 16u)
                printf(" ...");
            printf("\n");

            printf("  i16:");
            for (uint16_t i = 0; i + 1 < cb && i < 16u; i += 2u) {
                int16_t w = rd_i16(pb + i);
                printf(" %d", (int)w);
            }
            if (cb > 16u)
                printf(" ...");
            printf("\n");
        }
        break;
    }
}

void DumpPlanet(const PLANET *p) {
    STARSPOINT pt = {0, 0};

    if (p == NULL) {
        printf("Planet: (null)\n");
        return;
    }

    /* Get position from global rgptPlan if available */
    if (p->id >= 0 && p->id < (int16_t)(sizeof(rgptPlan) / sizeof(rgptPlan[0]))) {
        pt = rgptPlan[p->id];
    }

    printf("Planet %d\n", p->id);
    printf("  owner iPlayer: %d\n", p->iPlayer);
    printf("  pos: (%d,%d)\n", (int)pt.x, (int)pt.y);
    printf("  det: %u\n", (unsigned)p->det);
    printf("  turn: %d\n", (int)p->turn);

    /* Flags */
    printf("  flags: include=%d starbase=%d homeworld=%d firstyear=%d wasinhabited=%d artifact=%d noresearch=%d\n", (int)p->fInclude, (int)p->fStarbase,
           (int)p->fHomeworld, (int)p->fFirstYear, (int)p->fWasInhabited, (int)p->fArtifact, (int)p->fNoResearch);

    /* Environment */
    printf("  env cur:  grav=%d temp=%d rad=%d\n", (int)p->rgEnvVar[0], (int)p->rgEnvVar[1], (int)p->rgEnvVar[2]);
    printf("  env orig: grav=%d temp=%d rad=%d\n", (int)p->rgEnvVarOrig[0], (int)p->rgEnvVarOrig[1], (int)p->rgEnvVarOrig[2]);

    /* Mineral concentrations */
    printf("  mineral conc: iron=%d bor=%d ger=%d\n", (int)p->rgMinConc[0], (int)p->rgMinConc[1], (int)p->rgMinConc[2]);
    printf("  mineral lvl%%: iron=%d bor=%d ger=%d\n", (int)p->rgpctMinLevel[0], (int)p->rgpctMinLevel[1], (int)p->rgpctMinLevel[2]);

    /* Surface minerals */
    printf("  surface: iron=%" PRId32 " bor=%" PRId32 " ger=%" PRId32 " col=%" PRId32 "\n", p->rgwtMin[0], p->rgwtMin[1], p->rgwtMin[2], p->rgwtMin[3]);

    /* Population/defense guesses */
    printf("  guesses: pop=%u def=%u\n", (unsigned)p->uPopGuess, (unsigned)p->uDefGuess);

    /* Improvements */
    printf("  improvements: deltaPop=%u mines=%u factories=%u defenses=%u\n", (unsigned)p->iDeltaPop, (unsigned)p->cMines, (unsigned)p->cFactories,
           (unsigned)p->cDefenses);
    printf("  scanner: %u\n", (unsigned)p->iScanner);

    /* Starbase info */
    if (p->fStarbase) {
        printf("  starbase: isb=%u pctDp=%u\n", (unsigned)p->isb, (unsigned)p->pctDp);
    }

    /* Fling gate info */
    printf("  fling: idFling=%u iWarpFling=%u fNoHeal=%d\n", (unsigned)p->idFling, (unsigned)p->iWarpFling, (int)p->fNoHeal);

    /* Routing */
    printf("  routing: idRoute=%u\n", (unsigned)p->idRoute);

    /* Production queue */
    printf("  production queue: %s\n", p->lpplprod ? "present" : "none");
}

void DumpFleet(const FLEET *f) {
    if (f == NULL) {
        printf("Fleet: (null)\n");
        return;
    }

    printf("Fleet %d\n", f->id);
    printf("  id breakdown: ifl=%u iplr=%u\n", (unsigned)f->ifl, (unsigned)f->iplr);
    printf("  owner iPlayer: %d\n", f->iPlayer);
    printf("  pos: (%d,%d)\n", (int)f->pt.x, (int)f->pt.y);
    printf("  idPlanet: %d\n", (int)f->idPlanet);
    printf("  det: %u\n", (unsigned)f->det);

    /* Flags */
    printf("  flags: include=%d reporders=%d dead=%d done=%d bombed=%d hereAllTurn=%d noheal=%d mark=%d\n", (int)f->fInclude, (int)f->fRepOrders, (int)f->fDead,
           (int)f->fDone, (int)f->fBombed, (int)f->fHereAllTurn, (int)f->fNoHeal, (int)f->fMark);

    /* Orders */
    printf("  plan: %u  cord: %d  lpplord: %s\n", (unsigned)f->iplan, (int)f->cord, f->lpplord ? "present" : "none");

    /* Movement */
    printf("  move: left=%d used=%d fuel=%" PRId32 "\n", (int)f->dMoveLeft, (int)f->dMoveUsed, f->lFuelUsed);

    /* Direction */
    printf("  dir: iwarpFlt=%u dirValid=%d compChg=%d targeted=%d skipped=%d\n", (unsigned)f->iwarpFlt, (int)f->fdirValid, (int)f->fCompChg, (int)f->fTargeted,
           (int)f->fSkipped);
    printf("  dir xy: (%u,%u)\n", (unsigned)f->dirFltX, (unsigned)f->dirFltY);

    /* Ship counts */
    printf("  rgcsh:");
    int has_ships = 0;
    for (int i = 0; i < 16; i++) {
        if (f->rgcsh[i] != 0) {
            printf(" [%d]=%d", i, (int)f->rgcsh[i]);
            has_ships = 1;
        }
    }
    if (!has_ships)
        printf(" (none)");
    printf("\n");

    /* Damage values (when fleet is in combat context) */
    printf("  rgdv:");
    int has_dv = 0;
    for (int i = 0; i < 16; i++) {
        if (f->rgdv[i].dp != 0) {
            printf(" [%d]=%u", i, (unsigned)f->rgdv[i].dp);
            has_dv = 1;
        }
    }
    if (!has_dv)
        printf(" (none)");
    printf("\n");

    /* Cargo */
    printf("  cargo: iron=%" PRId32 " bor=%" PRId32 " ger=%" PRId32 " col=%" PRId32 " fuel=%" PRId32 "\n", f->rgwtMin[0], f->rgwtMin[1], f->rgwtMin[2],
           f->rgwtMin[3], f->rgwtMin[4]);

    /* Name */
    printf("  name: %s\n", (f->lpszName != NULL) ? f->lpszName : "(null)");

    /* Linked list */
    printf("  lpflNext: %s\n", f->lpflNext ? "present" : "none");
}

void DumpShDef(const SHDEF *s, int idx) {
    if (s == NULL) {
        printf("ShDef: (null)\n");
        return;
    }

    printf("ShDef[%d]\n", idx);

    /* Basic flags and identifiers */
    printf("  ishdef=%u det=%u include=%d free=%d gift=%d\n", (unsigned)s->ishdef, (unsigned)s->det, (int)s->fInclude, (int)s->fFree, (int)s->fGift);
    printf("  turn=%u wFlags=0x%04x\n", (unsigned)s->turn, (unsigned)s->wFlags);

    /* Build/existence stats */
    printf("  built=%" PRIu32 " exist=%" PRIu32 "\n", (uint32_t)s->cBuilt, (uint32_t)s->cExist);
    printf("  lPower=%" PRId32 " grbitPlr=0x%04x\n", (int32_t)s->lPower, (unsigned)s->grbitPlr);

    /* Scanner info */
    printf("  scan: range=%u range2=%u pctDetect=%u iSteal=%u\n", (unsigned)s->dScanRange, (unsigned)s->dScanRange2, (unsigned)s->pctDetect,
           (unsigned)s->iSteal);

    /* Hull info */
    printf("  hul.ihuldef=%d\n", (int)s->hul.ihuldef);
    printf("  hul.szClass: \"%s\"\n", s->hul.szClass);
    printf("  hul.rgTech: [%d,%d,%d,%d,%d,%d]\n", (int)s->hul.rgTech[0], (int)s->hul.rgTech[1], (int)s->hul.rgTech[2], (int)s->hul.rgTech[3],
           (int)s->hul.rgTech[4], (int)s->hul.rgTech[5]);
    printf("  hul.wtEmpty=%u hul.dp=%u\n", (unsigned)s->hul.wtEmpty, (unsigned)s->hul.dp);
    printf("  hul.costs: res=%u ore=(%u,%u,%u)\n", (unsigned)s->hul.resCost, (unsigned)s->hul.rgwtOreCost[0], (unsigned)s->hul.rgwtOreCost[1],
           (unsigned)s->hul.rgwtOreCost[2]);
    printf("  hul.ibmp=%d wtCargoMax=%u wtFuelMax=%u\n", (int)s->hul.ibmp, (unsigned)s->hul.wtCargoMax, (unsigned)s->hul.wtFuelMax);
    printf("  hul.chs=%u\n", (unsigned)s->hul.chs);

    /* Hull slots */
    printf("  hul.rghs:");
    int has_slots = 0;
    for (int i = 0; i < 16; i++) {
        if (s->hul.rghs[i].grhst != 0 || s->hul.rghs[i].iItem != 0 || s->hul.rghs[i].cItem != 0) {
            printf(" [%d]={grhst=%u,iItem=%u,cItem=%u}", i, (unsigned)s->hul.rghs[i].grhst, (unsigned)s->hul.rghs[i].iItem, (unsigned)s->hul.rghs[i].cItem);
            has_slots = 1;
        }
    }
    if (!has_slots)
        printf(" (none)");
    printf("\n");
}

static int64_t DumpFileSizeBytes(const char *path) {
    FILE *fp;
    long  end;

    if (path == NULL)
        return -1;

    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    end = ftell(fp);
    fclose(fp);
    return (end < 0) ? -1 : (int64_t)end;
}

int DumpGameFileBlocksEx(const char *szPath, bool fVerbose) {
    FILE      *fp;
    int64_t    sz;
    int        block_count = 0;
    uint8_t    hdr_buf[2];
    uint8_t    stack_buf[1024];
    uint8_t   *data_buf = stack_buf;
    uint16_t   rt, cb;
    DtFileType dt;

    if (szPath == NULL || szPath[0] == '\0') {
        fprintf(stderr, "DumpGameFileBlocks: missing path\n");
        return 2;
    }

    dt = DumpGetFileType(szPath);
    sz = DumpFileSizeBytes(szPath);

    fp = fopen(szPath, "rb");
    if (!fp) {
        fprintf(stderr, "DumpGameFileBlocks: cannot open '%s'\n", szPath);
        return 1;
    }

    printf("File: %s", szPath);
    if (sz >= 0)
        printf(" (%" PRId64 " bytes)", sz);
    printf("\n");

    /* Iterate through all blocks */
    while (fread(hdr_buf, 1, 2, fp) == 2) {
        /* Header is 2 bytes: lower 10 bits = cb (size), upper 6 bits = rt (type) */
        uint16_t hdr_word = (uint16_t)hdr_buf[0] | ((uint16_t)hdr_buf[1] << 8);
        cb = hdr_word & 0x3FF;        /* lower 10 bits */
        rt = (hdr_word >> 10) & 0x3F; /* upper 6 bits */

        const char *name = DumpRecordTypeName(rt, dt);
        printf("Block %d: %s (type=%u, size=%u)\n", block_count, name, (unsigned)rt, (unsigned)cb);

        /* Read the data payload */
        size_t actual = 0;
        if (cb > 0) {
            if (fVerbose && cb > sizeof(stack_buf)) {
                data_buf = (uint8_t *)malloc(cb);
                if (data_buf == NULL) {
                    fprintf(stderr, "DumpGameFileBlocks: OOM for cb=%u\n", (unsigned)cb);
                    fclose(fp);
                    return 1;
                }
                actual = fread(data_buf, 1, cb, fp);
            } else {
                size_t cb_read = (cb <= sizeof(stack_buf)) ? cb : sizeof(stack_buf);
                actual = fread(data_buf, 1, cb_read, fp);
                if (cb > cb_read)
                    fseek(fp, (long)(cb - cb_read), SEEK_CUR);
            }
        }

        /* Handle BOF specially - show file metadata */
        if (rt == rtBOF && actual >= sizeof(RTBOF)) {
            RTBOF bof;
            memcpy(&bof, data_buf, sizeof(bof));

            printf("  GameID: %" PRIu32 ", Turn: %u (Year %u), Player: %d\n", (uint32_t)bof.lidGame, (unsigned)bof.turn, (unsigned)(2400u + (uint16_t)bof.turn),
                   (int)bof.iPlayer);
            printf("  Version: %u.%u, Crippled: %d\n", (unsigned)bof.verMajor, (unsigned)bof.verMinor, (int)bof.fCrippled);
            if (fVerbose) {
                printf("  dt=%u  flags: done=%d inuse=%d multi=%d gameover=%d gen=%u\n", (unsigned)bof.dt, (int)bof.fDone, (int)bof.fInUse, (int)bof.fMulti,
                       (int)bof.fGameOverMan, (unsigned)bof.wGen);
            }
            printf("\n");
        } else if (fVerbose) {
            if (dt == dtLog && rt != rtEOF) {
                DumpVerbose_LogRecord(rt, data_buf, (uint16_t)actual);
                printf("\n");
            } else if (dt != dtLog) {
                switch (rt) {
                case rtPlr:
                    DumpVerbose_Player(data_buf, (uint16_t)actual);
                    break;
                case rtGame:
                    DumpVerbose_Game(data_buf, (uint16_t)actual);
                    break;
                case rtMsg:
                case rtPlrMsg:
                    DumpVerbose_Message(data_buf, (uint16_t)actual);
                    break;
                default:
                    break;
                }

                /* Always show a small preview too (helps with unknown formats). */
                printf("  Data: ");
                DumpPrintHexBytes(data_buf, (actual <= 64u) ? actual : 64u);
                if (actual > 64u)
                    printf("...");
                printf("\n\n");
            }
        } else {
            /* Print hex data (truncated if large) */
            size_t cb_show = (actual <= 64u) ? actual : 64u;
            printf("  Data: ");
            DumpPrintHexBytes(data_buf, cb_show);
            if (cb_show < actual)
                printf("...");
            printf("\n\n");
        }

        block_count++;

        if (data_buf != stack_buf) {
            free(data_buf);
            data_buf = stack_buf;
        }

        if (rt == rtEOF)
            break;
    }

    fclose(fp);

    printf("Total blocks: %d\n", block_count);
    return 0;
}

int DumpGameFileBlocks(const char *path) { return DumpGameFileBlocksEx(path, false); }
