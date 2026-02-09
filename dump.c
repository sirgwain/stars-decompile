
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

static bool DumpSplitBaseExt(const char *path, char *outBase, size_t cbBase, char *outExt, size_t cbExt) {
    const char *dot;
    size_t      n;

    if (outBase == NULL || cbBase == 0 || outExt == NULL || cbExt == 0)
        return false;
    outBase[0] = '\0';
    outExt[0] = '\0';

    if (path == NULL || path[0] == '\0')
        return false;

    dot = strrchr(path, '.');
    if (dot == NULL || dot[1] == '\0') {
        /* No extension; treat whole path as base. */
        strncpy(outBase, path, cbBase);
        outBase[cbBase - 1] = '\0';
        return true;
    }

    n = (size_t)(dot - path);
    if (n + 1 > cbBase)
        return false;
    memcpy(outBase, path, n);
    outBase[n] = '\0';

    strncpy(outExt, dot + 1, cbExt);
    outExt[cbExt - 1] = '\0';
    return true;
}

static void DumpVerbose_DecodedStructsForPath(const char *path) {
    char base[512];
    char ext[16];

    if (!DumpSplitBaseExt(path, base, sizeof(base), ext, sizeof(ext)))
        return;

    /* FLoadGame only supports HST and M1-M16 extensions.
       Skip decoded-struct dumps for xy, h1-h16, x1-x16, etc. */
    if ((ext[0] == 'h' || ext[0] == 'H') && (ext[1] == 's' || ext[1] == 'S')) {
        /* HST - ok */
    } else if ((ext[0] == 'm' || ext[0] == 'M') && ext[1] >= '1' && ext[1] <= '9') {
        /* M1-M16 - ok */
    } else {
        return;
    }

    /* Keep the dump command isolated from any prior load state. */
    DestroyCurGame();

    if (!FLoadGame(base, ext))
        return;

    printf("\n=== Decoded structures (FLoadGame '%s.%s') ===\n", base, ext);
    printf("\n");
    DumpGameStruct(&game);

    printf("\nPlayers:\n");
    for (int16_t iplr = 0; iplr < game.cPlayer; iplr++) {
        printf("\n-- Player %d --\n", (int)iplr);
        DumpPlayerStruct(&rgplr[iplr]);
    }

    printf("\nPlanets (%d):\n", (int)cPlanet);
    for (int16_t i = 0; i < cPlanet; i++) {
        printf("\n-- Planet[%d] id=%d --\n", (int)i, (int)lpPlanets[i].id);
        DumpPlanet(&lpPlanets[i]);
    }

    printf("\nFleets (%d):\n", (int)cFleet);
    for (int16_t i = 0; i < cFleet; i++) {
        if (rglpfl[i] == NULL)
            continue;
        printf("\n-- Fleet[%d] id=%d --\n", (int)i, (int)rglpfl[i]->id);
        DumpFleet(rglpfl[i]);
    }

    printf("\nShip designs:\n");
    for (int16_t iplr = 0; iplr < game.cPlayer; iplr++) {
        if (rglpshdef[iplr] != NULL) {
            printf("\n-- Player %d ships (%u) --\n", (int)iplr, (unsigned)(uint8_t)rgplr[iplr].cShDef);
            for (int j = 0; j < (int)(uint8_t)rgplr[iplr].cShDef; j++) {
                printf("\nDesign %d:\n", j);
                DumpShDef(&rglpshdef[iplr][j], j);
            }
        }

        if (rglpshdefSB[iplr] != NULL) {
            printf("\n-- Player %d starbases (%u) --\n", (int)iplr, (unsigned)rgplr[iplr].cshdefSB);
            for (int j = 0; j < (int)rgplr[iplr].cshdefSB; j++) {
                printf("\nSB Design %d:\n", j);
                DumpShDef(&rglpshdefSB[iplr][j], j);
            }
        }
    }

    printf("\n=== End decoded structures ===\n\n");

    DestroyCurGame();
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

    /*
     * For verbose dumps of non-log files, also show the fully decoded
     * in-memory structures as loaded by the real game loader.
     */
    if (fVerbose && dt != dtLog) {
        DumpVerbose_DecodedStructsForPath(szPath);
    }
    return 0;
}

int DumpGameFileBlocks(const char *path) { return DumpGameFileBlocksEx(path, false); }

/* ------------------------------------------------------------------ */
/* Block-level reading and diffing                                     */
/* ------------------------------------------------------------------ */

int ReadGameFileBlocks(const char *path, GameBlockList *out) {
    FILE    *fp;
    uint8_t  hdr_buf[2];

    if (path == NULL || out == NULL)
        return 2;

    memset(out, 0, sizeof(*out));

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "ReadGameFileBlocks: cannot open '%s'\n", path);
        return 2;
    }

    int cap = 64;
    out->blocks = (GameBlock *)malloc(cap * sizeof(GameBlock));
    if (!out->blocks) {
        fclose(fp);
        return 2;
    }
    out->capacity = cap;
    out->count = 0;

    while (fread(hdr_buf, 1, 2, fp) == 2) {
        uint16_t hdr_word = (uint16_t)hdr_buf[0] | ((uint16_t)hdr_buf[1] << 8);
        uint16_t cb = hdr_word & 0x3FF;
        uint16_t rt = (hdr_word >> 10) & 0x3F;

        /* Grow array if needed */
        if (out->count >= out->capacity) {
            int newcap = out->capacity * 2;
            GameBlock *nb = (GameBlock *)realloc(out->blocks, newcap * sizeof(GameBlock));
            if (!nb) {
                fclose(fp);
                return 2;
            }
            out->blocks = nb;
            out->capacity = newcap;
        }

        GameBlock *blk = &out->blocks[out->count];
        blk->rt = rt;
        blk->cb = cb;
        blk->data = NULL;

        if (cb > 0) {
            blk->data = (uint8_t *)malloc(cb);
            if (!blk->data) {
                fclose(fp);
                return 2;
            }
            if (fread(blk->data, 1, cb, fp) != cb) {
                fprintf(stderr, "ReadGameFileBlocks: short read at block %d\n", out->count);
                free(blk->data);
                blk->data = NULL;
                fclose(fp);
                return 2;
            }
        }

        out->count++;

        if (rt == rtEOF)
            break;
    }

    fclose(fp);
    return 0;
}

void FreeGameBlockList(GameBlockList *list) {
    if (list == NULL)
        return;
    for (int i = 0; i < list->count; i++) {
        free(list->blocks[i].data);
    }
    free(list->blocks);
    memset(list, 0, sizeof(*list));
}

/* ------------------------------------------------------------------ */
/* Struct-level diffing (operates on FLoadGame-populated globals)       */
/* ------------------------------------------------------------------ */

/* Helper: compare and print a single field.  Increments fdiffs if different. */
#define DIFF_FIELD_FMT(label, valA, valB, fmt)                                    \
    do {                                                                           \
        if ((valA) != (valB)) {                                                    \
            printf("    " label ": " fmt " -> " fmt "\n", (valA), (valB));         \
            fdiffs++;                                                              \
        }                                                                          \
    } while (0)

#define DIFF_I(label, a, b, field) \
    DIFF_FIELD_FMT(label, (int)(a).field, (int)(b).field, "%d")

#define DIFF_U(label, a, b, field) \
    DIFF_FIELD_FMT(label, (unsigned)(a).field, (unsigned)(b).field, "%u")

#define DIFF_X16(label, a, b, field) \
    DIFF_FIELD_FMT(label, (unsigned)(a).field, (unsigned)(b).field, "0x%04x")

#define DIFF_X32(label, a, b, field) \
    DIFF_FIELD_FMT(label, (unsigned)(a).field, (unsigned)(b).field, "0x%08x")

#define DIFF_U32(label, a, b, field) \
    DIFF_FIELD_FMT(label, (uint32_t)(a).field, (uint32_t)(b).field, "%u")

#define DIFF_I32(label, a, b, field) \
    DIFF_FIELD_FMT(label, (int32_t)(a).field, (int32_t)(b).field, "%d")

int DiffGame(const GAME *a, const GAME *b) {
    int fdiffs = 0;

    DIFF_I32("lid", *a, *b, lid);
    DIFF_I("mdSize", *a, *b, mdSize);
    DIFF_I("mdDensity", *a, *b, mdDensity);
    DIFF_I("cPlayer", *a, *b, cPlayer);
    DIFF_I("cPlanMax", *a, *b, cPlanMax);
    DIFF_I("mdStartDist", *a, *b, mdStartDist);
    DIFF_I("fDirty", *a, *b, fDirty);
    DIFF_U("fExtraFuel", *a, *b, fExtraFuel);
    DIFF_U("fSlowTech", *a, *b, fSlowTech);
    DIFF_U("fSinglePlr", *a, *b, fSinglePlr);
    DIFF_U("fTutorial", *a, *b, fTutorial);
    DIFF_U("fAisBand", *a, *b, fAisBand);
    DIFF_U("fBBSPlay", *a, *b, fBBSPlay);
    DIFF_U("fVisScores", *a, *b, fVisScores);
    DIFF_U("fNoRandom", *a, *b, fNoRandom);
    DIFF_U("fClumping", *a, *b, fClumping);
    DIFF_U("wGen", *a, *b, wGen);
    DIFF_U("turn", *a, *b, turn);

    if (memcmp(a->rgvc, b->rgvc, sizeof(a->rgvc)) != 0) {
        printf("    rgvc: ");
        DumpPrintHexBytes(a->rgvc, sizeof(a->rgvc));
        printf(" -> ");
        DumpPrintHexBytes(b->rgvc, sizeof(b->rgvc));
        printf("\n");
        fdiffs++;
    }

    if (strcmp(a->szName, b->szName) != 0) {
        printf("    szName: \"%s\" -> \"%s\"\n", a->szName, b->szName);
        fdiffs++;
    }

    return fdiffs;
}

int DiffPlayer(const PLAYER *a, const PLAYER *b, int iplr) {
    int fdiffs = 0;

    /* Skip entirely empty/identical slots */
    if (memcmp(a, b, sizeof(*a)) == 0)
        return 0;

    printf("  Player %d:\n", iplr);

    DIFF_I("iPlayer", *a, *b, iPlayer);
    DIFF_I("cShDef", *a, *b, cShDef);
    DIFF_I("cPlanet", *a, *b, cPlanet);
    DIFF_U("cFleet", *a, *b, cFleet);
    DIFF_U("cshdefSB", *a, *b, cshdefSB);
    DIFF_U("det", *a, *b, det);
    DIFF_U("iPlrBmp", *a, *b, iPlrBmp);
    DIFF_U("fInclude", *a, *b, fInclude);
    DIFF_U("mdPlayer", *a, *b, mdPlayer);
    DIFF_U("fAi", *a, *b, fAi);
    DIFF_U("lvlAi", *a, *b, lvlAi);
    DIFF_U("idAi", *a, *b, idAi);
    DIFF_I("idPlanetHome", *a, *b, idPlanetHome);
    DIFF_U("wScore", *a, *b, wScore);
    DIFF_I32("lSalt", *a, *b, lSalt);

    for (int j = 0; j < 3; j++) {
        if (a->rgEnvVar[j] != b->rgEnvVar[j]) {
            printf("    rgEnvVar[%d]: %d -> %d\n", j, (int)a->rgEnvVar[j], (int)b->rgEnvVar[j]);
            fdiffs++;
        }
    }
    for (int j = 0; j < 3; j++) {
        if (a->rgEnvVarMin[j] != b->rgEnvVarMin[j]) {
            printf("    rgEnvVarMin[%d]: %d -> %d\n", j, (int)a->rgEnvVarMin[j], (int)b->rgEnvVarMin[j]);
            fdiffs++;
        }
    }
    for (int j = 0; j < 3; j++) {
        if (a->rgEnvVarMax[j] != b->rgEnvVarMax[j]) {
            printf("    rgEnvVarMax[%d]: %d -> %d\n", j, (int)a->rgEnvVarMax[j], (int)b->rgEnvVarMax[j]);
            fdiffs++;
        }
    }
    DIFF_I("pctIdealGrowth", *a, *b, pctIdealGrowth);

    for (int j = 0; j < 6; j++) {
        if (a->rgTech[j] != b->rgTech[j]) {
            printf("    rgTech[%d]: %d -> %d\n", j, (int)a->rgTech[j], (int)b->rgTech[j]);
            fdiffs++;
        }
    }
    for (int j = 0; j < 6; j++) {
        if (a->rgResSpent[j] != b->rgResSpent[j]) {
            printf("    rgResSpent[%d]: %u -> %u\n", j, (unsigned)a->rgResSpent[j], (unsigned)b->rgResSpent[j]);
            fdiffs++;
        }
    }
    DIFF_I("pctResearch", *a, *b, pctResearch);
    DIFF_I("iTechCur", *a, *b, iTechCur);
    DIFF_I32("lResLastYear", *a, *b, lResLastYear);

    for (int j = 0; j < 16; j++) {
        if (a->rgAttr[j] != b->rgAttr[j]) {
            printf("    rgAttr[%d]: %d -> %d\n", j, (int)a->rgAttr[j], (int)b->rgAttr[j]);
            fdiffs++;
        }
    }
    DIFF_X32("grbitAttr", *a, *b, grbitAttr);
    DIFF_X16("grbitTrader", *a, *b, grbitTrader);
    DIFF_X16("wFlags", *a, *b, wFlags);

    if (memcmp(&a->zpq1, &b->zpq1, sizeof(a->zpq1)) != 0) {
        printf("    zpq1: differs\n");
        fdiffs++;
    }

    for (int j = 0; j < 16; j++) {
        if (a->rgmdRelation[j] != b->rgmdRelation[j]) {
            printf("    rgmdRelation[%d]: %u -> %u\n", j, (unsigned)a->rgmdRelation[j], (unsigned)b->rgmdRelation[j]);
            fdiffs++;
        }
    }

    if (strcmp(a->szName, b->szName) != 0) {
        printf("    szName: \"%s\" -> \"%s\"\n", a->szName, b->szName);
        fdiffs++;
    }
    if (strcmp(a->szNames, b->szNames) != 0) {
        printf("    szNames: \"%s\" -> \"%s\"\n", a->szNames, b->szNames);
        fdiffs++;
    }

    return fdiffs;
}

#undef DIFF_FIELD_FMT
#undef DIFF_I
#undef DIFF_U
#undef DIFF_X16
#undef DIFF_X32
#undef DIFF_U32
#undef DIFF_I32

/* ------------------------------------------------------------------ */
/* Planet / Fleet / ShDef diffs                                        */
/* ------------------------------------------------------------------ */

static void DiffHS(const HS *a, const HS *b, const char *label, int idx, int *pDiffs) {
    if (a->grhst != b->grhst || a->wRaw_0002 != b->wRaw_0002) {
        printf("      %s[%d]: grhst=0x%04x iItem=%u cItem=%u -> grhst=0x%04x iItem=%u cItem=%u\n",
               label, idx,
               (unsigned)a->grhst, (unsigned)a->iItem, (unsigned)a->cItem,
               (unsigned)b->grhst, (unsigned)b->iItem, (unsigned)b->cItem);
        (*pDiffs)++;
    }
}

static int DiffHul(const HUL *a, const HUL *b) {
    int fdiffs = 0;

    if (a->ihuldef != b->ihuldef) {
        printf("      ihuldef: %d -> %d\n", (int)a->ihuldef, (int)b->ihuldef);
        fdiffs++;
    }

    for (int i = 0; i < 6; i++) {
        if (a->rgTech[i] != b->rgTech[i]) {
            printf("      rgTech[%d]: %d -> %d\n", i, (int)a->rgTech[i], (int)b->rgTech[i]);
            fdiffs++;
        }
    }

    if (strcmp(a->szClass, b->szClass) != 0) {
        printf("      szClass: \"%s\" -> \"%s\"\n", a->szClass, b->szClass);
        fdiffs++;
    }

    if (a->wtEmpty != b->wtEmpty) {
        printf("      wtEmpty: %u -> %u\n", (unsigned)a->wtEmpty, (unsigned)b->wtEmpty);
        fdiffs++;
    }
    if (a->resCost != b->resCost) {
        printf("      resCost: %u -> %u\n", (unsigned)a->resCost, (unsigned)b->resCost);
        fdiffs++;
    }
    for (int i = 0; i < 3; i++) {
        if (a->rgwtOreCost[i] != b->rgwtOreCost[i]) {
            printf("      rgwtOreCost[%d]: %u -> %u\n", i, (unsigned)a->rgwtOreCost[i], (unsigned)b->rgwtOreCost[i]);
            fdiffs++;
        }
    }
    if (a->ibmp != b->ibmp) {
        printf("      ibmp: %d -> %d\n", (int)a->ibmp, (int)b->ibmp);
        fdiffs++;
    }
    if (a->wtCargoMax != b->wtCargoMax) {
        printf("      wtCargoMax: %u -> %u\n", (unsigned)a->wtCargoMax, (unsigned)b->wtCargoMax);
        fdiffs++;
    }
    if (a->wtFuelMax != b->wtFuelMax) {
        printf("      wtFuelMax: %u -> %u\n", (unsigned)a->wtFuelMax, (unsigned)b->wtFuelMax);
        fdiffs++;
    }
    if (a->dp != b->dp) {
        printf("      dp: %u -> %u\n", (unsigned)a->dp, (unsigned)b->dp);
        fdiffs++;
    }

    for (int i = 0; i < 16; i++) {
        DiffHS(&a->rghs[i], &b->rghs[i], "rghs", i, &fdiffs);
    }

    if (a->chs != b->chs) {
        printf("      chs: %u -> %u\n", (unsigned)a->chs, (unsigned)b->chs);
        fdiffs++;
    }

    return fdiffs;
}

static int DiffShDefOne(const SHDEF *a, const SHDEF *b, int iplr, int idx, const char *which) {
    int fdiffs = 0;

    /* Skip identical and both-free entries. */
    if (a->fFree && b->fFree)
        return 0;
    if (memcmp(a, b, sizeof(*a)) == 0)
        return 0;

    printf("  Player %d %s SHDEF[%d]:\n", iplr, which, idx);

    if (a->det != b->det) {
        printf("    det: %u -> %u\n", (unsigned)a->det, (unsigned)b->det);
        fdiffs++;
    }
    if (a->fInclude != b->fInclude) {
        printf("    fInclude: %u -> %u\n", (unsigned)a->fInclude, (unsigned)b->fInclude);
        fdiffs++;
    }
    if (a->fFree != b->fFree) {
        printf("    fFree: %u -> %u\n", (unsigned)a->fFree, (unsigned)b->fFree);
        fdiffs++;
    }
    if (a->ishdef != b->ishdef) {
        printf("    ishdef: %u -> %u\n", (unsigned)a->ishdef, (unsigned)b->ishdef);
        fdiffs++;
    }
    if (a->fGift != b->fGift) {
        printf("    fGift: %u -> %u\n", (unsigned)a->fGift, (unsigned)b->fGift);
        fdiffs++;
    }
    if (a->turn != b->turn) {
        printf("    turn: %u -> %u\n", (unsigned)a->turn, (unsigned)b->turn);
        fdiffs++;
    }
    if (a->cBuilt != b->cBuilt) {
        printf("    cBuilt: %" PRIu32 " -> %" PRIu32 "\n", (uint32_t)a->cBuilt, (uint32_t)b->cBuilt);
        fdiffs++;
    }
    if (a->cExist != b->cExist) {
        printf("    cExist: %" PRIu32 " -> %" PRIu32 "\n", (uint32_t)a->cExist, (uint32_t)b->cExist);
        fdiffs++;
    }
    if (a->lPower != b->lPower) {
        printf("    lPower: %" PRId32 " -> %" PRId32 "\n", (int32_t)a->lPower, (int32_t)b->lPower);
        fdiffs++;
    }
    if (a->grbitPlr != b->grbitPlr) {
        printf("    grbitPlr: 0x%04x -> 0x%04x\n", (unsigned)a->grbitPlr, (unsigned)b->grbitPlr);
        fdiffs++;
    }
    if (a->dScanRange != b->dScanRange) {
        printf("    dScanRange: %u -> %u\n", (unsigned)a->dScanRange, (unsigned)b->dScanRange);
        fdiffs++;
    }
    if (a->dScanRange2 != b->dScanRange2) {
        printf("    dScanRange2: %u -> %u\n", (unsigned)a->dScanRange2, (unsigned)b->dScanRange2);
        fdiffs++;
    }
    if (a->pctDetect != b->pctDetect) {
        printf("    pctDetect: %u -> %u\n", (unsigned)a->pctDetect, (unsigned)b->pctDetect);
        fdiffs++;
    }
    if (a->iSteal != b->iSteal) {
        printf("    iSteal: %u -> %u\n", (unsigned)a->iSteal, (unsigned)b->iSteal);
        fdiffs++;
    }

    if (memcmp(&a->hul, &b->hul, sizeof(a->hul)) != 0) {
        printf("    hul:\n");
        fdiffs += DiffHul(&a->hul, &b->hul);
    }

    return fdiffs;
}

static int DiffProdQ(const PLPROD *a, const PLPROD *b, const char *prefix) {
    int fdiffs = 0;

    if (a == NULL && b == NULL)
        return 0;
    if (a == NULL || b == NULL) {
        printf("    %s prodQ: %s -> %s\n", prefix, (a ? "present" : "none"), (b ? "present" : "none"));
        return 1;
    }

    if (a->iprodMac != b->iprodMac) {
        printf("    %s prodQ.iprodMac: %u -> %u\n", prefix, (unsigned)a->iprodMac, (unsigned)b->iprodMac);
        fdiffs++;
    }
    uint8_t mac = (a->iprodMac < b->iprodMac) ? a->iprodMac : b->iprodMac;
    for (uint8_t i = 0; i < mac; i++) {
        if (a->rgprod[i].dwRaw_0000 != b->rgprod[i].dwRaw_0000) {
            printf("    %s prodQ[%u]: 0x%08" PRIx32 " -> 0x%08" PRIx32 "\n", prefix, (unsigned)i,
                   (uint32_t)a->rgprod[i].dwRaw_0000, (uint32_t)b->rgprod[i].dwRaw_0000);
            fdiffs++;
        }
    }

    return fdiffs;
}

static int DiffPlanetOne(const PLANET *a, const PLANET *b, int16_t id) {
    int fdiffs = 0;

    if (a == NULL || b == NULL) {
        printf("  Planet %d: %s -> %s\n", (int)id, (a ? "present" : "missing"), (b ? "present" : "missing"));
        return 1;
    }

    /* Ignore lpplprod pointer value; diff contents below. */
    PLANET ta = *a;
    PLANET tb = *b;
    ta.lpplprod = NULL;
    tb.lpplprod = NULL;

    if (memcmp(&ta, &tb, sizeof(PLANET)) == 0) {
        /* Still check prod queue, which is out-of-line. */
        return DiffProdQ(a->lpplprod, b->lpplprod, "Planet");
    }

    printf("  Planet %d:\n", (int)id);

    if (a->iPlayer != b->iPlayer) {
        printf("    iPlayer: %d -> %d\n", (int)a->iPlayer, (int)b->iPlayer);
        fdiffs++;
    }
    if (a->det != b->det) {
        printf("    det: %u -> %u\n", (unsigned)a->det, (unsigned)b->det);
        fdiffs++;
    }
    if (a->fInclude != b->fInclude) {
        printf("    fInclude: %u -> %u\n", (unsigned)a->fInclude, (unsigned)b->fInclude);
        fdiffs++;
    }
    if (a->fStarbase != b->fStarbase) {
        printf("    fStarbase: %u -> %u\n", (unsigned)a->fStarbase, (unsigned)b->fStarbase);
        fdiffs++;
    }
    if (a->fHomeworld != b->fHomeworld) {
        printf("    fHomeworld: %u -> %u\n", (unsigned)a->fHomeworld, (unsigned)b->fHomeworld);
        fdiffs++;
    }
    if (a->fFirstYear != b->fFirstYear) {
        printf("    fFirstYear: %u -> %u\n", (unsigned)a->fFirstYear, (unsigned)b->fFirstYear);
        fdiffs++;
    }
    if (a->fWasInhabited != b->fWasInhabited) {
        printf("    fWasInhabited: %u -> %u\n", (unsigned)a->fWasInhabited, (unsigned)b->fWasInhabited);
        fdiffs++;
    }

    for (int i = 0; i < 3; i++) {
        if (a->rgpctMinLevel[i] != b->rgpctMinLevel[i]) {
            printf("    rgpctMinLevel[%d]: %u -> %u\n", i, (unsigned)a->rgpctMinLevel[i], (unsigned)b->rgpctMinLevel[i]);
            fdiffs++;
        }
        if (a->rgMinConc[i] != b->rgMinConc[i]) {
            printf("    rgMinConc[%d]: %u -> %u\n", i, (unsigned)a->rgMinConc[i], (unsigned)b->rgMinConc[i]);
            fdiffs++;
        }
        if (a->rgEnvVar[i] != b->rgEnvVar[i]) {
            printf("    rgEnvVar[%d]: %u -> %u\n", i, (unsigned)a->rgEnvVar[i], (unsigned)b->rgEnvVar[i]);
            fdiffs++;
        }
        if (a->rgEnvVarOrig[i] != b->rgEnvVarOrig[i]) {
            printf("    rgEnvVarOrig[%d]: %u -> %u\n", i, (unsigned)a->rgEnvVarOrig[i], (unsigned)b->rgEnvVarOrig[i]);
            fdiffs++;
        }
    }

    if (a->uPopGuess != b->uPopGuess || a->uDefGuess != b->uDefGuess) {
        printf("    guesses: uPopGuess=%u uDefGuess=%u -> uPopGuess=%u uDefGuess=%u\n",
               (unsigned)a->uPopGuess, (unsigned)a->uDefGuess,
               (unsigned)b->uPopGuess, (unsigned)b->uDefGuess);
        fdiffs++;
    }

    if (a->iDeltaPop != b->iDeltaPop) {
        printf("    iDeltaPop: %u -> %u\n", (unsigned)a->iDeltaPop, (unsigned)b->iDeltaPop);
        fdiffs++;
    }
    if (a->cMines != b->cMines) {
        printf("    cMines: %u -> %u\n", (unsigned)a->cMines, (unsigned)b->cMines);
        fdiffs++;
    }
    if (a->cFactories != b->cFactories) {
        printf("    cFactories: %u -> %u\n", (unsigned)a->cFactories, (unsigned)b->cFactories);
        fdiffs++;
    }
    if (a->cDefenses != b->cDefenses) {
        printf("    cDefenses: %u -> %u\n", (unsigned)a->cDefenses, (unsigned)b->cDefenses);
        fdiffs++;
    }
    if (a->iScanner != b->iScanner) {
        printf("    iScanner: %u -> %u\n", (unsigned)a->iScanner, (unsigned)b->iScanner);
        fdiffs++;
    }
    if (a->fArtifact != b->fArtifact) {
        printf("    fArtifact: %u -> %u\n", (unsigned)a->fArtifact, (unsigned)b->fArtifact);
        fdiffs++;
    }
    if (a->fNoResearch != b->fNoResearch) {
        printf("    fNoResearch: %u -> %u\n", (unsigned)a->fNoResearch, (unsigned)b->fNoResearch);
        fdiffs++;
    }

    for (int i = 0; i < 4; i++) {
        if (a->rgwtMin[i] != b->rgwtMin[i]) {
            printf("    rgwtMin[%d]: %" PRId32 " -> %" PRId32 "\n", i, (int32_t)a->rgwtMin[i], (int32_t)b->rgwtMin[i]);
            fdiffs++;
        }
    }

    if (a->lStarbase != b->lStarbase) {
        printf("    lStarbase: %" PRId32 " -> %" PRId32 "\n", (int32_t)a->lStarbase, (int32_t)b->lStarbase);
        fdiffs++;
    }
    if (a->wRouting != b->wRouting) {
        printf("    wRouting: 0x%04x -> 0x%04x\n", (unsigned)a->wRouting, (unsigned)b->wRouting);
        fdiffs++;
    }
    if (a->turn != b->turn) {
        printf("    turn: %d -> %d\n", (int)a->turn, (int)b->turn);
        fdiffs++;
    }

    fdiffs += DiffProdQ(a->lpplprod, b->lpplprod, "Planet");
    return fdiffs;
}

static int DiffOrderOne(const ORDER *a, const ORDER *b, int idx, const char *prefix) {
    if (memcmp(a, b, sizeof(*a)) == 0)
        return 0;

    printf("      %s ord[%d]: pt=(%d,%d) id=%d task=%u warp=%u grobj=%u valid=%u noauto=%u unused=%u raw=0x%04x\n",
           prefix,
           idx,
           (int)a->pt.x, (int)a->pt.y,
           (int)a->id,
           (unsigned)a->grTask, (unsigned)a->iWarp, (unsigned)a->grobj,
           (unsigned)a->fValidTask, (unsigned)a->fNoAutoTrack, (unsigned)a->fUnused, (unsigned)a->wRaw_0006);

    printf("              -> pt=(%d,%d) id=%d task=%u warp=%u grobj=%u valid=%u noauto=%u unused=%u raw=0x%04x\n",
           (int)b->pt.x, (int)b->pt.y,
           (int)b->id,
           (unsigned)b->grTask, (unsigned)b->iWarp, (unsigned)b->grobj,
           (unsigned)b->fValidTask, (unsigned)b->fNoAutoTrack, (unsigned)b->fUnused, (unsigned)b->wRaw_0006);

    return 1;
}

static int DiffFleetOne(const FLEET *a, const FLEET *b, int16_t id) {
    int fdiffs = 0;

    if (a == NULL || b == NULL) {
        printf("  Fleet %d: %s -> %s\n", (int)id, (a ? "present" : "missing"), (b ? "present" : "missing"));
        return 1;
    }

    /* Ignore pointers for cheap equality check. */
    FLEET ta = *a;
    FLEET tb = *b;
    ta.lpplord = NULL;
    tb.lpplord = NULL;
    ta.lpflNext = NULL;
    tb.lpflNext = NULL;
    ta.lpszName = NULL;
    tb.lpszName = NULL;

    bool fSameBase = (memcmp(&ta, &tb, sizeof(FLEET)) == 0);
    bool fSameName = true;
    if (a->lpszName == NULL && b->lpszName == NULL) {
        fSameName = true;
    } else if (a->lpszName != NULL && b->lpszName != NULL) {
        fSameName = (strcmp(a->lpszName, b->lpszName) == 0);
    } else {
        fSameName = false;
    }

    bool fSameOrders = true;
    if (a->lpplord == NULL && b->lpplord == NULL) {
        fSameOrders = true;
    } else if (a->lpplord != NULL && b->lpplord != NULL) {
        uint8_t macA = a->lpplord->iordMac;
        uint8_t macB = b->lpplord->iordMac;
        if (macA != macB) {
            fSameOrders = false;
        } else {
            for (uint8_t i = 0; i < macA; i++) {
                if (memcmp(&a->lpplord->rgord[i], &b->lpplord->rgord[i], sizeof(ORDER)) != 0) {
                    fSameOrders = false;
                    break;
                }
            }
        }
    } else {
        fSameOrders = false;
    }

    if (fSameBase && fSameName && fSameOrders)
        return 0;

    printf("  Fleet %d iplr: %d:\n", (int)id, a->iPlayer);

    if (a->iPlayer != b->iPlayer) {
        printf("    iPlayer: %d -> %d\n", (int)a->iPlayer, (int)b->iPlayer);
        fdiffs++;
    }
    if (a->det != b->det) {
        printf("    det: %u -> %u\n", (unsigned)a->det, (unsigned)b->det);
        fdiffs++;
    }
    if (a->wRaw_0004 != b->wRaw_0004) {
        printf("    wFlags: 0x%04x -> 0x%04x\n", (unsigned)a->wRaw_0004, (unsigned)b->wRaw_0004);
        fdiffs++;
    }
    if (a->idPlanet != b->idPlanet) {
        printf("    idPlanet: %d -> %d\n", (int)a->idPlanet, (int)b->idPlanet);
        fdiffs++;
    }
    if (a->pt.x != b->pt.x || a->pt.y != b->pt.y) {
        printf("    pt: (%d,%d) -> (%d,%d)\n", (int)a->pt.x, (int)a->pt.y, (int)b->pt.x, (int)b->pt.y);
        fdiffs++;
    }

    for (int i = 0; i < 16; i++) {
        if (a->rgcsh[i] != b->rgcsh[i]) {
            printf("    rgcsh[%d]: %d -> %d\n", i, (int)a->rgcsh[i], (int)b->rgcsh[i]);
            fdiffs++;
        }
    }

    if (a->det >= detAll || b->det >= detAll) {
        for (int i = 0; i < 16; i++) {
            if (memcmp(&a->rgdv[i], &b->rgdv[i], sizeof(DV)) != 0) {
                printf("    rgdv[%d]: dp=%u pct=%u -> dp=%u pct=%u\n",
                       i,
                       (unsigned)a->rgdv[i].dp, (unsigned)a->rgdv[i].pctDp,
                       (unsigned)b->rgdv[i].dp, (unsigned)b->rgdv[i].pctDp);
                fdiffs++;
            }
        }
    } else {
        if (a->wtFleet != b->wtFleet) {
            printf("    wtFleet: %" PRId32 " -> %" PRId32 "\n", (int32_t)a->wtFleet, (int32_t)b->wtFleet);
            fdiffs++;
        }
    }

    for (int i = 0; i < 5; i++) {
        if (a->rgwtMin[i] != b->rgwtMin[i]) {
            printf("    rgwtMin[%d]: %" PRId32 " -> %" PRId32 "\n", i, (int32_t)a->rgwtMin[i], (int32_t)b->rgwtMin[i]);
            fdiffs++;
        }
    }
    if (a->iplan != b->iplan) {
        printf("    iplan: %u -> %u\n", (unsigned)a->iplan, (unsigned)b->iplan);
        fdiffs++;
    }
    if (a->cord != b->cord) {
        printf("    cord: %d -> %d\n", (int)a->cord, (int)b->cord);
        fdiffs++;
    }
    if (a->lPower != b->lPower) {
        printf("    lPower: %" PRId32 " -> %" PRId32 "\n", (int32_t)a->lPower, (int32_t)b->lPower);
        fdiffs++;
    }
    if (a->lFuelUsed != b->lFuelUsed) {
        printf("    lFuelUsed: %" PRId32 " -> %" PRId32 "\n", (int32_t)a->lFuelUsed, (int32_t)b->lFuelUsed);
        fdiffs++;
    }
    if (a->dirLong != b->dirLong) {
        printf("    dirLong: 0x%08" PRIx32 " -> 0x%08" PRIx32 "\n", (uint32_t)a->dirLong, (uint32_t)b->dirLong);
        fdiffs++;
    }

    if (!fSameName) {
        printf("    name: \"%s\" -> \"%s\"\n", (a->lpszName ? a->lpszName : ""), (b->lpszName ? b->lpszName : ""));
        fdiffs++;
    }

    if (a->lpplord == NULL && b->lpplord == NULL) {
        /* ok */
    } else if (a->lpplord == NULL || b->lpplord == NULL) {
        printf("    orders: %s -> %s\n", (a->lpplord ? "present" : "none"), (b->lpplord ? "present" : "none"));
        fdiffs++;
    } else {
        if (a->lpplord->iordMac != b->lpplord->iordMac) {
            printf("    orders.iordMac: %u -> %u\n", (unsigned)a->lpplord->iordMac, (unsigned)b->lpplord->iordMac);
            fdiffs++;
        }
        uint8_t mac = (a->lpplord->iordMac < b->lpplord->iordMac) ? a->lpplord->iordMac : b->lpplord->iordMac;
        for (uint8_t i = 0; i < mac; i++) {
            fdiffs += DiffOrderOne(&a->lpplord->rgord[i], &b->lpplord->rgord[i], (int)i, "");
        }
    }

    return fdiffs;
}

/* Simple snapshots so we can compare file A vs file B without relying on
 * pointer stability inside the allocator.
 */

typedef struct DumpSnapshot {
    GAME   game;
    PLAYER rgplr[16];

    STARSPOINT rgptPlan[999];

    int16_t cPlanet;
    PLANET *rgpl; /* length cPlanet */
    PLPROD **rgplprod; /* parallel array, owned */

    int16_t cFleet;
    FLEET  *rgfl;       /* length cFleet */
    PLORD **rgflord;    /* parallel, owned */
    char  **rgflname;   /* parallel, owned */
    int16_t *rgflid;    /* parallel, owned */

    SHDEF  *rglpshdef[16];
    SHDEF  *rglpshdefSB[16];
} DumpSnapshot;

static void SnapshotFree(DumpSnapshot *s) {
    if (s == NULL)
        return;

    if (s->rgpl != NULL) {
        for (int16_t i = 0; i < s->cPlanet; i++) {
            free(s->rgplprod ? s->rgplprod[i] : NULL);
        }
        free(s->rgpl);
        free(s->rgplprod);
    }

    if (s->rgfl != NULL) {
        for (int16_t i = 0; i < s->cFleet; i++) {
            free(s->rgflord ? s->rgflord[i] : NULL);
            free(s->rgflname ? s->rgflname[i] : NULL);
        }
        free(s->rgfl);
        free(s->rgflord);
        free(s->rgflname);
        free(s->rgflid);
    }

    for (int i = 0; i < 16; i++) {
        free(s->rglpshdef[i]);
        free(s->rglpshdefSB[i]);
    }

    memset(s, 0, sizeof(*s));
}

static bool SnapshotTake(DumpSnapshot *s) {
    if (s == NULL)
        return false;

    memset(s, 0, sizeof(*s));
    memcpy(&s->game, &game, sizeof(game));
    memcpy(&s->rgplr[0], &rgplr[0], sizeof(s->rgplr));

    memcpy(&s->rgptPlan[0], &rgptPlan[0], sizeof(s->rgptPlan));

    s->cPlanet = cPlanet;
    if (s->cPlanet < 0)
        s->cPlanet = 0;
    if (s->cPlanet > 0) {
        s->rgpl = (PLANET *)calloc((size_t)s->cPlanet, sizeof(PLANET));
        s->rgplprod = (PLPROD **)calloc((size_t)s->cPlanet, sizeof(PLPROD *));
        if (s->rgpl == NULL || s->rgplprod == NULL)
            return false;

        for (int16_t i = 0; i < s->cPlanet; i++) {
            s->rgpl[i] = lpPlanets[i];
            s->rgpl[i].lpplprod = NULL;
            s->rgplprod[i] = NULL;

            if (lpPlanets[i].lpplprod != NULL) {
                const PLPROD *pq = lpPlanets[i].lpplprod;
                size_t cb = sizeof(PLPROD) + (size_t)pq->iprodMac * sizeof(PROD);
                PLPROD *copy = (PLPROD *)malloc(cb);
                if (copy == NULL)
                    return false;
                memcpy(copy, pq, cb);
                s->rgplprod[i] = copy;
            }
        }
    }

    s->cFleet = cFleet;
    if (s->cFleet < 0)
        s->cFleet = 0;
    if (s->cFleet > 0) {
        s->rgfl = (FLEET *)calloc((size_t)s->cFleet, sizeof(FLEET));
        s->rgflord = (PLORD **)calloc((size_t)s->cFleet, sizeof(PLORD *));
        s->rgflname = (char **)calloc((size_t)s->cFleet, sizeof(char *));
        s->rgflid = (int16_t *)calloc((size_t)s->cFleet, sizeof(int16_t));
        if (s->rgfl == NULL || s->rgflord == NULL || s->rgflname == NULL || s->rgflid == NULL)
            return false;

        for (int16_t i = 0; i < s->cFleet; i++) {
            const FLEET *src = rglpfl[i];
            s->rgfl[i] = *src;
            s->rgflid[i] = src->id;
            s->rgfl[i].lpplord = NULL;
            s->rgfl[i].lpflNext = NULL;
            s->rgfl[i].lpszName = NULL;

            if (src->lpszName != NULL) {
                size_t n = strlen(src->lpszName) + 1;
                s->rgflname[i] = (char *)malloc(n);
                if (s->rgflname[i] == NULL)
                    return false;
                memcpy(s->rgflname[i], src->lpszName, n);
            }

            if (src->lpplord != NULL) {
                const PLORD *po = src->lpplord;
                uint8_t nord = po->iordMax;
                if (nord == 0)
                    nord = (uint8_t)(src->cord + 1);
                size_t cb = sizeof(PLORD) + (size_t)nord * sizeof(ORDER);
                PLORD *copy = (PLORD *)malloc(cb);
                if (copy == NULL)
                    return false;
                memcpy(copy, po, cb);
                s->rgflord[i] = copy;
            }
        }
    }

    for (int i = 0; i < 16; i++) {
        if (rglpshdef[i] != NULL) {
            s->rglpshdef[i] = (SHDEF *)malloc(sizeof(SHDEF) * ishdefMax);
            if (s->rglpshdef[i] == NULL)
                return false;
            memcpy(s->rglpshdef[i], rglpshdef[i], sizeof(SHDEF) * ishdefMax);
        }

        if (rglpshdefSB[i] != NULL) {
            s->rglpshdefSB[i] = (SHDEF *)malloc(sizeof(SHDEF) * ishdefSBMax);
            if (s->rglpshdefSB[i] == NULL)
                return false;
            memcpy(s->rglpshdefSB[i], rglpshdefSB[i], sizeof(SHDEF) * ishdefSBMax);
        }
    }

    return true;
}

static const PLANET *SnapshotFindPlanet(const DumpSnapshot *s, int16_t id, const PLPROD **ppq) {
    if (ppq != NULL)
        *ppq = NULL;
    if (s == NULL || s->rgpl == NULL)
        return NULL;
    for (int16_t i = 0; i < s->cPlanet; i++) {
        if (s->rgpl[i].id == id) {
            if (ppq != NULL && s->rgplprod != NULL)
                *ppq = s->rgplprod[i];
            return &s->rgpl[i];
        }
    }
    return NULL;
}

static const FLEET *SnapshotFindFleet(const DumpSnapshot *s, int16_t id, const PLORD **ppord, const char **ppname) {
    if (ppord != NULL)
        *ppord = NULL;
    if (ppname != NULL)
        *ppname = NULL;
    if (s == NULL || s->rgfl == NULL)
        return NULL;

    for (int16_t i = 0; i < s->cFleet; i++) {
        if (s->rgflid != NULL && s->rgflid[i] == id) {
            if (ppord != NULL)
                *ppord = (s->rgflord ? s->rgflord[i] : NULL);
            if (ppname != NULL)
                *ppname = (s->rgflname ? s->rgflname[i] : NULL);
            return &s->rgfl[i];
        }
    }
    return NULL;
}

int DiffGameFileBlocks(const char *pathA, const char *pathB) {
    char    baseA[1024], extA[16];
    char    baseB[1024], extB[16];
    int     diffs = 0;

    /* Split paths into base + extension for FLoadGame */
    if (!Stars_PathSplitExt(pathA, baseA, sizeof(baseA), extA, sizeof(extA))) {
        fprintf(stderr, "diff: invalid path: %s\n", pathA);
        return 2;
    }
    if (!Stars_PathSplitExt(pathB, baseB, sizeof(baseB), extB, sizeof(extB))) {
        fprintf(stderr, "diff: invalid path: %s\n", pathB);
        return 2;
    }

    /* Load file A */
    if (!FLoadGame(baseA, extA)) {
        fprintf(stderr, "diff: FLoadGame failed for '%s'\n", pathA);
        return 2;
    }

    /* Snapshot globals from file A (deep copy where needed). */
    DumpSnapshot snapA;
    if (!SnapshotTake(&snapA)) {
        fprintf(stderr, "diff: out of memory while snapshotting '%s'\n", pathA);
        SnapshotFree(&snapA);
        return 2;
    }

    DestroyCurGame();

    /* Load file B (overwrites globals) */
    if (!FLoadGame(baseB, extB)) {
        fprintf(stderr, "diff: FLoadGame failed for '%s'\n", pathB);
        SnapshotFree(&snapA);
        return 2;
    }

    /* --- Diff GAME struct --- */
    printf("GAME:\n");
    int gameDiffs = DiffGame(&snapA.game, &game);
    if (gameDiffs == 0)
        printf("    (identical)\n");
    diffs += gameDiffs;

    /* --- Diff PLAYER structs --- */
    int maxPlr = (snapA.game.cPlayer > game.cPlayer) ? snapA.game.cPlayer : game.cPlayer;
    if (maxPlr > 16) maxPlr = 16;

    printf("\nPLAYERS:\n");
    int plrDiffs = 0;
    for (int i = 0; i < maxPlr; i++) {
        plrDiffs += DiffPlayer(&snapA.rgplr[i], &rgplr[i], i);
    }
    if (plrDiffs == 0)
        printf("  (all identical)\n");
    diffs += plrDiffs;

    /* --- Diff PLANET structs (matched by planet id) --- */
    printf("\nPLANETS:\n");
    int planetDiffs = 0;
    int16_t maxPlanId = snapA.game.cPlanMax;
    if (game.cPlanMax > maxPlanId)
        maxPlanId = game.cPlanMax;
    if (maxPlanId < 0)
        maxPlanId = 0;

    if (game.cPlanMax != snapA.game.cPlanMax) {
        printf("  Num Planets: %d -> %d\n", snapA.game.cPlanMax, game.cPlanMax);
    }
    /* Diff planet XY coordinates (rgptPlan, loaded from .XY) before planet structs. */
    int xyDiffs = 0;
    for (int16_t id = 0; id < maxPlanId; id++) {
        const STARSPOINT a = snapA.rgptPlan[id];
        const STARSPOINT b = rgptPlan[id];
        if (a.x != b.x || a.y != b.y) {
            printf("  Planet %d xy: (%d,%d) -> (%d,%d)\n", (int)id, (int)a.x, (int)a.y, (int)b.x, (int)b.y);
            xyDiffs++;
        }
    }
    if (xyDiffs == 0)
        printf("  (all coordinates identical)\n");
    planetDiffs += xyDiffs;

    for (int16_t id = 0; id < maxPlanId; id++) {
        const PLPROD *pqA = NULL;
        const PLANET *pa = SnapshotFindPlanet(&snapA, id, &pqA);

        const PLANET *pb = NULL;
        const PLPROD *pqB = NULL;
        for (int16_t j = 0; j < cPlanet; j++) {
            if (lpPlanets[j].id == id) {
                pb = &lpPlanets[j];
                pqB = lpPlanets[j].lpplprod;
                break;
            }
        }

        PLANET ta;
        PLANET tb;
        const PLANET *pTa = pa;
        const PLANET *pTb = pb;
        if (pa != NULL) {
            ta = *pa;
            ta.lpplprod = (PLPROD *)pqA;
            pTa = &ta;
        }
        if (pb != NULL) {
            tb = *pb;
            tb.lpplprod = (PLPROD *)pqB;
            pTb = &tb;
        }

        planetDiffs += DiffPlanetOne(pTa, pTb, id);
    }
    if (planetDiffs == 0)
        printf("  (all identical)\n");
    diffs += planetDiffs;

    /* --- Diff FLEET structs (matched by fleet id) --- */
    printf("\nFLEETS:\n");
    int fleetDiffs = 0;
    bool *seen = NULL;
    if (cFleet > 0) {
        seen = (bool *)calloc((size_t)cFleet, sizeof(bool));
    }

    for (int16_t i = 0; i < snapA.cFleet; i++) {
        int16_t id = snapA.rgflid[i];

        const PLORD *ordA = (snapA.rgflord ? snapA.rgflord[i] : NULL);
        const char  *nameA = (snapA.rgflname ? snapA.rgflname[i] : NULL);

        const FLEET *fb = NULL;
        for (int16_t j = 0; j < cFleet; j++) {
            if (rglpfl[j]->id == id) {
                fb = rglpfl[j];
                if (seen != NULL)
                    seen[j] = true;
                break;
            }
        }

        FLEET fa = snapA.rgfl[i];
        fa.lpplord = (PLORD *)ordA;
        fa.lpszName = (char *)nameA;

        fleetDiffs += DiffFleetOne(&fa, fb, id);
    }

    /* Fleets present only in B. */
    for (int16_t j = 0; j < cFleet; j++) {
        if (seen != NULL && seen[j])
            continue;
        fleetDiffs += DiffFleetOne(NULL, rglpfl[j], rglpfl[j]->id);
    }
    free(seen);
    if (fleetDiffs == 0)
        printf("  (all identical)\n");
    diffs += fleetDiffs;

    /* --- Diff SHDEF arrays (matched by slot index) --- */
    printf("\nSHDEFS:\n");
    int shdefDiffs = 0;
    for (int i = 0; i < maxPlr; i++) {
        const SHDEF *a = snapA.rglpshdef[i];
        const SHDEF *b = rglpshdef[i];
        if (a == NULL && b == NULL)
            continue;

        for (int j = 0; j < ishdefMax; j++) {
            SHDEF tmpA;
            SHDEF tmpB;
            const SHDEF *pa = a;
            const SHDEF *pb = b;

            if (a == NULL) {
                memset(&tmpA, 0, sizeof(tmpA));
                tmpA.fFree = true;
                pa = &tmpA;
            } else {
                pa = &a[j];
            }
            if (b == NULL) {
                memset(&tmpB, 0, sizeof(tmpB));
                tmpB.fFree = true;
                pb = &tmpB;
            } else {
                pb = &b[j];
            }

            shdefDiffs += DiffShDefOne(pa, pb, i, j, "");
        }
    }

    /* Starbase ship defs. */
    printf("\nSTARBASE SHDEFS:\n");
    for (int i = 0; i < maxPlr; i++) {
        const SHDEF *a = snapA.rglpshdefSB[i];
        const SHDEF *b = rglpshdefSB[i];
        if (a == NULL && b == NULL)
            continue;

        for (int j = 0; j < ishdefSBMax; j++) {
            SHDEF tmpA;
            SHDEF tmpB;
            const SHDEF *pa = a;
            const SHDEF *pb = b;

            if (a == NULL) {
                memset(&tmpA, 0, sizeof(tmpA));
                tmpA.fFree = true;
                pa = &tmpA;
            } else {
                pa = &a[j];
            }
            if (b == NULL) {
                memset(&tmpB, 0, sizeof(tmpB));
                tmpB.fFree = true;
                pb = &tmpB;
            } else {
                pb = &b[j];
            }

            shdefDiffs += DiffShDefOne(pa, pb, i, j, "SB");
        }
    }
    if (shdefDiffs == 0)
        printf("  (all identical)\n");
    diffs += shdefDiffs;

    printf("\n%d difference(s) found.\n", diffs);
    SnapshotFree(&snapA);
    return (diffs > 0) ? 1 : 0;
}
