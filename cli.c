#include "cli.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file.h"
#include "globals.h"

/* ------------------------------------------------------------ */
/* small helpers */

static void build_fullpath(char *out, size_t outsz, const char *base, const char *ext)
{
    /*
     * CLI convention: <base> is a path without extension, <ext> may be:
     *   - ".HST" (with dot)
     *   - "HST"  (without dot)
     */
    const char *e = (ext != NULL) ? ext : "";
    if (e[0] == '.') {
        snprintf(out, outsz, "%s%s", base ? base : "", e);
    } else if (e[0] != '\0') {
        snprintf(out, outsz, "%s.%s", base ? base : "", e);
    } else {
        snprintf(out, outsz, "%s", base ? base : "");
    }
}

static int64_t file_size_bytes(const char *path)
{
    FILE *fp;
    long end;

    if (path == NULL) return -1;

    fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    end = ftell(fp);
    fclose(fp);
    return (end < 0) ? -1 : (int64_t)end;
}

static const char *record_type_name(uint16_t rt)
{
    /*
     * Note: the file format uses 6-bit record types. Some of our internal enum
     * names are still being reconciled; here we bias toward common Stars!
     * .HST record meanings (and match Houston output where possible).
     */
    switch (rt) {
    case 0x00: return "FileFooter";
    case 0x06: return "Player";
    case 0x07: return "Game";
    case 0x08: return "FileHeader";
    case 0x0C: return "Message";
    case 0x0D: return "Planet";
    case 0x10: return "Fleet";
    case 0x14: return "Waypoint";
    case 0x15: return "String";
    case 0x1A: return "Design";
    case 0x1E: return "BattlePlan";
    case 0x1F: return "BattleData";
    case 0x2B: return "Thing";
    case 0x2D: return "Score";
    default: return "Unknown";
    }
}

static void print_usage(FILE *out)
{
    fprintf(out,
            "stars_cli - inspect Stars! save files\n\n"
            "Usage:\n"
            "  stars_cli load <base> <ext> [--player N] <cmd> [cmd-args]\n\n"
            "Where:\n"
            "  <base> is the path without extension (e.g. test/data/tiny/2400)\n"
            "  <ext>  is the extension including dot (e.g. .m1, .p1, .hst)\n\n"
            "Commands:\n"
            "  planets                List planets\n"
            "  planet <id>            Show a planet\n"
            "  things                 List things\n"
            "  thing <idfull>         Show a thing (decimal or hex like 0x1234)\n"
            "  fleets                 List fleets (all players)\n"
            "  fleet <id>             Show a fleet (id/ifl packed field)\n"
            "  shdefs                 List ship designs (best-effort)\n"
            "  shdef <index>          Show a ship design by index (best-effort)\n"
            "  game                   Dump loaded game summary\n"
            "  blocks                 Dump raw record blocks (type/size/data)\n");
}

static int32_t parse_i32(const char *s, bool *ok)
{
    char *end = NULL;
    long v;

    if (s == NULL || *s == '\0') {
        if (ok) *ok = false;
        return 0;
    }

    v = strtol(s, &end, 0 /* base: 0 allows 0x... */);
    if (end == s || (end && *end != '\0')) {
        if (ok) *ok = false;
        return 0;
    }
    if (ok) *ok = true;
    return (int32_t)v;
}

static const PLANET *find_planet_by_id(int16_t id)
{
    int16_t i;
    if (lpPlanets == NULL) return NULL;
    for (i = 0; i < cPlanet; i++) {
        if (lpPlanets[i].id == id) return &lpPlanets[i];
    }
    return NULL;
}

static const THING *find_thing_by_idfull(uint16_t idFull)
{
    int16_t i;
    if (lpThings == NULL) return NULL;
    for (i = 0; i < cThing; i++) {
        if (lpThings[i].idFull == idFull) return &lpThings[i];
    }
    return NULL;
}

static const FLEET *find_fleet_by_id(int16_t id)
{
    /*
     * Fleet storage is a little opaque in this codebase right now.
     * rglpfl is known to be a pointer-to-pointer, and many routines build
     * linked lists via lpflNext. For the CLI we do a best-effort scan:
     * treat rglpfl as an array of per-player head pointers sized by game.cPlayer.
     */
    int16_t iplr;

    if (rglpfl == NULL) return NULL;
    for (iplr = 0; iplr < game.cPlayer; iplr++) {
        const FLEET *lpfl = rglpfl[iplr];
        while (lpfl != NULL) {
            if (lpfl->id == id) return lpfl;
            lpfl = lpfl->lpflNext;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------ */
/* printing */

static void print_planet_row(const PLANET *p)
{
    int16_t id = p->id;
    POINT pt = {0, 0};

    /* rgptPlan is indexed by planet id in Stars! (0..998). */
    if (id >= 0 && id < (int16_t)(sizeof(rgptPlan) / sizeof(rgptPlan[0]))) {
        pt = rgptPlan[id];
    }

    printf("%4d  plr=%2d  (%5d,%5d)  det=%3u  hw=%d  sb=%d  pop=%u  fac=%u  min=%u\n",
           p->id,
           p->iPlayer,
           (int)pt.x,
           (int)pt.y,
           (unsigned)p->det,
           (int)p->fHomeworld,
           (int)p->fStarbase,
           (unsigned)p->uPopGuess,
           (unsigned)p->cFactories,
           (unsigned)p->cMines);
}

static void print_planet_detail(const PLANET *p)
{
    POINT pt = {0, 0};
    if (p->id >= 0 && p->id < (int16_t)(sizeof(rgptPlan) / sizeof(rgptPlan[0]))) {
        pt = rgptPlan[p->id];
    }

    printf("Planet %d\n", p->id);
    printf("  owner iPlayer: %d\n", p->iPlayer);
    printf("  pos: (%d,%d)\n", (int)pt.x, (int)pt.y);
    printf("  det: %u\n", (unsigned)p->det);
    printf("  flags: include=%d starbase=%d homeworld=%d firstyear=%d wasinhabited=%d artifact=%d noresearch=%d\n",
           (int)p->fInclude,
           (int)p->fStarbase,
           (int)p->fHomeworld,
           (int)p->fFirstYear,
           (int)p->fWasInhabited,
           (int)p->fArtifact,
           (int)p->fNoResearch);
    printf("  env: cur=(%d,%d,%d) orig=(%d,%d,%d)\n",
           (int)p->rgEnvVar[0], (int)p->rgEnvVar[1], (int)p->rgEnvVar[2],
           (int)p->rgEnvVarOrig[0], (int)p->rgEnvVarOrig[1], (int)p->rgEnvVarOrig[2]);
    printf("  guesses: pop=%u def=%u\n", (unsigned)p->uPopGuess, (unsigned)p->uDefGuess);
    printf("  imp: deltaPop=%u mines=%u factories=%u defenses=%u\n",
           (unsigned)p->iDeltaPop,
           (unsigned)p->cMines,
           (unsigned)p->cFactories,
           (unsigned)p->cDefenses);
    printf("  scanner=%u  turn=%d\n", (unsigned)p->iScanner, (int)p->turn);
    printf("  minerals (surf) iron=%" PRId32 " bor=%" PRId32 " ger=%" PRId32 "\n",
           p->rgwtMin[0], p->rgwtMin[1], p->rgwtMin[2]);
    printf("  minerals (conc) iron=%d bor=%d ger=%d\n",
           (int)p->rgMinConc[0], (int)p->rgMinConc[1], (int)p->rgMinConc[2]);
}

static void print_thing_row(const THING *t)
{
    printf("0x%04x  id=%3u  iplr=%2u  ith=%u  (%5d,%5d)  turn=%u\n",
           (unsigned)t->idFull,
           (unsigned)t->id,
           (unsigned)t->iplr,
           (unsigned)t->ith,
           (int)t->pt.x,
           (int)t->pt.y,
           (unsigned)t->turn);
}

static void print_thing_detail(const THING *t)
{
    printf("Thing 0x%04x\n", (unsigned)t->idFull);
    printf("  id=%u  iplr=%u  ith=%u\n", (unsigned)t->id, (unsigned)t->iplr, (unsigned)t->ith);
    printf("  pos: (%d,%d)\n", (int)t->pt.x, (int)t->pt.y);
    printf("  turn: %u\n", (unsigned)t->turn);
    printf("  raw bytes:");
    for (int i = 0; i < 10; i++) {
        printf(" %02x", (unsigned)t->rgb[i]);
    }
    printf("\n");
}

static void print_fleet_row(const FLEET *f)
{
    const char *name = (f->lpszName != NULL) ? f->lpszName : "";
    printf("%5d  plr=%2d  det=%3u  dead=%d  (%5d,%5d)  idPlanet=%d  plan=%u  name=\"%s\"\n",
           f->id,
           f->iPlayer,
           (unsigned)f->det,
           (int)f->fDead,
           (int)f->pt.x,
           (int)f->pt.y,
           (int)f->idPlanet,
           (unsigned)f->iplan,
           name);
}

static void print_fleet_detail(const FLEET *f)
{
    printf("Fleet %d\n", f->id);
    printf("  iPlayer: %d\n", f->iPlayer);
    printf("  pos: (%d,%d)\n", (int)f->pt.x, (int)f->pt.y);
    printf("  idPlanet: %d\n", (int)f->idPlanet);
    printf("  det: %u\n", (unsigned)f->det);
    printf("  flags: include=%d reporders=%d dead=%d done=%d bombed=%d hereAllTurn=%d noheal=%d mark=%d\n",
           (int)f->fInclude,
           (int)f->fRepOrders,
           (int)f->fDead,
           (int)f->fDone,
           (int)f->fBombed,
           (int)f->fHereAllTurn,
           (int)f->fNoHeal,
           (int)f->fMark);
    printf("  plan: %u  cord: %d\n", (unsigned)f->iplan, (int)f->cord);
    printf("  move: left=%d used=%d fuel=%" PRId32 "\n", (int)f->dMoveLeft, (int)f->dMoveUsed, f->lFuelUsed);
    printf("  name: %s\n", (f->lpszName != NULL) ? f->lpszName : "(null)");

    /* ship counts */
    printf("  rgcsh:");
    for (int i = 0; i < 16; i++) {
        if (f->rgcsh[i] != 0) {
            printf(" [%d]=%d", i, (int)f->rgcsh[i]);
        }
    }
    printf("\n");
}

static void print_shdef_row(const SHDEF *s, int idx)
{
    printf("%3d  ishdef=%u  free=%d  gift=%d  det=%u  class=\"%s\"  ihuldef=%d  chs=%u  built=%" PRIu32 " exist=%" PRIu32 "\n",
           idx,
           (unsigned)s->ishdef,
           (int)s->fFree,
           (int)s->fGift,
           (unsigned)s->det,
           s->hul.szClass,
           (int)s->hul.ihuldef,
           (unsigned)s->hul.chs,
           (uint32_t)s->cBuilt,
           (uint32_t)s->cExist);
}

static void print_shdef_detail(const SHDEF *s, int idx)
{
    printf("ShDef[%d]\n", idx);
    printf("  ishdef=%u det=%u include=%d free=%d gift=%d\n",
           (unsigned)s->ishdef,
           (unsigned)s->det,
           (int)s->fInclude,
           (int)s->fFree,
           (int)s->fGift);
    printf("  class: %s\n", s->hul.szClass);
    printf("  ihuldef=%d chs=%u wtEmpty=%u dp=%u\n",
           (int)s->hul.ihuldef,
           (unsigned)s->hul.chs,
           (unsigned)s->hul.wtEmpty,
           (unsigned)s->hul.dp);
    printf("  costs: res=%u ore=(%u,%u,%u)\n",
           (unsigned)s->hul.resCost,
           (unsigned)s->hul.rgwtOreCost[0],
           (unsigned)s->hul.rgwtOreCost[1],
           (unsigned)s->hul.rgwtOreCost[2]);
    printf("  built=%" PRIu32 " exist=%" PRIu32 " grbitPlr=0x%04x\n",
           (uint32_t)s->cBuilt,
           (uint32_t)s->cExist,
           (unsigned)s->grbitPlr);
    printf("  scan: range=%u range2=%u pctDetect=%u iSteal=%u\n",
           (unsigned)s->dScanRange,
           (unsigned)s->dScanRange2,
           (unsigned)s->pctDetect,
           (unsigned)s->iSteal);
}

/* ------------------------------------------------------------ */
/* command handlers */

static int cmd_planets(void)
{
    if (lpPlanets == NULL) {
        fprintf(stderr, "No planets loaded (lpPlanets == NULL).\n");
        return 2;
    }
    printf("Planets: cPlanet=%d\n", (int)cPlanet);
    for (int16_t i = 0; i < cPlanet; i++) {
        print_planet_row(&lpPlanets[i]);
    }
    return 0;
}

static int cmd_planet(const char *sid)
{
    bool ok;
    int32_t id32 = parse_i32(sid, &ok);
    if (!ok || id32 < -32768 || id32 > 32767) {
        fprintf(stderr, "planet: invalid id: %s\n", sid ? sid : "(null)");
        return 2;
    }
    const PLANET *p = find_planet_by_id((int16_t)id32);
    if (!p) {
        fprintf(stderr, "planet: not found: %d\n", (int)id32);
        return 2;
    }
    print_planet_detail(p);
    return 0;
}

static int cmd_things(void)
{
    if (lpThings == NULL) {
        fprintf(stderr, "No things loaded (lpThings == NULL).\n");
        return 2;
    }
    printf("Things: cThing=%d\n", (int)cThing);
    for (int16_t i = 0; i < cThing; i++) {
        print_thing_row(&lpThings[i]);
    }
    return 0;
}

static int cmd_thing(const char *sidfull)
{
    bool ok;
    int32_t v = parse_i32(sidfull, &ok);
    if (!ok || v < 0 || v > 0xFFFF) {
        fprintf(stderr, "thing: invalid idFull: %s\n", sidfull ? sidfull : "(null)");
        return 2;
    }
    const THING *t = find_thing_by_idfull((uint16_t)v);
    if (!t) {
        fprintf(stderr, "thing: not found: 0x%04x\n", (unsigned)v);
        return 2;
    }
    print_thing_detail(t);
    return 0;
}

static int cmd_fleets(void)
{
    if (rglpfl == NULL) {
        fprintf(stderr, "No fleets loaded (rglpfl == NULL).\n");
        return 2;
    }
    printf("Fleets (best-effort per-player lists): cPlayer=%d\n", (int)game.cPlayer);
    for (int16_t iplr = 0; iplr < game.cPlayer; iplr++) {
        const FLEET *f = rglpfl[iplr];
        if (f == NULL) continue;
        printf("-- player %d --\n", (int)iplr);
        while (f != NULL) {
            print_fleet_row(f);
            f = f->lpflNext;
        }
    }
    return 0;
}

static int cmd_fleet(const char *sid)
{
    bool ok;
    int32_t id32 = parse_i32(sid, &ok);
    if (!ok || id32 < -32768 || id32 > 32767) {
        fprintf(stderr, "fleet: invalid id: %s\n", sid ? sid : "(null)");
        return 2;
    }
    const FLEET *f = find_fleet_by_id((int16_t)id32);
    if (!f) {
        fprintf(stderr, "fleet: not found: %d\n", (int)id32);
        return 2;
    }
    print_fleet_detail(f);
    return 0;
}

static int cmd_shdefs(void)
{
    /*
     * Today we only have a reliable global: c_common::rgshdef[16].
     * The real game also has per-player shdef tables (rglpshdef / rglpshdefSB)
     * but these are not fully wired up in the current decompile.
     */
    printf("Ship designs (rgshdef[16]):\n");
    for (int i = 0; i < 16; i++) {
        print_shdef_row(&rgshdef[i], i);
    }
    return 0;
}

static int cmd_shdef(const char *sidx)
{
    bool ok;
    int32_t idx = parse_i32(sidx, &ok);
    if (!ok || idx < 0 || idx >= 16) {
        fprintf(stderr, "shdef: index must be 0..15\n");
        return 2;
    }
    print_shdef_detail(&rgshdef[idx], (int)idx);
    return 0;
}

static int cmd_game(const StarsCli *cli)
{
    char path[1024];
    int64_t sz;

    build_fullpath(path, sizeof(path), cli ? cli->path_base : NULL, cli ? cli->ext : NULL);
    sz = file_size_bytes(path);

    printf("File: %s", path);
    if (sz >= 0) printf(" (%" PRId64 " bytes)", sz);
    printf("\n");

    printf("Game ID: %" PRIu32 ", Turn: %u (Year %u)\n",
           (uint32_t)game.lid,
           (unsigned)game.turn,
           (unsigned)(2400u + (uint16_t)game.turn));

    printf("\nPlayers found:\n");
    for (int16_t iplr = 0; iplr < game.cPlayer; iplr++) {
        const PLAYER *p = &rgplr[iplr];
        /* Skip empty/default slots. */
        if (p->szName[0] == '\0' && p->szNames[0] == '\0' && p->cPlanet == 0 && p->cFleet == 0 && p->cShDef == 0 && p->cshdefSB == 0)
            continue;

        printf("  Player %d: %s (%s)\n", (int)iplr,
               (p->szName[0] != '\0') ? p->szName : "(unnamed)",
               (p->szNames[0] != '\0') ? p->szNames : "(unnamed)");
        printf("    Ships: %u designs, Starbases: %u designs\n", (unsigned)(uint8_t)p->cShDef, (unsigned)p->cshdefSB);
        printf("    Planets: %u, Fleets: %u\n", (unsigned)(uint16_t)p->cPlanet, (unsigned)p->cFleet);
    }

    return 0;
}

static void print_hex_bytes(const uint8_t *pb, size_t cb)
{
    for (size_t i = 0; i < cb; i++) {
        printf("%02x", (unsigned)pb[i]);
    }
}

static int cmd_blocks(const StarsCli *cli)
{
    char path[1024];
    build_fullpath(path, sizeof(path), cli ? cli->path_base : NULL, cli ? cli->ext : NULL);
    return DumpGameFileBlocks(path);
}

/* ------------------------------------------------------------ */

static int do_load(StarsCli *cli)
{
    int16_t ok = FLoadGame((char *)cli->path_base, (char *)cli->ext);
    if (!ok) {
        fprintf(stderr, "FLoadGame failed for base='%s' ext='%s'\n",
                cli->path_base ? cli->path_base : "(null)",
                cli->ext ? cli->ext : "(null)");
        return 1;
    }
    cli->loaded = true;
    return 0;
}

int StarsCli_Run(int argc, char **argv)
{
    StarsCli cli;
    int i = 1;

    memset(&cli, 0, sizeof(cli));
    cli.iPlayer = 0;

    if (argc < 2) {
        print_usage(stderr);
        return 2;
    }

    if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(stdout);
        return 0;
    }

    if (strcmp(argv[1], "load") != 0) {
        fprintf(stderr, "First argument must be 'load'.\n\n");
        print_usage(stderr);
        return 2;
    }
    i++;
    if (i + 1 >= argc) {
        fprintf(stderr, "load requires <base> and <ext>.\n\n");
        print_usage(stderr);
        return 2;
    }
    cli.path_base = argv[i++];
    cli.ext = argv[i++];

    /* optional flags */
    while (i < argc && strncmp(argv[i], "--", 2) == 0) {
        if (strcmp(argv[i], "--player") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--player needs a value\n");
                return 2;
            }
            bool ok;
            int32_t v = parse_i32(argv[i + 1], &ok);
            if (!ok || v < -1 || v > 15) {
                fprintf(stderr, "--player must be -1..15\n");
                return 2;
            }
            cli.iPlayer = (int16_t)v;
            i += 2;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return 2;
    }

    if (i >= argc) {
        fprintf(stderr, "Missing command after load.\n\n");
        print_usage(stderr);
        return 2;
    }

    const char *cmd = argv[i++];

    /* 'blocks' is a raw-dump command: do NOT call FLoadGame (it can fail on
     * partially-supported records). Mirror Houston's blocks behavior.
     */
    if (strcmp(cmd, "blocks") == 0) {
        return cmd_blocks(&cli);
    }

    /* In the real UI load path, idPlayer influences what gets read; for CLI we
     * set the global and then load the file.
     */
    idPlayer = cli.iPlayer;
    {
        int rc = do_load(&cli);
        if (rc != 0) return rc;
    }

    if (strcmp(cmd, "planets") == 0) {
        return cmd_planets();
    } else if (strcmp(cmd, "planet") == 0) {
        if (i >= argc) {
            fprintf(stderr, "planet requires <id>\n");
            return 2;
        }
        return cmd_planet(argv[i]);
    } else if (strcmp(cmd, "things") == 0) {
        return cmd_things();
    } else if (strcmp(cmd, "thing") == 0) {
        if (i >= argc) {
            fprintf(stderr, "thing requires <idfull>\n");
            return 2;
        }
        return cmd_thing(argv[i]);
    } else if (strcmp(cmd, "fleets") == 0) {
        return cmd_fleets();
    } else if (strcmp(cmd, "fleet") == 0) {
        if (i >= argc) {
            fprintf(stderr, "fleet requires <id>\n");
            return 2;
        }
        return cmd_fleet(argv[i]);
    } else if (strcmp(cmd, "shdefs") == 0) {
        return cmd_shdefs();
    } else if (strcmp(cmd, "shdef") == 0) {
        if (i >= argc) {
            fprintf(stderr, "shdef requires <index>\n");
            return 2;
        }
        return cmd_shdef(argv[i]);
    } else if (strcmp(cmd, "game") == 0) {
        return cmd_game(&cli);
    }

    fprintf(stderr, "Unknown command: %s\n\n", cmd);
    print_usage(stderr);
    return 2;
}
