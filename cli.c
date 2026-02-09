#include "cli.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "create.h"
#include "dump.h"
#include "file.h"
#include "globals.h"
#include "mdi.h"
#include "memory.h"
#include "port.h"
#include "strings.h"
#include "turn.h"
#include "utilgen.h"

/* ------------------------------------------------------------ */
/* small helpers */

static int64_t file_size_bytes(const char *path) {
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

static void print_usage(FILE *out) {
    fprintf(out, "stars_cli - inspect and generate Stars! save files\n\n"
                 "Usage:\n"
                 "  stars_cli -a <file.def>    Generate a new game from a .def file\n"
                 "  stars_cli -g<N> <game.HST> Generate N turns from host file and exit\n"
                 "  stars_cli load <file> [options] <cmd> [cmd-args]\n\n"
                 "Flags:\n"
                 "  -a                     Generate new game from .def file (Stars! -A flag)\n\n"
                 "Where:\n"
                 "  <file> is the path to a Stars! file (e.g. game/TEST.HST, game/TEST.M1)\n"
                 "         For 'dump' command, use base path without extension (e.g. game/TEST)\n\n"
                 "Options:\n"
                 "  --player N             Set player index (-1..15)\n"
                 "  -v                     Verbose output for list commands\n\n"
                 "Commands:\n"
                 "  planets                List planets (use -v for full details)\n"
                 "  planet <id>            Show a planet\n"
                 "  things                 List things\n"
                 "  thing <idfull>         Show a thing (decimal or hex like 0x1234)\n"
                 "  fleets                 List fleets (use -v for full details)\n"
                 "  fleet <id>             Show a fleet (id/ifl packed field)\n"
                 "  shdefs                 List ship designs (use -v for full details)\n"
                 "  shdef <index>          Show a ship design by index\n"
                 "  game                   Dump loaded game summary\n"
                 "  blocks                 Dump raw record blocks (type/size/data)\n"
                 "  dump                   Dump blocks for all files (.XY, .HST, .M*, .H*)\n"
                 "\n"
                 "Standalone commands (no 'load' required):\n"
                 "  create-tutor [path]         Create a tutorial world (optional base path)\n"
                 "  create-test-world [path]    Create a test world\n"
                 "  diff <file1> <file2>        Diff two files block-by-block\n");
}

static int32_t parse_i32(const char *s, bool *ok) {
    char *end = NULL;
    long  v;

    if (s == NULL || *s == '\0') {
        if (ok)
            *ok = false;
        return 0;
    }

    v = strtol(s, &end, 0 /* base: 0 allows 0x... */);
    if (end == s || (end && *end != '\0')) {
        if (ok)
            *ok = false;
        return 0;
    }
    if (ok)
        *ok = true;
    return (int32_t)v;
}

static const PLANET *find_planet_by_id(int16_t id) {
    int16_t i;
    if (lpPlanets == NULL)
        return NULL;
    for (i = 0; i < cPlanet; i++) {
        if (lpPlanets[i].id == id)
            return &lpPlanets[i];
    }
    return NULL;
}

static const THING *find_thing_by_idfull(uint16_t idFull) {
    int16_t i;
    if (lpThings == NULL)
        return NULL;
    for (i = 0; i < cThing; i++) {
        if (lpThings[i].idFull == idFull)
            return &lpThings[i];
    }
    return NULL;
}

static const FLEET *find_fleet_by_id(int16_t id) {
    /*
     * Fleet storage is a little opaque in this codebase right now.
     * rglpfl is known to be a pointer-to-pointer, and many routines build
     * linked lists via lpflNext. For the CLI we do a best-effort scan:
     * treat rglpfl as an array of per-player head pointers sized by game.cPlayer.
     */
    int16_t iplr;

    if (rglpfl == NULL)
        return NULL;
    for (iplr = 0; iplr < game.cPlayer; iplr++) {
        const FLEET *lpfl = rglpfl[iplr];
        while (lpfl != NULL) {
            if (lpfl->id == id)
                return lpfl;
            lpfl = lpfl->lpflNext;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------ */
/* printing */

static void print_planet_row(const PLANET *p) {
    int16_t    id = p->id;
    STARSPOINT pt = {0, 0};

    /* rgptPlan is indexed by planet id in Stars! (0..998). */
    if (id >= 0 && id < (int16_t)(sizeof(rgptPlan) / sizeof(rgptPlan[0]))) {
        pt = rgptPlan[id];
    }

    printf("%4d  plr=%2d  (%5d,%5d)  det=%3u  hw=%d  sb=%d  pop=%u  fac=%u  min=%u\n", p->id, p->iPlayer, (int)pt.x, (int)pt.y, (unsigned)p->det,
           (int)p->fHomeworld, (int)p->fStarbase, (unsigned)p->uPopGuess, (unsigned)p->cFactories, (unsigned)p->cMines);
}

static void print_thing_row(const THING *t) {
    printf("0x%04x  id=%3u  iplr=%2u  ith=%u  (%5d,%5d)  turn=%u\n", (unsigned)t->idFull, (unsigned)t->id, (unsigned)t->iplr, (unsigned)t->ith, (int)t->pt.x,
           (int)t->pt.y, (unsigned)t->turn);
}

static void print_thing_detail(const THING *t) {
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

static void print_fleet_row(const FLEET *f) {
    const char *name = (f->lpszName != NULL) ? f->lpszName : "";
    printf("%5d  plr=%2d  det=%3u  dead=%d  (%5d,%5d)  idPlanet=%d  plan=%u  name=\"%s\"\n", f->id, f->iPlayer, (unsigned)f->det, (int)f->fDead, (int)f->pt.x,
           (int)f->pt.y, (int)f->idPlanet, (unsigned)f->iplan, name);
}

static void print_shdef_row(const SHDEF *s, int idx) {
    printf("%3d  ishdef=%u  free=%d  gift=%d  det=%u  class=\"%s\"  ihuldef=%d  chs=%u  built=%" PRIu32 " exist=%" PRIu32 "\n", idx, (unsigned)s->ishdef,
           (int)s->fFree, (int)s->fGift, (unsigned)s->det, s->hul.szClass, (int)s->hul.ihuldef, (unsigned)s->hul.chs, (uint32_t)s->cBuilt, (uint32_t)s->cExist);
}

/* ------------------------------------------------------------ */
/* command handlers */

static int cmd_planets(bool fVerbose) {
    if (lpPlanets == NULL) {
        fprintf(stderr, "No planets loaded (lpPlanets == NULL).\n");
        return 2;
    }
    printf("Planets: cPlanet=%d\n", (int)cPlanet);
    for (int16_t i = 0; i < cPlanet; i++) {
        printf("  Planet %d xy: (%d,%d)\n", i, rgptPlan[i].x, rgptPlan[i].y);
    }
    for (int16_t i = 0; i < cPlanet; i++) {
        if (fVerbose) {
            DumpPlanet(&lpPlanets[i]);
            printf("\n");
        } else {
            print_planet_row(&lpPlanets[i]);
        }
    }
    return 0;
}

static int cmd_planet(const char *sid) {
    bool    ok;
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
    DumpPlanet(p);
    return 0;
}

static int cmd_things(void) {
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

static int cmd_thing(const char *sidfull) {
    bool    ok;
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

static int cmd_fleets(bool fVerbose) {
    if (rglpfl == NULL) {
        fprintf(stderr, "No fleets loaded (rglpfl == NULL).\n");
        return 2;
    }
    printf("Fleets: cFleet=%d cPlayer=%d\n", (int)cFleet, (int)game.cPlayer);
    int16_t curPlayer = -1;
    for (int16_t i = 0; i < cFleet; i++) {
        const FLEET *f = rglpfl[i];
        if (f == NULL)
            continue;
        if (f->iPlayer != curPlayer) {
            curPlayer = f->iPlayer;
            printf("-- player %d --\n", (int)curPlayer);
        }
        if (fVerbose) {
            DumpFleet(f);
            printf("\n");
        } else {
            print_fleet_row(f);
        }
    }
    return 0;
}

static int cmd_fleet(const char *sid) {
    bool    ok;
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
    DumpFleet(f);
    return 0;
}

static int cmd_shdefs(bool fVerbose) {
    /*
     * Today we only have a reliable global: c_common::rgshdef[16].
     * The real game also has per-player shdef tables (rglpshdef / rglpshdefSB)
     * but these are not fully wired up in the current decompile.
     */
    printf("Ship designs (rgshdef[16]):\n");
    for (int i = 0; i < 16; i++) {
        if (fVerbose) {
            DumpShDef(&rgshdef[i], i);
            printf("\n");
        } else {
            print_shdef_row(&rgshdef[i], i);
        }
    }
    return 0;
}

static int cmd_shdef(const char *sidx) {
    bool    ok;
    int32_t idx = parse_i32(sidx, &ok);
    if (!ok || idx < 0 || idx >= 16) {
        fprintf(stderr, "shdef: index must be 0..15\n");
        return 2;
    }
    DumpShDef(&rgshdef[idx], (int)idx);
    return 0;
}

static int cmd_game(const CliContext *cli) {
    int64_t     sz;
    const char *path = cli ? cli->file : "(null)";

    sz = file_size_bytes(path);

    printf("File: %s", path);
    if (sz >= 0)
        printf(" (%" PRId64 " bytes)", sz);
    printf("\n");

    printf("Game ID: %" PRIu32 ", Turn: %u (Year %u)\n", (uint32_t)game.lid, (unsigned)game.turn, (unsigned)(2400u + (uint16_t)game.turn));

    if (cli != NULL && cli->fVerbose) {
        printf("\n");
        DumpGameStruct(&game);
    }

    printf("\nPlayers found:\n");
    for (int16_t iplr = 0; iplr < game.cPlayer; iplr++) {
        const PLAYER *p = &rgplr[iplr];
        /* Skip empty/default slots. */
        if (p->szName[0] == '\0' && p->szNames[0] == '\0' && p->cPlanet == 0 && p->cFleet == 0 && p->cShDef == 0 && p->cshdefSB == 0)
            continue;

        printf("  Player %d: %s (%s)\n", (int)iplr, (p->szName[0] != '\0') ? p->szName : "(unnamed)", (p->szNames[0] != '\0') ? p->szNames : "(unnamed)");
        printf("    Ships: %u designs, Starbases: %u designs\n", (unsigned)(uint8_t)p->cShDef, (unsigned)p->cshdefSB);
        printf("    Planets: %u, Fleets: %u\n", (unsigned)(uint16_t)p->cPlanet, (unsigned)p->cFleet);

        if (cli != NULL && cli->fVerbose) {
            DumpPlayerStruct(p);
        }
    }

    return 0;
}

static void print_hex_bytes(const uint8_t *pb, size_t cb) {
    for (size_t i = 0; i < cb; i++) {
        printf("%02x", (unsigned)pb[i]);
    }
}

static int dump_try_file(const CliContext *cli, const char *path_lower, const char *path_upper, int *pFound, int *pErrors) {
    const char *path_use = NULL;

    if (Stars_Access(path_lower, STARS_ACCESS_OK) == 0)
        path_use = path_lower;
    else if (path_upper != NULL && Stars_Access(path_upper, STARS_ACCESS_OK) == 0)
        path_use = path_upper;
    else
        return 0;

    if (pFound)
        (*pFound)++;
    printf("=== %s ===\n", path_use);
    if (DumpGameFileBlocksEx(path_use, cli ? cli->fVerbose : false) != 0) {
        if (pErrors)
            (*pErrors)++;
    }
    printf("\n");
    return 1;
}

static int cmd_blocks(const CliContext *cli) { return DumpGameFileBlocksEx(cli ? cli->file : NULL, cli ? cli->fVerbose : false); }

static int cmd_dump(const CliContext *cli) {
    char path[512];
    char path_up[512];
    int  found = 0;
    int  errors = 0;

    if (cli == NULL || cli->path_base[0] == '\0') {
        fprintf(stderr, "dump: missing base path\n");
        return 2;
    }

    /* .XY file (universe definition) */
    snprintf(path, sizeof(path), "%s.xy", cli->path_base);
    snprintf(path_up, sizeof(path_up), "%s.XY", cli->path_base);
    dump_try_file(cli, path, path_up, &found, &errors);

    /* .HST file (host file) */
    snprintf(path, sizeof(path), "%s.hst", cli->path_base);
    snprintf(path_up, sizeof(path_up), "%s.HST", cli->path_base);
    dump_try_file(cli, path, path_up, &found, &errors);

    /* .M1 - .M16 files (turn files per player) */
    for (int i = 1; i <= 16; i++) {
        snprintf(path, sizeof(path), "%s.m%d", cli->path_base, i);
        snprintf(path_up, sizeof(path_up), "%s.M%d", cli->path_base, i);
        dump_try_file(cli, path, path_up, &found, &errors);
    }

    /* .H1 - .H16 files (history files per player) */
    for (int i = 1; i <= 16; i++) {
        snprintf(path, sizeof(path), "%s.h%d", cli->path_base, i);
        snprintf(path_up, sizeof(path_up), "%s.H%d", cli->path_base, i);
        dump_try_file(cli, path, path_up, &found, &errors);
    }

    /* .X1 - .X16 files (log files per player) */
    for (int i = 1; i <= 16; i++) {
        snprintf(path, sizeof(path), "%s.x%d", cli->path_base, i);
        snprintf(path_up, sizeof(path_up), "%s.X%d", cli->path_base, i);
        dump_try_file(cli, path, path_up, &found, &errors);
    }

    if (found == 0) {
        fprintf(stderr, "dump: no Stars! files found with base path '%s'\n", cli->path_base);
        return 2;
    }

    printf("Dumped %d file(s)", found);
    if (errors > 0)
        printf(" (%d error(s))", errors);
    printf("\n");

    return errors > 0 ? 1 : 0;
}

/* ------------------------------------------------------------ */

static int do_load(CliContext *cli) {
    int16_t ok = FLoadGame(cli->path_base, cli->ext);
    if (!ok) {
        fprintf(stderr, "FLoadGame failed for file='%s'\n", cli->file ? cli->file : "(null)");
        return 1;
    }
    cli->loaded = true;
    return 0;
}

static int do_generate_turns_from_host(const char *host_file, int16_t cTurns) {
    CliContext cli;
    memset(&cli, 0, sizeof(cli));

    if (host_file == NULL || *host_file == '\0') {
        fprintf(stderr, "-g requires a host file (e.g. game/TEST.HST)\n");
        return 2;
    }
    if (cTurns < 0) {
        fprintf(stderr, "-g requires a non-negative turn count\n");
        return 2;
    }

    cli.file = host_file;
    if (!Stars_PathSplitExt(cli.file, cli.path_base, sizeof(cli.path_base), cli.ext, sizeof(cli.ext))) {
        fprintf(stderr, "Invalid file path: %s\n", cli.file);
        return 2;
    }

    /* Host-only: Stars! cannot load a player file when generating turns. */
    if (Stars_stricmp(cli.ext, "HST") != 0) {
        fprintf(stderr, "-g expects a host file (.HST). Got: %s\n", cli.file);
        return 2;
    }

    /* Host context. */
    idPlayer = -1;

    strncpy(szBase, cli.path_base, sizeof(szBase));
    for (int16_t t = 0; t < cTurns; t++) {
        printf("Generating turn %d/%d...\n", (int)(t + 1), (int)cTurns);
        EnsureAis();
        (void)FGenerateTurn();
    }

    return 0;
}

int StarsCli_Run(int argc, char **argv) {
    CliContext cli;
    StarsCli   starscli;
    int        i;

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

    /* ---- Parse flags via Stars_ParseCommandLine ---- */
    if (!Stars_ParseCommandLine(argc, (const char *const *)argv, &starscli)) {
        fprintf(stderr, "Error parsing command line flags.\n\n");
        print_usage(stderr);
        return 2;
    }

    /* ---- Handle -A / -a: generate new game from .def file ---- */
    if (starscli.fNewGame) {
        if (!starscli.startup_file) {
            fprintf(stderr, "-a requires a .def file path.\n\n");
            print_usage(stderr);
            return 2;
        }
        printf("Generating new game from: %s\n", starscli.startup_file);
        int16_t ok = GenNewGameFromFile((char *)starscli.startup_file);
        if (ok) {
            printf("Game generated successfully. Output base: %s\n", szBase);
            return 0;
        } else {
            fprintf(stderr, "GenNewGameFromFile failed.\n");
            return 1;
        }
    }

    /* ---- -g/-G: generate turns from a host file and exit ---- */
    if (starscli.gen_turns >= 0) {
        /* In this mode the positional argument is the host file path (not a subcommand). */
        if (!starscli.startup_file) {
            fprintf(stderr, "-g requires a host file path.\n\n");
            print_usage(stderr);
            return 2;
        }

        /* Disallow mixing with legacy subcommands like `load`. */
        if (strcmp(starscli.startup_file, "load") == 0 || strcmp(starscli.startup_file, "diff") == 0 || strcmp(starscli.startup_file, "create-tutor") == 0 ||
            strcmp(starscli.startup_file, "create-test-world") == 0) {
            fprintf(stderr, "-g cannot be combined with subcommands (use: stars_cli -g<N> <game.HST>)\n\n");
            print_usage(stderr);
            return 2;
        }

        return do_generate_turns_from_host(starscli.startup_file, starscli.gen_turns);
    }

    /* ---- Legacy subcommand handling ---- */
    /* Stars_ParseCommandLine treats the first non-flag arg as startup_file,
       which for legacy commands is the subcommand name (load, diff, etc.) */
    const char *subcmd = starscli.startup_file;
    if (!subcmd) {
        fprintf(stderr, "Missing command.\n\n");
        print_usage(stderr);
        return 2;
    }

    if (strcmp(subcmd, "create-tutor") == 0) {
        /* Find the path arg after "create-tutor" in argv */
        int idx = 0;
        for (int j = 1; j < argc; j++) {
            if (strcmp(argv[j], "create-tutor") == 0) {
                idx = j + 1;
                break;
            }
        }
        if (idx > 0 && idx < argc) {
            strncpy(szBase, argv[idx], sizeof(szBase) - 1);
            szBase[sizeof(szBase) - 1] = '\0';
        } else {
            CchGetString(idsTutorial, szBase);
        }
        CreateTutorWorld();
        printf("Tutorial world created.\n");
        return 0;
    }

    if (strcmp(subcmd, "create-test-world") == 0) {
        int idx = 0;
        for (int j = 1; j < argc; j++) {
            if (strcmp(argv[j], "create-test-world") == 0) {
                idx = j + 1;
                break;
            }
        }
        if (idx > 0 && idx < argc) {
            strncpy(szBase, argv[idx], sizeof(szBase) - 1);
            szBase[sizeof(szBase) - 1] = '\0';
        } else {
            printf("Must specify path\n");
            return 1;
        }
        CreateTinyTestWorld();
        printf("Test world created.\n");
        return 0;
    }

    if (strcmp(subcmd, "diff") == 0) {
        /* Find "diff" in argv, then grab the next two args */
        int idx = 0;
        for (int j = 1; j < argc; j++) {
            if (strcmp(argv[j], "diff") == 0) {
                idx = j + 1;
                break;
            }
        }
        if (idx == 0 || idx + 1 >= argc) {
            fprintf(stderr, "diff requires two file arguments.\n\n");
            print_usage(stderr);
            return 2;
        }
        return DiffGameFileBlocks(argv[idx], argv[idx + 1]);
    }

    if (strcmp(subcmd, "load") != 0) {
        fprintf(stderr, "Unknown command: %s\n\n", subcmd);
        print_usage(stderr);
        return 2;
    }

    /* ---- "load" subcommand: find the file arg and command after it ---- */
    i = 0;
    for (int j = 1; j < argc; j++) {
        if (strcmp(argv[j], "load") == 0) {
            i = j + 1;
            break;
        }
    }
    if (i == 0 || i >= argc) {
        fprintf(stderr, "load requires <file>.\n\n");
        print_usage(stderr);
        return 2;
    }
    cli.file = argv[i++];

    /* Peek ahead to see if the command is 'dump' - it uses base path without extension.
     * This special-case also accepts "-v" after "dump" (mirrors your invocation:
     *   stars_cli load <base> dump -v
     */
    {
        int cmd_idx = i;
        /* Skip optional flags to find the command (we only support --player VALUE here) */
        while (cmd_idx < argc && strncmp(argv[cmd_idx], "--", 2) == 0) {
            if (strcmp(argv[cmd_idx], "--player") == 0)
                cmd_idx += 2;
            else
                break;
        }
        if (cmd_idx < argc && strcmp(argv[cmd_idx], "dump") == 0) {
            /* For dump command, treat file as base path (no extension required) */
            strncpy(cli.path_base, cli.file, sizeof(cli.path_base) - 1);
            cli.path_base[sizeof(cli.path_base) - 1] = '\0';
            cli.ext[0] = '\0';
            /* Consume --player here if present (matches normal option parsing). */
            while (i < argc && strncmp(argv[i], "--", 2) == 0) {
                if (strcmp(argv[i], "--player") == 0) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "--player needs a value\n");
                        return 2;
                    }
                    bool    ok;
                    int32_t v = parse_i32(argv[i + 1], &ok);
                    if (!ok || v < -1 || v > 15) {
                        fprintf(stderr, "--player must be -1..15\n");
                        return 2;
                    }
                    cli.iPlayer = (int16_t)v;
                    i += 2;
                    continue;
                }
                break;
            }
            if (i < argc && strcmp(argv[i], "dump") == 0) {
                i++;
                /* Accept optional -v after dump for convenience. */
                while (i < argc) {
                    if (strcmp(argv[i], "-v") == 0) {
                        cli.fVerbose = true;
                        i++;
                        continue;
                    }
                    fprintf(stderr, "Unknown option after dump: %s\n", argv[i]);
                    return 2;
                }
                return cmd_dump(&cli);
            }
        }
    }

    /* Split file path into base and extension */
    if (!Stars_PathSplitExt(cli.file, cli.path_base, sizeof(cli.path_base), cli.ext, sizeof(cli.ext))) {
        fprintf(stderr, "Invalid file path: %s\n", cli.file);
        return 2;
    }

    /* optional flags */
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "--player") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--player needs a value\n");
                return 2;
            }
            bool    ok;
            int32_t v = parse_i32(argv[i + 1], &ok);
            if (!ok || v < -1 || v > 15) {
                fprintf(stderr, "--player must be -1..15\n");
                return 2;
            }
            cli.iPlayer = (int16_t)v;
            i += 2;
            continue;
        }

        if (strcmp(argv[i], "-v") == 0) {
            cli.fVerbose = true;
            i++;
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
        if (rc != 0)
            return rc;
    }

    if (strcmp(cmd, "planets") == 0) {
        return cmd_planets(cli.fVerbose);
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
        return cmd_fleets(cli.fVerbose);
    } else if (strcmp(cmd, "fleet") == 0) {
        if (i >= argc) {
            fprintf(stderr, "fleet requires <id>\n");
            return 2;
        }
        return cmd_fleet(argv[i]);
    } else if (strcmp(cmd, "shdefs") == 0) {
        return cmd_shdefs(cli.fVerbose);
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
