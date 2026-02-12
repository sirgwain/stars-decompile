#ifndef STARS_CLI_H_
#define STARS_CLI_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * Minimal CLI front-end for the Stars! core API.
 *
 * The core game state is held in globals (see globals.h). The CLI is
 * intentionally thin: it loads a game via FLoadGame() and then provides
 * read-only inspection commands.
 */

typedef struct CliContext {
    const char *file;            /* original file path, e.g. "test/data/test/2400/TEST.HST" */
    char        path_base[1024]; /* parsed: path without extension */
    char        ext[32];         /* parsed: extension without dot */
    int16_t     iPlayer;         /* -1 for "host"/no-player loads when supported */
    bool        loaded;
    bool        fVerbose; /* -v: verbose output for list commands */
} CliContext;

int StarsCli_Run(int argc, char **argv);

#endif /* STARS_CLI_H_ */
