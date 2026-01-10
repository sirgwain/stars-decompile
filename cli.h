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

typedef struct StarsCli {
    const char *path_base; /* e.g. "test/data/tiny/2400" */
    const char *ext;       /* e.g. ".m1" or ".p1"; may be "" */
    int16_t     iPlayer;   /* -1 for "host"/no-player loads when supported */
    bool        loaded;
} StarsCli;

int StarsCli_Run(int argc, char **argv);

#endif /* STARS_CLI_H_ */
