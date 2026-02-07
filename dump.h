#ifndef DUMP_H_
#define DUMP_H_

#include "types.h"

/*
 * Debug/diagnostic helper: dump record blocks from a Stars! file.
 *
 * Opens the file at `path`, iterates blocks, prints each block
 * (type name, numeric type, size, and data).
 *
 * If `fVerbose` is false, output is a compact hex preview.
 * If `fVerbose` is true, output attempts to decode known record payloads
 * (especially .x* log records) into readable fields.
 */
int DumpGameFileBlocksEx(const char *path, bool fVerbose);

/* Back-compat shim (non-verbose). */
int DumpGameFileBlocks(const char *path);

/* Dump all fields of GAME and PLAYER structs (verbose game command). */
void DumpGameStruct(const GAME *g);
void DumpPlayerStruct(const PLAYER *p);

/*
 * Dump all fields of a PLANET struct in a nicely formatted output.
 */
void DumpPlanet(const PLANET *p);

/*
 * Dump all fields of a FLEET struct in a nicely formatted output.
 */
void DumpFleet(const FLEET *f);

/*
 * Dump all fields of a SHDEF struct in a nicely formatted output.
 */
void DumpShDef(const SHDEF *s, int idx);

/* ------------------------------------------------------------------ */
/* Block-level reading and diffing                                     */
/* ------------------------------------------------------------------ */

typedef struct GameBlock {
    uint16_t rt;       /* record type */
    uint16_t cb;       /* payload size */
    uint8_t *data;     /* heap-allocated payload (NULL if cb==0) */
} GameBlock;

typedef struct GameBlockList {
    GameBlock *blocks;
    int        count;
    int        capacity;
} GameBlockList;

/* Read all blocks from a file into a list.  Caller must call FreeGameBlockList(). */
int  ReadGameFileBlocks(const char *path, GameBlockList *out);
void FreeGameBlockList(GameBlockList *list);

/* Field-level struct diffs.  Return number of differences found.
 *
 * Note: DiffGameFileBlocks() compares GAME, PLAYER, plus detailed diffs for
 * planets, fleets, and ship definitions (including starbase ship defs).
 */
int DiffGame(const GAME *a, const GAME *b);
int DiffPlayer(const PLAYER *a, const PLAYER *b, int iplr);

/* Diff two files by loading each via FLoadGame and comparing globals.
 * Returns 0 if identical, 1 if different, 2 on error. */
int DiffGameFileBlocks(const char *pathA, const char *pathB);

#endif /* DUMP_H_ */
