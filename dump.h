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

#endif /* DUMP_H_ */
