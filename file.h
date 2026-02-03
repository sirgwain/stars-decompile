#ifndef FILE_H_
#define FILE_H_

#include "strings.h"
#include "types.h"

#define cbPlayerSome ((uint16_t)offsetof(PLAYER, idPlanetHome))
#define cbPlayerAll  ((uint16_t)offsetof(PLAYER, rgmdRelation))
#define cbrtshdefB   (2 * sizeof(uint8_t) + 2 * sizeof(uint16_t)) // ihuldef + wFlags + ibmp + wtEmpty

typedef enum MdCheckType {
    mdInUse = 0x0001,      /* BOF.fInUse */
    mdDone = 0x0002,       /* BOF.fDone */
    mdMulti = 0x0004,      /* BOF.fMulti */
    mdPlayerType = 0x0008, /* PLAYER.fAi */
} MdCheckType;

typedef enum DtFileType {
    dtXY = 0,   /* Universe file: .xy */
    dtLog = 1,  /* Log file: .xN */
    dtHost = 2, /* Host file: .hst */
    dtTurn = 3, /* Turn file: .mN */
    dtHist = 4, /* History file: .hN */
} DtFileType;

/* dt flag bits (upper bits) */
enum {
    bitfMulti = 0x2000,  /* multi-part file */
    bitfRewind = 0x1000, /* rewind stream after BOF */
};

/* mask to extract the base dt value */
enum { grbitDtBase = 0x00FF };

typedef enum RecordType {
    /*
     * NOTE: Stars! file records encode a 6-bit "record type" (rt) plus a 10-bit
     * byte count (cb) in a 16-bit header word.
     *
     * In .HST files (and others), record type 0x00 is used for the footer record
     * (cb=2, data=0000). The original code treats "rt==0" as a terminator while
     * reading, so we keep rtEOF=0 for that behavior.
     */
    rtEOF = 0x00,

    rtPlr = 0x06,  /* Player */
    rtGame = 0x07, /* Game */
    rtBOF = 0x08,  /* FileHeader / BOF */
    rtMsg = 0x0C,  /* Message */

    /* Common .HST records (matches Houston blocks output). */
    rtPlanet = 0x0D,
    rtFleet = 0x10,
    rtWaypoint = 0x14,
    rtDesign = 0x1A,
    rtBattlePlan = 0x1E,

    /* Legacy/internal aliases observed in decompilation. */
    rtFleetA = rtFleet,
    rtOrderA = 0x13, /* other order-like record type seen in decompile */
    rtOrderB = rtWaypoint,
    rtString = 0x15, /* decompile: alloc/copy string from rgbCur when rt == 0x15 */

    rtSel = 0x16, /* decompile: after things, if (rt == 0x16) ReadRt(); matches file.c rtSel */

    rtShDef = rtDesign, /* decompile: while (rt == 0x1a) { ... FReadShDef(...) } */

    rtPlanetB = 0x1c, /* decompile: after FReadPlanet(...), if (rt == 0x1c) { ...planet extra... } */

    rtBtlPlan = rtBattlePlan, /* decompile: while (rt == 0x1e) { ...battle plan... } */
    rtBtlData = 0x1f,         /* decompile: while (rt == 0x1f || rt == 0x27) { ... } */
    rtContinue = 0x27,        /* decompile: inside loop: if (rt != 0x27) { ... } matches `rt != rtContinue` */

    rtHistHdr = 0x20, /* decompile: after opening dtHist, expects rt == 0x20 */
    rtMsgFilt = 0x21, /* decompile: checks cbbitfMsg vs cb and memcpy(bitfMsgFiltered, ...) */
    rtProdQ = 0x21,

    rtChgPassword = 0x24, /* file.c: if (hdrCur.rt == rtChgPassword) { lSaltCur = *(long*)rgbCur; } */

    rtPlrMsg = 0x28,
    rtAiData = 0x29, /* decompile: loop skips/reads while (rt == 0x29) around vlpbAiData */

    rtThing = 0x2b, /* decompile: if (rt == 0x2b) { cThing = rgbCur; alloc things } */
    rtScore = 0x2d, /* decompile: loop `if (rt != 0x2d) break;` in score load path */

    rtMax = 46 /* one past highest observed (0x2d) */
} RecordType;

enum {
    MAJORVER = 2,
    MINORVERMin = 48, /* 0x30 */
    MINORVERMax = 84, /* 0x54 */
};

/* functions */
void    FileError(StringId ids);                                           /* MEMORY_IO:0x4a10 */
void    StreamOpen(const char *szFile, int16_t mdOpen);                    /* MEMORY_IO:0x52ae */
void    UnpackBattlePlan(uint8_t *lpb, BTLPLAN *lpbtlplan, int16_t iplan); /* MEMORY_IO:0x40ce */
bool    FBadFileError(StringId ids);                                       /* MEMORY_IO:0x524e */
void    ReadRtPlr(PLAYER *pplr, uint8_t *pbIn);                            /* MEMORY_IO:0x05e2 */
void    UpdateBattleRecords(void);                                         /* MEMORY_IO:0x41ac */
bool    FReadFleet(FLEET *lpfl);                                           /* MEMORY_IO:0x3a4c */
bool    FLoadGame(const char *pszFileName, char *pszExt);                  /* MEMORY_IO:0x0810 */
bool    FReadShDef(RTSHDEF *lprt, SHDEF *lpshdef, int16_t iplrLoad);       /* MEMORY_IO:0x0006 */
void    ReadRt(void);                                                      /* MEMORY_IO:0x5168 */
bool    FOpenFile(DtFileType dt, int16_t iPlayer, int16_t md);             /* MEMORY_IO:0x4ac2 */
int16_t AskSaveDialog(void); /* PASCAL */                                  /* MEMORY_IO:0x432a */
void    StreamClose(void);                                                 /* MEMORY_IO:0x53cc */

/*
 * Debug/diagnostic helper: dump raw record blocks from a Stars! file.
 *
 * Opens the file at `path`, iterates records with ReadRt(), prints each block
 * (type name, numeric type, size, and hex data), then closes the file.
 * Returns 0 on success, non-zero on failure.
 */
int  DumpGameFileBlocks(const char *path);
bool FNewTurnAvail(int16_t idPlayer);                                            /* MEMORY_IO:0x4f22 */
void GetFileStatus(int16_t dt, int16_t iPlayer);                                 /* MEMORY_IO:0x4a60 */
bool FReadPlanet(int16_t iPlayer, PLANET *lppl, bool fHistory, bool fPreInited); /* MEMORY_IO:0x3206 */
void PromptSaveGame(void);                                                       /* MEMORY_IO:0x43ee */
bool FCheckFile(DtFileType dt, int16_t iPlayer, MdCheckType md);                 /* MEMORY_IO:0x4fb2 */
bool FValidSerialLong(uint32_t lSerial);                                         /* MEMORY_IO:0x48c4 */
void DestroyCurGame(void);                                                       /* MEMORY_IO:0x44b0 */
void RgFromStream(void *rg, uint16_t cb);                                        /* MEMORY_IO:0x53f4 */
bool FBogusLong(uint32_t lSerial);                                               /* MEMORY_IO:0x484c */

#endif /* FILE_H_ */
