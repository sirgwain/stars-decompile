#ifndef FILE_H_
#define FILE_H_

#include "types.h"
#include "strings.h"

#define cbPlayerSome ((unsigned)&((PLAYER *)0)->idPlanetHome)
#define cbPlayerAll (((unsigned)&((PLAYER *)0)->rgmdRelation[0]))
#define cbrtshdefB (2 * sizeof(uint8_t) + 2 * sizeof(uint16_t)) // ihuldef + wFlags + ibmp + wtEmpty

/* =========================================================================
 * Portable file handle wrapper (replaces Win16 HFILE + _lread/_lclose/_lseek)
 * =========================================================================
 *
 * Keep the global name `hf` so callers don't change.
 */
typedef struct StarsFile
{
    FILE *fp;
    int last_errno; /* capture errno from last open attempt */
} StarsFile;

extern StarsFile hf;

typedef enum MdCheckType
{
    mdInUse = 0x0001,      /* BOF.fInUse */
    mdDone = 0x0002,       /* BOF.fDone */
    mdMulti = 0x0004,      /* BOF.fMulti */
    mdPlayerType = 0x0008, /* PLAYER.fAi */
} MdCheckType;

/* mdOpen flags (passed to StreamOpen / FOpenFile) */
typedef enum MdOpenFlags
{
    mdRead = 0x0020,
    mdNoOpenErr = 0x4000,
} MdOpenFlags;

typedef enum DtFileType
{
    dtXY = 0,   /* Universe file: .xy */
    dtLog = 1,  /* Log file: .xN */
    dtHost = 2, /* Host file: .hst */
    dtTurn = 3, /* Turn file: .mN */
    dtHist = 4, /* History file: .hN */
} DtFileType;

/* dt flag bits (upper bits) */
enum
{
    bitfMulti = 0x2000,  /* multi-part file */
    bitfRewind = 0x1000, /* rewind stream after BOF */
};

/* mask to extract the base dt value */
enum
{
    grbitDtBase = 0x00FF
};

typedef enum RecordType
{
    rtEOF = 0x00, /* decompile: rt == 0 after ReadRt() -> end-of-file handling */

    rtPlr = 0x06,    /* decompile: while (rt == 6) { ReadRtPlr(...) } */
    rtGame = 0x07,   /* you already had this */
    rtBOF = 0x08,    /* original ReadRt(): if (rtBOF) SetFileXorStream(...); decompile: rt == 8 */
    rtMsg = 0x0C,    /* player messages*/
    rtFleetA = 0x10, /* decompile: inside FReadFleet(), rt == 0x10 */
    rtOrderA = 0x13, /* decompile: fleet order records accept 0x13 or 0x14 */
    rtOrderB = 0x14,
    rtString = 0x15, /* decompile: alloc/copy string from rgbCur when rt == 0x15 */

    rtSel = 0x16, /* decompile: after things, if (rt == 0x16) ReadRt(); matches file.c rtSel */

    rtShDef = 0x1a, /* decompile: while (rt == 0x1a) { ... FReadShDef(...) } */

    rtPlanetB = 0x1c, /* decompile: after FReadPlanet(...), if (rt == 0x1c) { ...planet extra... } */

    rtBtlPlan = 0x1e,  /* decompile: while (rt == 0x1e) { ...battle plan... } */
    rtBtlData = 0x1f,  /* decompile: while (rt == 0x1f || rt == 0x27) { ... } */
    rtContinue = 0x27, /* decompile: inside loop: if (rt != 0x27) { ... } matches `rt != rtContinue` */

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

enum
{
    MAJORVER = 2,
    MINORVERMin = 48, /* 0x30 */
    MINORVERMax = 84, /* 0x54 */
};

/* functions */
void FileError(StringId ids);                                                    /* MEMORY_IO:0x4a10 */
void StreamOpen(const char *szFile, int16_t mdOpen);                             /* MEMORY_IO:0x52ae */
void UnpackBattlePlan(uint8_t *lpb, BTLPLAN *lpbtlplan, int16_t iplan);          /* MEMORY_IO:0x40ce */
bool FBadFileError(StringId ids);                                                /* MEMORY_IO:0x524e */
void ReadRtPlr(PLAYER *pplr, uint8_t *pbIn);                                     /* MEMORY_IO:0x05e2 */
void UpdateBattleRecords(void);                                                  /* MEMORY_IO:0x41ac */
bool FReadFleet(FLEET *lpfl);                                                    /* MEMORY_IO:0x3a4c */
bool FLoadGame(const char *pszFileName, char *pszExt);                           /* MEMORY_IO:0x0810 */
bool FReadShDef(RTSHDEF *lprt, SHDEF *lpshdef, int16_t iplrLoad);                /* MEMORY_IO:0x0006 */
void ReadRt(void);                                                               /* MEMORY_IO:0x5168 */
bool FOpenFile(DtFileType dt, int16_t iPlayer, int16_t md);                      /* MEMORY_IO:0x4ac2 */
int16_t AskSaveDialog(void); /* PASCAL */                                        /* MEMORY_IO:0x432a */
void StreamClose(void);                                                          /* MEMORY_IO:0x53cc */
bool FNewTurnAvail(int16_t idPlayer);                                            /* MEMORY_IO:0x4f22 */
void GetFileStatus(int16_t dt, int16_t iPlayer);                                 /* MEMORY_IO:0x4a60 */
bool FReadPlanet(int16_t iPlayer, PLANET *lppl, bool fHistory, bool fPreInited); /* MEMORY_IO:0x3206 */
void PromptSaveGame(void);                                                       /* MEMORY_IO:0x43ee */
bool FCheckFile(DtFileType dt, int16_t iPlayer, uint16_t md);                    /* MEMORY_IO:0x4fb2 */
bool FValidSerialLong(uint32_t lSerial);                                         /* MEMORY_IO:0x48c4 */
void DestroyCurGame(void);                                                       /* MEMORY_IO:0x44b0 */
void RgFromStream(void *rg, uint16_t cb);                                        /* MEMORY_IO:0x53f4 */
bool FBogusLong(uint32_t lSerial);                                               /* MEMORY_IO:0x484c */

#endif /* FILE_H_ */
