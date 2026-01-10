#ifndef FILE_H_
#define FILE_H_

#include "types.h"
#include "strings.h"

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

/* mdOpen flags */
#define mdNoOpenErr 0x4000

typedef enum DtFileType
{
    dtTurn = 0, /* Universe file: .xy */
    dtXY = 1,   /* Log file: .xN */
    dtHost = 2, /* Host file: .hst */
    dtLog = 3,  /* Turn file: .mN */
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

/* Stars! record type identifiers (rt*)
 *
 * These values are serialized on disk and MUST NOT CHANGE.
 * Unknown / unnamed rt values are intentionally left without enum symbols.
 */
typedef enum RecordType
{
    rtEOF = 0, /* End of file marker */

    rtOrderA = 1, /* Small cargo transfer (RTXFER) */
    rtOrderB = 2, /* Medium cargo transfer (RTXFERX) */

    /* 3  WaypointDelete */
    /* 4  WaypointAdd (RTWAYPT) */
    /* 5  WaypointChangeTask */

    rtPlr = 6,     /* Player / race data (PLR) */
    rtPlanetB = 7, /* Planet list header (RTHISTHDR) */
    rtBOF = 8,     /* Beginning of file (RTBOF) */
    rtSel = 9,     /* Turn serial / hardware hash (TURNSERIAL) */

    /* 10 WaypointRepeatOrders */
    /* 11 WaypointTaskTypeChange */
    /* 12 Events */

    /* NOTE: rtPlanet / rtPlanetB naming historically inconsistent */
    /* 13 Planet (RTPLANET) */
    /* 14 PartialPlanet (PLANETMINIMAL) */

    rtFleetA = 16, /* Full fleet data */

    /* 17 PartialFleet */

    /* 18 unused */

    /* 19 WaypointTask */
    /* 20 Waypoint (RTWAYPT) */

    rtString = 21, /* Fleet name change (RTCHGNAME) */

    /* 22–25 unused */

    rtShDef = 26, /* Ship / starbase design (RTSHDEF) */
    /* 27 DesignChange (RTCHGSHDEF) */

    rtProdQ = 28, /* Production queue (RTCHGPRODQ) */
    /* 29 ProductionQueueChange */

    rtBtlPlan = 30, /* Battle plan definition */
    rtBtlData = 31, /* Battle record */

    rtGame = 32,    /* Game counters (GAME) */
    rtMsgFilt = 33, /* Message filter settings */

    /* 34–35 unused */

    rtChgPassword = 36, /* Change password */

    /* 37–38 unused */

    rtContinue = 39, /* Battle continuation */

    /* 40 Message */

    rtAiData = 41, /* AI host file record */

    /* 42 unused */

    rtThing = 43, /* Minefields, wormholes, packets (RTLOGTHING) */

    /* 44 unused */

    rtScore = 45, /* Player score data (SCORE) */

    /* 46 SaveAndSubmit */

    rtMax = 47 /* Sentinel / max rt value */
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
