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

/* dt flag bits (upper bits) */
enum {
    bitfMulti = 0x2000,  /* multi-part file */
    bitfRewind = 0x1000, /* rewind stream after BOF */
};

/* mask to extract the base dt value */
enum { grbitDtBase = 0x00FF };

enum {
    MAJORVER = 2,
    MINORVERMin = 48, /* 0x30 */
    MINORVERMax = 84, /* 0x54 */
};

/* functions */
void    FileError(StringId ids);                                           /* MEMORY_IO:0x4a10 */
void    StreamOpen(const char *szFile, MdOpenFlags mdOpen);                /* MEMORY_IO:0x52ae */
void    UnpackBattlePlan(uint8_t *lpb, BTLPLAN *lpbtlplan, int16_t iplan); /* MEMORY_IO:0x40ce */
bool    FBadFileError(StringId ids);                                       /* MEMORY_IO:0x524e */
void    ReadRtPlr(PLAYER *pplr, uint8_t *pbIn);                            /* MEMORY_IO:0x05e2 */
void    UpdateBattleRecords(void);                                         /* MEMORY_IO:0x41ac */
bool    FReadFleet(FLEET *lpfl);                                           /* MEMORY_IO:0x3a4c */
bool    FLoadGame(const char *pszFileName, char *pszExt);                  /* MEMORY_IO:0x0810 */
bool    FReadShDef(RTSHDEF *lprt, SHDEF *lpshdef, int16_t iplrLoad);       /* MEMORY_IO:0x0006 */
void    ReadRt(void);                                                      /* MEMORY_IO:0x5168 */
bool    FOpenFile(DtFileType dt, int16_t iPlayer, MdOpenFlags md);             /* MEMORY_IO:0x4ac2 */
int16_t AskSaveDialog(void); /* PASCAL */                                  /* MEMORY_IO:0x432a */
void    StreamClose(void);                                                 /* MEMORY_IO:0x53cc */

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
