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
void FileError(StringId ids);
void StreamOpen(const char *szFile, MdOpenFlags mdOpen);
void UnpackBattlePlan(uint8_t *lpb, BTLPLAN *lpbtlplan, int16_t iplan);
bool FBadFileError(StringId ids);
void ReadRtPlr(PLAYER *pplr, uint8_t *pbIn);
void UpdateBattleRecords(void);
bool FReadFleet(FLEET *lpfl);
bool FLoadGame(const char *pszFileName, char *pszExt);
bool FReadShDef(RTSHDEF *lprt, SHDEF *lpshdef, int16_t iplrLoad);
void ReadRt(void);
bool FOpenFile(DtFileType dt, int16_t iPlayer, MdOpenFlags md);
void StreamClose(void);

bool FNewTurnAvail(int16_t idPlayer);
void GetFileStatus(int16_t dt, int16_t iPlayer);
bool FReadPlanet(int16_t iPlayer, PLANET *lppl, bool fHistory, bool fPreInited);
bool FCheckFile(DtFileType dt, int16_t iPlayer, MdCheckType md);
bool FValidSerialLong(uint32_t lSerial);
void DestroyCurGame(void);
void RgFromStream(void *rg, uint16_t cb);
bool FBogusLong(uint32_t lSerial);

#ifdef _WIN32
void             PromptSaveGame(void);
INT_PTR CALLBACK AskSaveDialog(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
#endif

#endif /* FILE_H_ */
