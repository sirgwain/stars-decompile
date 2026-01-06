
#include "types.h"

#include "file.h"

/* functions */
void FileError(int16_t ids)
{

    /* TODO: implement */
}

void StreamOpen(char *szFile, int16_t mdOpen)
{
    uint32_t dwTick;
    OFSTRUCT of;
    int16_t fNoErr;
    uint32_t dwTickCur;

    /* debug symbols */
    /* label Retry @ MEMORY_IO:0x52e1 */

    /* TODO: implement */
}

void UnpackBattlePlan(uint8_t *lpb, BTLPLAN *lpbtlplan, int16_t iplan)
{
    char szTemp[33];
    char szName[33];
    int16_t cch;
    int16_t cOut;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x412a */

    /* TODO: implement */
}

int16_t FBadFileError(int16_t ids)
{

    /* TODO: implement */
    return 0;
}

void ReadRtPlr(PLAYER *pplr, uint8_t *pbIn)
{
    int16_t iOff;
    PLAYER * pplrRaw;
    int16_t cOut;
    char *psz;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x06d2 */
    /* block (block) @ MEMORY_IO:0x0739 */
    /* block (block) @ MEMORY_IO:0x07bb */

    /* TODO: implement */
}

void UpdateBattleRecords(void)
{
    BTLDATA * lpbd;
    BTLREC * lpbr;
    int16_t cKill;
    HB * lphb;
    BTLREC26 * lpbr26;
    int16_t itok;

    /* TODO: implement */
}

int16_t FReadFleet(FLEET *lpfl)
{
    uint16_t us;
    int16_t cord;
    int16_t fByte;
    ORDER * lpord;
    int16_t i;
    int16_t cish;
    uint8_t * pb;
    int16_t cch;
    uint16_t * pus;
    char szT[33];
    int16_t cOut;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x4047 */
    /* label Corrupt @ MEMORY_IO:0x3d24 */

    /* TODO: implement */
    return 0;
}

int16_t FLoadGame(char *pszFileName, char *pszExt)
{
    int16_t iplrSav;
    int16_t cPlanetHist;
    STARPACK sp;
    int16_t cPlanetAlloc;
    int16_t fHaveHistoryData;
    int16_t (* penvMemSav)[9];
    int16_t fSilentSav;
    PLANET * lppl;
    int16_t i;
    THING * lpth;
    FLEET * lpfl;
    int16_t env[9];
    int16_t cturn;
    THING * lpthMac;
    int16_t iPlayer;
    int16_t j;
    PLANET * lpplMac;
    int16_t dt;
    int16_t grf;
    int16_t x;
    int16_t iplr;
    int16_t cThingFile;
    int16_t iP;
    int16_t fWorking;
    POINT pt;
    uint8_t * lpb;
    int16_t isx;
    int16_t fHist;
    int16_t iprod;
    uint16_t turnCur;
    int16_t iFirst;
    int16_t iLast;
    PROD * lpprod;
    int16_t iWarp;
    int16_t fTwo;
    SCOREX sx;
    char szT[256];
    char szIniFile[16];
    char szSection[16];
    char *psz;
    char szEntry[16];

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x089e */
    /* block (block) @ MEMORY_IO:0x1055 */
    /* block (block) @ MEMORY_IO:0x10ce */
    /* block (block) @ MEMORY_IO:0x1312 */
    /* block (block) @ MEMORY_IO:0x2220 */
    /* block (block) @ MEMORY_IO:0x22b7 */
    /* block (block) @ MEMORY_IO:0x256d */
    /* block (block) @ MEMORY_IO:0x27ae */
    /* block (block) @ MEMORY_IO:0x2b29 */
    /* block (block) @ MEMORY_IO:0x2b81 */
    /* block (block) @ MEMORY_IO:0x3051 */
    /* label CorruptHist @ MEMORY_IO:0x0c4e */
    /* label LFoundPlanet @ MEMORY_IO:0x19aa */
    /* label LFoundThing @ MEMORY_IO:0x2710 */
    /* label LNoHistFile @ MEMORY_IO:0x14db */
    /* label Corrupt @ MEMORY_IO:0x285c */
    /* label FreeShdef @ MEMORY_IO:0x1bb1 */
    /* label DoneNow @ MEMORY_IO:0x300e */
    /* label LNextTurn @ MEMORY_IO:0x1587 */
    /* label LError @ MEMORY_IO:0x085e */
    /* label XYCorrupt @ MEMORY_IO:0x0946 */

    /* TODO: implement */
    return 0;
}

int16_t FReadShDef(RTSHDEF *lprt, SHDEF *lpshdef, int16_t iplrLoad)
{
    char szTemp[40];
    SHDEF shdef;
    uint8_t * lpb;
    int16_t ishdef;
    int16_t cch;
    int16_t iFirst;
    int16_t cOut;
    int16_t fOkay;
    HUL * lphulBase;
    uint32_t wt;
    int16_t c;
    HUL * lphul;
    PART part;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x0105 */
    /* block (block) @ MEMORY_IO:0x0181 */
    /* block (block) @ MEMORY_IO:0x0321 */

    /* TODO: implement */
    return 0;
}

void ReadRt(void)
{

    /* TODO: implement */
}

int16_t FOpenFile(uint16_t dt, int16_t iPlayer, int16_t md)
{
    RTBOF rtbof;
    int16_t ids;
    int16_t fCheckMulti;
    int16_t fRewind;
    int16_t fSilentSav;
    int16_t (* penvMemSav)[9];
    int16_t env[9];

    /* debug symbols */
    /* label LBadFile @ MEMORY_IO:0x4c36 */

    /* TODO: implement */
    return 0;
}

int16_t AskSaveDialog(void)
{

    /* TODO: implement */
    return 0;
}

void StreamClose(void)
{

    /* TODO: implement */
}

int16_t FNewTurnAvail(int16_t idPlayer)
{
    uint16_t wGenOld;
    uint16_t turnOld;
    int16_t fNew;

    /* TODO: implement */
    return 0;
}

void GetFileStatus(int16_t dt, int16_t iPlayer)
{

    /* TODO: implement */
}

int16_t FReadPlanet(int16_t iPlayer, PLANET *lppl, int16_t fHistory, int16_t fPreInited)
{
    int16_t fFirstYear;
    int16_t fRouting;
    uint8_t bMask;
    int16_t i;
    uint8_t * pb;
    int16_t idm;
    int16_t pctOpt;
    int16_t pct;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x380d */
    /* label LFinishBRecord @ MEMORY_IO:0x373b */

    /* TODO: implement */
    return 0;
}

void PromptSaveGame(void)
{
    int16_t (* lpProc)(void);
    int16_t fRet;

    /* TODO: implement */
}

int16_t FCheckFile(uint16_t dt, int16_t iPlayer, uint16_t md)
{
    int16_t fReturn;
    int16_t fOpened;
    uint16_t wGenOld;
    int16_t f;
    int16_t fErrSav;

    /* TODO: implement */
    return 0;
}

int16_t FValidSerialLong(uint32_t lSerial)
{
    uint32_t lNumber;
    int16_t i;
    uint32_t lSeries;

    /* TODO: implement */
    return 0;
}

void DestroyCurGame(void)
{
    int16_t i;

    /* TODO: implement */
}

void RgFromStream(void *rg, uint16_t cb)
{

    /* TODO: implement */
}

int16_t FBogusLong(uint32_t lSerial)
{
    int16_t i;

    /* TODO: implement */
    return 0;
}
