
#include "types.h"

#include "log.h"

/* functions */
void WriteMemRt(int16_t rt, int16_t cb, void *rg)
{
    HDR hdr;
    uint8_t * lpv;

    /* TODO: implement */
}

int16_t FWriteLogFile(char *pszFileBase, int16_t iPlayer)
{
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    int16_t iCur;
    HDR * lprts;
    RTLOGHDR rtlh;
    MSGPLR * lpmp;
    int16_t cb;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0xce40 */

    /* TODO: implement */
    return 0;
}

void LogMergeFleet(int16_t id)
{
    uint16_t idCur;
    int16_t i;
    uint16_t rgid[512];
    int16_t j;

    /* TODO: implement */
}

int16_t FLoadLogFile(char *pszLog)
{
    uint16_t hres;
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    int16_t fRet;
    int16_t cbLog;
    int16_t iCur;
    MSGPLR * lpmp;
    uint16_t hrsrc;
    int16_t cSkip;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0xc855 */
    /* label BailOut @ MEMORY_PLANET:0xc88f */
    /* label StrOpen @ MEMORY_PLANET:0xc935 */
    /* label FailSuccess @ MEMORY_PLANET:0xc96e */
    /* label Done @ MEMORY_PLANET:0xcc76 */

    /* TODO: implement */
    return 0;
}

void DirtyGame(int16_t fDirty)
{

    /* TODO: implement */
}

void LogSplitFleet(int16_t id)
{

    /* TODO: implement */
}

int16_t FWriteTutorialMFile(int16_t iTurn)
{
    uint16_t hrsrc;
    char szT[30];
    uint16_t hres;
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    int16_t cch;
    int16_t cSkip;

    /* debug symbols */
    /* label BailOut @ MEMORY_PLANET:0xd132 */

    /* TODO: implement */
    return 0;
}

void EnumLogRts(int16_t (*pfn)(void *, int16_t, int16_t, void *, int16_t), void *lpPass, int16_t iPass)
{
    int16_t fLogOld;
    int16_t fRet;
    int16_t iCur;
    HDR * lprts;

    /* TODO: implement */
}

int16_t FGetPrevLogRt(HDR *phdr, uint8_t *pb)
{
    uint8_t * lpv;

    /* TODO: implement */
    return 0;
}

void LogChangeThing(THING *lpth, THING *pthNew)
{
    int16_t i;
    int16_t fChg;
    LOGXFER lxNew;

    /* TODO: implement */
}

void LogChangePlanet(PLANET *ppl, PLANET *pplNew)
{
    int16_t i;
    int16_t fChg;
    HDR hdr;
    LOGXFER lxNew;

    /* debug symbols */
    /* label ChgIt @ MEMORY_PLANET:0x953a */

    /* TODO: implement */
}

int16_t FCheckLogFile(int16_t iplr, int16_t *pfError)
{
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    int16_t fRet;
    int16_t cbLog;
    int16_t iCur;

    /* debug symbols */
    /* label Done @ MEMORY_PLANET:0xcdde */

    /* TODO: implement */
    return 0;
}

void LogChangeBtlplan(BTLPLAN *pbtlplan)
{

    /* TODO: implement */
}

void LogChangeRelations(void)
{
    HDR hdr;

    /* TODO: implement */
}

int16_t FRunLogRecord(int16_t rt, int16_t cb, uint8_t *lpb)
{
    int16_t fExtra;
    int32_t cXfer;
    XFERFULL * lpxfCur;
    PLANET * lppl;
    int32_t rgcXfer[5];
    XFER rgxf[2];
    FLEET * lpfl;
    int16_t ifl;
    int16_t i;
    uint16_t grbit;
    int16_t rgifl[512];
    SHDEF * lpshdef;
    int16_t iPass;
    int16_t iLook;
    PLANET * lpplMac;
    char ch;
    int32_t l;
    int16_t id;
    int16_t iColDrop;
    int16_t idm;
    THING * lpth;
    XFERFULL * lpxfMax;
    COLDROP * lpcdT;
    char szT[33];
    int16_t cOut;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0xa852 */
    /* block (block) @ MEMORY_PLANET:0xa9bc */
    /* block (block) @ MEMORY_PLANET:0xafe5 */
    /* block (block) @ MEMORY_PLANET:0xb131 */
    /* block (block) @ MEMORY_PLANET:0xb329 */
    /* block (block) @ MEMORY_PLANET:0xb645 */
    /* block (block) @ MEMORY_PLANET:0xb6a7 */
    /* label StealCargo @ MEMORY_PLANET:0xb5a2 */
    /* label BombOut @ MEMORY_PLANET:0xc416 */
    /* label DoNext @ MEMORY_PLANET:0xb71d */

    /* TODO: implement */
    return 0;
}

int16_t FWriteHistFile(int16_t iPlayer)
{
    PLANET * lppl;
    int16_t i;
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    uint16_t cTurnBase;
    SHDEF * lpshdef;
    int16_t j;
    RTHISTHDR rthh;
    uint8_t * lpb;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0xd658 */

    /* TODO: implement */
    return 0;
}

void CancelMemRt(int16_t rt)
{

    /* TODO: implement */
}

void LogMakeValidXferf(LOGXFERF *plxf1, LOGXFERF *plxf2)
{
    RTXFERF * prt;
    int16_t iOff;
    int16_t i;
    char rgbuf[41];
    uint16_t grbit;
    int16_t grFlag;
    int16_t cb;

    /* TODO: implement */
}

int16_t FRunLogFile(void)
{
    int16_t fLogOld;
    int16_t fRet;
    int16_t iCur;
    HDR * lprts;

    /* TODO: implement */
    return 0;
}

void LogMakeValidXfer(LOGXFER *plx1, LOGXFER *plx2)
{
    int32_t rgQuan[5];
    RTXFER * prt;
    int16_t iOff;
    RTXFERL * prtl;
    int16_t rt;
    int16_t i;
    char rgbuf[28];
    int16_t grbit;
    RTXFERX * prtx;
    int16_t grFlag;
    int32_t iBiggest;
    int16_t cb;

    /* TODO: implement */
}

void LogChangeFleet(FLEET *pfl, FLEET *pflNew)
{
    int16_t d;
    int16_t i;
    int16_t fChg;
    RTWAYPT rtwp;
    LOGXFER lxNew;
    RTSHIPINT rtsi;
    int16_t iordNew;
    int16_t iordOld;
    int16_t cbWp;
    char * pbWp;
    HDR hdr;
    LOGXFERF lxfNew;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0x8edf */
    /* block (block) @ MEMORY_PLANET:0x8f88 */
    /* block (block) @ MEMORY_PLANET:0x9049 */
    /* block (block) @ MEMORY_PLANET:0x91e7 */
    /* block (block) @ MEMORY_PLANET:0x926b */
    /* label NextTest @ MEMORY_PLANET:0x9337 */

    /* TODO: implement */
}

void LogChangeName(int16_t grobj, int16_t id, char *szName)
{
    FLEET * lpfl;
    int16_t cOut;
    RTCHGNAME rtchgname;

    /* TODO: implement */
}

void LogChangeShDef(SHDEF *lpshdefNew)
{
    uint8_t rgb[149];
    uint8_t * pb;

    /* TODO: implement */
}
