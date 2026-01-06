
#include "types.h"

#include "save.h"

/* functions */
void WriteRt(int16_t rt, int16_t cb, void *rg)
{
    HDR hdr;

    /* TODO: implement */
}

void WriteRtString(char *lpsz)
{
    uint8_t rgb[33];
    int16_t cOut;

    /* TODO: implement */
}

void WriteBOF(int16_t iPlayer, int16_t dt, int16_t fMulti)
{
    RTBOF rtbof;

    /* TODO: implement */
}

void WriteRtShDef(SHDEF *lpshdef, uint8_t * *ppbStore)
{
    uint8_t rgb[147];
    char szHulName[32];
    uint8_t * pb;
    int16_t cOut;

    /* TODO: implement */
}

void WriteBattles(int16_t iPlayer)
{
    int16_t ctok;
    int16_t cbRec;
    PLANET * lppl;
    int16_t i;
    FLEET * lpfl;
    int16_t cbT;
    uint16_t fPlayerCur;
    BTLREC * lpbtlrec;
    uint8_t * lpbBattle;
    HB * lphb;
    BTLDATA * lpbtldata;
    int16_t cb;
    int16_t iplr;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x728a */

    /* TODO: implement */
}

void WriteFleet(FLEET *lpfl)
{
    uint16_t * pus;
    uint8_t rgb[134];
    uint16_t us;
    int16_t i;
    uint8_t * pb;
    int16_t fByte;
    uint16_t grMask;
    int32_t wt;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x8538 */

    /* TODO: implement */
}

void WriteOrders(FLEET *lpfl)
{
    int16_t cord;
    ORDER * lpord;

    /* TODO: implement */
}

void RgToStream(void *rg, uint16_t cb)
{

    /* TODO: implement */
}

void SetSzWorkFromDt(uint16_t dt, int16_t iPlayer)
{
    char *pchSlash;
    int16_t c;
    char *pchDot;

    /* TODO: implement */
}

int16_t FMarkFile(uint16_t dt, int16_t iPlayer, int16_t mdMark, int16_t f)
{
    int16_t ids;
    RTBOF rtbof;
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    int16_t fChange;
    int16_t fSuccess;
    int16_t fSilentSav;
    int32_t lSeedSav2;
    int32_t lSeedSav1;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x92b1 */
    /* label LBadFile @ MEMORY_IO:0x9432 */

    /* TODO: implement */
    return 0;
}

void SetVisPFInit(int16_t iPlr)
{
    PLANET * lpplMac;
    uint16_t detNew;
    PLANET * lppl;
    int16_t j;
    FLEET * lpfl;
    THING * lpth;
    int16_t ifl;
    int16_t i;
    THING * lpthMac;
    int16_t raMajor;
    uint16_t grbitPlr;
    int16_t iSteal;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x9d66 */

    /* TODO: implement */
}

void WriteBattlePlan(BTLPLAN *lpbtlplan, int16_t fLog)
{
    uint8_t rgb[36];
    uint8_t * pb;
    char szPlanName[32];
    int16_t cOut;

    /* TODO: implement */
}

int16_t FWriteDataFile(char *pszFileBase, int16_t iPlayer, int16_t fAppend)
{
    int16_t iMax;
    FLEET * lpflT;
    int16_t fNoAutoTrack;
    BTLPLAN * lpbtlplan;
    int16_t j;
    int16_t (* penvMemSav)[9];
    int16_t i;
    ORDER * lpord;
    THING * lpth;
    FLEET * lpfl;
    int16_t env[9];
    int16_t iord;
    SHDEF * lpshdef;
    THING * lpthMac;
    int16_t fRet;
    PLANET * lpplT;
    SCAN scan;
    int16_t mdTarget;
    FLEET * lpflTarget;
    POINT pt;
    int32_t dy;
    int16_t iflT;
    FLEET * lpflBest;
    int16_t fFoundIdeal;
    int32_t dx;
    int32_t lBest;
    int32_t l;
    PLANET pl;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x5b82 */
    /* block (block) @ MEMORY_IO:0x6975 */
    /* label FreeUp @ MEMORY_IO:0x7035 */
    /* label LAppend @ MEMORY_IO:0x67ab */
    /* label FixupCoords @ MEMORY_IO:0x64d5 */
    /* label LFail @ MEMORY_IO:0x66ca */

    /* TODO: implement */
    return 0;
}

int16_t FAppendFile(int16_t iPlayer)
{

    /* TODO: implement */
    return 0;
}

void SetVisPFFinish(int16_t iPlr)
{
    int16_t detMajor;
    int16_t j;
    int16_t i;

    /* debug symbols */
    /* label LFinShdef @ MEMORY_IO:0xc5ce */
    /* label LFinShdefSB @ MEMORY_IO:0xc7ae */

    /* TODO: implement */
}

int16_t FCreateFile(uint16_t dt, int16_t iPlayer, char *szForceName)
{
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    char *psz;

    /* TODO: implement */
    return 0;
}

void SetVisPFPlanets(int16_t iPlr)
{
    int32_t lRadPlanet2;
    int16_t iRadPlanet;
    PLANET * lpplMac;
    POINT pt;
    int16_t pctCloak;
    PLANET * lppl2;
    int16_t dy;
    FLEET * lpfl2;
    int32_t d2;
    PLANET * lppl;
    int16_t j;
    THING * lpth;
    int32_t lRadius2;
    int16_t i;
    THING * lpthMac;
    int16_t iRadius;
    int16_t fStargateView;
    int16_t dx;
    int32_t l;
    PLANET * lpplMac2;
    uint16_t grbitPlr;
    int16_t rgStargateRange[16];
    int32_t lVis2;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0xb674 */
    /* block (block) @ MEMORY_IO:0xb90e */
    /* label LMarkStargate @ MEMORY_IO:0xb6f7 */
    /* label LMark102 @ MEMORY_IO:0xb9af */
    /* label LThIncPlr2 @ MEMORY_IO:0xb230 */

    /* TODO: implement */
}

void SetVisPFFleets(int16_t iPlr)
{
    PLANET * lpplMac;
    POINT pt;
    int16_t pctCloak;
    int16_t dy;
    FLEET * lpfl2;
    int32_t d2;
    PLANET * lppl;
    int16_t j;
    FLEET * lpfl;
    THING * lpth;
    int32_t lRadius2;
    int16_t ifl;
    THING * lpthMac;
    int16_t iRadius;
    int16_t dx;
    uint16_t grbitPlr;
    int32_t lRadPlanet2;
    int16_t iRadPlanet;
    int16_t iSteal;
    int16_t pctDetect;
    int32_t l;
    int32_t lVis2;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0xa16a */
    /* block (block) @ MEMORY_IO:0xab0c */
    /* label LThIncPlr @ MEMORY_IO:0xa759 */
    /* label LMark101 @ MEMORY_IO:0xabad */

    /* TODO: implement */
}

void WritePlanet(PLANET *lppl, int16_t rt, int16_t fHistory)
{
    uint8_t bMask;
    uint8_t rgb[80];
    uint8_t * pbBase;
    int16_t i;
    uint8_t * pb;

    /* debug symbols */
    /* label LFinishBRecord @ MEMORY_IO:0x7f89 */

    /* TODO: implement */
}

void MarkFleet(FLEET *lpfl, int16_t det)
{
    int16_t i;
    SHDEF * lpshdef;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x887e */

    /* TODO: implement */
}

void MarkPlanet(PLANET *lppl, int16_t iPlr, uint16_t det)
{
    SHDEF * lpshdef;

    /* TODO: implement */
}

void SetVisPFThings(int16_t iPlr)
{
    POINT pt;
    int16_t pctCloak;
    int16_t dy;
    FLEET * lpfl2;
    int32_t d2;
    int16_t j;
    THING * lpth;
    int32_t lRadius2;
    THING * lpthMac;
    int16_t iRadius;
    int16_t dx;
    uint16_t grbitPlr;
    PLANET * lppl2;
    int32_t l;
    THING * lpthMac2;
    THING * lpth2;
    PLANET * lpplMac2;
    int32_t lVis2;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0xba5c */
    /* block (block) @ MEMORY_IO:0xc11c */
    /* block (block) @ MEMORY_IO:0xc244 */
    /* label LThIncPlr3 @ MEMORY_IO:0xbe8e */
    /* label LMark103 @ MEMORY_IO:0xc1bd */

    /* TODO: implement */
}

void WriteRtPlr(PLAYER *pplr, uint8_t *pbStore)
{
    uint8_t rgb[264];
    int16_t i;
    uint8_t * pb;
    int16_t cOut;

    /* TODO: implement */
}

void SetVisiblePlanFleet(int16_t iPlr)
{

    /* TODO: implement */
}
