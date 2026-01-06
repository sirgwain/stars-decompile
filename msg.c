
#include "types.h"

#include "msg.h"

/* globals */
char aMSGCmpr[22836];  /* MEMORY_MSG:0x0000 */
uint8_t acMSG[387];  /* MEMORY_MSG:0x5934 */
int16_t aiMSGChunkOffset[7];  /* MEMORY_MSG:0x5ab8 */
char rgMSGLookupTable[72];  /* MEMORY_MSG:0x5ac6 */
char rgcMsgArgs[387];  /* MEMORY_MSG:0x5b0e */

/* functions */
int16_t FFindPlayerMessage(int16_t iPlr, int16_t iMsg, int16_t iObj)
{
    uint8_t * lpbMax;
    uint8_t * lpb;

    /* TODO: implement */
    return 0;
}

int16_t FGetNMsgbig(int16_t iMsg, MSGBIG *pmb)
{
    uint8_t * lpbMax;
    int16_t iMax;
    MSGHDR * lpmh;
    int16_t i;
    uint8_t * lpb;
    uint16_t u;

    /* TODO: implement */
    return 0;
}

void DecorateMsgTitleBar(uint16_t hdc, RECT *prc)
{
    int16_t xDst;
    int16_t ySrcMask;
    uint16_t hbrSav;
    uint16_t hbmpSav;
    int16_t dySrc;
    int16_t i;
    uint16_t hdcMem;
    int16_t idm;
    int16_t ySrc;
    int16_t yDst;
    int16_t dxSrc;
    int16_t xyStart;
    uint32_t crBkSav;
    uint32_t crTextSav;

    /* debug symbols */
    /* label Cleanup @ MEMORY_MSG:0x7cbf */
    /* label DoMinMax @ MEMORY_MSG:0x7b18 */

    /* TODO: implement */
}

int16_t PackageUpMsg(uint8_t *pb, int16_t iPlr, int16_t iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7)
{
    int16_t * pi;
    int16_t i;
    uint16_t grbit;
    MSGTURN * lpmt;
    uint8_t * lpb;
    uint8_t * lpbBase;

    /* TODO: implement */
    return 0;
}

char * PszGetMessageN(int16_t iMsg)
{
    MSGBIG mb;
    char *psz;

    /* TODO: implement */
    return NULL;
}

int16_t IdmGetMessageN(int16_t iMsg)
{
    MSGBIG mb;

    /* TODO: implement */
    return 0;
}

int16_t FFinishPlrMsgEntry(int16_t dInc)
{
    uint8_t * lpbMsg;
    int16_t i;
    int16_t cbNew;
    int16_t iPlrTo;
    MSGPLR * lpmpCur;
    MSGPLR * lpmpPrev;
    int16_t cb;

    /* TODO: implement */
    return 0;
}

void SetMsgTitle(uint16_t hwnd)
{
    int16_t cMsgTot;
    int16_t i;
    MSGBIG mb;
    char ch;
    char szT[80];
    int16_t sw;
    MSGPLR * lpmp;
    RECT rc;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x732e */
    /* label FinishUp @ MEMORY_MSG:0x77de */

    /* TODO: implement */
}

void MarkPlanetsPlayerLost(int16_t iPlayer)
{
    uint8_t * lpbMax;
    PLANET * lppl;
    uint8_t * lpbT;
    uint16_t w;
    uint8_t * lpb;

    /* debug symbols */
    /* label LLookupPlanet @ MEMORY_MSG:0x9489 */

    /* TODO: implement */
}

char * PszFormatMessage(int16_t idm, int16_t *pParams)
{

    /* TODO: implement */
    return NULL;
}

int16_t FSendPlrMsg2XGen(int16_t fPrepend, int16_t iMsg, int16_t iObj, int16_t p1, int16_t p2)
{
    uint8_t rgb[64];
    int16_t * pi;
    int16_t i;
    uint16_t grbit;
    uint8_t * pb;
    uint16_t cSize;
    MSGHDR * pmsghdr;

    /* TODO: implement */
    return 0;
}

void SetFilteringGroups(int16_t idm, int16_t fSet)
{
    int16_t i;

    /* TODO: implement */
}

int16_t FSendPlrMsg2(int16_t iPlr, int16_t iMsg, int16_t iObj, int16_t p1, int16_t p2)
{

    /* TODO: implement */
    return 0;
}

void ReadPlayerMessages(void)
{
    uint8_t * lpbMax;
    int16_t iMax;
    int16_t fOOM;
    int16_t (* penvMemSav)[9];
    MSGHDR * lpmh;
    uint16_t imemMsgT;
    int16_t i;
    int16_t env[9];
    MSGPLR * lpmp;
    uint8_t * lpb;
    uint16_t u;

    /* debug symbols */
    /* label LOutOfMem @ MEMORY_MSG:0x9bb2 */

    /* TODO: implement */
}

int16_t FSendPrependedPlrMsg(int16_t iPlr, int16_t iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7)
{
    uint8_t rgbWork[40];
    int16_t cbMsg;

    /* TODO: implement */
    return 0;
}

void MarkPlayersThatSentMsgs(int16_t iPlayer)
{
    MSGPLR * lpmp;

    /* TODO: implement */
}

void ResetMessages(void)
{

    /* TODO: implement */
}

int16_t FRemovePlayerMessage(int16_t iPlr, int16_t iMsg, int16_t iObj)
{
    uint8_t * lpbMax;
    uint8_t * lpb;
    int16_t cDel;

    /* TODO: implement */
    return 0;
}

char * PszFormatString(char *pszFormat, int16_t *pParamsReal)
{
    int16_t iMineral;
    int16_t cOut;
    int16_t c;
    int16_t i;
    int16_t * pParams;
    char *pchT;
    char szBuf[480];
    uint16_t w;
    char *pch;
    int32_t l;
    SHDEF * lpshdef;
    PART part;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x8b5e */
    /* block (block) @ MEMORY_MSG:0x8cfd */
    /* block (block) @ MEMORY_MSG:0x8db5 */
    /* label DoPlanet @ MEMORY_MSG:0x8ad8 */
    /* label DoFleet @ MEMORY_MSG:0x8b26 */
    /* label LThingName @ MEMORY_MSG:0x8bec */
    /* label DoInt @ MEMORY_MSG:0x87c9 */
    /* label FinishString @ MEMORY_MSG:0x8ae9 */
    /* label DoNothing @ MEMORY_MSG:0x8b07 */

    /* TODO: implement */
    return NULL;
}

char * PszGetCompressedMessage(int16_t idm)
{
    int16_t iBuild;
    int16_t iNibble;
    int16_t i;
    int16_t iLen;
    char *pchLen;
    int16_t iOffset;
    char *pszOut;
    int16_t fHigh;
    char *pch;
    int16_t iChunk;

    /* TODO: implement */
    return NULL;
}

int16_t MsgDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    RECT rc;
    uint16_t hdc;
    POINT pt;
    RECT rcEdit;
    int16_t cch;
    char szT[256];
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x8f77 */
    /* block (block) @ MEMORY_MSG:0x9031 */

    /* TODO: implement */
    return 0;
}

void WritePlayerMessages(int16_t iPlayer)
{
    uint8_t * lpbMax;
    uint8_t rgb[1024];
    int16_t cbMsg;
    MSGPLR * lpmp;
    uint8_t * lpb;

    /* TODO: implement */
}

int16_t HtMsgBox(POINT pt)
{
    int16_t i;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x7e19 */

    /* TODO: implement */
    return 0;
}

int16_t IMsgPrev(int16_t fFilteredOnly)
{
    int16_t i;
    int16_t idm;

    /* TODO: implement */
    return 0;
}

int16_t IMsgNext(int16_t fFilteredOnly)
{
    int16_t i;
    int16_t idm;

    /* TODO: implement */
    return 0;
}

char * PszFormatIds(int16_t ids, int16_t *pParams)
{

    /* TODO: implement */
    return NULL;
}

int16_t FSendPlrMsg(int16_t iPlr, int16_t iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7)
{
    uint8_t rgbWork[40];
    int16_t cbMsg;
    uint8_t * lpb;

    /* TODO: implement */
    return 0;
}

int32_t MessageWndProc(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    int16_t i;
    char *psz;
    PAINTSTRUCT ps;
    int16_t dy;
    int16_t idm;
    int16_t dx;
    POINT pt;
    char *lpsz;
    THING * lpth;
    int16_t (* lpProc)(void);
    uint16_t hcs;
    int16_t ht;
    uint16_t hbrSav;
    int16_t fRet;
    RECT rc;
    int16_t fSet;
    MSGPLR * lpmp;
    uint32_t crFore;
    int32_t lSerial;
    int16_t dxMax;
    MSGPLR * lpmpSrc;
    uint32_t crBack;
    SCAN scan;
    RECT rcActual;
    int16_t cch;
    int16_t iMode;
    char szT[32];
    MSGPLR * lpmsgplr;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x5ef1 */
    /* block (block) @ MEMORY_MSG:0x6059 */
    /* block (block) @ MEMORY_MSG:0x6084 */
    /* block (block) @ MEMORY_MSG:0x60cf */
    /* block (block) @ MEMORY_MSG:0x6109 */
    /* block (block) @ MEMORY_MSG:0x62c6 */
    /* block (block) @ MEMORY_MSG:0x643a */
    /* block (block) @ MEMORY_MSG:0x65ec */
    /* block (block) @ MEMORY_MSG:0x6aff */
    /* block (block) @ MEMORY_MSG:0x6db8 */
    /* block (block) @ MEMORY_MSG:0x6ea6 */
    /* block (block) @ MEMORY_MSG:0x6eca */
    /* block (block) @ MEMORY_MSG:0x6fee */
    /* block (block) @ MEMORY_MSG:0x704c */
    /* block (block) @ MEMORY_MSG:0x70fd */
    /* label SetupNewMsg @ MEMORY_MSG:0x6c2a */
    /* label Default @ MEMORY_MSG:0x718a */
    /* label CheckBox @ MEMORY_MSG:0x6109 */
    /* label ZoomBox @ MEMORY_MSG:0x61cc */
    /* label NextMsg @ MEMORY_MSG:0x6ca9 */
    /* label PrevMsg @ MEMORY_MSG:0x6ba0 */
    /* label ToggleMsgMode @ MEMORY_MSG:0x6298 */
    /* label GotoMsg @ MEMORY_MSG:0x6d8d */

    /* TODO: implement */
    return 0;
}
