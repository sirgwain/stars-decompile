
#include "types.h"

#include "create.h"

/* globals */
uint8_t vrgWormholeMin[5];  /* MEMORY_CREATE:0x0000 */
uint8_t vrgWormholeVar[5];  /* MEMORY_CREATE:0x0006 */
BTLPLAN rgbtlplanT[5];  /* MEMORY_CREATE:0x000c */
char rgNG3Width[9][2];  /* MEMORY_CREATE:0x9d4c */
PLAYER vrgplrComp[6][4];  /* MEMORY_CREATE:0xa370 */
int16_t vrgvcMax[10];  /* MEMORY_CREATE:0xb5a8 */

/* functions */
int16_t CreateStartupShip(int16_t iplr, int16_t idPlanet, int16_t ishdef, int16_t fAddShdef)
{
    int16_t ishMac;
    FLEET * lpfl;

    /* TODO: implement */
    return 0;
}

int16_t GetVCCheck(GAME *pgame, int16_t vc)
{

    /* TODO: implement */
    return 0;
}

void InitBattlePlan(BTLPLAN *lpbtlplan, int16_t iplan, int16_t iplr)
{

    /* TODO: implement */
}

void InitNewGamePlr(int16_t iStepMaxSoFar, int16_t lvlAi)
{
    int16_t i;
    int16_t c;
    uint8_t ch;

    /* TODO: implement */
}

void SetNGWTitle(uint16_t hwnd, int16_t iStep)
{
    int16_t cch;
    char szBuf[50];

    /* TODO: implement */
}

int16_t GetVCVal(GAME *pgame, int16_t vc, int16_t fRaw)
{
    int16_t c;
    int16_t i;
    int16_t val;

    /* TODO: implement */
    return 0;
}

void SetVCCheck(GAME *pgame, int16_t vc, int16_t fChecked)
{

    /* TODO: implement */
}

void CreateTutorWorld(void)
{
    int16_t i;

    /* TODO: implement */
}

int16_t FTrackNewGameDlg3(uint16_t hwnd, POINT pt, int16_t kbd)
{
    int16_t bt;
    int16_t irc;
    BTNT btnt;
    int16_t i;
    int16_t dShift;
    int16_t iMod;
    int16_t iStat;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0xa2cb */

    /* TODO: implement */
    return 0;
}

void NewGameWizard(uint16_t hwnd, int16_t fReadOnly)
{
    int16_t iStepMaxSoFar;
    int16_t mdRet;
    int16_t (* lpProc)(void);
    int16_t fIdleSav;
    int16_t rgplrbmp[16];
    int16_t i;
    int16_t c;
    char szFile[256];
    int16_t idAi;
    int16_t fEasy;
    char szFileLocal[208];
    int16_t j;
    RECT rgrcStack[20];
    PLAYER rgplrLocal[16];
    int16_t lvlAi;
    GAME gameT;

    /* debug symbols */
    /* label Cancel @ MEMORY_CREATE:0x63a3 */
    /* label Finish @ MEMORY_CREATE:0x64e6 */
    /* label Step1 @ MEMORY_CREATE:0x635b */
    /* label Step2 @ MEMORY_CREATE:0x63f5 */

    /* TODO: implement */
}

int16_t NewGameDlg3(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t i;
    RECT rc;
    uint16_t hdc;
    POINT pt;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x9b45 */
    /* block (block) @ MEMORY_CREATE:0x9b88 */
    /* block (block) @ MEMORY_CREATE:0x9bc0 */

    /* TODO: implement */
    return 0;
}

int16_t NewGameDlg2(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t i;
    RECT rc;
    int16_t iNewVal;
    uint16_t hdc;
    POINT pt;
    int16_t iDiamond;
    RECT rcT;
    int16_t dyBut;
    int16_t j;
    int16_t dy;
    char *psz;
    int16_t dyCur;
    int16_t tpm;
    uint16_t hwndBtn;
    int16_t iChecked;
    PAINTSTRUCT ps;
    uint16_t rghmenuSubPopup[14];
    uint16_t hmenuPopup;
    MSG msg;
    int16_t iCurVal;
    RECT * prcSav;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x87e1 */
    /* block (block) @ MEMORY_CREATE:0x89da */
    /* block (block) @ MEMORY_CREATE:0x8a76 */
    /* block (block) @ MEMORY_CREATE:0x8fc8 */
    /* block (block) @ MEMORY_CREATE:0x912e */
    /* block (block) @ MEMORY_CREATE:0x9401 */
    /* label FinishClick @ MEMORY_CREATE:0x93f6 */
    /* label PlaceNew @ MEMORY_CREATE:0x9056 */

    /* TODO: implement */
    return 0;
}

int16_t NewGameDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t i;
    RECT rc;
    uint16_t hdc;
    int16_t iRet;
    RECT rcGBox;
    int16_t c;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x8261 */
    /* block (block) @ MEMORY_CREATE:0x8510 */

    /* TODO: implement */
    return 0;
}

int16_t SimpleNewGameDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t i;
    RECT rc;
    uint16_t hwndDD;
    uint16_t hdc;
    RECT * prcSav;
    RECT rcGBox;
    int16_t dy;
    int16_t c;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x76b9 */
    /* block (block) @ MEMORY_CREATE:0x7858 */
    /* block (block) @ MEMORY_CREATE:0x7cde */

    /* TODO: implement */
    return 0;
}

int16_t SetVCVal(GAME *pgame, int16_t vc, int16_t val)
{
    int16_t cur;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0xb6ba */

    /* TODO: implement */
    return 0;
}

int16_t GenerateWorld(int16_t fBatchMode)
{
    int32_t * pl;
    int16_t iBest;
    int16_t cKill;
    char grUsed[128];
    int16_t (* penvMemSav)[9];
    POINT * ppt;
    int16_t raMajor;
    int16_t k;
    POINT pt;
    int16_t fFound;
    int16_t iMax;
    STARPACK starpack;
    int16_t dy;
    int16_t dGalMinSq;
    int16_t iLow;
    PLANET * lppl;
    int16_t iMin;
    int16_t i;
    int16_t env[9];
    int16_t xOld;
    int16_t iplrSingle;
    POINT * pptMax;
    int16_t dMin;
    int16_t ktLeft;
    SHDEF * lpshdef;
    int32_t lDistMax2;
    int32_t lDistIdeal2;
    int16_t rgi[16];
    int16_t iNewLine;
    uint8_t * pb;
    int16_t dMax;
    int32_t lDistMin2;
    int16_t j;
    int16_t cPlanMax;
    int16_t dx;
    int16_t cKillMax;
    POINT * pptT;
    int32_t lBest;
    int32_t l;
    int16_t iT;
    int16_t jj;
    int16_t iTechMin;
    int16_t pct10;
    int16_t idHome;
    int16_t ishRet;
    THING * lpth;
    char szExt[4];
    uint16_t idLast;
    THING * lpthLast;
    PART part;
    int16_t cFit;
    HS * lphs;
    PLANET * lpplClosest;
    int16_t chs;
    int16_t cTry;
    POINT ptHome;
    PLANET * lpplPicked;
    int32_t lDistCur2;
    int16_t rgTry[5];

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x0cae */
    /* block (block) @ MEMORY_CREATE:0x0cf8 */
    /* block (block) @ MEMORY_CREATE:0x18c3 */
    /* block (block) @ MEMORY_CREATE:0x2028 */
    /* block (block) @ MEMORY_CREATE:0x2d93 */
    /* block (block) @ MEMORY_CREATE:0x2f1f */
    /* block (block) @ MEMORY_CREATE:0x330e */
    /* block (block) @ MEMORY_CREATE:0x3a7a */
    /* block (block) @ MEMORY_CREATE:0x4040 */
    /* block (block) @ MEMORY_CREATE:0x45e6 */
    /* label RetryAll @ MEMORY_CREATE:0x0f9e */
    /* label LConcentrations @ MEMORY_CREATE:0x22d4 */
    /* label LGive2ndPlanet @ MEMORY_CREATE:0x330e */

    /* TODO: implement */
    return 0;
}

PLAYER * LpplrComp(int16_t idAi, int16_t lvlAi)
{

    /* TODO: implement */
    return NULL;
}

int16_t FGetNewGameName(char *szFileSuggest)
{
    char szXY[3];
    uint16_t i;
    char szFileTitle[256];
    char szFile[256];
    char szFilter[256];
    OFN ofn;

    /* TODO: implement */
    return 0;
}

void InitNewGame3(void)
{

    /* TODO: implement */
}

void DrawNewGame3(uint16_t hwnd, uint16_t hdc, int16_t iDraw)
{
    int16_t yTop;
    int16_t bt;
    int16_t vcCur;
    int16_t irc;
    int16_t ids;
    int16_t fCreatedDC;
    int16_t i;
    int16_t dxItem;
    RECT rcCBox;
    int16_t j;
    uint32_t crBkSav;
    int16_t bkMode;
    int16_t dxDig;
    int16_t xLeft;
    int16_t cch;
    RECT rc;

    /* TODO: implement */
}

void DrawNewGame2(uint16_t hwnd, uint16_t hdc, int16_t iDraw)
{
    int16_t fCreatedDC;
    int16_t yCur;
    int16_t i;
    int16_t iPlr;
    int16_t bkMode;
    int16_t cch;
    RECT rcDiamond;
    RECT rc;
    int16_t ids;
    char szT[20];

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x977e */
    /* block (block) @ MEMORY_CREATE:0x97b5 */
    /* label DisplayName @ MEMORY_CREATE:0x996b */

    /* TODO: implement */
}

int16_t GenNewGameFromFile(char *pszFile)
{
    int32_t rgl[10];
    int16_t cPlr;
    int16_t rgplrbmp[16];
    int16_t cNum;
    int16_t c;
    int16_t i;
    int16_t fSuccess;
    char * lpbStart;
    int16_t env[9];
    int16_t j;
    char * lpb;
    char * lpbDef;
    int16_t cb;
    char *pchT;
    int16_t idAi;
    int16_t lvlAi;

    /* debug symbols */
    /* block (block) @ MEMORY_CREATE:0x485f */
    /* block (block) @ MEMORY_CREATE:0x4dc2 */
    /* label LError @ MEMORY_CREATE:0x5e2c */
    /* label LUniDefShort @ MEMORY_CREATE:0x49bd */
    /* label LUniDefError @ MEMORY_CREATE:0x4a15 */
    /* label LUniDefError3 @ MEMORY_CREATE:0x4b5b */
    /* label LCantGetRace @ MEMORY_CREATE:0x4fb4 */
    /* label LBadDefVc @ MEMORY_CREATE:0x509f */

    /* TODO: implement */
    return 0;
}
