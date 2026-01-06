
#include "types.h"

#include "mdi.h"

/* globals */
uint8_t vrgbShuffleSerial[21];  /* MEMORY_MDI:0x2870 */
char rgTOWidth[2][2];  /* MEMORY_MDI:0x7702 */

/* functions */
void VerifyTurns(void)
{
    int16_t idsError;
    int16_t idCur;
    int16_t cAi;
    int16_t i;
    int16_t cOut;
    int16_t fOut;

    /* TODO: implement */
}

int16_t FSerialAndEnvFromSz(int32_t *plSerial, uint8_t *pbEnv, char *pszIn)
{
    uint8_t rgbRaw[21];
    int16_t fSuccess;
    int16_t j;
    uint8_t bXor;
    int16_t i;
    int16_t cBits;
    int16_t iRaw;
    int16_t iPass;
    int32_t lSerial;
    int32_t lTank;
    uint8_t rgbRaw2[21];
    uint8_t b64;

    /* TODO: implement */
    return 0;
}

void FormatSerialAndEnv(int32_t lSerial, uint8_t *pbEnv, char *pszOut)
{
    uint8_t rgbRaw[21];
    int16_t j;
    uint8_t bXor;
    int16_t i;
    int16_t cBits;
    int16_t iRaw;
    int16_t iPass;
    int32_t lTank;
    uint8_t rgbRaw2[21];
    uint8_t b64;

    /* TODO: implement */
}

void RestoreSelection(void)
{
    PLANET * lppl;

    /* TODO: implement */
}

void RefitFrameChildren(void)
{
    int16_t dyMsg;
    uint16_t hmenu;
    int16_t i;
    int16_t dyMinMin;
    int16_t dyMsgMin;
    int16_t dyMin;
    int16_t dyT;
    int16_t yScanner;
    int16_t dyTot;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x8d56 */
    /* block (block) @ MEMORY_MDI:0x8de6 */
    /* block (block) @ MEMORY_MDI:0x8fb7 */

    /* TODO: implement */
}

int16_t FWasRaceFile(char *szFile, int16_t fChkPass)
{
    int16_t idsError;
    int32_t lSaltSav;
    PLAYER plr;
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    int16_t fRet;
    int16_t fSav;

    /* debug symbols */
    /* label LBadFile @ MEMORY_MDI:0x5dec */

    /* TODO: implement */
    return 0;
}

int16_t HostModeDialog(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t (* lpProc)(void);
    int16_t fRet;
    RECT rc;
    int16_t mf;
    uint16_t hdc;
    POINT pt;
    int16_t tpm;
    int16_t i;
    int16_t iRet;
    int16_t iSel;
    int16_t iDiamond;
    uint16_t hmenuPopup;
    PAINTSTRUCT ps;
    MSG msg;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x6db6 */
    /* block (block) @ MEMORY_MDI:0x71b9 */
    /* label Done @ MEMORY_MDI:0x6d62 */

    /* TODO: implement */
    return 0;
}

void EnsureAis(void)
{
    int16_t fHostSav;
    int16_t fErrSav;
    int16_t fOpened;
    int16_t fWorkDone;
    int16_t fSubmitSav;
    int16_t iPlayer;
    MDPLR rgmdplr[16];

    /* TODO: implement */
}

int16_t FFindSomethingAndSelectIt(void)
{
    PLANET * lpplMac;
    PLANET * lppl;
    int16_t i;
    FLEET * lpfl;

    /* TODO: implement */
    return 0;
}

int16_t CFindTurnsOutstanding(void)
{
    int16_t idsError;
    int16_t cAi;
    int16_t i;
    int16_t cOut;
    int16_t fSav;
    int16_t fOut;

    /* TODO: implement */
    return 0;
}

int32_t TitleWndProc(uint16_t hwnd, uint16_t msg, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    int16_t i;
    uint16_t hpalSav;
    RECT rc;
    int16_t dy;
    int16_t dxGap;
    int16_t dx;
    int16_t xCur;
    char *psz;
    PAINTSTRUCT ps;
    RECT rcWnd;
    uint16_t hbrSav;
    RECT rcT;
    LOGFONT * plf;
    uint16_t hfont;
    uint16_t hfontSav;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x9135 */
    /* block (block) @ MEMORY_MDI:0x9200 */
    /* block (block) @ MEMORY_MDI:0x957e */
    /* block (block) @ MEMORY_MDI:0x95b9 */
    /* block (block) @ MEMORY_MDI:0x967e */
    /* block (block) @ MEMORY_MDI:0x96f0 */
    /* label MapIt @ MEMORY_MDI:0x92e3 */
    /* label Default @ MEMORY_MDI:0x97e2 */
    /* label LOpenGame @ MEMORY_MDI:0x945e */
    /* label LTry16Color @ MEMORY_MDI:0x967e */

    /* TODO: implement */
    return 0;
}

void CommandHandler(uint16_t hwnd, uint16_t wParam)
{
    POINT pt;
    uint16_t hmenu;
    int16_t (* lpProc)(void);
    int16_t dy;
    char szExt[4];
    int16_t dx;
    int16_t fRet;
    RECT rc;
    int16_t iplrOld;
    int16_t cPageX;
    int16_t idCur;
    int16_t mf;
    int16_t id;
    char *psz;
    uint16_t hcurSav;
    int16_t ids;
    PLANET * lpplMac;
    int16_t cObj;
    int16_t ifl;
    PLANET * lppl;
    FLEET * lpfl;
    int16_t i;
    TIMERINFO ti;
    uint32_t dwTickCur;
    uint32_t dwTickBase;
    PD pd;
    int16_t cPageY;
    int16_t xPage;
    int16_t dxMax;
    int16_t dxDPI;
    int16_t dyPrintTiny;
    int16_t dMargin;
    int16_t y;
    int32_t ldx;
    uint16_t hfontPrintTiny;
    uint16_t hfontPrint;
    POINT ptLegendB;
    POINT ptLegendA;
    int16_t dyPrint;
    int16_t dyMax;
    uint16_t hfontSav;
    int16_t dSize;
    int16_t yPage;
    int16_t cch;
    int32_t ldy;
    int16_t dyDPI;
    int16_t yOff;
    int16_t xOff;
    int32_t x;
    char szT[256];

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x3112 */
    /* block (block) @ MEMORY_MDI:0x32e6 */
    /* block (block) @ MEMORY_MDI:0x3387 */
    /* block (block) @ MEMORY_MDI:0x3602 */
    /* block (block) @ MEMORY_MDI:0x39c0 */
    /* block (block) @ MEMORY_MDI:0x3b66 */
    /* block (block) @ MEMORY_MDI:0x3bf0 */
    /* block (block) @ MEMORY_MDI:0x3f6e */
    /* block (block) @ MEMORY_MDI:0x4090 */
    /* block (block) @ MEMORY_MDI:0x440c */
    /* block (block) @ MEMORY_MDI:0x44cc */
    /* block (block) @ MEMORY_MDI:0x451d */
    /* block (block) @ MEMORY_MDI:0x4592 */
    /* block (block) @ MEMORY_MDI:0x461d */
    /* block (block) @ MEMORY_MDI:0x4818 */
    /* block (block) @ MEMORY_MDI:0x4b14 */
    /* block (block) @ MEMORY_MDI:0x4df3 */
    /* label LTutorialFinishUp @ MEMORY_MDI:0x433d */
    /* label LWaitForTurn @ MEMORY_MDI:0x47d1 */
    /* label RepGen @ MEMORY_MDI:0x42d0 */
    /* label Default @ MEMORY_MDI:0x50ba */
    /* label LNewTurnAvail @ MEMORY_MDI:0x4818 */
    /* label LRetryReport @ MEMORY_MDI:0x4504 */

    /* TODO: implement */
}

int32_t FrameWndProc(uint16_t a1, uint16_t a2, uint16_t a3, int32_t a4)
{
    uint16_t hdc;
    int16_t i;
    uint16_t hpalSav;
    int16_t ich;
    int16_t fErrSav;
    int16_t idCur;
    int16_t iOffset;
    uint16_t hcs;
    int16_t id;
    int16_t idPlanet;
    POINT ptOld;
    POINT pt;
    uint16_t uTimerIdOld;
    int16_t grSel;
    char *pch;
    RECT rc;
    char szExt[4];
    int16_t (* lpProc)(void);
    int16_t fRet;
    POINT ptAct;
    RECT rc2;
    int32_t lSerial;
    POINT ptD;
    uint16_t hbrSav;
    POINT ptStart;
    POINT ptChg;
    TEXTMETRIC tm;
    PAINTSTRUCT ps;
    int16_t yOffset;
    char szTemp[80];
    uint16_t hwnd;
    uint16_t wParam;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x06eb */
    /* block (block) @ MEMORY_MDI:0x07f7 */
    /* block (block) @ MEMORY_MDI:0x082c */
    /* block (block) @ MEMORY_MDI:0x0d97 */
    /* block (block) @ MEMORY_MDI:0x0e10 */
    /* block (block) @ MEMORY_MDI:0x0f7f */
    /* block (block) @ MEMORY_MDI:0x10ee */
    /* block (block) @ MEMORY_MDI:0x14c5 */
    /* block (block) @ MEMORY_MDI:0x15f7 */
    /* block (block) @ MEMORY_MDI:0x161b */
    /* block (block) @ MEMORY_MDI:0x1632 */
    /* block (block) @ MEMORY_MDI:0x1691 */
    /* block (block) @ MEMORY_MDI:0x16fc */
    /* block (block) @ MEMORY_MDI:0x1a1f */
    /* block (block) @ MEMORY_MDI:0x1aaa */
    /* label LTryNextBatch @ MEMORY_MDI:0x0a76 */
    /* label LNop @ MEMORY_MDI:0x0d67 */
    /* label LShowStartup @ MEMORY_MDI:0x0cee */
    /* label MapIt @ MEMORY_MDI:0x074c */
    /* label Default @ MEMORY_MDI:0x1d5a */
    /* label LExit @ MEMORY_MDI:0x0af1 */
    /* label LBatchNext @ MEMORY_MDI:0x0a14 */

    /* TODO: implement */
    return 0;
}

void GetWindowRc(uint16_t hwnd, RECT *prc)
{
    WINDOWPLACEMENT wndpl;

    /* TODO: implement */
}

void DrawHostDialog2(uint16_t hwnd, uint16_t hdcIn)
{
    uint32_t dsec;
    uint16_t hdc;
    uint16_t dhour;
    int16_t bkMode;
    int16_t yCur;
    int16_t i;
    uint16_t dmin;
    int16_t dday;
    int16_t cch;
    RECT rcDiamond;
    uint32_t crBackSav;
    int16_t x;
    char szStat[30];

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x6300 */

    /* TODO: implement */
}

void DrawHostOptions(uint16_t hwnd, uint16_t hdc, int16_t iDraw)
{

    /* TODO: implement */
}

void WriteIniSettings(void)
{
    int16_t ctile;
    char szPd[3];
    TILE * rgtile;
    int16_t i;
    int16_t iPass;
    char szEntry[16];
    char szIniFile[16];
    char *psz;
    char szSection[16];
    uint16_t iCol;
    char ch;

    /* TODO: implement */
}

void HostTimerProc(uint16_t hwnd, uint16_t msg, uint16_t idTimer, uint32_t dwTime)
{
    uint16_t hwndT;
    char szExt[4];
    int16_t cOut;
    int16_t fSav;
    int16_t idCur;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x7756 */
    /* label Done @ MEMORY_MDI:0x7997 */
    /* label RedrawText @ MEMORY_MDI:0x7906 */
    /* label Loop @ MEMORY_MDI:0x784a */

    /* TODO: implement */
}

uint16_t GetASubMenu(uint16_t hwnd, int16_t iMenu)
{
    int16_t fChildMenu;
    uint16_t hmenu;

    /* TODO: implement */
    return 0;
}

int16_t FOpenGame(uint16_t hwnd, int16_t fRaceOnly)
{
    OFN ofn;
    uint16_t i;
    char szFile[256];
    char *pch;
    char szFileTitle[256];
    char szFilter[256];
    int16_t fRet;
    int16_t grobjIni;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x5a99 */
    /* block (block) @ MEMORY_MDI:0x5cd3 */
    /* label LGotFileName @ MEMORY_MDI:0x5a99 */

    /* TODO: implement */
    return 0;
}

void InitializeMenu(uint16_t hmenu)
{
    int16_t cMenu;
    int16_t i;
    uint16_t hmenuSub;

    /* TODO: implement */
}

uint16_t HcrsFromFrameWindowPt(POINT pt, int16_t *pgrSel)
{
    uint16_t hcs;
    int16_t fInHBar2;
    int16_t fInHBar1;
    int16_t fInVBar;

    /* TODO: implement */
    return 0;
}

POINT InvertPaneBorder(uint16_t hdc, int16_t grSel, POINT dpt, POINT *pdptPrev)
{
    int16_t notMin;
    int16_t dChg;
    POINT dptT;
    POINT dptPrev;
    int16_t dyAboveMinCur;
    POINT dptOld;
    int16_t dyMsgCur;
    int16_t dyMinAboveH2;
    int16_t dyPlanMin;
    int16_t dxScanMin;
    int16_t x;
    int16_t dyMin;
    POINT pt;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x1e63 */
    /* block (block) @ MEMORY_MDI:0x1f93 */
    /* block (block) @ MEMORY_MDI:0x1fe4 */
    /* block (block) @ MEMORY_MDI:0x20ba */
    /* block (block) @ MEMORY_MDI:0x210e */

    /* TODO: implement */
    return 0;
}

int16_t CTurnsOutSafe(void)
{
    int16_t idPlayerSav;
    int16_t fHostModeSav;
    int16_t fGenSav;
    int16_t cturn;

    /* TODO: implement */
    return 0;
}

void BringUpHostDlg(void)
{
    POINT pt;
    int16_t (* lpProc)(void);
    int16_t fRet;

    /* debug symbols */
    /* label LAutoMode @ MEMORY_MDI:0x60cc */
    /* label Top @ MEMORY_MDI:0x6083 */
    /* label LNextGen @ MEMORY_MDI:0x6120 */

    /* TODO: implement */
}

int16_t HostOptionsDialog(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    RECT rc;
    uint16_t hdc;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x761b */

    /* TODO: implement */
    return 0;
}

int16_t InitMDIApp(void)
{
    WNDCLASS wc;

    /* TODO: implement */
    return 0;
}

void CreateChildWindows(void)
{
    char szData[100];
    POINT pt;
    char *psz;
    char szGame[15];

    /* TODO: implement */
}

void SetWindowIniString(char *sz, uint16_t hwnd)
{
    char ch;
    RECT rc;

    /* TODO: implement */
}
