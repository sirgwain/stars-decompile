
#include "types.h"

#include "globals.h"
#include "race.h"

/* globals */
int16_t rgRaceAdvDisPts[14] = {-235, -25, -159, -201, 40, -240, -155, 160, 240, 255, 325, 180, 70, 30};
int16_t rgRaceDisEnvPts[6] = {150, 330, 540, 780, 1050, 1380};
int16_t rgRacePrimaryTrait[10] = {40, 95, 45, 10, -100, -150, 120, 180, 90, -66};
char rgRaceStatMax[16] = {25, 15, 25, 25, 25, 15, 25, 6, 2, 2, 2, 2, 2, 2, 9, 0};
char rgRaceStatMin[16] = {7, 5, 5, 5, 5, 2, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0};

#ifdef _WIN32

char rgRW3IStat[7] = {0, 1, 2, 3, 4, 5, 6};
char rgRW3Spacing[7] = {4, 3, 3, 3, 3, 3, 3};
char rgRW3Width[7] = {-2, 2, 2, 2, -2, 2, 2};

#endif /* _WIN32 */

/* functions */

void SetRaceGrbit(PLAYER *pplr, RaceGrbit ibit, int16_t fSet)
{
    uint32_t grMask;

    if (pplr == NULL)
    {
        return;
    }
    if (ibit < 0 || ibit >= 32)
    {
        /* The original code used a 32-bit mask here (16-bit helpers made it
         * look like a wider operation). */
        return;
    }
    grMask = (uint32_t)1u << (uint32_t)ibit;
    if (fSet)
    {
        pplr->grbitAttr |= grMask;
    }
    else
    {
        pplr->grbitAttr &= ~grMask;
    }
}

int16_t GetRaceGrbit(PLAYER *pplr, RaceGrbit ibit)
{
    uint32_t grMask;

    if (pplr == NULL)
    {
        return 0;
    }
    if (ibit < 0 || ibit >= 32)
    {
        return 0;
    }
    grMask = (uint32_t)1u << (uint32_t)ibit;
    return (pplr->grbitAttr & grMask) ? 1 : 0;
}

int16_t CAdvantagePoints(PLAYER *pplr)
{
    int16_t pctGrowth;
    int16_t iSpread;
    int32_t cPoints;
    int16_t cBad;
    int16_t cCur;
    int16_t i;
    int16_t rgi[3];
    int16_t cGood;
    int32_t lInnate;
    int16_t raMajor;
    int16_t cOperate;
    int16_t cProduce;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x4683 */

    /* TODO: implement */
    return 0;
}

int16_t SetRaceStat(PLAYER *pplr, int16_t iStat, int16_t iVal)
{
    int16_t min = (int16_t)(int8_t)rgRaceStatMin[iStat];
    int16_t max = (int16_t)(int8_t)rgRaceStatMax[iStat];

    if (iVal < min)
        iVal = min;
    if (iVal > max)
        iVal = max;

    pplr->rgAttr[iStat] = (int8_t)iVal;
    return iVal;
}

int16_t PctTrueMaxGrowth(int16_t iplr)
{

    /* TODO: implement */
    return 0;
}

int16_t FSaveRace(char *szFileSuggest, PLAYER *pplr)
{
    uint16_t icksum;
    char szFileTitle[256];
    char szDirName[256];
    char szFilter[256];
    uint16_t i;
    char szFile[256];
    // OFN ofn;

    /* TODO: implement */
    return 0;
}

int16_t GetRaceStat(PLAYER *pplr, int16_t iStat)
{
    return pplr->rgAttr[iStat];
}

uint16_t IRaceChecksum(PLAYER *pplr)
{
    uint16_t ick = 0;
    const uint16_t *p = (const uint16_t *)pplr;

#define PLAYER_CHECKSUM_BYTES 192

    for (int i = 0; i < PLAYER_CHECKSUM_BYTES / 2; i++)
        ick ^= p[i];

    return ick;
}

void BoundsCheckPlayer(PLAYER *pplr)
{
    int16_t i;

    /* TODO: implement */
}

void CreateRandomRace(PLAYER *pplr)
{
    int16_t cPts;
    int16_t i;
    int16_t cPass;
    int16_t j;
    int16_t iVal;
    int16_t dAwayNew;
    int16_t dAwayCur;
    int16_t k;
    PLAYER plrT;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x60a0 */
    /* block (block) @ MEMORY_RACE:0x6539 */

    /* TODO: implement */
}

int32_t LInnateRaceHabitability(PLAYER *pplr)
{
    int16_t iTry;
    PLANET pl;
    double l2;
    int16_t rgSteps[3];
    PLAYER plrT;
    int16_t rgDelta[3];
    int16_t fTotalTerra;
    int16_t rgInc[3];
    int16_t i;
    int16_t iTerra;
    int16_t j;
    int32_t l1;
    int16_t rgBase[3];
    double l3;
    int16_t iDelta;
    int32_t pctDesire;
    int16_t k;
    double lInnate;
    int16_t pctTerra;

    /* TODO: implement */
    return 0;
}

int16_t RaMajor(int16_t iplr)
{
    /* rsMajorAdv encodes the primary race attribute (HE/SS/WM/... in Stars!). */
    return GetRaceStat(&rgplr[iplr], rsMajorAdv);
}

#ifdef _WIN32

INT_PTR CALLBACK RaceWizardDlg6(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int16_t i;
    RECT rc;
    HDC hdc;
    PAINTSTRUCT ps;
    int16_t cch;
    RECT rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x3dd9 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg5(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int16_t i;
    RECT rc;
    HWND hwndCtl;
    HDC hdc;
    PAINTSTRUCT ps;
    int16_t cch;
    RECT rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x379d */
    /* block (block) @ MEMORY_RACE:0x38e5 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg4(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int16_t i;
    RECT rc;
    HDC hdc;
    char szT[600];
    int16_t ids;
    PAINTSTRUCT ps;
    int16_t cch;
    RECT rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x3338 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg3(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int16_t i;
    RECT rc;
    HDC hdc;
    POINT pt;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x28ac */
    /* block (block) @ MEMORY_RACE:0x28ef */
    /* block (block) @ MEMORY_RACE:0x2927 */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg2(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int16_t i;
    RECT rc;
    HDC hdc;
    int16_t iVar;
    int16_t yTop;
    POINT pt;
    int16_t dy;
    int16_t dxMiddle;
    int16_t dxLabel;
    int16_t cch;
    char szTemp[20];
    HFONT hfontSav;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x106f */
    /* block (block) @ MEMORY_RACE:0x155e */
    /* block (block) @ MEMORY_RACE:0x159d */
    /* block (block) @ MEMORY_RACE:0x15e0 */
    /* block (block) @ MEMORY_RACE:0x16ac */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK RaceWizardDlg1(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int16_t i;
    RECT rc;
    int16_t iPlrBmp;
    int16_t iOffset;
    PLAYER *pplr;
    HWND hwndCB;
    POINT pt;
    HDC hdc;
    int16_t j;
    char *psz;
    uint8_t k;
    BTNT btnt;
    int16_t bt;
    RECT *prc;
    char szBuf[32];
    int16_t iDir;
    int16_t iCur;
    PAINTSTRUCT ps;
    int16_t cch;
    RECT rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x03bb */
    /* block (block) @ MEMORY_RACE:0x0699 */
    /* block (block) @ MEMORY_RACE:0x06f7 */
    /* block (block) @ MEMORY_RACE:0x08ef */
    /* block (block) @ MEMORY_RACE:0x0937 */
    /* block (block) @ MEMORY_RACE:0x0c31 */
    /* block (block) @ MEMORY_RACE:0x0c76 */
    /* block (block) @ MEMORY_RACE:0x0daa */
    /* block (block) @ MEMORY_RACE:0x0e66 */

    /* TODO: implement */
    return 0;
}

void DrawRaceAdvantagePoints(HDC hdc, RECT *prc, PLAYER *pplr)
{
    TEXTMETRIC tm;
    LOGFONT *plf;
    COLORREF crBkSav;
    int16_t bkMode;
    int16_t dyBig;
    char szAdvantage[32];
    int16_t c;
    COLORREF crSav;
    HFONT hfont;
    int16_t dx;
    int16_t iPts;
    int16_t cch;
    RECT rc;
    HFONT hfontSav;

    /* TODO: implement */
}
int16_t RaceCreationWizard(HWND hwndParent, int16_t fReadOnly, int16_t fDontWrite)
{
    int16_t mdRet;
    int16_t (*lpProc)(void);
    RECT rgrcStack[17];
    int16_t cpts;

    /* debug symbols */
    /* label Step2 @ MEMORY_RACE:0x007d */
    /* label Step3 @ MEMORY_RACE:0x00ea */
    /* label Step4 @ MEMORY_RACE:0x0157 */
    /* label Step5 @ MEMORY_RACE:0x01c4 */
    /* label Step6 @ MEMORY_RACE:0x0231 */
    /* label Step1 @ MEMORY_RACE:0x001c */
    /* label Finish @ MEMORY_RACE:0x029e */

    /* TODO: implement */
    return 0;
}

void DrawRace3(HWND hwnd, HDC hdc, int16_t iDraw)
{
    int16_t dxItem;
    int16_t idsT;
    int16_t fMacintosh;
    int16_t yTop;
    int16_t bt;
    int16_t ids;
    COLORREF crBkSav;
    int16_t bkMode;
    int16_t fCreatedDC;
    int16_t dxkT;
    int16_t i;
    int16_t irc;
    int16_t dxDig;
    int16_t dx;
    int16_t cch;
    RECT rc;

    /* TODO: implement */
}

void InvalidateAdvPtsRect(HWND hwnd)
{
    HDC hdc;
    TEXTMETRIC tm;
    LOGFONT *plf;
    int16_t dyBig;
    HFONT hfont;
    int16_t dx;
    RECT rc;
    HFONT hfontSav;

    /* TODO: implement */
}

void SetRCWTitle(HWND hwnd, int16_t iStep)
{
    char szBuf[50];
    int16_t cch;

    /* TODO: implement */
}

void DrawRace2(HWND hwnd, HDC hdc, int16_t iDraw)
{
    int16_t iPit;
    int16_t bt;
    int16_t iMax;
    char szT[32];
    int16_t dy;
    int16_t iMin;
    int16_t bkMode;
    int16_t fCreatedDC;
    int16_t xRLabel;
    int16_t i;
    int16_t iMod;
    char *psz;
    int16_t dx;
    int16_t cch;
    int16_t bt1;
    RECT rc;
    int32_t l2;
    int16_t iStore;
    int32_t l;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x1d2d */
    /* block (block) @ MEMORY_RACE:0x1e61 */

    /* TODO: implement */
}

int16_t FTrackRaceDlg3(HWND hwnd, POINT pt, int16_t kbd)
{
    BTNT btnt;
    int16_t bt;
    int16_t dShift;
    int16_t i;
    int16_t irc;
    int16_t iMod;
    int16_t iStat;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x3073 */

    /* TODO: implement */
    return 0;
}

int16_t FTrackRaceDlg2(HWND hwnd, POINT pt, int16_t kbd)
{
    BTNT btnt;
    int16_t bt;
    int16_t dShift;
    char iMax;
    char iMin;
    int16_t i;
    int16_t irc;
    int16_t iMod;
    char *psz;
    int16_t dWidth;
    int16_t dx;

    /* debug symbols */
    /* block (block) @ MEMORY_RACE:0x252b */

    /* TODO: implement */
    return 0;
}

int16_t IrcRaceDlgHitTest(POINT pt)
{
    int16_t i;

    /* TODO: implement */
    return 0;
}

#endif /* _WIN32 */
