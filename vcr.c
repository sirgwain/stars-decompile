
#include "types.h"

#include "vcr.h"

/* functions */
void EnableVCRButtons(void)
{
    int16_t i;

    /* TODO: implement */
}

int16_t PopupVCRMenu(uint16_t hwnd, int16_t x, int16_t y, uint8_t brc)
{
    int16_t fAttack;
    char * rgsz[1];
    int16_t i;
    int16_t c;
    char rgch[1536];
    SHDEF * lpshdef;
    int16_t rgid[40];
    int16_t iChecked;
    int16_t iSel;
    int16_t j;
    char *psz;
    int16_t cch;
    int16_t cKilled;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x477e */

    /* TODO: implement */
    return 0;
}

void DrawVCR(uint16_t hdc, int16_t iStart, int16_t iEnd)
{
    int16_t ctok;
    int16_t ibmpRace;
    int16_t bkMode;
    uint16_t hbrSav;
    int32_t dpShields;
    int16_t itokT;
    int32_t dpT;
    int16_t fCreatedDC;
    int32_t dpArmor;
    int16_t y;
    uint8_t rgfSeen[256];
    int16_t c;
    int16_t i;
    uint8_t brcT;
    SHDEF * lpshdef;
    int16_t ibmp;
    int16_t csh;
    char *psz;
    int16_t dx;
    int16_t j;
    char szT[96];
    int16_t fJam;
    RECT rc;
    int16_t x;
    int16_t cshT;
    DV dv;
    int32_t dpShT;
    int16_t xT;
    int16_t cshNew;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x258e */
    /* block (block) @ MEMORY_VCR:0x2a1b */
    /* block (block) @ MEMORY_VCR:0x38e7 */

    /* TODO: implement */
}

void GetVCRStats(int16_t itok, int32_t *pdpArmor, DV *pdv, int32_t *pdpShields, int16_t *pcsh)
{
    int16_t cshT;
    DV dv;
    int32_t dpShields;
    int32_t dpArmor;
    int16_t i;
    int16_t cshKill;
    uint16_t dpShdef;

    /* TODO: implement */
}

BTLDATA * BtlDataGet(int16_t i)
{
    BTLDATA * lpbd;
    HB * lphb;

    /* TODO: implement */
    return NULL;
}

void BattleVCR(int16_t iBattle)
{
    int16_t (* lpProc)(void);
    int16_t (* penvMemSav)[9];
    int16_t env[9];
    HB * lphb;

    /* debug symbols */
    /* label LCleanup @ MEMORY_VCR:0x0201 */

    /* TODO: implement */
}

int32_t LdpFromItokDv(int16_t itok, DV *lpdv)
{
    DV dv;
    uint16_t dpShdef;
    int16_t csh;
    int32_t dp;

    /* TODO: implement */
    return 0;
}

int32_t CBattleKills(BTLDATA *lpbd, int16_t fOurDead)
{
    int32_t cKilled;
    BTLDATA * lpbdNext;
    int16_t i;
    BTLREC * lpbr;
    int16_t cKill;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x0692 */

    /* TODO: implement */
    return 0;
}

int32_t CBattleUnits(BTLDATA *lpbd, uint16_t grbitBU)
{
    TOK * lptok;
    int16_t ctok;
    int32_t lUnits;
    int16_t i;
    int16_t imd;

    /* TODO: implement */
    return 0;
}

int16_t CBattles(void)
{
    BTLDATA * lpbd;
    HB * lphb;
    int16_t cBattles;

    /* TODO: implement */
    return 0;
}

int16_t SetVCRBoard(int16_t iStep)
{
    TOK * ptok;
    int16_t i;
    int16_t itok;

    /* TODO: implement */
    return 0;
}

int16_t VCRDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    int16_t i;
    int16_t ibtn;
    RECT rc;
    int16_t dyFrame;
    uint8_t brc;
    int16_t iStep;
    POINT pt;
    int16_t dStep;
    int16_t bkMode;
    int16_t iSel;
    RECT rcWindow;
    int16_t bt;
    int16_t dx;
    RECT * prc;
    int16_t iDir;
    int16_t iCur;
    uint32_t crBkSav;
    PAINTSTRUCT ps;
    BTNT btnt;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x0e9f */
    /* block (block) @ MEMORY_VCR:0x1076 */
    /* block (block) @ MEMORY_VCR:0x10e4 */
    /* block (block) @ MEMORY_VCR:0x1138 */
    /* block (block) @ MEMORY_VCR:0x14f7 */
    /* block (block) @ MEMORY_VCR:0x1618 */
    /* block (block) @ MEMORY_VCR:0x1693 */
    /* label GoodSel @ MEMORY_VCR:0x1601 */
    /* label KillTime @ MEMORY_VCR:0x16af */
    /* label NextBtn @ MEMORY_VCR:0x1788 */

    /* TODO: implement */
    return 0;
}

void AnimateAttack(uint16_t hdc)
{
    TOK * ptokSrc;
    TOK * ptokAttack;
    POINT ptBeam1;
    int16_t cFrame;
    int16_t dyFrame;
    POINT ptRay2;
    POINT ptTop;
    uint32_t dwTickLast;
    int16_t dxFrame;
    uint32_t dwTickCur;
    POINT ptBase;
    int16_t dy;
    POINT ptRay1;
    int16_t y;
    POINT ptRight;
    POINT ptDest;
    int16_t iHit;
    uint16_t grfWeapon;
    POINT ptSrc;
    POINT ptTorp;
    POINT ptLeft;
    TIMERINFO ti;
    int16_t iFrame;
    int16_t dx;
    int16_t fKill;
    POINT ptDestBottom;
    POINT ptBeam2;
    POINT ptBottom;
    POINT ptDestTop;
    POINT ptDestRight;
    POINT ptDestLeft;
    int16_t x;
    uint16_t hdcMem;
    uint16_t hbmpSav;
    uint16_t hbmpScreen;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x414d */
    /* label LNextTarget @ MEMORY_VCR:0x3c09 */
    /* label LFinishUp @ MEMORY_VCR:0x43dc */

    /* TODO: implement */
}

void Delay(int16_t ctick)
{
    uint32_t dwTickLast;
    uint32_t dwTickCur;
    TIMERINFO ti;

    /* TODO: implement */
}
