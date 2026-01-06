
#include "types.h"

#include "popup.h"

/* globals */
uint16_t mpimdgrbitBU[8];  /* MEMORY_POPUP:0x0138 */

/* functions */
int32_t PopupWndProc(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    PAINTSTRUCT ps;
    RECT rc;

    /* debug symbols */
    /* label Default @ MEMORY_POPUP:0x00e1 */

    /* TODO: implement */
    return 0;
}

int16_t PopupMenu(uint16_t hwnd, int16_t x, int16_t y, int16_t cString, int32_t *rgids, char * *rgsz, int16_t iChecked, int16_t fRightBtn)
{
    char *pszTitle;
    int16_t tpm;
    POINT pt;
    int16_t i;
    char szTemp[128];
    uint16_t hmenuSub;
    uint16_t hmenuPopup;
    char *pszT;
    char *psz;
    MSG msg;
    int16_t fChecked;
    int16_t fCheckedCur;

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x15bf */

    /* TODO: implement */
    return 0;
}

void DrawPopup(uint16_t hwnd, uint16_t hdc)
{
    uint32_t crBack;
    char szT[80];
    int16_t yCur;
    int16_t i;
    int16_t c;
    int16_t bkMode;
    uint16_t hfontSav;
    char *psz;
    int16_t dx;
    uint32_t crFore;
    RECT rc;
    char *lpsz;
    int16_t csh;
    int16_t dpT;
    char szTB[40];

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x0561 */
    /* block (block) @ MEMORY_POPUP:0x06cc */

    /* TODO: implement */
}

POINT PtDisplayResourceInfo(uint16_t hdc, int16_t dx, int16_t fPrint)
{
    int16_t iMax;
    POINT pt;
    int16_t ids;
    int16_t y;
    int16_t xMax;
    int16_t i;
    char *psz;
    int16_t cnt;
    int16_t x;

    /* debug symbols */
    /* label OutOfFor @ MEMORY_POPUP:0x3536 */
    /* label SetQuan @ MEMORY_POPUP:0x346f */

    /* TODO: implement */
    return 0;
}

POINT PtDisplayPlanetStateInfo(uint16_t hdc, int16_t fPrint)
{
    POINT pt;
    int16_t y;
    int16_t xMax;
    int16_t cch;
    int16_t x;
    int16_t iNewVal;
    int16_t ids;
    int16_t dChg;
    PLANET * lppl;
    int16_t pctDesireOld;
    int16_t pctDesire;
    int16_t iValSav;
    char szOut[90];

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x1ebf */
    /* block (block) @ MEMORY_POPUP:0x1f24 */
    /* block (block) @ MEMORY_POPUP:0x2192 */

    /* TODO: implement */
    return 0;
}

void Popup(uint16_t hwnd, int16_t x, int16_t y)
{
    uint16_t hdc;
    POINT pt;
    int16_t dy;
    int16_t i;
    int16_t c;
    uint16_t hfontSav;
    char *psz;
    int16_t dx;
    POINT ptT;
    int16_t dx2;
    int16_t dxDamage;
    int16_t dxName;
    int16_t dxL;
    int16_t dxCoord;
    char *lpsz;
    int16_t dxR;
    char szTB[40];

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x0d22 */
    /* block (block) @ MEMORY_POPUP:0x0daa */
    /* block (block) @ MEMORY_POPUP:0x0e46 */
    /* block (block) @ MEMORY_POPUP:0x0fd7 */
    /* label SetDxDy @ MEMORY_POPUP:0x1113 */

    /* TODO: implement */
}

int16_t FIsPopupHullType(int16_t ishdef)
{
    uint16_t imd;

    /* TODO: implement */
    return 0;
}

POINT PtDisplayString(uint16_t hdc, int16_t dx, int16_t fPrint)
{
    POINT pt;
    int16_t y;
    int16_t xMax;
    int16_t x;

    /* TODO: implement */
    return 0;
}

POINT PtDisplayPlanetPopInfo(uint16_t hdc, int16_t fPrint)
{
    PLANET pl;
    char szT[150];
    POINT pt;
    int16_t y;
    int16_t xMax;
    int16_t c;
    char *psz;
    int32_t lMax;
    int16_t pctDesire;
    int16_t x;
    int32_t lPopChg;

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x2aac */
    /* label AfterDesire @ MEMORY_POPUP:0x2d3e */

    /* TODO: implement */
    return 0;
}

POINT PtDisplayZipOrdInfo(uint16_t hdc, int16_t xCtr, int16_t fPrint)
{
    POINT pt;
    int16_t y;
    int16_t xMax;
    char *psz;
    int16_t x;

    /* TODO: implement */
    return 0;
}

POINT PtDisplayFactoryMineInfo(uint16_t hdc, int16_t dx, int16_t fPrint)
{
    char *pszTypes;
    char szT[40];
    POINT pt;
    int16_t ids;
    char *pszType;
    int16_t y;
    int16_t xMax;
    int16_t i;
    int16_t c;
    char *psz;
    int16_t cnt;
    int16_t x;

    /* debug symbols */
    /* label LDone @ MEMORY_POPUP:0x3352 */
    /* label SetQuan @ MEMORY_POPUP:0x327d */

    /* TODO: implement */
    return 0;
}
