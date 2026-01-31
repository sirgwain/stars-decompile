
#include "types.h"

#include "popup.h"

#ifdef _WIN32

/* globals */
uint16_t mpimdgrbitBU[8] = {0x0008, 0x0008, 0x0010, 0x0020, 0x0080, 0x0040, 0x0008, 0x0008};

/* functions */
LRESULT CALLBACK PopupWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    PAINTSTRUCT ps;
    RECT        rc;

    /* debug symbols */
    /* label Default @ MEMORY_POPUP:0x00e1 */

    /* TODO: implement */
    return 0;
}

int16_t PopupMenu(HWND hwnd, int16_t x, int16_t y, int16_t cString, int32_t *rgids, char **rgsz, int16_t iChecked, int16_t fRightBtn) {
    char   *pszTitle;
    int16_t tpm;
    POINT   pt;
    int16_t i;
    char    szTemp[128];
    HMENU   hmenuSub;
    HMENU   hmenuPopup;
    char   *pszT;
    char   *psz;
    MSG     msg;
    int16_t fChecked;
    int16_t fCheckedCur;

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x15bf */

    /* TODO: implement */
    return 0;
}

void DrawPopup(HWND hwnd, HDC hdc) {
    COLORREF crBack;
    char     szT[80];
    int16_t  yCur;
    int16_t  i;
    int16_t  c;
    int16_t  bkMode;
    HFONT    hfontSav;
    char    *psz;
    int16_t  dx;
    COLORREF crFore;
    RECT     rc;
    char    *lpsz;
    int16_t  csh;
    int16_t  dpT;
    char     szTB[40];

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x0561 */
    /* block (block) @ MEMORY_POPUP:0x06cc */

    /* TODO: implement */
}

POINT PtDisplayResourceInfo(HDC hdc, int16_t dx, int16_t fPrint) {
    int16_t iMax;
    POINT   pt;
    int16_t ids;
    int16_t y;
    int16_t xMax;
    int16_t i;
    char   *psz;
    int16_t cnt;
    int16_t x;

    /* debug symbols */
    /* label OutOfFor @ MEMORY_POPUP:0x3536 */
    /* label SetQuan @ MEMORY_POPUP:0x346f */

    /* TODO: implement */
    return (POINT){0, 0};
}

POINT PtDisplayPlanetStateInfo(HDC hdc, int16_t fPrint) {
    POINT   pt;
    int16_t y;
    int16_t xMax;
    int16_t cch;
    int16_t x;
    int16_t iNewVal;
    int16_t ids;
    int16_t dChg;
    PLANET *lppl;
    int16_t pctDesireOld;
    int16_t pctDesire;
    int16_t iValSav;
    char    szOut[90];

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x1ebf */
    /* block (block) @ MEMORY_POPUP:0x1f24 */
    /* block (block) @ MEMORY_POPUP:0x2192 */

    /* TODO: implement */
    return (POINT){0, 0};
}

void Popup(HWND hwnd, int16_t x, int16_t y) {
    HDC     hdc;
    POINT   pt;
    int16_t dy;
    int16_t i;
    int16_t c;
    HFONT   hfontSav;
    char   *psz;
    int16_t dx;
    POINT   ptT;
    int16_t dx2;
    int16_t dxDamage;
    int16_t dxName;
    int16_t dxL;
    int16_t dxCoord;
    char   *lpsz;
    int16_t dxR;
    char    szTB[40];

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x0d22 */
    /* block (block) @ MEMORY_POPUP:0x0daa */
    /* block (block) @ MEMORY_POPUP:0x0e46 */
    /* block (block) @ MEMORY_POPUP:0x0fd7 */
    /* label SetDxDy @ MEMORY_POPUP:0x1113 */

    /* TODO: implement */
}

int16_t FIsPopupHullType(int16_t ishdef) {
    uint16_t imd;

    /* TODO: implement */
    return 0;
}

POINT PtDisplayString(HDC hdc, int16_t dx, int16_t fPrint) {
    POINT   pt;
    int16_t y;
    int16_t xMax;
    int16_t x;

    /* TODO: implement */
    return (POINT){0, 0};
}

POINT PtDisplayPlanetPopInfo(HDC hdc, int16_t fPrint) {
    PLANET  pl;
    char    szT[150];
    POINT   pt;
    int16_t y;
    int16_t xMax;
    int16_t c;
    char   *psz;
    int32_t lMax;
    int16_t pctDesire;
    int16_t x;
    int32_t lPopChg;

    /* debug symbols */
    /* block (block) @ MEMORY_POPUP:0x2aac */
    /* label AfterDesire @ MEMORY_POPUP:0x2d3e */

    /* TODO: implement */
    return (POINT){0, 0};
}

POINT PtDisplayZipOrdInfo(HDC hdc, int16_t xCtr, int16_t fPrint) {
    POINT   pt;
    int16_t y;
    int16_t xMax;
    char   *psz;
    int16_t x;

    /* TODO: implement */
    return (POINT){0, 0};
}

POINT PtDisplayFactoryMineInfo(HDC hdc, int16_t dx, int16_t fPrint) {
    char   *pszTypes;
    char    szT[40];
    POINT   pt;
    int16_t ids;
    char   *pszType;
    int16_t y;
    int16_t xMax;
    int16_t i;
    int16_t c;
    char   *psz;
    int16_t cnt;
    int16_t x;

    /* debug symbols */
    /* label LDone @ MEMORY_POPUP:0x3352 */
    /* label SetQuan @ MEMORY_POPUP:0x327d */

    /* TODO: implement */
    return (POINT){0, 0};
}

#endif /* _WIN32 */