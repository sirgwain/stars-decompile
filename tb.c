
#include "types.h"

#include "tb.h"

/* globals */
char    vrgTBBtn[29];  /* MEMORY_TB:0x0000 */
int16_t vrgpctZoom[9]; /* MEMORY_TB:0x0da4 */

#ifdef _WIN32

LRESULT CALLBACK TbWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    int16_t     fInside;
    POINT       pt;
    int16_t     ids;
    int16_t     itb;
    PAINTSTRUCT ps;
    int16_t     i;
    int16_t     fCur;
    int16_t     fDown;
    int16_t     iSel;
    int16_t     dx;
    POINT       ptBtn;
    int16_t     j;
    int16_t     x;
    RECT        rc;
    uint16_t    hwndCE;
    int16_t     pct;

    /* debug symbols */
    /* block (block) @ MEMORY_TB:0x002d */
    /* block (block) @ MEMORY_TB:0x00e3 */
    /* label LShowTip @ MEMORY_TB:0x04ac */

    /* TODO: implement */
    return 0;
}

LRESULT CALLBACK FakeComboProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {

    /* TODO: implement */
    return 0;
}

LRESULT CALLBACK FakeCEProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {

    /* TODO: implement */
    return 0;
}

LRESULT CALLBACK TooltipWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    POINT       pt;
    PAINTSTRUCT ps;
    RECT        rc;
    int16_t     bkSav;
    int16_t     cch;

    /* debug symbols */
    /* block (block) @ MEMORY_TB:0x1c41 */
    /* label LKillTip @ MEMORY_TB:0x1c05 */

    /* TODO: implement */
    return 0;
}

void ShowTooltip(StringId ids, RECT *prc) {
    HDC     hdc;
    HFONT   hfontSav;
    int16_t fVisCur;
    int16_t cch;
    int16_t fShowNow;

    /* TODO: implement */
}

void DrawToolbar(HDC hdc, RECT *prc) {
    POINT   pt;
    int16_t i;
    int16_t ibtn;

    /* TODO: implement */
}

int16_t DxOfBtn(int16_t itb) {

    /* TODO: implement */
    return 0;
}

void DrawBitmapButton(HDC hdc, POINT pt, int16_t ibtn, int16_t fDown) {
    int16_t  dx;
    uint16_t hbrBotRight;
    uint16_t hbrTopLeft;
    int16_t  dxDraw;

    /* TODO: implement */
}

void ExecuteButton(int16_t itb, int16_t fDown) {
    uint16_t grbitNew;
    uint16_t grbitSh;
    POINT    pt;
    char    *rgszScan[1];
    int16_t  c;
    int16_t  i;
    uint16_t grbit;
    int16_t  ish;
    int32_t  rgid[9];
    int16_t  iSel;

    /* debug symbols */
    /* block (block) @ MEMORY_TB:0x0e4e */
    /* block (block) @ MEMORY_TB:0x1076 */
    /* block (block) @ MEMORY_TB:0x12fa */
    /* block (block) @ MEMORY_TB:0x1519 */
    /* label LInvalS @ MEMORY_TB:0x12cb */
    /* label LBitDiddle @ MEMORY_TB:0x0df7 */
    /* label LInvalE @ MEMORY_TB:0x14ea */

    /* TODO: implement */
}

int16_t FIsButtonDown(int16_t itb) {

    /* TODO: implement */
    return 0;
}

int16_t ItbFromPpt(POINT *ppt) {
    int16_t i;
    int16_t dx;
    int16_t x;

    /* TODO: implement */
    return 0;
}

void TerminateToolbarFocus(int16_t fCancel) {
    int16_t pct;
    char   *psz;

    /* TODO: implement */
}

#endif /* _WIN32 */
