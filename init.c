
#include "types.h"

#include "init.h"

#ifdef _WIN32
/* globals */
uint8_t rgPalGray[20] = {0x0a, 0x14, 0x1e, 0x28, 0x3d, 0x47, 0x51, 0x5c, 0x70, 0x7a, 0x85, 0x8f, 0xa1, 0xab, 0xb6, 0xc1, 0xd7, 0xe1, 0xeb, 0xf5};

/* functions */
bool FCreateStuff(void)
{
    int16_t fFailed;
    int16_t dy;
    int16_t i;
    uint16_t hbmp;
    int16_t dx;

    /* TODO: implement */
    return 0;
}

bool FCreateFonts(HDC hdc)
{
    int16_t i;
    LOGFONT *plf;
    uint16_t hfontSav;
    TEXTMETRIC tm;
    int32_t l;

    /* TODO: implement */
    return 0;
}

void ReadIniTileSettings(char *pszFormat, TILE *rgtile, int16_t ctile)
{
    TILE tile;
    int16_t fPopped;
    int16_t i;
    int16_t iTile;
    uint16_t iCol;
    uint16_t iBit;

    /* debug symbols */
    /* label DoNext @ MEMORY_INIT:0x2d7a */

    /* TODO: implement */
}

void ReadIniSettings(void)
{
    uint16_t uDateCur;
    int16_t i;
    int16_t iPass;
    char szEntry[16];
    WN wnT;
    char szIniFile[16];
    uint16_t w;
    char *psz;
    char szSection[16];
    int16_t cch;
    int16_t cpq;

    /* debug symbols */
    /* block (block) @ MEMORY_INIT:0x2822 */

    /* TODO: implement */
}

int16_t InitInstance(int16_t nCmdShow)
{
    int16_t sw;
    RECT rc;

    /* TODO: implement */
    return 0;
}

void GetIniWinRc(char *szSection, char *szIniFile, StringId ids, WN *pwn)
{
    int16_t fInitalized;
    int16_t fMinimized;
    int16_t fMaximized;
    char szEntry[16];
    int16_t cch;
    RECT rc;
    int16_t j;
    char *pch;
    int16_t i;
    int16_t fNeg;
    int16_t rg[4];

    /* debug symbols */
    /* block (block) @ MEMORY_INIT:0x10cc */
    /* label NoRc @ MEMORY_INIT:0x1094 */

    /* TODO: implement */
}

void InitTiles(void)
{
    int16_t yTop;
    int16_t ctile;
    TILE *rgtile;
    int16_t i;
    int16_t iPass;
    uint16_t iCol;

    /* TODO: implement */
}

#endif