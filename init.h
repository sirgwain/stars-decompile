#ifndef INIT_H_
#define INIT_H_

#include "strings.h"
#include "types.h"

#ifdef _WIN32
/* globals */
extern uint8_t rgPalGray[20]; /* MEMORY_INIT:0x0000 */

/* functions */
bool    FCreateStuff(void);                                                   /* MEMORY_INIT:0x0014 */
bool    FCreateFonts(HDC hdc);                                                /* MEMORY_INIT:0x0ab2 */
void    ReadIniTileSettings(char *pszFormat, TILE *rgtile, int16_t ctile);    /* MEMORY_INIT:0x2b8a */
void    ReadIniSettings(void);                                                /* MEMORY_INIT:0x124c */
int16_t InitInstance(int16_t nCmdShow);                                       /* MEMORY_INIT:0x0d70 */
void    GetIniWinRc(char *szSection, char *szIniFile, StringId ids, WN *pwn); /* MEMORY_INIT:0x1020 */
void    InitTiles(void);                                                      /* MEMORY_INIT:0x0eaa */

#endif /* _WIN32 */
#endif /* INIT_H_ */
