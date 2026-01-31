#ifndef MINE_H_
#define MINE_H_

#include "types.h"

/* functions */
void GetMineFieldCounts(uint16_t id, int16_t *pithm, int16_t *pcthm);                 /* MEMORY_MINE:0x05ac */
void EstMineralsMined(PLANET *lppl, int32_t *plQuan, int32_t cMines, int16_t fApply); /* MEMORY_MINE:0x5362 */

#ifdef _WIN32
void             MineClick(int16_t x, int16_t y, int16_t msg, int16_t sks);      /* MEMORY_MINE:0x3b4e */
int16_t          FOtherStuffAtScanSel(void);                                     /* MEMORY_MINE:0x4d6e */
void             DrawMineSurvey(HDC hdc, RECT *prc);                             /* MEMORY_MINE:0x065a */
void             InvalidateMineralBars(void);                                    /* MEMORY_MINE:0x040a */
LRESULT CALLBACK MineWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_MINE:0x0000 */
void             DrawSelectionArrow(HDC hdc, RECT *prc, int16_t fEnabled);       /* MEMORY_MINE:0x4a68 */
void             PopupMineralScanChoices(HWND hwnd, int16_t x, int16_t y);       /* MEMORY_MINE:0x4ecc */
void             SetMineralTitleBar(HWND hwnd);                                  /* MEMORY_MINE:0x47dc */
int16_t          HtMineWindow(HWND hwnd, int16_t x, int16_t y);                  /* MEMORY_MINE:0x37ac */
void             DrawDiamond(HDC hdc, RECT *prc, HBRUSH hbr);                    /* MEMORY_MINE:0x4b60 */
#endif                                                                           /* _WIN32 */

#endif /* MINE_H_ */
