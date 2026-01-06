#ifndef MINE_H_
#define MINE_H_


#include "types.h"

/* functions */
void GetMineFieldCounts(uint16_t, int16_t *, int16_t *);  /* MEMORY_MINE:0x05ac */
void MineClick(int16_t, int16_t, int16_t, int16_t);  /* MEMORY_MINE:0x3b4e */
int16_t FOtherStuffAtScanSel(void);  /* MEMORY_MINE:0x4d6e */
void DrawMineSurvey(uint16_t, RECT *);  /* MEMORY_MINE:0x065a */
void InvalidateMineralBars(void);  /* MEMORY_MINE:0x040a */
int32_t MineWndProc(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_MINE:0x0000 */
void DrawSelectionArrow(uint16_t, RECT *, int16_t);  /* MEMORY_MINE:0x4a68 */
void PopupMineralScanChoices(uint16_t, int16_t, int16_t);  /* MEMORY_MINE:0x4ecc */
void SetMineralTitleBar(uint16_t);  /* MEMORY_MINE:0x47dc */
void EstMineralsMined(PLANET *, int32_t *, int32_t, int16_t);  /* MEMORY_MINE:0x5362 */
int16_t HtMineWindow(uint16_t, int16_t, int16_t);  /* MEMORY_MINE:0x37ac */
void DrawDiamond(uint16_t, RECT *, uint16_t);  /* MEMORY_MINE:0x4b60 */

#endif /* MINE_H_ */
