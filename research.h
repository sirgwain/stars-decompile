#ifndef RESEARCH_H_
#define RESEARCH_H_


#include "types.h"

/* globals */
extern int32_t rglTechCost[27];  /* MEMORY_RESEARCH:0x1d4e */
extern uint16_t rggrbitBrParts[17];  /* MEMORY_RESEARCH:0x1eb6 */

/* functions */
int32_t CostOfDevelopingItem(char *);  /* MEMORY_RESEARCH:0x66e0 */
int32_t GetTechLevelCost(int16_t, int16_t, int16_t);  /* MEMORY_RESEARCH:0x1dba */
int16_t ResearchDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RESEARCH:0x0000 */
int16_t FTrackResearchDlg(uint16_t, int16_t, int16_t, int16_t);  /* MEMORY_RESEARCH:0x1a8c */
int32_t ProjectedResearchSpending(int32_t);  /* MEMORY_RESEARCH:0x65ae */
void DrawResearchDlg(uint16_t, uint16_t, RECT *, int16_t);  /* MEMORY_RESEARCH:0x090a */
void DisplayComponentInfo(uint16_t, int16_t, int16_t, PART *);  /* MEMORY_RESEARCH:0x2ac6 */
int16_t FShouldPartBeHidden(PART *);  /* MEMORY_RESEARCH:0x68c4 */
int16_t BrowserDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RESEARCH:0x1ed8 */
int32_t BrowserWndProc(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_RESEARCH:0x2876 */

#endif /* RESEARCH_H_ */
