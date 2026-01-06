#ifndef SHIP2_H_
#define SHIP2_H_


#include "types.h"

/* functions */
int16_t FScout(FLEET *);  /* MEMORY_SHIP2:0x2322 */
int16_t RenameDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_SHIP2:0x0a68 */
int16_t FStargateJump(FLEET *, int16_t, int16_t, int16_t);  /* MEMORY_SHIP2:0x0cfe */
int32_t PctTerraFromLpfl(FLEET *);  /* MEMORY_SHIP2:0x275c */
void AutoFleetOrder(FLEET *, PLANET *);  /* MEMORY_SHIP2:0x23c8 */
int32_t CMineSweepFromLphul(HUL *);  /* MEMORY_SHIP2:0x2bfa */
int16_t MdCalcStargateDamage(int16_t, int16_t, int16_t, int16_t, int16_t *);  /* MEMORY_SHIP2:0x152e */
int16_t PctCloakFromLpfl(FLEET *);  /* MEMORY_SHIP2:0x2d5e */
void NoAutoTrackFleet(FLEET *);  /* MEMORY_SHIP2:0x1d32 */
int32_t CLayMinesFromLpfl(FLEET *, int16_t, int16_t);  /* MEMORY_SHIP2:0x2886 */
int16_t FColonizer(FLEET *);  /* MEMORY_SHIP2:0x227c */
void AutoRouteFleet(FLEET *, PLANET *);  /* MEMORY_SHIP2:0x1e52 */
void KillUsedWaypoints(void);  /* MEMORY_SHIP2:0x189a */
int16_t MergeFleetsDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_SHIP2:0x3376 */
int32_t CMineFromLpfl(FLEET *);  /* MEMORY_SHIP2:0x25d2 */
int16_t ZipOrderDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_SHIP2:0x0000 */
void MarkTechsSeen(HUL *, int16_t);  /* MEMORY_SHIP2:0x36b6 */
int16_t CPtsCloakFromLphs(HS *);  /* MEMORY_SHIP2:0x3170 */
int16_t RenameZipDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_SHIP2:0x0880 */
int32_t CMineSweepFromLpfl(FLEET *);  /* MEMORY_SHIP2:0x2b26 */
void EnableZipBtns(uint16_t, int16_t);  /* MEMORY_SHIP2:0x0832 */

#endif /* SHIP2_H_ */
