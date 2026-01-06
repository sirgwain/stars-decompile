#ifndef VCR_H_
#define VCR_H_


#include "types.h"

/* functions */
void EnableVCRButtons(void);  /* MEMORY_VCR:0x48f6 */
int16_t PopupVCRMenu(uint16_t, int16_t, int16_t, uint8_t);  /* MEMORY_VCR:0x4518 */
void DrawVCR(uint16_t, int16_t, int16_t);  /* MEMORY_VCR:0x1c62 */
void GetVCRStats(int16_t, int32_t *, DV *, int32_t *, int16_t *);  /* MEMORY_VCR:0x193e */
BTLDATA * BtlDataGet(int16_t);  /* RETFAR */  /* MEMORY_VCR:0x0362 */
void BattleVCR(int16_t);  /* MEMORY_VCR:0x0000 */
int32_t LdpFromItokDv(int16_t, DV *);  /* MEMORY_VCR:0x07a8 */
int32_t CBattleKills(BTLDATA *, int16_t);  /* MEMORY_VCR:0x062e */
int32_t CBattleUnits(BTLDATA *, uint16_t);  /* MEMORY_VCR:0x0450 */
int16_t CBattles(void);  /* MEMORY_VCR:0x028c */
int16_t SetVCRBoard(int16_t);  /* MEMORY_VCR:0x08d8 */
int16_t VCRDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_VCR:0x0e90 */
void AnimateAttack(uint16_t);  /* MEMORY_VCR:0x3ac2 */
void Delay(int16_t);  /* MEMORY_VCR:0x3a3e */

#endif /* VCR_H_ */
