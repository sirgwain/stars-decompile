#ifndef SHIP2_H_
#define SHIP2_H_

#include "types.h"

/* functions */
int16_t FScout(FLEET *lpfl);                                                                                 /* MEMORY_SHIP2:0x2322 */
int16_t FStargateJump(FLEET *lpfl, int16_t isbsSrc, int16_t isbsDst, int16_t dDist);                         /* MEMORY_SHIP2:0x0cfe */
int32_t PctTerraFromLpfl(FLEET *lpfl);                                                                       /* MEMORY_SHIP2:0x275c */
void    AutoFleetOrder(FLEET *lpfl, PLANET *lppl);                                                           /* MEMORY_SHIP2:0x23c8 */
int32_t CMineSweepFromLphul(HUL *lphul);                                                                     /* MEMORY_SHIP2:0x2bfa */
int16_t MdCalcStargateDamage(int16_t isbsSrc, int16_t isbsDst, int16_t dDist, int16_t wt, int16_t *ppctDmg); /* MEMORY_SHIP2:0x152e */
int16_t PctCloakFromLpfl(FLEET *lpfl);                                                                       /* MEMORY_SHIP2:0x2d5e */
void    NoAutoTrackFleet(FLEET *lpflTarget);                                                                 /* MEMORY_SHIP2:0x1d32 */
int32_t CLayMinesFromLpfl(FLEET *lpfl, int16_t iType, int16_t ishdef);                                       /* MEMORY_SHIP2:0x2886 */
int16_t FColonizer(FLEET *lpfl);                                                                             /* MEMORY_SHIP2:0x227c */
void    AutoRouteFleet(FLEET *lpfl, PLANET *lppl);                                                           /* MEMORY_SHIP2:0x1e52 */
void    KillUsedWaypoints(void);                                                                             /* MEMORY_SHIP2:0x189a */
int32_t CMineFromLpfl(FLEET *lpfl);                                                                          /* MEMORY_SHIP2:0x25d2 */
void    MarkTechsSeen(HUL *lphul, int16_t iplr);                                                             /* MEMORY_SHIP2:0x36b6 */
int16_t CPtsCloakFromLphs(HS *lphs);                                                                         /* MEMORY_SHIP2:0x3170 */
int32_t CMineSweepFromLpfl(FLEET *lpfl);                                                                     /* MEMORY_SHIP2:0x2b26 */

#ifdef _WIN32

INT_PTR CALLBACK RenameDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */      /* MEMORY_SHIP2:0x0a68 */
INT_PTR CALLBACK MergeFleetsDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_SHIP2:0x3376 */
INT_PTR CALLBACK ZipOrderDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */    /* MEMORY_SHIP2:0x0000 */
INT_PTR CALLBACK RenameZipDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */   /* MEMORY_SHIP2:0x0880 */
void             EnableZipBtns(HWND hwnd, int16_t iSel);                                         /* MEMORY_SHIP2:0x0832 */

#endif /* _WIN32 */

#endif /* SHIP2_H_ */
