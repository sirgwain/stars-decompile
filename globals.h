#ifndef GLOBALS_H_
#define GLOBALS_H_

#include "types.h"

/* Unassigned symbols (no file inferred) */

/* globals */
uint16_t hbrButtonFace;  /* _DATA:0x0000 */
uint16_t hbrButtonText;  /* _DATA:0x0002 */
uint16_t hbrButtonHilite;  /* _DATA:0x0004 */
uint16_t hbrButtonShadow;  /* _DATA:0x0006 */
uint16_t hbrWindow;  /* _DATA:0x0008 */
uint16_t hbrWindowText;  /* _DATA:0x000a */
uint16_t hbrWindowFrame;  /* _DATA:0x000c */
uint16_t hbrDesktop;  /* _DATA:0x000e */
uint16_t hbrLightGray;  /* _DATA:0x0010 */
uint16_t hbrGray;  /* _DATA:0x0012 */
uint16_t hbrRed;  /* _DATA:0x0014 */
uint16_t hbrGreen;  /* _DATA:0x0016 */
uint16_t hbrBlue;  /* _DATA:0x0018 */
int16_t (* lpfnTutorDlgProc)(void);  /* _DATA:0x001a */
uint32_t rgcrPlrHistory[16];  /* _DATA:0x001e */
int16_t (* penvMem)[9];  /* _DATA:0x005e */
GAME game;  /* _DATA:0x0060 */
int16_t dGal;  /* _DATA:0x00e0 */
int16_t dGalInv;  /* _DATA:0x00e2 */
int16_t dGalMinDist;  /* _DATA:0x00e4 */
PLANET * lpPlanets;  /* _DATA:0x00e6 */
FLEET * * rglpfl;  /* _DATA:0x00ea */
SHDEF * rglpshdef[1];  /* _DATA:0x00ee */
char *szHelpFile;  /* _DATA:0x013a */
SHDEF * rglpshdefSB[1];  /* _DATA:0x013c */
int16_t idPlayer;  /* _DATA:0x017c */
uint16_t hwndBrowser;  /* _DATA:0x017e */
uint16_t hwndScanner;  /* _DATA:0x0180 */
uint16_t hwndActive;  /* _DATA:0x0182 */
uint16_t hwndMine;  /* _DATA:0x0184 */
uint16_t hwndPlanet;  /* _DATA:0x0186 */
uint16_t hwndMessage;  /* _DATA:0x0188 */
uint16_t hwndTb;  /* _DATA:0x018a */
int16_t fLogOut;  /* _DATA:0x018c */
char *lpchBatch;  /* _DATA:0x018e */
uint16_t uTimerId;  /* _DATA:0x0192 */
uint16_t uTimerType;  /* _DATA:0x0194 */
char * PCTD;  /* _DATA:0x019a */
char * PCTLD;  /* _DATA:0x01a0 */
char * PCTDPCTPCT;  /* _DATA:0x01a8 */
char * PCTDKT;  /* _DATA:0x01b0 */
char * MPCTD;  /* _DATA:0x01b6 */
char * PCTDXPCTDPCTPCT;  /* _DATA:0x01c0 */
uint32_t ctickLast;  /* _DATA:0x01c2 */
char szFrame[11];  /* _DATA:0x01c6 */
char szScan[10];  /* _DATA:0x01d2 */
char szMine[10];  /* _DATA:0x01dc */
char szPlanet[12];  /* _DATA:0x01e6 */
char szMessage[13];  /* _DATA:0x01f2 */
char szPopup[11];  /* _DATA:0x0200 */
char szBrowser[13];  /* _DATA:0x020c */
char szTitle[11];  /* _DATA:0x021a */
char szReport[12];  /* _DATA:0x0226 */
char szTb[8];  /* _DATA:0x0232 */
char szTooltip[8];  /* _DATA:0x023a */
char szDirName[256];  /* _DATA:0x0242 */
uint16_t hwndTitle;  /* _DATA:0x0342 */
int16_t fFreeingTitle;  /* _DATA:0x0344 */
uint16_t hiconStars;  /* _DATA:0x0346 */
uint16_t hiconHost;  /* _DATA:0x0348 */
uint16_t hiconWait;  /* _DATA:0x034a */
int32_t lSaltCur;  /* _DATA:0x034c */
int32_t lSaltLast;  /* _DATA:0x0350 */
int16_t vretExitValue;  /* _DATA:0x037c */
int16_t iPassCnt;  /* _DATA:0x03c2 */
int16_t fProcessingTimer;  /* _DATA:0x0404 */
POINT ptStickyHostModeDlg;  /* _DATA:0x0406 */
uint16_t vhpalSplash;  /* _DATA:0x041e */
uint16_t vhdibTitle;  /* _DATA:0x0420 */
uint16_t rghwndBtnSplash[4];  /* _DATA:0x0422 */
uint32_t rgcrMinerals[6];  /* _DATA:0x0438 */
char * rgszPlanetAttr[1];  /* _DATA:0x046e */
char * rgszPlanetAttrAbbr[1];  /* _DATA:0x0482 */
char * rgszMinerals[1];  /* _DATA:0x04bc */
char * rgszMineField[1];  /* _DATA:0x04e2 */
int16_t cMinGrafMax;  /* _DATA:0x04e8 */
uint8_t mpiTypeiItem[3];  /* _DATA:0x04fa */
char * mpdtsz[1];  /* _DATA:0x0542 */
int16_t fOrdersVis;  /* _DATA:0x0576 */
uint16_t grbitScan;  /* _DATA:0x0578 */
int16_t vpctRadarView;  /* _DATA:0x057a */
int16_t vrgScanPO[2][5];  /* _DATA:0x057c */
int16_t iScanZoom;  /* _DATA:0x0590 */
int16_t fInScrollSet;  /* _DATA:0x05bc */
POINT ptStickyFindDlg;  /* _DATA:0x05be */
char * vrgszMRU;  /* _DATA:0x05c2 */
int16_t bitTbl[8];  /* _DATA:0x05c6 */
char rgszArial[4][32];  /* _DATA:0x0696 */
int16_t fFileErrSilent;  /* _DATA:0x073c */
int16_t idsFileError;  /* _DATA:0x073e */
uint16_t wVersFile;  /* _DATA:0x0740 */
uint32_t bogi[25];  /* _DATA:0x0756 */
GDATA gd;  /* _DATA:0x07ba */
char *szListbox;  /* _DATA:0x07cc */
char *szCombobox;  /* _DATA:0x07d8 */
char *szEdit;  /* _DATA:0x07e0 */
char *szButton;  /* _DATA:0x07ea */
TILE rgtilePlanet[0];  /* _DATA:0x07ec */
int16_t rgdxOrderDD[3];  /* _DATA:0x084c */
int16_t dxBattleDD;  /* _DATA:0x0852 */
int16_t dxShipLB;  /* _DATA:0x0854 */
int16_t dyShipLB;  /* _DATA:0x0856 */
int16_t dxFleetCompLB;  /* _DATA:0x0858 */
int16_t dyFleetCompLB;  /* _DATA:0x085a */
int16_t dxPlanetProdLB;  /* _DATA:0x085c */
int16_t dyPlanetProdLB;  /* _DATA:0x085e */
int16_t dxOrderED;  /* _DATA:0x0860 */
int16_t iselProd;  /* _DATA:0x0862 */
uint16_t hwndOrderED;  /* _DATA:0x0864 */
int32_t vSerialNumber;  /* _DATA:0x089c */
int32_t rglPopMac[5];  /* _DATA:0x08bc */
POINT ptStickyRenameDlg;  /* _DATA:0x08d0 */
char * rgszZipOrder[1];  /* _DATA:0x08f6 */
TILE rgtileShip[0];  /* _DATA:0x08fe */
int16_t mdXferDlg;  /* _DATA:0x0974 */
POINT ptStickyTransferDlg;  /* _DATA:0x0976 */
int16_t fValidLx;  /* _DATA:0x0988 */
int16_t fValidLxf;  /* _DATA:0x098a */
uint8_t * vlpMemStream;  /* _DATA:0x098c */
uint8_t * lpLog;  /* _DATA:0x0990 */
int16_t imemLogCur;  /* _DATA:0x0994 */
int16_t imemLogPrev;  /* _DATA:0x0996 */
int16_t fLogOff;  /* _DATA:0x0998 */
TURNSERIAL * vrgts;  /* _DATA:0x09a4 */
uint16_t * vrgPlanResExtra;  /* _DATA:0x09a8 */
COLDROP * lpcd;  /* _DATA:0x09ac */
XFERFULL * lpxf;  /* _DATA:0x09b0 */
int16_t vcBackupDirs;  /* _DATA:0x09ce */
int16_t hf;  /* _DATA:0x0a12 */
char * lpbDefUni;  /* _DATA:0x0a1a */
char * vrgszComputerPlayers[1];  /* _DATA:0x0a6e */
char * vrgszComputerLevel[1];  /* _DATA:0x0a9e */
POINT ptStickyNewDlg;  /* _DATA:0x0ac8 */
int16_t cbbitfMsg;  /* _DATA:0x0ae6 */
int16_t * lpMsg;  /* _DATA:0x0ae8 */
int16_t imemMsgCur;  /* _DATA:0x0aec */
int16_t cMsg;  /* _DATA:0x0aee */
int16_t iMsgCur;  /* _DATA:0x0af0 */
int16_t iMsgSendCur;  /* _DATA:0x0af2 */
int16_t fViewFilteredMsg;  /* _DATA:0x0af4 */
MSGPLR * vlpmsgplrIn;  /* _DATA:0x0af6 */
MSGPLR * vlpmsgplrOut;  /* _DATA:0x0afa */
int16_t vcmsgplrIn;  /* _DATA:0x0afe */
int16_t vcmsgplrOut;  /* _DATA:0x0b00 */
int16_t viInRe;  /* _DATA:0x0b02 */
char * vrgszUnits[1];  /* _DATA:0x0b38 */
char iLastMsgGet;  /* _DATA:0x0b65 */
char * PCTLD00;  /* _DATA:0x0b6c */
uint16_t hwndPopup;  /* _DATA:0x0b6e */
POPUPDATA GlobalPD;  /* _DATA:0x0b70 */
int16_t fInEditUpdate;  /* _DATA:0x0c40 */
int16_t rgmapBuildBmps[21];  /* _DATA:0x0c42 */
int16_t iselSlot;  /* _DATA:0x0c6c */
POINT ptStickySlotDlg;  /* _DATA:0x0c6e */
uint16_t hdibPlaque;  /* _DATA:0x0c72 */
uint16_t hwndSlotDlg;  /* _DATA:0x0c80 */
char rgszSpeed[30];  /* _DATA:0x0c90 */
PLPROD * lpplProdGlob;  /* _DATA:0x0cbe */
uint16_t hwndProdDlg;  /* _DATA:0x0cc2 */
int16_t fDlgUp;  /* _DATA:0x0cc4 */
POINT ptStickyProduceDlg;  /* _DATA:0x0cc6 */
POINT ptStickyZipProdDlg;  /* _DATA:0x0cf0 */
int16_t vyZPDStatic;  /* _DATA:0x0cf4 */
int16_t pctResGlob;  /* _DATA:0x0cf6 */
POINT ptStickyResDlg;  /* _DATA:0x0cf8 */
int16_t yTopTechNote;  /* _DATA:0x0cfc */
POINT ptStickyBrowserDlg;  /* _DATA:0x0d0e */
int16_t fBrowserValid;  /* _DATA:0x0d12 */
HB * rglphb[1];  /* _DATA:0x0d24 */
uint16_t mphtcbAlloc[12];  /* _DATA:0x0d54 */
uint8_t * lpbBattleLog;  /* _DATA:0x0d6c */
uint8_t * lpbBattleCur;  /* _DATA:0x0d70 */
uint8_t * lpbBattleT;  /* _DATA:0x0d74 */
uint16_t * vlpwtCargo;  /* _DATA:0x0d78 */
int16_t idBattle;  /* _DATA:0x0d7c */
int16_t fStarbaseDied;  /* _DATA:0x0d7e */
int16_t fStarbaseDamaged;  /* _DATA:0x0d80 */
POINT ptStickyRelationsDlg;  /* _DATA:0x0d82 */
POINT ptStickyBattlePlansDlg;  /* _DATA:0x0d86 */
int16_t iPlanSelDlg;  /* _DATA:0x0d8a */
PLAYER vrgplrDef[0];  /* _DATA:0x0d92 */
uint16_t rgidRaceBtn[0];  /* _DATA:0x12d2 */
POINT ptStickyRaceDlg;  /* _DATA:0x12dc */
char * vrgszRCWWidth[1];  /* _DATA:0x12f4 */
char szRacePass[0];  /* _DATA:0x12f8 */
char szRaceFile[0];  /* _DATA:0x1308 */
int32_t lRandSeed1;  /* _DATA:0x1360 */
int32_t lRandSeed2;  /* _DATA:0x1364 */
int16_t cRandStack;  /* _DATA:0x1368 */
char iLastGet;  /* _DATA:0x136a */
POINT rgptArrow[5];  /* _DATA:0x137c */
POINT rgptTriangle[3];  /* _DATA:0x1390 */
int16_t chbrCache;  /* _DATA:0x139c */
int16_t rgcompstrlower[26];  /* _DATA:0x139e */
char *rgchcompstrlower;  /* _DATA:0x13ee */
char rgchcomp[13];  /* _DATA:0x13f0 */
uint16_t vcPasswordFailures;  /* _DATA:0x13fe */
uint16_t hwndProgressGauge;  /* _DATA:0x1400 */
int32_t * vrgdpVCR;  /* _DATA:0x1402 */
int16_t fAnimate;  /* _DATA:0x1406 */
int16_t viSpeedVCR;  /* _DATA:0x1408 */
POINT ptStickyVCRDlg;  /* _DATA:0x140a */
uint16_t hwndVCRDlg;  /* _DATA:0x140e */
int16_t fAi;  /* _DATA:0x1432 */
uint8_t * vlpbAiPlanet;  /* _DATA:0x1434 */
uint8_t * vlpbAiData;  /* _DATA:0x1438 */
PLANET * * vrglpplAi;  /* _DATA:0x143c */
uint8_t vrgcAiParts[45];  /* _DATA:0x1440 */
char iLastStrGet;  /* _DATA:0x1474 */
POINT ptStickyTutorDlg;  /* _DATA:0x1476 */
int16_t iLastTutGet;  /* _DATA:0x1482 */
RPT vrptPlanet;  /* _DATA:0x1484 */
RPT vrptFleet;  /* _DATA:0x14ba */
RPT vrptEFleet;  /* _DATA:0x14f0 */
RPT vrptBattle;  /* _DATA:0x1526 */
SCOREX * rgsxPlr[1];  /* _DATA:0x155c */
RPT * vprptCur;  /* _DATA:0x159c */
int16_t irowEFleetCur;  /* _DATA:0x159e */
uint16_t * vlprgidRep;  /* _DATA:0x15a0 */
uint16_t * vlprgidMisc;  /* _DATA:0x15a4 */
uint16_t * vlprgidPlanet;  /* _DATA:0x15a8 */
uint16_t * vlprgidFleet;  /* _DATA:0x15ac */
SCOREX * vlprgScoreX;  /* _DATA:0x15b0 */
uint16_t hwndReportDlg;  /* _DATA:0x15b4 */
char *szDblDash;  /* _DATA:0x15ba */
POINT ptStickyScoreXDlg;  /* _DATA:0x15d0 */
uint16_t hwndScoreXDlg;  /* _DATA:0x15d4 */
int16_t fInScoreDialog;  /* _DATA:0x15d6 */
int16_t vicolSortPrev;  /* _DATA:0x161c */
int16_t viSubsortPrev;  /* _DATA:0x161e */
char szCRLF[3];  /* _DATA:0x1620 */
POINT ptStickyPrintMapDlg;  /* _DATA:0x1680 */
int16_t vrgcPrintMapPage[2];  /* _DATA:0x1684 */
THING * lpThings;  /* _DATA:0x1688 */
int16_t cThing;  /* _DATA:0x168c */
int16_t cThingAlloc;  /* _DATA:0x168e */
POINT ptStickyZipOrderDlg;  /* _DATA:0x16a4 */
uint16_t hwndZipOrderDlg;  /* _DATA:0x16a8 */
POINT ptStickyMergeFleetsDlg;  /* _DATA:0x16b0 */
uint16_t hwndTBRadar;  /* _DATA:0x16b8 */
POINT vptTbLast;  /* _DATA:0x16ba */
uint16_t hwndTooltip;  /* _DATA:0x16c8 */
int16_t vidTimerTooltip;  /* _DATA:0x16ca */
uint32_t vtickTooltipLast;  /* _DATA:0x16cc */
uint8_t ctype[0];  /* _DATA:0x174e */
int32_t lFileSeed1;  /* _BSS:0x0000 */
int32_t lFileSeed2;  /* _BSS:0x0004 */
INI ini;  /* c_common:0x0000 */
PART vpartBrowser;  /* c_common:0x001a */
RECT rcMsgText;  /* c_common:0x0022 */
uint32_t crButtonFace;  /* c_common:0x002a */
uint16_t hrgnScratch;  /* c_common:0x002e */
int16_t vcStepVCR;  /* c_common:0x0030 */
int16_t (* lpfnRealEditProc)(void);  /* c_common:0x0032 */
uint16_t hbrYellow;  /* c_common:0x0036 */
char szLastGet[19];  /* c_common:0x0038 */
int16_t fMarkedPlanets;  /* c_common:0x004c */
int16_t iWindowLayout;  /* c_common:0x004e */
char szPassLast[16];  /* c_common:0x0050 */
uint16_t hwndBattleDD;  /* c_common:0x0060 */
char * vrgszFileNew;  /* c_common:0x0062 */
int16_t dxyVCRSquare;  /* c_common:0x0064 */
ZIPPRODQ vrgZipProd[5];  /* c_common:0x0066 */
RECT rcCargo;  /* c_common:0x012e */
int16_t dySBar;  /* c_common:0x0136 */
uint16_t hpenDkYellow;  /* c_common:0x0138 */
FRAMESTUFF vfs;  /* c_common:0x013a */
int16_t dxResRadio;  /* c_common:0x0150 */
BTLDATA * vlpbdVCRNext;  /* c_common:0x0152 */
uint16_t hAccel;  /* c_common:0x0156 */
int16_t (* lpfnRealComboProc)(void);  /* c_common:0x0158 */
int16_t dxWinFrame;  /* c_common:0x015c */
int16_t dyWinFrame;  /* c_common:0x015e */
uint16_t hcurResizeWE;  /* c_common:0x0160 */
int16_t dxResRight;  /* c_common:0x0162 */
int16_t dxShipDD;  /* c_common:0x0164 */
int16_t dyArial7;  /* c_common:0x0166 */
int16_t dyArial6;  /* c_common:0x0168 */
int16_t dyArial8;  /* c_common:0x016a */
uint16_t hwndRepCB;  /* c_common:0x016c */
uint32_t crButtonShadow;  /* c_common:0x016e */
int16_t (* lpfnFakeListProc)(void);  /* c_common:0x0172 */
int16_t dyShipDD;  /* c_common:0x0176 */
int16_t (* lpfnGaugeDlgProc)(void);  /* c_common:0x0178 */
uint16_t grfMissed;  /* c_common:0x017c */
int16_t rgcsxPlr[16];  /* c_common:0x017e */
uint16_t hdibThings;  /* c_common:0x019e */
uint16_t hbrSelect;  /* c_common:0x01a0 */
int32_t lResBudget;  /* c_common:0x01a2 */
SHDEF shdefBuild;  /* c_common:0x01a6 */
LOGXFER lx;  /* c_common:0x023a */
uint16_t hbmpBackBld;  /* c_common:0x0252 */
uint16_t hwndMDIClient;  /* c_common:0x0254 */
uint16_t rghiconVCR[7];  /* c_common:0x0256 */
LOGXFERF lxf;  /* c_common:0x0264 */
uint8_t rghbrCacheUse[32];  /* c_common:0x0288 */
int16_t (* lpfnFakeEditProc)(void);  /* c_common:0x02a8 */
int32_t lResTotal;  /* c_common:0x02ac */
BTN * rgbtnXfer;  /* c_common:0x02b0 */
int16_t csh;  /* c_common:0x02b2 */
int16_t (* lpfnFakeComboProc)(void);  /* c_common:0x02b4 */
char vszDefPass[17];  /* c_common:0x02b8 */
uint16_t hbrRadar;  /* c_common:0x02ca */
uint8_t rgTechBattle[6];  /* c_common:0x02cc */
uint8_t rgTechTrader[13];  /* c_common:0x02d2 */
int16_t yScanTop;  /* c_common:0x02e0 */
int16_t xScanTop;  /* c_common:0x02e2 */
uint32_t crWindow;  /* c_common:0x02e4 */
int16_t vcflMerge;  /* c_common:0x02e8 */
uint16_t uDateInstalled;  /* c_common:0x02ea */
uint16_t rghbrMineral[5];  /* c_common:0x02ec */
int16_t (* lpfnRealListProc)(void);  /* c_common:0x02f6 */
uint16_t hcurTrashCan;  /* c_common:0x02fa */
uint16_t hwndFrame;  /* c_common:0x02fc */
uint16_t rghdibInventory[7];  /* c_common:0x02fe */
char szMineralTitle[90];  /* c_common:0x030c */
uint32_t crButtonText;  /* c_common:0x0366 */
int16_t * rgXferValidHulls;  /* c_common:0x036a */
BTLREC * vlpbrVCR;  /* c_common:0x036c */
int16_t dxyVCRBoard;  /* c_common:0x0370 */
int16_t iPanelActive;  /* c_common:0x0372 */
uint16_t hdibRacesX;  /* c_common:0x0374 */
uint16_t hdibRacesT;  /* c_common:0x0376 */
int16_t viStore;  /* c_common:0x0378 */
uint16_t hbmpMsg;  /* c_common:0x037a */
int16_t viStepVCRCur;  /* c_common:0x037c */
int16_t cFutureTech;  /* c_common:0x037e */
int16_t dxMaxMineralQuan;  /* c_common:0x0380 */
uint32_t rgcrCache[32];  /* c_common:0x0382 */
uint16_t hbrPurple;  /* c_common:0x0402 */
PLAYER * vrgplrNew;  /* c_common:0x0404 */
HDR hdrCur;  /* c_common:0x0406 */
uint16_t rghwndBtn[13];  /* c_common:0x0408 */
int16_t fDirtyPlan;  /* c_common:0x0422 */
uint16_t rghfontArial8[5];  /* c_common:0x0424 */
uint16_t rghfontArial7[1];  /* c_common:0x042e */
uint16_t rghfontArial6[1];  /* c_common:0x0430 */
uint16_t hpenDkPurple;  /* c_common:0x0432 */
uint16_t hpenYellow;  /* c_common:0x0434 */
uint16_t hcurResizeNS;  /* c_common:0x0436 */
RECT vrgrcSlot[16];  /* c_common:0x0438 */
int16_t (* lpfnFakeCEProc)(void);  /* c_common:0x04b8 */
int16_t dScanPage;  /* c_common:0x04bc */
RECT vrcTooltip;  /* c_common:0x04be */
uint16_t hwndMain;  /* c_common:0x04c6 */
int16_t viRound;  /* c_common:0x04c8 */
uint16_t hbrTooltip;  /* c_common:0x04ca */
RECT rcSpinTop;  /* c_common:0x04cc */
RECT rcSpinBot;  /* c_common:0x04d4 */
int16_t vcRound;  /* c_common:0x04dc */
int16_t rgidPlan[999];  /* c_common:0x04de */
int16_t (* lpfnRealCEProc)(void);  /* c_common:0x0cac */
POINT rgptPlan[999];  /* c_common:0x0cb0 */
POINT vptMsg;  /* c_common:0x1c4c */
int16_t yBuildInfoSum;  /* c_common:0x1c50 */
int16_t mdMsgObj;  /* c_common:0x1c52 */
uint16_t hcurNoWay;  /* c_common:0x1c54 */
int16_t idMsgObj;  /* c_common:0x1c56 */
POINT ptPlaque;  /* c_common:0x1c58 */
uint32_t crButtonHilite;  /* c_common:0x1c5c */
TIMER vtimer;  /* c_common:0x1c60 */
uint16_t hbmpUnknownPlanet;  /* c_common:0x1c6a */
int16_t (* lpfnReportDlgProc)(void);  /* c_common:0x1c6c */
SHDEF rgshdef[16];  /* c_common:0x1c70 */
uint8_t rgcbtlplan[16];  /* c_common:0x25a0 */
uint16_t rghfontArial10[2];  /* c_common:0x25b0 */
int16_t xNewGameDiamond;  /* c_common:0x25b4 */
uint8_t vrgAiCyberArmadaPotency[4];  /* c_common:0x25b6 */
int16_t dScanInc;  /* c_common:0x25ba */
char szMsgTitle[90];  /* c_common:0x25bc */
uint32_t crWindowText;  /* c_common:0x2616 */
uint16_t hwndRaceParent;  /* c_common:0x261a */
RECT * vrgrcRCW;  /* c_common:0x261c */
uint16_t hcurArrowHelp;  /* c_common:0x261e */
RECT rgrcRef[19];  /* c_common:0x2620 */
int16_t vclpplAi;  /* c_common:0x26b8 */
RECT rcMsgTitle;  /* c_common:0x26ba */
uint16_t hdibPlanets;  /* c_common:0x26c2 */
int16_t yTopFutureTech;  /* c_common:0x26c4 */
SEL sel;  /* c_common:0x26c6 */
HS rghsFutureTech[8];  /* c_common:0x27a8 */
uint16_t hAccelTitle;  /* c_common:0x27c8 */
uint16_t hbmpScanner;  /* c_common:0x27ca */
uint16_t grbitScanMines;  /* c_common:0x27cc */
RECT rcProdDiamond;  /* c_common:0x27ce */
uint16_t hcurScanner;  /* c_common:0x27d6 */
XFER * pxfer;  /* c_common:0x27d8 */
int16_t iPopMenuSel;  /* c_common:0x27da */
char szPopupBuffer[256];  /* c_common:0x27dc */
int16_t dxTip;  /* c_common:0x28dc */
uint16_t rghdibShips[5];  /* c_common:0x28de */
uint16_t hbr50Screen;  /* c_common:0x28e8 */
uint16_t hcurOpenGrab;  /* c_common:0x28ea */
int16_t cPlanet;  /* c_common:0x28ec */
uint16_t hbmpScanShip;  /* c_common:0x28ee */
TOK * vrgtok;  /* c_common:0x28f0 */
uint16_t rghwndMsgBtn[4];  /* c_common:0x28f4 */
int16_t vidsTooltip;  /* c_common:0x28fc */
int16_t vfAscendingPrev;  /* c_common:0x28fe */
POINT ptSpeedVCR;  /* c_common:0x2900 */
int16_t crcRCW;  /* c_common:0x2904 */
int16_t crgbtnXfer;  /* c_common:0x2906 */
char rgbCur[1024];  /* c_common:0x2908 */
int16_t iResTechNow;  /* c_common:0x2d08 */
PLAYER vplr;  /* c_common:0x2d0a */
int16_t dyTitleBar;  /* c_common:0x2dca */
char szLastMsgGet[256];  /* c_common:0x2dcc */
uint8_t vrgAiArmadaPotency[4];  /* c_common:0x2ecc */
uint16_t rghdibShipsT[5];  /* c_common:0x2ed0 */
uint8_t bitfMsgSent[49];  /* c_common:0x2eda */
uint16_t hbrDkYellow;  /* c_common:0x2f0c */
uint8_t vrgbMachineConfig[11];  /* c_common:0x2f0e */
uint16_t grbitScanEShip;  /* c_common:0x2f1a */
int16_t iAboutPartial;  /* c_common:0x2f1c */
uint8_t * vAiMacRecycleSB;  /* c_common:0x2f1e */
char *lpchBatchMac;  /* c_common:0x2f20 */
POINT ptslotGlob;  /* c_common:0x2f24 */
int16_t vpctProgressGauge;  /* c_common:0x2f28 */
uint16_t hwndFleetCompLB;  /* c_common:0x2f2a */
int16_t * vrgiflMerge;  /* c_common:0x2f2c */
uint8_t vrgplrTypeNew[16];  /* c_common:0x2f2e */
uint16_t hcurResize4Way;  /* c_common:0x2f3e */
int16_t (* lpfnBrowserDlgProc)(void);  /* c_common:0x2f40 */
BTLPLAN btlplan;  /* c_common:0x2f44 */
int16_t vdxScoreX;  /* c_common:0x2f68 */
int16_t dxResStrRight;  /* c_common:0x2f6a */
uint16_t hwndMsgDrop;  /* c_common:0x2f6c */
int16_t (* lpfnHostTimerProc)(void);  /* c_common:0x2f6e */
SHDEF * lpshdefBuild;  /* c_common:0x2f72 */
uint8_t * lpb2k;  /* c_common:0x2f76 */
uint16_t hbrCargo;  /* c_common:0x2f7a */
TUTOR tutor;  /* c_common:0x2f7c */
int32_t rglRandStack[4][2];  /* c_common:0x2fa8 */
int16_t cXferValidHulls;  /* c_common:0x2fc8 */
uint16_t hrgnHuge;  /* c_common:0x2fca */
uint16_t hwndPlanetProdLB;  /* c_common:0x2fcc */
uint16_t hcurHand;  /* c_common:0x2fce */
HDR hdrPrev;  /* c_common:0x2fd0 */
uint16_t hbrDock;  /* c_common:0x2fd2 */
ZIPORDER vrgZip[4];  /* c_common:0x2fd4 */
uint16_t rghbrCache[32];  /* c_common:0x3034 */
uint16_t hcurCloseGrab;  /* c_common:0x3074 */
uint8_t vbrcVCRFocus;  /* c_common:0x3076 */
uint16_t grbitScanShip;  /* c_common:0x3078 */
int16_t dyArial10;  /* c_common:0x307a */
int16_t ishdefBuild;  /* c_common:0x307c */
uint16_t hwndShipDD;  /* c_common:0x307e */
uint16_t hInst;  /* c_common:0x3080 */
int16_t vcScreenColors;  /* c_common:0x3082 */
uint16_t vhpal;  /* c_common:0x3084 */
uint16_t hwndShipLB;  /* c_common:0x3086 */
uint16_t hbrShip;  /* c_common:0x3088 */
uint16_t hwndMsgScroll;  /* c_common:0x308a */
BTLDATA * vlpbdVCR;  /* c_common:0x308c */
int16_t fRCWReadOnly;  /* c_common:0x3090 */
uint16_t * vrgPlrLosses;  /* c_common:0x3092 */
uint8_t bitfMsgFiltered[49];  /* c_common:0x3094 */
int16_t cFleet;  /* c_common:0x30c6 */
uint16_t hpenDkGreen;  /* c_common:0x30c8 */
char szMsgBuf[256];  /* c_common:0x30ca */
char * lpbDefMac;  /* c_common:0x31d2 */
int16_t mdBuild;  /* c_common:0x31d6 */
uint8_t vrgbEnvCur[0];  /* c_common:0x31d8 */
uint16_t hwndBrowserChild;  /* c_common:0x31e4 */
uint16_t hdibRaces;  /* c_common:0x31e6 */
int16_t viVCRFocus;  /* c_common:0x31e8 */
char szLastStrGet[256];  /* c_common:0x31ea */
char szBackup[0];  /* c_common:0x32ea */
uint16_t hwndMineCB;  /* c_common:0x33ea */
int16_t cXferFull;  /* c_common:0x33ec */
uint16_t hpenRadarNear;  /* c_common:0x33ee */
uint16_t rghbrPlanetAttr[3][2];  /* c_common:0x33f0 */
uint16_t hpenEnemy;  /* c_common:0x33fc */
uint16_t hbrRadarNear;  /* c_common:0x33fe */
uint16_t hpenDkBlue;  /* c_common:0x3400 */
uint16_t rghbrMinSum[4][2];  /* c_common:0x3402 */
char szBase[256];  /* c_common:0x3412 */
uint16_t hcurScanAdd;  /* c_common:0x3512 */
char szWork[360];  /* c_common:0x3514 */
uint16_t hbrStarbase;  /* c_common:0x367c */
char szFormatNumber[12];  /* c_common:0x367e */
int16_t dySysFont;  /* c_common:0x368a */
int16_t fHullCopy;  /* c_common:0x368c */
uint16_t rghbrPat[3];  /* c_common:0x368e */
uint16_t hwndMsgEdit;  /* c_common:0x3694 */
RECT rgrcBuildSpin[2];  /* c_common:0x3696 */
uint16_t hpenRadar;  /* c_common:0x36a6 */
BTLPLAN * rglpbtlplan[1];  /* c_common:0x36a8 */
int16_t vctok;  /* c_common:0x36e8 */
uint16_t hbmpNumbers;  /* c_common:0x36ea */
THING * lpthBattle;  /* c_common:0x36ec */
uint16_t hpenStarbase;  /* c_common:0x36f0 */
uint32_t vtickTooltip1stVis;  /* c_common:0x36f2 */
uint16_t rghwndOrderDD[3];  /* c_common:0x36f6 */
uint16_t hdibToolbar;  /* c_common:0x36fc */
int16_t fStarbaseMode;  /* c_common:0x36fe */
int16_t vcplrNew;  /* c_common:0x3700 */
uint16_t hbmpMono;  /* c_common:0x3702 */
int16_t iAbout1st;  /* c_common:0x3704 */
uint16_t hbrEnemy;  /* c_common:0x3706 */
int16_t cColDrop;  /* c_common:0x3708 */
uint16_t hbrBBlue;  /* c_common:0x370a */
int16_t dxResLeft;  /* c_common:0x370c */
uint16_t hpenMassPath;  /* c_common:0x370e */
PROD * pProdGlob;  /* c_common:0x3710 */
PLAYER rgplr[16];  /* c_common:0x3712 */
uint16_t hpenShip;  /* c_common:0x4312 */
int16_t rgOut[16];  /* c_common:0x4314 */
int16_t cProdGlob;  /* c_common:0x4334 */

#endif /* GLOBALS_H_ */
