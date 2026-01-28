#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <assert.h>
#include "types.h"
#ifdef _WIN32
#include <windows.h>

#endif /* _WIN32 */

#ifdef NDEBUG
#define Assert(expr) ((void)0)
#else
#define Assert(expr) assert(expr)
#endif

#define IDOK 1
#define IDYES 6
#define IDNO 7

// guessed defines from the decompile
#define MsgYesNo(ids) AlertSz(PszFormatIds((ids), NULL), MB_YESNO | MB_ICONQUESTION)
#define Error(ids) AlertSz(PszFormatIds((ids), NULL), MB_OK | MB_ICONHAND)

/* Message box helpers used by decompiled/ported code. */
#ifndef MessageSz
#define MessageSz(sz) ((void)AlertSz((char *)(sz), MB_OK))
#endif

/* These are constants in the original; keep them header-only without creating
 * multiple definitions across TUs.
 */
#define dGalOff 1000 /* map border inset ("off") */
#define ishdefMax 16
#define ishdefSBMax 10
#define cbAllocMac 65480
#define BTLPLANMAX 16
#define cPlanetAbsMax 999
#define cThingAbsMax 4050
#define cFleetAbsMax 512

/* Stream helper: treat EOF like the Win16 macro. */
static bool AtEOF(FILE *fp)
{
    long pos = ftell(fp);
    if (pos < 0)
        return true;

    if (fseek(fp, 0, SEEK_END) != 0)
        return true;

    long end = ftell(fp);
    if (end < 0)
        return true;

    /* Restore position */
    fseek(fp, pos, SEEK_SET);

    return pos >= end;
}

/* UI helper used in a few places in the original. */
#ifndef MessageSz
#define MessageSz(sz) ((void)AlertSz((char *)(sz), MB_OK))
#endif

// platform independent jmp_buf wrapper
typedef struct MemJump
{
    jmp_buf env;
} MemJump;

extern MemJump *penvMem; // pointer to wrapper is fine

/* Unassigned symbols (no file inferred) */

/* globals */

extern BTLDATA *
    vlpbdVCR;
extern BTLDATA *vlpbdVCRNext;
extern BTLPLAN *rglpbtlplan[1];
extern BTLPLAN btlplan;
extern BTLREC *vlpbrVCR;
extern BTN *rgbtnXfer;
extern char *lpbDefMac;
extern char *lpbDefUni;
extern char *lpchBatch;
extern char *lpchBatchMac;
extern char *MPCTD;
extern char *mpdtsz[8];
extern char *PCTD;
extern char *PCTDKT;
extern char *PCTDPCTPCT;
extern char *PCTDXPCTDPCTPCT;
extern char *PCTLD;
extern char *PCTLD00;
extern char *rgszMineField[5];
extern char *rgszMinerals[6];
extern char *rgszPlanetAttr[3];
extern char *rgszPlanetAttrAbbr[3];
extern char *rgszZipOrder[7];
extern char *szButton;
extern char *szCombobox;
extern char *szDblDash;
extern char *szEdit;
extern char *szHelpFile;
extern char *szListbox;
extern char *vrgszComputerLevel[5];
extern char *vrgszComputerPlayers[7];
extern char *vrgszFileNew;
extern char *vrgszMRU;
extern char *vrgszRCWWidth[2];
extern char *vrgszUnits[6];
extern char iLastGet;
extern char iLastMsgGet;
extern char iLastStrGet;
extern uint8_t rgbCur[1024];
extern char rgszArial[4][32];
extern char rgszSpeed[30];
extern char szBackup[0];
extern char szBase[256];
extern char szBrowser[13];
extern char szCRLF[3];
extern char szDirName[256];
extern char szFormatNumber[12];
extern char szFrame[11];
extern char szLastGet[19];
extern char szLastMsgGet[256];
extern char szLastStrGet[256];
extern char szMessage[13];
extern char szMine[10];
extern char szMineralTitle[90];
extern char szMsgBuf[256];
extern char szMsgTitle[90];
extern char szPassLast[16];
extern char szPlanet[12];
extern char szPopup[11];
extern char szPopupBuffer[256];
extern char szRaceFile[0];
extern char szRacePass[0];
extern char szReport[12];
extern char szScan[10];
extern char szTb[8];
extern char szTitle[11];
extern char szTooltip[8];
extern char szWork[360];
extern char vszDefPass[17];
extern COLDROP *lpcd;
extern FLEET **rglpfl;
extern FRAMESTUFF vfs;
extern GAME game;
extern GDATA gd;
extern HDR hdrCur;
extern HDR hdrPrev;
extern HS rghsFutureTech[8];
extern INI ini;
extern int16_t *lpMsg;
extern int16_t *rgXferValidHulls;
extern int16_t *vrgiflMerge;
extern int16_t bitTbl[8];
extern int16_t cbbitfMsg;
extern int16_t cColDrop;
extern int16_t cFleet;
extern int16_t cFutureTech;
extern int16_t chbrCache;
extern int16_t cMinGrafMax;
extern int16_t cMsg;
extern int16_t cPlanet;
extern int16_t cProdGlob;
extern int16_t cRandStack;
extern int16_t crcRCW;
extern int16_t crgbtnXfer;
extern int16_t csh;
extern int16_t cThing;
extern int16_t cThingAlloc;
extern int16_t cXferFull;
extern int16_t cXferValidHulls;
extern int16_t dGal;
extern int16_t dGalInv;
extern int16_t dGalMinDist;
extern int16_t dScanInc;
extern int16_t dScanPage;
extern int16_t dxBattleDD;
extern int16_t dxFleetCompLB;
extern int16_t dxMaxMineralQuan;
extern int16_t dxOrderED;
extern int16_t dxPlanetProdLB;
extern int16_t dxResLeft;
extern int16_t dxResRadio;
extern int16_t dxResRight;
extern int16_t dxResStrRight;
extern int16_t dxShipDD;
extern int16_t dxShipLB;
extern int16_t dxTip;
extern int16_t dxWinFrame;
extern int16_t dxyVCRBoard;
extern int16_t dxyVCRSquare;
extern int16_t dyArial10;
extern int16_t dyArial6;
extern int16_t dyArial7;
extern int16_t dyArial8;
extern int16_t dyFleetCompLB;
extern int16_t dyPlanetProdLB;
extern int16_t dySBar;
extern int16_t dyShipDD;
extern int16_t dyShipLB;
extern int16_t dySysFont;
extern int16_t dyTitleBar;
extern int16_t dyWinFrame;
extern int16_t fAi;
extern int16_t fAnimate;
extern int16_t fBrowserValid;
extern int16_t fDirtyPlan;
extern int16_t fDlgUp;
extern bool fFileErrSilent;
extern int16_t fFreeingTitle;
extern int16_t fHullCopy;
extern int16_t fInEditUpdate;
extern int16_t fInScoreDialog;
extern int16_t fInScrollSet;
extern int16_t fLogOff;
extern int16_t fLogOut;
extern int16_t fMarkedPlanets;
extern int16_t fOrdersVis;
extern int16_t fProcessingTimer;
extern int16_t fRCWReadOnly;
extern int16_t fStarbaseDamaged;
extern int16_t fStarbaseDied;
extern int16_t fStarbaseMode;
extern int16_t fValidLx;
extern int16_t fValidLxf;
extern int16_t fViewFilteredMsg;
extern int16_t iAbout1st;
extern int16_t iAboutPartial;
extern int16_t idBattle;
extern int16_t idMsgObj;
extern int16_t idPlayer;
extern int16_t idsFileError;
extern int16_t iLastTutGet;
extern int16_t imemLogCur;
extern int16_t imemLogPrev;
extern int16_t imemMsgCur;
extern int16_t iMsgCur;
extern int16_t iMsgSendCur;
extern int16_t iPanelActive;
extern int16_t iPassCnt;
extern int16_t iPlanSelDlg;
extern int16_t iPopMenuSel;
extern int16_t iResTechNow;
extern int16_t irowEFleetCur;
extern int16_t iScanZoom;
extern int16_t iselProd;
extern int16_t iselSlot;
extern int16_t ishdefBuild;
extern int16_t iWindowLayout;
extern int16_t mdBuild;
extern int16_t mdMsgObj;
extern int16_t mdXferDlg;
extern int16_t pctResGlob;
extern int16_t rgcsxPlr[16];
extern int16_t rgdxOrderDD[3];
extern int16_t rgidPlan[999];
extern int16_t rgmapBuildBmps[21];
extern int16_t rgOut[16];
extern int16_t vcBackupDirs;
extern int16_t vcflMerge;
extern int16_t vclpplAi;
extern int16_t vcmsgplrIn;
extern int16_t vcmsgplrOut;
extern int16_t vcplrNew;
extern int16_t vcRound;
extern int16_t vcScreenColors;
extern int16_t vcStepVCR;
extern int16_t vctok;
extern int16_t vdxScoreX;
extern int16_t vfAscendingPrev;
extern int16_t vicolSortPrev;
extern int16_t vidsTooltip;
extern int16_t vidTimerTooltip;
extern int16_t viInRe;
extern int16_t viRound;
extern int16_t viSpeedVCR;
extern int16_t viStepVCRCur;
extern int16_t viStore;
extern int16_t viSubsortPrev;
extern int16_t viVCRFocus;
extern int16_t vpctProgressGauge;
extern int16_t vpctRadarView;
extern int16_t vretExitValue;
extern int16_t vrgcPrintMapPage[2];
extern int16_t vrgScanPO[2][5];
extern int16_t vyZPDStatic;
extern int16_t xNewGameDiamond;
extern int16_t xScanTop;
extern int16_t yBuildInfoSum;
extern int16_t yScanTop;
extern int16_t yTopFutureTech;
extern int16_t yTopTechNote;
extern int32_t *vrgdpVCR;
extern int32_t lFileSeed1;
extern int32_t lFileSeed2;
extern int32_t lRandSeed1;
extern int32_t lRandSeed2;
extern int32_t lResBudget;
extern int32_t lResTotal;
extern int32_t lSaltCur;
extern int32_t lSaltLast;
extern int32_t rglPopMac[5];
extern int32_t rglRandStack[4][2];
extern int32_t vSerialNumber;
extern LOGXFER lx;
extern LOGXFERF lxf;
extern MSGPLR *vlpmsgplrIn;
extern MSGPLR *vlpmsgplrOut;
extern PART vpartBrowser;
extern PLANET **vrglpplAi;
extern PLANET *lpPlanets;
extern PLAYER *vrgplrNew;
extern PLAYER rgplr[16];
extern PLAYER vplr;
extern PLAYER vrgplrDef[0];
extern PLPROD *lpplProdGlob;
extern POINT ptPlaque;
extern POINT ptslotGlob;
extern POINT ptSpeedVCR;
extern POINT ptStickyBattlePlansDlg;
extern POINT ptStickyBrowserDlg;
extern POINT ptStickyFindDlg;
extern POINT ptStickyHostModeDlg;
extern POINT ptStickyMergeFleetsDlg;
extern POINT ptStickyNewDlg;
extern POINT ptStickyPrintMapDlg;
extern POINT ptStickyProduceDlg;
extern POINT ptStickyRaceDlg;
extern POINT ptStickyRelationsDlg;
extern POINT ptStickyRenameDlg;
extern POINT ptStickyResDlg;
extern POINT ptStickyScoreXDlg;
extern POINT ptStickySlotDlg;
extern POINT ptStickyTransferDlg;
extern POINT ptStickyTutorDlg;
extern POINT ptStickyVCRDlg;
extern POINT ptStickyZipOrderDlg;
extern POINT ptStickyZipProdDlg;
extern POINT rgptArrow[5];
extern POINT rgptPlan[999];
extern POINT rgptTriangle[3];
extern POINT vptMsg;
extern POINT vptTbLast;
extern POPUPDATA GlobalPD;
extern PROD *pProdGlob;
extern RECT *vrgrcRCW;
extern RECT rcCargo;
extern RECT rcMsgText;
extern RECT rcMsgTitle;
extern RECT rcProdDiamond;
extern RECT rcSpinBot;
extern RECT rcSpinTop;
extern RECT rgrcBuildSpin[2];
extern RECT rgrcRef[19];
extern RECT vrcTooltip;
extern RECT vrgrcSlot[16];
extern RPT *vprptCur;
extern RPT vrptBattle;
extern RPT vrptEFleet;
extern RPT vrptFleet;
extern RPT vrptPlanet;
extern SCOREX *rgsxPlr[1];
extern SCOREX *vlprgScoreX;
extern SEL sel;
extern SHDEF *lpshdefBuild;
extern SHDEF *rglpshdef[cPlayerMax];
extern SHDEF *rglpshdefSB[cPlayerMax];
extern SHDEF rgshdef[cPlayerMax];
extern SHDEF shdefBuild;
extern THING *lpthBattle;
extern THING *lpThings;
extern TILE rgtilePlanet[0];
extern TILE rgtileShip[0];
extern TIMER vtimer;
extern TOK *vrgtok;
extern TURNSERIAL *vrgts;
extern TUTOR tutor;
extern uint16_t *vlprgidFleet;
extern uint16_t *vlprgidMisc;
extern uint16_t *vlprgidPlanet;
extern uint16_t *vlprgidRep;
extern uint16_t *vlpwtCargo;
extern uint16_t *vrgPlanResExtra;
extern uint16_t *vrgPlrLosses;
extern uint16_t grbitScan;
extern uint16_t grbitScanEShip;
extern uint16_t grbitScanMines;
extern uint16_t grbitScanShip;
extern uint16_t grfMissed;
extern uint16_t rghbrCache[32];
extern uint16_t rghbrMineral[5];
extern uint16_t rghbrMinSum[4][2];
extern uint16_t rghbrPat[3];
extern uint16_t rghbrPlanetAttr[3][2];
extern uint16_t rghdibInventory[7];
extern uint16_t rghdibShips[5];
extern uint16_t rghdibShipsT[5];
extern uint16_t rghfontArial10[2];
extern uint16_t rghfontArial6[1];
extern uint16_t rghfontArial7[1];
extern uint16_t rghfontArial8[5];
extern uint16_t rghiconVCR[7];
extern uint16_t rghwndBtn[13];
extern uint16_t rghwndBtnSplash[4];
extern uint16_t rghwndMsgBtn[4];
extern uint16_t rghwndOrderDD[3];
extern uint16_t rgidRaceBtn[0];
extern uint16_t uDateInstalled;
extern uint16_t uTimerId;
extern uint16_t uTimerType;
extern uint16_t vcPasswordFailures;
extern uint16_t vhdibTitle;
extern uint16_t vhpal;
extern uint16_t vhpalSplash;
extern uint16_t wVersFile;
extern uint32_t crButtonFace;
extern uint32_t crButtonHilite;
extern uint32_t crButtonShadow;
extern uint32_t crButtonText;
extern uint32_t crWindow;
extern uint32_t crWindowText;
extern uint32_t ctickLast;
extern uint32_t vtickTooltip1stVis;
extern uint32_t vtickTooltipLast;
extern uint8_t *lpb2k;
extern uint8_t *lpbBattleCur;
extern uint8_t *lpbBattleLog;
extern uint8_t *lpbBattleT;
extern uint8_t *lpLog;
extern uint8_t *vAiMacRecycleSB;
extern uint8_t *vlpbAiData;
extern uint8_t *vlpbAiPlanet;
extern uint8_t *vlpMemStream;
extern uint8_t bitfMsgFiltered[49];
extern uint8_t bitfMsgSent[49];
extern uint8_t ctype[0];
extern uint8_t mpiTypeiItem[3];
extern uint8_t rgcbtlplan[16];
extern uint8_t rghbrCacheUse[32];
extern uint8_t rgTechBattle[6];
extern uint8_t rgTechTrader[13];
extern uint8_t vbrcVCRFocus;
extern uint8_t vrgAiArmadaPotency[4];
extern uint8_t vrgAiCyberArmadaPotency[4];
extern uint8_t vrgbEnvCur[0];
extern uint8_t vrgbMachineConfig[11];
extern uint8_t vrgcAiParts[45];
extern uint8_t vrgplrTypeNew[16];
extern XFER *pxfer;
extern XFERFULL *lpxf;
extern ZIPORDER vrgZip[4];
extern ZIPPRODQ vrgZipProd[5];

#ifdef _WIN32
// win32 only globals

extern COLORREF rgcrCache[32];
extern COLORREF rgcrMinerals[6];
extern COLORREF rgcrPlrHistory[16];
extern HINSTANCE hInst;
extern HPEN hpenDkBlue;
extern HPEN hpenDkGreen;
extern HPEN hpenDkPurple;
extern HPEN hpenDkYellow;
extern HPEN hpenEnemy;
extern HPEN hpenMassPath;
extern HPEN hpenRadar;
extern HPEN hpenRadarNear;
extern HPEN hpenShip;
extern HPEN hpenStarbase;
extern HPEN hpenYellow;
extern HRGN hrgnHuge;
extern HRGN hrgnScratch;
extern HWND hwndActive;
extern HWND hwndBattleDD;
extern HWND hwndBrowser;
extern HWND hwndBrowserChild;
extern HWND hwndFleetCompLB;
extern HWND hwndFrame;
extern HWND hwndMain;
extern HWND hwndMDIClient;
extern HWND hwndMessage;
extern HWND hwndMine;
extern HWND hwndMineCB;
extern HWND hwndMsgDrop;
extern HWND hwndMsgEdit;
extern HWND hwndMsgScroll;
extern HWND hwndOrderED;
extern HWND hwndPlanet;
extern HWND hwndPlanetProdLB;
extern HWND hwndPopup;
extern HWND hwndProdDlg;
extern HWND hwndProgressGauge;
extern HWND hwndRaceParent;
extern HWND hwndRepCB;
extern HWND hwndReportDlg;
extern HWND hwndScanner;
extern HWND hwndScoreXDlg;
extern HWND hwndShipDD;
extern HWND hwndShipLB;
extern HWND hwndSlotDlg;
extern HWND hwndTb;
extern HWND hwndTBRadar;
extern HWND hwndTitle;
extern HWND hwndTooltip;
extern HWND hwndVCRDlg;
extern HWND hwndZipOrderDlg;
extern HACCEL hAccel;
extern HACCEL hAccelTitle;
extern HBITMAP hbmpBackBld;
extern HBITMAP hbmpMono;
extern HBITMAP hbmpMsg;
extern HBITMAP hbmpNumbers;
extern HBITMAP hbmpScanner;
extern HBITMAP hbmpScanShip;
extern HBITMAP hbmpUnknownPlanet;
extern HBRUSH hbr50Screen;
extern HBRUSH hbrBBlue;
extern HBRUSH hbrBlue;
extern HBRUSH hbrButtonFace;
extern HBRUSH hbrButtonHilite;
extern HBRUSH hbrButtonShadow;
extern HBRUSH hbrButtonText;
extern HBRUSH hbrCargo;
extern HBRUSH hbrDesktop;
extern HBRUSH hbrDkYellow;
extern HBRUSH hbrDock;
extern HBRUSH hbrEnemy;
extern HBRUSH hbrGray;
extern HBRUSH hbrGreen;
extern HBRUSH hbrLightGray;
extern HBRUSH hbrPurple;
extern HBRUSH hbrRadar;
extern HBRUSH hbrRadarNear;
extern HBRUSH hbrRed;
extern HBRUSH hbrSelect;
extern HBRUSH hbrShip;
extern HBRUSH hbrStarbase;
extern HBRUSH hbrTooltip;
extern HBRUSH hbrWindow;
extern HBRUSH hbrWindowFrame;
extern HBRUSH hbrWindowText;
extern HBRUSH hbrYellow;
extern HCURSOR hcurArrowHelp;
extern HCURSOR hcurCloseGrab;
extern HCURSOR hcurHand;
extern HCURSOR hcurNoWay;
extern HCURSOR hcurOpenGrab;
extern HCURSOR hcurResize4Way;
extern HCURSOR hcurResizeNS;
extern HCURSOR hcurResizeWE;
extern HCURSOR hcurScanAdd;
extern HCURSOR hcurScanner;
extern HCURSOR hcurTrashCan;
extern HGLOBAL hdibPlanets;
extern HGLOBAL hdibPlaque;
extern HGLOBAL hdibRaces;
extern HGLOBAL hdibRacesT;
extern HGLOBAL hdibRacesX;
extern HGLOBAL hdibThings;
extern HGLOBAL hdibToolbar;
extern HICON hiconHost;
extern HICON hiconStars;
extern HICON hiconWait;
/* Subclassing: real edit control proc (Win32 only) */
extern WNDPROC lpfnRealEditProc;

#endif /* _WIN32 */

#endif /* GLOBALS_H_ */
