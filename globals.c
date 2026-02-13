#include "types.h"

#define GLOBALS_DEFINE 1
#include "globals.h"

/* Unassigned symbols (no file inferred) */

/* globals */
BTLDATA *vlpbdVCR;
BTLDATA *vlpbdVCRNext;
BTLPLAN *rglpbtlplan[16];
BTLPLAN  btlplan = {0};
BTLREC  *vlpbrVCR;
BTN     *rgbtnXfer;
char    *lpbDefMac;
char    *lpbDefUni;
char    *lpchBatch;
char    *lpchBatchMac;
char    *MPCTD = "m%d";
char    *mpdtsz[8] = {"xy", "x", "hst", "m", "h", "r", "log", "chk"};
char    *PCTD = "%d";
char    *PCTDKT = "%dkT";
char    *PCTDPCTPCT = "%d%%";
char    *PCTDXPCTDPCTPCT = "%d.%d%%";
char    *PCTLD = "%ld";
char    *PCTLD00 = "%ld00";
char    *rgszMineField[5] = {"Standard", "Heavy", "Speed Bump", "rs!", ""};
char    *rgszMinerals[6] = {"Ironium", "Boranium", "Germanium", "Colonists", "Fuel", "Resources"};
char    *rgszPlanetAttr[3] = {"Gravity", "Temperature", "Radiation"};
char    *rgszPlanetAttrAbbr[3] = {"Grav", "Temp", "Rad"};
char    *rgszZipOrder[7] = {"QuikLoad", "QuikDrop", "WaitLoad", "Clear", "", "", ""};
char    *szButton = "BUTTON";
char    *szCombobox = "COMBOBOX";
char    *szDblDash = "-- ";
char    *szEdit = "EDIT";
char    *szHelpFile = "stars!.hlp";
char    *szListbox = "LISTBOX";
char    *vrgszComputerLevel[5] = {"Easy", "Standard", "Tough", "Expert", "Random"};
char    *vrgszComputerPlayers[7] = {"Robotoids", "Turindrones", "Automitrons", "Rototills", "Cybertrons", "Macinti", "Random"};
char    *vrgszFileNew;
char    *vrgszMRU;
char    *vrgszRCWWidth[2] = {"<<     >>", ">>     <<"};
char    *vrgszUnits[6] = {"kT", "kT", "kT", "00", "mg", "% "};
char     iLastGet = -1;
char     iLastMsgGet = -1;
char     iLastStrGet = -1;
uint8_t  rgbCur[1024] = {0};
char     rgszArial[4][32] = {0};
char     rgszSpeed[30] = {
    '-', '-', 0, 189, 0, 0, // 1/2
    190, 0,   0,            // 3/4
    '1', 0,   0,            // 1
    '1', 188, 0,            // 1 1/4
    '1', 189, 0,            // 1 1/2
    '1', 190, 0,            // 1 3/4
    '2', 0,   0,            // 2
    '2', 188, 0,            // 1 1/4
    '2', 189, 0,            // 1 1/2
};
char       szBackup[256];
char       szBase[256];
char       szCRLF[3];
char       szStarsPath[256];
char       szDirName[256];
char       szFormatNumber[12];
char       szLastGet[19];
char       szLastMsgGet[256];
char       szLastStrGet[256];
char       szMineralTitle[90];
char       szMsgBuf[256];
char       szMsgTitle[90];
char       szPassLast[16];
char       szPopupBuffer[256];
char       szRaceFile[256];
char       szRacePass[256];
char       szWork[360];
char       vszDefPass[17] = {0};
COLDROP   *lpcd;
FLEET    **rglpfl;
FRAMESTUFF vfs = {0};
GAME       game = {.mdSize = 2, .mdDensity = 1, .cPlayer = 2, .mdStartDist = 1};
GDATA      gd = {};
HDR        hdrCur = {0};
HDR        hdrPrev = {0};
HS         rghsFutureTech[8] = {0};
INI        ini = {0};
MemJump   *penvMem;
int16_t   *lpMsg;
int16_t   *rgXferValidHulls;
int16_t   *vrgiflMerge;
int16_t    bitTbl[8] = {1, 2, 4, 8, 16, 32, 64, 128};
int16_t    cbbitfMsg = 49;
int16_t    cColDrop = 0;
int16_t    cFleet = 0;
int16_t    cFutureTech = 0;
int16_t    chbrCache = 0;
int16_t    cMinGrafMax = 5000;
int16_t    cMsg = 0;
int16_t    cPlanet = 0;
int16_t    cProdGlob = 0;
int16_t    cRandStack = 0;
int16_t    crcRCW = 0;
int16_t    crgbtnXfer = 0;
int16_t    csh = 0;
int16_t    cThing = 0;
int16_t    cThingAlloc = 0;
int16_t    cXferFull = 0;
int16_t    cXferValidHulls = 0;
int16_t    dGal = 2000;
int16_t    dGalInv = 4000;
int16_t    dGalMinDist = 12;
int16_t    dScanInc = 0;
int16_t    dScanPage = 0;
int16_t    dxBattleDD = 0;
int16_t    dxFleetCompLB = 0;
int16_t    dxMaxMineralQuan = 0;
int16_t    dxOrderED = 0;
int16_t    dxPlanetProdLB = 0;
int16_t    dxResLeft = 0;
int16_t    dxResRadio = 0;
int16_t    dxResRight = 0;
int16_t    dxResStrRight = 0;
int16_t    dxShipDD = 0;
int16_t    dxShipLB = 0;
int16_t    dxTip = 0;
int16_t    dxWinFrame = 0;
int16_t    dxyVCRBoard = 0;
int16_t    dxyVCRSquare = 0;
int16_t    dyArial10 = 0;
int16_t    dyArial6 = 0;
int16_t    dyArial7 = 0;
int16_t    dyArial8 = 0;
int16_t    dyFleetCompLB = 0;
int16_t    dyPlanetProdLB = 0;
int16_t    dySBar = 0;
int16_t    dyShipDD = 0;
int16_t    dyShipLB = 0;
int16_t    dySysFont = 0;
int16_t    dyTitleBar = 0;
int16_t    dyWinFrame = 0;
int16_t    fAi = 0;
int16_t    fAnimate = 0;
int16_t    fBrowserValid = 0;
int16_t    fDirtyPlan = 0;
int16_t    fDlgUp = 0;
bool       fFileErrSilent = false;
int16_t    fFreeingTitle = 0;
int16_t    fHullCopy = 0;
int16_t    fInEditUpdate = 0;
int16_t    fInScoreDialog = 0;
int16_t    fInScrollSet = 0;
int16_t    fLogOff = 0;
int16_t    fLogOut = 1;
int16_t    fMarkedPlanets = 0;
int16_t    fOrdersVis = 0;
int16_t    fProcessingTimer = 0;
int16_t    fRCWReadOnly = 0;
int16_t    fStarbaseDamaged = 0;
int16_t    fStarbaseDied = 0;
int16_t    fStarbaseMode = 0;
int16_t    fValidLx = 0;
int16_t    fValidLxf = 0;
int16_t    fViewFilteredMsg = 0;
int16_t    iAbout1st = 0;
int16_t    iAboutPartial = 0;
int16_t    idBattle = 0;
int16_t    idMsgObj = 0;
int16_t    idPlayer = 1;
int16_t    idsFileError = -1;
int16_t    iLastTutGet = -1;
int16_t    imemLogCur = 0;
int16_t    imemLogPrev = -1;
int16_t    imemMsgCur = 0;
int16_t    iMsgCur = 0;
int16_t    iMsgSendCur = 0;
int16_t    iPanelActive = 0;
int16_t    iPassCnt = 0;
int16_t    iPlanSelDlg = -1;
int16_t    iPopMenuSel = 0;
int16_t    iResTechNow = 0;
int16_t    irowEFleetCur = -1;
int16_t    iScanZoom = 0;
int16_t    iselProd = 0;
int16_t    iselSlot = -2;
int16_t    ishdefBuild = 0;
int16_t    iWindowLayout = 0;
int16_t    mdBuild = 0;
int16_t    mdMsgObj = 0;
int16_t    mdXferDlg = -1;
int16_t    pctResGlob = -1;
int16_t    rgcsxPlr[16] = {0};
int16_t    rgdxOrderDD[3] = {0, 0, 0};
int16_t    rgidPlan[999] = {0};
int16_t    rgmapBuildBmps[21] = {6655, 1, 2, 4, 48, 6462, 6144, 6146, 64, 12, 8, 128, 6154, 52, 256, 512, 2560, 6400, 2048, 4096, 6148};
int16_t    rgOut[16] = {0};
int16_t    vcBackupDirs = 1;
int16_t    vcflMerge = 0;
int16_t    vclpplAi = 0;
int16_t    vcmsgplrIn = 0;
int16_t    vcmsgplrOut = 0;
int16_t    vcplrNew = 0;
int16_t    vcRound = 0;
int16_t    vcScreenColors = 0;
int16_t    vcStepVCR = 0;
int16_t    vctok = 0;
int16_t    vdxScoreX = 0;
int16_t    vfAscendingPrev = 0;
int16_t    vicolSortPrev = -1;
int16_t    vidsTooltip = 0;
int16_t    vidTimerTooltip = -1;
int16_t    viInRe = 0;
int16_t    viRound = 0;
int16_t    viSpeedVCR = 1;
int16_t    viStepVCRCur = 0;
int16_t    viStore = 0;
int16_t    viSubsortPrev = -1;
int16_t    viVCRFocus = 0;
int16_t    vpctProgressGauge = 0;
int16_t    vpctRadarView = 100;
int16_t    vretExitValue = 0;
int16_t    vrgcPrintMapPage[2] = {1, 1};
int16_t    vrgScanPO[2][5] = {{7, 12, 19, 4, 6}, {3, 10, 11, 2, 3}};
int16_t    vyZPDStatic = -1;
int16_t    xNewGameDiamond = 0;
int16_t    xScanTop = 0;
int16_t    yBuildInfoSum = 0;
int16_t    yScanTop = 0;
int16_t    yTopFutureTech = 0;
int16_t    yTopTechNote = -1;
int32_t   *vrgdpVCR;
int32_t    lFileSeed1 = 0;
int32_t    lFileSeed2 = 0;
int32_t    lRandSeed1 = 17;
int32_t    lRandSeed2 = 37;
int32_t    lResBudget = 0;
int32_t    lResTotal = 0;
int32_t    lSaltCur = 0;
int32_t    lSaltLast = 0;
int32_t    rglPopMac[5] = {2500, 5000, 10000, 20000, 30000};
int32_t    rglRandStack[4][2] = {0};
int32_t    vSerialNumber = 0;
LOGXFER    lx = {0};
LOGXFERF   lxf = {0};
MSGPLR    *vlpmsgplrIn;
MSGPLR    *vlpmsgplrOut;
PART       vpartBrowser = {0};
PLANET   **vrglpplAi;
PLANET    *lpPlanets;
PLAYER    *vrgplrNew;
PLAYER     rgplr[16] = {0};
PLAYER     vplr = {0};
PLAYER     vrgplrDef[7] = {
    {.iPlayer = -1,
         .det = 7,
         .iPlrBmp = 1,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {15, 15, 15},
         .rgEnvVarMax = {85, 85, 85},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {10, 10, 10, 10, 10, 5, 10, 0, 1, 1, 1, 1, 1, 1, 9, 0}},
    {.iPlayer = -1,
         .det = 7,
         .iPlrBmp = 12,
         .rgEnvVar = {33, 58, 33},
         .rgEnvVarMin = {10, 35, 13},
         .rgEnvVarMax = {56, 81, 53},
         .pctIdealGrowth = 20,
         .pctResearch = 15,
         .rgAttr = {10, 10, 9, 17, 10, 9, 10, 4, 0, 0, 2, 1, 1, 2, 7, 0},
         .grbitAttr = 0x80000503},
    {.iPlayer = -1,
         .det = 7,
         .iPlrBmp = 4,
         .rgEnvVar = {-1, 50, 85},
         .rgEnvVarMin = {-1, 0, 70},
         .rgEnvVarMax = {-1, 100, 100},
         .pctIdealGrowth = 10,
         .pctResearch = 15,
         .rgAttr = {10, 10, 10, 10, 9, 10, 6, 1, 2, 2, 2, 2, 1, 0, 2, 0},
         .grbitAttr = 0x00002108},
    {.iPlayer = -1,
         .det = 7,
         .iPlrBmp = 25,
         .rgEnvVar = {-1, 50, 50},
         .rgEnvVarMin = {-1, 12, 0},
         .rgEnvVarMax = {-1, 88, 100},
         .pctIdealGrowth = 10,
         .pctResearch = 15,
         .rgAttr = {9, 10, 10, 10, 10, 15, 5, 3, 0, 0, 0, 0, 0, 0, 1, 0},
         .grbitAttr = 0x2000000c},
    {.iPlayer = -1,
         .det = 7,
         .iPlrBmp = 5,
         .rgEnvVar = {-1, -1, -1},
         .rgEnvVarMin = {-1, -1, -1},
         .rgEnvVarMax = {-1, -1, -1},
         .pctIdealGrowth = 6,
         .pctResearch = 15,
         .rgAttr = {8, 12, 12, 15, 10, 9, 10, 3, 1, 1, 2, 2, 1, 0, 0, 0},
         .grbitAttr = 0x00001221},
    {.iPlayer = -1,
         .det = 7,
         .iPlrBmp = 18,
         .rgEnvVar = {15, 50, 85},
         .rgEnvVarMin = {0, 0, 70},
         .rgEnvVarMax = {30, 100, 100},
         .pctIdealGrowth = 7,
         .pctResearch = 15,
         .rgAttr = {7, 11, 10, 18, 10, 10, 10, 0, 2, 0, 2, 2, 2, 2, 5, 0},
         .grbitAttr = 0x000005c4},
    {.iPlayer = -1,
         .det = 7,
         .iPlrBmp = 31,
         .rgEnvVar = {50, 50, 50},
         .rgEnvVarMin = {17, 17, 17},
         .rgEnvVarMax = {83, 83, 83},
         .pctIdealGrowth = 15,
         .pctResearch = 15,
         .rgAttr = {10, 10, 10, 10, 10, 3, 10, 0, 1, 1, 1, 1, 1, 1, 0, 0},
         .grbitAttr = 0x40000000},
};
PLPROD    *lpplProdGlob = NULL;
POINT      ptPlaque = {0};
POINT      ptslotGlob = {0};
POINT      ptSpeedVCR = {0};
POINT      ptStickyBattlePlansDlg = {.x = -1, .y = -1};
POINT      ptStickyBrowserDlg = {.x = -1, .y = -1};
POINT      ptStickyFindDlg = {.x = -1, .y = -1};
POINT      ptStickyHostModeDlg = {.x = -1, .y = -1};
POINT      ptStickyMergeFleetsDlg = {.x = -1, .y = -1};
POINT      ptStickyNewDlg = {.x = -1, .y = -1};
POINT      ptStickyPrintMapDlg = {.x = -1, .y = -1};
POINT      ptStickyProduceDlg = {.x = -1, .y = -1};
POINT      ptStickyRaceDlg = {.x = -1, .y = -1};
POINT      ptStickyRelationsDlg = {.x = -1, .y = -1};
POINT      ptStickyRenameDlg = {.x = -1, .y = -1};
POINT      ptStickyResDlg = {.x = -1, .y = -1};
POINT      ptStickyScoreXDlg = {.x = -1, .y = -1};
POINT      ptStickySlotDlg = {.x = -1, .y = -1};
POINT      ptStickyTransferDlg = {.x = -1, .y = -1};
POINT      ptStickyTutorDlg = {.x = -1, .y = -1};
POINT      ptStickyVCRDlg = {.x = -1, .y = -1};
POINT      ptStickyZipOrderDlg = {.x = -1, .y = -1};
POINT      ptStickyZipProdDlg = {.x = -1, .y = -1};
POINT      rgptArrow[5] = {{.x = 3, .y = 0}, {.x = 0, .y = 3}, {.x = -1, .y = 3}, {.x = 2, .y = 3}, {.x = -3, .y = 6}};
STARSPOINT rgptPlan[999] = {0};
POINT      rgptTriangle[3] = {{.x = 4, .y = 0}, {.x = 0, .y = 4}, {.x = -1, .y = 4}};
POINT      vptMsg = {0};
POINT      vptTbLast = {.x = -1, .y = -1};
PROD      *pProdGlob;
POPUPDATA  GlobalPD = {.grPopup = 0, .iPlrMax = 0};
RECT      *vrgrcRCW;
RECT       rcCargo = {0};
RECT       rcMsgText = {0};
RECT       rcMsgTitle = {0};
RECT       rcProdDiamond = {0};
RECT       rcSpinBot = {0};
RECT       rcSpinTop = {0};
RECT       rgrcBuildSpin[2] = {0};
RECT       rgrcRef[19] = {0};
RECT       vrcTooltip = {0};
RECT       vrgrcSlot[16] = {0};
RPT       *vprptCur;
RPT        vrptBattle = {.grbitVisible = 65535, .irpt = 3, .cFields = 15, .cFieldFirst = 1, .fAscending = 1, .ptDlg = {0}, .ptSize = {0}};
RPT        vrptEFleet = {.grbitVisible = 65535, .irpt = 2, .cFields = 12, .cFieldFirst = 1, .fAscending = 1, .ptDlg = {0}, .ptSize = {0}};
RPT        vrptFleet = {.grbitVisible = 65535, .irpt = 1, .cFields = 12, .cFieldFirst = 1, .fAscending = 1, .ptDlg = {0}, .ptSize = {0}};
RPT        vrptPlanet = {.grbitVisible = 65535, .cFields = 15, .cFieldFirst = 1, .fAscending = 1, .ptDlg = {0}, .ptSize = {0}};
SCOREX    *rgsxPlr[1];
SCOREX    *vlprgScoreX;
SEL        sel = {0};
SHDEF     *lpshdefBuild;
SHDEF     *rglpshdef[cPlayerMax] = {0};
SHDEF     *rglpshdefSB[cPlayerMax] = {0};
SHDEF      rgshdef[16] = {0};
SHDEF      shdefBuild = {0};
THING     *lpthBattle;
THING     *lpThings;
TILE       rgtilePlanet[6] = {
    {.yTop = 1, .dyFull = 85, .grbit = 128, .fPopped = 1, .fMinTitle = 1, .idh = 0x05e2},
    {.yTop = 6, .dyFull = 5, .grbit = 1, .id = 1, .fPopped = 1, .idh = 0x05e5},
    {.yTop = 8, .dyFull = 6, .grbit = 8, .id = 4, .fPopped = 1, .idh = 0x05e4},
    {.yTop = 6, .dyFull = 22, .grbit = 4, .iCol = 1, .id = 5, .fPopped = 1, .fNullPtr = 1, .idh = 0x05e6},
    {.yTop = 10, .dyFull = 20, .grbit = 64, .iCol = 1, .id = 6, .fPopped = 1, .idh = 0x05e3},
    {.yTop = 8, .dyFull = 15, .grbit = 256, .iCol = 1, .id = 7, .fPopped = 1, .fNullPtr = 1, .fMinTitle = 1, .idh = 0x05e7},
};
TILE rgtileShip[7] = {
    {.yTop = 1, .dyFull = 85, .grbit = 128, .fPopped = 1, .fMinTitle = 1, .idh = 0x05e9},
    {.yTop = 3, .dyFull = 5, .grbit = 64, .id = 5, .fPopped = 1, .fMinTitle = 1, .idh = 0x05ea},
    {.yTop = 11, .dyFull = 19, .grbit = 32, .id = 3, .fPopped = 1, .idh = 0x05ee},
    {.yTop = 6, .dyFull = 12, .grbit = 256, .id = 4, .fPopped = 1, .idh = 0x05ef},
    {.yTop = 7, .dyFull = 14, .grbit = 1, .iCol = 1, .id = 1, .fPopped = 1, .idh = 0x05eb},
    {.yTop = 12, .dyFull = 16, .grbit = 512, .iCol = 1, .id = 9, .fPopped = 1, .idh = 0x05ec},
    {.yTop = 6, .dyFull = 22, .grbit = 4, .iCol = 1, .id = 8, .fPopped = 1, .idh = 0x05ed},
};
TIMER       vtimer = {0};
TOK        *vrgtok;
TURNSERIAL *vrgts;
TUTOR       tutor = {0};
uint16_t   *vlprgidFleet;
uint16_t   *vlprgidMisc;
uint16_t   *vlprgidPlanet;
uint16_t   *vlprgidRep;
uint16_t   *vlpwtCargo;
uint16_t   *vrgPlanResExtra;
uint16_t   *vrgPlrLosses;
uint16_t    grbitScan = 0x0000;
uint16_t    grbitScanEShip = 0;
uint16_t    grbitScanMines = 0;
uint16_t    grbitScanShip = 0;
uint16_t    grfMissed = 0;

uint16_t  rgidRaceBtn[0];
uint16_t  uDateInstalled = 0;
uint16_t  uTimerId = 0x0000;
uint16_t  uTimerType = 0x0000;
uint16_t  vcPasswordFailures = 0x0000;
uint16_t  wVersFile = 0x0000;
uint32_t  crButtonFace = 0;
uint32_t  crButtonHilite = 0;
uint32_t  crButtonShadow = 0;
uint32_t  crButtonText = 0;
uint32_t  crWindow = 0;
uint32_t  crWindowText = 0;
uint32_t  ctickLast = 0x00000000;
uint32_t  vtickTooltip1stVis = 0;
uint32_t  vtickTooltipLast = 0x00000000;
uint8_t  *lpb2k;
uint8_t  *lpbBattleCur;
uint8_t  *lpbBattleLog;
uint8_t  *lpbBattleT;
uint8_t  *lpLog;
uint8_t  *vAiMacRecycleSB;
uint8_t  *vlpbAiData;
uint8_t  *vlpbAiPlanet;
uint8_t  *vlpMemStream;
uint8_t   bitfMsgFiltered[49] = {0};
uint8_t   bitfMsgSent[49] = {0};
uint8_t   ctype[0];
uint8_t   mpiTypeiItem[3] = {0x00, 0x04, 0x07};
uint8_t   rgcbtlplan[16] = {0};
uint8_t   rgTechBattle[6] = {0};
uint8_t   rgTechTrader[13] = {0};
uint8_t   vbrcVCRFocus = 0;
uint8_t   vrgAiArmadaPotency[4] = {0};
uint8_t   vrgAiCyberArmadaPotency[4] = {0};
uint8_t   vrgbEnvCur[11] = {0};
uint8_t   vrgbMachineConfig[11] = {0};
uint8_t   vrgcAiParts[45] = {0x01, 0x01, 0x04, 0x04, 0x06, 0x03, 0x04, 0x03, 0x04, 0x06, 0x07, 0x01, 0x04, 0x05, 0x02,
                             0x04, 0x01, 0x02, 0x03, 0x02, 0x04, 0x02, 0x03, 0x04, 0x02, 0x01, 0x07, 0x03, 0x01, 0x01,
                             0x04, 0x01, 0x01, 0x01, 0x04, 0x04, 0x08, 0x02, 0x05, 0x02, 0x01, 0x05, 0x01, 0x02, 0x03};
uint8_t   vrgplrTypeNew[16] = {0};
XFER     *pxfer;
XFERFULL *lpxf;
ZIPORDER  vrgZip[4] = {0};
ZIPPRODQ  vrgZipProd[5] = {0};

#ifdef _WIN32

COLORREF rgcrCache[32] = {0};
COLORREF rgcrMinerals[6] = {0x00ff0000, 0x00007f00, 0x0000ffff, 0x00ffffff, 0x000000ff, 0x00000000};
COLORREF rgcrPlrHistory[16] = {0x003ff0f0, 0x000000ff, 0x0000ff00, 0x00ff0000, 0x0000ffff, 0x00ff00ff, 0x00ffff00, 0x0000007f,
                               0x00007f00, 0x007f0000, 0x007f7f7f, 0x0067c839, 0x00237fff, 0x00ff7f23, 0x00007f7f, 0x00606060};

HINSTANCE hInst = 0;
WNDPROC   lpfnRealEditProc = NULL;

HPEN     hpenDkBlue = 0;
HPEN     hpenDkGreen = 0;
HPEN     hpenDkPurple = 0;
HPEN     hpenDkYellow = 0;
HPEN     hpenEnemy = 0;
HPEN     hpenMassPath = 0;
HPEN     hpenRadar = 0;
HPEN     hpenRadarNear = 0;
HPEN     hpenShip = 0;
HPEN     hpenStarbase = 0;
HPEN     hpenYellow = 0;
HRGN     hrgnHuge = 0;
HRGN     hrgnScratch = 0;
HWND     hwndActive = 0x0000;
HWND     hwndBattleDD = 0;
HWND     hwndBrowser = 0x0000;
HWND     hwndBrowserChild = 0;
HWND     hwndFleetCompLB = 0;
HWND     hwndFrame = 0;
HWND     hwndMain = 0;
HWND     hwndMDIClient = 0;
HWND     hwndMessage = 0x0000;
HWND     hwndMine = 0x0000;
HWND     hwndMineCB = 0;
HWND     hwndMsgDrop = 0;
HWND     hwndMsgEdit = 0;
HWND     hwndMsgScroll = 0;
HWND     hwndOrderED = 0x0000;
HWND     hwndPlanet = 0x0000;
HWND     hwndPlanetProdLB = 0;
HWND     hwndPopup = 0x0000;
HWND     hwndProdDlg = 0x0000;
HWND     hwndProgressGauge = 0x0000;
HWND     hwndRaceParent = 0;
HWND     hwndRepCB = 0;
HWND     hwndReportDlg = 0x0000;
HWND     hwndScanner = 0x0000;
HWND     hwndScoreXDlg = 0x0000;
HWND     hwndShipDD = 0;
HWND     hwndShipLB = 0;
HWND     hwndSlotDlg = 0x0000;
HWND     hwndTb = 0x0000;
HWND     hwndTBRadar = 0x0000;
HWND     hwndTitle = 0x0000;
HWND     hwndTooltip = 0x0000;
HWND     hwndVCRDlg = 0x0000;
HWND     hwndZipOrderDlg = 0x0000;
HACCEL   hAccel = 0;
HACCEL   hAccelTitle = 0;
HBITMAP  hbmpBackBld = 0;
HBITMAP  hbmpMono = 0;
HBITMAP  hbmpMsg = 0;
HBITMAP  hbmpNumbers = 0;
HBITMAP  hbmpScanner = 0;
HBITMAP  hbmpScanShip = 0;
HBITMAP  hbmpUnknownPlanet = 0;
HBRUSH   hbr50Screen = 0;
HBRUSH   hbrBBlue = 0;
HBRUSH   hbrBlue = 0x0000;
HBRUSH   hbrButtonFace = 0x0000;
HBRUSH   hbrButtonHilite = 0x0000;
HBRUSH   hbrButtonShadow = 0x0000;
HBRUSH   hbrButtonText = 0x0000;
HBRUSH   hbrCargo = 0;
HBRUSH   hbrDesktop = 0x0000;
HBRUSH   hbrDkYellow = 0;
HBRUSH   hbrDock = 0;
HBRUSH   hbrEnemy = 0;
HBRUSH   hbrGray = 0x0000;
HBRUSH   hbrGreen = 0x0000;
HBRUSH   hbrLightGray = 0x0000;
HBRUSH   hbrPurple = 0;
HBRUSH   hbrRadar = 0;
HBRUSH   hbrRadarNear = 0;
HBRUSH   hbrRed = 0x0000;
HBRUSH   hbrSelect = 0;
HBRUSH   hbrShip = 0;
HBRUSH   hbrStarbase = 0;
HBRUSH   hbrTooltip = 0;
HBRUSH   hbrWindow = 0x0000;
HBRUSH   hbrWindowFrame = 0x0000;
HBRUSH   hbrWindowText = 0x0000;
HBRUSH   hbrYellow = 0;
HCURSOR  hcurArrowHelp = 0;
HCURSOR  hcurCloseGrab = 0;
HCURSOR  hcurHand = 0;
HCURSOR  hcurNoWay = 0;
HCURSOR  hcurOpenGrab = 0;
HCURSOR  hcurResize4Way = 0;
HCURSOR  hcurResizeNS = 0;
HCURSOR  hcurResizeWE = 0;
HCURSOR  hcurScanAdd = 0;
HCURSOR  hcurScanner = 0;
HCURSOR  hcurTrashCan = 0;
HGLOBAL  hdibPlanets = 0;
HGLOBAL  hdibPlaque = 0x0000;
HGLOBAL  hdibRaces = 0;
HGLOBAL  hdibRacesT = 0;
HGLOBAL  hdibRacesX = 0;
HGLOBAL  hdibThings = 0;
HGLOBAL  hdibToolbar = 0;
HICON    hiconHost = 0x0000;
HICON    hiconStars = 0x0000;
HICON    hiconWait = 0x0000;
HBRUSH   rghbrCache[32] = {0};
HBRUSH   rghbrMineral[5] = {0};
HBRUSH   rghbrMinSum[4][2] = {0};
HBRUSH   rghbrPat[3] = {0};
HBRUSH   rghbrPlanetAttr[3][2] = {0};
uint8_t  rghbrCacheUse[32] = {0};
HGLOBAL  rghdibInventory[7] = {0};
HGLOBAL  rghdibShips[5] = {0};
HGLOBAL  rghdibShipsT[5] = {0};
HFONT    rghfontArial10[2] = {0};
HFONT    rghfontArial6[1] = {0};
HFONT    rghfontArial7[1] = {0};
HFONT    rghfontArial8[5] = {0};
HICON    rghiconVCR[7] = {0};
HWND     rghwndBtn[13] = {0};
HWND     rghwndBtnSplash[4] = {0x0000, 0x0000, 0x0000, 0x0000};
HWND     rghwndMsgBtn[4] = {0};
HWND     rghwndOrderDD[3] = {0};
HGLOBAL  vhdibTitle = 0x0000;
HPALETTE vhpal = 0;
HPALETTE vhpalSplash = 0x0000;

#endif /* _WIN32 */