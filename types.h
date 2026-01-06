#ifndef STARS_NB09_TYPES_H
#define STARS_NB09_TYPES_H
#include <stdint.h>
#include <stdbool.h>

/* forward declarations (to satisfy pointer members) */
typedef struct _planet PLANET;
typedef struct _fleet FLEET;
typedef struct _order ORDER;
typedef struct _thing THING;
typedef struct _shdef SHDEF;
typedef struct _game GAME;
typedef struct _gdata GDATA;
typedef struct _player PLAYER;
typedef struct tagPOINT POINT;
typedef struct tagPAINTSTRUCT PAINTSTRUCT;
typedef struct tagRECT RECT;
typedef struct _framestuff FRAMESTUFF;
typedef struct _prod PROD;
typedef struct _cyberinfo CYBERINFO;
typedef struct _cyberinfotemp CYBERINFOTEMP;
typedef struct _scan SCAN;
typedef struct PLPROD PLPROD;
typedef struct _sel SEL;
typedef struct _part PART;
typedef struct _hul HUL;
typedef struct _hs HS;
typedef struct _ziporder ZIPORDER;
typedef struct _scorex SCOREX;
typedef struct _btldata BTLDATA;
typedef struct _rpt RPT;
typedef struct _btlplan BTLPLAN;
typedef struct _popupdata POPUPDATA;
typedef struct _itemaction ITEMACTION;
typedef struct _tok TOK;
typedef struct _ini INI;
typedef struct _tutor TUTOR;
typedef struct _zipprodq1 ZIPPRODQ1;
typedef struct _zipprodq ZIPPRODQ;
typedef struct _aipart AIPART;
typedef struct tagTIMERINFO TIMERINFO;
typedef struct _hb HB;
typedef struct _btlrec BTLREC;
typedef struct _dv DV;
typedef struct _btnt BTNT;
typedef struct _find_t FIND_T;
typedef struct _diskfree_t DISKFREE_T;
typedef struct tagOFSTRUCT OFSTRUCT;
typedef struct tagLOGFONT LOGFONT;
typedef struct tagMSG MSG;
typedef struct tagBITMAPCOREHEADER BITMAPCOREHEADER;
typedef struct tagBITMAPINFOHEADER BITMAPINFOHEADER;
typedef struct tagLOGPALETTE LOGPALETTE;
typedef struct tagBITMAP BITMAP;
typedef struct tagTEXTMETRIC TEXTMETRIC;
typedef struct tagOFN OFN;
typedef struct _engine ENGINE;
typedef struct _pl PL;
typedef struct tagDRAWITEMSTRUCT DRAWITEMSTRUCT;
typedef struct tagMEASUREITEMSTRUCT MEASUREITEMSTRUCT;
typedef struct _huldef HULDEF;
typedef struct _scanner SCANNER;
typedef struct _planetary PLANETARY;
typedef struct _armor ARMOR;
typedef struct _shield SHIELD;
typedef struct _special SPECIAL;
typedef struct _mines MINES;
typedef struct _mining MINING;
typedef struct _terra TERRA;
typedef struct _bomb BOMB;
typedef struct _torp TORP;
typedef struct _beam BEAM;
typedef struct _specialsb SPECIALSB;
typedef struct _msgplr MSGPLR;
typedef struct _msgbig MSGBIG;
typedef struct _msgturn MSGTURN;
typedef struct _msghdr MSGHDR;
typedef struct _hdr HDR;
typedef struct _starpack STARPACK;
typedef struct _rtbof RTBOF;
typedef struct _xfer XFER;
typedef struct _xferfull XFERFULL;
typedef struct _coldrop COLDROP;
typedef struct _score SCORE;
typedef struct _turnserial TURNSERIAL;
typedef struct _rthisthdr RTHISTHDR;
typedef struct _rtChgProdQ RTCHGPRODQ;
typedef struct _prodq1 PRODQ1;
typedef struct tagEVENTMSG EVENTMSG;
typedef struct _rtlogthing RTLOGTHING;
typedef struct tagFINDREPLACE FINDREPLACE;
typedef struct _rtChgPlanetLong RTCHGPLANETLONG;
typedef struct _planetsome PLANETSOME;
typedef struct tagRGBTRIPLE RGBTRIPLE;
typedef struct tagBITMAPCOREINFO BITMAPCOREINFO;
typedef struct _exceptionl EXCEPTIONL;
typedef struct tagGLYPHMETRICS GLYPHMETRICS;
typedef struct _taskxport TASKXPORT;
typedef struct _tasklaymines TASKLAYMINES;
typedef struct _taskpatrol TASKPATROL;
typedef struct _tasksell TASKSELL;
typedef struct _complexl COMPLEXL;
typedef struct tagBITMAPFILEHEADER BITMAPFILEHEADER;
typedef struct tagCLIENTCREATESTRUCT CLIENTCREATESTRUCT;
typedef struct tagWNDCLASS WNDCLASS;
typedef struct tagMETAFILEPICT METAFILEPICT;
typedef struct tagDEBUGHOOKINFO DEBUGHOOKINFO;
typedef struct _obj OBJ;
typedef struct _tile TILE;
typedef struct HELPWININFO HELPWININFO;
typedef struct MENUITEMTEMPLATE MENUITEMTEMPLATE;
typedef struct MENUITEMTEMPLATEHEADER MENUITEMTEMPLATEHEADER;
typedef struct DOCINFO DOCINFO;
typedef struct tagDEVNAMES DEVNAMES;
typedef struct tagDRVCONFIGINFO DRVCONFIGINFO;
typedef struct _logxfer LOGXFER;
typedef struct _btn BTN;
typedef struct _kill KILL;
typedef struct _logxferf LOGXFERF;
typedef struct _fleetsome FLEETSOME;
typedef struct tagMETAHEADER METAHEADER;
typedef struct tagWINDEBUGINFO WINDEBUGINFO;
typedef struct tagLOGPEN LOGPEN;
typedef struct _rtxfer RTXFER;
typedef struct tagFIXED FIXED;
typedef struct _compart COMPART;
typedef struct tagDCB DCB;
typedef struct _rtxferx RTXFERX;
typedef struct _thmine THMINE;
typedef struct tagCOMSTAT COMSTAT;
typedef struct tagMAT2 MAT2;
typedef struct _rtxferl RTXFERL;
typedef struct _rtxferf RTXFERF;
typedef struct _btlrec26 BTLREC26;
typedef struct tagRGBQUAD RGBQUAD;
typedef struct _thpack THPACK;
typedef struct _rtshipint RTSHIPINT;
typedef struct _aistarbase AISTARBASE;
typedef struct _exception EXCEPTION;
typedef struct tagHANDLETABLE HANDLETABLE;
typedef struct _sbar SBAR;
typedef struct _rtshipint2 RTSHIPINT2;
typedef struct tagWINDOWPOS WINDOWPOS;
typedef struct tagCREATESTRUCT CREATESTRUCT;
typedef struct tagPD PD;
typedef struct _thworm THWORM;
typedef struct _aihist AIHIST;
typedef struct tagCHOOSEFONT CHOOSEFONT;
typedef struct _rtwaypt RTWAYPT;
typedef struct _drawcir DRAWCIR;
typedef struct tagMETARECORD METARECORD;
typedef struct tagMDICREATESTRUCT MDICREATESTRUCT;
typedef struct _timer TIMER;
typedef struct _complex COMPLEX;
typedef struct _rtchgname RTCHGNAME;
typedef struct complex complex;
typedef struct _lsb LSB;
typedef struct tagPOINTFX POINTFX;
typedef struct tagPANOSE PANOSE;
typedef struct tagOUTLINETEXTMETRIC OUTLINETEXTMETRIC;
typedef struct _thtrader THTRADER;
typedef struct tagCBT_CREATEWND CBT_CREATEWND;
typedef struct tagMOUSEHOOKSTRUCT MOUSEHOOKSTRUCT;
typedef struct tagTTPOLYCURVE TTPOLYCURVE;
typedef struct tagNEWTEXTMETRIC NEWTEXTMETRIC;
typedef struct tagWINDOWPLACEMENT WINDOWPLACEMENT;
typedef struct tagCBTACTIVATESTRUCT CBTACTIVATESTRUCT;
typedef struct tagTTPOLYGONHEADER TTPOLYGONHEADER;
typedef struct tagPALETTEENTRY PALETTEENTRY;
typedef struct _rtshdef RTSHDEF;
typedef struct _rtchgshdef RTCHGSHDEF;
typedef struct tagDELETEITEMSTRUCT DELETEITEMSTRUCT;
typedef struct tagHARDWAREHOOKSTRUCT HARDWAREHOOKSTRUCT;
typedef struct _rtplanet RTPLANET;
typedef struct tagDRIVERINFOSTRUCT DRIVERINFOSTRUCT;
typedef struct tagCHOOSECOLOR CHOOSECOLOR;
typedef struct tagABC ABC;
typedef struct tagLOGBRUSH LOGBRUSH;
typedef struct tagSIZE SIZE;
typedef struct _fleetid FLEETID;
typedef struct tagMULTIKEYHELP MULTIKEYHELP;
typedef struct _vers VERS;
typedef struct tagNCCALCSIZE_PARAMS NCCALCSIZE_PARAMS;
typedef struct tagCOMPAREITEMSTRUCT COMPAREITEMSTRUCT;
typedef struct tagMINMAXINFO MINMAXINFO;
typedef struct tagSEGINFO SEGINFO;
typedef struct tagKERNINGPAIR KERNINGPAIR;
typedef struct tagENUMLOGFONT ENUMLOGFONT;
typedef struct PLORD PLORD;
typedef struct _selSome SELSOME;
typedef struct _planetminimal PLANETMINIMAL;
typedef struct _wn WN;
typedef struct tagBITMAPINFO BITMAPINFO;
typedef struct tagRASTERIZER_STATUS RASTERIZER_STATUS;
typedef struct _rtloghdr RTLOGHDR;
typedef struct _mdplr MDPLR;
typedef struct _div_t DIV_T;
typedef struct _ldiv_t LDIV_T;

/* typind 4098 (0x1002) size=56 */
typedef struct _planet {
    int16_t id;  /* +0x0000 */
    int16_t iPlayer;  /* +0x0002 */
    union {
        struct {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fStarbase : 1;
            uint16_t fHomeworld : 1;
            uint16_t fFirstYear : 1;
            uint16_t unusedC : 1;
            uint16_t fWasInhabited : 1;
            uint16_t unusedD : 2;
        };
    };  /* +0x0004 */
    uint8_t rgpctMinLevel[3];  /* +0x0006 */
    uint8_t rgMinConc[3];  /* +0x0009 */
    char rgEnvVar[3];  /* +0x000c */
    char rgEnvVarOrig[3];  /* +0x000f */
    union {
        uint16_t uGuesses;
        struct {
            uint16_t uPopGuess : 12;
            uint16_t uDefGuess : 4;
        };
    };  /* +0x0012 */
    union {
        uint8_t rgbImp[8];
        struct {
            uint32_t iDeltaPop : 8;
            uint32_t cMines : 12;
            uint32_t cFactories : 12;
        };
    };  /* +0x0014 */
    union {
        struct {
            uint32_t cDefenses : 12;
            uint32_t iScanner : 5;
            uint32_t unused5 : 5;
            uint32_t fArtifact : 1;
            uint32_t fNoResearch : 1;
            uint32_t unused2 : 8;
        };
    };  /* +0x0018 */
    int32_t rgwtMin[4];  /* +0x001c */
    union {
        int32_t lStarbase;
        struct {
            uint16_t isb : 4;
            uint16_t pctDp : 12;
        };
    };  /* +0x002c */
    union {
        struct {
            uint16_t idFling : 10;
            uint16_t iWarpFling : 4;
            uint16_t fNoHeal : 1;
            uint16_t unused3 : 1;
        };
    };  /* +0x002e */
    union {
        uint16_t wRouting;
        struct {
            uint16_t idRoute : 10;
            uint16_t unused4 : 6;
        };
    };  /* +0x0030 */
    int16_t turn;  /* +0x0032 */
    PLPROD * lpplprod;  /* +0x0034 */
} PLANET;

/* typind 4114 (0x1012) size=64 */
typedef struct _game {
    int32_t lid;  /* +0x0000 */
    int16_t mdSize;  /* +0x0004 */
    int16_t mdDensity;  /* +0x0006 */
    int16_t cPlayer;  /* +0x0008 */
    int16_t cPlanMax;  /* +0x000a */
    int16_t mdStartDist;  /* +0x000c */
    int16_t fDirty;  /* +0x000e */
    union {
        uint16_t wCrap;
        struct {
            uint16_t fExtraFuel : 1;
            uint16_t fSlowTech : 1;
            uint16_t fSinglePlr : 1;
            uint16_t fTutorial : 1;
            uint16_t fAisBand : 1;
            uint16_t fBBSPlay : 1;
            uint16_t fVisScores : 1;
            uint16_t fNoRandom : 1;
            uint16_t fClumping : 1;
            uint16_t wGen : 3;
            uint16_t unused : 4;
        };
    };  /* +0x0010 */
    uint16_t turn;  /* +0x0012 */
    uint8_t rgvc[12];  /* +0x0014 */
    char szName[32];  /* +0x0020 */
} GAME;

/* typind 4115 (0x1013) size=10 */
typedef struct _gdata {
    union {
        int32_t grBits;
        struct {
            uint16_t fUnknownShip : 1;
            uint16_t fGeneratingTurn : 1;
            uint16_t fForceTurn : 1;
            uint16_t fHostMode : 1;
            uint16_t fSubmit : 1;
            uint16_t fNoResearchSav : 1;
            uint16_t fRadiatingEngine : 1;
            uint16_t fNoIdleChecks : 1;
            uint16_t fSendMsgMode : 1;
            uint16_t fRetryOpens : 1;
            uint16_t fAisDone : 1;
            uint16_t fTutorial : 1;
            uint16_t fGotoVCR : 1;
            uint16_t fVCRTimer : 1;
            uint16_t mdScreenSize : 2;
        };
    };  /* +0x0000 */
    union {
        struct {
            uint16_t fGameOverMan : 1;
            uint16_t fDontDoLogFiles : 1;
            uint16_t fFileCrippled : 1;
            uint16_t fSmallTileMode : 1;
            uint16_t fAllAis : 1;
            uint16_t fReadOnly : 1;
            uint16_t fExitWindows : 1;
            uint16_t fPartialTurn : 1;
            uint16_t fSetMassMode : 1;
            uint16_t fRptSafeDraw : 1;
            uint16_t fProgressTxt : 1;
            uint16_t fSoundFX : 1;
            uint16_t fNoSound : 1;
            uint16_t fSetRouteMode : 1;
            uint16_t fBleedingEdge : 1;
            uint16_t fToolbar : 1;
        };
    };  /* +0x0002 */
    union {
        int32_t grBits2;
        struct {
            uint16_t fNoScannerDraw : 1;
            uint16_t fTrialPeriodOver : 1;
            uint16_t fClose : 1;
            uint16_t fDontCalcBleed : 1;
            uint16_t fChgZipOrd : 1;
            uint16_t fChgZipProd : 1;
            uint16_t fChgScanner : 1;
            uint16_t fChgReports : 1;
            uint16_t fWriteTurnNum : 1;
            uint16_t fHotSeat : 1;
            uint16_t fFleetLinkValid : 1;
            uint16_t fScoreVictory : 2;
        };
    };  /* +0x0004 */
    union {
        struct {
            uint16_t iCurGraph : 4;
            uint16_t fMusic : 1;
            uint16_t fPerPlayerDumps : 1;
            uint16_t fNoHostNames : 1;
        };
    };  /* +0x0006 */
    uint16_t fUnused2 : 14;  /* +0x0008 */
} GDATA;

/* typind 4120 (0x1018) size=4 */
typedef struct tagPOINT {
    int16_t x;  /* +0x0000 */
    int16_t y;  /* +0x0002 */
} POINT;

/* typind 4122 (0x101a) size=8 */
typedef struct tagRECT {
    int16_t left;  /* +0x0000 */
    int16_t top;  /* +0x0002 */
    int16_t right;  /* +0x0004 */
    int16_t bottom;  /* +0x0006 */
} RECT;

/* typind 4152 (0x1038) size=22 */
typedef struct _framestuff {
    int16_t dx;  /* +0x0000 */
    int16_t dy;  /* +0x0002 */
    int16_t xTop;  /* +0x0004 */
    int16_t y1;  /* +0x0006 */
    int16_t y2;  /* +0x0008 */
    int16_t dxPlanWant;  /* +0x000a */
    int16_t dyMsgWant;  /* +0x000c */
    int16_t dyMinWant;  /* +0x000e */
    int16_t dx2PlanWant;  /* +0x0010 */
    int16_t dy2MsgWant;  /* +0x0012 */
    int16_t dy2MinWant;  /* +0x0014 */
} FRAMESTUFF;

/* typind 4153 (0x1039) size=4 */
typedef struct _prod {
    union {
        struct {
            uint32_t cItem : 10;
            uint32_t iItem : 7;
            uint32_t grobj : 3;
            uint32_t pct : 7;
            uint32_t unused : 5;
        };
    };  /* +0x0000 */
} PROD;

/* typind 4158 (0x103e) size=2 */
typedef struct _cyberinfo {
    union {
        uint16_t wInfo;
        struct {
            uint16_t iLstPktDir : 3;
            uint16_t fBltColony : 1;
            uint16_t fLaunchedPkt : 1;
            uint16_t iPktTarget : 2;
            uint16_t fNeedScanPkt : 1;
            uint16_t unused : 8;
        };
    };  /* +0x0000 */
} CYBERINFO;

/* typind 4160 (0x1040) size=2 */
typedef struct _cyberinfotemp {
    union {
        uint16_t wInfo1;
        struct {
            uint16_t fIdleColonizers : 1;
            uint16_t cIdleFreighters : 2;
            uint16_t cFreightersDst : 2;
            uint16_t fNeedDefenders : 1;
            uint16_t fDefended : 1;
            uint16_t fUnderAttack : 1;
            uint16_t fNeedsMin1 : 1;
            uint16_t fNeedsMin2 : 1;
            uint16_t fNeedsMin3 : 1;
            uint16_t unused : 5;
        };
    };  /* +0x0000 */
} CYBERINFOTEMP;

/* typind 4216 (0x1078) size=4 */
typedef struct _hs {
    uint16_t grhst;  /* +0x0000 */
    union {
        struct {
            uint16_t iItem : 8;
            uint16_t cItem : 8;
        };
    };  /* +0x0002 */
} HS;

/* typind 4286 (0x10be) size=36 */
typedef struct _btlplan {
    union {
        struct {
            uint16_t iplr : 4;
            uint16_t iplan : 4;
            uint16_t mdTactic : 4;
            uint16_t unused1 : 2;
            uint16_t fDelete : 1;
            uint16_t fDumpCargo : 1;
        };
    };  /* +0x0000 */
    union {
        struct {
            uint16_t mdTarget1 : 4;
            uint16_t mdTarget2 : 4;
            uint16_t iplrAttack : 5;
            uint16_t unused2 : 3;
        };
    };  /* +0x0002 */
    char szName[32];  /* +0x0004 */
} BTLPLAN;

/* typind 4299 (0x10cb) size=2 */
typedef struct _itemaction {
    union {
        struct {
            uint16_t cQuan : 12;
            uint16_t iAction : 4;
        };
    };  /* +0x0000 */
} ITEMACTION;

/* typind 4416 (0x1140) size=2 */
typedef struct _aipart {
    union {
        struct {
            uint16_t ibit : 4;
            uint16_t iItem : 5;
            uint16_t cItem : 4;
            uint16_t fRandom : 3;
        };
    };  /* +0x0000 */
} AIPART;

/* typind 4427 (0x114b) size=12 */
typedef struct tagTIMERINFO {
    uint32_t dwSize;  /* +0x0000 */
    uint32_t dwmsSinceStart;  /* +0x0004 */
    uint32_t dwmsThisVM;  /* +0x0008 */
} TIMERINFO;

/* typind 4431 (0x114f) size=16 */
typedef struct _hb {
    uint16_t cbFree;  /* +0x0000 */
    uint16_t cbBlock;  /* +0x0002 */
    uint16_t cbSlop;  /* +0x0004 */
    uint16_t ibTop;  /* +0x0006 */
    HB * lphbNext;  /* +0x0008 */
    uint16_t hmem;  /* +0x000c */
    uint8_t ht;  /* +0x000e */
    uint8_t unused1;  /* +0x000f */
} HB;

/* typind 4440 (0x1158) size=2 */
typedef struct _dv {
    union {
        uint16_t dp;
        struct {
            uint16_t pctSh : 7;
            uint16_t pctDp : 9;
        };
    };  /* +0x0000 */
} DV;

/* typind 4462 (0x116e) size=44 */
typedef struct _find_t {
    char reserved[21];  /* +0x0000 */
    char attrib;  /* +0x0015 */
    uint16_t wr_time;  /* +0x0016 */
    uint16_t wr_date;  /* +0x0018 */
    int32_t size;  /* +0x001a */
    char name[13];  /* +0x001e */
} FIND_T;

/* typind 4464 (0x1170) size=8 */
typedef struct _diskfree_t {
    uint16_t total_clusters;  /* +0x0000 */
    uint16_t avail_clusters;  /* +0x0002 */
    uint16_t sectors_per_cluster;  /* +0x0004 */
    uint16_t bytes_per_sector;  /* +0x0006 */
} DISKFREE_T;

/* typind 4477 (0x117d) size=136 */
typedef struct tagOFSTRUCT {
    uint8_t cBytes;  /* +0x0000 */
    uint8_t fFixedDisk;  /* +0x0001 */
    uint16_t nErrCode;  /* +0x0002 */
    uint8_t reserved[4];  /* +0x0004 */
    char szPathName[128];  /* +0x0008 */
} OFSTRUCT;

/* typind 4503 (0x1197) size=50 */
typedef struct tagLOGFONT {
    int16_t lfHeight;  /* +0x0000 */
    int16_t lfWidth;  /* +0x0002 */
    int16_t lfEscapement;  /* +0x0004 */
    int16_t lfOrientation;  /* +0x0006 */
    int16_t lfWeight;  /* +0x0008 */
    uint8_t lfItalic;  /* +0x000a */
    uint8_t lfUnderline;  /* +0x000b */
    uint8_t lfStrikeOut;  /* +0x000c */
    uint8_t lfCharSet;  /* +0x000d */
    uint8_t lfOutPrecision;  /* +0x000e */
    uint8_t lfClipPrecision;  /* +0x000f */
    uint8_t lfQuality;  /* +0x0010 */
    uint8_t lfPitchAndFamily;  /* +0x0011 */
    char lfFaceName[32];  /* +0x0012 */
} LOGFONT;

/* typind 4537 (0x11b9) size=12 */
typedef struct tagBITMAPCOREHEADER {
    uint32_t bcSize;  /* +0x0000 */
    int16_t bcWidth;  /* +0x0004 */
    int16_t bcHeight;  /* +0x0006 */
    uint16_t bcPlanes;  /* +0x0008 */
    uint16_t bcBitCount;  /* +0x000a */
} BITMAPCOREHEADER;

/* typind 4539 (0x11bb) size=40 */
typedef struct tagBITMAPINFOHEADER {
    uint32_t biSize;  /* +0x0000 */
    int32_t biWidth;  /* +0x0004 */
    int32_t biHeight;  /* +0x0008 */
    uint16_t biPlanes;  /* +0x000c */
    uint16_t biBitCount;  /* +0x000e */
    uint32_t biCompression;  /* +0x0010 */
    uint32_t biSizeImage;  /* +0x0014 */
    int32_t biXPelsPerMeter;  /* +0x0018 */
    int32_t biYPelsPerMeter;  /* +0x001c */
    uint32_t biClrUsed;  /* +0x0020 */
    uint32_t biClrImportant;  /* +0x0024 */
} BITMAPINFOHEADER;

/* typind 4549 (0x11c5) size=14 */
typedef struct tagBITMAP {
    int16_t bmType;  /* +0x0000 */
    int16_t bmWidth;  /* +0x0002 */
    int16_t bmHeight;  /* +0x0004 */
    int16_t bmWidthBytes;  /* +0x0006 */
    uint8_t bmPlanes;  /* +0x0008 */
    uint8_t bmBitsPixel;  /* +0x0009 */
    void * bmBits;  /* +0x000a */
} BITMAP;

/* typind 4571 (0x11db) size=31 */
typedef struct tagTEXTMETRIC {
    int16_t tmHeight;  /* +0x0000 */
    int16_t tmAscent;  /* +0x0002 */
    int16_t tmDescent;  /* +0x0004 */
    int16_t tmInternalLeading;  /* +0x0006 */
    int16_t tmExternalLeading;  /* +0x0008 */
    int16_t tmAveCharWidth;  /* +0x000a */
    int16_t tmMaxCharWidth;  /* +0x000c */
    int16_t tmWeight;  /* +0x000e */
    uint8_t tmItalic;  /* +0x0010 */
    uint8_t tmUnderlined;  /* +0x0011 */
    uint8_t tmStruckOut;  /* +0x0012 */
    uint8_t tmFirstChar;  /* +0x0013 */
    uint8_t tmLastChar;  /* +0x0014 */
    uint8_t tmDefaultChar;  /* +0x0015 */
    uint8_t tmBreakChar;  /* +0x0016 */
    uint8_t tmPitchAndFamily;  /* +0x0017 */
    uint8_t tmCharSet;  /* +0x0018 */
    int16_t tmOverhang;  /* +0x0019 */
    int16_t tmDigitizedAspectX;  /* +0x001b */
    int16_t tmDigitizedAspectY;  /* +0x001d */
} TEXTMETRIC;

/* typind 4614 (0x1206) size=72 */
typedef struct tagOFN {
    uint32_t lStructSize;  /* +0x0000 */
    uint16_t hwndOwner;  /* +0x0004 */
    uint16_t hInstance;  /* +0x0006 */
    char * lpstrFilter;  /* +0x0008 */
    char * lpstrCustomFilter;  /* +0x000c */
    uint32_t nMaxCustFilter;  /* +0x0010 */
    uint32_t nFilterIndex;  /* +0x0014 */
    char * lpstrFile;  /* +0x0018 */
    uint32_t nMaxFile;  /* +0x001c */
    char * lpstrFileTitle;  /* +0x0020 */
    uint32_t nMaxFileTitle;  /* +0x0024 */
    char * lpstrInitialDir;  /* +0x0028 */
    char * lpstrTitle;  /* +0x002c */
    uint32_t Flags;  /* +0x0030 */
    uint16_t nFileOffset;  /* +0x0034 */
    uint16_t nFileExtension;  /* +0x0036 */
    char * lpstrDefExt;  /* +0x0038 */
    int32_t lCustData;  /* +0x003c */
    uint16_t (* lpfnHook)(uint16_t, uint16_t, uint16_t, int32_t);  /* +0x0040 */
    char * lpTemplateName;  /* +0x0044 */
} OFN;

/* typind 4636 (0x121c) size=78 */
typedef struct _engine {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t grfAbilities;  /* +0x0034 */
    int16_t rgcFuelUsed[12];  /* +0x0036 */
} ENGINE;

/* typind 4700 (0x125c) size=4 */
typedef struct _pl {
    union {
        struct {
            uint16_t cbItem : 8;
            uint16_t fMark : 1;
            uint16_t ht : 3;
            uint16_t cAlloc : 4;
        };
    };  /* +0x0000 */
    uint8_t iMax;  /* +0x0002 */
    uint8_t iMac;  /* +0x0003 */
    uint8_t rgb[0];  /* +0x0004 */
} PL;

/* typind 4729 (0x1279) size=14 */
typedef struct tagMEASUREITEMSTRUCT {
    uint16_t CtlType;  /* +0x0000 */
    uint16_t CtlID;  /* +0x0002 */
    uint16_t itemID;  /* +0x0004 */
    uint16_t itemWidth;  /* +0x0006 */
    uint16_t itemHeight;  /* +0x0008 */
    uint32_t itemData;  /* +0x000a */
} MEASUREITEMSTRUCT;

/* typind 4749 (0x128d) size=56 */
typedef struct _scanner {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t dRange;  /* +0x0034 */
    int16_t grfAbilities;  /* +0x0036 */
} SCANNER;

/* typind 4753 (0x1291) size=54 */
typedef struct _planetary {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t grAbility;  /* +0x0034 */
} PLANETARY;

/* typind 4761 (0x1299) size=54 */
typedef struct _armor {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t dp;  /* +0x0034 */
} ARMOR;

/* typind 4764 (0x129c) size=54 */
typedef struct _shield {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t dp;  /* +0x0034 */
} SHIELD;

/* typind 4766 (0x129e) size=54 */
typedef struct _special {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t grAbility;  /* +0x0034 */
} SPECIAL;

/* typind 4769 (0x12a1) size=54 */
typedef struct _mines {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t grAbility;  /* +0x0034 */
} MINES;

/* typind 4771 (0x12a3) size=54 */
typedef struct _mining {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t grAbility;  /* +0x0034 */
} MINING;

/* typind 4774 (0x12a6) size=54 */
typedef struct _terra {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t grAbility;  /* +0x0034 */
} TERRA;

/* typind 4776 (0x12a8) size=58 */
typedef struct _bomb {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t cRounds;  /* +0x0034 */
    int16_t dDmgCol;  /* +0x0036 */
    int16_t dDmgBldg;  /* +0x0038 */
} BOMB;

/* typind 4778 (0x12aa) size=60 */
typedef struct _torp {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t dRangeMax;  /* +0x0034 */
    int16_t dp;  /* +0x0036 */
    int16_t init;  /* +0x0038 */
    int16_t dHitChance;  /* +0x003a */
} TORP;

/* typind 4780 (0x12ac) size=60 */
typedef struct _beam {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t dRangeMax;  /* +0x0034 */
    int16_t dp;  /* +0x0036 */
    int16_t init;  /* +0x0038 */
    int16_t grfAbilities;  /* +0x003a */
} BEAM;

/* typind 4786 (0x12b2) size=56 */
typedef struct _specialsb {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    int16_t grAbility;  /* +0x0034 */
    int16_t grAbility2;  /* +0x0036 */
} SPECIALSB;

/* typind 4820 (0x12d4) size=12 */
typedef struct _msgplr {
    MSGPLR * lpmsgplrNext;  /* +0x0000 */
    int16_t iPlrFrom;  /* +0x0004 */
    int16_t iPlrTo;  /* +0x0006 */
    int16_t iInRe;  /* +0x0008 */
    int16_t cLen;  /* +0x000a */
    uint8_t rgbMsg[0];  /* +0x000c */
} MSGPLR;

/* typind 4822 (0x12d6) size=18 */
typedef struct _msgbig {
    int16_t iMsg;  /* +0x0000 */
    int16_t wGoto;  /* +0x0002 */
    int16_t rgParam[7];  /* +0x0004 */
} MSGBIG;

/* typind 4832 (0x12e0) size=4 */
typedef struct _msghdr {
    union {
        struct {
            uint16_t iMsg : 9;
            uint16_t grWord : 7;
        };
    };  /* +0x0000 */
    int16_t wGoto;  /* +0x0002 */
} MSGHDR;

/* typind 4844 (0x12ec) size=2 */
typedef struct _hdr {
    union {
        struct {
            uint16_t cb : 10;
            uint16_t rt : 6;
        };
    };  /* +0x0000 */
} HDR;

/* typind 4854 (0x12f6) size=4 */
typedef struct _starpack {
    union {
        struct {
            uint32_t dx : 10;
            uint32_t y : 12;
            uint32_t id : 10;
        };
    };  /* +0x0000 */
} STARPACK;

/* typind 4899 (0x1323) size=16 */
typedef struct _rtbof {
    char rgid[4];  /* +0x0000 */
    int32_t lidGame;  /* +0x0004 */
    union {
        uint16_t wVersion;
        struct {
            uint16_t verInc : 5;
            uint16_t verMinor : 7;
            uint16_t verMajor : 4;
        };
    };  /* +0x0008 */
    uint16_t turn;  /* +0x000a */
    union {
        struct {
            int16_t iPlayer : 5;
            int16_t lSaltTime : 11;
        };
    };  /* +0x000c */
    union {
        struct {
            uint16_t dt : 8;
            uint16_t fDone : 1;
            uint16_t fInUse : 1;
            uint16_t fMulti : 1;
            uint16_t fGameOverMan : 1;
            uint16_t fCrippled : 1;
            uint16_t wGen : 3;
        };
    };  /* +0x000e */
} RTBOF;

/* typind 4912 (0x1330) size=25 */
typedef struct _xferfull {
    uint16_t id1;  /* +0x0000 */
    uint16_t id2;  /* +0x0002 */
    union {
        struct {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
    };  /* +0x0004 */
    int32_t rgcQuan[5];  /* +0x0005 */
} XFERFULL;

/* typind 4914 (0x1332) size=12 */
typedef struct _coldrop {
    int16_t idFleetSrc;  /* +0x0000 */
    int16_t idPlr;  /* +0x0002 */
    int16_t idPlanetDst;  /* +0x0004 */
    union {
        struct {
            uint16_t fCanColonize : 1;
            uint16_t unused : 15;
        };
    };  /* +0x0006 */
    int32_t cColonist;  /* +0x0008 */
} COLDROP;

/* typind 4918 (0x1336) size=20 */
typedef struct _score {
    int32_t lScore;  /* +0x0000 */
    int32_t cResources;  /* +0x0004 */
    int16_t cPlanet;  /* +0x0008 */
    int16_t cStarbase;  /* +0x000a */
    uint16_t rgcsh[3];  /* +0x000c */
    int16_t cTechLevels;  /* +0x0012 */
} SCORE;

/* typind 4927 (0x133f) size=16 */
typedef struct _turnserial {
    int32_t lSerialNumber;  /* +0x0000 */
    uint8_t rgbConfig[11];  /* +0x0004 */
    uint8_t bPad;  /* +0x000f */
} TURNSERIAL;

/* typind 4930 (0x1342) size=4 */
typedef struct _rthisthdr {
    int16_t cPlanet;  /* +0x0000 */
    int16_t cPlanetExtra;  /* +0x0002 */
} RTHISTHDR;

/* typind 4937 (0x1349) size=2 */
typedef struct _prodq1 {
    union {
        uint16_t w;
        struct {
            uint16_t mdIdle : 6;
            uint16_t cQuan : 10;
        };
    };  /* +0x0000 */
} PRODQ1;

/* typind 4939 (0x134b) size=10 */
typedef struct tagEVENTMSG {
    uint16_t message;  /* +0x0000 */
    uint16_t paramL;  /* +0x0002 */
    uint16_t paramH;  /* +0x0004 */
    uint32_t time;  /* +0x0006 */
} EVENTMSG;

/* typind 4942 (0x134e) size=4 */
typedef struct _rtlogthing {
    uint16_t idFull;  /* +0x0000 */
    int16_t fDetonate;  /* +0x0002 */
} RTLOGTHING;

/* typind 4948 (0x1354) size=36 */
typedef struct tagFINDREPLACE {
    uint32_t lStructSize;  /* +0x0000 */
    uint16_t hwndOwner;  /* +0x0004 */
    uint16_t hInstance;  /* +0x0006 */
    uint32_t Flags;  /* +0x0008 */
    char * lpstrFindWhat;  /* +0x000c */
    char * lpstrReplaceWith;  /* +0x0010 */
    uint16_t wFindWhatLen;  /* +0x0014 */
    uint16_t wReplaceWithLen;  /* +0x0016 */
    int32_t lCustData;  /* +0x0018 */
    uint16_t (* lpfnHook)(uint16_t, uint16_t, uint16_t, int32_t);  /* +0x001c */
    char * lpTemplateName;  /* +0x0020 */
} FINDREPLACE;

/* typind 4955 (0x135b) size=6 */
typedef struct _rtChgPlanetLong {
    int16_t id;  /* +0x0000 */
    union {
        uint32_t ul;
        struct {
            uint32_t fNoResearch : 1;
            uint32_t idFling : 10;
            uint32_t iWarpFling : 4;
            uint32_t idRoute : 10;
            uint32_t unused : 7;
        };
    };  /* +0x0002 */
} RTCHGPLANETLONG;

/* typind 4966 (0x1366) size=23 */
typedef struct _planetsome {
    int16_t id;  /* +0x0000 */
    int16_t iPlayer;  /* +0x0002 */
    union {
        struct {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fStarbase : 1;
            uint16_t unusedA : 1;
            uint16_t fFirstYear : 1;
            uint16_t unusedB : 4;
        };
    };  /* +0x0004 */
    uint16_t rgpctMinLevel[3];  /* +0x0006 */
    char rgMinConc[3];  /* +0x000c */
    char rgEnvVar[3];  /* +0x000f */
    char rgEnvVarOrig[3];  /* +0x0012 */
    union {
        uint16_t uGuesses;
        struct {
            uint16_t uPopGuess : 12;
            uint16_t uDefGuess : 4;
        };
    };  /* +0x0015 */
} PLANETSOME;

/* typind 4968 (0x1368) size=3 */
typedef struct tagRGBTRIPLE {
    uint8_t rgbtBlue;  /* +0x0000 */
    uint8_t rgbtGreen;  /* +0x0001 */
    uint8_t rgbtRed;  /* +0x0002 */
} RGBTRIPLE;

/* typind 4975 (0x136f) size=34 */
typedef struct _exceptionl {
    int16_t type;  /* +0x0000 */
    char * name;  /* +0x0002 */
    long double arg1;  /* +0x0004 */
    long double arg2;  /* +0x000e */
    long double retval;  /* +0x0018 */
} EXCEPTIONL;

/* typind 4993 (0x1381) size=4 */
typedef struct _tasklaymines {
    uint16_t cTime;  /* +0x0000 */
    uint16_t cTimeOld;  /* +0x0002 */
} TASKLAYMINES;

/* typind 4995 (0x1383) size=4 */
typedef struct _taskpatrol {
    uint16_t iWarp;  /* +0x0000 */
    uint16_t iDist;  /* +0x0002 */
} TASKPATROL;

/* typind 4997 (0x1385) size=2 */
typedef struct _tasksell {
    uint16_t iPlrX;  /* +0x0000 */
} TASKSELL;

/* typind 5018 (0x139a) size=20 */
typedef struct _complexl {
    long double x;  /* +0x0000 */
    long double y;  /* +0x000a */
} COMPLEXL;

/* typind 5021 (0x139d) size=14 */
typedef struct tagBITMAPFILEHEADER {
    uint16_t bfType;  /* +0x0000 */
    uint32_t bfSize;  /* +0x0002 */
    uint16_t bfReserved1;  /* +0x0006 */
    uint16_t bfReserved2;  /* +0x0008 */
    uint32_t bfOffBits;  /* +0x000a */
} BITMAPFILEHEADER;

/* typind 5028 (0x13a4) size=4 */
typedef struct tagCLIENTCREATESTRUCT {
    uint16_t hWindowMenu;  /* +0x0000 */
    uint16_t idFirstChild;  /* +0x0002 */
} CLIENTCREATESTRUCT;

/* typind 5031 (0x13a7) size=26 */
typedef struct tagWNDCLASS {
    uint16_t style;  /* +0x0000 */
    int32_t (* lpfnWndProc)(uint16_t, uint16_t, uint16_t, int32_t);  /* +0x0002 */
    int16_t cbClsExtra;  /* +0x0006 */
    int16_t cbWndExtra;  /* +0x0008 */
    uint16_t hInstance;  /* +0x000a */
    uint16_t hIcon;  /* +0x000c */
    uint16_t hCursor;  /* +0x000e */
    uint16_t hbrBackground;  /* +0x0010 */
    char *lpszMenuName;  /* +0x0012 */
    char *lpszClassName;  /* +0x0016 */
} WNDCLASS;

/* typind 5036 (0x13ac) size=8 */
typedef struct tagMETAFILEPICT {
    int16_t mm;  /* +0x0000 */
    int16_t xExt;  /* +0x0002 */
    int16_t yExt;  /* +0x0004 */
    uint16_t hMF;  /* +0x0006 */
} METAFILEPICT;

/* typind 5038 (0x13ae) size=14 */
typedef struct tagDEBUGHOOKINFO {
    uint16_t hModuleHook;  /* +0x0000 */
    int32_t reserved;  /* +0x0002 */
    int32_t lParam;  /* +0x0006 */
    uint16_t wParam;  /* +0x000a */
    int16_t code;  /* +0x000c */
} DEBUGHOOKINFO;

/* typind 5042 (0x13b2) size=2 */
typedef struct _obj {
    union {
        FLEET * pfl;
        PLANET * ppl;
        THING * pth;
    };  /* +0x0000 */
} OBJ;

/* typind 5046 (0x13b6) size=16 */
typedef struct _tile {
    int16_t yTop;  /* +0x0000 */
    int16_t dyFull;  /* +0x0002 */
    int16_t grbit;  /* +0x0004 */
    void (* pfn)(uint16_t, TILE *, OBJ);  /* +0x0006 */
    union {
        struct {
            uint16_t iCol : 3;
            uint16_t id : 4;
            uint16_t fPopped : 1;
            uint16_t fNullPtr : 1;
            uint16_t fMinTitle : 1;
            uint16_t fErase : 1;
            uint16_t fFixCtls : 1;
            uint16_t fMinDraw : 1;
        };
    };  /* +0x000a */
    uint16_t fUnused : 4;  /* +0x000c */
    uint16_t idh;  /* +0x000e */
} TILE;

/* typind 5087 (0x13df) size=14 */
typedef struct HELPWININFO {
    int16_t wStructSize;  /* +0x0000 */
    int16_t x;  /* +0x0002 */
    int16_t y;  /* +0x0004 */
    int16_t dx;  /* +0x0006 */
    int16_t dy;  /* +0x0008 */
    int16_t wMax;  /* +0x000a */
    char rgchMember[2];  /* +0x000c */
} HELPWININFO;

/* typind 5090 (0x13e2) size=5 */
typedef struct MENUITEMTEMPLATE {
    uint16_t mtOption;  /* +0x0000 */
    uint16_t mtID;  /* +0x0002 */
    char mtString[1];  /* +0x0004 */
} MENUITEMTEMPLATE;

/* typind 5092 (0x13e4) size=4 */
typedef struct MENUITEMTEMPLATEHEADER {
    uint16_t versionNumber;  /* +0x0000 */
    uint16_t offset;  /* +0x0002 */
} MENUITEMTEMPLATEHEADER;

/* typind 5094 (0x13e6) size=10 */
typedef struct DOCINFO {
    int16_t cbSize;  /* +0x0000 */
    char *lpszDocName;  /* +0x0002 */
    char *lpszOutput;  /* +0x0006 */
} DOCINFO;

/* typind 5096 (0x13e8) size=8 */
typedef struct tagDEVNAMES {
    uint16_t wDriverOffset;  /* +0x0000 */
    uint16_t wDeviceOffset;  /* +0x0002 */
    uint16_t wOutputOffset;  /* +0x0004 */
    uint16_t wDefault;  /* +0x0006 */
} DEVNAMES;

/* typind 5098 (0x13ea) size=12 */
typedef struct tagDRVCONFIGINFO {
    uint32_t dwDCISize;  /* +0x0000 */
    char *lpszDCISectionName;  /* +0x0004 */
    char *lpszDCIAliasName;  /* +0x0008 */
} DRVCONFIGINFO;

/* typind 5100 (0x13ec) size=24 */
typedef struct _logxfer {
    int16_t id;  /* +0x0000 */
    int16_t grobj;  /* +0x0002 */
    int32_t rgdItem[5];  /* +0x0004 */
} LOGXFER;

/* typind 5115 (0x13fb) size=36 */
typedef struct _logxferf {
    int16_t id;  /* +0x0000 */
    int16_t grobj;  /* +0x0002 */
    int16_t rgdItem[16];  /* +0x0004 */
} LOGXFERF;

/* typind 5120 (0x1400) size=18 */
typedef struct tagMETAHEADER {
    uint16_t mtType;  /* +0x0000 */
    uint16_t mtHeaderSize;  /* +0x0002 */
    uint16_t mtVersion;  /* +0x0004 */
    uint32_t mtSize;  /* +0x0006 */
    uint16_t mtNoObjects;  /* +0x000a */
    uint32_t mtMaxRecord;  /* +0x000c */
    uint16_t mtNoParameters;  /* +0x0010 */
} METAHEADER;

/* typind 5122 (0x1402) size=26 */
typedef struct tagWINDEBUGINFO {
    uint16_t flags;  /* +0x0000 */
    uint32_t dwOptions;  /* +0x0002 */
    uint32_t dwFilter;  /* +0x0006 */
    char achAllocModule[8];  /* +0x000a */
    uint32_t dwAllocBreak;  /* +0x0012 */
    uint32_t dwAllocCount;  /* +0x0016 */
} WINDEBUGINFO;

/* typind 5132 (0x140c) size=7 */
typedef struct _rtxfer {
    uint16_t id1;  /* +0x0000 */
    uint16_t id2;  /* +0x0002 */
    union {
        struct {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
    };  /* +0x0004 */
    uint8_t grbitItems;  /* +0x0005 */
    char rgcQuan[1];  /* +0x0006 */
} RTXFER;

/* typind 5134 (0x140e) size=4 */
typedef struct tagFIXED {
    uint16_t fract;  /* +0x0000 */
    int16_t value;  /* +0x0002 */
} FIXED;

/* typind 5141 (0x1415) size=52 */
typedef struct _compart {
    int16_t id;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szName[32];  /* +0x0008 */
    int16_t cMass;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
} COMPART;

/* typind 5149 (0x141d) size=25 */
typedef struct tagDCB {
    uint8_t Id;  /* +0x0000 */
    uint16_t BaudRate;  /* +0x0001 */
    uint8_t ByteSize;  /* +0x0003 */
    uint8_t Parity;  /* +0x0004 */
    uint8_t StopBits;  /* +0x0005 */
    uint16_t RlsTimeout;  /* +0x0006 */
    uint16_t CtsTimeout;  /* +0x0008 */
    uint16_t DsrTimeout;  /* +0x000a */
    union {
        struct {
            uint16_t fBinary : 1;
            uint16_t fRtsDisable : 1;
            uint16_t fParity : 1;
            uint16_t fOutxCtsFlow : 1;
            uint16_t fOutxDsrFlow : 1;
            uint16_t fDummy : 2;
            uint16_t fDtrDisable : 1;
            uint16_t fOutX : 1;
            uint16_t fInX : 1;
            uint16_t fPeChar : 1;
            uint16_t fNull : 1;
            uint16_t fChEvt : 1;
            uint16_t fDtrflow : 1;
            uint16_t fRtsflow : 1;
            uint16_t fDummy2 : 1;
        };
    };  /* +0x000c */
    char XonChar;  /* +0x000e */
    char XoffChar;  /* +0x000f */
    uint16_t XonLim;  /* +0x0010 */
    uint16_t XoffLim;  /* +0x0012 */
    char PeChar;  /* +0x0014 */
    char EofChar;  /* +0x0015 */
    char EvtChar;  /* +0x0016 */
    uint16_t TxDelay;  /* +0x0017 */
} DCB;

/* typind 5153 (0x1421) size=8 */
typedef struct _rtxferx {
    uint16_t id1;  /* +0x0000 */
    uint16_t id2;  /* +0x0002 */
    union {
        struct {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
    };  /* +0x0004 */
    uint8_t grbitItems;  /* +0x0005 */
    int16_t rgcQuan[1];  /* +0x0006 */
} RTXFERX;

/* typind 5161 (0x1429) size=10 */
typedef struct _thmine {
    int32_t cMines;  /* +0x0000 */
    uint16_t grbitPlr;  /* +0x0004 */
    uint8_t iType;  /* +0x0006 */
    uint8_t fDetonate;  /* +0x0007 */
    uint16_t grbitPlrNow;  /* +0x0008 */
} THMINE;

/* typind 5163 (0x142b) size=5 */
typedef struct tagCOMSTAT {
    uint8_t status;  /* +0x0000 */
    uint16_t cbInQue;  /* +0x0001 */
    uint16_t cbOutQue;  /* +0x0003 */
} COMSTAT;

/* typind 5169 (0x1431) size=10 */
typedef struct _rtxferl {
    uint16_t id1;  /* +0x0000 */
    uint16_t id2;  /* +0x0002 */
    union {
        struct {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
    };  /* +0x0004 */
    uint8_t grbitItems;  /* +0x0005 */
    int32_t rgcQuan[1];  /* +0x0006 */
} RTXFERL;

/* typind 5174 (0x1436) size=9 */
typedef struct _rtxferf {
    uint16_t id1;  /* +0x0000 */
    uint16_t id2;  /* +0x0002 */
    union {
        struct {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
    };  /* +0x0004 */
    uint16_t grbitItems;  /* +0x0005 */
    int16_t rgcQuan[1];  /* +0x0007 */
} RTXFERF;

/* typind 5180 (0x143c) size=4 */
typedef struct tagRGBQUAD {
    uint8_t rgbBlue;  /* +0x0000 */
    uint8_t rgbGreen;  /* +0x0001 */
    uint8_t rgbRed;  /* +0x0002 */
    uint8_t rgbReserved;  /* +0x0003 */
} RGBQUAD;

/* typind 5185 (0x1441) size=10 */
typedef struct _thpack {
    union {
        struct {
            uint16_t idPlanet : 10;
            uint16_t iWarp : 4;
            uint16_t fMoved : 1;
            uint16_t fInclude : 1;
        };
    };  /* +0x0000 */
    int16_t rgwtMin[3];  /* +0x0002 */
    union {
        struct {
            uint16_t wtMax : 14;
            uint16_t iDecayRate : 2;
        };
    };  /* +0x0008 */
} THPACK;

/* typind 5187 (0x1443) size=4 */
typedef struct _rtshipint {
    int16_t id;  /* +0x0000 */
    int16_t i;  /* +0x0002 */
} RTSHIPINT;

/* typind 5190 (0x1446) size=20 */
typedef struct _aistarbase {
    int16_t idPlanet;  /* +0x0000 */
    int16_t cFreighter;  /* +0x0002 */
    int16_t rgflid[8];  /* +0x0004 */
} AISTARBASE;

/* typind 5192 (0x1448) size=28 */
typedef struct _exception {
    int16_t type;  /* +0x0000 */
    char * name;  /* +0x0002 */
    double arg1;  /* +0x0004 */
    double arg2;  /* +0x000c */
    double retval;  /* +0x0014 */
} EXCEPTION;

/* typind 5195 (0x144b) size=2 */
typedef struct tagHANDLETABLE {
    uint16_t objectHandle[1];  /* +0x0000 */
} HANDLETABLE;

/* typind 5201 (0x1451) size=6 */
typedef struct _rtshipint2 {
    int16_t id;  /* +0x0000 */
    int16_t i;  /* +0x0002 */
    int16_t i2;  /* +0x0004 */
} RTSHIPINT2;

/* typind 5204 (0x1454) size=14 */
typedef struct tagWINDOWPOS {
    uint16_t hwnd;  /* +0x0000 */
    uint16_t hwndInsertAfter;  /* +0x0002 */
    int16_t x;  /* +0x0004 */
    int16_t y;  /* +0x0006 */
    int16_t cx;  /* +0x0008 */
    int16_t cy;  /* +0x000a */
    uint16_t flags;  /* +0x000c */
} WINDOWPOS;

/* typind 5207 (0x1457) size=34 */
typedef struct tagCREATESTRUCT {
    void * lpCreateParams;  /* +0x0000 */
    uint16_t hInstance;  /* +0x0004 */
    uint16_t hMenu;  /* +0x0006 */
    uint16_t hwndParent;  /* +0x0008 */
    int16_t cy;  /* +0x000a */
    int16_t cx;  /* +0x000c */
    int16_t y;  /* +0x000e */
    int16_t x;  /* +0x0010 */
    int32_t style;  /* +0x0012 */
    char *lpszName;  /* +0x0016 */
    char *lpszClass;  /* +0x001a */
    uint32_t dwExStyle;  /* +0x001e */
} CREATESTRUCT;

/* typind 5209 (0x1459) size=52 */
typedef struct tagPD {
    uint32_t lStructSize;  /* +0x0000 */
    uint16_t hwndOwner;  /* +0x0004 */
    uint16_t hDevMode;  /* +0x0006 */
    uint16_t hDevNames;  /* +0x0008 */
    uint16_t hDC;  /* +0x000a */
    uint32_t Flags;  /* +0x000c */
    uint16_t nFromPage;  /* +0x0010 */
    uint16_t nToPage;  /* +0x0012 */
    uint16_t nMinPage;  /* +0x0014 */
    uint16_t nMaxPage;  /* +0x0016 */
    uint16_t nCopies;  /* +0x0018 */
    uint16_t hInstance;  /* +0x001a */
    int32_t lCustData;  /* +0x001c */
    uint16_t (* lpfnPrintHook)(uint16_t, uint16_t, uint16_t, int32_t);  /* +0x0020 */
    uint16_t (* lpfnSetupHook)(uint16_t, uint16_t, uint16_t, int32_t);  /* +0x0024 */
    char * lpPrintTemplateName;  /* +0x0028 */
    char * lpSetupTemplateName;  /* +0x002c */
    uint16_t hPrintTemplate;  /* +0x0030 */
    uint16_t hSetupTemplate;  /* +0x0032 */
} PD;

/* typind 5213 (0x145d) size=8 */
typedef struct _thworm {
    union {
        struct {
            uint16_t iStable : 2;
            uint16_t cLastMove : 10;
            uint16_t fDestKnown : 1;
            uint16_t fInclude : 1;
        };
    };  /* +0x0000 */
    uint16_t grbitPlr;  /* +0x0002 */
    uint16_t grbitPlrTrav;  /* +0x0004 */
    uint16_t idPartner;  /* +0x0006 */
} THWORM;

/* typind 5224 (0x1468) size=46 */
typedef struct tagCHOOSEFONT {
    uint32_t lStructSize;  /* +0x0000 */
    uint16_t hwndOwner;  /* +0x0004 */
    uint16_t hDC;  /* +0x0006 */
    LOGFONT * lpLogFont;  /* +0x0008 */
    int16_t iPointSize;  /* +0x000c */
    uint32_t Flags;  /* +0x000e */
    uint32_t rgbColors;  /* +0x0012 */
    int32_t lCustData;  /* +0x0016 */
    uint16_t (* lpfnHook)(uint16_t, uint16_t, uint16_t, int32_t);  /* +0x001a */
    char * lpTemplateName;  /* +0x001e */
    uint16_t hInstance;  /* +0x0022 */
    char *lpszStyle;  /* +0x0024 */
    uint16_t nFontType;  /* +0x0028 */
    int16_t nSizeMin;  /* +0x002a */
    int16_t nSizeMax;  /* +0x002c */
} CHOOSEFONT;

/* typind 5241 (0x1479) size=8 */
typedef struct tagMETARECORD {
    uint32_t rdSize;  /* +0x0000 */
    uint16_t rdFunction;  /* +0x0004 */
    uint16_t rdParm[1];  /* +0x0006 */
} METARECORD;

/* typind 5243 (0x147b) size=26 */
typedef struct tagMDICREATESTRUCT {
    char *szClass;  /* +0x0000 */
    char *szTitle;  /* +0x0004 */
    uint16_t hOwner;  /* +0x0008 */
    int16_t x;  /* +0x000a */
    int16_t y;  /* +0x000c */
    int16_t cx;  /* +0x000e */
    int16_t cy;  /* +0x0010 */
    uint32_t style;  /* +0x0012 */
    int32_t lParam;  /* +0x0016 */
} MDICREATESTRUCT;

/* typind 5250 (0x1482) size=10 */
typedef struct _timer {
    int16_t mdForce;  /* +0x0000 */
    int16_t fAutoGenWhenIn;  /* +0x0002 */
    union {
        int16_t hrsForce;
        struct {
            uint16_t minForce : 12;
            uint16_t cPlr : 4;
        };
    };  /* +0x0004 */
    int32_t tickcount;  /* +0x0006 */
} TIMER;

/* typind 5252 (0x1484) size=16 */
typedef struct _complex {
    double x;  /* +0x0000 */
    double y;  /* +0x0008 */
} COMPLEX;

/* typind 5254 (0x1486) size=37 */
typedef struct _rtchgname {
    int16_t id;  /* +0x0000 */
    int16_t grobj;  /* +0x0002 */
    uint8_t rgb[33];  /* +0x0004 */
} RTCHGNAME;

/* typind 5257 (0x1489) size=16 */
typedef struct complex {
    double x;  /* +0x0000 */
    double y;  /* +0x0008 */
} complex;

/* typind 5259 (0x148b) size=4 */
typedef struct _lsb {
    union {
        struct {
            uint16_t isb : 4;
            uint16_t pctDp : 12;
        };
    };  /* +0x0000 */
    union {
        struct {
            uint16_t idFling : 10;
            uint16_t iWarpFling : 4;
            uint16_t unused3 : 2;
        };
    };  /* +0x0002 */
} LSB;

/* typind 5263 (0x148f) size=10 */
typedef struct tagPANOSE {
    uint8_t bFamilyType;  /* +0x0000 */
    uint8_t bSerifStyle;  /* +0x0001 */
    uint8_t bWeight;  /* +0x0002 */
    uint8_t bProportion;  /* +0x0003 */
    uint8_t bContrast;  /* +0x0004 */
    uint8_t bStrokeVariation;  /* +0x0005 */
    uint8_t bArmStyle;  /* +0x0006 */
    uint8_t bLetterform;  /* +0x0007 */
    uint8_t bMidline;  /* +0x0008 */
    uint8_t bXHeight;  /* +0x0009 */
} PANOSE;

/* typind 5274 (0x149a) size=6 */
typedef struct tagCBT_CREATEWND {
    CREATESTRUCT * lpcs;  /* +0x0000 */
    uint16_t hwndInsertAfter;  /* +0x0004 */
} CBT_CREATEWND;

/* typind 5298 (0x14b2) size=41 */
typedef struct tagNEWTEXTMETRIC {
    int16_t tmHeight;  /* +0x0000 */
    int16_t tmAscent;  /* +0x0002 */
    int16_t tmDescent;  /* +0x0004 */
    int16_t tmInternalLeading;  /* +0x0006 */
    int16_t tmExternalLeading;  /* +0x0008 */
    int16_t tmAveCharWidth;  /* +0x000a */
    int16_t tmMaxCharWidth;  /* +0x000c */
    int16_t tmWeight;  /* +0x000e */
    uint8_t tmItalic;  /* +0x0010 */
    uint8_t tmUnderlined;  /* +0x0011 */
    uint8_t tmStruckOut;  /* +0x0012 */
    uint8_t tmFirstChar;  /* +0x0013 */
    uint8_t tmLastChar;  /* +0x0014 */
    uint8_t tmDefaultChar;  /* +0x0015 */
    uint8_t tmBreakChar;  /* +0x0016 */
    uint8_t tmPitchAndFamily;  /* +0x0017 */
    uint8_t tmCharSet;  /* +0x0018 */
    int16_t tmOverhang;  /* +0x0019 */
    int16_t tmDigitizedAspectX;  /* +0x001b */
    int16_t tmDigitizedAspectY;  /* +0x001d */
    uint32_t ntmFlags;  /* +0x001f */
    uint16_t ntmSizeEM;  /* +0x0023 */
    uint16_t ntmCellHeight;  /* +0x0025 */
    uint16_t ntmAvgWidth;  /* +0x0027 */
} NEWTEXTMETRIC;

/* typind 5303 (0x14b7) size=4 */
typedef struct tagCBTACTIVATESTRUCT {
    int16_t fMouse;  /* +0x0000 */
    uint16_t hWndActive;  /* +0x0002 */
} CBTACTIVATESTRUCT;

/* typind 5322 (0x14ca) size=4 */
typedef struct tagPALETTEENTRY {
    uint8_t peRed;  /* +0x0000 */
    uint8_t peGreen;  /* +0x0001 */
    uint8_t peBlue;  /* +0x0002 */
    uint8_t peFlags;  /* +0x0003 */
} PALETTEENTRY;

/* typind 5339 (0x14db) size=12 */
typedef struct tagDELETEITEMSTRUCT {
    uint16_t CtlType;  /* +0x0000 */
    uint16_t CtlID;  /* +0x0002 */
    uint16_t itemID;  /* +0x0004 */
    uint16_t hwndItem;  /* +0x0006 */
    uint32_t itemData;  /* +0x0008 */
} DELETEITEMSTRUCT;

/* typind 5341 (0x14dd) size=10 */
typedef struct tagHARDWAREHOOKSTRUCT {
    uint16_t hWnd;  /* +0x0000 */
    uint16_t wMessage;  /* +0x0002 */
    uint16_t wParam;  /* +0x0004 */
    int32_t lParam;  /* +0x0006 */
} HARDWAREHOOKSTRUCT;

/* typind 5346 (0x14e2) size=4 */
typedef struct _rtplanet {
    union {
        struct {
            int16_t id : 11;
            int16_t iPlayer : 5;
        };
    };  /* +0x0000 */
    union {
        struct {
            uint16_t det : 7;
            uint16_t fHomeworld : 1;
            uint16_t fInclude : 1;
            uint16_t fStarbase : 1;
            uint16_t fIncEVO : 1;
            uint16_t fIncImp : 1;
            uint16_t fIsArtifact : 1;
            uint16_t fIncSurfMin : 1;
            uint16_t fRouting : 1;
            uint16_t fFirstYear : 1;
        };
    };  /* +0x0002 */
} RTPLANET;

/* typind 5349 (0x14e5) size=134 */
typedef struct tagDRIVERINFOSTRUCT {
    uint16_t length;  /* +0x0000 */
    uint16_t hDriver;  /* +0x0002 */
    uint16_t hModule;  /* +0x0004 */
    char szAliasName[128];  /* +0x0006 */
} DRIVERINFOSTRUCT;

/* typind 5354 (0x14ea) size=32 */
typedef struct tagCHOOSECOLOR {
    uint32_t lStructSize;  /* +0x0000 */
    uint16_t hwndOwner;  /* +0x0004 */
    uint16_t hInstance;  /* +0x0006 */
    uint32_t rgbResult;  /* +0x0008 */
    uint32_t * lpCustColors;  /* +0x000c */
    uint32_t Flags;  /* +0x0010 */
    int32_t lCustData;  /* +0x0014 */
    uint16_t (* lpfnHook)(uint16_t, uint16_t, uint16_t, int32_t);  /* +0x0018 */
    char * lpTemplateName;  /* +0x001c */
} CHOOSECOLOR;

/* typind 5360 (0x14f0) size=6 */
typedef struct tagABC {
    int16_t abcA;  /* +0x0000 */
    uint16_t abcB;  /* +0x0002 */
    int16_t abcC;  /* +0x0004 */
} ABC;

/* typind 5365 (0x14f5) size=8 */
typedef struct tagLOGBRUSH {
    uint16_t lbStyle;  /* +0x0000 */
    uint32_t lbColor;  /* +0x0002 */
    int16_t lbHatch;  /* +0x0006 */
} LOGBRUSH;

/* typind 5368 (0x14f8) size=4 */
typedef struct tagSIZE {
    int16_t cx;  /* +0x0000 */
    int16_t cy;  /* +0x0002 */
} SIZE;

/* typind 5372 (0x14fc) size=2 */
typedef struct _fleetid {
    union {
        struct {
            uint16_t ifl : 9;
            uint16_t iplr : 4;
            uint16_t junk : 3;
        };
    };  /* +0x0000 */
} FLEETID;

/* typind 5375 (0x14ff) size=4 */
typedef struct tagMULTIKEYHELP {
    uint16_t mkSize;  /* +0x0000 */
    uint8_t mkKeylist;  /* +0x0002 */
    char szKeyphrase[1];  /* +0x0003 */
} MULTIKEYHELP;

/* typind 5378 (0x1502) size=2 */
typedef struct _vers {
    union {
        struct {
            uint16_t verInc : 5;
            uint16_t verMinor : 7;
            uint16_t verMajor : 4;
        };
    };  /* +0x0000 */
} VERS;

/* typind 5391 (0x150f) size=18 */
typedef struct tagCOMPAREITEMSTRUCT {
    uint16_t CtlType;  /* +0x0000 */
    uint16_t CtlID;  /* +0x0002 */
    uint16_t hwndItem;  /* +0x0004 */
    uint16_t itemID1;  /* +0x0006 */
    uint32_t itemData1;  /* +0x0008 */
    uint16_t itemID2;  /* +0x000c */
    uint32_t itemData2;  /* +0x000e */
} COMPAREITEMSTRUCT;

/* typind 5395 (0x1513) size=16 */
typedef struct tagSEGINFO {
    uint16_t offSegment;  /* +0x0000 */
    uint16_t cbSegment;  /* +0x0002 */
    uint16_t flags;  /* +0x0004 */
    uint16_t cbAlloc;  /* +0x0006 */
    uint16_t h;  /* +0x0008 */
    uint16_t alignShift;  /* +0x000a */
    uint16_t reserved[2];  /* +0x000c */
} SEGINFO;

/* typind 5400 (0x1518) size=6 */
typedef struct tagKERNINGPAIR {
    uint16_t wFirst;  /* +0x0000 */
    uint16_t wSecond;  /* +0x0002 */
    int16_t iKernAmount;  /* +0x0004 */
} KERNINGPAIR;

/* typind 5426 (0x1532) size=6 */
typedef struct _planetminimal {
    int16_t id;  /* +0x0000 */
    int16_t iPlayer;  /* +0x0002 */
    union {
        struct {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fStarbase : 1;
            uint16_t unusedA : 1;
            uint16_t fFirstYear : 1;
            uint16_t unusedB : 4;
        };
    };  /* +0x0004 */
} PLANETMINIMAL;

/* typind 5453 (0x154d) size=6 */
typedef struct tagRASTERIZER_STATUS {
    int16_t nSize;  /* +0x0000 */
    int16_t wFlags;  /* +0x0002 */
    int16_t nLanguageID;  /* +0x0004 */
} RASTERIZER_STATUS;

/* typind 5456 (0x1550) size=17 */
typedef struct _rtloghdr {
    int16_t cbLog;  /* +0x0000 */
    int32_t lSerialNumber;  /* +0x0002 */
    uint8_t rgbConfig[11];  /* +0x0006 */
} RTLOGHDR;

/* typind 5460 (0x1554) size=2 */
typedef struct _mdplr {
    union {
        struct {
            uint16_t reserved : 9;
            uint16_t fAi : 1;
            uint16_t lvlAi : 3;
            uint16_t idAi : 3;
        };
    };  /* +0x0000 */
} MDPLR;

/* typind 5482 (0x156a) size=4 */
typedef struct _div_t {
    int16_t quot;  /* +0x0000 */
    int16_t rem;  /* +0x0002 */
} DIV_T;

/* typind 5485 (0x156d) size=8 */
typedef struct _ldiv_t {
    int32_t quot;  /* +0x0000 */
    int32_t rem;  /* +0x0004 */
} LDIV_T;

/* typind 5127 (0x1407) size=10 */
typedef struct tagLOGPEN {
    uint16_t lopnStyle;  /* +0x0000 */
    POINT lopnWidth;  /* +0x0002 */
    uint32_t lopnColor;  /* +0x0006 */
} LOGPEN;

/* typind 4167 (0x1047) size=16 */
typedef struct _scan {
    POINT pt;  /* +0x0000 */
    int16_t grobj;  /* +0x0004 */
    int16_t grobjFull;  /* +0x0006 */
    int16_t idpl;  /* +0x0008 */
    int16_t ifl;  /* +0x000a */
    int16_t iwp;  /* +0x000c */
    int16_t ith;  /* +0x000e */
} SCAN;

/* typind 5198 (0x144e) size=12 */
typedef struct _sbar {
    int16_t grbit;  /* +0x0000 */
    int16_t id;  /* +0x0002 */
    POINT pt;  /* +0x0004 */
    char *psz;  /* +0x0008 */
    SCAN * pscan;  /* +0x000a */
} SBAR;

/* typind 5270 (0x1496) size=10 */
typedef struct _thtrader {
    POINT ptDest;  /* +0x0000 */
    union {
        struct {
            uint16_t iWarp : 4;
            uint16_t fInclude : 1;
            uint16_t unused : 11;
        };
    };  /* +0x0004 */
    uint16_t grbitPlr;  /* +0x0006 */
    uint16_t grbitTrader;  /* +0x0008 */
} THTRADER;

/* typind 5279 (0x149f) size=12 */
typedef struct tagMOUSEHOOKSTRUCT {
    POINT pt;  /* +0x0000 */
    uint16_t hwnd;  /* +0x0004 */
    uint16_t wHitTestCode;  /* +0x0006 */
    uint32_t dwExtraInfo;  /* +0x0008 */
} MOUSEHOOKSTRUCT;

/* typind 4276 (0x10b4) size=54 */
typedef struct _rpt {
    int32_t grbitVisible;  /* +0x0000 */
    int16_t irpt;  /* +0x0004 */
    int16_t cFields;  /* +0x0006 */
    int16_t cFieldFirst;  /* +0x0008 */
    int16_t icolSort;  /* +0x000a */
    int16_t fAscending;  /* +0x000c */
    int16_t irowFirst;  /* +0x000e */
    POINT ptDlg;  /* +0x0010 */
    POINT ptSize;  /* +0x0014 */
    int16_t fCached;  /* +0x0018 */
    uint8_t rgbdx[16];  /* +0x001a */
    int16_t cRows;  /* +0x002a */
    int16_t cRowsVis;  /* +0x002c */
    int16_t iSubsort;  /* +0x002e */
    uint16_t hwndVScroll;  /* +0x0030 */
    uint16_t hwndHScroll;  /* +0x0032 */
    int16_t cColScroll;  /* +0x0034 */
} RPT;

/* typind 5393 (0x1511) size=20 */
typedef struct tagMINMAXINFO {
    POINT ptReserved;  /* +0x0000 */
    POINT ptMaxSize;  /* +0x0004 */
    POINT ptMaxPosition;  /* +0x0008 */
    POINT ptMinTrackSize;  /* +0x000c */
    POINT ptMaxTrackSize;  /* +0x0010 */
} MINMAXINFO;

/* typind 4983 (0x1377) size=12 */
typedef struct tagGLYPHMETRICS {
    uint16_t gmBlackBoxX;  /* +0x0000 */
    uint16_t gmBlackBoxY;  /* +0x0002 */
    POINT gmptGlyphOrigin;  /* +0x0004 */
    int16_t gmCellIncX;  /* +0x0008 */
    int16_t gmCellIncY;  /* +0x000a */
} GLYPHMETRICS;

/* typind 4523 (0x11ab) size=18 */
typedef struct tagMSG {
    uint16_t hwnd;  /* +0x0000 */
    uint16_t message;  /* +0x0002 */
    uint16_t wParam;  /* +0x0004 */
    int32_t lParam;  /* +0x0006 */
    uint32_t time;  /* +0x000a */
    POINT pt;  /* +0x000e */
} MSG;

/* typind 5117 (0x13fd) size=12 */
typedef struct _fleetsome {
    int16_t id;  /* +0x0000 */
    int16_t iPlayer;  /* +0x0002 */
    union {
        struct {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fRepOrders : 1;
            uint16_t fDead : 1;
            uint16_t fByteCsh : 1;
            uint16_t unused : 4;
        };
    };  /* +0x0004 */
    int16_t idPlanet;  /* +0x0006 */
    POINT pt;  /* +0x0008 */
} FLEETSOME;

/* typind 4121 (0x1019) size=32 */
typedef struct tagPAINTSTRUCT {
    uint16_t hdc;  /* +0x0000 */
    int16_t fErase;  /* +0x0002 */
    RECT rcPaint;  /* +0x0004 */
    int16_t fRestore;  /* +0x000c */
    int16_t fIncUpdate;  /* +0x000e */
    uint8_t rgbReserved[16];  /* +0x0010 */
} PAINTSTRUCT;

/* typind 4727 (0x1277) size=26 */
typedef struct tagDRAWITEMSTRUCT {
    uint16_t CtlType;  /* +0x0000 */
    uint16_t CtlID;  /* +0x0002 */
    uint16_t itemID;  /* +0x0004 */
    uint16_t itemAction;  /* +0x0006 */
    uint16_t itemState;  /* +0x0008 */
    uint16_t hwndItem;  /* +0x000a */
    uint16_t hDC;  /* +0x000c */
    RECT rcItem;  /* +0x000e */
    uint32_t itemData;  /* +0x0016 */
} DRAWITEMSTRUCT;

/* typind 5239 (0x1477) size=24 */
typedef struct _drawcir {
    int16_t * rgx;  /* +0x0000 */
    int16_t * rgy;  /* +0x0002 */
    int16_t * rgrad;  /* +0x0004 */
    int16_t cCur;  /* +0x0006 */
    int16_t cMax;  /* +0x0008 */
    uint16_t hdc;  /* +0x000a */
    RECT rcClip;  /* +0x000c */
    int16_t fCovered;  /* +0x0014 */
    int16_t fHollowOut;  /* +0x0016 */
} DRAWCIR;

/* typind 5301 (0x14b5) size=22 */
typedef struct tagWINDOWPLACEMENT {
    uint16_t length;  /* +0x0000 */
    uint16_t flags;  /* +0x0002 */
    uint16_t showCmd;  /* +0x0004 */
    POINT ptMinPosition;  /* +0x0006 */
    POINT ptMaxPosition;  /* +0x000a */
    RECT rcNormalPosition;  /* +0x000e */
} WINDOWPLACEMENT;

/* typind 5386 (0x150a) size=28 */
typedef struct tagNCCALCSIZE_PARAMS {
    RECT rgrc[3];  /* +0x0000 */
    WINDOWPOS * lppos;  /* +0x0018 */
} NCCALCSIZE_PARAMS;

/* typind 5429 (0x1535) size=10 */
typedef struct _wn {
    RECT rc;  /* +0x0000 */
    union {
        struct {
            uint16_t fMaximized : 1;
            uint16_t fMinimized : 1;
            uint16_t fInitalized : 1;
            uint16_t fUnused : 13;
        };
    };  /* +0x0008 */
} WN;

/* typind 4444 (0x115c) size=24 */
typedef struct _btnt {
    uint16_t hwnd;  /* +0x0000 */
    uint16_t hdc;  /* +0x0002 */
    RECT rc;  /* +0x0004 */
    int16_t dTimer;  /* +0x000c */
    int16_t btf;  /* +0x000e */
    char *szText;  /* +0x0010 */
    int32_t lTicks;  /* +0x0012 */
    union {
        struct {
            uint16_t fFirst : 1;
            uint16_t fDown : 1;
            uint16_t fInitDown : 1;
            uint16_t fCreatedDC : 1;
            uint16_t fNoEndRedraw : 1;
            uint16_t fUnused : 11;
        };
    };  /* +0x0016 */
} BTNT;

/* typind 5103 (0x13ef) size=14 */
typedef struct _btn {
    RECT rc;  /* +0x0000 */
    int16_t bt;  /* +0x0008 */
    int16_t iVal;  /* +0x000a */
    union {
        struct {
            uint16_t fVisible : 1;
            uint16_t fDisabled : 1;
            uint16_t iSide : 2;
            uint16_t fUnused : 12;
        };
    };  /* +0x000c */
} BTN;

/* typind 4180 (0x1054) size=4 */
typedef struct PLPROD {
    union {
        struct {
            uint16_t cbItem : 8;
            uint16_t fMark : 1;
            uint16_t ht : 3;
            uint16_t cAlloc : 4;
        };
    };  /* +0x0000 */
    uint8_t iprodMax;  /* +0x0002 */
    uint8_t iprodMac;  /* +0x0003 */
    PROD rgprod[0];  /* +0x0004 */
} PLPROD;

/* typind 4933 (0x1345) size=2 */
typedef struct _rtChgProdQ {
    int16_t id;  /* +0x0000 */
    PROD rgprod[0];  /* +0x0002 */
} RTCHGPRODQ;

/* typind 4190 (0x105e) size=8 */
typedef struct _part {
    HS hs;  /* +0x0000 */
    union {
        ARMOR * parmor;
        BEAM * pbeam;
        BOMB * pbomb;
        COMPART * pcom;
        ENGINE * pengine;
        HUL * phul;
        MINES * pmines;
        MINING * pmining;
        PLANETARY * pplanetary;
        SCANNER * pscanner;
        SHIELD * pshield;
        SPECIAL * pspecial;
        SPECIALSB * pspecialsb;
        TERRA * pterra;
        TORP * ptorp;
    };  /* +0x0004 */
} PART;

/* typind 4214 (0x1076) size=123 */
typedef struct _hul {
    int16_t ihuldef;  /* +0x0000 */
    char rgTech[6];  /* +0x0002 */
    char szClass[32];  /* +0x0008 */
    uint16_t wtEmpty;  /* +0x0028 */
    uint16_t resCost;  /* +0x002a */
    uint16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;  /* +0x0032 */
    uint16_t wtCargoMax;  /* +0x0034 */
    uint16_t wtFuelMax;  /* +0x0036 */
    uint16_t dp;  /* +0x0038 */
    HS rghs[16];  /* +0x003a */
    uint8_t chs;  /* +0x007a */
} HUL;

/* typind 5327 (0x14cf) size=17 */
typedef struct _rtshdef {
    union {
        uint16_t wFlags;
        struct {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fFree : 1;
            uint16_t ishdef : 5;
            uint16_t fGift : 1;
        };
    };  /* +0x0000 */
    uint8_t ihuldef;  /* +0x0002 */
    uint8_t ibmp;  /* +0x0003 */
    union {
        uint16_t dp;
        uint16_t wtEmpty;
    };  /* +0x0004 */
    uint8_t chs;  /* +0x0006 */
    uint16_t turn;  /* +0x0007 */
    uint32_t cBuilt;  /* +0x0009 */
    uint32_t cExist;  /* +0x000d */
    HS rghs[0];  /* +0x0011 */
} RTSHDEF;

/* typind 4991 (0x137f) size=10 */
typedef struct _taskxport {
    ITEMACTION rgia[5];  /* +0x0000 */
} TASKXPORT;

/* typind 4099 (0x1003) size=124 */
typedef struct _fleet {
    union {
        int16_t id;
        struct {
            uint16_t ifl : 9;
            uint16_t iplr : 4;
            uint16_t junk : 3;
        };
    };  /* +0x0000 */
    int16_t iPlayer;  /* +0x0002 */
    union {
        struct {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fRepOrders : 1;
            uint16_t fDead : 1;
            uint16_t fDone : 1;
            uint16_t fBombed : 1;
            uint16_t fHereAllTurn : 1;
            uint16_t fNoHeal : 1;
            uint16_t fMark : 1;
        };
    };  /* +0x0004 */
    int16_t idPlanet;  /* +0x0006 */
    POINT pt;  /* +0x0008 */
    int16_t rgcsh[16];  /* +0x000c */
    union {
        DV rgdv[16];
        int32_t wtFleet;
    };  /* +0x002c */
    int32_t rgwtMin[5];  /* +0x004c */
    uint8_t iplan;  /* +0x0060 */
    uint8_t bUnused;  /* +0x0061 */
    int16_t cord;  /* +0x0062 */
    PLORD * lpplord;  /* +0x0064 */
    FLEET * lpflNext;  /* +0x0068 */
    union {
        int16_t dMoveLeft;
        int32_t lPower;
    };  /* +0x006c */
    int16_t dMoveUsed;  /* +0x006e */
    int32_t lFuelUsed;  /* +0x0070 */
    union {
        int32_t dirLong;
        struct {
            uint16_t dirFltX : 8;
            uint16_t dirFltY : 8;
        };
    };  /* +0x0074 */
    union {
        struct {
            uint16_t iwarpFlt : 4;
            uint16_t fdirValid : 1;
            uint16_t fCompChg : 1;
            uint16_t fTargeted : 1;
            uint16_t fSkipped : 1;
            uint16_t fUnused : 8;
        };
    };  /* +0x0076 */
    char *lpszName;  /* +0x0078 */
} FLEET;

/* typind 4329 (0x10e9) size=29 */
typedef struct _tok {
    uint16_t id;  /* +0x0000 */
    uint8_t iplr;  /* +0x0002 */
    uint8_t grobj;  /* +0x0003 */
    uint8_t ishdef;  /* +0x0004 */
    uint8_t brc;  /* +0x0005 */
    uint8_t initBase;  /* +0x0006 */
    uint8_t initMin;  /* +0x0007 */
    uint8_t initMac;  /* +0x0008 */
    uint8_t itokTarget;  /* +0x0009 */
    uint8_t pctCloak;  /* +0x000a */
    uint8_t pctJam;  /* +0x000b */
    uint8_t pctBC;  /* +0x000c */
    uint8_t pctCap;  /* +0x000d */
    uint8_t pctBeamDef;  /* +0x000e */
    uint16_t wt;  /* +0x000f */
    uint16_t dpShield;  /* +0x0011 */
    uint16_t csh;  /* +0x0013 */
    DV dv;  /* +0x0015 */
    union {
        struct {
            uint16_t mdTarget1 : 4;
            uint16_t mdTarget2 : 4;
            uint16_t mdTactic : 4;
            uint16_t mdTarget0 : 4;
        };
    };  /* +0x0017 */
    union {
        struct {
            uint16_t dxyLim : 4;
            uint16_t dxyMax : 4;
            uint16_t spd : 4;
            uint16_t cTarget : 4;
        };
    };  /* +0x0019 */
    union {
        uint16_t wFlags;
        struct {
            uint16_t fActive : 1;
            uint16_t fDetector : 1;
            uint16_t fTorp : 1;
            uint16_t fRegen : 1;
            uint16_t fMoved : 1;
            uint16_t dzDis : 5;
            uint16_t dwt : 4;
            uint16_t dMovesLeft : 2;
        };
    };  /* +0x001b */
} TOK;

/* typind 5107 (0x13f3) size=8 */
typedef struct _kill {
    uint8_t itok;  /* +0x0000 */
    uint8_t grfWeapon;  /* +0x0001 */
    uint16_t cshKill;  /* +0x0002 */
    uint16_t dpShield;  /* +0x0004 */
    DV dv;  /* +0x0006 */
} KILL;

/* typind 5407 (0x151f) size=146 */
typedef struct tagENUMLOGFONT {
    LOGFONT elfLogFont;  /* +0x0000 */
    char elfFullName[64];  /* +0x0032 */
    char elfStyle[32];  /* +0x0072 */
} ENUMLOGFONT;

/* typind 4830 (0x12de) size=5 */
typedef struct _msgturn {
    union {
        struct {
            uint8_t iPlr : 4;
            uint8_t cbParams : 4;
        };
    };  /* +0x0000 */
    MSGHDR msghdr;  /* +0x0001 */
} MSGTURN;

/* typind 4250 (0x109a) size=24 */
typedef struct _scorex {
    union {
        uint16_t wWord;
        struct {
            uint16_t iPlayer : 5;
            uint16_t fValid : 1;
            uint16_t grbitVC : 8;
            uint16_t fWinner : 1;
            uint16_t fHistory : 1;
        };
    };  /* +0x0000 */
    union {
        int16_t iRank;
        uint16_t turn;
    };  /* +0x0002 */
    SCORE score;  /* +0x0004 */
} SCOREX;

/* typind 4335 (0x10ef) size=26 */
typedef struct _zipprodq1 {
    uint8_t fNoResearch;  /* +0x0000 */
    uint8_t cpq;  /* +0x0001 */
    PRODQ1 rgpq[12];  /* +0x0002 */
} ZIPPRODQ1;

/* typind 4971 (0x136b) size=15 */
typedef struct tagBITMAPCOREINFO {
    BITMAPCOREHEADER bmciHeader;  /* +0x0000 */
    RGBTRIPLE bmciColors[1];  /* +0x000c */
} BITMAPCOREINFO;

/* typind 5165 (0x142d) size=16 */
typedef struct tagMAT2 {
    FIXED eM11;  /* +0x0000 */
    FIXED eM12;  /* +0x0004 */
    FIXED eM21;  /* +0x0008 */
    FIXED eM22;  /* +0x000c */
} MAT2;

/* typind 5261 (0x148d) size=8 */
typedef struct tagPOINTFX {
    FIXED x;  /* +0x0000 */
    FIXED y;  /* +0x0004 */
} POINTFX;

/* typind 5446 (0x1546) size=44 */
typedef struct tagBITMAPINFO {
    BITMAPINFOHEADER bmiHeader;  /* +0x0000 */
    RGBQUAD bmiColors[1];  /* +0x0028 */
} BITMAPINFO;

/* typind 5218 (0x1462) size=1284 */
typedef struct _aihist {
    uint16_t cbAiHist;  /* +0x0000 */
    int16_t cStarbase;  /* +0x0002 */
    AISTARBASE rgasb[64];  /* +0x0004 */
} AIHIST;

/* typind 5265 (0x1491) size=114 */
typedef struct tagOUTLINETEXTMETRIC {
    uint16_t otmSize;  /* +0x0000 */
    TEXTMETRIC otmTextMetrics;  /* +0x0002 */
    uint8_t otmFiller;  /* +0x0021 */
    PANOSE otmPanoseNumber;  /* +0x0022 */
    uint16_t otmfsSelection;  /* +0x002c */
    uint16_t otmfsType;  /* +0x002e */
    int16_t otmsCharSlopeRise;  /* +0x0030 */
    int16_t otmsCharSlopeRun;  /* +0x0032 */
    int16_t otmItalicAngle;  /* +0x0034 */
    uint16_t otmEMSquare;  /* +0x0036 */
    int16_t otmAscent;  /* +0x0038 */
    int16_t otmDescent;  /* +0x003a */
    uint16_t otmLineGap;  /* +0x003c */
    uint16_t otmsCapEmHeight;  /* +0x003e */
    uint16_t otmsXHeight;  /* +0x0040 */
    RECT otmrcFontBox;  /* +0x0042 */
    int16_t otmMacAscent;  /* +0x004a */
    int16_t otmMacDescent;  /* +0x004c */
    uint16_t otmMacLineGap;  /* +0x004e */
    uint16_t otmusMinimumPPEM;  /* +0x0050 */
    POINT otmptSubscriptSize;  /* +0x0052 */
    POINT otmptSubscriptOffset;  /* +0x0056 */
    POINT otmptSuperscriptSize;  /* +0x005a */
    POINT otmptSuperscriptOffset;  /* +0x005e */
    uint16_t otmsStrikeoutSize;  /* +0x0062 */
    int16_t otmsStrikeoutPosition;  /* +0x0064 */
    int16_t otmsUnderscorePosition;  /* +0x0066 */
    int16_t otmsUnderscoreSize;  /* +0x0068 */
    char * otmpFamilyName;  /* +0x006a */
    char * otmpFaceName;  /* +0x006c */
    char * otmpStyleName;  /* +0x006e */
    char * otmpFullName;  /* +0x0070 */
} OUTLINETEXTMETRIC;

/* typind 4542 (0x11be) size=8 */
typedef struct tagLOGPALETTE {
    uint16_t palVersion;  /* +0x0000 */
    uint16_t palNumEntries;  /* +0x0002 */
    PALETTEENTRY palPalEntry[1];  /* +0x0004 */
} LOGPALETTE;

/* typind 5422 (0x152e) size=28 */
typedef struct _selSome {
    POINT pt;  /* +0x0000 */
    int16_t grobj;  /* +0x0004 */
    int16_t grobjFull;  /* +0x0006 */
    int16_t id;  /* +0x0008 */
    int16_t iwpAct;  /* +0x000a */
    SCAN scan;  /* +0x000c */
} SELSOME;

/* typind 4102 (0x1006) size=18 */
typedef struct _thing {
    union {
        uint16_t idFull;
        struct {
            uint16_t id : 9;
            uint16_t iplr : 4;
            uint16_t ith : 3;
        };
    };  /* +0x0000 */
    POINT pt;  /* +0x0002 */
    union {
        uint8_t rgb[10];
        THMINE thm;
        THPACK thp;
        THTRADER tht;
        THWORM thw;
    };  /* +0x0006 */
    uint16_t turn;  /* +0x0010 */
} THING;

/* typind 4332 (0x10ec) size=26 */
typedef struct _ini {
    WN wnFrame;  /* +0x0000 */
    union {
        uint16_t wFlags;
        struct {
            uint16_t fStartupFile : 1;
            uint16_t fCmdLine : 1;
            uint16_t fWait : 1;
            uint16_t fGen : 1;
            uint16_t fTry : 1;
            uint16_t grobjSel : 4;
            uint16_t fBatch : 1;
            uint16_t fNewGame : 1;
            uint16_t fDumpFleets : 1;
            uint16_t fDumpPlanets : 1;
            uint16_t fDumpMap : 1;
            uint16_t fValidate : 1;
            uint16_t fLogging : 1;
        };
    };  /* +0x000a */
    uint16_t turn;  /* +0x000c */
    int16_t iObjSel;  /* +0x000e */
    int16_t idPlayer;  /* +0x0010 */
    int32_t lid;  /* +0x0012 */
    int16_t cTurnGen;  /* +0x0016 */
    int16_t iMsg;  /* +0x0018 */
} INI;

/* typind 4291 (0x10c3) size=22 */
typedef struct _popupdata {
    int16_t grPopup;  /* +0x0000 */
    union {
        int16_t dxOut;
        int16_t iPlayer;
        int16_t idPlan;
        int16_t idPlanet;
        FLEET * lpfl;
        SHDEF * lpshdef;
        PART part;
        int32_t rgi[5];
    };  /* +0x0002 */
    union {
        int16_t cMax;
        int16_t iPlanetVar;
        char * psz;
    };  /* +0x0004 */
    union {
        int16_t cCur;
        int16_t fRedDamage;
        int16_t fShowDamage;
        int16_t iPlanVal;
    };  /* +0x0006 */
    union {
        int16_t cOperate;
        int16_t dxDamage;
        int16_t fHideCounts;
        int16_t iPlanMin;
    };  /* +0x0008 */
    union {
        int16_t fFactory;
        int16_t fToken;
        uint16_t grbit;
        int16_t iPlanMax;
    };  /* +0x000a */
    union {
        int16_t fSummary;
        int16_t iPlrVal;
    };  /* +0x000c */
    union {
        int16_t iPlrMin;
        int16_t itok;
    };  /* +0x000e */
    int16_t iPlrMax;  /* +0x0010 */
} POPUPDATA;

/* typind 4104 (0x1008) size=147 */
typedef struct _shdef {
    HUL hul;  /* +0x0000 */
    union {
        uint16_t wFlags;
        struct {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fFree : 1;
            uint16_t ishdef : 5;
            uint16_t fGift : 1;
        };
    };  /* +0x007b */
    uint16_t turn;  /* +0x007d */
    uint32_t cBuilt;  /* +0x007f */
    uint32_t cExist;  /* +0x0083 */
    union {
        int32_t lPower;
        int32_t lVisible;
    };  /* +0x0087 */
    uint16_t grbitPlr;  /* +0x008b */
    uint16_t dScanRange;  /* +0x008d */
    uint16_t dScanRange2;  /* +0x008f */
    uint8_t pctDetect;  /* +0x0091 */
    uint8_t iSteal;  /* +0x0092 */
} SHDEF;

/* typind 4745 (0x1289) size=143 */
typedef struct _huldef {
    HUL hul;  /* +0x0000 */
    union {
        struct {
            uint16_t init : 6;
            uint16_t imdAttack : 4;
            uint16_t imdCategory : 4;
            uint16_t unused : 2;
        };
    };  /* +0x007b */
    uint16_t wrcCargo;  /* +0x007d */
    uint8_t rgbrc[16];  /* +0x007f */
} HULDEF;

/* typind 5337 (0x14d9) size=19 */
typedef struct _rtchgshdef {
    union {
        struct {
            uint16_t mdChg : 4;
            uint16_t iPlr : 4;
            uint16_t ishdef : 5;
            uint16_t junk : 3;
        };
    };  /* +0x0000 */
    RTSHDEF rtshdef;  /* +0x0002 */
} RTCHGSHDEF;

/* typind 4101 (0x1005) size=18 */
typedef struct _order {
    POINT pt;  /* +0x0000 */
    int16_t id;  /* +0x0004 */
    union {
        struct {
            uint16_t grTask : 4;
            uint16_t iWarp : 4;
            uint16_t grobj : 4;
            uint16_t fValidTask : 1;
            uint16_t fNoAutoTrack : 1;
            uint16_t fUnused : 2;
        };
    };  /* +0x0006 */
    union {
        TASKLAYMINES tlm;
        TASKPATROL tptl;
        TASKSELL tsell;
        TASKXPORT txp;
    };  /* +0x0008 */
} ORDER;

/* typind 4229 (0x1085) size=24 */
typedef struct _ziporder {
    TASKXPORT txp;  /* +0x0000 */
    char szName[13];  /* +0x000a */
    uint8_t fValid;  /* +0x0017 */
} ZIPORDER;

/* typind 4258 (0x10a2) size=14 */
typedef struct _btldata {
    uint16_t id;  /* +0x0000 */
    uint8_t cplr;  /* +0x0002 */
    uint8_t ctok;  /* +0x0003 */
    uint16_t grfPlr;  /* +0x0004 */
    uint16_t cbData;  /* +0x0006 */
    uint16_t idPlanet;  /* +0x0008 */
    POINT pt;  /* +0x000a */
    TOK rgtok[0];  /* +0x000e */
} BTLDATA;

/* typind 5176 (0x1438) size=6 */
typedef struct _btlrec26 {
    uint8_t itok;  /* +0x0000 */
    uint8_t brcDest;  /* +0x0001 */
    uint8_t itokAttack;  /* +0x0002 */
    uint8_t ctok;  /* +0x0003 */
    union {
        struct {
            uint16_t iRound : 4;
            uint16_t dzDis : 4;
            uint16_t unused : 8;
        };
    };  /* +0x0004 */
    KILL rgkill[0];  /* +0x0006 */
} BTLREC26;

/* typind 4438 (0x1156) size=6 */
typedef struct _btlrec {
    uint8_t itok;  /* +0x0000 */
    uint8_t brcDest;  /* +0x0001 */
    int16_t ctok;  /* +0x0002 */
    union {
        struct {
            uint16_t iRound : 4;
            uint16_t dzDis : 4;
            uint16_t itokAttack : 8;
        };
    };  /* +0x0004 */
    KILL rgkill[0];  /* +0x0006 */
} BTLREC;

/* typind 4116 (0x1014) size=192 */
typedef struct _player {
    char iPlayer;  /* +0x0000 */
    char cShDef;  /* +0x0001 */
    int16_t cPlanet;  /* +0x0002 */
    union {
        struct {
            uint16_t cFleet : 12;
            uint16_t cshdefSB : 4;
        };
    };  /* +0x0004 */
    union {
        uint16_t wMdPlr;
        struct {
            uint16_t det : 3;
            uint16_t reserved : 9;
            uint16_t iPlrBmp : 5;
            uint16_t fInclude : 1;
            uint16_t fAi : 1;
            uint16_t mdPlayer : 7;
            uint16_t lvlAi : 3;
            uint16_t idAi : 3;
        };
    };  /* +0x0006 */
    int16_t idPlanetHome;  /* +0x0008 */
    uint16_t wScore;  /* +0x000a */
    int32_t lSalt;  /* +0x000c */
    char rgEnvVar[3];  /* +0x0010 */
    char rgEnvVarMin[3];  /* +0x0013 */
    char rgEnvVarMax[3];  /* +0x0016 */
    char pctIdealGrowth;  /* +0x0019 */
    char rgTech[6];  /* +0x001a */
    uint32_t rgResSpent[6];  /* +0x0020 */
    char pctResearch;  /* +0x0038 */
    char iTechCur;  /* +0x0039 */
    int32_t lResLastYear;  /* +0x003a */
    char rgAttr[16];  /* +0x003e */
    uint32_t grbitAttr;  /* +0x004e */
    uint16_t grbitTrader;  /* +0x0052 */
    union {
        uint16_t wFlags;
        struct {
            uint16_t fDead : 1;
            uint16_t fCrippled : 1;
            uint16_t fCheater : 1;
            uint16_t fLearned : 1;
            uint16_t fHacker : 1;
            uint16_t unused : 11;
        };
    };  /* +0x0054 */
    ZIPPRODQ1 zpq1;  /* +0x0056 */
    char rgmdRelation[16];  /* +0x0070 */
    char szName[32];  /* +0x0080 */
    char szNames[32];  /* +0x00a0 */
} PLAYER;

/* typind 4333 (0x10ed) size=44 */
typedef struct _tutor {
    union {
        int16_t wFlags;
        struct {
            uint16_t fVisible : 1;
            uint16_t fGameSaved : 1;
            uint16_t fChange : 1;
            uint16_t fTurnDone : 1;
            uint16_t fTutorDone : 1;
            uint16_t fNoErrors : 1;
            uint16_t cError : 3;
            uint16_t fAutoComplete : 1;
            uint16_t fProgress : 1;
            uint16_t fTBVis : 1;
            uint16_t fValidQ : 1;
            uint16_t fFreeing : 1;
            uint16_t fShowHidMsg : 1;
            uint16_t unused : 1;
        };
    };  /* +0x0000 */
    int16_t idt;  /* +0x0002 */
    int16_t idtBold;  /* +0x0004 */
    int16_t idh;  /* +0x0006 */
    int16_t idsError;  /* +0x0008 */
    int16_t iScanZoom;  /* +0x000a */
    int16_t icolFSort;  /* +0x000c */
    uint16_t grbitScan;  /* +0x000e */
    uint16_t hwnd;  /* +0x0010 */
    ZIPPRODQ1 zpq;  /* +0x0012 */
} TUTOR;

/* typind 4337 (0x10f1) size=40 */
typedef struct _zipprodq {
    char szName[13];  /* +0x0000 */
    uint8_t fValid;  /* +0x000d */
    union {
        uint8_t fNoResearch;
        ZIPPRODQ1 zpq1;
    };  /* +0x000e */
    uint8_t cpq;  /* +0x000f */
    PRODQ1 rgpq[12];  /* +0x0010 */
} ZIPPRODQ;

/* typind 5286 (0x14a6) size=12 */
typedef struct tagTTPOLYCURVE {
    uint16_t wType;  /* +0x0000 */
    uint16_t cpfx;  /* +0x0002 */
    POINTFX apfx[1];  /* +0x0004 */
} TTPOLYCURVE;

/* typind 5320 (0x14c8) size=16 */
typedef struct tagTTPOLYGONHEADER {
    uint32_t cb;  /* +0x0000 */
    uint32_t dwType;  /* +0x0004 */
    POINTFX pfxStart;  /* +0x0008 */
} TTPOLYGONHEADER;

/* typind 4187 (0x105b) size=226 */
typedef struct _sel {
    POINT pt;  /* +0x0000 */
    int16_t grobj;  /* +0x0004 */
    int16_t grobjFull;  /* +0x0006 */
    int16_t id;  /* +0x0008 */
    int16_t iwpAct;  /* +0x000a */
    SCAN scan;  /* +0x000c */
    FLEET fl;  /* +0x001c */
    PLANET pl;  /* +0x0098 */
    THING th;  /* +0x00d0 */
} SEL;

/* typind 4910 (0x132e) size=128 */
typedef struct _xfer {
    int16_t id;  /* +0x0000 */
    int16_t grobj;  /* +0x0002 */
    union {
        FLEET fl;
        PLANET pl;
        THING th;
    };  /* +0x0004 */
} XFER;

/* typind 5226 (0x146a) size=22 */
typedef struct _rtwaypt {
    int16_t id;  /* +0x0000 */
    int16_t iWaypt;  /* +0x0002 */
    ORDER order;  /* +0x0004 */
} RTWAYPT;

/* typind 5416 (0x1528) size=4 */
typedef struct PLORD {
    union {
        struct {
            uint16_t cbItem : 8;
            uint16_t fMark : 1;
            uint16_t ht : 3;
            uint16_t cAlloc : 4;
        };
    };  /* +0x0000 */
    uint8_t iordMax;  /* +0x0002 */
    uint8_t iordMac;  /* +0x0003 */
    ORDER rgord[0];  /* +0x0004 */
} PLORD;

#endif /* STARS_NB09_TYPES_H */
