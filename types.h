#ifndef STARS_NB09_TYPES_H
#define STARS_NB09_TYPES_H
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <setjmp.h>

#ifdef _WIN32
#include <windows.h>
#else /* !_WIN32 */
/* MessageBox-style flags (Win16/Win32 compatible values) */
typedef enum MBFlags
{
    MB_OK = 0x0000, /* default */
    MB_YESNO = 0x0004,
    MB_ICONHAND = 0x0010,     /* error / stop */
    MB_ICONQUESTION = 0x0020, /* question */
} MBFlags;

/* typind 4120 (0x1018) size=4 */
typedef struct tagPOINT
{
    int16_t x; /* +0x0000 */
    int16_t y; /* +0x0002 */
} POINT;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(POINT) == 4, "sizeof(POINT)");
_Static_assert(offsetof(POINT, x) == 0x0, "offsetof(POINT,x)");
_Static_assert(offsetof(POINT, y) == 0x2, "offsetof(POINT,y)");
#endif

/* typind 4122 (0x101a) size=8 */
typedef struct tagRECT
{
    int16_t left;   /* +0x0000 */
    int16_t top;    /* +0x0002 */
    int16_t right;  /* +0x0004 */
    int16_t bottom; /* +0x0006 */
} RECT;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RECT) == 8, "sizeof(RECT)");
_Static_assert(offsetof(RECT, left) == 0x0, "offsetof(RECT,left)");
_Static_assert(offsetof(RECT, top) == 0x2, "offsetof(RECT,top)");
_Static_assert(offsetof(RECT, right) == 0x4, "offsetof(RECT,right)");
_Static_assert(offsetof(RECT, bottom) == 0x6, "offsetof(RECT,bottom)");
#endif

/* Minimal “Windows SDK” stubs for non-Windows builds.
 * These exist only so code that declares locals/params compiles.
 * Do NOT rely on their layouts/fields on non-Windows.
 */

typedef struct tagLOGFONT
{
    int _unused;
} LOGFONT;
typedef struct tagTEXTMETRIC
{
    int _unused;
} TEXTMETRIC;
typedef struct tagPAINTSTRUCT
{
    int _unused;
} PAINTSTRUCT;
typedef struct tagDRAWITEMSTRUCT
{
    int _unused;
} DRAWITEMSTRUCT;
typedef struct tagMEASUREITEMSTRUCT
{
    int _unused;
} MEASUREITEMSTRUCT;
typedef struct tagWNDCLASS
{
    int _unused;
} WNDCLASS;
typedef struct tagWINDOWPLACEMENT
{
    int _unused;
} WINDOWPLACEMENT;

/* Windows message struct (careful: name is MSG). */
typedef struct tagMSG
{
    int _unused;
} MSG;

/* If you used these abbreviated names in generated code: */
typedef struct tagOPENFILENAME
{
    int _unused;
} OFN;
typedef struct tagTIMERINFO
{
    int _unused;
} TIMERINFO;
typedef struct tagPD
{
    int _unused;
} PD;
typedef struct tagBITMAP
{
    int _unused;
} BITMAP;
typedef struct tagBITMAPCOREHEADER
{
    int _unused;
} BITMAPCOREHEADER;
typedef struct tagBITMAPINFOHEADER
{
    int _unused;
} BITMAPINFOHEADER;
typedef struct tagBITMAPINFO
{
    int _unused;
} BITMAPINFO;
typedef struct tagLOGPALETTE
{
    int _unused;
} LOGPALETTE;
typedef struct tagOFSTRUCT
{
    int _unused;
} OFSTRUCT;

#endif

#define fFalse 0
#define fTrue 1

#define iPlayerNil -1
#define iPlayerMax 16
#define iPlanetPartNone -1

typedef enum RaceAttribute
{
    raCheapCol = 0,  // HE (Hyper Expansion)
    raStealth = 1,   // SS (Super Stealth)
    raAttack = 2,    // WM (War Monger)
    raTerra = 3,     // CA (Claim Adjuster)
    raDefend = 4,    // IS (Inner Strength)
    raMines = 5,     // SD (Space Demolition)
    raMassAccel = 6, // PP (Packet Physics)
    raStargate = 7,  // IT (Inner Tech)
    raMacintosh = 8, // AR (Alternate Reality)
    raNone = 9,      // JoaT (Jack of All Trades)
    raMax = 10,
} RaceAttribute;

typedef enum RaceGrbit
{
    ibitRaceIFE = 0x00,
    ibitRaceTT = 0x01,
    ibitRaceARM = 0x02,
    ibitRaceISB = 0x03,
    ibitRaceGeneralizedResearch = 0x04,
    ibitRaceMineralAlchemy = 0x06,
    ibitRaceNoRamscoops = 0x07,
    ibitRaceCheapEngines = 0x08,
    ibitRaceOBRM = 0x09,
    ibitRaceNoAdvScanner = 0x0a,
    ibitRaceLowStartingPop = 0x0b,
    ibitRaceBleedingEdgeTech = 0x0c,
    ibitRaceRegeneratingShields = 0x0d,
    ibitRaceTech3 = 0x1d,
    ibitRaceAIPlayer = 0x1e,
    ibitRaceCheapFact = 0x1f,
    ibitRaceLast = 32,
} RaceGrbit;

typedef enum RaceStat
{
    rsResGen = 0,
    rsFactProd = 1,
    rsFactBuild = 2,
    rsFactOperate = 3,
    rsMineProd = 4,
    rsMineBuild = 5,
    rsMineOperate = 6,
    rsUseLeftover = 7,
    rsTechBonus1 = 8,
    rsTechBonus2 = 9,
    rsTechBonus3 = 10,
    rsTechBonus4 = 11,
    rsTechBonus5 = 12,
    rsTechBonus6 = 13,
    rsMajorAdv = 14,
} RaceStat;

typedef enum DetType
{
    detNone = 0,
    detMinimal = 1,
    detObscure = 2,
    detSome = 3,
    detMore = 4,
    detAll = 7,
} DetType;

typedef enum GrobjClass
{
    grobjNone = 0x0,
    grobjPlanet = 0x1,
    grobjFleet = 0x2,
    grobjOther = 0x4,
    grobjThing = 0x8,
} GrobjClass;

typedef enum HullSlotType
{
    hstEngine = 0x0001,
    hstScanner = 0x0002,
    hstShield = 0x0004,
    hstArmor = 0x0008,
    hstBeam = 0x0010,
    hstTorp = 0x0020,
    hstBomb = 0x0040,
    hstMining = 0x0080,
    hstMines = 0x0100,
    hstSpecialSB = 0x0200,
    hstSBHull = 0x0400,
    hstSpecialE = 0x0800,
    hstSpecialM = 0x1000,
    hstTerra = 0x2000,
    hstHull = 0x4000,
    hstPlanetary = 0x8000,
} HullSlotType;

typedef enum StartingStarbase
{
    Starbase = 0,
    AcceleratorPlatform = 1,
    PortholetoBeyond = 2,
    StarterColony = 3,
} StartingStarbase;

typedef enum StartingShip
{
    LilliputianFreighter = 0,
    ShadowTransport = 1,
    SmaugarianPeepingTom = 2,
    ArmedProbe = 3,
    LongRangeScout = 4,
    ShadowSleuth = 5,
    Teamster = 6,
    StalwartDefender = 7,
    Swashbuckler = 8,
    SantaMaria = 9,
    Pinta = 10,
    Mayflower = 11,
    SporeCloud = 12,
    Gadfly = 13,
    CottonPicker = 14,
    PotatoBug = 15,
    LittleHen = 16,
    ChangeofHeart = 17,
    SpeedTurtle = 18,
    MTLifeboat = 19,
    MTScout = 20,
    MTProbe = 21,
} StartingShip;

typedef enum ThingType
{
    ithMinefield = 0,
    ithMineralPacket = 1,
    ithWormhole = 2,
    ithMysteryTrader = 3,
} ThingType;

typedef enum HulDefSB
{
    ihuldefSBOrbitalFort = 0,
    ihuldefSBSpaceDock = 1,
    ihuldefSBSpaceStation = 2,
    ihuldefSBUltraStation = 3,
    ihuldefSBDeathStar = 4,
} HulDefSB;

typedef enum HullDef
{
    ihuldefSmallFreighter = 0,
    ihuldefMediumFreighter = 1,
    ihuldefLargeFreighter = 2,
    ihuldefSuperFreighter = 3,
    ihuldefScout = 4,
    ihuldefFrigate = 5,
    ihuldefDestroyer = 6,
    ihuldefCruiser = 7,
    ihuldefBattleCruiser = 8,
    ihuldefBattleship = 9,
    ihuldefDreadnought = 10,
    ihuldefPrivateer = 11,
    ihuldefRogue = 12,
    ihuldefGalleon = 13,
    ihuldefMiniColonyShip = 14,
    ihuldefColonyShip = 15,
    ihuldefMiniBomber = 16,
    ihuldefB17Bomber = 17,
    ihuldefStealthBomber = 18,
    ihuldefB52Bomber = 19,
    ihuldefMidgetMiner = 20,
    ihuldefMiniMiner = 21,
    ihuldefMiner = 22,
    ihuldefMaxiMiner = 23,
    ihuldefUltraMiner = 24,
    ihuldefFuelTransport = 25,
    ihuldefSuperFuelXport = 26,
    ihuldefMiniMineLayer = 27,
    ihuldefSuperMineLayer = 28,
    ihuldefNubian = 29,
    ihuldefMiniMorph = 30,
    ihuldefMetaMorph = 31,
    ihuldefCount = 32,
} HullDef;

/* Match Win16/Stars! default struct packing (2-byte alignment). */
#pragma pack(push, 1)

/* offsetof is needed for optional layout checks; avoid stddef.h. */
#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

/* typind 4153 (0x1039) size=4 */
typedef struct _prod
{
    union
    {
        struct
        {
            uint32_t cItem : 10;
            uint32_t iItem : 7;
            uint32_t grobj : 3;
            uint32_t pct : 7;
            uint32_t unused : 5;
        };
        uint32_t dwRaw_0000;
    }; /* +0x0000 */
} PROD;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PROD) == 4, "sizeof(PROD)");
#endif

/* typind 4180 (0x1054) size=4 */
typedef struct PLPROD
{
    union
    {
        struct
        {
            uint16_t cbItem : 8;
            uint16_t fMark : 1;
            uint16_t ht : 3;
            uint16_t cAlloc : 4;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    uint8_t iprodMax; /* +0x0002 */
    uint8_t iprodMac; /* +0x0003 */
    PROD rgprod[0];   /* +0x0004 */
} PLPROD;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PLPROD) == 4, "sizeof(PLPROD)");
_Static_assert(offsetof(PLPROD, iprodMax) == 0x2, "offsetof(PLPROD,iprodMax)");
_Static_assert(offsetof(PLPROD, iprodMac) == 0x3, "offsetof(PLPROD,iprodMac)");
_Static_assert(offsetof(PLPROD, rgprod) == 0x4, "offsetof(PLPROD,rgprod)");
#endif

/* typind 4299 (0x10cb) size=2 */
typedef struct _itemaction
{
    union
    {
        struct
        {
            uint16_t cQuan : 12;
            uint16_t iAction : 4;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
} ITEMACTION;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(ITEMACTION) == 2, "sizeof(ITEMACTION)");
#endif

/* typind 4991 (0x137f) size=10 */
typedef struct _taskxport
{
    ITEMACTION rgia[5]; /* +0x0000 */
} TASKXPORT;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TASKXPORT) == 10, "sizeof(TASKXPORT)");
_Static_assert(offsetof(TASKXPORT, rgia) == 0x0, "offsetof(TASKXPORT,rgia)");
#endif

/* typind 4993 (0x1381) size=4 */
typedef struct _tasklaymines
{
    uint16_t cTime;    /* +0x0000 */
    uint16_t cTimeOld; /* +0x0002 */
} TASKLAYMINES;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TASKLAYMINES) == 4, "sizeof(TASKLAYMINES)");
_Static_assert(offsetof(TASKLAYMINES, cTime) == 0x0, "offsetof(TASKLAYMINES,cTime)");
_Static_assert(offsetof(TASKLAYMINES, cTimeOld) == 0x2, "offsetof(TASKLAYMINES,cTimeOld)");
#endif

/* typind 4995 (0x1383) size=4 */
typedef struct _taskpatrol
{
    uint16_t iWarp; /* +0x0000 */
    uint16_t iDist; /* +0x0002 */
} TASKPATROL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TASKPATROL) == 4, "sizeof(TASKPATROL)");
_Static_assert(offsetof(TASKPATROL, iWarp) == 0x0, "offsetof(TASKPATROL,iWarp)");
_Static_assert(offsetof(TASKPATROL, iDist) == 0x2, "offsetof(TASKPATROL,iDist)");
#endif

/* typind 4997 (0x1385) size=2 */
typedef struct _tasksell
{
    uint16_t iPlrX; /* +0x0000 */
} TASKSELL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TASKSELL) == 2, "sizeof(TASKSELL)");
_Static_assert(offsetof(TASKSELL, iPlrX) == 0x0, "offsetof(TASKSELL,iPlrX)");
#endif
/* typind 4101 (0x1005) size=18 */
typedef struct _order
{
    POINT pt;   /* +0x0000 */
    int16_t id; /* +0x0004 */
    union
    {
        struct
        {
            uint16_t grTask : 4;
            uint16_t iWarp : 4;
            uint16_t grobj : 4;
            uint16_t fValidTask : 1;
            uint16_t fNoAutoTrack : 1;
            uint16_t fUnused : 2;
        };
        uint16_t wRaw_0006;
    }; /* +0x0006 */
    union
    {
        TASKXPORT txp;
        TASKLAYMINES tlm;
        TASKPATROL tptl;
        TASKSELL tsell;
    }; /* +0x0008 */
} ORDER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(ORDER) == 18, "sizeof(ORDER)");
_Static_assert(offsetof(ORDER, pt) == 0x0, "offsetof(ORDER,pt)");
_Static_assert(offsetof(ORDER, id) == 0x4, "offsetof(ORDER,id)");
_Static_assert(offsetof(ORDER, txp) == 0x8, "offsetof(ORDER,txp)");
_Static_assert(offsetof(ORDER, tlm) == 0x8, "offsetof(ORDER,tlm)");
_Static_assert(offsetof(ORDER, tptl) == 0x8, "offsetof(ORDER,tptl)");
_Static_assert(offsetof(ORDER, tsell) == 0x8, "offsetof(ORDER,tsell)");
#endif

/* typind 4229 (0x1085) size=24 */
typedef struct _ziporder
{
    TASKXPORT txp;   /* +0x0000 */
    char szName[13]; /* +0x000a */
    uint8_t fValid;  /* +0x0017 */
} ZIPORDER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(ZIPORDER) == 24, "sizeof(ZIPORDER)");
_Static_assert(offsetof(ZIPORDER, txp) == 0x0, "offsetof(ZIPORDER,txp)");
_Static_assert(offsetof(ZIPORDER, szName) == 0xa, "offsetof(ZIPORDER,szName)");
_Static_assert(offsetof(ZIPORDER, fValid) == 0x17, "offsetof(ZIPORDER,fValid)");
#endif

/* typind 5416 (0x1528) size=4 */
typedef struct PLORD
{
    union
    {
        struct
        {
            uint16_t cbItem : 8;
            uint16_t fMark : 1;
            uint16_t ht : 3;
            uint16_t cAlloc : 4;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    uint8_t iordMax; /* +0x0002 */
    uint8_t iordMac; /* +0x0003 */
    ORDER rgord[0];  /* +0x0004 */
} PLORD;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PLORD) == 4, "sizeof(PLORD)");
_Static_assert(offsetof(PLORD, iordMax) == 0x2, "offsetof(PLORD,iordMax)");
_Static_assert(offsetof(PLORD, iordMac) == 0x3, "offsetof(PLORD,iordMac)");
_Static_assert(offsetof(PLORD, rgord) == 0x4, "offsetof(PLORD,rgord)");
#endif

/* typind 4098 (0x1002) size=56 */
typedef struct _planet
{
    int16_t id;      /* +0x0000 */
    int16_t iPlayer; /* +0x0002 */
    union
    {
        struct
        {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fStarbase : 1;
            uint16_t fHomeworld : 1;
            uint16_t fFirstYear : 1;
            uint16_t unusedC : 1;
            uint16_t fWasInhabited : 1;
            uint16_t unusedD : 2;
        };
        uint16_t wRaw_0004;
    }; /* +0x0004 */
    uint8_t rgpctMinLevel[3]; /* +0x0006 */
    uint8_t rgMinConc[3];     /* +0x0009 */
    uint8_t rgEnvVar[3];      /* +0x000c */
    uint8_t rgEnvVarOrig[3];  /* +0x000f */
    union
    {
        uint16_t uGuesses;
        struct
        {
            uint16_t uPopGuess : 12;
            uint16_t uDefGuess : 4;
        };
    }; /* +0x0012 */
    union
    {
        uint8_t rgbImp[8];
        struct
        {
            uint32_t iDeltaPop : 8;
            uint32_t cMines : 12;
            uint32_t cFactories : 12;
        };
        struct
        {
            uint32_t cDefenses : 12;
            uint32_t iScanner : 5;
            uint32_t unused5 : 5;
            uint32_t fArtifact : 1;
            uint32_t fNoResearch : 1;
            uint32_t unused2 : 8;
        };
        uint32_t dwRaw_0014;
    }; /* +0x0014 */
    int32_t rgwtMin[4]; /* +0x001c */
    union
    {
        int32_t lStarbase;
        struct
        {
            uint16_t isb : 4;
            uint16_t pctDp : 12;
        };
        struct
        {
            uint16_t idFling : 10;
            uint16_t iWarpFling : 4;
            uint16_t fNoHeal : 1;
            uint16_t unused3 : 1;
        };
    }; /* +0x002c */
    union
    {
        uint16_t wRouting;
        struct
        {
            uint16_t idRoute : 10;
            uint16_t unused4 : 6;
        };
    }; /* +0x0030 */
    int16_t turn;     /* +0x0032 */
    PLPROD *lpplprod; /* +0x0034 */
} PLANET;

/* typind 4114 (0x1012) size=64 */
typedef struct _game
{
    int32_t lid;         /* +0x0000 */
    int16_t mdSize;      /* +0x0004 */
    int16_t mdDensity;   /* +0x0006 */
    int16_t cPlayer;     /* +0x0008 */
    int16_t cPlanMax;    /* +0x000a */
    int16_t mdStartDist; /* +0x000c */
    int16_t fDirty;      /* +0x000e */
    union
    {
        uint16_t wCrap;
        struct
        {
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
    }; /* +0x0010 */
    uint16_t turn;    /* +0x0012 */
    uint8_t rgvc[12]; /* +0x0014 */
    char szName[32];  /* +0x0020 */
} GAME;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(GAME) == 64, "sizeof(GAME)");
_Static_assert(offsetof(GAME, lid) == 0x0, "offsetof(GAME,lid)");
_Static_assert(offsetof(GAME, mdSize) == 0x4, "offsetof(GAME,mdSize)");
_Static_assert(offsetof(GAME, mdDensity) == 0x6, "offsetof(GAME,mdDensity)");
_Static_assert(offsetof(GAME, cPlayer) == 0x8, "offsetof(GAME,cPlayer)");
_Static_assert(offsetof(GAME, cPlanMax) == 0xa, "offsetof(GAME,cPlanMax)");
_Static_assert(offsetof(GAME, mdStartDist) == 0xc, "offsetof(GAME,mdStartDist)");
_Static_assert(offsetof(GAME, fDirty) == 0xe, "offsetof(GAME,fDirty)");
_Static_assert(offsetof(GAME, wCrap) == 0x10, "offsetof(GAME,wCrap)");
_Static_assert(offsetof(GAME, turn) == 0x12, "offsetof(GAME,turn)");
_Static_assert(offsetof(GAME, rgvc) == 0x14, "offsetof(GAME,rgvc)");
_Static_assert(offsetof(GAME, szName) == 0x20, "offsetof(GAME,szName)");
#endif

/* typind 4115 (0x1013) size=10 */
typedef struct _gdata
{
    union
    {
        int32_t grBits;
        struct
        {
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
        struct
        {
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
    }; /* +0x0000 */
    union
    {
        int32_t grBits2;
        struct
        {
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
            uint16_t : 3;
        };
        struct
        {
            uint16_t iCurGraph : 4;
            uint16_t fMusic : 1;
            uint16_t fPerPlayerDumps : 1;
            uint16_t fNoHostNames : 1;
            uint16_t : 9;
        };
    }; /* +0x0004 */
    uint16_t fUnused2 : 14; /* +0x0008 */
} GDATA;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(GDATA) == 10, "sizeof(GDATA)");
_Static_assert(offsetof(GDATA, grBits) == 0x0, "offsetof(GDATA,grBits)");
_Static_assert(offsetof(GDATA, grBits2) == 0x4, "offsetof(GDATA,grBits2)");
#endif

/* typind 4152 (0x1038) size=22 */
typedef struct _framestuff
{
    int16_t dx;          /* +0x0000 */
    int16_t dy;          /* +0x0002 */
    int16_t xTop;        /* +0x0004 */
    int16_t y1;          /* +0x0006 */
    int16_t y2;          /* +0x0008 */
    int16_t dxPlanWant;  /* +0x000a */
    int16_t dyMsgWant;   /* +0x000c */
    int16_t dyMinWant;   /* +0x000e */
    int16_t dx2PlanWant; /* +0x0010 */
    int16_t dy2MsgWant;  /* +0x0012 */
    int16_t dy2MinWant;  /* +0x0014 */
} FRAMESTUFF;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(FRAMESTUFF) == 22, "sizeof(FRAMESTUFF)");
_Static_assert(offsetof(FRAMESTUFF, dx) == 0x0, "offsetof(FRAMESTUFF,dx)");
_Static_assert(offsetof(FRAMESTUFF, dy) == 0x2, "offsetof(FRAMESTUFF,dy)");
_Static_assert(offsetof(FRAMESTUFF, xTop) == 0x4, "offsetof(FRAMESTUFF,xTop)");
_Static_assert(offsetof(FRAMESTUFF, y1) == 0x6, "offsetof(FRAMESTUFF,y1)");
_Static_assert(offsetof(FRAMESTUFF, y2) == 0x8, "offsetof(FRAMESTUFF,y2)");
_Static_assert(offsetof(FRAMESTUFF, dxPlanWant) == 0xa, "offsetof(FRAMESTUFF,dxPlanWant)");
_Static_assert(offsetof(FRAMESTUFF, dyMsgWant) == 0xc, "offsetof(FRAMESTUFF,dyMsgWant)");
_Static_assert(offsetof(FRAMESTUFF, dyMinWant) == 0xe, "offsetof(FRAMESTUFF,dyMinWant)");
_Static_assert(offsetof(FRAMESTUFF, dx2PlanWant) == 0x10, "offsetof(FRAMESTUFF,dx2PlanWant)");
_Static_assert(offsetof(FRAMESTUFF, dy2MsgWant) == 0x12, "offsetof(FRAMESTUFF,dy2MsgWant)");
_Static_assert(offsetof(FRAMESTUFF, dy2MinWant) == 0x14, "offsetof(FRAMESTUFF,dy2MinWant)");
#endif

/* typind 4158 (0x103e) size=2 */
typedef struct _cyberinfo
{
    union
    {
        uint16_t wInfo;
        struct
        {
            uint16_t iLstPktDir : 3;
            uint16_t fBltColony : 1;
            uint16_t fLaunchedPkt : 1;
            uint16_t iPktTarget : 2;
            uint16_t fNeedScanPkt : 1;
            uint16_t unused : 8;
        };
    }; /* +0x0000 */
} CYBERINFO;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(CYBERINFO) == 2, "sizeof(CYBERINFO)");
_Static_assert(offsetof(CYBERINFO, wInfo) == 0x0, "offsetof(CYBERINFO,wInfo)");
#endif

/* typind 4160 (0x1040) size=2 */
typedef struct _cyberinfotemp
{
    union
    {
        uint16_t wInfo1;
        struct
        {
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
    }; /* +0x0000 */
} CYBERINFOTEMP;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(CYBERINFOTEMP) == 2, "sizeof(CYBERINFOTEMP)");
_Static_assert(offsetof(CYBERINFOTEMP, wInfo1) == 0x0, "offsetof(CYBERINFOTEMP,wInfo1)");
#endif

/* typind 4216 (0x1078) size=4 */
typedef struct _hs
{
    uint16_t grhst; /* +0x0000 */
    union
    {
        struct
        {
            uint16_t iItem : 8;
            uint16_t cItem : 8;
        };
        uint16_t wRaw_0002;
    }; /* +0x0002 */
} HS;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(HS) == 4, "sizeof(HS)");
_Static_assert(offsetof(HS, grhst) == 0x0, "offsetof(HS,grhst)");
#endif

/* typind 4286 (0x10be) size=36 */
typedef struct _btlplan
{
    union
    {
        struct
        {
            uint16_t iplr : 4;
            uint16_t iplan : 4;
            uint16_t mdTactic : 4;
            uint16_t unused1 : 2;
            uint16_t fDelete : 1;
            uint16_t fDumpCargo : 1;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    union
    {
        struct
        {
            uint16_t mdTarget1 : 4;
            uint16_t mdTarget2 : 4;
            uint16_t iplrAttack : 5;
            uint16_t unused2 : 3;
        };
        uint16_t wRaw_0002;
    }; /* +0x0002 */
    char szName[32]; /* +0x0004 */
} BTLPLAN;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(BTLPLAN) == 36, "sizeof(BTLPLAN)");
_Static_assert(offsetof(BTLPLAN, szName) == 0x4, "offsetof(BTLPLAN,szName)");
#endif

/* typind 4416 (0x1140) size=2 */
typedef struct _aipart
{
    union
    {
        struct
        {
            uint16_t ibit : 4;
            uint16_t iItem : 5;
            uint16_t cItem : 4;
            uint16_t fRandom : 3;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
} AIPART;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(AIPART) == 2, "sizeof(AIPART)");
#endif

/* typind 4431 (0x114f) size=16 */
typedef struct _hb
{
    uint16_t cbFree;      /* +0x0000 */
    uint16_t cbBlock;     /* +0x0002 */
    uint16_t cbSlop;      /* +0x0004 */
    uint16_t ibTop;       /* +0x0006 */
    struct _hb *lphbNext; /* +0x0008 */
    uint16_t hmem;        /* +0x000c */
    uint8_t ht;           /* +0x000e */
    uint8_t unused1;      /* +0x000f */
} HB;

/* typind 4440 (0x1158) size=2 */
typedef struct _dv
{
    union
    {
        uint16_t dp;
        struct
        {
            uint16_t pctSh : 7;
            uint16_t pctDp : 9;
        };
    }; /* +0x0000 */
} DV;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(DV) == 2, "sizeof(DV)");
_Static_assert(offsetof(DV, dp) == 0x0, "offsetof(DV,dp)");
#endif

/* typind 4464 (0x1170) size=8 */
typedef struct _diskfree_t
{
    uint16_t total_clusters;      /* +0x0000 */
    uint16_t avail_clusters;      /* +0x0002 */
    uint16_t sectors_per_cluster; /* +0x0004 */
    uint16_t bytes_per_sector;    /* +0x0006 */
} DISKFREE_T;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(DISKFREE_T) == 8, "sizeof(DISKFREE_T)");
_Static_assert(offsetof(DISKFREE_T, total_clusters) == 0x0, "offsetof(DISKFREE_T,total_clusters)");
_Static_assert(offsetof(DISKFREE_T, avail_clusters) == 0x2, "offsetof(DISKFREE_T,avail_clusters)");
_Static_assert(offsetof(DISKFREE_T, sectors_per_cluster) == 0x4, "offsetof(DISKFREE_T,sectors_per_cluster)");
_Static_assert(offsetof(DISKFREE_T, bytes_per_sector) == 0x6, "offsetof(DISKFREE_T,bytes_per_sector)");
#endif

#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TEXTMETRIC) == 31, "sizeof(TEXTMETRIC)");
_Static_assert(offsetof(TEXTMETRIC, tmHeight) == 0x0, "offsetof(TEXTMETRIC,tmHeight)");
_Static_assert(offsetof(TEXTMETRIC, tmAscent) == 0x2, "offsetof(TEXTMETRIC,tmAscent)");
_Static_assert(offsetof(TEXTMETRIC, tmDescent) == 0x4, "offsetof(TEXTMETRIC,tmDescent)");
_Static_assert(offsetof(TEXTMETRIC, tmInternalLeading) == 0x6, "offsetof(TEXTMETRIC,tmInternalLeading)");
_Static_assert(offsetof(TEXTMETRIC, tmExternalLeading) == 0x8, "offsetof(TEXTMETRIC,tmExternalLeading)");
_Static_assert(offsetof(TEXTMETRIC, tmAveCharWidth) == 0xa, "offsetof(TEXTMETRIC,tmAveCharWidth)");
_Static_assert(offsetof(TEXTMETRIC, tmMaxCharWidth) == 0xc, "offsetof(TEXTMETRIC,tmMaxCharWidth)");
_Static_assert(offsetof(TEXTMETRIC, tmWeight) == 0xe, "offsetof(TEXTMETRIC,tmWeight)");
_Static_assert(offsetof(TEXTMETRIC, tmItalic) == 0x10, "offsetof(TEXTMETRIC,tmItalic)");
_Static_assert(offsetof(TEXTMETRIC, tmUnderlined) == 0x11, "offsetof(TEXTMETRIC,tmUnderlined)");
_Static_assert(offsetof(TEXTMETRIC, tmStruckOut) == 0x12, "offsetof(TEXTMETRIC,tmStruckOut)");
_Static_assert(offsetof(TEXTMETRIC, tmFirstChar) == 0x13, "offsetof(TEXTMETRIC,tmFirstChar)");
_Static_assert(offsetof(TEXTMETRIC, tmLastChar) == 0x14, "offsetof(TEXTMETRIC,tmLastChar)");
_Static_assert(offsetof(TEXTMETRIC, tmDefaultChar) == 0x15, "offsetof(TEXTMETRIC,tmDefaultChar)");
_Static_assert(offsetof(TEXTMETRIC, tmBreakChar) == 0x16, "offsetof(TEXTMETRIC,tmBreakChar)");
_Static_assert(offsetof(TEXTMETRIC, tmPitchAndFamily) == 0x17, "offsetof(TEXTMETRIC,tmPitchAndFamily)");
_Static_assert(offsetof(TEXTMETRIC, tmCharSet) == 0x18, "offsetof(TEXTMETRIC,tmCharSet)");
_Static_assert(offsetof(TEXTMETRIC, tmOverhang) == 0x19, "offsetof(TEXTMETRIC,tmOverhang)");
_Static_assert(offsetof(TEXTMETRIC, tmDigitizedAspectX) == 0x1b, "offsetof(TEXTMETRIC,tmDigitizedAspectX)");
_Static_assert(offsetof(TEXTMETRIC, tmDigitizedAspectY) == 0x1d, "offsetof(TEXTMETRIC,tmDigitizedAspectY)");
#endif

/* typind 4636 (0x121c) size=78 */
typedef struct _engine
{
    int16_t id;              /* +0x0000 */
    int8_t rgTech[6];        /* +0x0002 */
    char szName[32];         /* +0x0008 */
    int16_t cMass;           /* +0x0028 */
    uint16_t resCost;        /* +0x002a */
    int16_t rgwtOreCost[3];  /* +0x002c */
    int16_t ibmp;            /* +0x0032 */
    int16_t grfAbilities;    /* +0x0034 */
    int16_t rgcFuelUsed[12]; /* +0x0036 */
} ENGINE;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(ENGINE) == 78, "sizeof(ENGINE)");
_Static_assert(offsetof(ENGINE, id) == 0x0, "offsetof(ENGINE,id)");
_Static_assert(offsetof(ENGINE, rgTech) == 0x2, "offsetof(ENGINE,rgTech)");
_Static_assert(offsetof(ENGINE, szName) == 0x8, "offsetof(ENGINE,szName)");
_Static_assert(offsetof(ENGINE, cMass) == 0x28, "offsetof(ENGINE,cMass)");
_Static_assert(offsetof(ENGINE, resCost) == 0x2a, "offsetof(ENGINE,resCost)");
_Static_assert(offsetof(ENGINE, rgwtOreCost) == 0x2c, "offsetof(ENGINE,rgwtOreCost)");
_Static_assert(offsetof(ENGINE, ibmp) == 0x32, "offsetof(ENGINE,ibmp)");
_Static_assert(offsetof(ENGINE, grfAbilities) == 0x34, "offsetof(ENGINE,grfAbilities)");
_Static_assert(offsetof(ENGINE, rgcFuelUsed) == 0x36, "offsetof(ENGINE,rgcFuelUsed)");
#endif

/* typind 4700 (0x125c) size=4 */
typedef struct _pl
{
    union
    {
        struct
        {
            uint16_t cbItem : 8;
            uint16_t fMark : 1;
            uint16_t ht : 3;
            uint16_t cAlloc : 4;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    uint8_t iMax;   /* +0x0002 */
    uint8_t iMac;   /* +0x0003 */
    uint8_t rgb[0]; /* +0x0004 */
} PL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PL) == 4, "sizeof(PL)");
_Static_assert(offsetof(PL, iMax) == 0x2, "offsetof(PL,iMax)");
_Static_assert(offsetof(PL, iMac) == 0x3, "offsetof(PL,iMac)");
_Static_assert(offsetof(PL, rgb) == 0x4, "offsetof(PL,rgb)");
#endif

/* typind 4749 (0x128d) size=56 */
typedef struct _scanner
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t dRange;         /* +0x0034 */
    int16_t grfAbilities;   /* +0x0036 */
} SCANNER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SCANNER) == 56, "sizeof(SCANNER)");
_Static_assert(offsetof(SCANNER, id) == 0x0, "offsetof(SCANNER,id)");
_Static_assert(offsetof(SCANNER, rgTech) == 0x2, "offsetof(SCANNER,rgTech)");
_Static_assert(offsetof(SCANNER, szName) == 0x8, "offsetof(SCANNER,szName)");
_Static_assert(offsetof(SCANNER, cMass) == 0x28, "offsetof(SCANNER,cMass)");
_Static_assert(offsetof(SCANNER, resCost) == 0x2a, "offsetof(SCANNER,resCost)");
_Static_assert(offsetof(SCANNER, rgwtOreCost) == 0x2c, "offsetof(SCANNER,rgwtOreCost)");
_Static_assert(offsetof(SCANNER, ibmp) == 0x32, "offsetof(SCANNER,ibmp)");
_Static_assert(offsetof(SCANNER, dRange) == 0x34, "offsetof(SCANNER,dRange)");
_Static_assert(offsetof(SCANNER, grfAbilities) == 0x36, "offsetof(SCANNER,grfAbilities)");
#endif

/* typind 4753 (0x1291) size=54 */
typedef struct _planetary
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t grAbility;      /* +0x0034 */
} PLANETARY;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PLANETARY) == 54, "sizeof(PLANETARY)");
_Static_assert(offsetof(PLANETARY, id) == 0x0, "offsetof(PLANETARY,id)");
_Static_assert(offsetof(PLANETARY, rgTech) == 0x2, "offsetof(PLANETARY,rgTech)");
_Static_assert(offsetof(PLANETARY, szName) == 0x8, "offsetof(PLANETARY,szName)");
_Static_assert(offsetof(PLANETARY, cMass) == 0x28, "offsetof(PLANETARY,cMass)");
_Static_assert(offsetof(PLANETARY, resCost) == 0x2a, "offsetof(PLANETARY,resCost)");
_Static_assert(offsetof(PLANETARY, rgwtOreCost) == 0x2c, "offsetof(PLANETARY,rgwtOreCost)");
_Static_assert(offsetof(PLANETARY, ibmp) == 0x32, "offsetof(PLANETARY,ibmp)");
_Static_assert(offsetof(PLANETARY, grAbility) == 0x34, "offsetof(PLANETARY,grAbility)");
#endif

/* typind 4761 (0x1299) size=54 */
typedef struct _armor
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t dp;             /* +0x0034 */
} ARMOR;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(ARMOR) == 54, "sizeof(ARMOR)");
_Static_assert(offsetof(ARMOR, id) == 0x0, "offsetof(ARMOR,id)");
_Static_assert(offsetof(ARMOR, rgTech) == 0x2, "offsetof(ARMOR,rgTech)");
_Static_assert(offsetof(ARMOR, szName) == 0x8, "offsetof(ARMOR,szName)");
_Static_assert(offsetof(ARMOR, cMass) == 0x28, "offsetof(ARMOR,cMass)");
_Static_assert(offsetof(ARMOR, resCost) == 0x2a, "offsetof(ARMOR,resCost)");
_Static_assert(offsetof(ARMOR, rgwtOreCost) == 0x2c, "offsetof(ARMOR,rgwtOreCost)");
_Static_assert(offsetof(ARMOR, ibmp) == 0x32, "offsetof(ARMOR,ibmp)");
_Static_assert(offsetof(ARMOR, dp) == 0x34, "offsetof(ARMOR,dp)");
#endif

/* typind 4764 (0x129c) size=54 */
typedef struct _shield
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t dp;             /* +0x0034 */
} SHIELD;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SHIELD) == 54, "sizeof(SHIELD)");
_Static_assert(offsetof(SHIELD, id) == 0x0, "offsetof(SHIELD,id)");
_Static_assert(offsetof(SHIELD, rgTech) == 0x2, "offsetof(SHIELD,rgTech)");
_Static_assert(offsetof(SHIELD, szName) == 0x8, "offsetof(SHIELD,szName)");
_Static_assert(offsetof(SHIELD, cMass) == 0x28, "offsetof(SHIELD,cMass)");
_Static_assert(offsetof(SHIELD, resCost) == 0x2a, "offsetof(SHIELD,resCost)");
_Static_assert(offsetof(SHIELD, rgwtOreCost) == 0x2c, "offsetof(SHIELD,rgwtOreCost)");
_Static_assert(offsetof(SHIELD, ibmp) == 0x32, "offsetof(SHIELD,ibmp)");
_Static_assert(offsetof(SHIELD, dp) == 0x34, "offsetof(SHIELD,dp)");
#endif

/* typind 4766 (0x129e) size=54 */
typedef struct _special
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t grAbility;      /* +0x0034 */
} SPECIAL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SPECIAL) == 54, "sizeof(SPECIAL)");
_Static_assert(offsetof(SPECIAL, id) == 0x0, "offsetof(SPECIAL,id)");
_Static_assert(offsetof(SPECIAL, rgTech) == 0x2, "offsetof(SPECIAL,rgTech)");
_Static_assert(offsetof(SPECIAL, szName) == 0x8, "offsetof(SPECIAL,szName)");
_Static_assert(offsetof(SPECIAL, cMass) == 0x28, "offsetof(SPECIAL,cMass)");
_Static_assert(offsetof(SPECIAL, resCost) == 0x2a, "offsetof(SPECIAL,resCost)");
_Static_assert(offsetof(SPECIAL, rgwtOreCost) == 0x2c, "offsetof(SPECIAL,rgwtOreCost)");
_Static_assert(offsetof(SPECIAL, ibmp) == 0x32, "offsetof(SPECIAL,ibmp)");
_Static_assert(offsetof(SPECIAL, grAbility) == 0x34, "offsetof(SPECIAL,grAbility)");
#endif

/* typind 4769 (0x12a1) size=54 */
typedef struct _mines
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t grAbility;      /* +0x0034 */
} MINES;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(MINES) == 54, "sizeof(MINES)");
_Static_assert(offsetof(MINES, id) == 0x0, "offsetof(MINES,id)");
_Static_assert(offsetof(MINES, rgTech) == 0x2, "offsetof(MINES,rgTech)");
_Static_assert(offsetof(MINES, szName) == 0x8, "offsetof(MINES,szName)");
_Static_assert(offsetof(MINES, cMass) == 0x28, "offsetof(MINES,cMass)");
_Static_assert(offsetof(MINES, resCost) == 0x2a, "offsetof(MINES,resCost)");
_Static_assert(offsetof(MINES, rgwtOreCost) == 0x2c, "offsetof(MINES,rgwtOreCost)");
_Static_assert(offsetof(MINES, ibmp) == 0x32, "offsetof(MINES,ibmp)");
_Static_assert(offsetof(MINES, grAbility) == 0x34, "offsetof(MINES,grAbility)");
#endif

/* typind 4771 (0x12a3) size=54 */
typedef struct _mining
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t grAbility;      /* +0x0034 */
} MINING;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(MINING) == 54, "sizeof(MINING)");
_Static_assert(offsetof(MINING, id) == 0x0, "offsetof(MINING,id)");
_Static_assert(offsetof(MINING, rgTech) == 0x2, "offsetof(MINING,rgTech)");
_Static_assert(offsetof(MINING, szName) == 0x8, "offsetof(MINING,szName)");
_Static_assert(offsetof(MINING, cMass) == 0x28, "offsetof(MINING,cMass)");
_Static_assert(offsetof(MINING, resCost) == 0x2a, "offsetof(MINING,resCost)");
_Static_assert(offsetof(MINING, rgwtOreCost) == 0x2c, "offsetof(MINING,rgwtOreCost)");
_Static_assert(offsetof(MINING, ibmp) == 0x32, "offsetof(MINING,ibmp)");
_Static_assert(offsetof(MINING, grAbility) == 0x34, "offsetof(MINING,grAbility)");
#endif

/* typind 4774 (0x12a6) size=54 */
typedef struct _terra
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t grAbility;      /* +0x0034 */
} TERRA;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TERRA) == 54, "sizeof(TERRA)");
_Static_assert(offsetof(TERRA, id) == 0x0, "offsetof(TERRA,id)");
_Static_assert(offsetof(TERRA, rgTech) == 0x2, "offsetof(TERRA,rgTech)");
_Static_assert(offsetof(TERRA, szName) == 0x8, "offsetof(TERRA,szName)");
_Static_assert(offsetof(TERRA, cMass) == 0x28, "offsetof(TERRA,cMass)");
_Static_assert(offsetof(TERRA, resCost) == 0x2a, "offsetof(TERRA,resCost)");
_Static_assert(offsetof(TERRA, rgwtOreCost) == 0x2c, "offsetof(TERRA,rgwtOreCost)");
_Static_assert(offsetof(TERRA, ibmp) == 0x32, "offsetof(TERRA,ibmp)");
_Static_assert(offsetof(TERRA, grAbility) == 0x34, "offsetof(TERRA,grAbility)");
#endif

/* typind 4776 (0x12a8) size=58 */
typedef struct _bomb
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t cRounds;        /* +0x0034 */
    int16_t dDmgCol;        /* +0x0036 */
    int16_t dDmgBldg;       /* +0x0038 */
} BOMB;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(BOMB) == 58, "sizeof(BOMB)");
_Static_assert(offsetof(BOMB, id) == 0x0, "offsetof(BOMB,id)");
_Static_assert(offsetof(BOMB, rgTech) == 0x2, "offsetof(BOMB,rgTech)");
_Static_assert(offsetof(BOMB, szName) == 0x8, "offsetof(BOMB,szName)");
_Static_assert(offsetof(BOMB, cMass) == 0x28, "offsetof(BOMB,cMass)");
_Static_assert(offsetof(BOMB, resCost) == 0x2a, "offsetof(BOMB,resCost)");
_Static_assert(offsetof(BOMB, rgwtOreCost) == 0x2c, "offsetof(BOMB,rgwtOreCost)");
_Static_assert(offsetof(BOMB, ibmp) == 0x32, "offsetof(BOMB,ibmp)");
_Static_assert(offsetof(BOMB, cRounds) == 0x34, "offsetof(BOMB,cRounds)");
_Static_assert(offsetof(BOMB, dDmgCol) == 0x36, "offsetof(BOMB,dDmgCol)");
_Static_assert(offsetof(BOMB, dDmgBldg) == 0x38, "offsetof(BOMB,dDmgBldg)");
#endif

/* typind 4778 (0x12aa) size=60 */
typedef struct _torp
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t dRangeMax;      /* +0x0034 */
    int16_t dp;             /* +0x0036 */
    int16_t init;           /* +0x0038 */
    int16_t dHitChance;     /* +0x003a */
} TORP;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TORP) == 60, "sizeof(TORP)");
_Static_assert(offsetof(TORP, id) == 0x0, "offsetof(TORP,id)");
_Static_assert(offsetof(TORP, rgTech) == 0x2, "offsetof(TORP,rgTech)");
_Static_assert(offsetof(TORP, szName) == 0x8, "offsetof(TORP,szName)");
_Static_assert(offsetof(TORP, cMass) == 0x28, "offsetof(TORP,cMass)");
_Static_assert(offsetof(TORP, resCost) == 0x2a, "offsetof(TORP,resCost)");
_Static_assert(offsetof(TORP, rgwtOreCost) == 0x2c, "offsetof(TORP,rgwtOreCost)");
_Static_assert(offsetof(TORP, ibmp) == 0x32, "offsetof(TORP,ibmp)");
_Static_assert(offsetof(TORP, dRangeMax) == 0x34, "offsetof(TORP,dRangeMax)");
_Static_assert(offsetof(TORP, dp) == 0x36, "offsetof(TORP,dp)");
_Static_assert(offsetof(TORP, init) == 0x38, "offsetof(TORP,init)");
_Static_assert(offsetof(TORP, dHitChance) == 0x3a, "offsetof(TORP,dHitChance)");
#endif

/* typind 4780 (0x12ac) size=60 */
typedef struct _beam
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t dRangeMax;      /* +0x0034 */
    int16_t dp;             /* +0x0036 */
    int16_t init;           /* +0x0038 */
    int16_t grfAbilities;   /* +0x003a */
} BEAM;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(BEAM) == 60, "sizeof(BEAM)");
_Static_assert(offsetof(BEAM, id) == 0x0, "offsetof(BEAM,id)");
_Static_assert(offsetof(BEAM, rgTech) == 0x2, "offsetof(BEAM,rgTech)");
_Static_assert(offsetof(BEAM, szName) == 0x8, "offsetof(BEAM,szName)");
_Static_assert(offsetof(BEAM, cMass) == 0x28, "offsetof(BEAM,cMass)");
_Static_assert(offsetof(BEAM, resCost) == 0x2a, "offsetof(BEAM,resCost)");
_Static_assert(offsetof(BEAM, rgwtOreCost) == 0x2c, "offsetof(BEAM,rgwtOreCost)");
_Static_assert(offsetof(BEAM, ibmp) == 0x32, "offsetof(BEAM,ibmp)");
_Static_assert(offsetof(BEAM, dRangeMax) == 0x34, "offsetof(BEAM,dRangeMax)");
_Static_assert(offsetof(BEAM, dp) == 0x36, "offsetof(BEAM,dp)");
_Static_assert(offsetof(BEAM, init) == 0x38, "offsetof(BEAM,init)");
_Static_assert(offsetof(BEAM, grfAbilities) == 0x3a, "offsetof(BEAM,grfAbilities)");
#endif

/* typind 4786 (0x12b2) size=56 */
typedef struct _specialsb
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
    int16_t grAbility;      /* +0x0034 */
    int16_t grAbility2;     /* +0x0036 */
} SPECIALSB;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SPECIALSB) == 56, "sizeof(SPECIALSB)");
_Static_assert(offsetof(SPECIALSB, id) == 0x0, "offsetof(SPECIALSB,id)");
_Static_assert(offsetof(SPECIALSB, rgTech) == 0x2, "offsetof(SPECIALSB,rgTech)");
_Static_assert(offsetof(SPECIALSB, szName) == 0x8, "offsetof(SPECIALSB,szName)");
_Static_assert(offsetof(SPECIALSB, cMass) == 0x28, "offsetof(SPECIALSB,cMass)");
_Static_assert(offsetof(SPECIALSB, resCost) == 0x2a, "offsetof(SPECIALSB,resCost)");
_Static_assert(offsetof(SPECIALSB, rgwtOreCost) == 0x2c, "offsetof(SPECIALSB,rgwtOreCost)");
_Static_assert(offsetof(SPECIALSB, ibmp) == 0x32, "offsetof(SPECIALSB,ibmp)");
_Static_assert(offsetof(SPECIALSB, grAbility) == 0x34, "offsetof(SPECIALSB,grAbility)");
_Static_assert(offsetof(SPECIALSB, grAbility2) == 0x36, "offsetof(SPECIALSB,grAbility2)");
#endif

/* typind 4820 (0x12d4) size=12 */
typedef struct _msgplr
{
    struct _msgplr *lpmsgplrNext; /* +0x0000 */
    int16_t iPlrFrom;             /* +0x0004 */
    int16_t iPlrTo;               /* +0x0006 */
    int16_t iInRe;                /* +0x0008 */
    int16_t cLen;                 /* +0x000a */
    uint8_t rgbMsg[0];            /* +0x000c */
} MSGPLR;

/* typind 4822 (0x12d6) size=18 */
typedef struct _msgbig
{
    int16_t iMsg;       /* +0x0000 */
    int16_t wGoto;      /* +0x0002 */
    int16_t rgParam[7]; /* +0x0004 */
} MSGBIG;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(MSGBIG) == 18, "sizeof(MSGBIG)");
_Static_assert(offsetof(MSGBIG, iMsg) == 0x0, "offsetof(MSGBIG,iMsg)");
_Static_assert(offsetof(MSGBIG, wGoto) == 0x2, "offsetof(MSGBIG,wGoto)");
_Static_assert(offsetof(MSGBIG, rgParam) == 0x4, "offsetof(MSGBIG,rgParam)");
#endif

/* typind 4832 (0x12e0) size=4 */
typedef struct _msghdr
{
    union
    {
        struct
        {
            uint16_t iMsg : 9;
            uint16_t grWord : 7;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    int16_t wGoto; /* +0x0002 */
} MSGHDR;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(MSGHDR) == 4, "sizeof(MSGHDR)");
_Static_assert(offsetof(MSGHDR, wGoto) == 0x2, "offsetof(MSGHDR,wGoto)");
#endif

/* typind 4844 (0x12ec) size=2 */
typedef struct _hdr
{
    union
    {
        struct
        {
            uint16_t cb : 10;
            uint16_t rt : 6;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
} HDR;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(HDR) == 2, "sizeof(HDR)");
#endif

/* typind 4854 (0x12f6) size=4 */
typedef struct _starpack
{
    union
    {
        struct
        {
            uint32_t dx : 10;
            uint32_t y : 12;
            uint32_t id : 10;
        };
        uint32_t dwRaw_0000;
    }; /* +0x0000 */
} STARPACK;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(STARPACK) == 4, "sizeof(STARPACK)");
#endif

/* typind 4899 (0x1323) size=16 */
typedef struct _rtbof
{
    char rgid[4];    /* +0x0000 */
    int32_t lidGame; /* +0x0004 */
    union
    {
        uint16_t wVersion;
        struct
        {
            uint16_t verInc : 5;
            uint16_t verMinor : 7;
            uint16_t verMajor : 4;
        };
    }; /* +0x0008 */
    uint16_t turn; /* +0x000a */
    union
    {
        struct
        {
            int16_t iPlayer : 5;
            int16_t lSaltTime : 11;
        };
        int16_t wRaw_000c;
    }; /* +0x000c */
    union
    {
        struct
        {
            uint16_t dt : 8;
            uint16_t fDone : 1;
            uint16_t fInUse : 1;
            uint16_t fMulti : 1;
            uint16_t fGameOverMan : 1;
            uint16_t fCrippled : 1;
            uint16_t wGen : 3;
        };
        uint16_t wRaw_000e;
    }; /* +0x000e */
} RTBOF;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTBOF) == 16, "sizeof(RTBOF)");
_Static_assert(offsetof(RTBOF, rgid) == 0x0, "offsetof(RTBOF,rgid)");
_Static_assert(offsetof(RTBOF, lidGame) == 0x4, "offsetof(RTBOF,lidGame)");
_Static_assert(offsetof(RTBOF, wVersion) == 0x8, "offsetof(RTBOF,wVersion)");
_Static_assert(offsetof(RTBOF, turn) == 0xa, "offsetof(RTBOF,turn)");
#endif

/* typind 4912 (0x1330) size=25 */
typedef struct _xferfull
{
    uint16_t id1; /* +0x0000 */
    uint16_t id2; /* +0x0002 */
    union
    {
        struct
        {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
        uint8_t wRaw_0004;
    }; /* +0x0004 */
    int32_t rgcQuan[5]; /* +0x0005 */
} XFERFULL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(XFERFULL) == 25, "sizeof(XFERFULL)");
_Static_assert(offsetof(XFERFULL, id1) == 0x0, "offsetof(XFERFULL,id1)");
_Static_assert(offsetof(XFERFULL, id2) == 0x2, "offsetof(XFERFULL,id2)");
_Static_assert(offsetof(XFERFULL, rgcQuan) == 0x5, "offsetof(XFERFULL,rgcQuan)");
#endif

/* typind 4914 (0x1332) size=12 */
typedef struct _coldrop
{
    int16_t idFleetSrc;  /* +0x0000 */
    int16_t idPlr;       /* +0x0002 */
    int16_t idPlanetDst; /* +0x0004 */
    union
    {
        struct
        {
            uint16_t fCanColonize : 1;
            uint16_t unused : 15;
        };
        uint16_t wRaw_0006;
    }; /* +0x0006 */
    int32_t cColonist; /* +0x0008 */
} COLDROP;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(COLDROP) == 12, "sizeof(COLDROP)");
_Static_assert(offsetof(COLDROP, idFleetSrc) == 0x0, "offsetof(COLDROP,idFleetSrc)");
_Static_assert(offsetof(COLDROP, idPlr) == 0x2, "offsetof(COLDROP,idPlr)");
_Static_assert(offsetof(COLDROP, idPlanetDst) == 0x4, "offsetof(COLDROP,idPlanetDst)");
_Static_assert(offsetof(COLDROP, cColonist) == 0x8, "offsetof(COLDROP,cColonist)");
#endif

/* typind 4918 (0x1336) size=20 */
typedef struct _score
{
    int32_t lScore;      /* +0x0000 */
    int32_t cResources;  /* +0x0004 */
    int16_t cPlanet;     /* +0x0008 */
    int16_t cStarbase;   /* +0x000a */
    uint16_t rgcsh[3];   /* +0x000c */
    int16_t cTechLevels; /* +0x0012 */
} SCORE;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SCORE) == 20, "sizeof(SCORE)");
_Static_assert(offsetof(SCORE, lScore) == 0x0, "offsetof(SCORE,lScore)");
_Static_assert(offsetof(SCORE, cResources) == 0x4, "offsetof(SCORE,cResources)");
_Static_assert(offsetof(SCORE, cPlanet) == 0x8, "offsetof(SCORE,cPlanet)");
_Static_assert(offsetof(SCORE, cStarbase) == 0xa, "offsetof(SCORE,cStarbase)");
_Static_assert(offsetof(SCORE, rgcsh) == 0xc, "offsetof(SCORE,rgcsh)");
_Static_assert(offsetof(SCORE, cTechLevels) == 0x12, "offsetof(SCORE,cTechLevels)");
#endif

/* typind 4927 (0x133f) size=16 */
typedef struct _turnserial
{
    int32_t lSerialNumber; /* +0x0000 */
    uint8_t rgbConfig[11]; /* +0x0004 */
    uint8_t bPad;          /* +0x000f */
} TURNSERIAL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TURNSERIAL) == 16, "sizeof(TURNSERIAL)");
_Static_assert(offsetof(TURNSERIAL, lSerialNumber) == 0x0, "offsetof(TURNSERIAL,lSerialNumber)");
_Static_assert(offsetof(TURNSERIAL, rgbConfig) == 0x4, "offsetof(TURNSERIAL,rgbConfig)");
_Static_assert(offsetof(TURNSERIAL, bPad) == 0xf, "offsetof(TURNSERIAL,bPad)");
#endif

/* typind 4930 (0x1342) size=4 */
typedef struct _rthisthdr
{
    int16_t cPlanet;      /* +0x0000 */
    int16_t cPlanetExtra; /* +0x0002 */
} RTHISTHDR;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTHISTHDR) == 4, "sizeof(RTHISTHDR)");
_Static_assert(offsetof(RTHISTHDR, cPlanet) == 0x0, "offsetof(RTHISTHDR,cPlanet)");
_Static_assert(offsetof(RTHISTHDR, cPlanetExtra) == 0x2, "offsetof(RTHISTHDR,cPlanetExtra)");
#endif

/* typind 4937 (0x1349) size=2 */
typedef struct _prodq1
{
    union
    {
        uint16_t w;
        struct
        {
            uint16_t mdIdle : 6;
            uint16_t cQuan : 10;
        };
    }; /* +0x0000 */
} PRODQ1;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PRODQ1) == 2, "sizeof(PRODQ1)");
_Static_assert(offsetof(PRODQ1, w) == 0x0, "offsetof(PRODQ1,w)");
#endif

/* typind 4942 (0x134e) size=4 */
typedef struct _rtlogthing
{
    uint16_t idFull;   /* +0x0000 */
    int16_t fDetonate; /* +0x0002 */
} RTLOGTHING;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTLOGTHING) == 4, "sizeof(RTLOGTHING)");
_Static_assert(offsetof(RTLOGTHING, idFull) == 0x0, "offsetof(RTLOGTHING,idFull)");
_Static_assert(offsetof(RTLOGTHING, fDetonate) == 0x2, "offsetof(RTLOGTHING,fDetonate)");
#endif

/* typind 4955 (0x135b) size=6 */
typedef struct _rtChgPlanetLong
{
    int16_t id; /* +0x0000 */
    union
    {
        uint32_t ul;
        struct
        {
            uint32_t fNoResearch : 1;
            uint32_t idFling : 10;
            uint32_t iWarpFling : 4;
            uint32_t idRoute : 10;
            uint32_t unused : 7;
        };
    }; /* +0x0002 */
} RTCHGPLANETLONG;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTCHGPLANETLONG) == 6, "sizeof(RTCHGPLANETLONG)");
_Static_assert(offsetof(RTCHGPLANETLONG, id) == 0x0, "offsetof(RTCHGPLANETLONG,id)");
_Static_assert(offsetof(RTCHGPLANETLONG, ul) == 0x2, "offsetof(RTCHGPLANETLONG,ul)");
#endif

/* typind 4966 (0x1366) size=23 */
typedef struct _planetsome
{
    int16_t id;      /* +0x0000 */
    int16_t iPlayer; /* +0x0002 */
    union
    {
        struct
        {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fStarbase : 1;
            uint16_t unusedA : 1;
            uint16_t fFirstYear : 1;
            uint16_t unusedB : 4;
        };
        uint16_t wRaw_0004;
    }; /* +0x0004 */
    uint16_t rgpctMinLevel[3]; /* +0x0006 */
    char rgMinConc[3];         /* +0x000c */
    uint8_t rgEnvVar[3];       /* +0x000f */
    uint8_t rgEnvVarOrig[3];   /* +0x0012 */
    union
    {
        uint16_t uGuesses;
        struct
        {
            uint16_t uPopGuess : 12;
            uint16_t uDefGuess : 4;
        };
    }; /* +0x0015 */
} PLANETSOME;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PLANETSOME) == 23, "sizeof(PLANETSOME)");
_Static_assert(offsetof(PLANETSOME, id) == 0x0, "offsetof(PLANETSOME,id)");
_Static_assert(offsetof(PLANETSOME, iPlayer) == 0x2, "offsetof(PLANETSOME,iPlayer)");
_Static_assert(offsetof(PLANETSOME, rgpctMinLevel) == 0x6, "offsetof(PLANETSOME,rgpctMinLevel)");
_Static_assert(offsetof(PLANETSOME, rgMinConc) == 0xc, "offsetof(PLANETSOME,rgMinConc)");
_Static_assert(offsetof(PLANETSOME, rgEnvVar) == 0xf, "offsetof(PLANETSOME,rgEnvVar)");
_Static_assert(offsetof(PLANETSOME, rgEnvVarOrig) == 0x12, "offsetof(PLANETSOME,rgEnvVarOrig)");
_Static_assert(offsetof(PLANETSOME, uGuesses) == 0x15, "offsetof(PLANETSOME,uGuesses)");
#endif

/* typind 4975 (0x136f) size=34 */
typedef struct _exceptionl
{
    int16_t type;       /* +0x0000 */
    char *name;         /* +0x0002 */
    long double arg1;   /* +0x0004 */
    long double arg2;   /* +0x000e */
    long double retval; /* +0x0018 */
} EXCEPTIONL;

/* typind 5100 (0x13ec) size=24 */
typedef struct _logxfer
{
    int16_t id;         /* +0x0000 */
    int16_t grobj;      /* +0x0002 */
    int32_t rgdItem[5]; /* +0x0004 */
} LOGXFER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(LOGXFER) == 24, "sizeof(LOGXFER)");
_Static_assert(offsetof(LOGXFER, id) == 0x0, "offsetof(LOGXFER,id)");
_Static_assert(offsetof(LOGXFER, grobj) == 0x2, "offsetof(LOGXFER,grobj)");
_Static_assert(offsetof(LOGXFER, rgdItem) == 0x4, "offsetof(LOGXFER,rgdItem)");
#endif

/* typind 5115 (0x13fb) size=36 */
typedef struct _logxferf
{
    int16_t id;          /* +0x0000 */
    int16_t grobj;       /* +0x0002 */
    int16_t rgdItem[16]; /* +0x0004 */
} LOGXFERF;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(LOGXFERF) == 36, "sizeof(LOGXFERF)");
_Static_assert(offsetof(LOGXFERF, id) == 0x0, "offsetof(LOGXFERF,id)");
_Static_assert(offsetof(LOGXFERF, grobj) == 0x2, "offsetof(LOGXFERF,grobj)");
_Static_assert(offsetof(LOGXFERF, rgdItem) == 0x4, "offsetof(LOGXFERF,rgdItem)");
#endif

/* typind 5132 (0x140c) size=7 */
typedef struct _rtxfer
{
    uint16_t id1; /* +0x0000 */
    uint16_t id2; /* +0x0002 */
    union
    {
        struct
        {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
        uint8_t wRaw_0004;
    }; /* +0x0004 */
    uint8_t grbitItems; /* +0x0005 */
    char rgcQuan[1];    /* +0x0006 */
} RTXFER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTXFER) == 7, "sizeof(RTXFER)");
_Static_assert(offsetof(RTXFER, id1) == 0x0, "offsetof(RTXFER,id1)");
_Static_assert(offsetof(RTXFER, id2) == 0x2, "offsetof(RTXFER,id2)");
_Static_assert(offsetof(RTXFER, grbitItems) == 0x5, "offsetof(RTXFER,grbitItems)");
_Static_assert(offsetof(RTXFER, rgcQuan) == 0x6, "offsetof(RTXFER,rgcQuan)");
#endif

/* typind 5141 (0x1415) size=52 */
typedef struct _compart
{
    int16_t id;             /* +0x0000 */
    int8_t rgTech[6];       /* +0x0002 */
    char szName[32];        /* +0x0008 */
    int16_t cMass;          /* +0x0028 */
    uint16_t resCost;       /* +0x002a */
    int16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;           /* +0x0032 */
} COMPART;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(COMPART) == 52, "sizeof(COMPART)");
_Static_assert(offsetof(COMPART, id) == 0x0, "offsetof(COMPART,id)");
_Static_assert(offsetof(COMPART, rgTech) == 0x2, "offsetof(COMPART,rgTech)");
_Static_assert(offsetof(COMPART, szName) == 0x8, "offsetof(COMPART,szName)");
_Static_assert(offsetof(COMPART, cMass) == 0x28, "offsetof(COMPART,cMass)");
_Static_assert(offsetof(COMPART, resCost) == 0x2a, "offsetof(COMPART,resCost)");
_Static_assert(offsetof(COMPART, rgwtOreCost) == 0x2c, "offsetof(COMPART,rgwtOreCost)");
_Static_assert(offsetof(COMPART, ibmp) == 0x32, "offsetof(COMPART,ibmp)");
#endif

/* typind 5153 (0x1421) size=8 */
typedef struct _rtxferx
{
    uint16_t id1; /* +0x0000 */
    uint16_t id2; /* +0x0002 */
    union
    {
        struct
        {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
        uint8_t wRaw_0004;
    }; /* +0x0004 */
    uint8_t grbitItems; /* +0x0005 */
    int16_t rgcQuan[1]; /* +0x0006 */
} RTXFERX;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTXFERX) == 8, "sizeof(RTXFERX)");
_Static_assert(offsetof(RTXFERX, id1) == 0x0, "offsetof(RTXFERX,id1)");
_Static_assert(offsetof(RTXFERX, id2) == 0x2, "offsetof(RTXFERX,id2)");
_Static_assert(offsetof(RTXFERX, grbitItems) == 0x5, "offsetof(RTXFERX,grbitItems)");
_Static_assert(offsetof(RTXFERX, rgcQuan) == 0x6, "offsetof(RTXFERX,rgcQuan)");
#endif

/* typind 5161 (0x1429) size=10 */
typedef struct _thmine
{
    int32_t cMines;       /* +0x0000 */
    uint16_t grbitPlr;    /* +0x0004 */
    uint8_t iType;        /* +0x0006 */
    uint8_t fDetonate;    /* +0x0007 */
    uint16_t grbitPlrNow; /* +0x0008 */
} THMINE;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(THMINE) == 10, "sizeof(THMINE)");
_Static_assert(offsetof(THMINE, cMines) == 0x0, "offsetof(THMINE,cMines)");
_Static_assert(offsetof(THMINE, grbitPlr) == 0x4, "offsetof(THMINE,grbitPlr)");
_Static_assert(offsetof(THMINE, iType) == 0x6, "offsetof(THMINE,iType)");
_Static_assert(offsetof(THMINE, fDetonate) == 0x7, "offsetof(THMINE,fDetonate)");
_Static_assert(offsetof(THMINE, grbitPlrNow) == 0x8, "offsetof(THMINE,grbitPlrNow)");
#endif

/* typind 5169 (0x1431) size=10 */
typedef struct _rtxferl
{
    uint16_t id1; /* +0x0000 */
    uint16_t id2; /* +0x0002 */
    union
    {
        struct
        {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
        uint8_t wRaw_0004;
    }; /* +0x0004 */
    uint8_t grbitItems; /* +0x0005 */
    int32_t rgcQuan[1]; /* +0x0006 */
} RTXFERL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTXFERL) == 10, "sizeof(RTXFERL)");
_Static_assert(offsetof(RTXFERL, id1) == 0x0, "offsetof(RTXFERL,id1)");
_Static_assert(offsetof(RTXFERL, id2) == 0x2, "offsetof(RTXFERL,id2)");
_Static_assert(offsetof(RTXFERL, grbitItems) == 0x5, "offsetof(RTXFERL,grbitItems)");
_Static_assert(offsetof(RTXFERL, rgcQuan) == 0x6, "offsetof(RTXFERL,rgcQuan)");
#endif

/* typind 5174 (0x1436) size=9 */
typedef struct _rtxferf
{
    uint16_t id1; /* +0x0000 */
    uint16_t id2; /* +0x0002 */
    union
    {
        struct
        {
            uint8_t grobj1 : 4;
            uint8_t grobj2 : 4;
        };
        uint8_t wRaw_0004;
    }; /* +0x0004 */
    uint16_t grbitItems; /* +0x0005 */
    int16_t rgcQuan[1];  /* +0x0007 */
} RTXFERF;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTXFERF) == 9, "sizeof(RTXFERF)");
_Static_assert(offsetof(RTXFERF, id1) == 0x0, "offsetof(RTXFERF,id1)");
_Static_assert(offsetof(RTXFERF, id2) == 0x2, "offsetof(RTXFERF,id2)");
_Static_assert(offsetof(RTXFERF, grbitItems) == 0x5, "offsetof(RTXFERF,grbitItems)");
_Static_assert(offsetof(RTXFERF, rgcQuan) == 0x7, "offsetof(RTXFERF,rgcQuan)");
#endif

/* typind 5185 (0x1441) size=10 */
typedef struct _thpack
{
    union
    {
        struct
        {
            uint16_t idPlanet : 10;
            uint16_t iWarp : 4;
            uint16_t fMoved : 1;
            uint16_t fInclude : 1;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    int16_t rgwtMin[3]; /* +0x0002 */
    union
    {
        struct
        {
            uint16_t wtMax : 14;
            uint16_t iDecayRate : 2;
        };
        uint16_t wRaw_0008;
    }; /* +0x0008 */
} THPACK;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(THPACK) == 10, "sizeof(THPACK)");
_Static_assert(offsetof(THPACK, rgwtMin) == 0x2, "offsetof(THPACK,rgwtMin)");
#endif

/* typind 5187 (0x1443) size=4 */
typedef struct _rtshipint
{
    int16_t id; /* +0x0000 */
    int16_t i;  /* +0x0002 */
} RTSHIPINT;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTSHIPINT) == 4, "sizeof(RTSHIPINT)");
_Static_assert(offsetof(RTSHIPINT, id) == 0x0, "offsetof(RTSHIPINT,id)");
_Static_assert(offsetof(RTSHIPINT, i) == 0x2, "offsetof(RTSHIPINT,i)");
#endif

/* typind 5190 (0x1446) size=20 */
typedef struct _aistarbase
{
    int16_t idPlanet;   /* +0x0000 */
    int16_t cFreighter; /* +0x0002 */
    int16_t rgflid[8];  /* +0x0004 */
} AISTARBASE;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(AISTARBASE) == 20, "sizeof(AISTARBASE)");
_Static_assert(offsetof(AISTARBASE, idPlanet) == 0x0, "offsetof(AISTARBASE,idPlanet)");
_Static_assert(offsetof(AISTARBASE, cFreighter) == 0x2, "offsetof(AISTARBASE,cFreighter)");
_Static_assert(offsetof(AISTARBASE, rgflid) == 0x4, "offsetof(AISTARBASE,rgflid)");
#endif

/* typind 5201 (0x1451) size=6 */
typedef struct _rtshipint2
{
    int16_t id; /* +0x0000 */
    int16_t i;  /* +0x0002 */
    int16_t i2; /* +0x0004 */
} RTSHIPINT2;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTSHIPINT2) == 6, "sizeof(RTSHIPINT2)");
_Static_assert(offsetof(RTSHIPINT2, id) == 0x0, "offsetof(RTSHIPINT2,id)");
_Static_assert(offsetof(RTSHIPINT2, i) == 0x2, "offsetof(RTSHIPINT2,i)");
_Static_assert(offsetof(RTSHIPINT2, i2) == 0x4, "offsetof(RTSHIPINT2,i2)");
#endif

/* typind 5213 (0x145d) size=8 */
typedef struct _thworm
{
    union
    {
        struct
        {
            uint16_t iStable : 2;
            uint16_t cLastMove : 10;
            uint16_t fDestKnown : 1;
            uint16_t fInclude : 1;
            uint16_t : 2;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    uint16_t grbitPlr;     /* +0x0002 */
    uint16_t grbitPlrTrav; /* +0x0004 */
    uint16_t idPartner;    /* +0x0006 */
} THWORM;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(THWORM) == 8, "sizeof(THWORM)");
_Static_assert(offsetof(THWORM, grbitPlr) == 0x2, "offsetof(THWORM,grbitPlr)");
_Static_assert(offsetof(THWORM, grbitPlrTrav) == 0x4, "offsetof(THWORM,grbitPlrTrav)");
_Static_assert(offsetof(THWORM, idPartner) == 0x6, "offsetof(THWORM,idPartner)");
#endif

/* typind 5250 (0x1482) size=10 */
typedef struct _timer
{
    int16_t mdForce;        /* +0x0000 */
    int16_t fAutoGenWhenIn; /* +0x0002 */
    union
    {
        int16_t hrsForce;
        struct
        {
            uint16_t minForce : 12;
            uint16_t cPlr : 4;
        };
    }; /* +0x0004 */
    int32_t tickcount; /* +0x0006 */
} TIMER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TIMER) == 10, "sizeof(TIMER)");
_Static_assert(offsetof(TIMER, mdForce) == 0x0, "offsetof(TIMER,mdForce)");
_Static_assert(offsetof(TIMER, fAutoGenWhenIn) == 0x2, "offsetof(TIMER,fAutoGenWhenIn)");
_Static_assert(offsetof(TIMER, hrsForce) == 0x4, "offsetof(TIMER,hrsForce)");
_Static_assert(offsetof(TIMER, tickcount) == 0x6, "offsetof(TIMER,tickcount)");
#endif

/* typind 5254 (0x1486) size=37 */
typedef struct _rtchgname
{
    int16_t id;      /* +0x0000 */
    int16_t grobj;   /* +0x0002 */
    uint8_t rgb[33]; /* +0x0004 */
} RTCHGNAME;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTCHGNAME) == 37, "sizeof(RTCHGNAME)");
_Static_assert(offsetof(RTCHGNAME, id) == 0x0, "offsetof(RTCHGNAME,id)");
_Static_assert(offsetof(RTCHGNAME, grobj) == 0x2, "offsetof(RTCHGNAME,grobj)");
_Static_assert(offsetof(RTCHGNAME, rgb) == 0x4, "offsetof(RTCHGNAME,rgb)");
#endif

/* typind 5257 (0x1489) size=16 */
typedef struct complex
{
    double x; /* +0x0000 */
    double y; /* +0x0008 */
} complex;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(complex) == 16, "sizeof(complex)");
_Static_assert(offsetof(complex, x) == 0x0, "offsetof(complex,x)");
_Static_assert(offsetof(complex, y) == 0x8, "offsetof(complex,y)");
#endif

/* typind 5259 (0x148b) size=4 */
typedef struct _lsb
{
    union
    {
        struct
        {
            uint16_t isb : 4;
            uint16_t pctDp : 12;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    union
    {
        struct
        {
            uint16_t idFling : 10;
            uint16_t iWarpFling : 4;
            uint16_t unused3 : 2;
        };
        uint16_t wRaw_0002;
    }; /* +0x0002 */
} LSB;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(LSB) == 4, "sizeof(LSB)");
#endif

#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(NEWTEXTMETRIC) == 41, "sizeof(NEWTEXTMETRIC)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmHeight) == 0x0, "offsetof(NEWTEXTMETRIC,tmHeight)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmAscent) == 0x2, "offsetof(NEWTEXTMETRIC,tmAscent)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmDescent) == 0x4, "offsetof(NEWTEXTMETRIC,tmDescent)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmInternalLeading) == 0x6, "offsetof(NEWTEXTMETRIC,tmInternalLeading)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmExternalLeading) == 0x8, "offsetof(NEWTEXTMETRIC,tmExternalLeading)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmAveCharWidth) == 0xa, "offsetof(NEWTEXTMETRIC,tmAveCharWidth)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmMaxCharWidth) == 0xc, "offsetof(NEWTEXTMETRIC,tmMaxCharWidth)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmWeight) == 0xe, "offsetof(NEWTEXTMETRIC,tmWeight)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmItalic) == 0x10, "offsetof(NEWTEXTMETRIC,tmItalic)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmUnderlined) == 0x11, "offsetof(NEWTEXTMETRIC,tmUnderlined)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmStruckOut) == 0x12, "offsetof(NEWTEXTMETRIC,tmStruckOut)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmFirstChar) == 0x13, "offsetof(NEWTEXTMETRIC,tmFirstChar)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmLastChar) == 0x14, "offsetof(NEWTEXTMETRIC,tmLastChar)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmDefaultChar) == 0x15, "offsetof(NEWTEXTMETRIC,tmDefaultChar)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmBreakChar) == 0x16, "offsetof(NEWTEXTMETRIC,tmBreakChar)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmPitchAndFamily) == 0x17, "offsetof(NEWTEXTMETRIC,tmPitchAndFamily)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmCharSet) == 0x18, "offsetof(NEWTEXTMETRIC,tmCharSet)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmOverhang) == 0x19, "offsetof(NEWTEXTMETRIC,tmOverhang)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmDigitizedAspectX) == 0x1b, "offsetof(NEWTEXTMETRIC,tmDigitizedAspectX)");
_Static_assert(offsetof(NEWTEXTMETRIC, tmDigitizedAspectY) == 0x1d, "offsetof(NEWTEXTMETRIC,tmDigitizedAspectY)");
_Static_assert(offsetof(NEWTEXTMETRIC, ntmFlags) == 0x1f, "offsetof(NEWTEXTMETRIC,ntmFlags)");
_Static_assert(offsetof(NEWTEXTMETRIC, ntmSizeEM) == 0x23, "offsetof(NEWTEXTMETRIC,ntmSizeEM)");
_Static_assert(offsetof(NEWTEXTMETRIC, ntmCellHeight) == 0x25, "offsetof(NEWTEXTMETRIC,ntmCellHeight)");
_Static_assert(offsetof(NEWTEXTMETRIC, ntmAvgWidth) == 0x27, "offsetof(NEWTEXTMETRIC,ntmAvgWidth)");
#endif

/* typind 5346 (0x14e2) size=4 */
typedef struct _rtplanet
{
    union
    {
        struct
        {
            int16_t id : 11;
            int16_t iPlayer : 5;
        };
        int16_t wRaw_0000;
    }; /* +0x0000 */
    union
    {
        struct
        {
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
        uint16_t wRaw_0002;
    }; /* +0x0002 */
} RTPLANET;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTPLANET) == 4, "sizeof(RTPLANET)");
#endif

/* typind 5372 (0x14fc) size=2 */
typedef struct _fleetid
{
    union
    {
        struct
        {
            uint16_t ifl : 9;
            uint16_t iplr : 4;
            uint16_t junk : 3;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
} FLEETID;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(FLEETID) == 2, "sizeof(FLEETID)");
#endif

/* typind 5378 (0x1502) size=2 */
typedef struct _vers
{
    union
    {
        struct
        {
            uint16_t verInc : 5;
            uint16_t verMinor : 7;
            uint16_t verMajor : 4;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
} VERS;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(VERS) == 2, "sizeof(VERS)");
#endif

/* typind 5426 (0x1532) size=6 */
typedef struct _planetminimal
{
    int16_t id;      /* +0x0000 */
    int16_t iPlayer; /* +0x0002 */
    union
    {
        struct
        {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fStarbase : 1;
            uint16_t unusedA : 1;
            uint16_t fFirstYear : 1;
            uint16_t unusedB : 4;
        };
        uint16_t wRaw_0004;
    }; /* +0x0004 */
} PLANETMINIMAL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PLANETMINIMAL) == 6, "sizeof(PLANETMINIMAL)");
_Static_assert(offsetof(PLANETMINIMAL, id) == 0x0, "offsetof(PLANETMINIMAL,id)");
_Static_assert(offsetof(PLANETMINIMAL, iPlayer) == 0x2, "offsetof(PLANETMINIMAL,iPlayer)");
#endif

/* typind 5456 (0x1550) size=17 */
typedef struct _rtloghdr
{
    int16_t cbLog;         /* +0x0000 */
    int32_t lSerialNumber; /* +0x0002 */
    uint8_t rgbConfig[11]; /* +0x0006 */
} RTLOGHDR;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTLOGHDR) == 17, "sizeof(RTLOGHDR)");
_Static_assert(offsetof(RTLOGHDR, cbLog) == 0x0, "offsetof(RTLOGHDR,cbLog)");
_Static_assert(offsetof(RTLOGHDR, lSerialNumber) == 0x2, "offsetof(RTLOGHDR,lSerialNumber)");
_Static_assert(offsetof(RTLOGHDR, rgbConfig) == 0x6, "offsetof(RTLOGHDR,rgbConfig)");
#endif

/* typind 5460 (0x1554) size=2 */
typedef struct _mdplr
{
    union
    {
        struct
        {
            uint16_t reserved : 9;
            uint16_t fAi : 1;
            uint16_t lvlAi : 3;
            uint16_t idAi : 3;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
} MDPLR;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(MDPLR) == 2, "sizeof(MDPLR)");
#endif

/* typind 4167 (0x1047) size=16 */
typedef struct _scan
{
    POINT pt;          /* +0x0000 */
    int16_t grobj;     /* +0x0004 */
    int16_t grobjFull; /* +0x0006 */
    int16_t idpl;      /* +0x0008 */
    int16_t ifl;       /* +0x000a */
    int16_t iwp;       /* +0x000c */
    int16_t ith;       /* +0x000e */
} SCAN;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SCAN) == 16, "sizeof(SCAN)");
_Static_assert(offsetof(SCAN, pt) == 0x0, "offsetof(SCAN,pt)");
_Static_assert(offsetof(SCAN, grobj) == 0x4, "offsetof(SCAN,grobj)");
_Static_assert(offsetof(SCAN, grobjFull) == 0x6, "offsetof(SCAN,grobjFull)");
_Static_assert(offsetof(SCAN, idpl) == 0x8, "offsetof(SCAN,idpl)");
_Static_assert(offsetof(SCAN, ifl) == 0xa, "offsetof(SCAN,ifl)");
_Static_assert(offsetof(SCAN, iwp) == 0xc, "offsetof(SCAN,iwp)");
_Static_assert(offsetof(SCAN, ith) == 0xe, "offsetof(SCAN,ith)");
#endif

/* typind 5198 (0x144e) size=12 */
typedef struct _sbar
{
    int16_t grbit; /* +0x0000 */
    int16_t id;    /* +0x0002 */
    POINT pt;      /* +0x0004 */
    char *psz;     /* +0x0008 */
    SCAN *pscan;   /* +0x000a */
} SBAR;

/* typind 5270 (0x1496) size=10 */
typedef struct _thtrader
{
    POINT ptDest; /* +0x0000 */
    union
    {
        struct
        {
            uint16_t iWarp : 4;
            uint16_t fInclude : 1;
            uint16_t unused : 11;
        };
        uint16_t wRaw_0004;
    }; /* +0x0004 */
    uint16_t grbitPlr;    /* +0x0006 */
    uint16_t grbitTrader; /* +0x0008 */
} THTRADER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(THTRADER) == 10, "sizeof(THTRADER)");
_Static_assert(offsetof(THTRADER, ptDest) == 0x0, "offsetof(THTRADER,ptDest)");
_Static_assert(offsetof(THTRADER, grbitPlr) == 0x6, "offsetof(THTRADER,grbitPlr)");
_Static_assert(offsetof(THTRADER, grbitTrader) == 0x8, "offsetof(THTRADER,grbitTrader)");
#endif

/* typind 4276 (0x10b4) size=54 */
typedef struct _rpt
{
    int32_t grbitVisible; /* +0x0000 */
    int16_t irpt;         /* +0x0004 */
    int16_t cFields;      /* +0x0006 */
    int16_t cFieldFirst;  /* +0x0008 */
    int16_t icolSort;     /* +0x000a */
    int16_t fAscending;   /* +0x000c */
    int16_t irowFirst;    /* +0x000e */
    POINT ptDlg;          /* +0x0010 */
    POINT ptSize;         /* +0x0014 */
    int16_t fCached;      /* +0x0018 */
    uint8_t rgbdx[16];    /* +0x001a */
    int16_t cRows;        /* +0x002a */
    int16_t cRowsVis;     /* +0x002c */
    int16_t iSubsort;     /* +0x002e */
    uint16_t hwndVScroll; /* +0x0030 */
    uint16_t hwndHScroll; /* +0x0032 */
    int16_t cColScroll;   /* +0x0034 */
} RPT;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RPT) == 54, "sizeof(RPT)");
_Static_assert(offsetof(RPT, grbitVisible) == 0x0, "offsetof(RPT,grbitVisible)");
_Static_assert(offsetof(RPT, irpt) == 0x4, "offsetof(RPT,irpt)");
_Static_assert(offsetof(RPT, cFields) == 0x6, "offsetof(RPT,cFields)");
_Static_assert(offsetof(RPT, cFieldFirst) == 0x8, "offsetof(RPT,cFieldFirst)");
_Static_assert(offsetof(RPT, icolSort) == 0xa, "offsetof(RPT,icolSort)");
_Static_assert(offsetof(RPT, fAscending) == 0xc, "offsetof(RPT,fAscending)");
_Static_assert(offsetof(RPT, irowFirst) == 0xe, "offsetof(RPT,irowFirst)");
_Static_assert(offsetof(RPT, ptDlg) == 0x10, "offsetof(RPT,ptDlg)");
_Static_assert(offsetof(RPT, ptSize) == 0x14, "offsetof(RPT,ptSize)");
_Static_assert(offsetof(RPT, fCached) == 0x18, "offsetof(RPT,fCached)");
_Static_assert(offsetof(RPT, rgbdx) == 0x1a, "offsetof(RPT,rgbdx)");
_Static_assert(offsetof(RPT, cRows) == 0x2a, "offsetof(RPT,cRows)");
_Static_assert(offsetof(RPT, cRowsVis) == 0x2c, "offsetof(RPT,cRowsVis)");
_Static_assert(offsetof(RPT, iSubsort) == 0x2e, "offsetof(RPT,iSubsort)");
_Static_assert(offsetof(RPT, hwndVScroll) == 0x30, "offsetof(RPT,hwndVScroll)");
_Static_assert(offsetof(RPT, hwndHScroll) == 0x32, "offsetof(RPT,hwndHScroll)");
_Static_assert(offsetof(RPT, cColScroll) == 0x34, "offsetof(RPT,cColScroll)");
#endif

/* typind 5117 (0x13fd) size=12 */
typedef struct _fleetsome
{
    int16_t id;      /* +0x0000 */
    int16_t iPlayer; /* +0x0002 */
    union
    {
        struct
        {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fRepOrders : 1;
            uint16_t fDead : 1;
            uint16_t fByteCsh : 1;
            uint16_t unused : 4;
        };
        uint16_t wRaw_0004;
    }; /* +0x0004 */
    int16_t idPlanet; /* +0x0006 */
    POINT pt;         /* +0x0008 */
} FLEETSOME;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(FLEETSOME) == 12, "sizeof(FLEETSOME)");
_Static_assert(offsetof(FLEETSOME, id) == 0x0, "offsetof(FLEETSOME,id)");
_Static_assert(offsetof(FLEETSOME, iPlayer) == 0x2, "offsetof(FLEETSOME,iPlayer)");
_Static_assert(offsetof(FLEETSOME, idPlanet) == 0x6, "offsetof(FLEETSOME,idPlanet)");
_Static_assert(offsetof(FLEETSOME, pt) == 0x8, "offsetof(FLEETSOME,pt)");
#endif

/* typind 5239 (0x1477) size=24 */
typedef struct _drawcir
{
    int16_t *rgx;       /* +0x0000 */
    int16_t *rgy;       /* +0x0002 */
    int16_t *rgrad;     /* +0x0004 */
    int16_t cCur;       /* +0x0006 */
    int16_t cMax;       /* +0x0008 */
    uint16_t hdc;       /* +0x000a */
    RECT rcClip;        /* +0x000c */
    int16_t fCovered;   /* +0x0014 */
    int16_t fHollowOut; /* +0x0016 */
} DRAWCIR;

/* typind 5429 (0x1535) size=10 */
typedef struct _wn
{
    RECT rc; /* +0x0000 */
    union
    {
        struct
        {
            uint16_t fMaximized : 1;
            uint16_t fMinimized : 1;
            uint16_t fInitalized : 1;
            uint16_t fUnused : 13;
        };
        uint16_t wRaw_0008;
    }; /* +0x0008 */
} WN;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(WN) == 10, "sizeof(WN)");
_Static_assert(offsetof(WN, rc) == 0x0, "offsetof(WN,rc)");
#endif

/* typind 4444 (0x115c) size=24 */
typedef struct _btnt
{
    uint16_t hwnd;  /* +0x0000 */
    uint16_t hdc;   /* +0x0002 */
    RECT rc;        /* +0x0004 */
    int16_t dTimer; /* +0x000c */
    int16_t btf;    /* +0x000e */
    char *szText;   /* +0x0010 */
    int32_t lTicks; /* +0x0012 */
    union
    {
        struct
        {
            uint16_t fFirst : 1;
            uint16_t fDown : 1;
            uint16_t fInitDown : 1;
            uint16_t fCreatedDC : 1;
            uint16_t fNoEndRedraw : 1;
            uint16_t fUnused : 11;
        };
        uint16_t wRaw_0016;
    }; /* +0x0016 */
} BTNT;

/* typind 5103 (0x13ef) size=14 */
typedef struct _btn
{
    RECT rc;      /* +0x0000 */
    int16_t bt;   /* +0x0008 */
    int16_t iVal; /* +0x000a */
    union
    {
        struct
        {
            uint16_t fVisible : 1;
            uint16_t fDisabled : 1;
            uint16_t iSide : 2;
            uint16_t fUnused : 12;
        };
        uint16_t wRaw_000c;
    }; /* +0x000c */
} BTN;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(BTN) == 14, "sizeof(BTN)");
_Static_assert(offsetof(BTN, rc) == 0x0, "offsetof(BTN,rc)");
_Static_assert(offsetof(BTN, bt) == 0x8, "offsetof(BTN,bt)");
_Static_assert(offsetof(BTN, iVal) == 0xa, "offsetof(BTN,iVal)");
#endif

/* typind 4933 (0x1345) size=2 */
typedef struct _rtChgProdQ
{
    int16_t id;     /* +0x0000 */
    PROD rgprod[0]; /* +0x0002 */
} RTCHGPRODQ;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTCHGPRODQ) == 2, "sizeof(RTCHGPRODQ)");
_Static_assert(offsetof(RTCHGPRODQ, id) == 0x0, "offsetof(RTCHGPRODQ,id)");
_Static_assert(offsetof(RTCHGPRODQ, rgprod) == 0x2, "offsetof(RTCHGPRODQ,rgprod)");
#endif

/* typind 4214 (0x1076) size=123 */
typedef struct _hul
{
    int16_t ihuldef;         /* +0x0000 */
    int8_t rgTech[6];        /* +0x0002 */
    char szClass[32];        /* +0x0008 */
    uint16_t wtEmpty;        /* +0x0028 */
    uint16_t resCost;        /* +0x002a */
    uint16_t rgwtOreCost[3]; /* +0x002c */
    int16_t ibmp;            /* +0x0032 */
    uint16_t wtCargoMax;     /* +0x0034 */
    uint16_t wtFuelMax;      /* +0x0036 */
    uint16_t dp;             /* +0x0038 */
    HS rghs[16];             /* +0x003a */
    uint8_t chs;             /* +0x007a */
} HUL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(HUL) == 123, "sizeof(HUL)");
_Static_assert(offsetof(HUL, ihuldef) == 0x0, "offsetof(HUL,ihuldef)");
_Static_assert(offsetof(HUL, rgTech) == 0x2, "offsetof(HUL,rgTech)");
_Static_assert(offsetof(HUL, szClass) == 0x8, "offsetof(HUL,szClass)");
_Static_assert(offsetof(HUL, wtEmpty) == 0x28, "offsetof(HUL,wtEmpty)");
_Static_assert(offsetof(HUL, resCost) == 0x2a, "offsetof(HUL,resCost)");
_Static_assert(offsetof(HUL, rgwtOreCost) == 0x2c, "offsetof(HUL,rgwtOreCost)");
_Static_assert(offsetof(HUL, ibmp) == 0x32, "offsetof(HUL,ibmp)");
_Static_assert(offsetof(HUL, wtCargoMax) == 0x34, "offsetof(HUL,wtCargoMax)");
_Static_assert(offsetof(HUL, wtFuelMax) == 0x36, "offsetof(HUL,wtFuelMax)");
_Static_assert(offsetof(HUL, dp) == 0x38, "offsetof(HUL,dp)");
_Static_assert(offsetof(HUL, rghs) == 0x3a, "offsetof(HUL,rghs)");
_Static_assert(offsetof(HUL, chs) == 0x7a, "offsetof(HUL,chs)");
#endif

/* typind 4190 (0x105e) size=8 */
typedef struct _part
{
    HS hs; /* +0x0000 */
    union
    {
        COMPART *pcom;
        ARMOR *parmor;
        HUL *phul;
        ENGINE *pengine;
        SCANNER *pscanner;
        BEAM *pbeam;
        TORP *ptorp;
        BOMB *pbomb;
        SHIELD *pshield;
        SPECIAL *pspecial;
        SPECIALSB *pspecialsb;
        MINES *pmines;
        MINING *pmining;
        PLANETARY *pplanetary;
        TERRA *pterra;
    }; /* +0x0004 */
} PART;

/* typind 5327 (0x14cf) size=17 */
typedef struct _rtshdef
{
    union
    {
        uint16_t wFlags;
        struct
        {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fFree : 1;
            uint16_t ishdef : 5;
            uint16_t fGift : 1;
        };
    }; /* +0x0000 */
    uint8_t ihuldef; /* +0x0002 */
    uint8_t ibmp;    /* +0x0003 */
    union
    {
        uint16_t wtEmpty;
        uint16_t dp;
    }; /* +0x0004 */
    uint8_t chs;     /* +0x0006 */
    uint16_t turn;   /* +0x0007 */
    uint32_t cBuilt; /* +0x0009 */
    uint32_t cExist; /* +0x000d */
    HS rghs[0];      /* +0x0011 */
} RTSHDEF;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTSHDEF) == 17, "sizeof(RTSHDEF)");
_Static_assert(offsetof(RTSHDEF, wFlags) == 0x0, "offsetof(RTSHDEF,wFlags)");
_Static_assert(offsetof(RTSHDEF, ihuldef) == 0x2, "offsetof(RTSHDEF,ihuldef)");
_Static_assert(offsetof(RTSHDEF, ibmp) == 0x3, "offsetof(RTSHDEF,ibmp)");
_Static_assert(offsetof(RTSHDEF, wtEmpty) == 0x4, "offsetof(RTSHDEF,wtEmpty)");
_Static_assert(offsetof(RTSHDEF, dp) == 0x4, "offsetof(RTSHDEF,dp)");
_Static_assert(offsetof(RTSHDEF, chs) == 0x6, "offsetof(RTSHDEF,chs)");
_Static_assert(offsetof(RTSHDEF, turn) == 0x7, "offsetof(RTSHDEF,turn)");
_Static_assert(offsetof(RTSHDEF, cBuilt) == 0x9, "offsetof(RTSHDEF,cBuilt)");
_Static_assert(offsetof(RTSHDEF, cExist) == 0xd, "offsetof(RTSHDEF,cExist)");
_Static_assert(offsetof(RTSHDEF, rghs) == 0x11, "offsetof(RTSHDEF,rghs)");
#endif

/* typind 4099 (0x1003) size=124 */
typedef struct _fleet
{
    union
    {
        int16_t id;
        struct
        {
            uint16_t ifl : 9;
            uint16_t iplr : 4;
            uint16_t junk : 3;
        };
    }; /* +0x0000 */
    int16_t iPlayer; /* +0x0002 */
    union
    {
        struct
        {
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
        uint16_t wRaw_0004;
    }; /* +0x0004 */
    int16_t idPlanet;  /* +0x0006 */
    POINT pt;          /* +0x0008 */
    int16_t rgcsh[16]; /* +0x000c */
    union
    {
        DV rgdv[16];
        int32_t wtFleet;
    }; /* +0x002c */
    int32_t rgwtMin[5];      /* +0x004c */
    uint8_t iplan;           /* +0x0060 */
    uint8_t bUnused;         /* +0x0061 */
    int16_t cord;            /* +0x0062 */
    PLORD *lpplord;          /* +0x0064 */
    struct _fleet *lpflNext; /* +0x0068 */
    union
    {
        int32_t lPower;
        struct
        {
            int16_t dMoveLeft;
            int16_t dMoveUsed;
        };
    }; /* +0x006c */
    int32_t lFuelUsed; /* +0x0070 */
    union
    {
        int32_t dirLong;
        struct
        {
            uint16_t dirFltX : 8;
            uint16_t dirFltY : 8;
        };
        struct
        {
            uint16_t iwarpFlt : 4;
            uint16_t fdirValid : 1;
            uint16_t fCompChg : 1;
            uint16_t fTargeted : 1;
            uint16_t fSkipped : 1;
            uint16_t fUnused : 8;
        };
    }; /* +0x0074 */
    char *lpszName; /* +0x0078 */
} FLEET;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(FLEET) == 124u, "FLEET size");
_Static_assert(offsetof(FLEET, id) == 0u, "FLEET.id offset");
_Static_assert(offsetof(FLEET, iPlayer) == 2u, "FLEET.iPlayer offset");
_Static_assert(offsetof(FLEET, idPlanet) == 6u, "FLEET.idPlanet offset");
_Static_assert(offsetof(FLEET, pt) == 8u, "FLEET.pt offset");
_Static_assert(offsetof(FLEET, rgcsh) == 12u, "FLEET.rgcsh offset");
_Static_assert(offsetof(FLEET, rgdv) == 44u, "FLEET.rgdv offset");
_Static_assert(offsetof(FLEET, wtFleet) == 44u, "FLEET.wtFleet offset");
_Static_assert(offsetof(FLEET, rgwtMin) == 76u, "FLEET.rgwtMin offset");
_Static_assert(offsetof(FLEET, iplan) == 96u, "FLEET.iplan offset");
_Static_assert(offsetof(FLEET, bUnused) == 97u, "FLEET.bUnused offset");
_Static_assert(offsetof(FLEET, cord) == 98u, "FLEET.cord offset");
_Static_assert(offsetof(FLEET, lpplord) == 100u, "FLEET.lpplord offset");
_Static_assert(offsetof(FLEET, lpflNext) == 104u, "FLEET.lpflNext offset");
_Static_assert(offsetof(FLEET, lPower) == 108u, "FLEET.lPower offset");
_Static_assert(offsetof(FLEET, dMoveLeft) == 108u, "FLEET.dMoveLeft offset");
_Static_assert(offsetof(FLEET, dMoveUsed) == 110u, "FLEET.dMoveUsed offset");
_Static_assert(offsetof(FLEET, lFuelUsed) == 112u, "FLEET.lFuelUsed offset");
_Static_assert(offsetof(FLEET, dirLong) == 116u, "FLEET.dirLong offset");
_Static_assert(offsetof(FLEET, lpszName) == 120u, "FLEET.lpszName offset");
#endif

/* typind 4329 (0x10e9) size=29 */
typedef struct _tok
{
    uint16_t id;        /* +0x0000 */
    uint8_t iplr;       /* +0x0002 */
    uint8_t grobj;      /* +0x0003 */
    uint8_t ishdef;     /* +0x0004 */
    uint8_t brc;        /* +0x0005 */
    uint8_t initBase;   /* +0x0006 */
    uint8_t initMin;    /* +0x0007 */
    uint8_t initMac;    /* +0x0008 */
    uint8_t itokTarget; /* +0x0009 */
    uint8_t pctCloak;   /* +0x000a */
    uint8_t pctJam;     /* +0x000b */
    uint8_t pctBC;      /* +0x000c */
    uint8_t pctCap;     /* +0x000d */
    uint8_t pctBeamDef; /* +0x000e */
    uint16_t wt;        /* +0x000f */
    uint16_t dpShield;  /* +0x0011 */
    uint16_t csh;       /* +0x0013 */
    DV dv;              /* +0x0015 */
    union
    {
        struct
        {
            uint16_t mdTarget1 : 4;
            uint16_t mdTarget2 : 4;
            uint16_t mdTactic : 4;
            uint16_t mdTarget0 : 4;
        };
        uint16_t wRaw_0017;
    }; /* +0x0017 */
    union
    {
        struct
        {
            uint16_t dxyLim : 4;
            uint16_t dxyMax : 4;
            uint16_t spd : 4;
            uint16_t cTarget : 4;
        };
        uint16_t wRaw_0019;
    }; /* +0x0019 */
    union
    {
        uint16_t wFlags;
        struct
        {
            uint16_t fActive : 1;
            uint16_t fDetector : 1;
            uint16_t fTorp : 1;
            uint16_t fRegen : 1;
            uint16_t fMoved : 1;
            uint16_t dzDis : 5;
            uint16_t dwt : 4;
            uint16_t dMovesLeft : 2;
        };
    }; /* +0x001b */
} TOK;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TOK) == 29, "sizeof(TOK)");
_Static_assert(offsetof(TOK, id) == 0x0, "offsetof(TOK,id)");
_Static_assert(offsetof(TOK, iplr) == 0x2, "offsetof(TOK,iplr)");
_Static_assert(offsetof(TOK, grobj) == 0x3, "offsetof(TOK,grobj)");
_Static_assert(offsetof(TOK, ishdef) == 0x4, "offsetof(TOK,ishdef)");
_Static_assert(offsetof(TOK, brc) == 0x5, "offsetof(TOK,brc)");
_Static_assert(offsetof(TOK, initBase) == 0x6, "offsetof(TOK,initBase)");
_Static_assert(offsetof(TOK, initMin) == 0x7, "offsetof(TOK,initMin)");
_Static_assert(offsetof(TOK, initMac) == 0x8, "offsetof(TOK,initMac)");
_Static_assert(offsetof(TOK, itokTarget) == 0x9, "offsetof(TOK,itokTarget)");
_Static_assert(offsetof(TOK, pctCloak) == 0xa, "offsetof(TOK,pctCloak)");
_Static_assert(offsetof(TOK, pctJam) == 0xb, "offsetof(TOK,pctJam)");
_Static_assert(offsetof(TOK, pctBC) == 0xc, "offsetof(TOK,pctBC)");
_Static_assert(offsetof(TOK, pctCap) == 0xd, "offsetof(TOK,pctCap)");
_Static_assert(offsetof(TOK, pctBeamDef) == 0xe, "offsetof(TOK,pctBeamDef)");
_Static_assert(offsetof(TOK, wt) == 0xf, "offsetof(TOK,wt)");
_Static_assert(offsetof(TOK, dpShield) == 0x11, "offsetof(TOK,dpShield)");
_Static_assert(offsetof(TOK, csh) == 0x13, "offsetof(TOK,csh)");
_Static_assert(offsetof(TOK, dv) == 0x15, "offsetof(TOK,dv)");
_Static_assert(offsetof(TOK, wFlags) == 0x1b, "offsetof(TOK,wFlags)");
#endif

/* typind 5107 (0x13f3) size=8 */
typedef struct _kill
{
    uint8_t itok;      /* +0x0000 */
    uint8_t grfWeapon; /* +0x0001 */
    uint16_t cshKill;  /* +0x0002 */
    uint16_t dpShield; /* +0x0004 */
    DV dv;             /* +0x0006 */
} KILL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(KILL) == 8, "sizeof(KILL)");
_Static_assert(offsetof(KILL, itok) == 0x0, "offsetof(KILL,itok)");
_Static_assert(offsetof(KILL, grfWeapon) == 0x1, "offsetof(KILL,grfWeapon)");
_Static_assert(offsetof(KILL, cshKill) == 0x2, "offsetof(KILL,cshKill)");
_Static_assert(offsetof(KILL, dpShield) == 0x4, "offsetof(KILL,dpShield)");
_Static_assert(offsetof(KILL, dv) == 0x6, "offsetof(KILL,dv)");
#endif

/* typind 4830 (0x12de) size=5 */
typedef struct _msgturn
{
    union
    {
        struct
        {
            uint8_t iPlr : 4;
            uint8_t cbParams : 4;
        };
        uint8_t wRaw_0000;
    }; /* +0x0000 */
    MSGHDR msghdr; /* +0x0001 */
} MSGTURN;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(MSGTURN) == 5, "sizeof(MSGTURN)");
_Static_assert(offsetof(MSGTURN, msghdr) == 0x1, "offsetof(MSGTURN,msghdr)");
#endif

/* typind 4250 (0x109a) size=24 */
typedef struct _scorex
{
    union
    {
        uint16_t wWord;
        struct
        {
            uint16_t iPlayer : 5;
            uint16_t fValid : 1;
            uint16_t grbitVC : 8;
            uint16_t fWinner : 1;
            uint16_t fHistory : 1;
        };
    }; /* +0x0000 */
    union
    {
        int16_t iRank;
        uint16_t turn;
    }; /* +0x0002 */
    SCORE score; /* +0x0004 */
} SCOREX;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SCOREX) == 24, "sizeof(SCOREX)");
_Static_assert(offsetof(SCOREX, wWord) == 0x0, "offsetof(SCOREX,wWord)");
_Static_assert(offsetof(SCOREX, iRank) == 0x2, "offsetof(SCOREX,iRank)");
_Static_assert(offsetof(SCOREX, turn) == 0x2, "offsetof(SCOREX,turn)");
_Static_assert(offsetof(SCOREX, score) == 0x4, "offsetof(SCOREX,score)");
#endif

/* typind 4335 (0x10ef) size=26 */
typedef struct _zipprodq1
{
    uint8_t fNoResearch; /* +0x0000 */
    uint8_t cpq;         /* +0x0001 */
    PRODQ1 rgpq[12];     /* +0x0002 */
} ZIPPRODQ1;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(ZIPPRODQ1) == 26, "sizeof(ZIPPRODQ1)");
_Static_assert(offsetof(ZIPPRODQ1, fNoResearch) == 0x0, "offsetof(ZIPPRODQ1,fNoResearch)");
_Static_assert(offsetof(ZIPPRODQ1, cpq) == 0x1, "offsetof(ZIPPRODQ1,cpq)");
_Static_assert(offsetof(ZIPPRODQ1, rgpq) == 0x2, "offsetof(ZIPPRODQ1,rgpq)");
#endif

/* typind 5218 (0x1462) size=1284 */
typedef struct _aihist
{
    uint16_t cbAiHist;    /* +0x0000 */
    int16_t cStarbase;    /* +0x0002 */
    AISTARBASE rgasb[64]; /* +0x0004 */
} AIHIST;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(AIHIST) == 1284, "sizeof(AIHIST)");
_Static_assert(offsetof(AIHIST, cbAiHist) == 0x0, "offsetof(AIHIST,cbAiHist)");
_Static_assert(offsetof(AIHIST, cStarbase) == 0x2, "offsetof(AIHIST,cStarbase)");
_Static_assert(offsetof(AIHIST, rgasb) == 0x4, "offsetof(AIHIST,rgasb)");
#endif

/* typind 5422 (0x152e) size=28 */
typedef struct _selSome
{
    POINT pt;          /* +0x0000 */
    int16_t grobj;     /* +0x0004 */
    int16_t grobjFull; /* +0x0006 */
    int16_t id;        /* +0x0008 */
    int16_t iwpAct;    /* +0x000a */
    SCAN scan;         /* +0x000c */
} SELSOME;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SELSOME) == 28, "sizeof(SELSOME)");
_Static_assert(offsetof(SELSOME, pt) == 0x0, "offsetof(SELSOME,pt)");
_Static_assert(offsetof(SELSOME, grobj) == 0x4, "offsetof(SELSOME,grobj)");
_Static_assert(offsetof(SELSOME, grobjFull) == 0x6, "offsetof(SELSOME,grobjFull)");
_Static_assert(offsetof(SELSOME, id) == 0x8, "offsetof(SELSOME,id)");
_Static_assert(offsetof(SELSOME, iwpAct) == 0xa, "offsetof(SELSOME,iwpAct)");
_Static_assert(offsetof(SELSOME, scan) == 0xc, "offsetof(SELSOME,scan)");
#endif

/* typind 4102 (0x1006) size=18 */
typedef struct _thing
{
    union
    {
        uint16_t idFull;
        struct
        {
            uint16_t id : 9;
            uint16_t iplr : 4;
            uint16_t ith : 3;
        };
    }; /* +0x0000 */
    POINT pt; /* +0x0002 */
    union
    {
        uint8_t rgb[10];
        THMINE thm;
        THPACK thp;
        THTRADER tht;
        THWORM thw;
    }; /* +0x0006 */
    uint16_t turn; /* +0x0010 */
} THING;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(THING) == 18, "sizeof(THING)");
_Static_assert(offsetof(THING, idFull) == 0x0, "offsetof(THING,idFull)");
_Static_assert(offsetof(THING, pt) == 0x2, "offsetof(THING,pt)");
_Static_assert(offsetof(THING, rgb) == 0x6, "offsetof(THING,rgb)");
_Static_assert(offsetof(THING, thm) == 0x6, "offsetof(THING,thm)");
_Static_assert(offsetof(THING, thp) == 0x6, "offsetof(THING,thp)");
_Static_assert(offsetof(THING, thw) == 0x6, "offsetof(THING,thw)");
_Static_assert(offsetof(THING, tht) == 0x6, "offsetof(THING,tht)");
_Static_assert(offsetof(THING, turn) == 0x10, "offsetof(THING,turn)");
#endif

/* typind 4332 (0x10ec) size=26 */
typedef struct _ini
{
    WN wnFrame; /* +0x0000 */
    union
    {
        uint16_t wFlags;
        struct
        {
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
    }; /* +0x000a */
    uint16_t turn;    /* +0x000c */
    int16_t iObjSel;  /* +0x000e */
    int16_t idPlayer; /* +0x0010 */
    int32_t lid;      /* +0x0012 */
    int16_t cTurnGen; /* +0x0016 */
    int16_t iMsg;     /* +0x0018 */
} INI;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(INI) == 26, "sizeof(INI)");
_Static_assert(offsetof(INI, wnFrame) == 0x0, "offsetof(INI,wnFrame)");
_Static_assert(offsetof(INI, wFlags) == 0xa, "offsetof(INI,wFlags)");
_Static_assert(offsetof(INI, turn) == 0xc, "offsetof(INI,turn)");
_Static_assert(offsetof(INI, iObjSel) == 0xe, "offsetof(INI,iObjSel)");
_Static_assert(offsetof(INI, idPlayer) == 0x10, "offsetof(INI,idPlayer)");
_Static_assert(offsetof(INI, lid) == 0x12, "offsetof(INI,lid)");
_Static_assert(offsetof(INI, cTurnGen) == 0x16, "offsetof(INI,cTurnGen)");
_Static_assert(offsetof(INI, iMsg) == 0x18, "offsetof(INI,iMsg)");
#endif

/* typind 4104 (0x1008) size=147 */
typedef struct _shdef
{
    HUL hul; /* +0x0000 */
    union
    {
        uint16_t wFlags;
        struct
        {
            uint16_t det : 8;
            uint16_t fInclude : 1;
            uint16_t fFree : 1;
            uint16_t ishdef : 5;
            uint16_t fGift : 1;
        };
    }; /* +0x007b */
    uint16_t turn;   /* +0x007d */
    uint32_t cBuilt; /* +0x007f */
    uint32_t cExist; /* +0x0083 */
    union
    {
        int32_t lPower;
        int32_t lVisible;
    }; /* +0x0087 */
    uint16_t grbitPlr;    /* +0x008b */
    uint16_t dScanRange;  /* +0x008d */
    uint16_t dScanRange2; /* +0x008f */
    uint8_t pctDetect;    /* +0x0091 */
    uint8_t iSteal;       /* +0x0092 */
} SHDEF;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SHDEF) == 147, "sizeof(SHDEF)");
_Static_assert(offsetof(SHDEF, hul) == 0x0, "offsetof(SHDEF,hul)");
_Static_assert(offsetof(SHDEF, wFlags) == 0x7b, "offsetof(SHDEF,wFlags)");
_Static_assert(offsetof(SHDEF, turn) == 0x7d, "offsetof(SHDEF,turn)");
_Static_assert(offsetof(SHDEF, cBuilt) == 0x7f, "offsetof(SHDEF,cBuilt)");
_Static_assert(offsetof(SHDEF, cExist) == 0x83, "offsetof(SHDEF,cExist)");
_Static_assert(offsetof(SHDEF, lPower) == 0x87, "offsetof(SHDEF,lPower)");
_Static_assert(offsetof(SHDEF, lVisible) == 0x87, "offsetof(SHDEF,lVisible)");
_Static_assert(offsetof(SHDEF, grbitPlr) == 0x8b, "offsetof(SHDEF,grbitPlr)");
_Static_assert(offsetof(SHDEF, dScanRange) == 0x8d, "offsetof(SHDEF,dScanRange)");
_Static_assert(offsetof(SHDEF, dScanRange2) == 0x8f, "offsetof(SHDEF,dScanRange2)");
_Static_assert(offsetof(SHDEF, pctDetect) == 0x91, "offsetof(SHDEF,pctDetect)");
_Static_assert(offsetof(SHDEF, iSteal) == 0x92, "offsetof(SHDEF,iSteal)");
#endif

/* typind 4745 (0x1289) size=143 */
typedef struct _huldef
{
    HUL hul; /* +0x0000 */
    union
    {
        struct
        {
            uint16_t init : 6;
            uint16_t imdAttack : 4;
            uint16_t imdCategory : 4;
            uint16_t unused : 2;
        };
        uint16_t wRaw_007b;
    }; /* +0x007b */
    uint16_t wrcCargo; /* +0x007d */
    uint8_t rgbrc[16]; /* +0x007f */
} HULDEF;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(HULDEF) == 143, "sizeof(HULDEF)");
_Static_assert(offsetof(HULDEF, hul) == 0x0, "offsetof(HULDEF,hul)");
_Static_assert(offsetof(HULDEF, wrcCargo) == 0x7d, "offsetof(HULDEF,wrcCargo)");
_Static_assert(offsetof(HULDEF, rgbrc) == 0x7f, "offsetof(HULDEF,rgbrc)");
#endif

/* typind 5337 (0x14d9) size=19 */
typedef struct _rtchgshdef
{
    union
    {
        struct
        {
            uint16_t mdChg : 4;
            uint16_t iPlr : 4;
            uint16_t ishdef : 5;
            uint16_t junk : 3;
        };
        uint16_t wRaw_0000;
    }; /* +0x0000 */
    RTSHDEF rtshdef; /* +0x0002 */
} RTCHGSHDEF;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTCHGSHDEF) == 19, "sizeof(RTCHGSHDEF)");
_Static_assert(offsetof(RTCHGSHDEF, rtshdef) == 0x2, "offsetof(RTCHGSHDEF,rtshdef)");
#endif

/* typind 4258 (0x10a2) size=14 */
typedef struct _btldata
{
    uint16_t id;       /* +0x0000 */
    uint8_t cplr;      /* +0x0002 */
    uint8_t ctok;      /* +0x0003 */
    uint16_t grfPlr;   /* +0x0004 */
    uint16_t cbData;   /* +0x0006 */
    uint16_t idPlanet; /* +0x0008 */
    POINT pt;          /* +0x000a */
    TOK rgtok[0];      /* +0x000e */
} BTLDATA;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(BTLDATA) == 14, "sizeof(BTLDATA)");
_Static_assert(offsetof(BTLDATA, id) == 0x0, "offsetof(BTLDATA,id)");
_Static_assert(offsetof(BTLDATA, cplr) == 0x2, "offsetof(BTLDATA,cplr)");
_Static_assert(offsetof(BTLDATA, ctok) == 0x3, "offsetof(BTLDATA,ctok)");
_Static_assert(offsetof(BTLDATA, grfPlr) == 0x4, "offsetof(BTLDATA,grfPlr)");
_Static_assert(offsetof(BTLDATA, cbData) == 0x6, "offsetof(BTLDATA,cbData)");
_Static_assert(offsetof(BTLDATA, idPlanet) == 0x8, "offsetof(BTLDATA,idPlanet)");
_Static_assert(offsetof(BTLDATA, pt) == 0xa, "offsetof(BTLDATA,pt)");
_Static_assert(offsetof(BTLDATA, rgtok) == 0xe, "offsetof(BTLDATA,rgtok)");
#endif

/* typind 5176 (0x1438) size=6 */
typedef struct _btlrec26
{
    uint8_t itok;       /* +0x0000 */
    uint8_t brcDest;    /* +0x0001 */
    uint8_t itokAttack; /* +0x0002 */
    uint8_t ctok;       /* +0x0003 */
    union
    {
        struct
        {
            uint16_t iRound : 4;
            uint16_t dzDis : 4;
            uint16_t unused : 8;
        };
        uint16_t wRaw_0004;
    }; /* +0x0004 */
    KILL rgkill[0]; /* +0x0006 */
} BTLREC26;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(BTLREC26) == 6, "sizeof(BTLREC26)");
_Static_assert(offsetof(BTLREC26, itok) == 0x0, "offsetof(BTLREC26,itok)");
_Static_assert(offsetof(BTLREC26, brcDest) == 0x1, "offsetof(BTLREC26,brcDest)");
_Static_assert(offsetof(BTLREC26, itokAttack) == 0x2, "offsetof(BTLREC26,itokAttack)");
_Static_assert(offsetof(BTLREC26, ctok) == 0x3, "offsetof(BTLREC26,ctok)");
_Static_assert(offsetof(BTLREC26, rgkill) == 0x6, "offsetof(BTLREC26,rgkill)");
#endif

/* typind 4438 (0x1156) size=6 */
typedef struct _btlrec
{
    uint8_t itok;    /* +0x0000 */
    uint8_t brcDest; /* +0x0001 */
    int16_t ctok;    /* +0x0002 */
    union
    {
        struct
        {
            uint16_t iRound : 4;
            uint16_t dzDis : 4;
            uint16_t itokAttack : 8;
        };
        uint16_t wRaw_0004;
    }; /* +0x0004 */
    KILL rgkill[0]; /* +0x0006 */
} BTLREC;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(BTLREC) == 6, "sizeof(BTLREC)");
_Static_assert(offsetof(BTLREC, itok) == 0x0, "offsetof(BTLREC,itok)");
_Static_assert(offsetof(BTLREC, brcDest) == 0x1, "offsetof(BTLREC,brcDest)");
_Static_assert(offsetof(BTLREC, ctok) == 0x2, "offsetof(BTLREC,ctok)");
_Static_assert(offsetof(BTLREC, rgkill) == 0x6, "offsetof(BTLREC,rgkill)");
#endif

/* typind 4116 (0x1014) size=192 */
typedef struct _player
{
    int8_t iPlayer;  /* +0x0000 */
    int8_t cShDef;   /* +0x0001 */
    int16_t cPlanet; /* +0x0002 */
    union
    {
        struct
        {
            uint16_t cFleet : 12;
            uint16_t cshdefSB : 4;
        };
        uint16_t wRaw_0004;
    }; /* +0x0004 */
    union
    {
        uint16_t wMdPlr;
        struct
        {
            uint16_t det : 3;
            uint16_t iPlrBmp : 5;
            uint16_t fInclude : 1;
            uint16_t mdPlayer : 7;
        };
        struct
        {
            uint16_t reserved : 9;
            uint16_t fAi : 1;
            uint16_t lvlAi : 3;
            uint16_t idAi : 3;
        };
    }; /* +0x0006 */
    int16_t idPlanetHome;   /* +0x0008 */
    uint16_t wScore;        /* +0x000a */
    int32_t lSalt;          /* +0x000c */
    int8_t rgEnvVar[3];     /* +0x0010 */
    int8_t rgEnvVarMin[3];  /* +0x0013 */
    int8_t rgEnvVarMax[3];  /* +0x0016 */
    int8_t pctIdealGrowth;  /* +0x0019 */
    int8_t rgTech[6];       /* +0x001a */
    uint32_t rgResSpent[6]; /* +0x0020 */
    int8_t pctResearch;     /* +0x0038 */
    int8_t iTechCur;        /* +0x0039 */
    int32_t lResLastYear;   /* +0x003a */
    int8_t rgAttr[16];      /* +0x003e */
    uint32_t grbitAttr;     /* +0x004e */
    uint16_t grbitTrader;   /* +0x0052 */
    union
    {
        uint16_t wFlags;
        struct
        {
            uint16_t fDead : 1;
            uint16_t fCrippled : 1;
            uint16_t fCheater : 1;
            uint16_t fLearned : 1;
            uint16_t fHacker : 1;
            uint16_t unused : 11;
        };
    }; /* +0x0054 */
    ZIPPRODQ1 zpq1;           /* +0x0056 */
    uint8_t rgmdRelation[16]; /* +0x0070 */
    char szName[32];          /* +0x0080 */
    char szNames[32];         /* +0x00a0 */
} PLAYER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(PLAYER) == 192, "sizeof(PLAYER)");
_Static_assert(offsetof(PLAYER, iPlayer) == 0x0, "offsetof(PLAYER,iPlayer)");
_Static_assert(offsetof(PLAYER, cShDef) == 0x1, "offsetof(PLAYER,cShDef)");
_Static_assert(offsetof(PLAYER, cPlanet) == 0x2, "offsetof(PLAYER,cPlanet)");
_Static_assert(offsetof(PLAYER, wMdPlr) == 0x6, "offsetof(PLAYER,wMdPlr)");
_Static_assert(offsetof(PLAYER, idPlanetHome) == 0x8, "offsetof(PLAYER,idPlanetHome)");
_Static_assert(offsetof(PLAYER, wScore) == 0xa, "offsetof(PLAYER,wScore)");
_Static_assert(offsetof(PLAYER, lSalt) == 0xc, "offsetof(PLAYER,lSalt)");
_Static_assert(offsetof(PLAYER, rgEnvVar) == 0x10, "offsetof(PLAYER,rgEnvVar)");
_Static_assert(offsetof(PLAYER, rgEnvVarMin) == 0x13, "offsetof(PLAYER,rgEnvVarMin)");
_Static_assert(offsetof(PLAYER, rgEnvVarMax) == 0x16, "offsetof(PLAYER,rgEnvVarMax)");
_Static_assert(offsetof(PLAYER, pctIdealGrowth) == 0x19, "offsetof(PLAYER,pctIdealGrowth)");
_Static_assert(offsetof(PLAYER, rgTech) == 0x1a, "offsetof(PLAYER,rgTech)");
_Static_assert(offsetof(PLAYER, rgResSpent) == 0x20, "offsetof(PLAYER,rgResSpent)");
_Static_assert(offsetof(PLAYER, pctResearch) == 0x38, "offsetof(PLAYER,pctResearch)");
_Static_assert(offsetof(PLAYER, iTechCur) == 0x39, "offsetof(PLAYER,iTechCur)");
_Static_assert(offsetof(PLAYER, lResLastYear) == 0x3a, "offsetof(PLAYER,lResLastYear)");
_Static_assert(offsetof(PLAYER, rgAttr) == 0x3e, "offsetof(PLAYER,rgAttr)");
_Static_assert(offsetof(PLAYER, grbitAttr) == 0x4e, "offsetof(PLAYER,grbitAttr)");
_Static_assert(offsetof(PLAYER, grbitTrader) == 0x52, "offsetof(PLAYER,grbitTrader)");
_Static_assert(offsetof(PLAYER, wFlags) == 0x54, "offsetof(PLAYER,wFlags)");
_Static_assert(offsetof(PLAYER, zpq1) == 0x56, "offsetof(PLAYER,zpq1)");
_Static_assert(offsetof(PLAYER, rgmdRelation) == 0x70, "offsetof(PLAYER,rgmdRelation)");
_Static_assert(offsetof(PLAYER, szName) == 0x80, "offsetof(PLAYER,szName)");
_Static_assert(offsetof(PLAYER, szNames) == 0xa0, "offsetof(PLAYER,szNames)");
#endif

/* typind 4333 (0x10ed) size=44 */
typedef struct _tutor
{
    union
    {
        int16_t wFlags;
        struct
        {
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
    }; /* +0x0000 */
    int16_t idt;        /* +0x0002 */
    int16_t idtBold;    /* +0x0004 */
    int16_t idh;        /* +0x0006 */
    int16_t idsError;   /* +0x0008 */
    int16_t iScanZoom;  /* +0x000a */
    int16_t icolFSort;  /* +0x000c */
    uint16_t grbitScan; /* +0x000e */
    uint16_t hwnd;      /* +0x0010 */
    ZIPPRODQ1 zpq;      /* +0x0012 */
} TUTOR;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(TUTOR) == 44, "sizeof(TUTOR)");
_Static_assert(offsetof(TUTOR, wFlags) == 0x0, "offsetof(TUTOR,wFlags)");
_Static_assert(offsetof(TUTOR, idt) == 0x2, "offsetof(TUTOR,idt)");
_Static_assert(offsetof(TUTOR, idtBold) == 0x4, "offsetof(TUTOR,idtBold)");
_Static_assert(offsetof(TUTOR, idh) == 0x6, "offsetof(TUTOR,idh)");
_Static_assert(offsetof(TUTOR, idsError) == 0x8, "offsetof(TUTOR,idsError)");
_Static_assert(offsetof(TUTOR, iScanZoom) == 0xa, "offsetof(TUTOR,iScanZoom)");
_Static_assert(offsetof(TUTOR, icolFSort) == 0xc, "offsetof(TUTOR,icolFSort)");
_Static_assert(offsetof(TUTOR, grbitScan) == 0xe, "offsetof(TUTOR,grbitScan)");
_Static_assert(offsetof(TUTOR, hwnd) == 0x10, "offsetof(TUTOR,hwnd)");
_Static_assert(offsetof(TUTOR, zpq) == 0x12, "offsetof(TUTOR,zpq)");
#endif

/* typind 4337 (0x10f1) size=40 */
typedef struct _zipprodq
{
    char szName[13]; /* +0x0000 */
    uint8_t fValid;  /* +0x000d */
    union
    {
        ZIPPRODQ1 zpq1;
        struct
        {
            uint8_t fNoResearch;
            uint8_t cpq;
            PRODQ1 rgpq[12];
        };
    }; /* +0x000e */
} ZIPPRODQ;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(ZIPPRODQ) == 40, "sizeof(ZIPPRODQ)");
_Static_assert(offsetof(ZIPPRODQ, szName) == 0x0, "offsetof(ZIPPRODQ,szName)");
_Static_assert(offsetof(ZIPPRODQ, fValid) == 0xd, "offsetof(ZIPPRODQ,fValid)");
_Static_assert(offsetof(ZIPPRODQ, zpq1) == 0xe, "offsetof(ZIPPRODQ,zpq1)");
_Static_assert(offsetof(ZIPPRODQ, fNoResearch) == 0xe, "offsetof(ZIPPRODQ,fNoResearch)");
_Static_assert(offsetof(ZIPPRODQ, cpq) == 0xf, "offsetof(ZIPPRODQ,cpq)");
_Static_assert(offsetof(ZIPPRODQ, rgpq) == 0x10, "offsetof(ZIPPRODQ,rgpq)");
#endif

/* typind 4187 (0x105b) size=226 */
typedef struct _sel
{
    POINT pt;          /* +0x0000 */
    int16_t grobj;     /* +0x0004 */
    int16_t grobjFull; /* +0x0006 */
    int16_t id;        /* +0x0008 */
    int16_t iwpAct;    /* +0x000a */
    SCAN scan;         /* +0x000c */
    FLEET fl;          /* +0x001c */
    PLANET pl;         /* +0x0098 */
    THING th;          /* +0x00d0 */
} SEL;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(SEL) == 226, "sizeof(SEL)");
_Static_assert(offsetof(SEL, pt) == 0x0, "offsetof(SEL,pt)");
_Static_assert(offsetof(SEL, grobj) == 0x4, "offsetof(SEL,grobj)");
_Static_assert(offsetof(SEL, grobjFull) == 0x6, "offsetof(SEL,grobjFull)");
_Static_assert(offsetof(SEL, id) == 0x8, "offsetof(SEL,id)");
_Static_assert(offsetof(SEL, iwpAct) == 0xa, "offsetof(SEL,iwpAct)");
_Static_assert(offsetof(SEL, scan) == 0xc, "offsetof(SEL,scan)");
_Static_assert(offsetof(SEL, fl) == 0x1c, "offsetof(SEL,fl)");
_Static_assert(offsetof(SEL, pl) == 0x98, "offsetof(SEL,pl)");
_Static_assert(offsetof(SEL, th) == 0xd0, "offsetof(SEL,th)");
#endif

/* typind 4910 (0x132e) size=128 */
typedef struct _xfer
{
    int16_t id;    /* +0x0000 */
    int16_t grobj; /* +0x0002 */
    union
    {
        FLEET fl;
        PLANET pl;
        THING th;
    }; /* +0x0004 */
} XFER;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(XFER) == 128, "sizeof(XFER)");
_Static_assert(offsetof(XFER, id) == 0x0, "offsetof(XFER,id)");
_Static_assert(offsetof(XFER, grobj) == 0x2, "offsetof(XFER,grobj)");
_Static_assert(offsetof(XFER, fl) == 0x4, "offsetof(XFER,fl)");
_Static_assert(offsetof(XFER, pl) == 0x4, "offsetof(XFER,pl)");
_Static_assert(offsetof(XFER, th) == 0x4, "offsetof(XFER,th)");
#endif

/* typind 5226 (0x146a) size=22 */
typedef struct _rtwaypt
{
    int16_t id;     /* +0x0000 */
    int16_t iWaypt; /* +0x0002 */
    ORDER order;    /* +0x0004 */
} RTWAYPT;
#ifdef STARS_LAYOUT_CHECKS
_Static_assert(sizeof(RTWAYPT) == 22, "sizeof(RTWAYPT)");
_Static_assert(offsetof(RTWAYPT, id) == 0x0, "offsetof(RTWAYPT,id)");
_Static_assert(offsetof(RTWAYPT, iWaypt) == 0x2, "offsetof(RTWAYPT,iWaypt)");
_Static_assert(offsetof(RTWAYPT, order) == 0x4, "offsetof(RTWAYPT,order)");
#endif

/* typind 4291 (0x10c3) size=22 */
typedef struct _popupdata
{
    int16_t grPopup; /* +0x0000 */
    union
    {
        int32_t rgi[5];
        int16_t dxOut;
        int16_t iPlayer;
        int16_t idPlan;
        int16_t idPlanet;
        FLEET *lpfl;
        SHDEF *lpshdef;
        PART part;
        int16_t cMax;
        int16_t iPlanetVar;
        char *psz;
        int16_t cCur;
        int16_t fRedDamage;
        int16_t fShowDamage;
        int16_t iPlanVal;
        int16_t cOperate;
        int16_t dxDamage;
        int16_t fHideCounts;
        int16_t iPlanMin;
        int16_t fFactory;
        int16_t fToken;
        uint16_t grbit;
        int16_t iPlanMax;
        int16_t fSummary;
        int16_t iPlrVal;
        int16_t iPlrMin;
        int16_t itok;
        int16_t iPlrMax;
    }; /* +0x0002 */
} POPUPDATA;

/* typind 5042 (0x13b2) size=2 */
typedef struct _obj
{
    union
    {
        PLANET *ppl;
        FLEET *pfl;
        THING *pth;
    }; /* +0x0000 */
} OBJ;

/* typind 5046 (0x13b6) size=16 */
typedef struct _tile
{
    int16_t yTop;                               /* +0x0000 */
    int16_t dyFull;                             /* +0x0002 */
    int16_t grbit;                              /* +0x0004 */
    void (*pfn)(uint16_t, struct _tile *, OBJ); /* +0x0006 */
    union
    {
        struct
        {
            uint16_t iCol : 3;
            uint16_t id : 4;
            uint16_t fPopped : 1;
            uint16_t fNullPtr : 1;
            uint16_t fMinTitle : 1;
            uint16_t fErase : 1;
            uint16_t fFixCtls : 1;
            uint16_t fMinDraw : 1;
            uint16_t : 3;
        };
        uint16_t wRaw_000a;
    }; /* +0x000a */
    uint16_t fUnused : 4; /* +0x000c */
    uint16_t idh;         /* +0x000e */
} TILE;

#pragma pack(pop)
#endif /* STARS_NB09_TYPES_H */
