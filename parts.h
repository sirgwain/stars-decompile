#ifndef PARTS_H_
#define PARTS_H_

#include "types.h"

typedef enum iengine
{
    iengineSettlersDelight = 0,
    iengineQuickJump5 = 1,
    iengineFuelMizer = 2,
    iengineLongHump6 = 3,
    iengineDaddyLongLegs7 = 4,
    iengineAlphaDrive8 = 5,
    iengineTransGalacticDrive = 6,
    iengineInterspace10 = 7,
    iengineEnigmaPulsar = 8,
    iengineTransStar10 = 9,
    iengineRadiatingHydroRamScoop = 10,
    iengineSubGalacticFuelScoop = 11,
    iengineTransGalacticFuelScoop = 12,
    iengineTransGalacticSuperScoop = 13,
    iengineTransGalacticMizerScoop = 14,
    iengineGalaxyScoop = 15,
    iengineCount = 16,
} iengine;

typedef enum iarmor
{
    iarmorTritanium = 0,
    iarmorCrobmnium = 1,
    iarmorCarbonicArmor = 2,
    iarmorStrobnium = 3,
    iarmorOrganicArmor = 4,
    iarmorKelarium = 5,
    iarmorFieldedKelarium = 6,
    iarmorDepletedNeutronium = 7,
    iarmorNeutronium = 8,
    iarmorMegaPolyShell = 9,
    iarmorValanium = 10,
    iarmorSuperlatanium = 11,
    iarmorCount = 12,
} iarmor;

typedef enum iscanner
{
    iscannerBatScanner = 0,
    iscannerRhinoScanner = 1,
    iscannerMoleScanner = 2,
    iscannerDNAScanner = 3,
    iscannerPossumScanner = 4,
    iscannerPickPocketScanner = 5,
    iscannerChameleonScanner = 6,
    iscannerFerretScanner = 7,
    iscannerDolphinScanner = 8,
    iscannerGazelleScanner = 9,
    iscannerRNAScanner = 10,
    iscannerCheetahScanner = 11,
    iscannerElephantScanner = 12,
    iscannerEagleEyeScanner = 13,
    iscannerRobberBaronScanner = 14,
    iscannerPeerlessScanner = 15,
    iscannerCount = 16,
} iscanner;

typedef enum ishield
{
    ishieldMoleSkinShield = 0,
    ishieldCowHideShield = 1,
    ishieldWolverineDiffuseShield = 2,
    ishieldCrobySharmor = 3,
    ishieldShadowShield = 4,
    ishieldBearNeutrinoBarrier = 5,
    ishieldLangstonShell = 6,
    ishieldGorillaDelagator = 7,
    ishieldElephantHideFortress = 8,
    ishieldCompletePhaseShield = 9,
    ishieldCount = 10,
} ishield;

typedef enum ispecialE
{
    ispecialETransportCloaking = 0,
    ispecialEStealthCloak = 1,
    ispecialESuperStealthCloak = 2,
    ispecialEUltraStealthCloak = 3,
    ispecialEMultiFunctionPod = 4,
    ispecialEBattleComputer = 5,
    ispecialEBattleSuperComputer = 6,
    ispecialEBattleNexus = 7,
    ispecialEJammer10 = 8,
    ispecialEJammer20 = 9,
    ispecialEJammer30 = 10,
    ispecialEJammer50 = 11,
    ispecialEEnergyCapacitor = 12,
    ispecialEFluxCapacitor = 13,
    ispecialEEnergyDampener = 14,
    ispecialETachyonDetector = 15,
    ispecialEAntiMatterGenerator = 16,
    ispecialECount = 17,
} ispecialE;

typedef enum ispecialM
{
    ispecialMColonizationModule = 0,
    ispecialMOrbitalConstructionModule = 1,
    ispecialMCargoPod = 2,
    ispecialMSuperCargoPod = 3,
    ispecialMMultiCargoPod = 4,
    ispecialMFuelTank = 5,
    ispecialMSuperFuelTank = 6,
    ispecialMManeuveringJet = 7,
    ispecialMOverthruster = 8,
    ispecialMJumpGate = 9,
    ispecialMBeamDeflector = 10,
    ispecialMCount = 11,
} ispecialM;

typedef enum imines
{
    iminesMineDispenser40 = 0,
    iminesMineDispenser50 = 1,
    iminesMineDispenser80 = 2,
    iminesMineDispenser130 = 3,
    iminesHeavyDispenser50 = 4,
    iminesHeavyDispenser110 = 5,
    iminesHeavyDispenser200 = 6,
    iminesSpeedTrap20 = 7,
    iminesSpeedTrap30 = 8,
    iminesSpeedTrap50 = 9,
    iminesCount = 10,
} imines;

typedef enum imining
{
    iminingRoboMidgetMiner = 0,
    iminingRoboMiniMiner = 1,
    iminingRoboMiner = 2,
    iminingRoboMaxiMiner = 3,
    iminingRoboSuperMiner = 4,
    iminingRoboUltraMiner = 5,
    iminingAlienMiner = 6,
    iminingOrbitalAdjuster = 7,
    iminingCount = 8,
} imining;

typedef enum iplanetary
{
    iplanetaryViewer50 = 0,
    iplanetaryViewer90 = 1,
    iplanetaryScoper150 = 2,
    iplanetaryScoper220 = 3,
    iplanetaryScoper280 = 4,
    iplanetarySnooper320X = 5,
    iplanetarySnooper400X = 6,
    iplanetarySnooper500X = 7,
    iplanetarySnooper620X = 8,
    iplanetarySDI = 9,
    iplanetaryMissileBattery = 10,
    iplanetaryLaserBattery = 11,
    iplanetaryPlanetaryShield = 12,
    iplanetaryNeutronShield = 13,
    iplanetaryGenesisDevice = 14,
    iplanetaryCount = 15,
} iplanetary;

typedef enum iterra
{
    iterraTotalTerraform3 = 0,
    iterraTotalTerraform5 = 1,
    iterraTotalTerraform7 = 2,
    iterraTotalTerraform10 = 3,
    iterraTotalTerraform15 = 4,
    iterraTotalTerraform20 = 5,
    iterraTotalTerraform25 = 6,
    iterraTotalTerraform30 = 7,
    iterraGravityTerraform3 = 8,
    iterraGravityTerraform7 = 9,
    iterraGravityTerraform11 = 10,
    iterraGravityTerraform15 = 11,
    iterraTempTerraform3 = 12,
    iterraTempTerraform7 = 13,
    iterraTempTerraform11 = 14,
    iterraTempTerraform15 = 15,
    iterraRadiationTerraform3 = 16,
    iterraRadiationTerraform7 = 17,
    iterraRadiationTerraform11 = 18,
    iterraRadiationTerraform15 = 19,
    iterraCount = 20,
} iterra;

typedef enum ibomb
{
    ibombLadyFingerBomb = 0,
    ibombBlackCatBomb = 1,
    ibombM70Bomb = 2,
    ibombM80Bomb = 3,
    ibombCherryBomb = 4,
    ibombLBU17Bomb = 5,
    ibombLBU32Bomb = 6,
    ibombLBU74Bomb = 7,
    ibombHushABoom = 8,
    ibombRetroBomb = 9,
    ibombSmartBomb = 10,
    ibombNeutronBomb = 11,
    ibombEnrichedNeutronBomb = 12,
    ibombPeerlessBomb = 13,
    ibombAnnihilatorBomb = 14,
    ibombCount = 15,
} ibomb;

typedef enum itorp
{
    itorpAlphaTorpedo = 0,
    itorpBetaTorpedo = 1,
    itorpDeltaTorpedo = 2,
    itorpEpsilonTorpedo = 3,
    itorpRhoTorpedo = 4,
    itorpUpsilonTorpedo = 5,
    itorpOmegaTorpedo = 6,
    itorpAntiMatterTorpedo = 7,
    itorpJihadMissile = 8,
    itorpJuggernautMissile = 9,
    itorpDoomsdayMissile = 10,
    itorpArmageddonMissile = 11,
    itorpCount = 12,
} itorp;

typedef enum ibeam
{
    ibeamLaser = 0,
    ibeamXRayLaser = 1,
    ibeamMiniGun = 2,
    ibeamYakimoraLightPhaser = 3,
    ibeamBlackjack = 4,
    ibeamPhaserBazooka = 5,
    ibeamPulsedSapper = 6,
    ibeamColloidalPhaser = 7,
    ibeamGatlingGun = 8,
    ibeamMiniBlaster = 9,
    ibeamBludgeon = 10,
    ibeamMarkIVBlaster = 11,
    ibeamPhasedSapper = 12,
    ibeamHeavyBlaster = 13,
    ibeamGatlingNeutrinoCannon = 14,
    ibeamMyopicDisruptor = 15,
    ibeamBlunderbuss = 16,
    ibeamDisruptor = 17,
    ibeamMultiContainedMunition = 18,
    ibeamSyncroSapper = 19,
    ibeamMegaDisruptor = 20,
    ibeamBigMuthaCannon = 21,
    ibeamStreamingPulverizer = 22,
    ibeamAntiMatterPulverizer = 23,
    ibeamCount = 24,
} ibeam;

typedef enum ispecialSB
{
    ispecialSBStargate100250 = 0,
    ispecialSBStargateAny300 = 1,
    ispecialSBStargate150600 = 2,
    ispecialSBStargate300500 = 3,
    ispecialSBStargate100Any = 4,
    ispecialSBStargateAny800 = 5,
    ispecialSBStargateAnyAny = 6,
    ispecialSBMassDriver5 = 7,
    ispecialSBMassDriver6 = 8,
    ispecialSBMassDriver7 = 9,
    ispecialSBSuperDriver8 = 10,
    ispecialSBSuperDriver9 = 11,
    ispecialSBUltraDriver10 = 12,
    ispecialSBUltraDriver11 = 13,
    ispecialSBUltraDriver12 = 14,
    ispecialSBUltraDriver13 = 15,
    ispecialSBCount = 16,
} ispecialSB;

typedef enum GrbitTrader
{
    grbitTraderNone = 0x0000,
    grbitTraderCargo = 0x0001,
    grbitTraderSpecial = 0x0002,
    grbitTraderShield = 0x0004,
    grbitTraderArmor = 0x0008,
    grbitTraderMiner = 0x0010,
    grbitTraderBomb = 0x0020,
    grbitTraderTorp = 0x0040,
    grbitTraderBeam = 0x0080,
    grbitTraderHull = 0x0100,
    grbitTraderEngine = 0x0200,
    grbitTraderGenesis = 0x0400,
    grbitTraderJumpgate = 0x0800,
    grbitTraderLifeboat = 0x1000,
    grbitTraderAll = 0x1fff,
} GrbitTrader;

typedef enum LookupResult
{
    LookupInvalid = 0,     // “out of range” / not a valid part id in group
    LookupDisallowed = -1, // disallowed for race/trait/other rule
    LookupOk = 1,          // meets tech reqs (original CheckTechRequirements == 1)
    LookupNear = 2,        // “one level away in current research field”
    LookupNeedMany = 99    // multiple tech deficits
} LookupResult;

/* globals */
extern ENGINE rgengine[16];       /* MEMORY_PARTS:0x0000 */
extern ARMOR rgarmor[12];         /* MEMORY_PARTS:0x04e0 */
extern SCANNER rgscanner[16];     /* MEMORY_PARTS:0x0768 */
extern SHIELD rgshield[10];       /* MEMORY_PARTS:0x0ae8 */
extern SPECIAL rgspecialE[17];    /* MEMORY_PARTS:0x0d04 */
extern SPECIAL rgspecialM[11];    /* MEMORY_PARTS:0x109a */
extern MINES rgmines[10];         /* MEMORY_PARTS:0x12ec */
extern MINING rgmining[8];        /* MEMORY_PARTS:0x1508 */
extern PLANETARY rgplanetary[15]; /* MEMORY_PARTS:0x16b8 */
extern TERRA rgterra[20];         /* MEMORY_PARTS:0x19e2 */
extern BOMB rgbomb[15];           /* MEMORY_PARTS:0x1e1a */
extern TORP rgtorp[12];           /* MEMORY_PARTS:0x2180 */
extern BEAM rgbeam[24];           /* MEMORY_PARTS:0x2450 */
extern HULDEF rghuldef[32];       /* MEMORY_PARTS:0x29f0 */
extern SHDEF rgshdefT[22];        /* MEMORY_PARTS:0x3bd0 */
extern HULDEF rghuldefSB[5];      /* MEMORY_PARTS:0x4872 */
extern SHDEF rgshdefSBT[4];       /* MEMORY_PARTS:0x4b3e */
extern SPECIALSB rgspecialSB[16]; /* MEMORY_PARTS:0x4d8a */

/* functions */
void LookupBestPlanetaryScanner(PART *ppart);                          /* MEMORY_PARTS:0x60be */
int16_t FLookupPart(PART *ppart);                                      /* MEMORY_PARTS:0x524e */
HULDEF *LphuldefFromId(HullDef id); /* RETFAR */                       /* MEMORY_PARTS:0x512c */
int16_t TechStatus(char *rgTech);                                      /* MEMORY_PARTS:0x6148 */
HULDEF *LphuldefSBFromId(int16_t id); /* RETFAR */                     /* MEMORY_PARTS:0x510a */
SHDEF *LpshdefT(void); /* RETFAR */                                    /* MEMORY_PARTS:0x51ac */
PLANETARY *LpplanetaryFromId(int16_t id); /* RETFAR */                 /* MEMORY_PARTS:0x51dc */
SHDEF *LpshdefSBT(void); /* RETFAR */                                  /* MEMORY_PARTS:0x51c4 */
int16_t FLookupPartX(PART *ppart, HullSlotType grhst, uint16_t iItem); /* MEMORY_PARTS:0x51fe */
SCANNER *LpscannerFromId(int16_t id); /* RETFAR */                     /* MEMORY_PARTS:0x518a */
ENGINE *LpengineFromId(int16_t id); /* RETFAR */                       /* MEMORY_PARTS:0x5168 */

#endif /* PARTS_H_ */
