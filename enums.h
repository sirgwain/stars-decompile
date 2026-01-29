#define fFalse 0
#define fTrue 1

#define iPlayerNil -1
#define cPlayerMax 16
#define cShdefMax 16
#define cDefenseCount 5
#define iPlanetPartNone -1

typedef enum CostType
{
    Ironium = 0,
    Boranium = 0,
    Germanium = 0,
    Resources = 0,
} CostType;

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

typedef enum HulDefSB
{
    ihuldefSBOrbitalFort = 0,
    ihuldefSBSpaceDock = 1,
    ihuldefSBSpaceStation = 2,
    ihuldefSBUltraStation = 3,
    ihuldefSBDeathStar = 4,
} HulDefSB;

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

typedef enum BattleUnitFlags
{
    /* Side selection */
    grBuOurUnits = 0x0001,   /* tok->iplr == idPlayer */
    grBuTheirUnits = 0x0002, /* tok->iplr != idPlayer */

    /* Object type selection */
    grBuIncludeSb = 0x0004, /* include starbases (ishdef >= 16) */

    /* Hull category filters (ships only; ishdef < 16) */
    grBuClassOther = 0x0008,  /* imdCategory < 2 or > 5 */
    grBuClassFight = 0x0010,  /* imdCategory == 2 */
    grBuClassBomber = 0x0020, /* imdCategory == 3 */
    grBuClassCap = 0x0040,    /* imdCategory == 5 */
    grBuClassFrig = 0x0080,   /* imdCategory == 4 */

    grBuClassAll = 0x00F8
} BattleUnitFlags;

typedef enum GrStat
{
    grStatFuel = 1,
    grStatCargo = 2,

} GrStat;

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
    LookupInvalid = 0,
    LookupDisallowed = -1,
    LookupOk = 1,
    LookupNear = 2,
    LookupNeedMany = 99
} LookupResult;

