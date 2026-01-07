# Stars! Data Structures

## Core Entity Structures

### PLANET (56 bytes)

The planet structure stores all information about a planetary body.

```c
typedef struct _planet {
    int16_t id;              // Planet ID (0-999)
    int16_t iPlayer;         // Owning player (-1 if uninhabited)

    // Bitfield flags (16 bits)
    uint16_t det : 8;        // Detection level (scanner info)
    uint16_t fInclude : 1;   // Include in reports
    uint16_t fStarbase : 1;  // Has a starbase
    uint16_t fHomeworld : 1; // Is a homeworld
    uint16_t fFirstYear : 1; // First year of colonization
    uint16_t fWasInhabited : 1; // Was previously inhabited

    uint8_t rgpctMinLevel[3];  // Mineral concentration levels (Ir, Bo, Ge)
    uint8_t rgMinConc[3];      // Current mineral concentrations
    char rgEnvVar[3];          // Environment (Grav, Temp, Rad) -50 to +50
    char rgEnvVarOrig[3];      // Original environment (before terraform)

    // Population/defense guesses for enemy planets
    uint16_t uPopGuess : 12;
    uint16_t uDefGuess : 4;

    // Infrastructure (packed bitfield)
    uint32_t iDeltaPop : 8;    // Population change indicator
    uint32_t cMines : 12;      // Number of mines
    uint32_t cFactories : 12;  // Number of factories

    // More infrastructure
    uint32_t cDefenses : 12;   // Number of defenses
    uint32_t iScanner : 5;     // Planetary scanner type
    uint32_t fArtifact : 1;    // Has ancient artifact
    uint32_t fNoResearch : 1;  // Research disabled for planet

    int32_t rgwtMin[4];        // Minerals on hand (Ir, Bo, Ge, ?)

    // Starbase info
    uint16_t isb : 4;          // Starbase design index
    uint16_t pctDp : 12;       // Starbase damage percent

    // Mass driver
    uint16_t idFling : 10;     // Target planet for mass driver
    uint16_t iWarpFling : 4;   // Packet speed
    uint16_t fNoHeal : 1;      // Starbase cannot repair

    // Routing
    uint16_t idRoute : 10;     // Planet for fleet routing

    int16_t turn;              // Last turn planet was seen
    PLPROD *lpplprod;          // Production queue pointer
} PLANET;
```

### FLEET (structure inferred from usage)

```c
typedef struct _fleet {
    int16_t id;                // Fleet ID
    int16_t iPlayer;           // Owning player
    POINT pt;                  // Location (x, y coordinates)
    int16_t warp;              // Current warp speed
    int32_t fuel;              // Fuel on board (mg)
    int32_t cargo[5];          // Cargo (Ir, Bo, Ge, Colonists, ?)
    ORDER *orders;             // Waypoint orders
    // ... more fields
} FLEET;
```

### SHDEF - Ship Definition (148 bytes)

Ship design template.

```c
typedef struct _shdef {
    int16_t ishdef;            // Design slot index
    int16_t iPlayer;           // Owning player
    int16_t ihul;              // Hull type
    char szName[32];           // Design name
    int16_t cBuilt;            // Number built
    int16_t cExist;            // Number existing
    int16_t cMass;             // Total mass
    int32_t fuel;              // Fuel capacity
    int16_t cargo;             // Cargo capacity
    // ... slot contents
    HS rghs[16];               // Hull slots with equipment
    // ... more fields
} SHDEF;
```

### GAME (64 bytes)

Global game settings.

```c
typedef struct _game {
    int32_t lid;               // Game ID (long)
    int16_t mdSize;            // Universe size mode
    int16_t mdDensity;         // Planet density mode
    int16_t cPlayer;           // Number of players
    int16_t cPlanMax;          // Maximum planets
    int16_t mdStartDist;       // Starting distance mode
    int16_t fDirty;            // Unsaved changes flag

    // Game options bitfield
    uint16_t fExtraFuel : 1;   // Accelerated BBS play
    uint16_t fSlowTech : 1;    // Slow tech advance
    uint16_t fSinglePlr : 1;   // Single player game
    uint16_t fTutorial : 1;    // Tutorial mode
    uint16_t fAisBand : 1;     // AI players banded together
    uint16_t fBBSPlay : 1;     // BBS play mode
    uint16_t fVisScores : 1;   // Scores visible
    uint16_t fNoRandom : 1;    // No random events
    uint16_t fClumping : 1;    // Planet clumping enabled
    uint16_t wGen : 3;         // Generation counter

    uint16_t turn;             // Current game year (turn)
    uint8_t rgvc[12];          // Victory conditions
    char szName[32];           // Game name
} GAME;
```

### PLAYER (192 bytes)

Player/race data.

```c
typedef struct _player {
    // Race traits and abilities
    int16_t grfTraits;         // Primary racial traits bitmask
    int16_t grfLRT;            // Lesser racial traits bitmask

    // Habitability ranges
    int8_t rgGravMin, rgGravMax;
    int8_t rgTempMin, rgTempMax;
    int8_t rgRadMin, rgRadMax;

    // Technology levels
    int16_t rgTech[6];         // Current tech (Ene, Wep, Prop, Con, Ele, Bio)
    int16_t rgResSpent[6];     // Resources spent per tech
    int16_t rgTechTarget;      // Research allocation

    // Race settings
    int16_t growthRate;        // Population growth rate
    int16_t popEfficiency;     // Population efficiency
    int16_t factEfficiency;    // Factory efficiency
    int16_t factCost;          // Factory cost
    int16_t mineEfficiency;    // Mine efficiency
    int16_t mineCost;          // Mine cost

    // Diplomacy
    int16_t rgRelation[16];    // Relations with other players

    char szRaceName[32];       // Race name
    char szPassword[16];       // Player password (hashed)

    // Statistics
    SCORE score;               // Current score
    // ... more fields
} PLAYER;
```

## Battle Structures

### BTLPLAN (36 bytes)

Battle plan configuration.

```c
typedef struct _btlplan {
    uint16_t iplr : 4;         // Player ID
    uint16_t iplan : 4;        // Plan index (0-15)
    uint16_t mdTactic : 4;     // Tactic mode
    uint16_t fDelete : 1;      // Delete plan flag
    uint16_t fDumpCargo : 1;   // Dump cargo before battle

    uint16_t mdTarget1 : 4;    // Primary target type
    uint16_t mdTarget2 : 4;    // Secondary target type
    uint16_t iplrAttack : 5;   // Specific player to attack

    char szName[32];           // Plan name
} BTLPLAN;
```

### Target Types (mdTarget)
- 0: None
- 1: Any
- 2: Starbase
- 3: Armed Ships
- 4: Bombers
- 5: Unarmed Ships
- 6: Fuel Transports
- 7: Freighters

### Tactic Modes (mdTactic)
- 0: Disengage
- 1: Disengage if challenged
- 2: Minimize damage
- 3: Maximize damage
- 4: Maximize damage ratio

## Production Structures

### PROD (4 bytes)

Single production queue item.

```c
typedef struct _prod {
    uint32_t cItem : 10;   // Quantity to build
    uint32_t iItem : 7;    // Item index
    uint32_t grobj : 3;    // Object type (ship, defense, etc.)
    uint32_t pct : 7;      // Percent complete
} PROD;
```

### Object Types (grobj)
- 0: Ship design
- 1: Starbase
- 2: Scanner
- 3: Defense
- 4: Terraform
- 5: Mineral alchemy
- 6: Factory
- 7: Mine

## Thing Structures

"Things" are miscellaneous space objects: minefields, mineral packets, wormholes, mystery traders.

### THING (base structure)

```c
typedef struct _thing {
    int16_t id;            // Thing ID
    int16_t iPlayer;       // Owning player
    int16_t iType;         // Thing type
    POINT pt;              // Location
    union {
        THMINE mine;       // Minefield data
        THPACK pack;       // Mineral packet data
        THWORM worm;       // Wormhole data
        THTRADER trader;   // Mystery Trader data
    };
} THING;
```

### THMINE (10 bytes) - Minefield

```c
typedef struct _thmine {
    int32_t cMines;        // Number of mines in field
    uint16_t grbitPlr;     // Players who can see it
    uint8_t iType;         // Mine type (normal/heavy/speed)
    uint8_t fDetonate;     // Will detonate next turn
    uint16_t grbitPlrNow;  // Players currently in field
} THMINE;
```

### THPACK (10 bytes) - Mineral Packet

```c
typedef struct _thpack {
    uint16_t idPlanet : 10;    // Target planet
    uint16_t iWarp : 4;        // Current speed
    uint16_t fMoved : 1;       // Has moved this turn
    uint16_t fInclude : 1;     // Include in reports
    int16_t rgwtMin[3];        // Minerals (Ir, Bo, Ge)
    uint16_t wtMax : 14;       // Maximum weight
    uint16_t iDecayRate : 2;   // Decay rate modifier
} THPACK;
```

## File Format Structures

### RTBOF (16 bytes) - Record Type Beginning of File

File header for all Stars! files.

```c
typedef struct _rtbof {
    char rgid[4];          // "J3D1" magic number
    int32_t lidGame;       // Game ID
    uint16_t verInc : 5;   // Incremental version
    uint16_t verMinor : 7; // Minor version
    uint16_t verMajor : 4; // Major version (2)
    uint16_t turn;         // Current turn
    int16_t iPlayer : 5;   // Player number
    int16_t lSaltTime : 11;// Salt/time value
    uint16_t dt : 8;       // Document type
    uint16_t fDone : 1;    // Turn submitted
    uint16_t fInUse : 1;   // File in use
    uint16_t fMulti : 1;   // Multiplayer game
    uint16_t fGameOverMan : 1; // Game has ended
    uint16_t fCrippled : 1;// Crippled/demo mode
    uint16_t wGen : 3;     // Generation counter
} RTBOF;
```

### Document Types (dt)
- 0: .xy file (universe definition)
- 1: .x# file (turn order/submitted)
- 2: .hst file (host file)
- 3: .m# file (player turn)
- 4: .h# file (history file)
- 5: .r# file (race file)

**Source:** `SetSzWorkFromDt` function in io_writefile.c/io_loadgame.c

## Score Structure

### SCORE (20 bytes)

```c
typedef struct _score {
    int32_t lScore;        // Total score
    int32_t cResources;    // Total resources
    int16_t cPlanet;       // Planets owned
    int16_t cStarbase;     // Starbases owned
    uint16_t rgcsh[3];     // Ship counts by type
    int16_t cTechLevels;   // Total tech levels
} SCORE;
```

## Message Structures

### MSGHDR (4 bytes)

```c
typedef struct _msghdr {
    uint16_t iMsg : 9;     // Message type ID
    uint16_t grWord : 7;   // Word flags
    int16_t wGoto;         // Jump-to location (planet/fleet)
} MSGHDR;
```

### MSGBIG (18 bytes)

Extended message with parameters.

```c
typedef struct _msgbig {
    int16_t iMsg;          // Message type
    int16_t wGoto;         // Jump-to location
    int16_t rgParam[7];    // Message parameters
} MSGBIG;
```
