# Decompilation Priorities

## Priority Levels

- **P1 (Critical)**: Core game logic, required for understanding other code
- **P2 (High)**: Important game mechanics
- **P3 (Medium)**: Supporting systems
- **P4 (Low)**: UI, polish, non-essential

## P1: Core Utility Functions

These functions are called throughout the codebase and understanding them first unlocks other functions.

### Lookup Functions (util.c)

- [x] `LpplFromId()` - Get planet by ID
- [x] `LpflFromId()` - Get fleet by ID
- [x] `LpthFromId()` - Get thing by ID
- [x] `PszGetLocName()` - Get location name string

### Memory Functions (memory.c)

- [x] `LpAlloc()` - Memory allocation
- [x] `LpReAlloc()` - Reallocate memory
- [x] `LphbAlloc()` - Allocate handle
- [x] `LphbReAlloc()` - Reallocate handle

### Math/Random (utilgen.c)

- [x] `Random()` - Random number generator
- [x] `Randomize()` - Seed RNG
- [x] `LDistance2()` - Distance squared between points

## P2: Core Game Logic

### Turn Generation (turn.c, turn2.c, turn3.c)

- [ ] `FGenerateTurn()` - Main turn generation
- [ ] `MoveFleets()` - Fleet movement
- [ ] `DoOrders()` - Process waypoint orders
- [ ] `FuelFleets()` - Refuel at planets

### Combat (battle.c)

- [ ] `DoBattle()` - Main battle resolution
- [ ] `DamageShip()` - Apply damage to ship
- [ ] `FireWeapon()` - Weapon firing logic
- [ ] `CalcInitiative()` - Battle initiative

### Production (produce.c)

- [ ] `DoProduction()` - Process production queues
- [ ] `CalcResCost()` - Calculate resource cost
- [ ] `CompleteItem()` - Complete production item

### Planet Logic (planet.c)

- [ ] `GrowPopulation()` - Population growth
- [ ] `DoMining()` - Local mining
- [ ] `CalcPlanetValue()` - Planet habitability value
- [ ] `Terraform()` - Apply terraforming

## P3: Ship Systems

### Ship Management (ship.c, ship2.c)

- [ ] `CalcFleetMass()` - Total fleet mass
- [ ] `CalcFleetFuel()` - Fleet fuel consumption
- [ ] `MergeFleets()` - Merge two fleets
- [ ] `SplitFleet()` - Split fleet

### Scanner Logic (scan.c)

- [ ] `UpdateScanner()` - Update scanner view
- [ ] `CalcScanRange()` - Calculate scan range
- [ ] `FCanSee()` - Visibility check

### Mining/Minerals (mine.c)

- [ ] `DoRemoteMining()` - Remote mining operations
- [ ] `LayMines()` - Lay minefields
- [ ] `SweepMines()` - Mine sweeping

## P4: AI System

### AI Controller (ai.c - ai4.c)

- [ ] `DoAiTurn()` - Main AI entry
- [ ] `AiEvaluatePlanet()` - Planet scoring
- [ ] `AiBuildFleet()` - Fleet construction
- [ ] `AiSelectTarget()` - Target selection

### AI Utilities (aiutil.c)

- [ ] `AiCalcThreat()` - Threat assessment
- [ ] `AiNeedDefense()` - Defense needs
- [ ] `AiPlanResearch()` - Research planning

## P5: File I/O

### Save/Load (save.c, file.c)

- [ ] `FSaveGame()` - Save game state
- [ ] `FLoadGame()` - Load game state
- [ ] `WriteRecord()` - Write file record
- [ ] `ReadRecord()` - Read file record

### Log Files (log.c)

- [ ] `WriteLog()` - Write turn log
- [ ] `ReadLog()` - Read turn log
- [ ] `ApplyLogEntry()` - Apply log change

## Recommended Approach

### Phase 1: Foundation (Week 1)

1. Complete all P1 utility functions
2. These will make other functions readable

### Phase 2: Core Mechanics (Week 2-3)

1. Production system (simpler logic)
2. Planet operations
3. Ship calculations

### Phase 3: Complex Systems (Week 4+)

1. Turn generation
2. Combat system
3. AI behavior

## Function Complexity Indicators

Look for these to estimate difficulty:

- **Simple**: Few local variables, short function, no loops
- **Medium**: Some loops, moderate local count, clear flow
- **Complex**: Many locals, nested loops, state machines
- **Very Complex**: Assembly-level optimizations, bitfield magic

## Already Implemented

Run `mise run track-implementation` for current status. Key completions:

- `parts.c` - All ship component data arrays (100%)
- `memory.c` - Memory management functions (100%)
- `file.c` - File I/O operations (90.9%)
- `util.c` - Core utilities including `LpplFromId`, `LpflFromId`, `LpthFromId` (23.9%)
- `utilgen.c` - Generic utilities including `Random`, formatting (26.0%)
- `msg.c` - Message system functions (32.1%)

Use `mise run call-graph -- unimplemented -f <FunctionName>` to see what's needed for a function.
