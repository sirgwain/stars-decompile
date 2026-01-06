#ifndef TURN2_H_
#define TURN2_H_


#include "types.h"

/* functions */
void Produce(void);  /* MEMORY_TURN2:0x0000 */
void CreateBackupDir(void);  /* MEMORY_TURN2:0x6dca */
void ThingDecay(void);  /* MEMORY_TURN2:0x70c6 */
void DropColonists(void);  /* MEMORY_TURN2:0x34e2 */
void TossNonAutoBuildItems(PLANET *);  /* MEMORY_TURN2:0x5aec */
void UpdateResearchStatus(int16_t);  /* MEMORY_TURN2:0x80fe */
void RemoteTerraforming(void);  /* MEMORY_TURN2:0x4c56 */
void UpdatePopulations(void);  /* MEMORY_TURN2:0x50a0 */
void SweepForMines(void);  /* MEMORY_TURN2:0x76a4 */
void UpdatePlayerScores(void);  /* MEMORY_TURN2:0x6258 */
void UpdateGuesses(void);  /* MEMORY_TURN2:0x532c */
void MysteryTrader(void);  /* MEMORY_TURN2:0x5efa */
int16_t FQueueColonistDrop(FLEET *, PLANET *, int32_t);  /* MEMORY_TURN2:0x4faa */
int16_t CBuildProdItem(PLANET *, PROD *, PROD *, int32_t *, int16_t, int16_t *, int16_t);  /* MEMORY_TURN2:0x0c92 */
void AutoTerraform(void);  /* MEMORY_TURN2:0x48f6 */
int16_t FPacketDecay(THING *, int16_t);  /* MEMORY_TURN2:0x6e9c */
void TransferToOthers(void);  /* MEMORY_TURN2:0x3088 */
void MineMinerals(void);  /* MEMORY_TURN2:0x55a4 */
int16_t FBuildObject(PLANET *, int16_t, int16_t, int16_t, int32_t *);  /* MEMORY_TURN2:0x19b2 */
int16_t IBestRemoteTerra(PLANET *, int16_t, int16_t);  /* MEMORY_TURN2:0x8b70 */
void PlanetaryClimateChange(void);  /* MEMORY_TURN2:0x5c54 */
void DiscoverNewMinerals(void);  /* MEMORY_TURN2:0x5e0c */
void MeteorStrike(void);  /* MEMORY_TURN2:0x560e */
void HealShips(void);  /* MEMORY_TURN2:0x444c */
void CreateShip(int16_t, FLEET *, int16_t, int16_t);  /* MEMORY_TURN2:0x2fd6 */
void BreedColonistsInTransit(void);  /* MEMORY_TURN2:0x7e4e */
void RandomEvents(void);  /* MEMORY_TURN2:0x3064 */
void UnmarkMineFields(void);  /* MEMORY_TURN2:0x7638 */

#endif /* TURN2_H_ */
