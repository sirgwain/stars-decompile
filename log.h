#ifndef LOG_H_
#define LOG_H_

#include "types.h"

typedef enum RecordTypeLog {
    /* Log record type 0 is effectively a no-op / padding record in FRunLogRecord. */
    rtLogNop = 0x00,

    /* Cargo transfer between objects (source encoded in low nibble of lpb[4],
       destination encoded in high nibble of lpb[4]). The three variants differ
       by quantity encoding size. */
    rtLogCargoXfer8 = 0x01,  /* quantities are int8  (lpb[6+iLook]) */
    rtLogCargoXfer16 = 0x02, /* quantities are int16 (lpb[6+2*iLook]) */
    rtLogCargoXfer32 = 0x19, /* quantities are int32 (lpb[6+4*iLook]) */

    /* Fleet orders list edits (lpfl->lpplord entries are 0x12 bytes each). */
    rtLogFleetOrderDelete = 0x03, /* delete 1 or 2 orders; index in *(u16*)(lpb+2), high bit => delete extra */
    rtLogFleetOrderInsert = 0x04, /* insert new order at index *(i16*)(lpb+2); payload from lpb+4 */
    rtLogFleetOrderUpdate = 0x05, /* overwrite existing order at index *(i16*)(lpb+2); payload from lpb+4 */

    /* Fleet flags / small per-order attribute tweaks. */
    rtLogFleetFlagBit9 = 0x0A,     /* lpfl->wFlags_0x4 bit 9 set/cleared by (*(u16*)(lpb+2) & 1) */
    rtLogFleetOrderAttrNib = 0x0B, /* order[index].word10 low nibble set to (*(i16*)(lpb+4) & 0xF), value constrained <=9 */

    /* Fleet↔fleet cargo balancing transfer: 16 cargo slots, bitmask + signed deltas.
       Ends by FleetTransferCargoBalance(), marks fleets dirty, may delete emptied fleets. */
    rtLogFleetCargoXfer = 0x17,

    /* Fleet split / merge operations. */
    rtLogFleetSplit = 0x18, /* LpflNewSplit(&fleet) */
    rtLogFleetMerge = 0x25, /* merge all-at-location (cb==2) or merge listed fleet ids (cb>2) */

    /* Ship design definition (SHDEF) create/update/delete for the current player. */
    rtLogShDef = 0x1B,

    /* Planet production queue set/clear (planet->lpplprod). */
    rtLogPlanetProdQ = 0x1D,

    /* Battle plan set/update/delete (UnpackBattlePlan / FDeleteBattlePlan). */
    rtLogBattlePlan = 0x1E,

    /* Research settings: pctResearch + iTechCur (packed nibble fields). */
    rtLogResearch = 0x22,

    /* Planet routing / starbase / infrastructure bitfields mutation. */
    rtLogPlanetRouting = 0x23,

    /* Host-only / protected-mode player fields. */
    rtLogPlayerSalt = 0x24, /* writes rgplr[idPlayer].lSalt when host-ish bit set */
    rtLogRelations = 0x26,  /* memcpy rgplr[idPlayer].rgmdRelation[0..cPlayer) */

    /* Fleet / thing misc settings. */
    rtLogFleetPlan = 0x2A,      /* lpfl->iplan = *(u16*)(lpb+2) truncated */
    rtLogThingByteParam = 0x2B, /* sets 1 byte inside THING union for a restricted subtype */

    /* User string (fleet rename); may be compressed via FDecompressUserString. */
    rtLogFleetName = 0x2C,

    /* Host-only opaque blob (size capped at 0x1A bytes) copied into rgplr[idPlayer].zpq1. */
    rtLogPlayerZpq1 = 0x2E,

    rtLogMax = 0x2F /* one past highest log rt observed in this function (0x2E) */
} RecordTypeLog;

/* functions */
void    WriteMemRt(int16_t rt, int16_t cb, void *rg);                                                       /* MEMORY_PLANET:0xa130 */
int16_t FWriteLogFile(char *pszFileBase, int16_t iPlayer);                                                  /* MEMORY_PLANET:0xcdf6 */
void    LogMergeFleet(int16_t id);                                                                          /* MEMORY_PLANET:0x8b6c */
int16_t FLoadLogFile(char *pszLog);                                                                         /* MEMORY_PLANET:0xc7a2 */
void    DirtyGame(int16_t fDirty);                                                                          /* MEMORY_PLANET:0xa228 */
void    LogSplitFleet(int16_t id);                                                                          /* MEMORY_PLANET:0x8b0e */
int16_t FWriteTutorialMFile(int16_t iTurn);                                                                 /* MEMORY_PLANET:0xd058 */
void    EnumLogRts(int16_t (*pfn)(void *, int16_t, int16_t, void *, int16_t), void *lpPass, int16_t iPass); /* MEMORY_PLANET:0xd6e0 */
int16_t FGetPrevLogRt(HDR *phdr, uint8_t *pb);                                                              /* MEMORY_PLANET:0xa25e */
void    LogChangeThing(THING *lpth, THING *pthNew);                                                         /* MEMORY_PLANET:0x9908 */
void    LogChangePlanet(PLANET *ppl, PLANET *pplNew);                                                       /* MEMORY_PLANET:0x9420 */
int16_t FCheckLogFile(int16_t iplr, int16_t *pfError);                                                      /* MEMORY_PLANET:0xcccc */
void    LogChangeBtlplan(BTLPLAN *pbtlplan);                                                                /* MEMORY_PLANET:0x93d0 */
void    LogChangeRelations(void);                                                                           /* MEMORY_PLANET:0x9340 */
int16_t FRunLogRecord(int16_t rt, int16_t cb, uint8_t *lpb);                                                /* MEMORY_PLANET:0xa38c */
int16_t FWriteHistFile(int16_t iPlayer);                                                                    /* MEMORY_PLANET:0xd29e */
void    CancelMemRt(int16_t rt);                                                                            /* MEMORY_PLANET:0xa108 */
void    LogMakeValidXferf(LOGXFERF *plxf1, LOGXFERF *plxf2);                                                /* MEMORY_PLANET:0x9fa6 */
int16_t FRunLogFile(void);                                                                                  /* MEMORY_PLANET:0xa2d6 */
void    LogMakeValidXfer(LOGXFER *plx1, LOGXFER *plx2);                                                     /* MEMORY_PLANET:0x99f6 */
void    LogChangeFleet(FLEET *pfl, FLEET *pflNew);                                                          /* MEMORY_PLANET:0x8ebe */
void    LogChangeName(GrobjClass grobj, int16_t id, char *szName);                                          /* MEMORY_PLANET:0x8d5a */
void    LogChangeShDef(SHDEF *lpshdefNew);                                                                  /* MEMORY_PLANET:0x8c28 */

#endif /* LOG_H_ */
