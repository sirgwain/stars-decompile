
#include "types.h"

#include "turn3.h"

/* functions */
void SatisfyOrders(int16_t iPass)
{
    int16_t fMining;
    int32_t amountWP;
    int16_t action;
    PLANET pl;
    int32_t l2;
    int16_t j;
    int32_t amount;
    int16_t iflWP;
    int16_t fSentBadFleetXfer;
    int16_t ifltcur;
    FLEET * lpfl;
    int16_t fAtPlanet;
    int16_t idm;
    int16_t iLoad;
    uint16_t xWP;
    int16_t fOptFuel;
    int16_t fStealing;
    FLEET * lpflWP;
    int16_t fHasPermission;
    int16_t fFulfilled;
    ORDER ord;
    int16_t fFueling;
    int32_t wtOptimalFuel;
    int16_t fDunnage;
    int32_t amountEdit;
    int32_t l;
    int16_t fDone;
    uint16_t idWP;
    THING * lpthWP;
    int16_t ishLastFree;
    int32_t cFuel2;
    int32_t cMine;
    PLANET * lppl;
    FLEET * lpflDest;
    THING * lpthMac;
    int32_t lT;
    int32_t iExcess;
    uint16_t iGoto;
    int32_t dy;
    int32_t lMaxFuel;
    int32_t wtFuelOrig;
    SHDEF * lpshdefT;
    int32_t lXferMinerals;
    THING * lpthBest;
    int16_t i;
    THING * lpth;
    int32_t lAmt;
    int32_t rglQuan[4];
    int32_t lBest;
    int32_t dx;
    int16_t rgishMap[16];
    int16_t ishMatch;
    int16_t ish;
    FLEET * lpflNew;
    int16_t iplrDest;
    SHDEF * lpshdefDest;
    SHDEF shdefT;
    int16_t csh;
    int16_t fBleeding;
    int32_t lResUltimate;
    int16_t fUltimate;
    int16_t fColonize;
    int32_t rgwt[3];

    /* debug symbols */
    /* block (block) @ MEMORY_TURN:0x7b9d */
    /* block (block) @ MEMORY_TURN:0x7cd7 */
    /* block (block) @ MEMORY_TURN:0x7e1b */
    /* block (block) @ MEMORY_TURN:0x817a */
    /* block (block) @ MEMORY_TURN:0x8f10 */
    /* block (block) @ MEMORY_TURN:0x908f */
    /* block (block) @ MEMORY_TURN:0x91d1 */
    /* block (block) @ MEMORY_TURN:0x9339 */
    /* block (block) @ MEMORY_TURN:0x96da */
    /* block (block) @ MEMORY_TURN:0x999e */
    /* label NMNF @ MEMORY_TURN:0x91f5 */
    /* label LCantDrop @ MEMORY_TURN:0x781c */
    /* label LScrap @ MEMORY_TURN:0x8207 */
    /* label Unload @ MEMORY_TURN:0x77c4 */
    /* label Load @ MEMORY_TURN:0x7240 */
    /* label SellNoCap @ MEMORY_TURN:0x9556 */
    /* label SetOptAmount @ MEMORY_TURN:0x7eb0 */
    /* label CancelOrder @ MEMORY_TURN:0x8e65 */
    /* label LTryDunnage @ MEMORY_TURN:0x6cad */
    /* label FinishFleet @ MEMORY_TURN:0x807a */
    /* label LDoMerge @ MEMORY_TURN:0x91e2 */

    /* TODO: implement */
}
