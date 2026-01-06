
#include "types.h"

#include "battle.h"

/* globals */
uint8_t rgbrcStart[136];  /* MEMORY_BATTLE:0x0000 */

/* functions */
int16_t FFleetHasTeeth(FLEET *lpfl)
{
    int16_t ishdef;

    /* TODO: implement */
    return 0;
}

void DropSalvage(THING * *plpth, int32_t *rgwtMinerals, int16_t iplr, POINT *ppt)
{
    int32_t wtTotal;
    int32_t wt;
    int16_t i;
    THING * lpth;

    /* TODO: implement */
}

void CheckTarget(TOK *ptok, FLEET *lpfl, int16_t ishdef)
{
    int16_t iplr;
    BTLPLAN * lpbtlplan;
    int16_t ibp;
    SHDEF * lpshdef;

    /* TODO: implement */
}

int16_t BattlePlansDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t (* lpProc)(void);
    int16_t idc;
    int16_t i;
    int16_t fRet;
    RECT rc;
    int16_t cLen;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x113e */
    /* label LSelectName @ MEMORY_BATTLE:0x14a5 */
    /* label LRename @ MEMORY_BATTLE:0x0f9c */

    /* TODO: implement */
    return 0;
}

int16_t NewPlanNameDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    RECT rc;

    /* TODO: implement */
    return 0;
}

void CreateSalvage(FLEET *pfl, THING * *plpth)
{
    int32_t wtTotal;
    SHDEF * lpshdefT;
    PLANET * lppl;
    int16_t i;
    int32_t rgwtMinerals[3];
    int16_t j;
    int16_t fBleeding;
    SHDEF shdefT;

    /* TODO: implement */
}

void DoBattles(int16_t fPostMovement)
{
    int16_t cplr;
    int16_t ifl;
    FLEET * lpfl;
    uint16_t grfSpectator;
    uint16_t grfPlayer;
    uint16_t rggrfAttack[16];

    /* TODO: implement */
}

void RandomizeTokOrder(void)
{
    TOK tok;
    int16_t itokSwap;
    int16_t itok;

    /* TODO: implement */
}

int16_t InitFromHuldef(HUL *lphul, int16_t *ppctBC)
{
    int16_t ihs;
    int16_t i;
    int16_t pct;
    int16_t initBase;
    int16_t cbc;
    int16_t pctBC;
    PART part;

    /* TODO: implement */
    return 0;
}

int32_t ScoreGuessBattleDamage(TOK *ptokSrc, uint8_t brc, int16_t fPrimary, uint16_t grfAttack)
{
    int16_t iBest;
    int16_t dMoves;
    int16_t rgy[2];
    TOK * ptok;
    int16_t yEnemy;
    int16_t dzEnemy;
    int32_t dpGivenBest;
    int32_t dpTakenBest;
    int16_t y;
    int32_t dpTakenTotal;
    int32_t dpGivenCur;
    int16_t i;
    int16_t xEnemy;
    int16_t yCur;
    int32_t dpTaken;
    int32_t scoreThemBest;
    int32_t scoreThem;
    int16_t dzCur;
    int16_t rgx[2];
    uint8_t brcEnemy;
    int32_t dpGiven;
    int16_t dMax;
    int32_t scoreUs;
    uint8_t iplrSrc;
    int16_t fWeAttack;
    int16_t xCur;
    int16_t x;
    int16_t dMin;
    int16_t itok;

    /* TODO: implement */
    return 0;
}

int16_t FAttackPlayer(FLEET *lpfl, int16_t iplr)
{
    int16_t iplrCur;
    int16_t iplrT;

    /* TODO: implement */
    return 0;
}

void CheckInitiative(TOK *ptok)
{
    SHDEF * lpshdef;
    int16_t pctBC;

    /* TODO: implement */
}

int16_t FDeleteBattlePlan(int16_t iplan, int16_t fWarn)
{
    int16_t fFoundBigger;
    int16_t iflMac;
    int16_t i;
    FLEET * lpfl;

    /* debug symbols */
    /* label LCommit @ MEMORY_BATTLE:0x1714 */

    /* TODO: implement */
    return 0;
}

void RegenShield(TOK *ptok)
{
    int32_t dpNew;
    int32_t dpOrig;

    /* TODO: implement */
}

int16_t FDumpCargo(FLEET *lpfl)
{
    POINT pt;
    PLANET * lppl;
    int16_t i;

    /* TODO: implement */
    return 0;
}

int32_t ScoreFromGiveAndTakeAndTactic(int32_t dpGive, int32_t dpTake, int16_t mdTactic)
{
    int32_t score;

    /* TODO: implement */
    return 0;
}

int16_t FAttack(int16_t itokAttacker, int16_t init, BTLREC *lpbtlrec, uint16_t grfAttack)
{
    int32_t dpShieldLeft;
    int16_t dz;
    SHDEF * lpshdefE;
    int32_t dpArmorLeft;
    int32_t dpSingle;
    int32_t scoreBest;
    TOK * ptok;
    int16_t ctokDamaged;
    int16_t itokTarget;
    int32_t dpMain;
    int32_t score;
    int16_t fSetItok;
    int16_t dxRangeCur;
    int16_t ihs;
    int32_t cTorpMiss;
    int32_t cTorpFire;
    int32_t cTorpsLeft;
    int16_t i;
    int32_t cTorpBase;
    uint16_t grfWeapon;
    int16_t cItem;
    int32_t pctHit;
    TOK * ptokTarget;
    SHDEF * lpshdef;
    int32_t lValue;
    int32_t dpT;
    HUL * lphul;
    int32_t cTorpHit;
    int16_t fPrimary;
    int32_t dp;
    int16_t itok;
    int32_t dpCol;
    TOK * ptokE;
    PART part;
    int32_t nds;
    int32_t dpShieldCur;
    int16_t fCapMissile;
    int32_t dpHitArmor;
    int32_t nts;
    int32_t ntk;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x726e */
    /* block (block) @ MEMORY_BATTLE:0x7a1a */
    /* label LFindAnotherTarget @ MEMORY_BATTLE:0x6e04 */

    /* TODO: implement */
    return 0;
}

int16_t RelationsDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t i;
    RECT rc;
    uint16_t hdc;
    int16_t mdSBase;
    PAINTSTRUCT ps;
    RECT rcGBox;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x019f */
    /* block (block) @ MEMORY_BATTLE:0x0464 */

    /* TODO: implement */
    return 0;
}

int16_t FHullHasTeeth(HUL *lphul)
{
    HS * lphs;
    int16_t ihs;

    /* TODO: implement */
    return 0;
}

int16_t FFleetHasBombs(FLEET *lpfl)
{
    HUL * lphul;
    int16_t imd;
    int16_t ishdef;

    /* TODO: implement */
    return 0;
}

int16_t DxyFromSpdRound(uint16_t spd, int16_t iRound)
{
    int16_t dxy;

    /* TODO: implement */
    return 0;
}

int32_t CTorpHit(int32_t cTorpBase, TOK *ptok, int16_t pctBase, int16_t pctBC)
{
    int32_t pctJam;
    int16_t i;
    int32_t pctHit;
    int32_t cTorpHit;

    /* TODO: implement */
    return 0;
}

int16_t FCanKillTok(TOK *ptok1, TOK *ptok2)
{
    int32_t lp1;
    int32_t lp2;

    /* TODO: implement */
    return 0;
}

int16_t FIsTargetOfMdTarget(TOK *ptok, int16_t mdTarget)
{

    /* TODO: implement */
    return 0;
}

int16_t SpdOfShip(FLEET *lpfl, int16_t ishdef, TOK *ptok, int16_t fDumpCargo, SHDEF *lpshdef)
{
    int32_t wtCargoFleetMax;
    int16_t spd;
    int16_t iWarp;
    uint16_t wt;
    int16_t cHalfThruster;
    int16_t cThruster;
    int32_t wtFleetCargo;
    int16_t j;
    int16_t cEngineT;
    uint16_t wtCargoShdefMax;
    int16_t iEngine;
    ENGINE * lpengine;

    /* TODO: implement */
    return 0;
}

void DoBombing(void)
{
    int16_t idmDst;
    int32_t modKill;
    int16_t fMulti;
    int32_t cKillPeople;
    int32_t dmgBombBldg;
    int32_t cKillPeopleS;
    int32_t cKillMine;
    int32_t dmgBombFloor;
    int16_t idmSrc;
    int32_t cKillDefenses;
    int32_t cKillFact;
    int32_t pctTerra;
    PLANET * lppl;
    int16_t ifl;
    FLEET * lpfl;
    int32_t cPPE;
    int32_t dmgBombPeople;
    float pctSmart;
    float pctSuccess;
    int32_t dmgPeopleSmart;
    int16_t pctTot;
    int16_t dChg;
    int16_t i;
    double pctSuccessHalf;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0xb10b */
    /* block (block) @ MEMORY_BATTLE:0xb7e8 */
    /* label GenericBombMsg @ MEMORY_BATTLE:0xbac4 */

    /* TODO: implement */
}

void InitializeBoard(FLEET *lpfl, int16_t ibrc, uint16_t grfPlayer, uint8_t *pinit, int16_t *pinitMin, int16_t *pinitMac)
{
    int16_t iplr;
    FLEET * lpflCur;
    TOK * ptok;
    int16_t initMac;
    PLANET * lppl;
    int16_t fDampeningField;
    int16_t initMin;
    uint16_t * lpwtCargoCur;
    TOK * ptokT;
    uint8_t mpiplrdibrc[16];
    int16_t fDumpCargo;
    int16_t ishdef;
    uint8_t rgfTorp[16];

    /* debug symbols */
    /* label LTooManyTokens @ MEMORY_BATTLE:0x4a8f */

    /* TODO: implement */
}

int16_t DzMoveRangeToConsider(TOK *ptok, uint16_t grfAttack, uint8_t *pbrc)
{
    int16_t dzNonSapper;
    uint8_t dz;
    int16_t iplr;
    uint16_t mdTarget;
    uint8_t dzBest;
    int16_t itokLook;
    int16_t iplrTarget;
    TOK * ptokTarget;
    int16_t dzMax;
    uint8_t brcCur;
    int16_t ihs;
    SHDEF * lpshdef;
    HUL * lphul;
    PART part;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x53a7 */

    /* TODO: implement */
    return 0;
}

int16_t FFuelTanker(SHDEF *lpshdef)
{

    /* TODO: implement */
    return 0;
}

int16_t FDoCoolBattle(FLEET *lpfl, int16_t cplr, uint16_t *rggrfAttack, uint16_t grfPlayer, uint16_t grfSpectator)
{
    int16_t cShipsInvolved;
    uint8_t * lpbMax;
    TOK * ptok;
    uint16_t wt;
    int16_t cShdefsInvolved;
    uint8_t * lpbSav;
    int16_t initMac;
    int16_t init;
    uint16_t wtT;
    uint16_t grplrLeft;
    int16_t i;
    int16_t j;
    int16_t initMin;
    BTLREC * lpbtlrec;
    int16_t iRound;
    FLEET * lpflT;
    uint16_t brcOrig;
    BTLDATA * lpbtldata;
    uint8_t rgfInit[64];
    uint16_t rgPlrLosses[256];
    uint16_t wtNext;
    int16_t itok;
    PLANET * lppl;
    int32_t lwt;
    int16_t env[9];
    int16_t (* penvMemSav)[9];

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x8be9 */
    /* block (block) @ MEMORY_BATTLE:0x8c52 */
    /* block (block) @ MEMORY_BATTLE:0x8e81 */
    /* block (block) @ MEMORY_BATTLE:0x91c0 */

    /* TODO: implement */
    return 0;
}

void CheckWeapons(TOK *ptok, int16_t *pfDampeningField, uint8_t *pinit)
{
    int16_t pctJam;
    int32_t ldp;
    int32_t pctBeamDef;
    int16_t ihs;
    int16_t initMac;
    int16_t init;
    int16_t dxyMax;
    int16_t i;
    int32_t pctCap;
    int16_t initMin;
    int32_t pctHit;
    SHDEF * lpshdef;
    int16_t dxyLim;
    int16_t initBase;
    HUL * lphul;
    int16_t dxyPart;
    PART part;

    /* TODO: implement */
}

SHDEF * LpshdefFromTok(TOK *ptok)
{

    /* TODO: implement */
    return NULL;
}

int16_t CplrBattle(FLEET *lpfl, uint16_t *rggrfAttack, uint16_t *pgrfPlayer, uint16_t *pgrfSpectator)
{
    int16_t iplrStarbase;
    FLEET * lpflCur;
    int32_t rgcsh[16];
    uint16_t grPlr;
    int16_t iplrCur;
    PLANET * lppl;
    int16_t cplr;
    int16_t i;
    int16_t mdRel;
    uint8_t rgctok[16];
    int16_t fChange;
    uint16_t iplrAttack;
    int16_t fAttack;
    int16_t cshdef;
    int16_t ishdef;
    int16_t cflTotal;
    uint16_t grfPlayer;
    int16_t ctokNew;
    int16_t ctokFleet;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x315e */
    /* label LNextFleet @ MEMORY_BATTLE:0x2d7c */

    /* TODO: implement */
    return 0;
}

void SpankTheCheaters(void)
{
    int32_t lSell;
    PLANET * lppl;
    FLEET * lpfl;
    int16_t ifl;
    int16_t i;
    int32_t pctSell;
    int16_t fCheater;
    int16_t fSellOff;
    char rgfCheater[16];
    PLANET * lpplMac;

    /* TODO: implement */
}

int16_t ITechLearnATech(int16_t iplr, int16_t x, int16_t y, int16_t idm, uint16_t *piGoto)
{
    uint16_t iGoto;
    int16_t fBattle;
    int16_t i;
    int16_t iTech;
    int32_t l;

    /* TODO: implement */
    return 0;
}

int16_t FDamageTok(TOK *ptok, int16_t itok, int32_t *pdpBeam, int32_t dpTorp, uint16_t grfWeapon, int16_t fShieldsOnly, int32_t *pcTorp)
{
    int16_t pctSh;
    DV dv;
    uint16_t * pwLosses;
    int16_t cshOrigDamaged;
    int32_t dpShdef;
    int32_t ddpOrig;
    int32_t dpOrig;
    PLANET * lppl;
    int16_t i;
    int16_t cshOrig;
    FLEET * lpfl;
    int32_t cKillMax;
    int16_t csh;
    int32_t dpT;
    int16_t pctDp;
    int16_t ishdef;
    int32_t dp;
    uint16_t pctDpNew;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x8514 */

    /* TODO: implement */
    return 0;
}

void KillShips(TOK *ptok, int16_t cshKill, int16_t ishdef, FLEET *lpfl, int16_t fFallout)
{
    FLEET flDead;
    int16_t i;
    FLEET flSrc;
    int16_t csh;

    /* TODO: implement */
}

void SendBattleMessages(FLEET *lpflBtl, int16_t cplr, int16_t idBtl, uint16_t *rgPlrLosses, int16_t grfPlayer, int16_t cShipsInvolved, int16_t cShdefsInvolved, uint16_t grfSpectator)
{
    int16_t iplrStarbase;
    int16_t iplr;
    uint8_t rgcfl[16];
    int32_t lpopStarbase;
    uint16_t * pw;
    int16_t isb;
    PLANET * lppl;
    uint16_t * pwThem;
    int16_t fAlive;
    int16_t cUs;
    int16_t y;
    FLEET * lpfl;
    int16_t cThemDead;
    int16_t i;
    int16_t idm;
    int16_t j;
    FLEET * lpflT;
    int16_t cUsDead;
    int16_t iThem;
    uint16_t * pwUs;
    int16_t cThem;
    int16_t x;

    /* debug symbols */
    /* label IndecisiveXWay @ MEMORY_BATTLE:0xaa8f */
    /* label CommonCountingCode @ MEMORY_BATTLE:0xa4a1 */

    /* TODO: implement */
}

int16_t FDoesPrimaryTargetTypeExist(TOK *ptok, uint16_t grfAttack)
{
    uint16_t mdTarget;
    int16_t iplr;
    int16_t iplrLook;
    TOK tok;
    int16_t itokLook;

    /* TODO: implement */
    return 0;
}

int16_t DzFromBrcBrc(uint8_t brc1, uint8_t brc2)
{
    int16_t dy;
    int16_t dx;

    /* TODO: implement */
    return 0;
}

int32_t DpFromPtokBrcToBrc(TOK *ptok, uint8_t brcSrc, uint8_t brcTarget, TOK *ptokTarget, int16_t fProximity)
{
    int16_t dz;
    int32_t dpMax;
    int32_t dpShdef;
    int16_t ihs;
    int32_t cTorpBase;
    int32_t dpTotal;
    int16_t fOutOfRange;
    int32_t dRange;
    HUL * lphul;
    int32_t cTorpHit;
    int32_t dp;
    PART part;
    int32_t dpShieldsLeft;

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x4fb1 */

    /* TODO: implement */
    return 0;
}

int16_t DxyMoveTokTo(TOK *ptok, int16_t spdMove, uint16_t grfAttack)
{
    uint16_t iplr;
    int16_t xMax;
    int16_t dz;
    int32_t scoreBest;
    uint8_t brc;
    int32_t rgscoreNear[3][3];
    int32_t score;
    int16_t cBest;
    int16_t yMin;
    int16_t dy;
    int16_t mdTactic;
    int16_t y;
    uint8_t brcOOR;
    int16_t i;
    int16_t yCur;
    uint8_t brcBest;
    int16_t dzAwayBest;
    int16_t yMax;
    int16_t dx;
    int16_t xCur;
    int16_t fPrimary;
    int32_t dp;
    int16_t dzAway;
    int16_t x;
    int16_t fXMajor;
    int32_t lLow;
    int16_t cLow;
    POINT rgptDeltas[2];

    /* debug symbols */
    /* block (block) @ MEMORY_BATTLE:0x6332 */
    /* block (block) @ MEMORY_BATTLE:0x646e */
    /* block (block) @ MEMORY_BATTLE:0x65a1 */
    /* label LTakeSquare @ MEMORY_BATTLE:0x625a */
    /* label LReturnDxy @ MEMORY_BATTLE:0x676f */

    /* TODO: implement */
    return 0;
}

int16_t FHullHasBombs(HUL *lphul)
{
    HS * lphs;
    int16_t ihs;

    /* TODO: implement */
    return 0;
}
