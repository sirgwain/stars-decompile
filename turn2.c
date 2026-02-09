
#include "types.h"

#include "globals.h"
#include "msg.h"
#include "planet.h"
#include "produce.h"
#include "race.h"
#include "turn2.h"
#include "util.h"
#include "utilgen.h"

/* functions */
void Produce(void) {
    int32_t lResCur;
    int16_t cMax;
    int32_t rgResAvail[4];
    int16_t iprodCur;
    int16_t mdStatus;
    int16_t cBuilt;
    int16_t fNoResearch;
    PLANET *lppl;
    int16_t i;
    int16_t idm;
    PROD    prodPartial;
    int16_t fPrevProdIsAlch;
    int16_t fAutoBuildDone;
    int32_t lResearchTake;
    PROD   *lpprod;
    PLANET *lpplMac;
    int16_t cMax2;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x05c2 */
    /* block (block) @ MEMORY_TURN2:0x06cd */
    /* block (block) @ MEMORY_TURN2:0x075c */
    /* label TopOfQueue @ MEMORY_TURN2:0x0371 */
    /* label RemoveFromQueue @ MEMORY_TURN2:0x09d0 */
    /* label LCantBuildP @ MEMORY_TURN2:0x0623 */
    /* label LCantBuildP2 @ MEMORY_TURN2:0x0628 */

    /* TODO: implement */
}

void CreateBackupDir(void) {
    char *pchT;

    /* TODO: implement */
}

void ThingDecay(void) {
    THING   *lpthMac;
    int32_t  pctDecay;
    int16_t  i;
    int16_t  ifl;
    FLEET   *lpfl;
    THING   *lpth;
    uint16_t wDecay;
    int32_t  lDecay;
    int16_t  fMineExpert;
    int32_t  dy;
    int32_t  dx;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x7346 */
    /* block (block) @ MEMORY_TURN2:0x7391 */
    /* label LFixUpLpth @ MEMORY_TURN2:0x72ca */

    /* TODO: implement */
}

void DropColonists(void) {
    COLDROP *lpcdLook;
    int16_t  fTie;
    int32_t  cMax;
    PLANET   pl;
    int32_t  lDefensePower;
    int32_t  cPowerTot;
    COLDROP *lpcdCur;
    int16_t  iMax;
    int16_t  idPlanet;
    int16_t  iplrOldOwner;
    int32_t  cColTot;
    int32_t  lOldPop;
    int32_t  c2nd;
    int16_t  i;
    int32_t  rgcPower[16];
    int16_t  cSides;
    float    pctSurvive;
    int32_t  rgcCol[16];
    int32_t  lPower;
    COLDROP *lpcdMax;
    int16_t  cpq;
    int16_t  iTech;
    int16_t  iDst;
    int16_t  iBonus;
    PROD     prod;
    int16_t  ipq;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x3ebb */
    /* block (block) @ MEMORY_TURN2:0x3f27 */
    /* block (block) @ MEMORY_TURN2:0x4329 */
    /* label IncCur @ MEMORY_TURN2:0x442b */
    /* label WritePlanet @ MEMORY_TURN2:0x42fc */

    /* TODO: implement */
}

void TossNonAutoBuildItems(PLANET *lppl) {
    int16_t iDst;
    int16_t iSrc;

    /* TODO: implement */
}

void UpdateResearchStatus(int16_t fUsePool) {
    int16_t mdAvail;
    int16_t fRedoItAll;
    int16_t iTechCur;
    int16_t fUsePoolOrig;
    int16_t iTechNext;
    int16_t iT;
    int16_t iItem;
    int16_t fGeneral;
    int16_t fChgNow;
    int16_t i;
    int16_t ibitCur;
    int32_t rglFieldSpent[6];
    int16_t grbitCur;
    int16_t cPlrAlive;
    int32_t lSpent;
    PART    part;
    int32_t l;
    int16_t iTT;
    int16_t iTechNext2;
    char    TechLevel;
    int32_t l15pct;
    int16_t jj;
    int16_t iGoto;
    int16_t idm;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x824f */
    /* block (block) @ MEMORY_TURN2:0x82cf */
    /* block (block) @ MEMORY_TURN2:0x8520 */
    /* block (block) @ MEMORY_TURN2:0x858f */
    /* block (block) @ MEMORY_TURN2:0x86c0 */
    /* block (block) @ MEMORY_TURN2:0x8814 */
    /* label RedoItAll @ MEMORY_TURN2:0x81cf */
    /* label CheckForBreakthrough @ MEMORY_TURN2:0x83dc */

    /* TODO: implement */
}

void RemoteTerraforming(void) {
    int16_t fHelp;
    int16_t iBest;
    int16_t pctCur;
    PLANET *lppl;
    int16_t ifl;
    FLEET  *lpfl;
    int16_t cDone;
    int16_t iEnv;
    int16_t cAllowed;
    int32_t ipct;
    int16_t pctNew;

    /* TODO: implement */
}

void UpdatePopulations(void) {
    int32_t lPopChg;
    PLANET *lppl;
    PLANET *lpplMac;
    int16_t fMac;
    int32_t lPopOld;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x515b */
    /* block (block) @ MEMORY_TURN2:0x5278 */
    /* label NextPlanet @ MEMORY_TURN2:0x5254 */

    /* TODO: implement */
}

void SweepForMines(void) {
    int16_t  iplr;
    THING   *lpthMac;
    POINT    pt;
    int32_t  dy;
    int32_t  lCur;
    PLANET  *lppl;
    int16_t  ifl;
    FLEET   *lpfl;
    THING   *lpth;
    int32_t  cMineCur;
    int32_t  dx;
    int32_t  cMine;
    uint16_t grbitPlr;
    PLANET  *lpplMac;

    /* TODO: implement */
}

void UpdatePlayerScores(void) {
    int32_t  lScoreTot;
    int16_t  cFirst;
    SCORE    score;
    int16_t  cDead;
    int16_t  c;
    int16_t  i;
    uint8_t  rgcCond[16];
    uint16_t wWinners2;
    int32_t  rglScore[16];
    int16_t  iScoreMax;
    int16_t  j;
    uint16_t wWinners;
    int16_t  imsg;
    int32_t  lScore2nd;
    int32_t  lScoreMax;

    /* TODO: implement */
}

void UpdateGuesses(void) {
    PLANET *lppl;
    float   pct;
    PLANET *lpplMac;
    int32_t l;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x5377 */

    /* TODO: implement */
}

void MysteryTrader(void) {
    int16_t iSrc;
    int16_t cRand;
    int16_t i;
    THING  *lpth;
    int16_t grbitTrader;
    int16_t rgC[4];

    /* TODO: implement */
}

int16_t FQueueColonistDrop(FLEET *lpfl, PLANET *lppl, int32_t cColonists) {
    int16_t  iColDrop;
    COLDROP *lpcdT;

    /* TODO: implement */
    return 0;
}

int16_t CBuildProdItem(PLANET *lppl, PROD *lpprod, PROD *pprodPartial, int32_t *rgRes, int16_t fAlchemy, int16_t *pmdStatus, int16_t fCalcOnly) {
    int32_t  pctT;
    int16_t  cMax;
    int32_t  cCanBuild;
    int32_t  lMinNeeded;
    int32_t  lAlchCost;
    PROD     prod;
    int16_t  fAutoBuild;
    int16_t  cBuilt;
    int16_t  cAlchemy;
    int32_t  rgCostPaid[4];
    int16_t  i;
    int16_t  fResourceBlocked;
    int32_t  pctTooBig;
    int32_t  pct;
    uint32_t rgCost[4];
    int16_t  fMineralBlocked;
    int32_t  addCost;
    uint16_t iItemOrig;

    cAlchemy = 0;
    iItemOrig = lpprod->iItem;
    prod.dwRaw_0000 = lpprod->dwRaw_0000;

    GetProductionCosts(lppl, lpprod, rgCost, lppl->iPlayer, 1);

    cBuilt = 0;

    if (lpprod->grobj == grobjPlanet && lpprod->iItem < 7) {
        fAutoBuild = 1;
    } else {
        fAutoBuild = 0;
    }

    if (fAutoBuild) {
        cMax = 1000;

        switch (lpprod->iItem) {
        case iobjMine:
            cMax = CMaxOperableMines(lppl, lppl->iPlayer, 1) - (int16_t)lppl->cMines;
            break;
        case iobjFactory:
            cMax = CMaxOperableFactories(lppl, lppl->iPlayer, 1) - (int16_t)lppl->cFactories;
            break;
        case iobjDefense:
            cMax = CMaxOperableDefenses(lppl, lppl->iPlayer, 1) - (int16_t)lppl->cDefenses;
            break;
        case iobjAlchemy:
            break;
        case iobjTerraform:
        case iobjTerraform2:
            cMax = IpctCanTerraformLppl(lppl);
            if (cMax > 0 && lpprod->iItem == iobjTerraform &&
                ChgPopFromPlanet(lppl, 0) >= 0 &&
                PctPlanetDesirability(lppl, lppl->iPlayer) > 0) {
                cMax = 0;
            }
            break;
        case iobjPacket:
            if (IWarpMAFromLppl(lppl, NULL) == 0 ||
                ((uint16_t)(lppl->lStarbase >> 16) & 0x3ff) == 0) {
                cMax = 0;
            }
            break;
        }

        if (cMax < 0)
            cMax = 0;

        if ((cMax >= 0 && (uint16_t)cMax < prod.cItem) || lpprod->iItem == iobjAlchemy) {
            prod.cItem = cMax;
        }
    }

    for (i = 0; i < 4; i++) {
        rgCostPaid[i] = (int32_t)rgCost[i] * prod.pct / 100;
    }

    for (;;) {
        if (prod.cItem == 0)
            goto LDone;

        for (i = 0; i < 4; i++) {
            if (rgRes[i] < (int32_t)rgCost[i] - rgCostPaid[i])
                break;
        }

        if (i > 3) {
            cBuilt++;
            prod.cItem--;
            prod.pct = 0;
            for (i = 0; i < 4; i++) {
                rgRes[i] -= ((int32_t)rgCost[i] - rgCostPaid[i]);
                rgCostPaid[i] = 0;
            }
            continue;
        }

        fMineralBlocked = 0;
        fResourceBlocked = 0;
        pct = 100;
        lMinNeeded = 0;

        for (i = 0; i < 4; i++) {
            if ((int32_t)rgCost[i] > 0) {
                if (rgRes[i] < (int32_t)rgCost[i]) {
                    pctT = (rgRes[i] + rgCostPaid[i]) * 100 / (int32_t)rgCost[i];
                    pctTooBig = (rgRes[i] + rgCostPaid[i] + 1) * 100 / (int32_t)rgCost[i];
                    if (pctT <= pctTooBig - 1)
                        pctT = pctTooBig - 1;
                } else {
                    pctT = 100;
                }
                if (pctT < pct) {
                    lMinNeeded = ((int32_t)rgCost[i] - rgCostPaid[i]) - rgRes[i];
                    pct = pctT;
                    if (i == 3)
                        fResourceBlocked = 1;
                    else
                        fMineralBlocked = 1;
                }
            }
        }

        if (fMineralBlocked && fAutoBuild != 0) {
            if (fAlchemy == 0) {
                fAutoBuild = 2;
                goto LDone;
            }
        } else {
            for (i = 0; i < 4; i++) {
                addCost = (int32_t)rgCost[i] * pct / 100 - rgCostPaid[i];
                rgRes[i] -= addCost;
                rgCostPaid[i] += addCost;
            }
            prod.pct = (uint32_t)pct;

            if (fAlchemy == 0 || fResourceBlocked)
                goto LDone;
        }

    /* LAlchemize */
        lAlchCost = (GetRaceGrbit(&rgplr[lppl->iPlayer], ibitRaceMineralAlchemy) != 0) ? 25 : 100;

        cCanBuild = rgRes[3] / lAlchCost;
        if (cCanBuild > lMinNeeded)
            cCanBuild = lMinNeeded;

        if (cCanBuild > 0) {
            for (i = 0; i < 3; i++)
                rgRes[i] += cCanBuild;
            rgRes[3] -= cCanBuild * lAlchCost;
            cAlchemy += (int16_t)cCanBuild;
        }

        if (cCanBuild != lMinNeeded) {
            if (rgRes[3] > 0 && pprodPartial != NULL) {
                memset(pprodPartial, 0, sizeof(PROD));
                pprodPartial->grobj = grobjPlanet;
                pprodPartial->iItem = mdIdleAlchemy;
                pprodPartial->cItem = 1;

                pctT = rgRes[3] * 100 / lAlchCost;
                pctTooBig = (rgRes[3] + 1) * 100 / lAlchCost;
                if (pctT <= pctTooBig - 1)
                    pctT = pctTooBig - 1;
                pprodPartial->pct = (uint32_t)pctT;

                addCost = pctT * lAlchCost / 100;
                rgRes[3] -= addCost;
            }
            goto LDone;
        }
    }

LDone:
    if (cBuilt > 0 && lpprod->grobj == grobjPlanet &&
        (lpprod->iItem == mdIdleAlchemy || lpprod->iItem == iobjAlchemy)) {
        cAlchemy += cBuilt;
        for (i = 0; i < 3; i++) {
            rgRes[i] += (int32_t)cBuilt;
        }
    }

    if (cAlchemy != 0 && fCalcOnly == 0 && gd.fGeneratingTurn) {
        FSendPlrMsg2(lppl->iPlayer, idmScientistsHaveTransmutedCommonMaterialsKtEach,
                     lppl->id, lppl->id, cAlchemy);
    }

    if (pmdStatus != NULL) {
        if (fAutoBuild == 2) {
            *pmdStatus = (cBuilt < 1) ? mdProdStatNoneAuto : mdProdStatSomeAuto;
        } else if (fAutoBuild == 0 || prod.cItem != 0) {
            if (cBuilt == 0) {
                *pmdStatus = (iItemOrig == lpprod->iItem) ?
                    mdProdStatBlockedSame : mdProdStatBlockedDiff;
            } else if (prod.cItem == 0) {
                *pmdStatus = mdProdStatComplete;
            } else {
                *pmdStatus = mdProdStatSome;
            }
        } else {
            *pmdStatus = (cBuilt < 1) ? mdProdStatSkippedAuto : mdProdStatCompleteAuto;
        }
    }

    if (fCalcOnly == 0 && fAutoBuild == 0) {
        lpprod->dwRaw_0000 = prod.dwRaw_0000;
    }

    if (fAutoBuild != 0 && pprodPartial != NULL &&
        pprodPartial->cItem == 0 && lpprod->iItem != iobjMine) {
        pprodPartial->dwRaw_0000 = prod.dwRaw_0000;
        pprodPartial->cItem = 1;
    }

    return cBuilt;
}

void AutoTerraform(void) {
    int16_t rgMax[3];
    int16_t rgp[16];
    PLANET *lppl;
    int16_t i;
    int16_t rgMin[3];
    int16_t rgCost[3];
    PLANET *lpplMac;
    bool fAnyTerra;
    int16_t iEnv;
    int16_t pctDesire;

    fAnyTerra = false;
    for (i = 0; i < game.cPlayer; i++) {
        rgp[i] = (GetRaceStat(&rgplr[i], rsMajorAdv) == raTerra);
        if (rgp[i] != 0) {
            fAnyTerra = true;
        }
    }
    if (!fAnyTerra)
        return;

    lpplMac = lpPlanets + cPlanet;
    for (lppl = lpPlanets; lppl < lpplMac; lppl++) {
        if (lppl->iPlayer == -1 || rgp[lppl->iPlayer] == 0)
            continue;

        if (lppl->fStarbase && lppl->iPlayer == -1) {
            lppl->fStarbase = 0;
        }

        iEnv = Random(3);
        if (rgplr[lppl->iPlayer].rgEnvVar[iEnv] != -1 &&
            rgplr[lppl->iPlayer].rgEnvVar[iEnv] != (int8_t)lppl->rgEnvVarOrig[iEnv] &&
            Random(10) == 0 &&
            (lppl->rgwtMin[3] > 999 || Random(1000) < (int16_t)lppl->rgwtMin[3])) {

            if (rgplr[lppl->iPlayer].rgEnvVar[iEnv] < (int8_t)lppl->rgEnvVarOrig[iEnv]) {
                lppl->rgEnvVarOrig[iEnv]--;
            } else {
                lppl->rgEnvVarOrig[iEnv]++;
            }
            FSendPlrMsg2(lppl->iPlayer, idmEngineersHaveManagedImproveUnderlying1, lppl->id, lppl->id, iEnv);
        }

        if (FCanTerraformLppl(lppl, rgMin, rgMax, rgCost, 1)) {
            for (i = 0; i < 3; i++) {
                if (rgMin[i] == -1) {
                    if (rgMax[i] != -1) {
                        lppl->rgEnvVar[i] = (uint8_t)rgMax[i];
                    }
                } else {
                    lppl->rgEnvVar[i] = (uint8_t)rgMin[i];
                }
            }
            pctDesire = PctPlanetDesirability(lppl, lppl->iPlayer);
            FSendPlrMsg2(lppl->iPlayer, idmHasAutoTerraformedValue, lppl->id, lppl->id, pctDesire);
        }
    }
}

int16_t FPacketDecay(THING *lpth, int16_t pctRate) {
    uint16_t iRateMin;
    int16_t  iRate;
    int16_t  i;
    uint16_t wDecay;
    int32_t  lDecay;

    /* TODO: implement */
    return 0;
}

void TransferToOthers(void) {
    int32_t   l2;
    int16_t   idDst;
    XFER      rgxf[2];
    int16_t   idSrc;
    int16_t   i;
    int16_t   idm;
    XFERFULL *lpxfMax;
    XFERFULL *lpxfCur;
    int32_t   l;

    /* debug symbols */
    /* label DoNext @ MEMORY_TURN2:0x34c6 */

    /* TODO: implement */
}

void MineMinerals(void) {
    int32_t rglQuan[3];
    PLANET *lppl;
    PLANET *lpplMac;

    /* TODO: implement */
}

int16_t FBuildObject(PLANET *lppl, GrobjClass grobj, int16_t iItem, int16_t cBuilt, int32_t *rgMinerals) {
    int16_t  iWarp;
    int16_t  i;
    FLEET   *lpfl;
    int16_t  idm;
    int16_t  fTwoMAs;
    SHDEF   *lpshdef;
    int16_t  cAllowed;
    int16_t  iEnv;
    int32_t  dpOrig;
    THING   *lpthMac;
    int16_t  cshDamaged;
    int16_t  cshOrig;
    int16_t  iDecayRate;
    PART     part;
    uint16_t dpShdef;
    THING   *lpth;
    int16_t  raMajor;
    int16_t  iWarpAsked;
    int16_t  cSize;
    int16_t  rgwt[3];
    int32_t  l;

    /* debug symbols */
    /* block (block) @ MEMORY_TURN2:0x1d3a */
    /* block (block) @ MEMORY_TURN2:0x2681 */
    /* block (block) @ MEMORY_TURN2:0x2785 */
    /* block (block) @ MEMORY_TURN2:0x2dd5 */
    /* block (block) @ MEMORY_TURN2:0x2ec1 */
    /* label SendMsgFactMine @ MEMORY_TURN2:0x248b */

    /* TODO: implement */
    return 0;
}

int16_t IBestRemoteTerra(PLANET *lppl, int16_t iplr, int16_t fHelp) {
    int16_t iBest;
    int16_t i;
    PLAYER  plrSav;

    /* TODO: implement */
    return 0;
}

void PlanetaryClimateChange(void) {
    int16_t iT;
    PLANET *lppl;
    int16_t i;
    int16_t j;

    /* TODO: implement */
}

void DiscoverNewMinerals(void) {
    PLANET *lppl;
    int16_t i;

    /* TODO: implement */
}

void MeteorStrike(void) {
    int16_t rgEnv[3];
    int16_t iT;
    int32_t rgQuan[4];
    int16_t iSize;
    PLANET *lppl;
    int16_t rgAffect[3];
    int16_t i;
    int16_t iConc;
    int16_t j;

    /* TODO: implement */
}

void HealShips(void) {
    int16_t pctShipHeal;
    int16_t dpHeal;
    PLANET *lppl;
    int16_t i;
    FLEET  *lpfl;
    SHDEF  *lpshdef;
    int16_t pct;
    int16_t ishdef;
    PLANET *lpplMac;

    /* TODO: implement */
}

void CreateShip(int16_t iPlr, FLEET *lpfl, int16_t ishdef, int16_t cShip) { /* TODO: implement */ }

void BreedColonistsInTransit(void) {
    int16_t fNoBreeders;
    char    grfBreeder[16];
    int32_t lColGain;
    PLANET *lppl;
    int16_t ifl;
    FLEET  *lpfl;
    int16_t i;
    int32_t lColGainAct;

    /* TODO: implement */
}

void RandomEvents(void) { /* TODO: implement */ }

void UnmarkMineFields(void) {
    THING *lpth;
    THING *end;

    end = lpThings + cThing;
    for (lpth = lpThings; lpth < end; lpth++) {
        if (lpth->ith == 0) {
            lpth->thm.grbitPlrNow = 0;
        }
    }
}
