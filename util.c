#include <limits.h>
#include <stdint.h>

#include "battle.h"
#include "enums.h"
#include "globals.h"
#include "log.h"
#include "memory.h"
#include "msg.h"
#include "parts.h"
#include "planet.h"
#include "race.h"
#include "report.h"
#include "scan.h"
#include "ship.h"
#include "strings.h"
#include "tutor.h"
#include "types.h"
#include "util.h"
#include "utilgen.h"

/* globals */
int32_t rgDSDivCnt[5] = {28000, 28000, 63000, 95000, 73000};
int32_t rgDSDivCnt2[5] = {80000, 210000, 310000, 260000, 0};
uint8_t vrgbTachyon[18] = {0x64, 0x5f, 0x5d, 0x5b, 0x5a, 0x59, 0x58, 0x57, 0x56, 0x56, 0x55, 0x54, 0x54, 0x53, 0x53, 0x52, 0x52, 0x51};

#ifdef _WIN32

COLORREF rgcrDrawStars[5] = {0x007f7f7f, 0x00ffffff, 0x000000ff, 0x0000ff00, 0x00ff0000};
COLORREF rgcrDrawStars2a[5] = {0x00c0c0c0, 0x000000ff, 0x0000ff00, 0x00ff0000, 0x00000000};
COLORREF rgcrDrawStars2b[5] = {0x007f7f7f, 0x0000007f, 0x00007f00, 0x007f0000, 0x00000000};

#endif /* _WIN32 */
/* functions */

int16_t muldiv_i16(int16_t number, int16_t numer, int16_t denom) {
    // faithful to the Win16 usage pattern here: 16-bit args, 16-bit return.
    // Use 32-bit intermediate; rounding to nearest, halves away from zero.
    if (denom == 0)
        return 0; // or assert

    int32_t prod = (int32_t)number * (int32_t)numer;
    int32_t den = (int32_t)denom;

    // Normalize sign so denom > 0
    if (den < 0) {
        den = -den;
        prod = -prod;
    }

    if (prod >= 0)
        prod += den / 2;
    else
        prod -= den / 2;

    int32_t q = prod / den;

    // Win32 MulDiv returns -1 on overflow; Win16 variants also commonly saturate/error.
    // For Stars’ ranges this won't trigger; pick a deterministic behavior:
    if (q > INT16_MAX)
        return (int16_t)INT16_MAX; // or (int16_t)-1 if you want "MulDiv overflow" behavior
    if (q < INT16_MIN)
        return (int16_t)INT16_MIN;
    return (int16_t)q;
}

char *SzVersion(void) {
    /* These are the wsprintf arguments in the decompile. */
    int16_t major = 2;
    int16_t minor = 60;
    char    letter = 'k';

    /* ids 0x22d is a format string stored in the compressed string table. */
    const char *fmt = PszGetCompressedString(idsVersionD02dC);

    /* wsprintf into shared work buffer and return it. */
    snprintf(szWork, sizeof(szWork), fmt, major, minor, letter);
    return szWork;
}

char *PszGetLocName(GrobjClass grobj, int16_t id, int16_t x, int16_t y) {
    if (id != -1) {
        if (grobj == grobjPlanet)
            return PszGetPlanetName(id);
        if (grobj == grobjFleet)
            return PszGetFleetName(id);
        if (grobj == grobjThing)
            return PszGetThingName(id);
    }

    if (x == -1 && y == -1) {
        strcpy(szWork, PszGetCompressedString(idsDeepSpace)); /* 0x362 */
    } else {
        (void)sprintf(szWork, PszGetCompressedString(idsSpaceDD), x, y); /* 0x363 */
    }
    return szWork;
}

int16_t FCanFleetUseStargates(FLEET *lpfl, POINT ptSrc, POINT ptDst) {
    int16_t dTravel;
    PLANET *lpplDst;
    int16_t pctDmg;
    int16_t fSrcPlanet;
    int16_t fUncertain;
    int16_t i;
    int16_t fDanger;
    PLANET *lpplSrc;
    int16_t isbsDst;
    int16_t fCargo;
    int16_t ishdef;
    int16_t isbsSrc;
    SCAN    scan;

    /* debug symbols */
    /* label LSrcChk @ MEMORY_UTIL:0x76a6 */
    /* label LJumpgate @ MEMORY_UTIL:0x7743 */

    /* TODO: implement */
    return 0;
}

FLEET *LpflFromId(int16_t idFleet) {
    int16_t i;
    int16_t iplrCur;
    int16_t iHi;
    int16_t iLo;
    int16_t iMid;
    int16_t want;

    // In Stars!, a fleet id is packed. The decompile shows the owner lives in bits 9..12
    i = 0;
    for (iplrCur = 0; iplrCur < (int16_t)(((uint16_t)idFleet >> 9) & 0x0f); iplrCur++) {
        i = (int16_t)(i + (int16_t)rgplr[iplrCur].cFleet);
    }

    iHi = cFleet;
    iMid = (int16_t)(i - 1);
    want = (int16_t)((uint16_t)idFleet & 0x1fff);

    for (;;) {
        iLo = iMid;
        if (iHi <= (int16_t)(iLo + 1)) {
            return (FLEET *)0;
        }

        iMid = (int16_t)((iLo + iHi) >> 1);

        if (rglpfl[iMid] == 0) {
            return (FLEET *)0;
        }

        if (rglpfl[iMid]->id < want) {
            /* go right */
            continue;
        }
        if (want < rglpfl[iMid]->id) {
            /* go left */
            iHi = iMid;
            iMid = iLo;
            continue;
        }

        return rglpfl[iMid];
    }
}

PLANET *LpplFromId(int16_t idPlanet) {
    int16_t idGuess;
    int16_t iLo;
    PLANET *lppl;
    int16_t iGuess;
    int16_t iHi;

    if (idPlanet < 0 || idPlanet >= game.cPlanMax) {
        return NULL;
    }

    /* If we have a dense array of all planets loaded, direct index. */
    if (cPlanet == game.cPlanMax) {
        return (PLANET *)((uint8_t *)lpPlanets + (int32_t)idPlanet * (int32_t)sizeof(PLANET));
    }

    /* Otherwise the planet list is sorted by id and has only cPlanet entries. */
    iLo = -1;
    iHi = cPlanet;
    while (true) {
        if (iHi <= (int16_t)(iLo + 1)) {
            return NULL;
        }
        iGuess = (int16_t)((iLo + iHi) >> 1);
        lppl = (PLANET *)((uint8_t *)lpPlanets + (int32_t)iGuess * (int32_t)sizeof(PLANET));
        idGuess = lppl->id;
        if (idGuess < idPlanet) {
            iLo = iGuess;
        } else if (idPlanet < idGuess) {
            iHi = iGuess;
        } else {
            return lppl;
        }
    }
}

THING *LpthFromId(int16_t idth) {
    for (int i = 0; i < cThing; i++) {
        THING *t = &lpThings[i];
        if ((int16_t)t->idFull == idth) {
            return t;
        }
    }
    return NULL;
}

int32_t LCalcFuelGainFromRamScoops(FLEET *lpfl, int16_t iWarp, int32_t dTravel) {
    int16_t  i;
    int16_t *rgiFuel;
    SHDEF   *lpshdef;
    int32_t  pct10;
    int32_t  pctShip10;

    (void)rgiFuel;
    pct10 = 0;

    if (iWarp >= 11) {
        return 0;
    }

    /*
     * Port of the original Win16 logic:
     *  - For each ship design present in the fleet, if its engine uses 0 fuel
     *    at the current warp (and possibly the next few warps), add a % gain
     *    proportional to engine count.
     *  - Multiply by ship count and then by distance.
     */
    for (i = 0; i < 16; i++) {
        int16_t csh = lpfl->rgcsh[i];
        if (csh <= 0) {
            continue;
        }

        lpshdef = (SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)i * 0x93);

        /* Engine is always slot 0 in this data model. */
        {
            uint8_t engineId = (uint8_t)lpshdef->hul.rghs[0].iItem;
            uint8_t cEngines = (uint8_t)lpshdef->hul.rghs[0].cItem;
            ENGINE *lpeng = LpengineFromId(engineId);

            pctShip10 = 0;
            if (iWarp < 10) {
                if (lpeng->rgcFuelUsed[iWarp] == 0) {
                    pctShip10 += (int32_t)cEngines;
                    if (lpeng->rgcFuelUsed[iWarp + 1] == 0) {
                        pctShip10 += (int32_t)cEngines * 2;
                        if (iWarp < 9 && lpeng->rgcFuelUsed[iWarp + 2] == 0) {
                            pctShip10 += (int32_t)cEngines * 3;
                            if (iWarp < 8 && lpeng->rgcFuelUsed[iWarp + 3] == 0) {
                                pctShip10 += (int32_t)cEngines * 4;
                            }
                        }
                    }
                }
            }

            pct10 += pctShip10 * (int32_t)csh;
        }
    }

    /* distance scaling (32-bit signed multiply in the original helpers) */
    return (int32_t)((int64_t)pct10 * (int64_t)dTravel);
}

int16_t IshdefPrimaryFromLpfl(FLEET *lpfl, int16_t *pcDiff) {
    int16_t cDiff;
    int16_t csh;
    int16_t ish;

    cDiff = 0;
    csh = 0;
    ish = 16;

    for (int16_t i = 0; i < 16; i++) {
        int16_t n = lpfl->rgcsh[i];

        if (n > 0) {
            cDiff++;

            if (n != csh && csh <= n) {
                HullDef ihuldef = rglpshdef[lpfl->iPlayer][i].hul.ihuldef;

                ish = i;
                csh = n;

                if (ihuldef == ihuldefFuelTransport || ihuldef == ihuldefSuperFuelXport) {
                    csh = (int16_t)(csh - 1);
                }
            }
        }
    }

    if (pcDiff != (int16_t *)0) {
        *pcDiff = cDiff;
    }
    return ish;
}

int16_t GetCachedFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal) {
    int16_t dPlanRange;
    int16_t i;
    int16_t iPlr;
    int16_t dRange;
    int16_t iSteal;
    int16_t pctDetect;

    iPlr = lpfl->iPlayer;
    dRange = -1;
    dPlanRange = 0;
    iSteal = 0;
    pctDetect = 100;

    if (!gd.fGeneratingTurn) {
        dRange = GetFleetScannerRange(lpfl, pdPlanRange, ppctDetect, piSteal);
    } else {
        for (i = 0; i < cShdefMax; i++) {
            if (lpfl->rgcsh[i] > 0) {
                SHDEF  *lpshdef = &rglpshdef[iPlr][i];
                int16_t scanRange = lpshdef->dScanRange;
                if (scanRange != 0x7ff && scanRange > dRange) {
                    dRange = scanRange;
                }
                if (lpshdef->dScanRange2 > dPlanRange) {
                    dPlanRange = lpshdef->dScanRange2;
                }
                if (lpshdef->pctDetect < (uint16_t)pctDetect) {
                    pctDetect = lpshdef->pctDetect;
                }
                iSteal |= lpshdef->iSteal;
            }
        }
        if (pdPlanRange != NULL) {
            *pdPlanRange = dPlanRange;
        }
        if (ppctDetect != NULL) {
            *ppctDetect = pctDetect;
        }
        if (piSteal != NULL) {
            *piSteal = iSteal;
        }
    }
    return dRange;
}

int16_t FLookupSelShip(FLEET *pfl) {
    if (sel.scan.grobj == grobjFleet)
        return FLookupFleet(((FLEET **)rglpfl)[sel.scan.ifl]->id, pfl);
    return 0;
}

int16_t FMatchTarget(FLEET *lpflTarget, int16_t mdTarget, int16_t fExact) {
    int16_t  ish;
    HULDEF  *pHuldef;
    uint16_t imdCat;

    // TODO: build an enum for these imdCat
    if (mdTarget != mdTargetArmedShips) {
        if (mdTarget == mdTargetBombersFreighters) {
            for (ish = 0; ish < 16; ish++) {
                if (lpflTarget->rgcsh[ish] != 0) {
                    pHuldef = LphuldefFromId(rglpshdef[lpflTarget->iPlayer][ish].hul.ihuldef);
                    imdCat = pHuldef->imdCategory;
                    if (imdCat == 1 || imdCat == 5)
                        break;
                }
            }
            return (ish != 16) ? 1 : 0;
        }
        if (mdTarget != mdTargetUnarmedShips) {
            if (mdTarget == mdTargetFuelTransports) {
                for (ish = 0; ish < cShdefMax; ish++) {
                    if (lpflTarget->rgcsh[ish] != 0) {
                        pHuldef = LphuldefFromId(rglpshdef[lpflTarget->iPlayer][ish].hul.ihuldef);
                        if (pHuldef->imdCategory == 7)
                            break;
                    }
                }
                return (ish != 16) ? 1 : 0;
            }
            if (mdTarget != mdTargetFreighters) {
                return fExact ? 0 : 1;
            }
            for (ish = 0; ish < cShdefMax; ish++) {
                if (lpflTarget->rgcsh[ish] != 0) {
                    pHuldef = LphuldefFromId(rglpshdef[lpflTarget->iPlayer][ish].hul.ihuldef);
                    if (pHuldef->imdCategory == 1)
                        break;
                }
            }
            return (ish != 16) ? 1 : 0;
        }
    }

    /* mdTarget == ArmedShips or UnarmedShips: look for armed ship categories (2,3,4) */
    for (ish = 0; ish < cShdefMax; ish++) {
        if (lpflTarget->rgcsh[ish] != 0) {
            pHuldef = LphuldefFromId(rglpshdef[lpflTarget->iPlayer][ish].hul.ihuldef);
            imdCat = pHuldef->imdCategory;
            if (imdCat > 1 && imdCat < 5)
                break;
        }
    }

    if (mdTarget == mdTargetArmedShips)
        return (ish != cShdefMax) ? 1 : 0;

    /* mdTarget == UnarmedShips: return 1 if NO armed ships found */
    return (ish == cShdefMax) ? 1 : 0;
}

void ClearFile(int16_t dt) {
    char  szFile[256];
    char *pch;

    /* _DATA::mpdtsz observed entries: xy, x, hst, m, h, r, log, chk */
    if (dt < 0 || dt >= 8) {
        return; /* original likely assumes caller passes valid dt */
    }

    /* Build from szBase, forcing the extension to mpdtsz[dt].
       Original logic:
         strcpy(szFile, szBase)
         pch = strrchr(szFile, '.')
         if (!pch) strcat(szFile, ".")
         else pch[1] = '\0'  (keep trailing '.')
         strcat(szFile, mpdtsz[dt])
         remove(szFile)
    */
    (void)strncpy(szFile, szBase, sizeof(szFile));
    szFile[sizeof(szFile) - 1] = '\0';

    pch = strrchr(szFile, '.');
    if (pch == NULL) {
        (void)strncat(szFile, ".", sizeof(szFile) - strlen(szFile) - 1);
    } else {
        pch[1] = '\0';
    }
    (void)strncat(szFile, mpdtsz[dt], sizeof(szFile) - strlen(szFile) - 1);

    (void)remove(szFile);
}

int32_t LComputePower(SHDEF *lpshdef) {
    int16_t dSpeed;
    int16_t dxRange;
    int16_t ihs;
    int32_t dpTorps;
    int16_t i;
    int32_t pctCap;
    int32_t dpBeams;
    int32_t dpBombs;
    int32_t dp;
    PART    part;

    for (ihs = 0; ihs < lpshdef->hul.chs; ihs++) {
        part.hs = lpshdef->hul.rghs[ihs];
        if (part.hs.cItem == 0)
            continue;

        if (FLookupPart(&part)) {
            switch (part.hs.grhst) {
            case hstBeam:
                dp = (long)part.pbeam->dp * part.hs.cItem * (part.pbeam->dRangeMax + 3) / 4L;

                if (part.pbeam->grfAbilities & 1) // Sapper
                    dp /= 3;

                dpBeams += dp;
                break;

            case hstTorp:
                dpTorps += (long)part.ptorp->dp * part.hs.cItem * (part.ptorp->dRangeMax - 2) / 2;
                break;
            case hstBomb:
                dpBombs += (part.pbomb->dDmgCol + part.pbomb->dDmgBldg) * part.hs.cItem * 2;
                break;
            case hstSpecialE:
                switch (part.hs.iItem) {
                case ispecialEEnergyCapacitor:
                case ispecialEFluxCapacitor:
                    for (i = (int)part.hs.cItem; i > 0; i--)
                        pctCap = pctCap * (100L + part.pspecial->grAbility) / 100L;
                    break;
                }
                break;
            }
        }
    }

    if (pctCap != 1000) {
        pctCap /= 10;
        if (pctCap > 255)
            pctCap = 255;
        dpBeams = dpBeams * pctCap / 100;
    }

    dSpeed = SpdOfShip(NULL, 0, NULL, fFalse, lpshdef);
    dpBeams += dpBeams * (dSpeed - 4) / 10;

    return (dpBombs + dpBeams + dpTorps);
}

char *PszGetFleetName(int16_t id) {
    FLEET   *lpfl;
    uint16_t iPlayer;
    char     szPlr[34];
    char     szShdef[34];
    int16_t  cshdef;
    int16_t  ishdef;
    int16_t  cch;

    lpfl = LpflFromId((int16_t)(id & 0x7fff));
    iPlayer = (uint16_t)((((uint16_t)id & 0x7fff) >> 9) & 15);

    if ((int16_t)iPlayer == idPlayer) {
        szPlr[0] = '\0';
    } else {
        char *pszPlr = PszPlayerName((int16_t)iPlayer, 0, 0, 0, 0, (PLAYER *)0);
        (void)sprintf(szPlr, "%s ", pszPlr);
    }

    if (lpfl == 0 || lpfl->lpszName == 0) {
        if (lpfl == 0) {
            strcpy(szShdef, PszGetCompressedString(idsFleet));
        } else {
            ishdef = IshdefPrimaryFromLpfl(lpfl, &cshdef);
            if (ishdef == 16) {
                strcpy(szShdef, PszGetCompressedString(idsFleet));
            } else {
                SHDEF *psh = &rglpshdef[iPlayer][ishdef];
                strcpy(szShdef, psh->hul.szClass);

                cch = (int16_t)strlen(szShdef);
                if (cch > 28) {
                    cch = 28;
                    szShdef[cch] = '\0';
                }
                if (cshdef > 1) {
                    szShdef[cch] = '+';
                    szShdef[cch + 1] = '\0';
                }
            }
        }

        (void)sprintf(szWork, "%s%s #%d", szPlr, szShdef, (int)(((uint16_t)id & 0x1ff) + 1)); /* 0x529 */
    } else {
        (void)sprintf(szWork, "%s%s", szPlr, lpfl->lpszName); /* 0x524 */
    }

    return szWork;
}

char *PszGetThingName(int16_t id) {
    THING *lpth;
    char   szPlr[54];

    lpth = LpthFromId(id);

    if (lpth == 0) {
        szWork[0] = '\0';
        return szWork;
    }

    if (lpth->ith == ithMinefield) {
        if ((int16_t)lpth->iplr == idPlayer) {
            szPlr[0] = '\0';
        } else {
            char *pszPlr = PszPlayerName((int16_t)lpth->iplr, 0, 0, 0, 0, (PLAYER *)0);
            (void)sprintf(szPlr, "%s ", pszPlr);
        }

        (void)sprintf(szWork, PszGetCompressedString(idsSSMineField), szPlr); /* 0x364 */
        return szWork;
    }

    if (lpth->ith == ithMineralPacket) {
        /* look at the first word of the payload (matches decompile at +6) */
        THPACK thp = lpth->thp;

        if (thp.iWarp == 0) {
            (void)CchGetString(idsSalvage, szWork);
        } else {
            if ((int16_t)lpth->iplr == idPlayer) {
                szPlr[0] = '\0';
            } else {
                char *pszPlr = PszPlayerName((int16_t)lpth->iplr, 0, 0, 0, 0, (PLAYER *)0);
                (void)sprintf(szPlr, "%s ", pszPlr);
            }

            (void)sprintf(szWork, PszGetCompressedString(idsSmineralPacket), szPlr);
        }
        return szWork;
    }

    if (lpth->ith == ithWormhole) {
        strcpy(szWork, PszGetCompressedString(idsWormhole));
        return szWork;
    }

    if (lpth->ith == ithMysteryTrader) {
        strcpy(szWork, PszGetCompressedString(idsMysteryTrader));
        return szWork;
    }

    strcpy(szWork, PszGetCompressedString(idsMysteryObject));
    return szWork;
}

int32_t LongFromSerialCh(char ch) {
    int32_t v;

    /* Map char to symbol */
    if (ch >= 'A' && ch <= 'Z')
        v = ch - 'A'; // 0–25
    else
        v = ch - '0' + 26; // 26–35

    /* Scramble base-32 symbols */
    if (v < 32)
        v ^= 0x15;

    return v;
}

/*
 * WPackLong
 *
 * Compress a 32-bit value into a 16-bit packed representation.
 *
 * The return value is formatted as:
 *   bits 15..13 : exponent (right-shift count)
 *   bits 12..0  : mantissa (13-bit unsigned value)
 *
 * The input value is repeatedly shifted right (logical shift)
 * until it fits in 13 bits. Each shift increments the exponent.
 *
 * This matches the original Win16 behavior:
 *   - shifting is unsigned (logical), not arithmetic
 *   - truncation occurs naturally during shifts
 *   - no saturation or rounding is performed
 *
 * Used to store large counters in a compact form while preserving
 * relative magnitude.
 */
uint16_t WPackLong(int32_t l) {
    /* Original uses logical (unsigned) right shifts and packs:
       top 3 bits = exponent, low 13 bits = mantissa (< 0x2000). */
    uint32_t u = (uint32_t)l;
    uint16_t exp = 0;

    while (((u & 0xE000u) != 0) || ((u >> 16) != 0)) {
        u >>= 1;
        exp++;
    }

    return (uint16_t)((exp << 13) | u);
}

double DGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2) {
    int32_t dy;
    int32_t dx;
    int32_t l;

    dx = (int32_t)x2 - (int32_t)x1;
    dy = (int32_t)y2 - (int32_t)y1;
    l = (int32_t)((int64_t)dx * (int64_t)dx + (int64_t)dy * (int64_t)dy);
    /* Use double sqrt like the original (which routed through the C runtime). */
    return sqrt((double)l);
}

int16_t FDeleteFleet(int16_t idFleet, int16_t grobjSel, int16_t idSel) {
    int16_t i;
    FLEET  *lpfl;
    int16_t iPlr;
    int16_t idDel;
    PLANET *lppl;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x2eb7 */

    /* TODO: implement */
    return 0;
}

int32_t WtFromLpfl(FLEET *lpfl) {
    int32_t cMass;
    int16_t i;

    cMass = 0;
    for (i = 0; i <= cShdefMax; i++) {
        if (lpfl->rgcsh[i] > 0) {
            cMass += (int32_t)lpfl->rgcsh[i] * (uint32_t)rglpshdef[lpfl->iPlayer][i].hul.wtEmpty;
        }
    }
    for (i = 0; i < 4; i++) {
        cMass += lpfl->rgwtMin[i];
    }
    return cMass;
}

#ifdef _WIN32
void SelectOursAtObject(POINT *ppt) {
    int16_t    id;
    STARSPOINT pt;
    int16_t    ish;
    int16_t    i;
    FLEET     *lpfl;
    SCAN       scan;

    if (ppt->x == -1) {
        if (ppt->y & 0x8000) {
            SelectAdjFleet(0, (int16_t)(ppt->y & 0x7FFF));
            return;
        }
        pt = rgptPlan[ppt->y];
    } else {
        pt.x = (int16_t)ppt->x;
        pt.y = (int16_t)ppt->y;
    }

    id = -1;
    for (ish = 0; ish < cFleet; ish++) {
        lpfl = rglpfl[ish];
        if (lpfl == NULL)
            break;
        if (pt.x == lpfl->pt.x && pt.y == lpfl->pt.y) {
            if (lpfl->iPlayer == idPlayer) {
                SelectAdjFleet(0, lpfl->id);
                return;
            }
            if (id == -1)
                id = lpfl->id;
        }
    }

    for (i = 0; i < game.cPlanMax; i++) {
        if (rgptPlan[i].x == pt.x && rgptPlan[i].y == pt.y) {
            SelectAdjPlanet(0, i);
            return;
        }
    }

    scan.iwp = -1;
    if (FFindNearestObject(pt, grobjThing, &scan) && scan.grobj == grobjThing && scan.ith != -1 && lpThings[scan.ith].ith == 1 &&
        lpThings[scan.ith].thp.iWarp == 0) {
        ChangeScanSel(&scan, 1);
        {
            POINT ptScreen = {scan.pt.x, scan.pt.y};
            FEnsurePointOnScreen(ptScreen, 1);
        }
        UpdateWindow(hwndScanner);
        SendMessage(hwndScanner, WM_CHAR, 0x76, 0);
    } else {
        if (id != -1)
            SelectAdjFleet(0, id);
    }
}
#endif /* _WIN32 */

char *PszGetPlanetName(int16_t id) {
    char *pszPlan;

    pszPlan = PszGetCompressedPlanet(rgidPlan[id & 0x7fff]);

    if (((uint16_t)id & 0x8000) == 0) {
        strcpy(szWork, pszPlan);
    } else {
        char *pszFmt = PszGetCompressedString(idsOrbitingS); /* 0x365 */
        (void)sprintf(szWork, pszFmt, pszPlan);
    }

    return szWork;
}

int16_t FDupFleet(FLEET *lpfl, FLEET *pfl) {
    PLORD *savedLpplord;
    PLORD *srcPlord;
    PLORD *dstPlord;

    savedLpplord = pfl->lpplord;

    /* REP MOVSW (0x3e words) == struct copy */
    *pfl = *lpfl;

    if (lpfl->lpplord == NULL) {
        if (savedLpplord != NULL) {
            FreePl((PL *)savedLpplord);
        }
    } else {
        /* restore destination's old order block pointer before resize/copy */
        pfl->lpplord = savedLpplord;

        srcPlord = lpfl->lpplord;

        if (pfl->lpplord == NULL) {
            dstPlord = (PLORD *)LpplAlloc(sizeof(ORDER), (uint16_t)srcPlord->iordMax, htOrd);
            pfl->lpplord = dstPlord;
        } else {
            dstPlord = pfl->lpplord;
            if (dstPlord->iordMax < srcPlord->iordMac) {
                dstPlord = (PLORD *)LpplReAlloc((PL *)dstPlord, (uint16_t)srcPlord->iordMax);
                pfl->lpplord = dstPlord;
            }
        }

        memcpy((uint8_t *)pfl->lpplord + 4, (uint8_t *)lpfl->lpplord + 4, (size_t)srcPlord->iordMac * sizeof(ORDER));

        pfl->lpplord->iordMac = srcPlord->iordMac;
    }

    return 1;
}

int16_t FDupPlanet(PLANET *lppl, PLANET *ppl) {
    PLPROD *savedLpplprod;
    PLPROD *srcPlprod;
    PLPROD *dstPlprod;

    savedLpplprod = ppl->lpplprod;

    /* REP MOVSW (0x1c words) == struct copy */
    // memcpy(ppl, lppl, offsetof(PLANET, lpplprod));
    *ppl = *lppl;

    /* restore destination's lpplprod */
    ppl->lpplprod = savedLpplprod;

    if (lppl->lpplprod == NULL) {
        if (ppl->lpplprod != NULL) {
            FreePl((PL *)ppl->lpplprod);
            ppl->lpplprod = NULL;
        }
    } else {
        srcPlprod = lppl->lpplprod;

        if (ppl->lpplprod == NULL) {
            dstPlprod = (PLPROD *)LpplAlloc(sizeof(PROD), (uint16_t)srcPlprod->iprodMax, htOrd);
            ppl->lpplprod = dstPlprod;
        } else {
            dstPlprod = ppl->lpplprod;
            if (dstPlprod->iprodMax < srcPlprod->iprodMac) {
                dstPlprod = (PLPROD *)LpplReAlloc((PL *)dstPlprod, (uint16_t)srcPlprod->iprodMax);
                ppl->lpplprod = dstPlprod;
            }
        }

        // copy production queue entries to duplicate planet
        memcpy(ppl->lpplprod->rgprod, srcPlprod->rgprod, (size_t)srcPlprod->iprodMac * sizeof(PROD));
        ppl->lpplprod->iprodMac = srcPlprod->iprodMac;
    }

    return 1;
}

char *PszFleetNameFromWord(uint16_t w) {
    uint16_t ishdef;
    int16_t  cch;
    char     szShdef[34];
    char    *lpsz;

    ishdef = (uint16_t)((w >> 9) & 15);

    if (!rglpshdef[idPlayer][ishdef].fFree) {
        strcpy(szShdef, rglpshdef[idPlayer][ishdef].hul.szClass);

        cch = (int16_t)strlen(szShdef);
        if (cch > 28) {
            cch = 28;
            szShdef[cch] = '\0';
        }

        if ((w & 0x2000) != 0) {
            szShdef[cch] = '+';
            szShdef[cch + 1] = '\0';
        }

        lpsz = szShdef;
    } else {
        lpsz = PszGetCompressedString(idsFleet); /* 0x4e8 */
    }

    (void)sprintf(szWork, "%s #%d", lpsz, (int)((w & 0x1ff) + 1));
    return szWork;
}

int16_t FValidSerialNo(char *psz, int32_t *plSerial) {
    // int32_t lBuild;
    // int16_t i;
    // int32_t lCur;
    // int32_t lSerial;
    // int32_t l;

    /* TODO: implement */
    // all serials are valid
    return true;
}

char *PszGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2) {
    int32_t d;
    int32_t whole;
    int32_t frac;
    char   *psz;

    d = (int32_t)DGetDistance(x1, y1, x2, y2);
    whole = d / 100;
    frac = d - whole * 100;
    if (dyArial8 < 15) {
        psz = PszGetCompressedString(idsLdLdLightYears);
        wsprintf(szWork, psz, whole, frac);
    } else {
        psz = PszGetCompressedString(idsLdLdLY);
        wsprintf(szWork, psz, whole, frac);
    }
    return szWork;
}

void CalcPctSurvive(PLANET *lppl, float *ppct, float *ppctSmart) {
    int16_t iPlrSav;
    int32_t cDefenses;
    float   pct;
    PART    part;
    int16_t cMax;

    /* Default smart-bomb survival to 1.0 if requested. */
    if (ppctSmart != NULL) {
        *ppctSmart = 1.0f;
    }

    /* If no owner or no defenses, everyone survives. */
    if (lppl->iPlayer == -1 || (lppl->cDefenses & 0x0FFFu) == 0) {
        pct = 1.0f;
        *ppct = pct;
        return;
    }

    /* Temporarily set global current player to planet owner (matches original). */
    iPlrSav = idPlayer;
    idPlayer = lppl->iPlayer;

    if (!FGetBestDefensePart(&part)) {
        pct = 1.0f;
    } else {
        /* Clamp defenses by max operable. */
        cDefenses = (int32_t)(lppl->cDefenses & 0x0FFFu);

        cMax = CMaxOperableDefenses(lppl, lppl->iPlayer, false);
        if ((int32_t)cMax < cDefenses) {
            cDefenses = (int32_t)cMax;
        }

        /* dDmgCol is at +0x34 in the defense "terra" part (bomb). */
        {
            const int16_t dDmgCol = *(const int16_t *)((const uint8_t *)part.pterra + 0x34);

            /* Normal bombs: (1 - dDmgCol/1000) ^ cDefenses */
            const double base = 1.0 - ((double)dDmgCol / 1000.0);
            pct = (float)pow(base, (double)cDefenses);

            /* Smart bombs: (1 - dDmgCol/2000) ^ cDefenses */
            if (ppctSmart != NULL) {
                const double baseSmart = 1.0 - ((double)dDmgCol / 2000.0);
                *ppctSmart = (float)pow(baseSmart, (double)cDefenses);
            }
        }
    }

    /* Restore global current player. */
    idPlayer = iPlrSav;

    *ppct = pct;
}

int16_t IshFindSimilarDesign(HUL *lphul, int16_t iPlrDst) {
    SHDEF  *lpshdefDest;
    int16_t i;
    int16_t j;

    lpshdefDest = rglpshdef[iPlrDst];
    for (i = 0; i <= cShdefMax; i++) {
        if (!lpshdefDest[i].fFree && lpshdefDest[i].fGift && lpshdefDest[i].hul.ihuldef == lphul->ihuldef) {
            if (lpshdefDest[i].hul.chs == lphul->chs) {
                j = 0;
                while (j < (int16_t)lphul->chs && lphul->rghs[j].cItem == lpshdefDest[i].hul.rghs[j].cItem &&
                       (lphul->rghs[j].cItem == 0 ||
                        (lphul->rghs[j].iItem == lpshdefDest[i].hul.rghs[j].iItem && lphul->rghs[j].grhst == lpshdefDest[i].hul.rghs[j].grhst))) {
                    j++;
                }
                if (j == (int16_t)lphul->chs) {
                    return i;
                }
            }
        }
    }
    return -1;
}

void DecorateHullName(int16_t iplr, int16_t ish, char *psz) {
    int16_t i;
    int16_t c;
    SHDEF  *lpshdef;
    int16_t iVal;

    lpshdef = &rglpshdef[iplr][ish];
    if (!lpshdef->fFree) {
        strcpy(psz, lpshdef->hul.szClass);
        if (iplr != idPlayer) {
            c = 0;
            iVal = 1;
            for (i = 0; i < 16; i++) {
                if (i != ish && !rglpshdef[iplr][i].fFree && strcmp(psz, rglpshdef[iplr][i].hul.szClass) == 0) {
                    c++;
                    if (i < ish) {
                        iVal++;
                    }
                }
            }
            if (c != 0) {
                int16_t len = (int16_t)strlen(psz);
                psz[len] = ' ';
                psz[len + 1] = '(';
                IntToRoman(iVal, psz + len + 2);
                strcat(psz, ")");
            }
        }
    } else {
        *psz = '\0';
    }
}

int16_t FCanBuildShdef(SHDEF *lpshdef, int16_t iplr) {
    int16_t j;
    int16_t iplrSav;
    PART    part;

    iplrSav = idPlayer;
    if (lpshdef->hul.ihuldef < ihuldefCount) {
        part.hs.grhst = hstHull;
        part.hs.iItem = lpshdef->hul.ihuldef & 0xff;
    } else {
        part.hs.grhst = hstSBHull;
        part.hs.iItem = (lpshdef->hul.ihuldef - ihuldefCount) & 0xff;
    }
    idPlayer = iplr;
    if (FLookupPart(&part) == 1) {
        for (j = 0; j < (int16_t)lpshdef->hul.chs; j++) {
            if (lpshdef->hul.rghs[j].cItem != 0) {
                part.hs = lpshdef->hul.rghs[j];
                if (FLookupPart(&part) != 1)
                    goto LFail;
            }
        }
        idPlayer = iplrSav;
        return 1;
    }
LFail:
    idPlayer = iplrSav;
    return 0;
}

int16_t FFleetMergeAll(FLEET *pfl) {
    int16_t iplr;
    int32_t dpT;
    int16_t fCshOverflow;
    int16_t rgcshDamaged[16];
    int16_t cflMerge;
    int16_t i;
    FLEET  *lpfl;
    int16_t cshT;
    SHDEF  *lpshdef;
    FLEET  *lpflMerge;
    int32_t rgdp[16];
    int16_t j;

    /* TODO: implement */
    return 0;
}

int16_t ICompFleetPoint2(void *arg1, void *arg2) {
    const uint16_t *ptw = (const uint16_t *)arg1;     /* POINT: [x, y] */
    const FLEET    *fl = *(const FLEET *const *)arg2; /* element is a FLEET* */

    int16_t y = (int16_t)ptw[1];
    int16_t fy = fl->pt.y;

    if (y < fy)
        return -1;
    if (y > fy)
        return 1;

    /* matches the packed-32bit compare semantics: low word is effectively unsigned */
    uint16_t x = ptw[0];
    uint16_t fx = (uint16_t)fl->pt.x;

    if (x < fx)
        return -1;
    if (x > fx)
        return 1;
    return 0;
}

void TurnLog(StringId ids) {
    char szTemp[256];

    if (ini.fLogging) {
        int16_t year = game.turn + 2401;
        char   *psz = PszFormatIds(ids, NULL);
        snprintf(szTemp, sizeof(szTemp), psz, year);
        OutputSz(6, szTemp);
    }
}

char *PszPlayerName(int16_t iPlayer, int16_t fCapital, int16_t fPlural, int16_t fThe, int16_t grWord, PLAYER *pplr) {
    uint16_t u;
    char     szName[50];
    char    *pchEnd;

    if (pplr == (PLAYER *)0) {
        pplr = &rgplr[iPlayer];
    }

    if (pplr->szName[0] == '\0') {
        // TODO: remove this dependency on szLastStrGet
        (void)PszGetCompressedString(idsPlayerD2);
        (void)sprintf(szName, "%s", szLastStrGet); /* faithful-ish: wsprintf used compressed result */
        if (fPlural == 0) {
            strcat(szName, "'s"); /* 0x515 */
        }
        if (grWord == 1) {
            u = (uint16_t)strlen(szName);
            (void)CchGetString(idsHas, szName + u); /* 0x55c */
        } else if (grWord == 2) {
            u = (uint16_t)strlen(szName);
            (void)CchGetString(idsIs2, szName + u); /* 0x55d */
        }
    } else {
        if (fThe == 0) {
            szName[0] = '\0';
        } else {
            strcpy(szName, "the "); /* 0x50e */
            if (fCapital != 0) {
                szName[0] = 'T';
            }
        }

        if ((fPlural == 0) || (pplr->szNames[0] == '\0')) {
            strcat(szName, pplr->szName);
        } else {
            strcat(szName, pplr->szNames);
        }

        u = (uint16_t)strlen(szName);
        if (u != 0) {
            pchEnd = szName + (u - 1);
            while ((pchEnd >= szName) && (*pchEnd == ' ')) {
                *pchEnd-- = '\0';
            }
        } else {
            pchEnd = szName - 1;
        }

        if (pchEnd < szName) {
            (void)CchGetString(idsName, szName);
        }

        if ((fPlural != 0) && (pplr->szNames[0] == '\0')) {
            u = (uint16_t)strlen(szName);
            if (u >= 2) {
                if ((szName[u - 1] != 's') && !((szName[u - 1] == 'e') && (szName[u - 2] == 's'))) {
                    strcat(szName, "s"); /* 0x513 */
                }
            } else if (u == 1) {
                if (szName[0] != 's') {
                    strcat(szName, "s"); /* 0x513 */
                }
            } else {
                strcat(szName, "s"); /* 0x513 */
            }
        }

        if (grWord == 1) {
            u = (uint16_t)strlen(szName);
            (void)CchGetString(idsHave2, szName + u);
        } else if (grWord == 2) {
            u = (uint16_t)strlen(szName);
            (void)CchGetString(idsAre, szName + u);
        }
    }

    strcpy(szWork, szName);
    return szWork;
}

int16_t IStargateFromLppl(PLANET *lppl) {
    int16_t chs;
    HS     *lphs;
    int16_t ihs;
    HUL    *lphul;

    if (lppl != NULL && lppl->fStarbase) {
        lphul = &rglpshdefSB[lppl->iPlayer][lppl->isb].hul;
        lphs = lphul->rghs;
        for (ihs = 0; ihs < lphul->chs; ihs++) {
            if (lphs->grhst == hstSpecialSB && lphs->cItem != 0 && lphs->iItem < 7) {
                return lphs->iItem;
            }
            lphs++;
        }
    }
    return -1;
}

int32_t DpOfLpflIshdef(FLEET *lpfl, int16_t ishdef) {
    uint16_t dpShdef;
    int32_t  l;
    int32_t  dp;
    uint32_t u;

    dp = 5000;

    dpShdef = rglpshdef[lpfl->iPlayer][ishdef].hul.dp;
    l = (int32_t)(((int32_t)lpfl->rgdv[ishdef].pctSh * (int32_t)dpShdef) / 10);
    l *= (int32_t)lpfl->rgdv[ishdef].pctDp;

    u = (uint32_t)lpfl->rgcsh[ishdef] * (uint32_t)l;
    return (int32_t)(u / (uint32_t)dp);
}

int16_t FFleetSplitAll(FLEET *pfl) {
    FLEET   flNew;
    int16_t cSplit;
    int16_t c;
    int16_t i;
    FLEET  *lpflNew;

    cSplit = 0;
    for (i = 0; i < cShdefMax; i++) {
        c = pfl->rgcsh[i];
        while (c != 0) {
            c--;
            cSplit++;
            if (cSplit > 1) {
                lpflNew = LpflNewSplit(pfl);
                flNew = *lpflNew;
                pfl->rgcsh[i]--;
                flNew.rgcsh[i]++;
                FleetTransferCargoBalance(pfl, &flNew);
                FLookupFleet(-1, pfl);
                FLookupFleet(-1, &flNew);
            }
        }
    }
    InvalidateReport(1, 2);
    return (int16_t)(cSplit > 1);
}

int16_t ICompFleetPoint(void *arg1, void *arg2) {
    int32_t l1;
    int32_t l2;
    FLEET  *lpfl1;
    FLEET  *lpfl2;

    lpfl1 = *(FLEET **)arg1;
    lpfl2 = *(FLEET **)arg2;
    l1 = ((int32_t)lpfl1->pt.y << 16) | (uint16_t)lpfl1->pt.x;
    l2 = ((int32_t)lpfl2->pt.y << 16) | (uint16_t)lpfl2->pt.x;
    if (l1 < l2)
        return -1;
    if (l1 > l2)
        return 1;
    return 0;
}

void OutputSz(int16_t dt, char *sz) {
    char       szTemp[256];
    char       szDate[100];
    char       szTime[100];
    char       szFile[256];
    FILE      *fp;
    time_t     t;
    struct tm *lt;

    if (sz == NULL) {
        return;
    }

    /* _DATA::mpdtsz observed entries: xy, x, hst, m, h, r, log, chk */
    if (dt < 0 || dt >= 8) {
        return; /* original likely assumes caller passes valid dt */
    }

    /* "%s.%s" -> szBase + "." + mpdtsz[dt] */
    (void)snprintf(szFile, sizeof(szFile), "%s.%s", szBase, mpdtsz[dt]);

    /* If file doesn't exist: write "Stars! %s\r\n\r\n" with version string. */
    fp = fopen(szFile, "rb");
    if (fp == NULL) {
        char *ver = SzVersion();
        (void)snprintf(szTemp, sizeof(szTemp), "Stars! %s\r\n\r\n", ver ? ver : "");
        OutputFileString(szFile, szTemp);
    } else {
        (void)fclose(fp);
    }

    /* __strdate -> mm/dd/yy, __strtime -> HH:MM:SS */
    t = time(NULL);
    lt = localtime(&t);
    if (lt != NULL) {
        strftime(szDate, sizeof(szDate), "%m/%d/%y", lt);
        strftime(szTime, sizeof(szTime), "%H:%M:%S", lt);
    } else {
        szDate[0] = '\0';
        szTime[0] = '\0';
    }

    /* "%s %s - %s\r\n" */
    (void)snprintf(szTemp, sizeof(szTemp), "%s %s - %s\r\n", szDate, szTime, sz);
    OutputFileString(szFile, szTemp);
}

void ComputeShdefPowers(void) {
    int16_t iplr;
    int16_t ishdef;
    int32_t lPower;

    for (iplr = 0; iplr < game.cPlayer; iplr++) {
        if (rglpshdef[iplr] != NULL) {
            for (ishdef = 0; ishdef < cShdefMax; ishdef++) {
                if (!rglpshdef[iplr][ishdef].fFree) {
                    lPower = LComputePower(&rglpshdef[iplr][ishdef]);
                    rglpshdef[iplr][ishdef].lPower = lPower;
                }
            }
        }
    }
}

int16_t GetPlanetScannerRange(PLANET *lppl, int16_t *pDeep) {
    int16_t iPlrSav;
    int16_t dRange;
    PART    part;

    iPlrSav = idPlayer;
    idPlayer = lppl->iPlayer;

    if (pDeep != NULL) {
        *pDeep = 0;
    }

    if (GetRaceStat(&rgplr[lppl->iPlayer], rsMajorAdv) == raMacintosh) {
        dRange = (int16_t)(int32_t)sqrt((double)((uint32_t)lppl->rgwtMin[3] * 10));
        if (GetRaceGrbit(&rgplr[idPlayer], ibitRaceNoAdvScanner) == 0) {
            if (pDeep != NULL && lppl->fStarbase && rglpshdefSB[lppl->iPlayer][lppl->isb].hul.ihuldef > (ihuldefSBSpaceStation + ihuldefCount)) {
                *pDeep = dRange / 2;
            }
        } else {
            dRange = (int16_t)((int32_t)dRange * 1412 / 1000);
            if (pDeep != NULL) {
                *pDeep = 0;
            }
        }
    } else {
        if (lppl->iScanner == iNoScanner) {
            dRange = 0;
        } else {
            LookupBestPlanetaryScanner(&part);
            if (pDeep != NULL && part.pscanner->dRange < 0) {
                *pDeep = -part.pscanner->dRange >> 1;
            }
            dRange = abs(part.pscanner->dRange);
            if (GetRaceGrbit(&rgplr[idPlayer], ibitRaceNoAdvScanner) != 0) {
                dRange = dRange << 1;
            }
        }
    }

    idPlayer = iPlrSav;
    return dRange;
}

FLEET *LpflNew(int16_t iPlr, int16_t idPl) {
    int16_t i;
    ORDER  *lpord;
    FLEET  *lpfl;
    int16_t iflPrev;

    iflPrev = -1;
    for (i = 0; i < cFleet; i++) {
        lpfl = rglpfl[i];
        if (lpfl == NULL)
            break;
        if (iPlr <= lpfl->iPlayer) {
            if (iPlr < lpfl->iPlayer || (lpfl->id & 0x1ff) != iflPrev + 1)
                break;
            iflPrev = lpfl->id & 0x1ff;
        }
    }

    rglpfl = LpReAlloc(rglpfl, (cFleet + 1) * 4, htMisc);
    if (cFleet != i) {
        memmove(&rglpfl[i + 1], &rglpfl[i], (cFleet - i) * 4);
    }

    lpfl = LpAlloc(sizeof(FLEET), htFleets);
    rglpfl[i] = lpfl;
    cFleet++;
    rgplr[iPlr].cFleet = (rgplr[iPlr].cFleet + 1) & 0xfff;

    memset(lpfl, 0, sizeof(FLEET));
    lpfl->ifl = (iflPrev + 1) & 0x1ff;
    lpfl->iPlayer = iPlr;
    lpfl->iplr = iPlr & 0xf;
    lpfl->det = detAll;
    lpfl->idPlanet = idPl;
    if (idPl != -1) {
        lpfl->pt.x = rgptPlan[idPl].x;
        lpfl->pt.y = rgptPlan[idPl].y;
    }
    lpfl->cord = 1;
    lpfl->fRepOrders = 0;

    lpfl->lpplord = (PLORD *)LpplAlloc(sizeof(ORDER), 3, htOrd);
    lpfl->lpplord->iordMac = 1;
    lpfl->fTargeted = 0;

    lpord = &lpfl->lpplord->rgord[0];
    lpord->pt.x = lpfl->pt.x;
    lpord->pt.y = lpfl->pt.y;
    lpord->id = lpfl->idPlanet;

    /* ASM: grobj = (idPl == -1) ? 4 : 1; iWarp = 0; fValidTask = 1; grTask = 0 */
    lpord->iWarp = 0;
    lpord->grobj = (lpfl->idPlanet == -1) ? 4 : 1; /* 4==deep space, 1==planet in the original */
    lpord->fValidTask = 1;
    lpord->fNoAutoTrack = 0;
    lpord->grTask = 0;

    if (sel.scan.ifl != -1 && i <= sel.scan.ifl) {
        sel.scan.ifl++;
    }
    gd.fFleetLinkValid = 0;

    return lpfl;
}

void UpdateShdefCost(SHDEF *shdef) {
    bool     fRegenArmorHalved;
    PART     part;
    HULDEF  *huldef;
    uint32_t rgMin[3];
    uint16_t rgCosts[4];
    uint16_t resCost;
    uint16_t wtEmpty;
    int16_t  c;
    int16_t  k;

    /* det == 7 enables the regenerating-shields race behavior */
    if (shdef->det == 7) {
        fRegenArmorHalved = GetRaceGrbit((PLAYER *)rgplr + idPlayer, ibitRaceRegeneratingShields) != 0;
    } else {
        fRegenArmorHalved = false;
    }

    huldef = LphuldefFromId(shdef->hul.ihuldef);
    part.hs.grhst = hstNone;
    part.phul = (HUL *)huldef;

    GetTruePartCost(idPlayer, &part, rgCosts);

    for (c = 0; c < 3; c++) {
        rgMin[c] = rgCosts[c];
    }

    resCost = rgCosts[Resources];

    wtEmpty = huldef->hul.wtEmpty;
    shdef->hul.dp = huldef->hul.dp;

    /* Installed slot parts */
    for (c = 0; c < shdef->hul.chs; c++) {
        HS          *hs;
        uint16_t     count;
        HullSlotType grhst;

        hs = &shdef->hul.rghs[c];

        if (hs->cItem == 0)
            continue;

        count = hs->cItem;

        part.hs.grhst = hs->grhst;
        part.hs.iItem = hs->iItem;
        part.hs.cItem = hs->cItem;

        FLookupPart(&part);
        GetTruePartCost(idPlayer, &part, rgCosts);

        for (k = 0; k < 3; k++) {
            rgMin[k] += (uint32_t)count * rgCosts[k];
        }

        resCost += count * rgCosts[Resources];
        wtEmpty += count * part.pcom->cMass;

        grhst = hs->grhst;

        if (grhst == hstShield) {
            if (hs->iItem == ishieldCrobySharmor || hs->iItem == ishieldLangstonShell) {
                shdef->hul.dp += count * 65;
            }
        } else if (grhst == hstArmor) {
            int32_t dpT = count * part.parmor->dp;
            if (fRegenArmorHalved) {
                dpT >>= 1;
            }
            shdef->hul.dp += dpT;
        } else if (grhst == hstSpecialM) {
            if (hs->iItem == ispecialMMultiCargoPod) {
                shdef->hul.dp += count * 50;
            }
        }
    }

    for (c = 0; c < 3; c++) {
        shdef->hul.rgwtOreCost[c] = rgMin[c];
    }

    shdef->hul.resCost = resCost;
    shdef->hul.wtEmpty = wtEmpty;

    /* Original wrote -1 (0xFFFFFFFF) */
    shdef->lPower = -1;
}

int16_t FLookupSelPlanet(PLANET *ppl) {
    if (sel.scan.grobj == grobjPlanet) {
        return FLookupPlanet(sel.scan.idpl, ppl);
    }
    return 0;
}

int16_t FLookupThing(int16_t idth, THING *pth) {
    THING  *lpth;
    int16_t fWrite;

    if (cThing < 1) {
        return 0;
    }

    fWrite = (int16_t)(idth < 0);
    if (fWrite) {
        /* If you want strict faithfulness, assume pth != NULL here. */
        if (pth == NULL) {
            return 0; /* or remove this check to match original crashy behavior */
        }
        idth = pth->idFull;
    }

    lpth = LpthFromId(idth);

    if (lpth != NULL && pth != NULL) {
        if (fWrite) {
            LogChangeThing(lpth, pth);
            memcpy(lpth, pth, sizeof(THING));
            if (gd.fTutorial && idPlayer == 0) {
                AdvanceTutor();
            }
        } else {
            memcpy(pth, lpth, sizeof(THING));
        }
    }

    return (lpth != NULL) ? 1 : 0;
}

int16_t FLookupFleet(int16_t idFleet, FLEET *pfl) {
    FLEET  *lpfl;
    int16_t fWrite;

    if (cFleet < 1) {
        return 0;
    }

    /* Negative idFleet means write mode: use pfl->id as the lookup key */
    fWrite = (int16_t)(idFleet < 0);
    if (fWrite) {
        if (pfl == NULL) {
            return 0;
        }
        idFleet = pfl->id;
    }

    lpfl = LpflFromId(idFleet);

    if (lpfl != NULL && pfl != NULL) {
        if (fWrite) {
            InvalidateReport(1, 0);
            LogChangeFleet(lpfl, pfl);

            /*
             * If the order-list pointer differs, ensure destination has enough capacity
             * and copy the orders (header already exists in dst).
             */
            if (lpfl->lpplord != pfl->lpplord) {
                PLORD *dst = lpfl->lpplord;
                PLORD *src = pfl->lpplord;

                if (dst != NULL && src != NULL) {
                    if ((int16_t)dst->iordMax < pfl->cord) {
                        dst = (PLORD *)LpplReAlloc((PL *)dst, (int16_t)(pfl->cord + 3));
                        lpfl->lpplord = dst;
                    }

                    memcpy((uint8_t *)dst + offsetof(PLORD, rgord), (const uint8_t *)src + offsetof(PLORD, rgord), (size_t)src->iordMac * sizeof(ORDER));

                    dst->iordMac = src->iordMac;
                }
            }

            /*
             * Decompile copied 100 bytes: everything up to (but not including) lpplord.
             * This preserves lpplord/lpflNext/etc. runtime pointers in the stored fleet.
             */
            _Static_assert(offsetof(FLEET, lpplord) == 100, "FLEET layout changed: expected lpplord at +0x64");
            memcpy(lpfl, pfl, offsetof(FLEET, lpplord));

            if (gd.fTutorial && idPlayer == 0) {
                AdvanceTutor();
            }
        } else if (pfl == (FLEET *)&sel.fl) {
            FDupFleet(lpfl, (FLEET *)&sel.fl);
        } else {
            /* Read mode: decompile copied the whole struct out. */
            memcpy(pfl, lpfl, sizeof(FLEET));
        }
    }

    /* Return true iff the fleet exists, regardless of pfl */
    return (lpfl != NULL) ? 1 : 0;
}
int16_t FLookupOrbitingXfer(int16_t idPlanet, int16_t iNth, XFER *pxf, int16_t idSkip) {
    int16_t i;
    THING  *lpth;
    FLEET  *lpfl;
    THING  *lpthMac;

    if (cFleet <= 0)
        return 0;

    for (i = 0; i < cFleet; i++) {
        lpfl = rglpfl[i];
        if (lpfl == NULL)
            break;
        if (lpfl->idPlanet == idPlanet && lpfl->id != idSkip && (idSkip == -1 || (lpfl->pt.x == sel.pt.x && lpfl->pt.y == sel.pt.y))) {
            if (iNth-- == 0) {
                if (pxf != NULL) {
                    pxf->fl = *lpfl;
                    pxf->grobj = grobjFleet;
                    pxf->id = lpfl->id;
                }
                return 1;
            }
        }
    }

    FORTHINGS(lpth, lpthMac) {
        if (lpth->ith == 1 && lpth->pt.x == sel.pt.x && lpth->pt.y == sel.pt.y) {
            if (iNth-- == 0) {
                if (pxf != NULL) {
                    pxf->th = *lpth;
                    pxf->grobj = grobjThing;
                    pxf->id = lpth->idFull;
                }
                return 1;
            }
        }
    }

    return 0;
}

void LinkFleets(int16_t fUnused) {
    FLEET **pSearch;
    POINT   pt;
    FLEET  *rglpflSrc[1];
    FLEET  *lpflTail;
    FLEET  *lpflHead;
    int16_t i;
    int16_t iflTail;
    int16_t iflHead;
    int16_t cSrc;

    /* TODO: implement */
}

int16_t FCalcFleetBombDamage(FLEET *lpfl, int32_t *pdmgPeople, int32_t *pdmgPeopleMin, int32_t *pdmgPeopleSmart, int32_t *pdmgBldg, int32_t *ppctTerra,
                             int16_t *pfMulti) {
    int16_t iplr;
    int16_t cfl;
    FLEET  *lpflNext;
    int16_t dmgFloor;
    FLEET  *lpflHead;
    double  dmgSmart;
    int16_t fBomber;
    int16_t j;
    int16_t ishdef;
    PART    part;
    int32_t cIter;
    double  dmgT;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x1615 */

    /* TODO: implement */
    return 0;
}

int16_t IflFromLpfl(FLEET *lpfl) {
    int16_t i;

    for (i = 0; i < cFleet; i++) {
        if (rglpfl[i] == lpfl) {
            return i;
        }
    }
    return -1;
}

int32_t DpShieldOfShdef(SHDEF *lpshdef, int16_t iplr) {
    HS     *lphs;
    int16_t ihs;
    int32_t dpShdef;
    PART    part;
    int16_t cItem;

    dpShdef = 0;
    lphs = lpshdef->hul.rghs;

    for (ihs = 0; ihs < (int16_t)lpshdef->hul.chs; ihs++) {
        cItem = lphs->cItem;
        if (lphs->grhst == hstShield && cItem != 0) {
            part.hs = *lphs;
            FLookupPart(&part);
            dpShdef += (uint32_t)part.pshield->dp * cItem;
        } else if (lphs->grhst == hstArmor && cItem != 0 && lphs->iItem == iarmorFieldedKelarium) {
            dpShdef += cItem * 50;
        } else if (lphs->grhst == hstArmor && lphs->iItem == iarmorMegaPolyShell) {
            dpShdef += cItem * 100;
        }
        lphs++;
    }

    if (GetRaceGrbit(&rgplr[iplr], ibitRaceRegeneratingShields)) {
        dpShdef = dpShdef + dpShdef * 2 / 5;
    }

    if ((dpShdef >> 16) != 0)
        dpShdef = 0xffff;

    return dpShdef;
}

void GetTrueHullCost(int16_t iPlayer, HUL *lphul, uint16_t *rgCost) {
    int16_t i;

    for (i = 0; i < 3; i++) {
        rgCost[i] = lphul->rgwtOreCost[i];
    }
    rgCost[3] = lphul->resCost;
}

int16_t GetShdefScannerRange(SHDEF *lpshdef, int16_t iplr, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal) {
    int16_t chs;
    HS     *lphs;
    int16_t dRangeT2;
    double  lBIR4;
    int16_t dRangeT;
    int16_t fHasScanner;
    int16_t iScanner;
    int16_t fBuiltIn;
    int16_t cDetectors;
    double  lPlanRange4;
    int16_t dRange;
    double  lT;
    int16_t iSteal;
    int16_t j;
    double  lBIPR4;
    double  lRange4;

    /* debug symbols */
    /* label LPlanScan @ MEMORY_UTIL:0x53ed */
    /* label LOddBallScanners @ MEMORY_UTIL:0x5482 */

    /* TODO: implement */
    return 0;
}

void ValidateWaypoints(void) {
    int16_t mdTarget;
    FLEET  *lpflTarget;
    int16_t ifl2;
    int32_t wt;
    FLEET  *lpflMatch;
    int32_t wtMatch;
    ORDER  *lpord;
    int16_t ifl;
    THING  *lpth;
    FLEET  *lpfl;
    int16_t cFound;
    int16_t iord;
    FLEET  *lpfl2;
    int16_t iplrHi;

    /* TODO: implement */
}

int32_t ChgPopFromPlanet(PLANET *lppl, int16_t fUpdate) {
    // TODO: not tested
    /* In the asm, lPopOld is read from ES:[BX+0x28] and +0x2A (a 32-bit long). */
    int32_t lPopOld = lppl->rgwtMin[3];
    int32_t lPopInc = 0;

    /* early out: unowned or zero pop */
    if (lppl->iPlayer == (int16_t)-1 || lPopOld == 0) {
        return 0;
    }

    int16_t pctDesire = PctPlanetDesirability(lppl, lppl->iPlayer);

    /* low byte accumulator stored in rgbImp (offset +0x14 in asm; your struct uses rgbImp[0]) */
    int16_t deltaCur = (uint8_t)lppl->rgbImp[0];

    if (pctDesire < 0) {
        /* ---- death path ----
           pctRetard initially set to 1, then compared against result of (lPopOld * -pctDesire)/10.
           If result <= 1, use 1; else recompute with divisor 10 and use that result. */

        int32_t lPopInc100;
        {
            uint32_t mul = (uint32_t)lPopOld * (uint32_t)(-pctDesire);
            int32_t  div10 = (int32_t)(mul / 10u);
            if (div10 <= 1) {
                lPopInc100 = 1;
            } else {
                /* recompute same expression (matches asm doing it twice) */
                lPopInc100 = (int32_t)(((uint32_t)lPopOld * (uint32_t)(-pctDesire)) / 10u);
            }
        }

        /* lPopInc = lPopInc100 / 100 ; lPopIncDelta = lPopInc100 % 100 */
        int32_t lPopIncDelta = lPopInc100 % 100;
        lPopInc = lPopInc100 / 100;

        /* if both quotient and remainder are zero, force remainder to 1 */
        if (lPopInc == 0 && lPopIncDelta == 0) {
            lPopIncDelta = 1;
        }

        /* deltaCur = (rgbImp&0xFF) - lPopIncDelta; if negative, increment lPopInc and add 100 */
        deltaCur -= (int16_t)lPopIncDelta;
        if (deltaCur < 0) {
            lPopInc += 1;
            deltaCur += 100;
        }

        /* negate lPopInc (asm does 32-bit NEG with ADC/NEG) */
        lPopInc = -lPopInc;
    } else {
        /* ---- growth path ---- */
        int32_t lMaxPop = CalcPlanetMaxPop(lppl->id, lppl->iPlayer);

        int16_t pctGrow = PctTrueMaxGrowth(lppl->iPlayer);

        /* pctGrow100 = pctGrow * pctDesire (signed 16x16 -> signed 32) */
        int32_t pctGrow100 = (int32_t)pctGrow * (int32_t)pctDesire;

        /* if generating turn and cheater => arithmetic shift right by 1 */
        if (gd.fGeneratingTurn && rgplr[lppl->iPlayer].fCheater) {
            pctGrow100 >>= 1;
        }

        /* if lPopOld <= lMaxPop/4 => skip crowding adjustments */
        if (lMaxPop != 0) {
            int32_t maxDiv4 = lMaxPop / 4;
            if (lPopOld > maxDiv4) {
                /* pctFull = (lPopOld * 1000) / lMaxPop (unsigned mul, signed div) */
                int32_t pctFull = (int32_t)(((uint32_t)lPopOld * 1000u) / (uint32_t)lMaxPop);

                if (lPopOld >= lMaxPop) {
                    /* if pop < max+10 => return 0 */
                    if (lPopOld < lMaxPop + 10) {
                        return 0;
                    }

                    /* pctRetard = 99 - (pctFull / 10) */
                    int32_t pctRetard = 99 - (pctFull / 10);

                    /* clamp: if pctRetard < -300 then set to -300 (asm constant 0xFED4) */
                    if (pctRetard < -300) {
                        pctRetard = -300;
                    }

                    /* pctGrow100 = pctRetard << 2 */
                    pctGrow100 = pctRetard << 2;
                } else {
                    /* lPopOld < lMaxPop */
                    int32_t pctRetard = 1000 - pctFull;

                    /* pctRetard = pctRetard * pctRetard (unsigned mul) */
                    uint32_t pr = (uint32_t)pctRetard;
                    uint32_t pctRetardSq = pr * pr;

                    /* if pctGrow100 < 1000 then pctGrow100 = (pctGrow100 * pctRetardSq) / 562500
                       else: pctGrow100 = (((pctGrow100 / 10) * pctRetardSq) / 562500) * 10 */
                    if (pctGrow100 < 1000) {
                        pctGrow100 = (int32_t)(((uint64_t)(uint32_t)pctGrow100 * (uint64_t)pctRetardSq) / 562500u);
                    } else {
                        int32_t t = pctGrow100 / 10;
                        t = (int32_t)(((uint64_t)(uint32_t)t * (uint64_t)pctRetardSq) / 562500u);
                        pctGrow100 = t * 10;
                    }
                }
            }
        }

        /* lPopInc100 = lPopOld * (pctGrow100 / 100)  (asm: div pctGrow100 by 100, then unsigned mul by lPopOld) */
        int32_t pctGrow100_div100 = pctGrow100 / 100;
        int32_t lPopInc100 = (int32_t)((uint32_t)lPopOld * (uint32_t)pctGrow100_div100);

        /* if lPopInc100 < 10,000,000 then recompute as (lPopOld * pctGrow100) / 100 (asm overflow-avoid / precision path) */
        if (lPopInc100 < 10000000) {
            lPopInc100 = (int32_t)(((uint64_t)(uint32_t)lPopOld * (uint64_t)(uint32_t)pctGrow100) / 100u);
        }

        /* lPopInc = lPopInc100 / 100 ; lPopIncDelta = lPopInc100 % 100 */
        int32_t lPopIncDelta = lPopInc100 % 100;
        lPopInc = lPopInc100 / 100;

        if (lPopInc == 0 && lPopIncDelta == 0) {
            lPopIncDelta = 1;
        }

        /* deltaCur = (rgbImp&0xFF) + lPopIncDelta; if >= 100 => lPopInc++ and deltaCur -= 100
           else if < 0 => lPopInc-- and deltaCur += 100 */
        deltaCur += (int16_t)lPopIncDelta;
        if (deltaCur >= 100) {
            lPopInc += 1;
            deltaCur -= 100;
        } else if (deltaCur < 0) {
            lPopInc -= 1;
            deltaCur += 100;
        }
    }

    /* ---- update-and-exit block ---- */
    if (fUpdate) {
        lppl->rgbImp[0] = (uint8_t)deltaCur;
        lppl->rgwtMin[3] += lPopInc;
    }

    return lPopInc;
}

int16_t FFleetCanJumpgate(FLEET *lpfl) {
    HS     *lphs;
    int16_t chs;
    int16_t i;
    int16_t j;

    for (i = 0; i <= cShdefMax; i++) {
        if (lpfl->rgcsh[i] > 0) {
            lphs = rglpshdef[lpfl->iPlayer][i].hul.rghs;
            chs = rglpshdef[lpfl->iPlayer][i].hul.chs;
            for (j = 0; j < chs; j++) {
                if (lphs->cItem != 0 && lphs->grhst == hstSpecialM && lphs->iItem == ispecialMJumpGate)
                    break;
                lphs++;
            }
            if (j == chs) {
                return 0;
            }
        }
    }
    return 1;
}

int32_t CalcPlayerScore(int16_t iPlr, SCORE *pscore) {
    int32_t rgcsh[3];
    int32_t lTemp;
    SCORE   score;
    PLANET *lpplMac;
    PLANET *lppl;
    int16_t i;
    int16_t ifl;
    FLEET  *lpfl;
    int16_t iTech;
    int32_t lPower;
    int16_t rgType[16];

    /* TODO: implement */
    return 0;
}

int16_t FLookupPlanet(int16_t iPlanet, PLANET *ppl) {
    PLANET *lpPl;
    int16_t fWrite;

    if (cPlanet < 1)
        return 0;

    /* Negative iPlanet means write-mode, with special handling for id == -1 */
    fWrite = 0;
    if (iPlanet < 0) {
        /* Decompile assumes ppl != NULL here */
        if (ppl == NULL) {
            return 0;
        }

        iPlanet = ppl->id;
        if (iPlanet == -1) {
            LogChangePlanet(NULL, ppl);
            return 1;
        }
        fWrite = 1;
    }

    lpPl = LpplFromId(iPlanet);

    /* If planet doesn't exist or ppl is NULL, skip copy but return existence */
    if (lpPl == NULL || ppl == NULL) {
        return (lpPl != NULL) ? 1 : 0;
    }

    if (!fWrite) {
        /* Read-mode: special-case selection planet */
        if (ppl == (PLANET *)&sel.pl) {
            FDupPlanet(lpPl, (PLANET *)&sel.pl);
        } else {
            /* Decompile did a word-loop copy; memcpy is equivalent here */
            memcpy(ppl, lpPl, sizeof(PLANET));
        }
        return 1;
    }

    /* Write-mode */
    InvalidateReport(0, 0);
    LogChangePlanet(lpPl, ppl);

    /*
     * If product-list pointer differs, reconcile dst allocation with src:
     * - allocate if dst NULL and src non-NULL
     * - free if dst non-NULL and src NULL
     * - else ensure capacity and copy products
     */
    if (lpPl->lpplprod != ppl->lpplprod) {
        PLPROD *dst = lpPl->lpplprod;
        PLPROD *src = ppl->lpplprod;

        if (dst == NULL) {
            if (src != NULL) {
                /* Decompile: LpplAlloc(4, src->iprodMac, htOrd) */
                dst = (PLPROD *)LpplAlloc((int16_t)sizeof(PROD), (uint16_t)src->iprodMac, htOrd);
                lpPl->lpplprod = dst;
            }
        } else if (src == NULL) {
            FreePl((PL *)dst);
            lpPl->lpplprod = NULL;
            goto UTIL_FinishCopy;
        }

        if (dst != NULL && src != NULL) {
            if (dst->iprodMax < src->iprodMac) {
                dst = (PLPROD *)LpplReAlloc((PL *)dst, (int16_t)(src->iprodMac + 2));
                lpPl->lpplprod = dst;
            }

            memcpy((uint8_t *)dst + offsetof(PLPROD, rgprod), (const uint8_t *)src + offsetof(PLPROD, rgprod), (size_t)src->iprodMac * sizeof(PROD));

            dst->iprodMac = src->iprodMac;
        }
    }

UTIL_FinishCopy:
    /*
     * Decompile: __fmemcpy(lpPl, ppl, 0x34)
     * In the original, this is a “prefix copy” (like fleets copying up to a pointer).
     * Prefer copying up to the lpplprod pointer using offsetof, and assert it matches 0x34.
     */
    _Static_assert(offsetof(PLANET, lpplprod) == 0x34, "PLANET layout changed: expected lpplprod at +0x34");
    memcpy(lpPl, ppl, offsetof(PLANET, lpplprod));

    if (gd.fTutorial && idPlayer == 0) {
        AdvanceTutor();
    }

    return 1;
}

FLEET *LpflNewSplit(FLEET *pfl) {
    uint8_t iordMac;
    FLEET  *lpflNew;

    lpflNew = LpflNew(pfl->iPlayer, pfl->idPlanet);
    if (pfl->idPlanet == -1) {
        lpflNew->pt.x = pfl->pt.x;
        lpflNew->pt.y = pfl->pt.y;
    }
    lpflNew->fRepOrders = pfl->fRepOrders;
    lpflNew->det = pfl->det;
    lpflNew->iplan = pfl->iplan;
    iordMac = pfl->lpplord->iordMac;
    if (lpflNew->lpplord->iordMax < iordMac) {
        lpflNew->lpplord = (PLORD *)LpplReAlloc((PL *)lpflNew->lpplord, pfl->lpplord->iordMax);
    }
    memcpy(lpflNew->lpplord->rgord, pfl->lpplord->rgord, (uint16_t)iordMac * sizeof(ORDER));
    lpflNew->lpplord->iordMac = iordMac;
    lpflNew->cord = pfl->cord;
    LogSplitFleet(pfl->id);
    return lpflNew;
}

/* Pack fleet into a 16-bit word: ifl (bits 0-8), primary ship design index
   (bits 9-12), and a multi-design flag (bit 13) if the fleet has more than
   one ship design. */
uint16_t WFromLpfl(FLEET *lpfl) {
    int16_t  cshdef;
    uint16_t w;
    int16_t  ishdef;

    ishdef = IshdefPrimaryFromLpfl(lpfl, &cshdef);
    w = (ishdef << 9) | lpfl->ifl;
    if (cshdef > 1) {
        w = w | 0x2000;
    }
    return w;
}

int16_t FLookupObject(GrobjClass grobj, int16_t id, void *pobj) {
    switch (grobj) {
    case grobjFleet:
        return FLookupFleet(id, pobj);
    case grobjPlanet:
        return FLookupPlanet(id, pobj);
    default:
        return FLookupThing(id, pobj);
    }
}

int16_t GetFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal) {
    int16_t iplr;
    int16_t dPlanRange;
    int16_t i;
    int16_t dRange;
    int16_t iSteal;
    int16_t dPlanRangeBest;
    int16_t dRangeBest;
    int16_t pctDetect;

    iplr = lpfl->iPlayer;
    dRange = -1;
    dPlanRange = 0;
    iSteal = 0;
    if (ppctDetect != NULL) {
        *ppctDetect = 100;
    }
    for (i = 0; i < cShdefMax; i++) {
        if (lpfl->rgcsh[i] > 0) {
            dRangeBest = GetShdefScannerRange(&rglpshdef[iplr][i], iplr, &dPlanRangeBest, &pctDetect, &iSteal);
            if (ppctDetect != NULL && pctDetect < *ppctDetect) {
                *ppctDetect = pctDetect;
            }
            if (piSteal != NULL) {
                *piSteal |= iSteal;
            }
            if (dRangeBest > dRange) {
                dRange = dRangeBest;
            }
            if (dPlanRangeBest > dPlanRange) {
                dPlanRange = dPlanRangeBest;
            }
        }
    }
    if (pdPlanRange != NULL) {
        *pdPlanRange = dPlanRange;
    }
    return dRange;
}

int16_t FFindNearestObject(STARSPOINT pt, GrobjClass grobj, SCAN *pscan) {
    STARSPOINT  ptWp;
    STARSPOINT *ppt;
    int16_t     dx;
    int16_t     dy;
    int16_t     i;
    int32_t     lTry;
    int32_t     lSquare;
    int16_t     iNearest;
    THING      *lpth;
    THING      *lpthMac;
    FLEET      *lpfl;
    SCAN        scan;
    SCAN        scanT;
    STARSPOINT  pt_00;

    /* ------------------------------------------------------------
     * asm: 1038:4070..40b1
     * ------------------------------------------------------------ */
    lSquare = 1000000000L;

    ppt = (STARSPOINT *)rgptPlan;

    scan.grobjFull = grobjNone;
    scan.grobj = grobjNone;
    scan.pt.x = 0;
    scan.pt.y = 0;
    scan.ith = -1;
    scan.iwp = -1;
    scan.ifl = -1;
    scan.idpl = 0;

    /* ------------------------------------------------------------
     * Initial radius handling (mdScanRadius / mdExact)
     * asm: 1038:40b4..4107
     * ------------------------------------------------------------ */
    if (grobj & mdScanRadius) {
        int16_t s = ScanToPt(0x14);
        lSquare = (int32_t)s * s;
    } else if (grobj & mdExact) {
        lSquare = 0;
    }

    /* ------------------------------------------------------------
     * Planets
     * asm: 1038:4107..4207
     * ------------------------------------------------------------ */
    if (grobj & grobjPlanet) {
        for (i = 0; i < game.cPlanMax; i++) {
            dx = pt.x - ppt->x;
            dy = pt.y - ppt->y;

            lTry = (int32_t)dx * dx + (int32_t)dy * dy;

            if (lTry <= lSquare) {
                if (lTry != lSquare || lSquare == 0) {
                    scan.pt = *ppt;
                    scan.idpl = i;
                    scan.grobj = grobjPlanet;
                    scan.grobjFull = grobjPlanet;
                    lSquare = lTry;
                }
            }

            ppt++;
        }
    }

    /* ------------------------------------------------------------
     * Fleets
     * ------------------------------------------------------------ */
    if (grobj & grobjFleet) {
        for (i = 0; i < cFleet; i++) {
            lpfl = ((FLEET **)rglpfl)[i];
            if (lpfl == NULL)
                break;

            dx = pt.x - lpfl->pt.x;
            dy = pt.y - lpfl->pt.y;

            lTry = (int32_t)dx * dx;
            if (lTry <= lSquare) {
                lTry += (int32_t)dy * dy;
                if (lTry <= lSquare) {
                    if (((lTry == lSquare) && !(scan.grobj & grobjPlanet)) || (lpfl->pt.x == scan.pt.x && lpfl->pt.y == scan.pt.y)) {

                        if (!(scan.grobjFull & grobjFleet) || (((FLEET **)rglpfl)[scan.ifl]->iPlayer != idPlayer && lpfl->iPlayer == idPlayer)) {

                            scan.ifl = i;
                            scan.grobjFull |= grobjFleet;

                            if (scan.grobj == grobjNone)
                                goto UTIL_SelectShip;
                        }
                    } else if (lTry < lSquare) {
                    UTIL_SelectShip:
                        scan.pt = lpfl->pt;
                        scan.ifl = i;
                        scan.idpl = -1;
                        scan.grobj = grobjFleet;
                        scan.grobjFull = grobjFleet;
                        lSquare = lTry;
                    }
                }
            }
        }
    }

    /* ------------------------------------------------------------
     * Things
     * ------------------------------------------------------------ */
    if (grobj & grobjThing) {
        lpth = (THING *)lpThings;
        lpthMac = lpth + cThing;

        while (lpth < lpthMac) {
            dx = pt.x - lpth->pt.x;
            dy = pt.y - lpth->pt.y;

            lTry = (int32_t)dx * dx;
            if (lTry <= lSquare) {
                lTry += (int32_t)dy * dy;
                if (lTry <= lSquare) {
                    if (((lTry == lSquare) && !(scan.grobj & (grobjFleet | grobjPlanet))) || (lpth->pt.x == scan.pt.x && lpth->pt.y == scan.pt.y)) {

                        if (!(scan.grobjFull & grobjThing)) {
                            scan.ith = (int16_t)(lpth - (THING *)lpThings);
                            scan.grobjFull |= grobjThing;

                            if (scan.grobj == grobjNone)
                                goto UTIL_SelectThing;
                        }
                    } else if (lTry < lSquare) {
                    UTIL_SelectThing:
                        scan.pt = lpth->pt;
                        scan.ith = (int16_t)(lpth - (THING *)lpThings);
                        scan.ifl = -1;
                        scan.idpl = -1;
                        scan.grobj = grobjThing;
                        scan.grobjFull = grobjThing;
                        lSquare = lTry;
                    }
                }
            }

            lpth++;
        }
    }

    /* ------------------------------------------------------------
     * Waypoints ("Other")
     * ------------------------------------------------------------ */
    if ((grobj & grobjOther) && sel.grobj == grobjFleet) {
        i = sel.fl.cord;

    LAB_1038_46f2:
        i--;
        if (i >= 0) {
            ptWp = sel.fl.lpplord->rgord[i].pt;

            dx = pt.x - ptWp.x;
            dy = pt.y - ptWp.y;

            lTry = (int32_t)dx * dx;
            if (lTry <= lSquare) {
                lTry += (int32_t)dy * dy;
                if (lTry <= lSquare) {
                    if (((lTry == lSquare) && !(scan.grobj & (grobjThing | grobjFleet | grobjPlanet))) || (ptWp.x == scan.pt.x && ptWp.y == scan.pt.y)) {

                        if ((scan.grobjFull & grobjOther) && i != sel.scan.iwp)
                            goto LAB_1038_46f2;

                        scan.iwp = i;
                        scan.grobjFull |= grobjOther;

                        if (scan.grobj != grobjNone)
                            goto LAB_1038_46f2;
                    } else if (lSquare <= lTry) {
                        goto LAB_1038_46f2;
                    }

                    lSquare = lTry;
                    scan.pt = ptWp;
                    scan.iwp = i;
                    scan.ith = -1;
                    scan.ifl = -1;
                    scan.idpl = -1;
                    scan.grobj = grobjOther;
                    scan.grobjFull = grobjOther;
                }
            }
            goto LAB_1038_46f2;
        }
    }

    /* ------------------------------------------------------------
     * Recursive fill-in pass (mdNoRecurse)
     * ------------------------------------------------------------ */
    if (!(grobj & mdNoRecurse) && scan.grobj != grobjNone) {
        pt_00 = scan.pt;

        {
            GrobjClass grobjRecurse = (grobj & grobjMask) ^ (grobjThing | grobjOther | grobjFleet | grobjPlanet);

            grobjRecurse |= mdRecurseMask;

            if (FFindNearestObject(pt_00, grobjRecurse, &scanT)) {
                if (scanT.idpl != -1)
                    scan.idpl = scanT.idpl;
                if (scanT.ifl != -1)
                    scan.ifl = scanT.ifl;
                if (scanT.iwp != -1)
                    scan.iwp = scanT.iwp;
                if (scanT.ith != -1)
                    scan.ith = scanT.ith;

                scan.grobjFull |= scanT.grobjFull;
            }
        }
    }

    /* ------------------------------------------------------------
     * Copy out SCAN (8-word copy, asm-accurate)
     * ------------------------------------------------------------ */
    if (pscan) {
        SCAN *src = &scan;
        for (i = 8; i != 0; i--) {
            pscan->pt.x = src->pt.x;
            pscan = (SCAN *)&pscan->pt.y;
            src = (SCAN *)&src->pt.y;
        }
    }

    return scan.grobj != grobjNone;
}

#ifdef _WIN32

// TODO: this should be platform independent eventually, it's used by DumpFleets
int16_t CchGetETA(HDC hdc, FLEET *lpfl, char *sz, int16_t iwp, int16_t fSmall) {
    int16_t iWarp;
    double  dbl;
    ORDER  *lpord;
    int16_t i;
    int16_t c;
    int16_t iSpeed;
    int16_t j;
    int16_t cYears;
    int16_t ids;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x3d24 */

    /* TODO: implement */
    return 0;
}

void DrawABunchOfStars(HDC hdc, RECT *prc) {
    int32_t lPixTot;
    int16_t iMax;
    int16_t dy;
    int16_t i;
    int16_t iClr;
    int16_t dx;
    RECT    rcOut;
    RECT    rc;

    /* TODO: implement */
}

void DrawPlanetPrintDot(HDC hdc, int16_t x, int16_t y, int16_t iSize) {
    if (iSize == 0) {
        PatBlt(hdc, (int16_t)(x - 3), (int16_t)(y - 1), 7, 3, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 1), (int16_t)(y - 3), 3, 7, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 2), (int16_t)(y - 2), 5, 5, PATINVERT);
    } else {
        PatBlt(hdc, (int16_t)(x - 5), (int16_t)(y - 2), 11, 5, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 2), (int16_t)(y - 5), 5, 11, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 4), (int16_t)(y - 3), 9, 7, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 3), (int16_t)(y - 4), 7, 9, PATINVERT);
    }
}

#endif /* _WIN32 */
