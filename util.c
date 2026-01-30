
#include "types.h"
#include "util.h"
#include "utilgen.h"
#include "parts.h"
#include "globals.h"
#include "planet.h"
#include "strings.h"

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

char *SzVersion(void)
{
    /* These are the wsprintf arguments in the decompile. */
    int16_t major = 2;
    int16_t minor = 60;
    char letter = 'k';

    /* ids 0x22d is a format string stored in the compressed string table. */
    const char *fmt = PszGetCompressedString(idsVersionD02dC);

    /* wsprintf into shared work buffer and return it. */
    snprintf(szWork, sizeof(szWork), fmt, major, minor, letter);
    return szWork;
}

char *PszGetLocName(GrobjClass grobj, int16_t id, int16_t x, int16_t y)
{
    if (id != -1)
    {
        if (grobj == grobjPlanet)
            return PszGetPlanetName(id);
        if (grobj == grobjFleet)
            return PszGetFleetName(id);
        if (grobj == grobjThing)
            return PszGetThingName(id);
    }

    if (x == -1 && y == -1)
    {
        strcpy(szWork, PszGetCompressedString(idsDeepSpace)); /* 0x362 */
    }
    else
    {
        (void)sprintf(szWork, PszGetCompressedString(idsSpaceDD), x, y); /* 0x363 */
    }
    return szWork;
}

int16_t FCanFleetUseStargates(FLEET *lpfl, POINT ptSrc, POINT ptDst)
{
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
    SCAN scan;

    /* debug symbols */
    /* label LSrcChk @ MEMORY_UTIL:0x76a6 */
    /* label LJumpgate @ MEMORY_UTIL:0x7743 */

    /* TODO: implement */
    return 0;
}

FLEET *LpflFromId(int16_t idFleet)
{
    int16_t i;
    int16_t iplrCur;
    int16_t iHi;
    int16_t iLo;
    int16_t iMid;
    int16_t want;

    // In Stars!, a fleet id is packed. The decompile shows the owner lives in bits 9..12
    i = 0;
    for (iplrCur = 0; iplrCur < (int16_t)(((uint16_t)idFleet >> 9) & 0x0f); iplrCur++)
    {
        i = (int16_t)(i + (int16_t)rgplr[iplrCur].cFleet);
    }

    iHi = cFleet;
    iMid = (int16_t)(i - 1);
    want = (int16_t)((uint16_t)idFleet & 0x1fff);

    for (;;)
    {
        iLo = iMid;
        if (iHi <= (int16_t)(iLo + 1))
        {
            return (FLEET *)0;
        }

        iMid = (int16_t)((iLo + iHi) >> 1);

        if (rglpfl[iMid] == 0)
        {
            return (FLEET *)0;
        }

        if (rglpfl[iMid]->id < want)
        {
            /* go right */
            continue;
        }
        if (want < rglpfl[iMid]->id)
        {
            /* go left */
            iHi = iMid;
            iMid = iLo;
            continue;
        }

        return rglpfl[iMid];
    }
}

PLANET *LpplFromId(int16_t idPlanet)
{
    int16_t idGuess;
    int16_t iLo;
    PLANET *lppl;
    int16_t iGuess;
    int16_t iHi;

    if (idPlanet < 0 || idPlanet >= game.cPlanMax)
    {
        return NULL;
    }

    /* If we have a dense array of all planets loaded, direct index. */
    if (cPlanet == game.cPlanMax)
    {
        return (PLANET *)((uint8_t *)lpPlanets + (int32_t)idPlanet * (int32_t)sizeof(PLANET));
    }

    /* Otherwise the planet list is sorted by id and has only cPlanet entries. */
    iLo = -1;
    iHi = cPlanet;
    while (true)
    {
        if (iHi <= (int16_t)(iLo + 1))
        {
            return NULL;
        }
        iGuess = (int16_t)((iLo + iHi) >> 1);
        lppl = (PLANET *)((uint8_t *)lpPlanets + (int32_t)iGuess * (int32_t)sizeof(PLANET));
        idGuess = lppl->id;
        if (idGuess < idPlanet)
        {
            iLo = iGuess;
        }
        else if (idPlanet < idGuess)
        {
            iHi = iGuess;
        }
        else
        {
            return lppl;
        }
    }
}

THING *LpthFromId(int16_t idth)
{
    for (int i = 0; i < cThing; i++)
    {
        THING *t = &lpThings[i];
        if ((int16_t)t->idFull == idth)
        {
            return t;
        }
    }
    return NULL;
}

int32_t LCalcFuelGainFromRamScoops(FLEET *lpfl, int16_t iWarp, int32_t dTravel)
{
    int16_t i;
    int16_t *rgiFuel;
    SHDEF *lpshdef;
    int32_t pct10;
    int32_t pctShip10;

    (void)rgiFuel;
    pct10 = 0;

    if (iWarp >= 11)
    {
        return 0;
    }

    /*
     * Port of the original Win16 logic:
     *  - For each ship design present in the fleet, if its engine uses 0 fuel
     *    at the current warp (and possibly the next few warps), add a % gain
     *    proportional to engine count.
     *  - Multiply by ship count and then by distance.
     */
    for (i = 0; i < 16; i++)
    {
        int16_t csh = lpfl->rgcsh[i];
        if (csh <= 0)
        {
            continue;
        }

        lpshdef = (SHDEF *)((uint8_t *)rglpshdef[lpfl->iPlayer] + (int32_t)i * 0x93);

        /* Engine is always slot 0 in this data model. */
        {
            uint8_t engineId = (uint8_t)lpshdef->hul.rghs[0].iItem;
            uint8_t cEngines = (uint8_t)lpshdef->hul.rghs[0].cItem;
            ENGINE *lpeng = LpengineFromId(engineId);

            pctShip10 = 0;
            if (iWarp < 10)
            {
                if (lpeng->rgcFuelUsed[iWarp] == 0)
                {
                    pctShip10 += (int32_t)cEngines;
                    if (lpeng->rgcFuelUsed[iWarp + 1] == 0)
                    {
                        pctShip10 += (int32_t)cEngines * 2;
                        if (iWarp < 9 && lpeng->rgcFuelUsed[iWarp + 2] == 0)
                        {
                            pctShip10 += (int32_t)cEngines * 3;
                            if (iWarp < 8 && lpeng->rgcFuelUsed[iWarp + 3] == 0)
                            {
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

int16_t IshdefPrimaryFromLpfl(FLEET *lpfl, int16_t *pcDiff)
{
    int16_t cDiff;
    int16_t csh;
    int16_t ish;

    cDiff = 0;
    csh = 0;
    ish = 16;

    for (int16_t i = 0; i < 16; i++)
    {
        int16_t n = lpfl->rgcsh[i];

        if (n > 0)
        {
            cDiff++;

            if (n != csh && csh <= n)
            {
                HullDef ihuldef = rglpshdef[lpfl->iPlayer][i].hul.ihuldef;

                ish = i;
                csh = n;

                if (ihuldef == ihuldefFuelTransport || ihuldef == ihuldefSuperFuelXport)
                {
                    csh = (int16_t)(csh - 1);
                }
            }
        }
    }

    if (pcDiff != (int16_t *)0)
    {
        *pcDiff = cDiff;
    }
    return ish;
}

int16_t GetCachedFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal)
{
    int16_t dT;
    int16_t dPlanRange;
    int16_t i;
    int16_t iPlr;
    int16_t dRange;
    int16_t iSteal;
    int16_t pctDetect;

    /* TODO: implement */
    return 0;
}

int16_t FLookupSelShip(FLEET *pfl)
{

    /* TODO: implement */
    return 0;
}

int16_t FMatchTarget(FLEET *lpflTarget, int16_t mdTarget, int16_t fExact)
{
    int16_t imd;
    int16_t ish;

    /* TODO: implement */
    return 0;
}

void ClearFile(int16_t dt)
{
    char *pch;
    char szFile[256];

    /* TODO: implement */
}

int32_t LComputePower(SHDEF *lpshdef)
{
    int16_t dSpeed;
    int16_t dxRange;
    int16_t ihs;
    int32_t dpTorps;
    int16_t i;
    int32_t pctCap;
    int32_t dpBeams;
    int32_t dpBombs;
    int32_t dp;
    PART part;

    /* TODO: implement */
    return 0;
}

char *PszGetFleetName(int16_t id)
{
    FLEET *lpfl;
    uint16_t iPlayer;
    char szPlr[34];
    char szShdef[34];
    int16_t cshdef;
    int16_t ishdef;
    int16_t cch;

    lpfl = LpflFromId((int16_t)(id & 0x7fff));
    iPlayer = (uint16_t)((((uint16_t)id & 0x7fff) >> 9) & 15);

    if ((int16_t)iPlayer == idPlayer)
    {
        szPlr[0] = '\0';
    }
    else
    {
        char *pszPlr = PszPlayerName((int16_t)iPlayer, 0, 0, 0, 0, (PLAYER *)0);
        (void)sprintf(szPlr, "%s ", pszPlr);
    }

    if (lpfl == 0 || lpfl->lpszName == 0)
    {
        if (lpfl == 0)
        {
            strcpy(szShdef, PszGetCompressedString(idsFleet));
        }
        else
        {
            ishdef = IshdefPrimaryFromLpfl(lpfl, &cshdef);
            if (ishdef == 16)
            {
                strcpy(szShdef, PszGetCompressedString(idsFleet));
            }
            else
            {
                SHDEF *psh = &rglpshdef[iPlayer][ishdef];
                strcpy(szShdef, psh->hul.szClass);

                cch = (int16_t)strlen(szShdef);
                if (cch > 28)
                {
                    cch = 28;
                    szShdef[cch] = '\0';
                }
                if (cshdef > 1)
                {
                    szShdef[cch] = '+';
                    szShdef[cch + 1] = '\0';
                }
            }
        }

        (void)sprintf(szWork, "%s%s #%d", szPlr, szShdef, (int)(((uint16_t)id & 0x1ff) + 1)); /* 0x529 */
    }
    else
    {
        (void)sprintf(szWork, "%s%s", szPlr, lpfl->lpszName); /* 0x524 */
    }

    return szWork;
}

char *PszGetThingName(int16_t id)
{
    THING *lpth;
    char szPlr[54];

    lpth = LpthFromId(id);

    if (lpth == 0)
    {
        szWork[0] = '\0';
        return szWork;
    }

    if (lpth->ith == ithMinefield)
    {
        if ((int16_t)lpth->iplr == idPlayer)
        {
            szPlr[0] = '\0';
        }
        else
        {
            char *pszPlr = PszPlayerName((int16_t)lpth->iplr, 0, 0, 0, 0, (PLAYER *)0);
            (void)sprintf(szPlr, "%s ", pszPlr);
        }

        (void)sprintf(szWork, PszGetCompressedString(idsSSMineField), szPlr); /* 0x364 */
        return szWork;
    }

    if (lpth->ith == ithMineralPacket)
    {
        /* look at the first word of the payload (matches decompile at +6) */
        THPACK thp = lpth->thp;

        if (thp.iWarp == 0)
        {
            (void)CchGetString(idsSalvage, szWork);
        }
        else
        {
            if ((int16_t)lpth->iplr == idPlayer)
            {
                szPlr[0] = '\0';
            }
            else
            {
                char *pszPlr = PszPlayerName((int16_t)lpth->iplr, 0, 0, 0, 0, (PLAYER *)0);
                (void)sprintf(szPlr, "%s ", pszPlr);
            }

            (void)sprintf(szWork, PszGetCompressedString(idsSmineralPacket), szPlr);
        }
        return szWork;
    }

    if (lpth->ith == ithWormhole)
    {
        strcpy(szWork, PszGetCompressedString(idsWormhole));
        return szWork;
    }

    if (lpth->ith == ithMysteryTrader)
    {
        strcpy(szWork, PszGetCompressedString(idsMysteryTrader));
        return szWork;
    }

    strcpy(szWork, PszGetCompressedString(idsMysteryObject));
    return szWork;
}

int32_t LongFromSerialCh(char ch)
{
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
uint16_t WPackLong(int32_t l)
{
    /* Original uses logical (unsigned) right shifts and packs:
       top 3 bits = exponent, low 13 bits = mantissa (< 0x2000). */
    uint32_t u = (uint32_t)l;
    uint16_t exp = 0;

    while (((u & 0xE000u) != 0) || ((u >> 16) != 0))
    {
        u >>= 1;
        exp++;
    }

    return (uint16_t)((exp << 13) | u);
}

double DGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2)
{
    int32_t dy;
    int32_t dx;
    int32_t l;

    dx = (int32_t)x2 - (int32_t)x1;
    dy = (int32_t)y2 - (int32_t)y1;
    l = (int32_t)((int64_t)dx * (int64_t)dx + (int64_t)dy * (int64_t)dy);
    /* Use double sqrt like the original (which routed through the C runtime). */
    return sqrt((double)l);
}

int16_t FDeleteFleet(int16_t idFleet, int16_t grobjSel, int16_t idSel)
{
    int16_t i;
    FLEET *lpfl;
    int16_t iPlr;
    int16_t idDel;
    PLANET *lppl;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x2eb7 */

    /* TODO: implement */
    return 0;
}

int32_t WtFromLpfl(FLEET *lpfl)
{
    int32_t cMass;
    int16_t i;

    /* TODO: implement */
    return 0;
}

void SelectOursAtObject(POINT *ppt)
{
    int16_t id;
    POINT pt;
    int16_t ish;
    int16_t i;
    FLEET *lpfl;
    SCAN scan;

    /* TODO: implement */
}

char *PszGetPlanetName(int16_t id)
{
    char *pszPlan;

    pszPlan = PszGetCompressedPlanet(rgidPlan[id & 0x7fff]);

    if (((uint16_t)id & 0x8000) == 0)
    {
        strcpy(szWork, pszPlan);
    }
    else
    {
        char *pszFmt = PszGetCompressedString(idsOrbitingS); /* 0x365 */
        (void)sprintf(szWork, pszFmt, pszPlan);
    }

    return szWork;
}

int16_t FDupFleet(FLEET *lpfl, FLEET *pfl)
{
    PLORD *lpplordT;

    /* TODO: implement */
    return 0;
}

int16_t FDupPlanet(PLANET *lppl, PLANET *ppl)
{
    PLPROD *lpplprodT;

    /* TODO: implement */
    return 0;
}

char *PszFleetNameFromWord(uint16_t w)
{
    uint16_t ishdef;
    int16_t cch;
    char szShdef[34];
    char *lpsz;

    ishdef = (uint16_t)((w >> 9) & 15);

    if (!rglpshdef[idPlayer][ishdef].fFree)
    {
        strcpy(szShdef, rglpshdef[idPlayer][ishdef].hul.szClass);

        cch = (int16_t)strlen(szShdef);
        if (cch > 28)
        {
            cch = 28;
            szShdef[cch] = '\0';
        }

        if ((w & 0x2000) != 0)
        {
            szShdef[cch] = '+';
            szShdef[cch + 1] = '\0';
        }

        lpsz = szShdef;
    }
    else
    {
        lpsz = PszGetCompressedString(idsFleet); /* 0x4e8 */
    }

    (void)sprintf(szWork, "%s #%d", lpsz, (int)((w & 0x1ff) + 1));
    return szWork;
}

int16_t FValidSerialNo(char *psz, int32_t *plSerial)
{
    int32_t lBuild;
    int16_t i;
    int32_t lCur;
    int32_t lSerial;
    int32_t l;

    /* TODO: implement */
    return 0;
}

char *PszGetDistance(int16_t x1, int16_t y1, int16_t x2, int16_t y2)
{
    int32_t d;
    int16_t fStarted;
    int32_t d2;

    /* TODO: implement */
    return NULL;
}

void CalcPctSurvive(PLANET *lppl, float *ppct, float *ppctSmart)
{
    int16_t iPlrSav;
    int32_t cDefenses;
    float pct;
    PART part;
    int16_t cMax;

    /* Default smart-bomb survival to 1.0 if requested. */
    if (ppctSmart != NULL)
    {
        *ppctSmart = 1.0f;
    }

    /* If no owner or no defenses, everyone survives. */
    if (lppl->iPlayer == -1 || (lppl->cDefenses & 0x0FFFu) == 0)
    {
        pct = 1.0f;
        *ppct = pct;
        return;
    }

    /* Temporarily set global current player to planet owner (matches original). */
    iPlrSav = idPlayer;
    idPlayer = lppl->iPlayer;

    if (!FGetBestDefensePart(&part))
    {
        pct = 1.0f;
    }
    else
    {
        /* Clamp defenses by max operable. */
        cDefenses = (int32_t)(lppl->cDefenses & 0x0FFFu);

        cMax = CMaxOperableDefenses(lppl, lppl->iPlayer, false);
        if ((int32_t)cMax < cDefenses)
        {
            cDefenses = (int32_t)cMax;
        }

        /* dDmgCol is at +0x34 in the defense "terra" part (bomb). */
        {
            const int16_t dDmgCol = *(const int16_t *)((const uint8_t *)part.pterra + 0x34);

            /* Normal bombs: (1 - dDmgCol/1000) ^ cDefenses */
            const double base = 1.0 - ((double)dDmgCol / 1000.0);
            pct = (float)pow(base, (double)cDefenses);

            /* Smart bombs: (1 - dDmgCol/2000) ^ cDefenses */
            if (ppctSmart != NULL)
            {
                const double baseSmart = 1.0 - ((double)dDmgCol / 2000.0);
                *ppctSmart = (float)pow(baseSmart, (double)cDefenses);
            }
        }
    }

    /* Restore global current player. */
    idPlayer = iPlrSav;

    *ppct = pct;
}

int16_t IshFindSimilarDesign(HUL *lphul, int16_t iPlrDst)
{
    SHDEF *lpshdefDest;
    int16_t i;
    int16_t j;

    /* TODO: implement */
    return 0;
}

void DecorateHullName(int16_t iplr, int16_t ish, char *psz)
{
    int16_t i;
    int16_t c;
    SHDEF *lpshdef;
    int16_t iVal;

    /* TODO: implement */
}

int16_t FCanBuildShdef(SHDEF *lpshdef, int16_t iplr)
{
    int16_t j;
    int16_t iplrSav;
    PART part;

    /* debug symbols */
    /* label LFail @ MEMORY_UTIL:0x7bbb */

    /* TODO: implement */
    return 0;
}

int16_t FFleetMergeAll(FLEET *pfl)
{
    int16_t iplr;
    int32_t dpT;
    int16_t fCshOverflow;
    int16_t rgcshDamaged[16];
    int16_t cflMerge;
    int16_t i;
    FLEET *lpfl;
    int16_t cshT;
    SHDEF *lpshdef;
    FLEET *lpflMerge;
    int32_t rgdp[16];
    int16_t j;

    /* TODO: implement */
    return 0;
}

int16_t ICompFleetPoint2(void *arg1, void *arg2)
{
    const uint16_t *ptw = (const uint16_t *)arg1;  /* POINT: [x, y] */
    const FLEET *fl = *(const FLEET *const *)arg2; /* element is a FLEET* */

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

void TurnLog(StringId ids)
{
    char szTemp[256];

    /* TODO: implement */
}

char *PszPlayerName(int16_t iPlayer, int16_t fCapital, int16_t fPlural, int16_t fThe, int16_t grWord, PLAYER *pplr)
{
    uint16_t u;
    char szName[50];
    char *pchEnd;

    if (pplr == (PLAYER *)0)
    {
        pplr = &rgplr[iPlayer];
    }

    if (pplr->szName[0] == '\0')
    {
        // TODO: remove this dependency on szLastStrGet
        (void)PszGetCompressedString(idsPlayerD2);
        (void)sprintf(szName, "%s", szLastStrGet); /* faithful-ish: wsprintf used compressed result */
        if (fPlural == 0)
        {
            strcat(szName, "'s"); /* 0x515 */
        }
        if (grWord == 1)
        {
            u = (uint16_t)strlen(szName);
            (void)CchGetString(idsHas, szName + u); /* 0x55c */
        }
        else if (grWord == 2)
        {
            u = (uint16_t)strlen(szName);
            (void)CchGetString(idsIs2, szName + u); /* 0x55d */
        }
    }
    else
    {
        if (fThe == 0)
        {
            szName[0] = '\0';
        }
        else
        {
            strcpy(szName, "the "); /* 0x50e */
            if (fCapital != 0)
            {
                szName[0] = 'T';
            }
        }

        if ((fPlural == 0) || (pplr->szNames[0] == '\0'))
        {
            strcat(szName, pplr->szName);
        }
        else
        {
            strcat(szName, pplr->szNames);
        }

        u = (uint16_t)strlen(szName);
        if (u != 0)
        {
            pchEnd = szName + (u - 1);
            while ((pchEnd >= szName) && (*pchEnd == ' '))
            {
                *pchEnd-- = '\0';
            }
        }
        else
        {
            pchEnd = szName - 1;
        }

        if (pchEnd < szName)
        {
            (void)CchGetString(idsName, szName);
        }

        if ((fPlural != 0) && (pplr->szNames[0] == '\0'))
        {
            u = (uint16_t)strlen(szName);
            if (u >= 2)
            {
                if ((szName[u - 1] != 's') && !((szName[u - 1] == 'e') && (szName[u - 2] == 's')))
                {
                    strcat(szName, "s"); /* 0x513 */
                }
            }
            else if (u == 1)
            {
                if (szName[0] != 's')
                {
                    strcat(szName, "s"); /* 0x513 */
                }
            }
            else
            {
                strcat(szName, "s"); /* 0x513 */
            }
        }

        if (grWord == 1)
        {
            u = (uint16_t)strlen(szName);
            (void)CchGetString(idsHave2, szName + u);
        }
        else if (grWord == 2)
        {
            u = (uint16_t)strlen(szName);
            (void)CchGetString(idsAre, szName + u);
        }
    }

    strcpy(szWork, szName);
    return szWork;
}

int16_t IStargateFromLppl(PLANET *lppl)
{
    int16_t chs;
    HS *lphs;
    int16_t ihs;
    HUL *lphul;

    /* TODO: implement */
    return 0;
}

int32_t DpOfLpflIshdef(FLEET *lpfl, int16_t ishdef)
{
    int16_t dpShdef;
    int32_t dp;

    /* TODO: implement */
    return 0;
}

int16_t FFleetSplitAll(FLEET *pfl)
{
    FLEET flNew;
    int16_t cSplit;
    int16_t c;
    int16_t i;
    FLEET *lpflNew;

    /* TODO: implement */
    return 0;
}

int16_t ICompFleetPoint(void *arg1, void *arg2)
{
    int32_t l2;
    int32_t l1;

    /* TODO: implement */
    return 0;
}

void OutputSz(int16_t dt, char *sz)
{
    char szTemp[256];
    char szDate[100];
    char szTime[100];
    char szFile[256];
    FILE *fp;
    time_t t;
    struct tm *lt;

    if (sz == NULL)
    {
        return;
    }

    /* _DATA::mpdtsz observed entries: xy, x, hst, m, h, r, log, chk */
    if (dt < 0 || dt >= 8)
    {
        return; /* original likely assumes caller passes valid dt */
    }

    /* "%s.%s" -> szBase + "." + mpdtsz[dt] */
    (void)snprintf(szFile, sizeof(szFile), "%s.%s", szBase, mpdtsz[dt]);

    /* If file doesn't exist: write "Stars! %s\r\n\r\n" with version string. */
    fp = fopen(szFile, "rb");
    if (fp == NULL)
    {
        char *ver = SzVersion();
        (void)snprintf(szTemp, sizeof(szTemp), "Stars! %s\r\n\r\n", ver ? ver : "");
        OutputFileString(szFile, szTemp);
    }
    else
    {
        (void)fclose(fp);
    }

    /* __strdate -> mm/dd/yy, __strtime -> HH:MM:SS */
    t = time(NULL);
    lt = localtime(&t);
    if (lt != NULL)
    {
        strftime(szDate, sizeof(szDate), "%m/%d/%y", lt);
        strftime(szTime, sizeof(szTime), "%H:%M:%S", lt);
    }
    else
    {
        szDate[0] = '\0';
        szTime[0] = '\0';
    }

    /* "%s %s - %s\r\n" */
    (void)snprintf(szTemp, sizeof(szTemp), "%s %s - %s\r\n", szDate, szTime, sz);
    OutputFileString(szFile, szTemp);
}

void ComputeShdefPowers(void)
{
    int16_t iplr;
    int16_t ishdef;

    /* TODO: implement */
}

int16_t GetPlanetScannerRange(PLANET *lppl, int16_t *pDeep)
{
    int16_t iPlrSav;
    int16_t dRange;
    PART part;

    /* debug symbols */
    /* label LFinishUp @ MEMORY_UTIL:0x4def */

    /* TODO: implement */
    return 0;
}

FLEET *LpflNew(int16_t iPlr, int16_t idPl)
{
    int16_t i;
    ORDER *lpord;
    FLEET *lpfl;
    int16_t iflPrev;

    /* TODO: implement */
    return NULL;
}

void UpdateShdefCost(SHDEF *lpshdef)
{
    int16_t dpT;
    uint32_t wt;
    int16_t k;
    int16_t c;
    uint16_t rgCosts[4];
    int16_t fWeakArmor;
    HUL *lphul;
    uint32_t resCost;
    uint32_t rgMin[3];
    PART part;

    /* TODO: implement */
}

int16_t FLookupSelPlanet(PLANET *ppl)
{
    if (sel.scan.grobj == grobjPlanet)
    {
        return FLookupPlanet(sel.scan.idpl, ppl);
    }
    return 0;
}

int16_t FLookupThing(int16_t idth, THING *pth)
{
    THING *lpth;
    int16_t fWrite;

    /* TODO: implement */
    return 0;
}

int16_t FLookupFleet(int16_t idFleet, FLEET *pfl)
{
    FLEET *lpfl;
    int16_t fWrite;

    /* TODO: implement */
    return 0;
}

int16_t FLookupOrbitingXfer(int16_t idPlanet, int16_t iNth, XFER *pxf, int16_t idSkip)
{
    int16_t i;
    THING *lpth;
    FLEET *lpfl;
    THING *lpthMac;

    /* TODO: implement */
    return 0;
}

void LinkFleets(int16_t fUnused)
{
    FLEET **pSearch;
    POINT pt;
    FLEET *rglpflSrc[1];
    FLEET *lpflTail;
    FLEET *lpflHead;
    int16_t i;
    int16_t iflTail;
    int16_t iflHead;
    int16_t cSrc;

    /* TODO: implement */
}

int16_t FCalcFleetBombDamage(FLEET *lpfl, int32_t *pdmgPeople, int32_t *pdmgPeopleMin, int32_t *pdmgPeopleSmart, int32_t *pdmgBldg, int32_t *ppctTerra, int16_t *pfMulti)
{
    int16_t iplr;
    int16_t cfl;
    FLEET *lpflNext;
    int16_t dmgFloor;
    FLEET *lpflHead;
    double dmgSmart;
    int16_t fBomber;
    int16_t j;
    int16_t ishdef;
    PART part;
    int32_t cIter;
    double dmgT;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x1615 */

    /* TODO: implement */
    return 0;
}

int16_t IflFromLpfl(FLEET *lpfl)
{
    int16_t i;

    for (i = 0; i < cFleet; i++)
    {
        if (rglpfl[i] == lpfl)
        {
            return i;
        }
    }
    return -1;
}

int32_t DpShieldOfShdef(SHDEF *lpshdef, int16_t iplr)
{
    int16_t chs;
    HS *lphs;
    int16_t ihs;
    int32_t dpShdef;
    HUL *lphul;
    PART part;

    /* TODO: implement */
    return 0;
}

void GetTrueHullCost(int16_t iPlayer, HUL *lphul, uint16_t *rgCost)
{
    int16_t i;

    for (i = 0; i < 3; i++)
    {
        rgCost[i] = lphul->rgwtOreCost[i];
    }
    rgCost[3] = lphul->resCost;
}

int16_t GetShdefScannerRange(SHDEF *lpshdef, int16_t iplr, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal)
{
    int16_t chs;
    HS *lphs;
    int16_t dRangeT2;
    double lBIR4;
    int16_t dRangeT;
    int16_t fHasScanner;
    int16_t iScanner;
    int16_t fBuiltIn;
    int16_t cDetectors;
    double lPlanRange4;
    int16_t dRange;
    double lT;
    int16_t iSteal;
    int16_t j;
    double lBIPR4;
    double lRange4;

    /* debug symbols */
    /* label LPlanScan @ MEMORY_UTIL:0x53ed */
    /* label LOddBallScanners @ MEMORY_UTIL:0x5482 */

    /* TODO: implement */
    return 0;
}

void ValidateWaypoints(void)
{
    int16_t mdTarget;
    FLEET *lpflTarget;
    int16_t ifl2;
    int32_t wt;
    FLEET *lpflMatch;
    int32_t wtMatch;
    ORDER *lpord;
    int16_t ifl;
    THING *lpth;
    FLEET *lpfl;
    int16_t cFound;
    int16_t iord;
    FLEET *lpfl2;
    int16_t iplrHi;

    /* TODO: implement */
}

int32_t ChgPopFromPlanet(PLANET *lppl, int16_t fUpdate)
{
    int32_t lMaxPop;
    int16_t fPopDied;
    int32_t lPopIncDelta;
    int16_t DeltaCur;
    int32_t pctGrow100;
    int16_t pctDesire;
    int32_t lPopInc100;
    int32_t lPopInc;
    int32_t lPopOld;
    int32_t pctRetard;
    int32_t pctFull;

    /* debug symbols */
    /* block (block) @ MEMORY_UTIL:0x72b1 */
    /* label LUpdateAndExit @ MEMORY_UTIL:0x756b */

    /* TODO: implement */
    return 0;
}

int16_t FFleetCanJumpgate(FLEET *lpfl)
{
    HS *lphs;
    int16_t chs;
    int16_t i;
    int16_t j;

    /* TODO: implement */
    return 0;
}

int32_t CalcPlayerScore(int16_t iPlr, SCORE *pscore)
{
    int32_t rgcsh[3];
    int32_t lTemp;
    SCORE score;
    PLANET *lpplMac;
    PLANET *lppl;
    int16_t i;
    int16_t ifl;
    FLEET *lpfl;
    int16_t iTech;
    int32_t lPower;
    int16_t rgType[16];

    /* TODO: implement */
    return 0;
}

short FLookupPlanet(int16_t iPlanet, PLANET *ppl)
{
    bool fWrite = false;

    if (cPlanet < 1)
        return 0;

    /* negative iPlanet means: use ppl->id, and (usually) write ppl back to master list */
    if (iPlanet < 0)
    {
        iPlanet = ppl ? ppl->id : (int16_t)-1;
        if (iPlanet == -1)
        {
            LogChangePlanet(NULL, ppl);
            return 1;
        }
        fWrite = true;
    }

    PLANET *lpPl = LpplFromId(iPlanet);
    if (lpPl == NULL || ppl == NULL)
        return 0;

    if (!fWrite)
    {
        /* read/lookup: copy master planet -> *ppl */
        if (ppl == (PLANET *)&sel.pl)
        {
            FDupPlanet(lpPl, (PLANET *)&sel.pl);
        }
        else
        {
            memcpy(ppl, lpPl, sizeof(*ppl));
        }
        return 1;
    }

    /* write/update: copy *ppl -> master planet (with special handling for lpplprod) */
    InvalidateReport(0, 0);
    LogChangePlanet(lpPl, ppl);

    if (lpPl->lpplprod != ppl->lpplprod)
    {
        PLPROD *dstProd = (PLPROD *)lpPl->lpplprod;
        PLPROD *srcProd = (PLPROD *)ppl->lpplprod;

        if (dstProd == NULL)
        {
            if (srcProd != NULL)
            {
                PL *p = LpplAlloc(4, (uint16_t)srcProd->iprodMac, htOrd);
                lpPl->lpplprod = (PLPROD *)p;
                dstProd = (PLPROD *)p;
            }
        }
        else if (srcProd == NULL)
        {
            FreePl((PL *)dstProd);
            lpPl->lpplprod = NULL;
            goto UTIL_FinishCopy;
        }

        if (srcProd != NULL && dstProd != NULL)
        {
            if (dstProd->iprodMax < srcProd->iprodMac)
            {
                PL *p = LpplReAlloc((PL *)dstProd, (uint16_t)(srcProd->iprodMac + 2));
                lpPl->lpplprod = (PLPROD *)p;
                dstProd = (PLPROD *)p;
            }

            memcpy((uint8_t *)dstProd + 4,
                   (const uint8_t *)srcProd + 4,
                   (uint32_t)srcProd->iprodMac * 4u);

            dstProd->iprodMac = srcProd->iprodMac;
        }
    }

UTIL_FinishCopy:
    /* copy everything up through turn; do NOT overwrite lpplprod pointer itself */
    memcpy(lpPl, ppl, 0x34);

    if ((((uint32_t)gd.grBits >> 11) & 1u) && (idPlayer == 0))
        AdvanceTutor();

    return 1;
}

FLEET *LpflNewSplit(FLEET *pfl)
{
    int16_t iordMac;
    FLEET *lpflNew;

    /* TODO: implement */
    return NULL;
}

uint16_t WFromLpfl(FLEET *lpfl)
{
    int16_t cshdef;
    uint16_t w;
    int16_t ishdef;

    /* TODO: implement */
    return 0;
}

int16_t FLookupObject(GrobjClass grobj, int16_t id, void *pobj)
{

    /* TODO: implement */
    return 0;
}

int16_t GetFleetScannerRange(FLEET *lpfl, int16_t *pdPlanRange, int16_t *ppctDetect, int16_t *piSteal)
{
    int16_t iplr;
    int16_t dPlanRange;
    int16_t i;
    int16_t dRange;
    int16_t iSteal;
    int16_t dPlanRangeBest;
    int16_t dRangeBest;
    int16_t pctDetect;

    /* TODO: implement */
    return 0;
}

int16_t FFindNearestObject(POINT pt, GrobjClass grobj, SCAN *pscan)
{
    POINT ptWp;
    POINT *ppt;
    int16_t dy;
    int32_t lTry;
    THING *lpth;
    FLEET *lpfl;
    int16_t i;
    THING *lpthMac;
    int32_t lSquare;
    SCAN scanT;
    int16_t iNearest;
    int16_t dx;
    SCAN scan;

    /* debug symbols */
    /* label SelectThing @ MEMORY_UTIL:0x4523 */
    /* label SelectSpace @ MEMORY_UTIL:0x46c3 */
    /* label SelectShip @ MEMORY_UTIL:0x439d */

    /* TODO: implement */
    return 0;
}

#ifdef _WIN32

// TODO: this should be platform independent eventually, it's used by DumpFleets
int16_t CchGetETA(HDC hdc, FLEET *lpfl, char *sz, int16_t iwp, int16_t fSmall)
{
    int16_t iWarp;
    double dbl;
    ORDER *lpord;
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

void DrawABunchOfStars(HDC hdc, RECT *prc)
{
    int32_t lPixTot;
    int16_t iMax;
    int16_t dy;
    int16_t i;
    int16_t iClr;
    int16_t dx;
    RECT rcOut;
    RECT rc;

    /* TODO: implement */
}

void DrawPlanetPrintDot(HDC hdc, int16_t x, int16_t y, int16_t iSize)
{
    if (iSize == 0)
    {
        PatBlt(hdc, (int16_t)(x - 3), (int16_t)(y - 1), 7, 3, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 1), (int16_t)(y - 3), 3, 7, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 2), (int16_t)(y - 2), 5, 5, PATINVERT);
    }
    else
    {
        PatBlt(hdc, (int16_t)(x - 5), (int16_t)(y - 2), 11, 5, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 2), (int16_t)(y - 5), 5, 11, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 4), (int16_t)(y - 3), 9, 7, PATINVERT);
        PatBlt(hdc, (int16_t)(x - 3), (int16_t)(y - 4), 7, 9, PATINVERT);
    }
}

#endif /* _WIN32 */
