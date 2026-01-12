
#include "types.h"
#include "globals.h"

#include "vcr.h"
#include "memory.h"
#include "battle.h"
#include "parts.h"

int32_t LdpFromItokDv(int16_t itok, DV *lpdv)
{
    TOK *ptok = &vrgtok[itok];
    SHDEF *pshdef = LpshdefFromTok(ptok);

    /* SHDEF +0x38: base hull DP (uint16_t) */
    uint16_t dpShdef = pshdef->hul.dp;

    /* Base DP = dpShdef * ptok->csh */
    int32_t dp = (int32_t)dpShdef * (int32_t)ptok->csh;

    if (lpdv->dp != 0)
    {
        /*
         * dv layout:
         *   pctSh : 7 (bits 0..6)
         *   pctDp : 9 (bits 7..15)
         *
         * Win16 decompile does:
         *   csh = (ptok->csh * (dv.dp & 0x007F)) / 100; clamp to >= 1
         *   dp -= ((dpShdef * (dv.dp >> 7)) / 10) * csh / 50
         *
         * All integer math with truncation.
         */
        int32_t csh = ((int32_t)ptok->csh * (int32_t)lpdv->pctSh) / 100;
        if (csh < 1)
            csh = 1;

        int32_t term = ((int32_t)dpShdef * (int32_t)lpdv->pctDp) / 10;
        term = (term * csh) / 50;

        dp -= term;
    }

    return dp;
}

BTLDATA *BtlDataGet(int16_t i)
{
    HB *lphb = rglphb[htBattle];
    if (lphb == NULL)
        return NULL;

    BTLDATA *lpbd = (BTLDATA *)((uint8_t *)lphb + sizeof(HB) + sizeof(uint16_t));

    for (;;)
    {
        while ((int16_t)lpbd->id != -1)
        {
            if (lpbd->cbData == 0)
                return NULL;

            if (i < 1)
                return lpbd;

            i--;
            lpbd = (BTLDATA *)((uint8_t *)lpbd + lpbd->cbData);
        }

        lphb = lphb->lphbNext;
        if (lphb == NULL)
            return NULL;

        /* Decompile: if (*(uint16_t *)(hb + 6) < 0x11) break; */
        /* maybe this is better if (lphb->ibTop < (uint16_t)(sizeof(HB) + sizeof(uint16_t)))*/
        if (lphb->ibTop < 0x11)
            return NULL;

        lpbd = (BTLDATA *)((uint8_t *)lphb + sizeof(HB) + sizeof(uint16_t));
    }
}

/*
 * CBattleKills
 *
 * Sum the number of units destroyed in a battle.
 *
 * This function walks the variable-length BTLREC/KILL stream stored inside
 * a BTLDATA block and accumulates kill counts. Depending on fOurDead, it
 * either counts units owned by the current player (idPlayer) or units
 * owned by other players.
 *
 * Parameters:
 *   lpbd     - Battle data block containing TOK, BTLREC, and KILL records.
 *   fOurDead - Nonzero to count our units destroyed; zero to count enemy
 *              units destroyed.
 *
 * Returns:
 *   Total number of units destroyed, using 32-bit integer arithmetic to
 *   match the original Win16 long behavior.
 */
int32_t CBattleKills(BTLDATA *lpbd, int16_t fOurDead)
{
    TOK *rgtok = (TOK *)((uint8_t *)lpbd + 0x0e);
    BTLREC *lpbr = (BTLREC *)((uint8_t *)rgtok +
                              (uint32_t)lpbd->ctok * (uint32_t)sizeof(TOK));
    uint8_t *pbEnd = (uint8_t *)lpbd + (uint32_t)lpbd->cbData;

    uint32_t cKilled = 0;

    while ((uint8_t *)lpbr < pbEnd)
    {
        int16_t cKill = lpbr->ctok;

        for (int16_t i = 0; i < cKill; i++)
        {
            KILL *pk = &lpbr->rgkill[i];

            if (pk->cshKill == 0)
                continue;

            uint8_t victimPlr = rgtok[pk->itok].iplr;

            if (victimPlr == (uint8_t)idPlayer)
            {
                if (fOurDead != 0)
                    cKilled += (uint32_t)pk->cshKill;
            }
            else
            {
                if (fOurDead == 0)
                    cKilled += (uint32_t)pk->cshKill;
            }
        }

        lpbr = (BTLREC *)((uint8_t *)lpbr +
                          6u +
                          (uint32_t)cKill * (uint32_t)sizeof(KILL));
    }

    return (int32_t)cKilled;
}

/*
 * CBattleUnits
 *
 * Count the number of battle units matching a filter mask.
 *
 * Iterates over the TOK table in a BTLDATA block and sums the unit counts
 * (TOK::csh) for tokens that match the specified BattleUnitFlags mask.
 * The mask controls which side (ours/theirs), whether starbases are
 * included, and which ship hull categories are counted.
 *
 * Parameters:
 *   lpbd     - Battle data block containing the TOK table.
 *   grbitBu  - Combination of BattleUnitFlags (grBu* values) selecting
 *              sides, object types, and hull classes.
 *
 * Returns:
 *   Total number of matching units as a 32-bit integer.
 *
 * Notes:
 *   - TOK entries with ishdef >= 16 are treated as starbases.
 *   - Hull category is derived from HULDEF::imdCategory.
 *   - All arithmetic and filtering behavior matches the original Win16
 *     implementation.
 */
int32_t CBattleUnits(BTLDATA *lpbd, uint16_t grbitBu)
{
    uint32_t lUnits = 0;

    TOK *rgtok = (TOK *)((uint8_t *)lpbd + 0x0e);
    uint8_t ctok = lpbd->ctok;

    for (int16_t i = 0; i < (int16_t)ctok; i++)
    {
        TOK *tok = &rgtok[i];

        /* Side filter */
        uint16_t sideOk =
            (tok->iplr == (uint8_t)idPlayer)
                ? (grbitBu & grBuOurUnits)
                : (grbitBu & grBuTheirUnits);

        if (sideOk == 0)
            continue;

        /* Starbase filter: ishdef >= 16 */
        bool isStarbase = (tok->ishdef >= 16);
        if (isStarbase && ((grbitBu & grBuIncludeSb) == 0))
            continue;

        /* Hull-category filtering (ships only) */
        if (!isStarbase && ((grbitBu & grBuClassAll) != grBuClassAll))
        {
            SHDEF *pshdef =
                (SHDEF *)((uint8_t *)rglpshdef[tok->iplr] +
                          (uint32_t)tok->ishdef * 0x93);

            HULDEF *phuldef = LphuldefFromId(pshdef->hul.ihuldef);

            uint16_t hulClass = (uint16_t)phuldef->imdCategory;

            uint16_t classOk;
            if (hulClass < 2 || hulClass > 5)
                classOk = grbitBu & grBuClassOther;
            else if (hulClass == 2)
                classOk = grbitBu & grBuClassFight;
            else if (hulClass == 3)
                classOk = grbitBu & grBuClassBomber;
            else if (hulClass == 5)
                classOk = grbitBu & grBuClassCap;
            else /* hulClass == 4 */
                classOk = grbitBu & grBuClassFrig;

            if (classOk == 0)
                continue;
        }

        lUnits += (uint32_t)tok->csh;
    }

    return (int32_t)lUnits;
}

int16_t CBattles(void)
{
    int16_t cBattles = 0;
    HB *lphb = rglphb[htBattle];
    BTLDATA *lpbd;

    if (lphb == NULL)
    {
        return 0;
    }

    /* Battle data begins immediately after HB + WORD (0x10 + 0x02 = 0x12). */
    lpbd = (BTLDATA *)((uint8_t *)lphb + sizeof(HB) + sizeof(uint16_t));

    for (;;)
    {
        /* Walk battle records within this heap block until sentinel id == -1. */
        while (lpbd->id != (int16_t)-1)
        {
            /* cb==0 means end of valid data (early out). In the decompile this is *(+6)==0. */
            if (lpbd->cbData == 0)
            {
                return cBattles;
            }

            cBattles++;
            lpbd = (BTLDATA *)((uint8_t *)lpbd + lpbd->cbData);
        }

        /* Move to next heap block (HB->lphbNext is a far pointer in the original). */
        lphb = lphb->lphbNext;

        /* Decompile: if null OR *(uint16_t *)(hb+6) < 17, stop.  */
        if (lphb == NULL || lphb->cbBlock < 17u)
        {
            break;
        }

        lpbd = (BTLDATA *)((uint8_t *)lphb + sizeof(HB) + sizeof(uint16_t));
    }

    return cBattles;
}

#ifdef _WIN32

INT_PTR CALLBACK VCRDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc;
    int16_t i;
    int16_t ibtn;
    RECT rc;
    int16_t dyFrame;
    uint8_t brc;
    int16_t iStep;
    POINT pt;
    int16_t dStep;
    int16_t bkMode;
    int16_t iSel;
    RECT rcWindow;
    int16_t bt;
    int16_t dx;
    RECT *prc;
    int16_t iDir;
    int16_t iCur;
    uint32_t crBkSav;
    PAINTSTRUCT ps;
    BTNT btnt;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x0e9f */
    /* block (block) @ MEMORY_VCR:0x1076 */
    /* block (block) @ MEMORY_VCR:0x10e4 */
    /* block (block) @ MEMORY_VCR:0x1138 */
    /* block (block) @ MEMORY_VCR:0x14f7 */
    /* block (block) @ MEMORY_VCR:0x1618 */
    /* block (block) @ MEMORY_VCR:0x1693 */
    /* label GoodSel @ MEMORY_VCR:0x1601 */
    /* label KillTime @ MEMORY_VCR:0x16af */
    /* label NextBtn @ MEMORY_VCR:0x1788 */

    /* TODO: implement */
    return 0;
}

void EnableVCRButtons(void)
{
    int16_t i;

    /* TODO: implement */
}

int16_t PopupVCRMenu(HWND hwnd, int16_t x, int16_t y, uint8_t brc)
{
    int16_t fAttack;
    char *rgsz[1];
    int16_t i;
    int16_t c;
    char rgch[1536];
    SHDEF *lpshdef;
    int16_t rgid[40];
    int16_t iChecked;
    int16_t iSel;
    int16_t j;
    char *psz;
    int16_t cch;
    int16_t cKilled;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x477e */

    /* TODO: implement */
    return 0;
}

void DrawVCR(HDC hdc, int16_t iStart, int16_t iEnd)
{
    int16_t ctok;
    int16_t ibmpRace;
    int16_t bkMode;
    HBRUSH hbrSav;
    int32_t dpShields;
    int16_t itokT;
    int32_t dpT;
    int16_t fCreatedDC;
    int32_t dpArmor;
    int16_t y;
    uint8_t rgfSeen[256];
    int16_t c;
    int16_t i;
    uint8_t brcT;
    SHDEF *lpshdef;
    int16_t ibmp;
    int16_t csh;
    char *psz;
    int16_t dx;
    int16_t j;
    char szT[96];
    int16_t fJam;
    RECT rc;
    int16_t x;
    int16_t cshT;
    DV dv;
    int32_t dpShT;
    int16_t xT;
    int16_t cshNew;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x258e */
    /* block (block) @ MEMORY_VCR:0x2a1b */
    /* block (block) @ MEMORY_VCR:0x38e7 */

    /* TODO: implement */
}

void GetVCRStats(int16_t itok, int32_t *pdpArmor, DV *pdv, int32_t *pdpShields, int16_t *pcsh)
{
    int16_t cshT;
    DV dv;
    int32_t dpShields;
    int32_t dpArmor;
    int16_t i;
    int16_t cshKill;
    uint16_t dpShdef;

    /* TODO: implement */
}

void BattleVCR(int16_t iBattle)
{
    int16_t (*lpProc)(void);
    int16_t (*penvMemSav)[9];
    int16_t env[9];
    HB *lphb;

    /* debug symbols */
    /* label LCleanup @ MEMORY_VCR:0x0201 */

    /* TODO: implement */
}

int16_t SetVCRBoard(int16_t iStep)
{
    TOK *ptok;
    int16_t i;
    int16_t itok;

    /* TODO: implement */
    return 0;
}

void AnimateAttack(HDC hdc)
{
    TOK *ptokSrc;
    TOK *ptokAttack;
    POINT ptBeam1;
    int16_t cFrame;
    int16_t dyFrame;
    POINT ptRay2;
    POINT ptTop;
    uint32_t dwTickLast;
    int16_t dxFrame;
    uint32_t dwTickCur;
    POINT ptBase;
    int16_t dy;
    POINT ptRay1;
    int16_t y;
    POINT ptRight;
    POINT ptDest;
    int16_t iHit;
    uint16_t grfWeapon;
    POINT ptSrc;
    POINT ptTorp;
    POINT ptLeft;
    // TIMERINFO ti;
    int16_t iFrame;
    int16_t dx;
    int16_t fKill;
    POINT ptDestBottom;
    POINT ptBeam2;
    POINT ptBottom;
    POINT ptDestTop;
    POINT ptDestRight;
    POINT ptDestLeft;
    int16_t x;
    HDC hdcMem;
    uint16_t hbmpSav;
    uint16_t hbmpScreen;

    /* debug symbols */
    /* block (block) @ MEMORY_VCR:0x414d */
    /* label LNextTarget @ MEMORY_VCR:0x3c09 */
    /* label LFinishUp @ MEMORY_VCR:0x43dc */

    /* TODO: implement */
}

void Delay(int16_t ctick)
{
    uint32_t dwTickLast;
    uint32_t dwTickCur;
    // TIMERINFO ti;

    /* TODO: implement */
}

#endif /* _WIN32 */