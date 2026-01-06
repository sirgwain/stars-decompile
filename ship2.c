
#include "types.h"

#include "ship2.h"

/* functions */
int16_t FScout(FLEET *lpfl)
{
    int16_t i;
    int32_t l;

    /* TODO: implement */
    return 0;
}

int16_t RenameDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    RECT rc;
    int32_t lSel;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x0c0c */

    /* TODO: implement */
    return 0;
}

int16_t FStargateJump(FLEET *lpfl, int16_t isbsSrc, int16_t isbsDst, int16_t dDist)
{
    int16_t dpPerShdefNew;
    int16_t dpShdef;
    POINT pt;
    int16_t id;
    FLEET flSrc;
    int16_t cshT;
    uint8_t pctKill;
    int16_t i;
    int32_t cshOrig;
    int16_t idm;
    int32_t cshKill;
    int16_t pct;
    int16_t rgpct[16];
    int16_t cshdef;
    int16_t ishdef;
    int32_t dp;
    int16_t dpPerShdefOld;
    int16_t cshDamagedOld;
    FLEET flDead;

    /* debug symbols */
    /* label LKilledEmAll @ MEMORY_SHIP2:0x0f06 */

    /* TODO: implement */
    return 0;
}

int32_t PctTerraFromLpfl(FLEET *lpfl)
{
    int16_t j;
    int32_t pctTot;
    int16_t i;
    int32_t pct;
    HUL * lphuldef;
    int16_t chs;
    HS * lphs;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x2794 */

    /* TODO: implement */
    return 0;
}

void AutoFleetOrder(FLEET *lpfl, PLANET *lppl)
{
    int32_t cMine;
    int16_t ifl;
    ORDER * lpord;
    FLEET * lpflT;
    int16_t fFoundFleet;

    /* TODO: implement */
}

int32_t CMineSweepFromLphul(HUL *lphul)
{
    int16_t chs;
    HS * lphs;
    int32_t lRange;
    int16_t j;
    int16_t fStarbase;
    int32_t lPow;
    PART part;

    /* TODO: implement */
    return 0;
}

int16_t MdCalcStargateDamage(int16_t isbsSrc, int16_t isbsDst, int16_t dDist, int16_t wt, int16_t *ppctDmg)
{
    int32_t dBaseDistance;
    PART partDst;
    PART partSrc;
    int32_t pctSurviveT;
    int32_t pctSurvive;

    /* debug symbols */
    /* label TotalDeath @ MEMORY_SHIP2:0x1702 */

    /* TODO: implement */
    return 0;
}

int16_t PctCloakFromLpfl(FLEET *lpfl)
{
    int16_t j;
    double dcPts;
    double dwtFleet;
    int16_t i;
    int32_t cPtsCur;
    int16_t fUseFloat;
    HUL * lphul;
    int32_t wtFleet;
    int16_t cScore;
    int32_t cPts;
    int32_t wtFleetCur;
    int16_t chs;
    HS * lphs;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x2dbb */

    /* TODO: implement */
    return 0;
}

void NoAutoTrackFleet(FLEET *lpflTarget)
{
    int16_t iplr;
    int16_t idTarget;
    int16_t i;
    ORDER * lpord;
    int16_t ifl;
    FLEET * lpfl;

    /* TODO: implement */
}

int32_t CLayMinesFromLpfl(FLEET *lpfl, int16_t iType, int16_t ishdef)
{
    uint16_t iMin;
    uint16_t iMax;
    int32_t cMine;
    int16_t j;
    int16_t i;
    HUL * lphul;
    PART part;
    int32_t cMineTot;
    int16_t chs;
    HS * lphs;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x291e */

    /* TODO: implement */
    return 0;
}

int16_t FColonizer(FLEET *lpfl)
{
    int16_t i;
    int32_t l;

    /* TODO: implement */
    return 0;
}

void AutoRouteFleet(FLEET *lpfl, PLANET *lppl)
{
    int32_t dTravel;
    int16_t iWarp;
    int16_t pctDmg;
    int16_t wt;
    int32_t cTurns;
    int16_t i;
    ORDER * lpord;
    PLANET * lpplRoute;
    int16_t isbsDst;
    int16_t wtBig;
    int16_t ishdef;
    int16_t ishdefBig;
    int16_t isbsSrc;

    /* TODO: implement */
}

void KillUsedWaypoints(void)
{
    int16_t j;
    int16_t i;
    FLEET * lpfl;
    int16_t fRep;
    PLANET * lppl;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x1c89 */
    /* label NoOrdFixupYet @ MEMORY_SHIP2:0x1bfb */

    /* TODO: implement */
}

int16_t MergeFleetsDlg(uint16_t hwnd, uint16_t msg, uint16_t wParam, int32_t lParam)
{
    int16_t i;
    RECT rc;
    char szT[80];
    char *psz;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x33a0 */

    /* TODO: implement */
    return 0;
}

int32_t CMineFromLpfl(FLEET *lpfl)
{
    int32_t cMine;
    int16_t j;
    int16_t i;
    HUL * lphuldef;
    PART part;
    int32_t cMineTot;
    int16_t chs;
    HS * lphs;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x260a */

    /* TODO: implement */
    return 0;
}

int16_t ZipOrderDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    int16_t i;
    PAINTSTRUCT ps;
    RECT rc;
    uint16_t hwndRad;
    char *psz;
    int16_t (* lpProc)(void);
    char *pszT;
    RECT rcGBox;
    int16_t cch;
    int16_t xCtr;
    int16_t iAction;

    /* debug symbols */
    /* block (block) @ MEMORY_SHIP2:0x000f */
    /* block (block) @ MEMORY_SHIP2:0x0092 */
    /* block (block) @ MEMORY_SHIP2:0x0202 */
    /* block (block) @ MEMORY_SHIP2:0x031e */
    /* block (block) @ MEMORY_SHIP2:0x033f */
    /* block (block) @ MEMORY_SHIP2:0x055f */
    /* block (block) @ MEMORY_SHIP2:0x05f7 */

    /* TODO: implement */
    return 0;
}

void MarkTechsSeen(HUL *lphul, int16_t iplr)
{
    int16_t iplrSav;
    int16_t iTech;
    int16_t ihs;
    PART part;

    /* TODO: implement */
}

int16_t CPtsCloakFromLphs(HS *lphs)
{
    int16_t cPts;
    PART part;

    /* TODO: implement */
    return 0;
}

int16_t RenameZipDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    int16_t ids;
    RECT rc;

    /* TODO: implement */
    return 0;
}

int32_t CMineSweepFromLpfl(FLEET *lpfl)
{
    int32_t lPowTot;
    int16_t i;
    HUL * lphul;
    int32_t lPow;

    /* TODO: implement */
    return 0;
}

void EnableZipBtns(uint16_t hwnd, int16_t iSel)
{
    int16_t fEnabled;

    /* TODO: implement */
}
