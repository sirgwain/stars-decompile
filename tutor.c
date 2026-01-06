
#include "types.h"

#include "tutor.h"

/* globals */
ITEMACTION rgiaQuikDrop[5];  /* MEMORY_TUTOR:0x0f94 */
ITEMACTION rgiaQuikLoad[5];  /* MEMORY_TUTOR:0x0f9e */
ITEMACTION rgiaUnloadAllCol[5];  /* MEMORY_TUTOR:0x0fa8 */
ITEMACTION rgiaLoadAllCol[5];  /* MEMORY_TUTOR:0x0fb2 */
ZIPPRODQ1 rgzpqTut[2];  /* MEMORY_TUTOR:0x663a */

/* functions */
void EndTutor(int16_t fClose)
{

    /* TODO: implement */
}

void DrawTutorText(uint16_t hwnd)
{
    uint16_t hdc;
    int16_t yTop;
    int16_t fPara;
    PAINTSTRUCT ps;
    int16_t didt;
    int16_t xLeft;
    int16_t cch;
    char rgch[256];
    RECT rcBtn;
    RECT rc;

    /* TODO: implement */
}

int16_t FCheckCargo(FLEET *lpfl, int16_t wtMin1, int16_t wtMin2, int16_t wtMin3, int16_t wtColonists)
{
    int16_t fRet;
    int16_t idh;
    int16_t idhSav;

    /* debug symbols */
    /* label LReturn @ MEMORY_TUTOR:0x778e */

    /* TODO: implement */
    return 0;
}

int16_t FCheckPlanetRoute(int16_t idpl, int16_t idplRoute)
{
    PLANET * lppl;
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckScanner(int16_t md, int16_t iZoom)
{
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckResearch(int16_t iTech, int16_t iTechNext, int16_t pct)
{

    /* TODO: implement */
    return 0;
}

int16_t FTutorTaskDone(void)
{
    HS hs1;
    HS hs2;
    HS hs;

    /* debug symbols */
    /* block (block) @ MEMORY_TUTOR:0x3625 */
    /* block (block) @ MEMORY_TUTOR:0x47c9 */
    /* block (block) @ MEMORY_TUTOR:0x50bc */

    /* TODO: implement */
    return 0;
}

int16_t TutorDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hmenu;
    RECT rc;
    int16_t (* lpProc)(void);
    int16_t fRet;

    /* debug symbols */
    /* block (block) @ MEMORY_TUTOR:0x00ad */

    /* TODO: implement */
    return 0;
}

int16_t FCheckFleetName(int16_t id, int16_t ids)
{
    FLEET * lpfl;
    char szT[33];
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckZip(int16_t iZip, ITEMACTION *lpiaGoal, int16_t ids)
{
    ITEMACTION * piaCur;
    int16_t i;
    char szT[33];
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

void SaveGameState(void)
{
    uint16_t hmenu;

    /* TODO: implement */
}

int16_t FCheckXferWP(uint16_t ifl, int16_t iord, int16_t id, uint16_t iWarp, ITEMACTION *lpiaGoal)
{
    ORDER ord;
    int16_t fRet;
    ITEMACTION * piaCur;
    int16_t i;
    FLEET * lpfl;
    int16_t idh;
    int16_t grobj;
    int16_t idhSav;

    /* debug symbols */
    /* label LReturn @ MEMORY_TUTOR:0x73fa */

    /* TODO: implement */
    return 0;
}

int16_t FCheckFleetWP(uint16_t ifl, int16_t iord, uint16_t grobj, int16_t id, uint16_t grTask, uint16_t iWarp)
{
    ORDER ord;
    int16_t fRet;
    FLEET * lpfl;
    int16_t idh;
    int16_t idhSav;

    /* debug symbols */
    /* label LReturn @ MEMORY_TUTOR:0x6f3e */

    /* TODO: implement */
    return 0;
}

void ShowTutor(int16_t fShow)
{

    /* TODO: implement */
}

void RestoreGameState(void)
{
    uint16_t hmenu;

    /* TODO: implement */
}

int16_t PanicDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    RECT rc;

    /* TODO: implement */
    return 0;
}

int16_t FCheckPatrolWP(uint16_t ifl, int16_t iord, int16_t id, uint16_t iWarp, uint16_t iPlan, uint16_t iDist)
{
    FLEET * lpfl;
    int16_t idhSav;
    int16_t grobj;

    /* TODO: implement */
    return 0;
}

int16_t FCheckLayingWP(uint16_t ifl, int16_t iord, int16_t id, int16_t iYears)
{
    FLEET * lpfl;
    int16_t idhSav;
    int16_t grobj;

    /* TODO: implement */
    return 0;
}

int16_t FCheckMessages(int16_t imsg, int16_t idm, int16_t fFilter)
{
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckQueue(int16_t ipl, int16_t iprod, uint16_t grobj, uint16_t iItem, uint16_t cItem, uint16_t fNoResearch)
{
    int16_t fRet;
    PLANET * lppl;
    PROD prod;
    int16_t idh;
    int16_t idhSav;

    /* debug symbols */
    /* label LReturn @ MEMORY_TUTOR:0x75c2 */

    /* TODO: implement */
    return 0;
}

int16_t FTutorialEnabledShipBuilder(int16_t itutsbAction)
{
    HS hs2;
    HS hs;
    HS hs1;
    HS hs3;
    HS hs4;

    /* debug symbols */
    /* block (block) @ MEMORY_TUTOR:0x7ca7 */
    /* block (block) @ MEMORY_TUTOR:0x7d72 */
    /* block (block) @ MEMORY_TUTOR:0x7e2f */
    /* block (block) @ MEMORY_TUTOR:0x7ee6 */
    /* block (block) @ MEMORY_TUTOR:0x7f52 */
    /* block (block) @ MEMORY_TUTOR:0x809d */
    /* label NoCustom @ MEMORY_TUTOR:0x7a23 */

    /* TODO: implement */
    return 0;
}

int16_t FCheckTemplate(int16_t iTemplate)
{
    int16_t i;

    /* TODO: implement */
    return 0;
}

int16_t FCheckColonizeWP(uint16_t ifl, int16_t id, uint16_t iWarp)
{
    int16_t ish;
    FLEET * lpfl;
    int16_t csh;
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckBuilderPart(int16_t iSlot, HS *phs, uint16_t cInit)
{
    uint16_t cItemAct;
    int16_t idhSav;

    /* debug symbols */
    /* label BadCnt @ MEMORY_TUTOR:0x7896 */
    /* label BadCntSilent @ MEMORY_TUTOR:0x78a2 */

    /* TODO: implement */
    return 0;
}

int16_t FAskKillTutor(void)
{

    /* TODO: implement */
    return 0;
}

void StartTutor(int16_t fRestart)
{
    int16_t cx;
    int16_t cch;

    /* TODO: implement */
}

int16_t FCheckSelection(uint16_t grobj, int16_t id)
{
    int16_t fRet;
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckSummary(uint16_t grobj, int16_t id)
{
    int16_t fRet;

    /* TODO: implement */
    return 0;
}

int16_t FOKMergeDialog(void)
{

    /* TODO: implement */
    return 0;
}

int16_t FCheckBtlPlan(int16_t ibp, uint16_t imdTarget, uint16_t fSpread, uint16_t fBomb, uint16_t fDump, uint16_t mdUnarmed, uint16_t mdScout, uint16_t mdWar, uint16_t mdBomber)
{
    BTLPLAN * lpbtlplan;
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckShipBuilder(int16_t iCategory, int16_t iShip)
{
    int16_t iSel;
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

void TutorError(int16_t idsError)
{

    /* TODO: implement */
}

void AdvanceTutor(void)
{
    char szTitle[50];
    int16_t fRedraw;
    int16_t idtT;
    int16_t fTaskDone;
    RECT rc;

    /* debug symbols */
    /* label LUpdatePage @ MEMORY_TUTOR:0x0b55 */
    /* label SkipToNext @ MEMORY_TUTOR:0x0a9e */

    /* TODO: implement */
}
