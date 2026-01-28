
#include "types.h"
#include "globals.h"

#include "tutor.h"

/* globals */
ITEMACTION rgiaQuikDrop[5];     /* MEMORY_TUTOR:0x0f94 */
ITEMACTION rgiaQuikLoad[5];     /* MEMORY_TUTOR:0x0f9e */
ITEMACTION rgiaUnloadAllCol[5]; /* MEMORY_TUTOR:0x0fa8 */
ITEMACTION rgiaLoadAllCol[5];   /* MEMORY_TUTOR:0x0fb2 */
ZIPPRODQ1 rgzpqTut[2];          /* MEMORY_TUTOR:0x663a */

char mpishdefishTutor[6] = {3, 4, 9, 6, 7, 14};

#ifdef _WIN32

INT_PTR CALLBACK TutorDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HMENU hmenu;
    RECT rc;
    int16_t (*lpProc)(void);
    int16_t fRet;

    /* debug symbols */
    /* block (block) @ MEMORY_TUTOR:0x00ad */

    /* TODO: implement */
    return 0;
}

INT_PTR CALLBACK PanicDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RECT rc;

    /* TODO: implement */
    return 0;
}

/* functions */
void EndTutor(int16_t fClose)
{

    /* TODO: implement */
}

void DrawTutorText(HWND hwnd)
{
    HDC hdc;
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
    PLANET *lppl;
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
    uint16_t cur;

    /*
     * rgplr[0].iTechCur packs two 4-bit tech fields into one byte/word:
     *
     *   bits 0–3  : current research tech (iTech)
     *   bits 4–7  : next research tech     (iTechNext)
     *
     * This function verifies that:
     *   1) the player is currently researching `iTech`
     *   2) the queued/next tech is `iTechNext`
     *   3) the research percentage matches `pct`
     *
     * If all three match, the research state is exactly what the caller
     * expects and we return true.
     */
    cur = (uint16_t)rgplr[0].iTechCur;

    if (((cur & 0x000F) == (uint16_t)iTech) &&
        ((cur >> 4) == (uint16_t)iTechNext) &&
        (rgplr[0].pctResearch == pct))
    {
        return 1;
    }

    /*
     * Otherwise, the research state does not match expectations.
     *
     * Setting tutor.idh updates the *context-sensitive help topic*
     * that should be shown to the player explaining why this action
     * is invalid or unavailable.
     *
     * NOTE:
     *  - tutor.idh is a global UI/help routing field
     *  - 0x042e is a numeric help/context ID, NOT necessarily a
     *    string table index
     *  - Many Stars! help IDs map to indirect topics, dialog states,
     *    or tutorial contexts rather than literal text entries
     */
    tutor.idh = 0x042e;

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

int16_t FCheckFleetName(int16_t id, int16_t ids)
{
    FLEET *lpfl;
    char szT[33];
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckZip(int16_t iZip, ITEMACTION *lpiaGoal, int16_t ids)
{
    ITEMACTION *piaCur;
    int16_t i;
    char szT[33];
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

void SaveGameState(void)
{
    HMENU hmenu;

    /* TODO: implement */
}

int16_t FCheckXferWP(uint16_t ifl, int16_t iord, int16_t id, uint16_t iWarp, ITEMACTION *lpiaGoal)
{
    ORDER ord;
    int16_t fRet;
    ITEMACTION *piaCur;
    int16_t i;
    FLEET *lpfl;
    int16_t idh;
    int16_t grobj;
    int16_t idhSav;

    /* debug symbols */
    /* label LReturn @ MEMORY_TUTOR:0x73fa */

    /* TODO: implement */
    return 0;
}

int16_t FCheckFleetWP(uint16_t ifl, int16_t iord, GrobjClass grobj, int16_t id, uint16_t grTask, uint16_t iWarp)
{
    ORDER ord;
    int16_t fRet;
    FLEET *lpfl;
    int16_t idh;
    int16_t idhSav;

    /* debug symbols */
    /* label LReturn @ MEMORY_TUTOR:0x6f3e */

    /* TODO: implement */
    return 0;
}

void ShowTutor(int16_t fShow)
{
    int16_t cmd;

    if (tutor.hwnd != 0)
    {
        cmd = (fShow == 0) ? 0 : 5;
        ShowWindow(tutor.hwnd, cmd);
        tutor.fVisible = (uint16_t)(fShow != 0);
    }
}

void RestoreGameState(void)
{
    HMENU hmenu;

    /* TODO: implement */
}

int16_t FCheckPatrolWP(uint16_t ifl, int16_t iord, int16_t id, uint16_t iWarp, uint16_t iPlan, uint16_t iDist)
{
    FLEET *lpfl;
    int16_t idhSav;
    int16_t grobj;

    /* TODO: implement */
    return 0;
}

int16_t FCheckLayingWP(uint16_t ifl, int16_t iord, int16_t id, int16_t iYears)
{
    FLEET *lpfl;
    int16_t idhSav;
    int16_t grobj;

    /* TODO: implement */
    return 0;
}

int16_t FCheckMessages(int16_t imsg, MessageId idm, int16_t fFilter)
{
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckQueue(int16_t ipl, int16_t iprod, GrobjClass grobj, uint16_t iItem, uint16_t cItem, uint16_t fNoResearch)
{
    int16_t fRet;
    PLANET *lppl;
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
    FLEET *lpfl;
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

int16_t FCheckSelection(GrobjClass grobj, int16_t id)
{
    int16_t fRet;
    int16_t idhSav;

    /* TODO: implement */
    return 0;
}

int16_t FCheckSummary(GrobjClass grobj, int16_t id)
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
    BTLPLAN *lpbtlplan;
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

#endif /* _WIN32 */
