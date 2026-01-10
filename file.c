
#include "types.h"
#include "globals.h"
#include "platform.h"
#include "strings.h"
#include "memory.h"
#include "msg.h"
#include "utilgen.h"
#include "save.h"
#include "util.h"

#include "file.h"

StarsFile hf = {0};

int stars_seek(StarsFile *h, long offset, int whence)
{
    if (h == NULL || h->fp == NULL)
    {
        return -1;
    }
    return fseek(h->fp, offset, whence);
}

/* mdOpen mapping:
 * - original passed mdOpen & 0xbfff to OpenFile()
 * - we map common cases you likely use in Stars:
 *     0 => "rb"
 *     1 => "r+b" (read/write existing)
 *     2 => "wb"  (truncate/create)
 * If your project already has an mdOpen enum, adjust here.
 */
static inline const char *stars_mode_from_md(int16_t mdOpen)
{
    mdOpen = (int16_t)(mdOpen & (int16_t)0xbfff);

    switch (mdOpen)
    {
    case 2:
        return "wb";
    case 1:
        return "r+b";
    default:
        return "rb";
    }
}

/* Portable "OpenFile": returns 0 on success, nonzero on failure (like hf == -1 check). */
static inline int stars_open_file(StarsFile *h, const char *path, int16_t mdOpen)
{
    const char *mode = stars_mode_from_md(mdOpen);

    errno = 0;
    h->fp = fopen(path, mode);
    if (!h->fp)
    {
        h->last_errno = errno;
        return 1;
    }

    h->last_errno = 0;
    return 0;
}

static inline void stars_close_file(StarsFile *h)
{
    if (h->fp)
    {
        fclose(h->fp);
        h->fp = NULL;
    }
    h->last_errno = 0;
}

static inline size_t stars_read(StarsFile *h, void *dst, size_t cb)
{
    if (!h->fp)
        return 0;
    return fread(dst, 1, cb, h->fp);
}

/* functions */
void FileError(StringId ids)
{
    idsFileError = ids;
    if (!fFileErrSilent && !gd.fGeneratingTurn)
    {
        Error(ids);
    }
}

void StreamOpen(const char *szFile, int16_t mdOpen)
{
    uint32_t deadline = 0;

    bool fNoErr = (mdOpen & mdNoOpenErr) != 0;
    mdOpen = (int16_t)(mdOpen & (int16_t)~mdNoOpenErr);

    Assert(hf.fp == NULL); /* faithful to Assert(hf == HFILE_ERROR) */

    for (;;)
    {
        if (stars_open_file(&hf, szFile, mdOpen) == 0)
            return;

        if (!gd.fRetryOpens)
            break;
        if (hf.last_errno == ENOENT)
            break;

        uint32_t now = stars_tick_ms();
        if (deadline == 0)
            deadline = now + 4000u;
        if (now >= deadline)
            break;

        stars_sleep_ms(500u);
    }

    if (!fNoErr)
        FileError(idsCantOpenFile);

    longjmp(*(jmp_buf *)penvMem, -1);
}

void UnpackBattlePlan(uint8_t *lpb, BTLPLAN *lpbtlplan, int16_t iplan)
{
    char szTemp[33];
    char szName[33];
    int16_t cch;
    int16_t cOut;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x412a */

    /* TODO: implement */
}

bool FBadFileError(StringId ids)
{

    switch (ids)
    {
    case idsUniverseDefinitionFileSeemsMissingCorrupt:
    case idsPlayerLogFileAppearsCorruptUnableLoad:
    case idsHistoryFileAppearsCorruptHistoricalDataWill:
    case idsGameFileAppearsCorruptUnableLoadFile:
    case idsErrorWritingFile:
    case idsFileDate:
    case idsFileGame:
        return 1;
    }
    return 0;
}

void ReadRtPlr(PLAYER *pplr, uint8_t *pbIn)
{
    int16_t iOff;
    PLAYER *pplrRaw;
    int16_t cOut;
    char *psz;

    pplrRaw = (PLAYER *)pbIn;
    memset(pplr, 0, sizeof(*pplr));

    if (pplrRaw->det == detAll)
    {
        /* Full player record up to relations, 112 bytes */
        memmove(pplr, pbIn, cbPlayerAll);

        /* pbIn[cbPlayerAll] is the count/size for rgmdRelation */
        memmove(pplr->rgmdRelation, &pbIn[cbPlayerAll + 1], pbIn[cbPlayerAll]);

        iOff = (int16_t)(cbPlayerAll + pbIn[cbPlayerAll] + 1);
    }
    else
    {
        /* Partial player record up to before idPlanetHome */
        memmove(pplr, pbIn, cbPlayerSome);
        iOff = (int16_t)cbPlayerSome;
    }

    /* Player singular name */
    if (pbIn[iOff] == 0)
    {
        /* Not compressed: flag(0), then NUL-terminated string */
        strcpy(pplr->szName, (char *)(pbIn + iOff + 1));
        iOff = (int16_t)(iOff + 2 + (int)strlen(pplr->szName));
    }
    else
    {
        /* Compressed: flag is length, bytes follow */
        cOut = 32;
        FDecompressUserString(pbIn + iOff + 1, pbIn[iOff], pplr->szName, &cOut);
        iOff = (int16_t)(iOff + 1 + pbIn[iOff]);
    }

    /* Plural name (szNames) */
    if (((VERS *)(&wVersFile))->verMinor < 55)
    {
        psz = PszPlayerName(0, isupper((unsigned char)pplr->szName[0]) != 0, true, false, 0, pplr);
        strcpy(pplr->szNames, psz);
    }
    else
    {
        if (pbIn[iOff] == 0)
        {
            strcpy(pplr->szNames, (char *)(pbIn + iOff + 1));
        }
        else
        {
            cOut = 32;
            FDecompressUserString(pbIn + iOff + 1, pbIn[iOff], pplr->szNames, &cOut);
        }
    }

    pplr->fLearned = false;
}

void UpdateBattleRecords(void)
{
    // UpdateBattleRecords updates save game battle records from older versions
    // to 2.6 versions. We are not implementing this for the port
}

bool FReadFleet(FLEET *lpfl)
{
    uint16_t us;
    int16_t cord;
    int16_t fByte;
    ORDER *lpord;
    int16_t i;
    int16_t cish;
    uint8_t *pb;
    int16_t cch;
    uint16_t *pus;
    char szT[33];
    int16_t cOut;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x4047 */
    /* label Corrupt @ MEMORY_IO:0x3d24 */

    /* TODO: implement */
    return 0;
}

bool FLoadGame(const char *pszFileName, char *pszExt)
{
    int16_t iplrSav;
    int16_t cPlanetHist;
    STARPACK sp;
    int16_t cPlanetAlloc;
    int16_t fHaveHistoryData;
    int16_t (*penvMemSav)[9];
    int16_t fSilentSav;
    PLANET *lppl;
    int16_t i;
    THING *lpth;
    FLEET *lpfl;
    int16_t env[9];
    int16_t cturn;
    THING *lpthMac;
    int16_t iPlayer;
    int16_t j;
    PLANET *lpplMac;
    int16_t dt;
    int16_t grf;
    int16_t x;
    int16_t iplr;
    int16_t cThingFile;
    int16_t iP;
    int16_t fWorking;
    POINT pt;
    uint8_t *lpb;
    int16_t isx;
    int16_t fHist;
    int16_t iprod;
    uint16_t turnCur;
    int16_t iFirst;
    int16_t iLast;
    PROD *lpprod;
    int16_t iWarp;
    int16_t fTwo;
    SCOREX sx;
    char szT[256];
    char szIniFile[16];
    char szSection[16];
    char *psz;
    char szEntry[16];

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x089e */
    /* block (block) @ MEMORY_IO:0x1055 */
    /* block (block) @ MEMORY_IO:0x10ce */
    /* block (block) @ MEMORY_IO:0x1312 */
    /* block (block) @ MEMORY_IO:0x2220 */
    /* block (block) @ MEMORY_IO:0x22b7 */
    /* block (block) @ MEMORY_IO:0x256d */
    /* block (block) @ MEMORY_IO:0x27ae */
    /* block (block) @ MEMORY_IO:0x2b29 */
    /* block (block) @ MEMORY_IO:0x2b81 */
    /* block (block) @ MEMORY_IO:0x3051 */
    /* label CorruptHist @ MEMORY_IO:0x0c4e */
    /* label LFoundPlanet @ MEMORY_IO:0x19aa */
    /* label LFoundThing @ MEMORY_IO:0x2710 */
    /* label LNoHistFile @ MEMORY_IO:0x14db */
    /* label Corrupt @ MEMORY_IO:0x285c */
    /* label FreeShdef @ MEMORY_IO:0x1bb1 */
    /* label DoneNow @ MEMORY_IO:0x300e */
    /* label LNextTurn @ MEMORY_IO:0x1587 */
    /* label LError @ MEMORY_IO:0x085e */
    /* label XYCorrupt @ MEMORY_IO:0x0946 */

    /* TODO: implement */
    return 0;
}

bool FReadShDef(RTSHDEF *lprt, SHDEF *lpshdef, int16_t iplrLoad)
{
    char szTemp[40];
    SHDEF shdef;
    uint8_t *lpb;
    int16_t ishdef;
    int16_t cch;
    int16_t iFirst;
    int16_t cOut;
    int16_t fOkay;
    HUL *lphulBase;
    uint32_t wt;
    int16_t c;
    HUL *lphul;
    PART part;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x0105 */
    /* block (block) @ MEMORY_IO:0x0181 */
    /* block (block) @ MEMORY_IO:0x0321 */

    /* TODO: implement */
    return 0;
}

void ReadRt(void)
{
    Assert(hf.fp != NULL || vlpMemStream != NULL);

    RgFromStream(&hdrCur, sizeof(HDR));

    if (hdrCur.cb != 0)
    {
        RgFromStream(rgbCur, hdrCur.cb);
    }

    if (hdrCur.rt == rtBOF)
    {
        RTBOF bof;
        memcpy(&bof, rgbCur, sizeof(bof));
        SetFileXorStream(bof.lidGame, bof.lSaltTime, bof.turn, bof.iPlayer, bof.fCrippled);
    }
    else if (hdrCur.rt != rtEOF)
    {
        XorFileBuf(rgbCur, hdrCur.cb);
    }
}

bool FOpenFile(DtFileType dt, int16_t iPlayer, int16_t md)
{
    jmp_buf env;
    jmp_buf *penvMemSav;
    bool fSilentSav = fFileErrSilent;
    bool fCheckMulti;
    bool fRewind;
    StringId ids = idsCantOpenFile;
    RTBOF rtbof;

    gd.fPartialTurn = false;

    fCheckMulti = (dt & bitfMulti) != 0;
    fRewind = (dt & bitfRewind) != 0;
    dt &= grbitDtBase; /* Convert to a valid dt. */
    Assert(!fCheckMulti || dt == dtTurn);

    SetSzWorkFromDt(dt, iPlayer);

    penvMemSav = penvMem;
    penvMem = &env;
    if (setjmp(env) != 0)
    {
        fFileErrSilent = fSilentSav;
        FileError(ids);
        StreamClose();
        penvMem = penvMemSav;
        return false;
    }

    fFileErrSilent = true;
    StreamOpen(szWork, md);
    fFileErrSilent = fSilentSav;

    ids = idsCorrupted;
    ReadRt();

    if (hdrCur.rt != rtBOF)
    {
        FileError(idsFileDoesBelongVersionStars);
        goto LBadFile;
    }

    const RTBOF *bof = (const RTBOF *)rgbCur;

    if (bof->verMajor != MAJORVER ||
        bof->verMinor < MINORVERMin ||
        bof->verMinor >= MINORVERMax)
    {
        bool newer =
            (bof->verMajor > MAJORVER) ||
            (bof->verMajor == MAJORVER && bof->verMinor > MINORVERMax);

        FileError(newer
                      ? idsFileCreatedNewerVersionStarsMustUpgrade
                      : idsSorryFileCreatedOlderVersionStarsIncompatible);
        goto LBadFile;
    }

    rtbof = *bof;

    if (rtbof.iPlayer != iPlayer)
    {
        FileError(idsGameFileAppearsCorruptUnableLoadFile);
        goto LBadFile;
    }

    if (game.lid != 0)
    {
        if (rtbof.lidGame != game.lid)
        {
            FileError(idsFileGame);
            goto LBadFile;
        }
        else if (dt != dtHist)
        {
            /* Hist file will always seem to be one turn out of date! */
            if (fCheckMulti && rtbof.fMulti)
            {
                /* Multi-part file. Let's check the rest of it. */
                stars_seek(&hf, -4, SEEK_END);
                ReadRt();
                if (hdrCur.rt != rtEOF && hdrCur.cb != 2)
                {
                    goto LBadFile;
                }
                rtbof.turn = *(const uint16_t *)rgbCur;
                game.wGen = rtbof.wGen;
            }

            if (game.turn == 0 && game.turn != rtbof.turn)
            {
                game.turn = rtbof.turn;
                game.wGen = rtbof.wGen;
            }
            else if (rtbof.turn != game.turn)
            {
                FileError(idsFileDate);
                goto LBadFile;
            }
            else if (dt == dtHost && !gd.fHostMode && rtbof.fInUse)
            {
                if (MsgYesNo(idsHostFileMarkedUseAnotherInstanceStars) != IDYES)
                {
                    goto LBadFile;
                }
            }
            else if (!rtbof.fDone && gd.fGeneratingTurn && !gd.fForceTurn)
            {
                gd.fPartialTurn = true;
                goto LBadFile;
            }
            else if (dt == dtLog && !game.fTutorial && rtbof.wGen != game.wGen)
            {
                FileError(idsFileGame);
                goto LBadFile;
            }
        }
        else if (rtbof.iPlayer != iPlayer)
        {
            /* Hist file for wrong person */
            goto LBadFile;
        }
    }

    if (fRewind)
    {
        stars_seek(&hf, 0, SEEK_SET);
        ReadRt();
    }

    penvMem = penvMemSav;
    wVersFile = rtbof.wVersion;
    gd.fFileCrippled = rtbof.fCrippled;

    return true;

LBadFile:
    StreamClose();
    penvMem = penvMemSav;
    return false;
}

int16_t AskSaveDialog(void)
{

    /* TODO: implement */
    return 0;
}

void StreamClose(void)
{
    stars_close_file(&hf);
}

bool FNewTurnAvail(int16_t idPlayer)
{
    bool fNew;
    uint16_t turnOld = game.turn;
    uint16_t wGenOld = game.wGen;
    bool fErrSav = fFileErrSilent;

    Assert(idPlayer != -1);
    Assert(game.lid != 0);

    fFileErrSilent = true;

    /* Force FOpenFile() to populate game.turn from the BOF turn (it only does this when game.turn==0). */
    game.turn = 0;

    fNew = FOpenFile((uint16_t)(dtTurn | bitfMulti), idPlayer, mdRead);
    if (fNew)
    {
        StreamClose();
        fNew = (game.turn > turnOld);
    }

    game.turn = turnOld;
    game.wGen = wGenOld;
    fFileErrSilent = fErrSav;

    return fNew;
}

void GetFileStatus(int16_t dt, int16_t iPlayer)
{
    SetSzWorkFromDt((uint16_t)dt, (int16_t)iPlayer);

    /* fReadOnly is true if we cannot open/write the file. */
    gd.fReadOnly = (stars_access(szWork, modeWrite) != 0);
}

bool FReadPlanet(int16_t iPlayer, PLANET *lppl, bool fHistory, bool fPreInited)
{
    bool fFirstYear;
    bool fRouting;
    uint8_t bMask;
    int16_t i;
    uint8_t *pb;
    int16_t idm;
    int16_t pctOpt;
    int16_t pct;

    /* debug symbols */
    /* block (block) @ MEMORY_IO:0x380d */
    /* label LFinishBRecord @ MEMORY_IO:0x373b */

    /* TODO: implement */
    return 0;
}

void PromptSaveGame(void)
{
    int16_t (*lpProc)(void);
    int16_t fRet;

    /* TODO: implement */
}

bool FCheckFile(DtFileType dt, int16_t iPlayer, uint16_t md)
{
    bool fReturn = false;
    bool fOpened;
    bool fErrSav = fFileErrSilent;
    bool f = false;
    uint16_t wGenOld = game.wGen;

    switch (dt)
    {
    case dtHost:
        Assert(iPlayer == iPlayerNil);
        f = gd.fHostMode;
        gd.fHostMode = true;
        break;

    default:
        break;
    }

    fFileErrSilent = true;

    fOpened = FOpenFile(dt, iPlayer, mdRead);

    switch (md)
    {
    case mdInUse:
        if (!fOpened)
        {
            fReturn = true;
        }
        else
        {
            const RTBOF *bof = (const RTBOF *)rgbCur;
            fReturn = bof->fInUse != 0;
        }
        break;

    case mdDone:
        if (fOpened)
        {
            const RTBOF *bof = (const RTBOF *)rgbCur;
            fReturn = bof->fDone != 0;
        }
        else
        {
            fReturn = false;
        }
        break;

    case mdMulti:
        if (fOpened)
        {
            const RTBOF *bof = (const RTBOF *)rgbCur;
            fReturn = bof->fMulti != 0;
        }
        else
        {
            fReturn = false;
        }
        break;

    case mdPlayerType:
        if (!fOpened)
        {
            fReturn = false;
        }
        else
        {
            for (;;)
            {
                ReadRt();

                if (hdrCur.rt == rtPlr)
                {
                    const PLAYER *plr = (const PLAYER *)rgbCur;
                    if (plr->iPlayer == iPlayer)
                    {
                        fReturn = plr->fAi != 0;
                        break;
                    }
                }

                if (hdrCur.rt == rtEOF)
                {
                    fReturn = false;
                    break;
                }
            }
        }
        break;

    default:
        fReturn = false;
        break;
    }

    if (fOpened)
    {
        StreamClose();
    }

    if (dt == dtHost)
    {
        gd.fHostMode = f;
    }

    fFileErrSilent = fErrSav;
    game.wGen = wGenOld;

    return fReturn;
}

bool FValidSerialLong(uint32_t lSerial)
{
    // no serials in the port
    return true;
}

void DestroyCurGame(void)
{
    int16_t i;

    if (gd.fSendMsgMode)
    {
        FFinishPlrMsgEntry(0);
    }

    if (idPlayer != iPlayerNil && game.fDirty)
    {
        PromptSaveGame();
    }

    ResetHb(htPlanets);
    lpPlanets = NULL;
    cPlanet = 0;

    ResetHb(htFleets);
    rglpfl = NULL;
    cFleet = 0;

    ResetHb(htThings);
    lpThings = NULL;
    cThing = 0;
    cThingAlloc = 0;

    vlprgScoreX = NULL;
    vrptFleet.fCached = false;
    vrptPlanet.fCached = false;
    vrptBattle.fCached = false;
    vrptEFleet.fCached = false;

    for (i = 0; i < iPlayerMax; i++)
    {
        rgsxPlr[i] = NULL;
    }

    lpbBattleCur = NULL;
    lpbBattleLog = NULL;
    lpbBattleT = NULL;

    gd.fAisDone = false;
    gd.fGotoVCR = false;
    gd.fFleetLinkValid = false;

    ResetHb(htBattle);
    if (rglphb[htBattle] != NULL)
    {
        /* Match original: ((BTLDATA*)((BYTE*)rglphb[htBattle] + sizeof(HB) + sizeof(WORD)))->id = 0xffff; */
        BTLDATA *pbtl = (BTLDATA *)((uint8_t *)rglphb[htBattle] + sizeof(HB) + sizeof(uint16_t));
        pbtl->id = 0xFFFF;
    }

    ResetHb(htMisc);
    ResetHb(htString);
    ResetHb(htShips);
    ResetHb(htOrd);

    ResetHb(htPlrMsg);

    for (i = 0; i < iPlayerMax; i++)
    {
        rglpshdef[i] = NULL;
        rglpshdefSB[i] = NULL;
        rglpbtlplan[i] = NULL;
        rgcbtlplan[i] = 0;
    }

    /* Cache the selection in case we're coming right back. */
    if (sel.grobj != grobjNone)
    {
        ini.grobjSel = sel.grobj;
        ini.iObjSel = sel.id;
        ini.idPlayer = idPlayer;
        ini.lid = game.lid;
    }

    idPlayer = iPlayerNil;
    imemLogCur = 0;
    imemLogPrev = -1;
    iMsgCur = 0;
    vlpbAiData = NULL;
    ResetMessages();

    lSaltCur = 0;
    ctickLast = 0;

    game.lid = 0;
    game.cPlayer = 0;
    game.cPlanMax = 0;
    game.fDirty = false;
    game.turn = 0;
    game.szName[0] = '\0';

    gd.fGameOverMan = false;
    gd.fSendMsgMode = false;

    if (hwndBrowser != 0)
    {
        DestroyWindow(hwndBrowser);
    }

    if (hwndReportDlg != 0)
    {
        DestroyWindow(hwndReportDlg);
    }

    if (hwndPopup != 0)
    {
        DestroyWindow(hwndPopup);
        hwndPopup = 0;
    }

    hwndActive = 0;

    sel.scan.grobj = grobjNone;
    sel.scan.grobjFull = grobjNone;
    sel.scan.idpl = -1;
    sel.scan.ifl = -1;
    sel.scan.iwp = -1;

    fOrdersVis = false;

    sel.grobj = grobjNone;
    sel.grobjFull = grobjNone;
    sel.id = -1;

    sel.pt.x = 0;
    sel.pt.y = 0;

    sel.fl.id = -1;
    sel.pl.id = -1;

    sel.fl.lpplord = NULL;
    sel.pl.lpplprod = NULL;

    dxShipDD = 0;
    dxShipLB = 0;
    dxFleetCompLB = 0;
    dxOrderED = 0;
    dxPlanetProdLB = 0;

    for (i = 0; i < 3; i++)
    {
        rgdxOrderDD[i] = 0;
    }
}

void RgFromStream(void *rg, uint16_t cb)
{
    if (cb == 0)
    {
        return;
    }

    Assert(rg != NULL);

    if (vlpMemStream != NULL)
    {
        /* Read from memory */
        memcpy(rg, vlpMemStream, cb);
        vlpMemStream = (uint8_t *)vlpMemStream + cb;
        return;
    }

    Assert(hf.fp != NULL);

    if (stars_read(&hf, rg, (size_t)cb) != (size_t)cb)
    {
        FileError(idsGameFileAppearsCorruptUnableLoadFile);
        Assert(penvMem != NULL);
        longjmp(*(jmp_buf *)penvMem, -1);
    }
}

bool FBogusLong(uint32_t lSerial)
{
    // no serials in the port
    return false;
}
