
#include "globals.h"
#include "types.h"

#include "debuglog.h"
#include "file.h"
#include "log.h"
#include "memory.h"
#include "msg.h"
#include "port.h"
#include "save.h"
#include "ship.h"
#include "tutor.h"
#include "util.h"
#include "utilgen.h"

#ifdef _WIN32
#include "resource.h"
#endif

/* functions */
void WriteMemRt(RecordType rt, int16_t cb, void *rg) {
    HDR hdr = hdrPrev;

    if (fLogOff == 0) {
        if ((int32_t)imemLogCur + (int32_t)cb + (int32_t)sizeof(uint16_t) > 32000) {
            int16_t mbType = 0x10;
            char   *sz = PszFormatIds(idsLogFileHasReachedMaximumAllowableSize, NULL);
            AlertSz(sz, mbType);
        }

        DirtyGame(1);

        imemLogPrev = imemLogCur;

        /* Bitfield assignment truncates like the original mask/shift pack. */
        hdr.cb = cb;
        hdr.rt = rt;

        /* Serialize exactly one 16-bit word: cb(10) | rt(6)<<10 */
        uint16_t hdrWord = (uint16_t)((cb & 0x03FF) | ((uint16_t)rt << 10));

        uint8_t *dst = (uint8_t *)lpLog + imemLogCur;
        memcpy(dst, &hdrWord, sizeof(hdrWord));

        if (cb > 0) {
            memcpy(dst + sizeof(hdrWord), rg, (size_t)cb);
        }

        imemLogCur = (int16_t)(imemLogCur + cb + (int16_t)sizeof(hdrWord));

        if (rt == 0) {
            hdr = hdrPrev;
        }
    }

    hdrPrev = hdr;
}

int16_t FWriteLogFile(char *pszFileBase, int16_t iPlayer) {
    MemJump *penvMemSav;
    MemJump  env;
    int16_t  iCur;
    HDR     *lprts;
    RTLOGHDR rtlh;
    MSGPLR  *lpmp;
    int16_t  sVar;

    iCur = 0;

    /* Check if zip production queue needs logging */
    if (iPlayer == idPlayer && rgplr[iPlayer].fAi == 0 && hdrPrev.rt != rtLogPlayerZpq1) {
        uint16_t cbZpq = (uint16_t)(2 * (uint8_t)vrgZipProd[0].cpq + 2);

        if (memcmp(&rgplr[iPlayer].zpq1, &vrgZipProd[0].zpq1, cbZpq) != 0) {
            WriteMemRt(rtLogPlayerZpq1, (int16_t)cbZpq, &vrgZipProd[0].zpq1);
        }
    }

    DBG_LOGI("FWriteLogFile: pszFileBase='%s' iPlayer='%d'", pszFileBase, iPlayer);

    if (pszFileBase != szBase) {
        /* copy + always terminate */
        size_t n = sizeof(szBase);
        strncpy(szBase, pszFileBase, n);
        szBase[n - 1] = '\0';
    }

    sVar = FCreateFile(dtLog, iPlayer, NULL);
    penvMemSav = penvMem;

    if (sVar == 0) {
        Error(idsUnableCreateLogFile);
        return 0;
    }

    penvMem = &env;
    if (setjmp(env.env) != 0) {
        penvMem = penvMemSav;
        StreamClose();
        return 0;
    }

    rtlh.cbLog = imemLogCur;
    rtlh.lSerialNumber = vSerialNumber;
    memcpy(rtlh.rgbConfig, vrgbEnvCur, 11);
    WriteRt(rtBOF, sizeof(RTLOGHDR), &rtlh);

    for (; iCur < imemLogCur; iCur = (int16_t)(iCur + (int16_t)lprts->cb + 2)) {
        lprts = (HDR *)(lpLog + (uint16_t)iCur);
        WriteRt(lprts->rt, lprts->cb, lpLog + (uint16_t)iCur + 2);
    }

    /* Write outgoing player messages */
    lpmp = vlpmsgplrOut;
    iCur = vcmsgplrOut;
    while (iCur != 0) {
        int16_t msgLen = (int16_t)(abs(lpmp->cLen) + 0x0C);
        WriteRt(rtPlrMsg, msgLen, lpmp);
        lpmp = lpmp->lpmsgplrNext;
        iCur--;
    }

    WriteRt(rtEOF, 0, NULL);
    StreamClose();
    penvMem = penvMemSav;
    DirtyGame(0);
    gd.fWriteTurnNum = 1;
    return 1;
}

void LogMergeFleet(int16_t id) {
    uint16_t rgid[512];
    int16_t  i;
    int16_t  j;

    if (gd.fGeneratingTurn == 0) {
        i = 0;
        while (i < vcflMerge) {
            rgid[0] = (uint16_t)id;
            j = 1;
            for (; j < 0x1FF && i < vcflMerge; i++) {
                if (vrgiflMerge[i] != -1 && vrgiflMerge[i] != id) {
                    rgid[j] = (uint16_t)vrgiflMerge[i];
                    j++;
                }
            }
            WriteMemRt(rtLogFleetMerge, (int16_t)(j << 1), rgid);
        }
    }
}

int16_t FLoadLogFile(char *pszLog) {
    HGLOBAL  hres;
    MemJump *penvMemSav;
    MemJump  env;
    int16_t  fRet;
    int16_t  cbLog;
    int16_t  iCur;
    int16_t  cSkip;

    /* debug symbols */
    /* block (block) @ MEMORY_PLANET:0xc855 */
    /* label BailOut @ MEMORY_PLANET:0xc88f */
    /* label StrOpen @ MEMORY_PLANET:0xc935 */
    /* label FailSuccess @ MEMORY_PLANET:0xc96e */
    /* label Done @ MEMORY_PLANET:0xcc76 */

    penvMemSav = penvMem;
    imemLogCur = 0;
    imemLogPrev = -1;

    penvMem = &env;
    if (setjmp(env.env) != 0) {
        /* StreamOpen / RgFromStream longjmp here.
         * Match decompile: distinguish missing file (success) from read failure.
         */
        if (vlpMemStream == NULL) {
            if (hf.fp != NULL) {
                penvMem = penvMemSav;
                StreamClose();
                return 0;
            }
            penvMem = penvMemSav;
            return 1;
        }

        penvMem = penvMemSav;
#ifdef _WIN32
        GlobalUnlock(hres);
        FreeResource(hres);
#endif
        return 0;
    }

    /* Tutorial autoplay can load a baked-in log resource; otherwise open the log on disk.
     * Decompile condition: if (!game.fTutorial || idPlayer != 0 || !gd.fGeneratingTurn) -> open file.
     */
#ifdef _WIN32
    if (game.fTutorial && idPlayer == 0 && gd.fGeneratingTurn) {
        cSkip = (int16_t)game.turn;

        HRSRC hrsrc = FindResource(hInst, MAKEINTRESOURCEA(IDR_TUTORIAL_HST), MAKEINTRESOURCEA(IDT_TUTORIAL_BLOB));
        hres = LoadResource(hInst, hrsrc);

        if (hres != 0) {
            vlpMemStream = (uint8_t *)LockResource(hres);
            if (vlpMemStream != NULL) {
                /* Resource begins with a single byte: max turn. If not new enough, fall back to file.
                 */
                if ((uint16_t)vlpMemStream[0] <= game.turn) {
                    vlpMemStream = NULL;
                    GlobalUnlock(hres);
                    FreeResource(hres);
                    goto StrOpen;
                }

                vlpMemStream++;

                while (cSkip != 0) {
                    /* Skip complete turns until we reach requested one.
                     * The stream is a log file byte-for-byte, so use record headers.
                     */
                    do {
                        const HDR *ph = (const HDR *)vlpMemStream;
                        vlpMemStream += (uint16_t)(2 + ph->cb);
                    } while (((const HDR *)vlpMemStream)->rt != rtBOF);
                    cSkip = (int16_t)(cSkip - 1);
                }
                goto ReadStart;
            }
        }
        fRet = 0;
        penvMem = penvMemSav;
        return fRet;
    }
#endif

StrOpen:
    StreamOpen(pszLog, (int16_t)(mdNoOpenErr | mdRead));

ReadStart:
    ReadRt();

    if (hdrCur.rt == rtBOF) {
        const RTBOF *bof = (const RTBOF *)rgbCur;

        if (bof->lidGame == game.lid && game.turn <= bof->turn) {
            if (bof->turn == game.turn) {
                if (bof->wGen == game.wGen) {
                    wVersFile = bof->wVersion;

                    gd.fFileCrippled = (uint16_t)bof->fCrippled;
                    if (gd.fGeneratingTurn) {
                        rgplr[idPlayer].fCrippled = (uint16_t)bof->fCrippled;
                    }

                    ReadRt();
                    memcpy(&cbLog, &rgbCur[0], sizeof(cbLog));

                    if (gd.fGeneratingTurn && vrgts != NULL && hdrCur.cb == (uint16_t)sizeof(RTLOGHDR)) {
                        /* Reset and capture current serial/config for this player. */
                        memset(&vrgts[idPlayer], 0, sizeof(TURNSERIAL));
                        {
                            const RTLOGHDR *rtlh = (const RTLOGHDR *)rgbCur;
                            vrgts[idPlayer].lSerialNumber = rtlh->lSerialNumber;
                            memcpy(vrgts[idPlayer].rgbConfig, rtlh->rgbConfig, sizeof(vrgts[idPlayer].rgbConfig));
                        }
                    }

                    for (iCur = 0; iCur < cbLog; iCur = (int16_t)(iCur + (int16_t)hdrCur.cb + 2)) {
                        ReadRt();
                        memmove(lpLog + (uint16_t)iCur, &hdrCur, 2);
                        memmove(lpLog + (uint16_t)iCur + 2, rgbCur, hdrCur.cb);
                    }

                    ReadRt();

                    /* Append any player messages (rtPlrMsg) to the outgoing message chain.
                     * Use pointer-to-pointer tail to avoid a sentinel MSGPLR.
                     */
                    MSGPLR **ppTail = &vlpmsgplrOut;
                    while (*ppTail != NULL) {
                        ppTail = &(*ppTail)->lpmsgplrNext;
                    }

                    while (hdrCur.rt == rtPlrMsg) {
                        MSGPLR *node = (MSGPLR *)LpAlloc(hdrCur.cb, htPlrMsg);
                        memcpy(node, rgbCur, hdrCur.cb);
                        node->lpmsgplrNext = NULL;
                        *ppTail = node;
                        ppTail = &node->lpmsgplrNext;
                        vcmsgplrOut++;
                        ReadRt();
                    }

                    fRet = (int16_t)(hdrCur.rt == rtEOF);
                    if (fRet) {
                        imemLogCur = cbLog;
                    }

                    if (vlpMemStream == NULL) {
                        StreamClose();
                    } else {
#ifdef _WIN32
                        GlobalUnlock(hres);
                        FreeResource(hres);
#endif
                        vlpMemStream = NULL;
                    }

                    penvMem = penvMemSav;
                    DirtyGame(0);
                    return fRet;
                }
                FileError(idsFileGame);
            } else {
                FileError(idsLogFileRecentGameTryingLoadIgnoring);
            }
        }
    }

    if (vlpMemStream == NULL) {
        StreamClose();
    } else {
        vlpMemStream = NULL;
#ifdef _WIN32
        GlobalUnlock(hres);
        FreeResource(hres);
#endif
    }

    penvMem = penvMemSav;
    return 1;
}

void DirtyGame(int16_t fDirty) {
    if ((fDirty != game.fDirty) && (game.fDirty = fDirty, fAi == 0)) {
#ifdef WIN32
        SetMsgTitle(hwndMessage);
#endif
    }
    return;
}

void LogSplitFleet(int16_t id) {
    if (gd.fGeneratingTurn == 0) {
        WriteMemRt(rtLogFleetSplit, 2, &id);
    } else {
        FLEET *pfl = LpflFromId(id);
        /* Set bit 5 of the high word of dirLong (split marker) */
        uint16_t *pw = (uint16_t *)((uint8_t *)&pfl->dirLong + 2);
        *pw = (*pw & 0xFFDF) | 0x0020;
    }
}

int16_t FWriteTutorialMFile(int16_t iTurn) {
    char     szT[30];
    MemJump *penvMemSav;
    MemJump  env;
    int16_t  cch;
    int16_t  cSkip;
    int16_t  sVar;
#ifdef _WIN32
    HRSRC   hrsrc;
    HGLOBAL hres;
#endif

    penvMemSav = penvMem;
    cSkip = iTurn;
    penvMem = &env;

    if (setjmp(env.env) != 0) {
        if (vlpMemStream == NULL) {
            if (hf.fp == NULL) {
                sVar = 1;
                penvMem = penvMemSav;
            } else {
                penvMem = penvMemSav;
                StreamClose();
                sVar = 0;
            }
        } else {
            penvMem = penvMemSav;
#ifdef _WIN32
            GlobalUnlock(hres);
            FreeResource(hres);
#endif
            sVar = 0;
        }
        return sVar;
    }

#ifdef _WIN32
    if (iTurn < 0x20) {
        hrsrc = FindResource(hInst, MAKEINTRESOURCEA(0x2713), MAKEINTRESOURCEA(0x2712));
    } else {
        hrsrc = FindResource(hInst, MAKEINTRESOURCEA(0x2715), MAKEINTRESOURCEA(0x2714));
        cSkip = (int16_t)(iTurn - 0x20);
    }

    hres = LoadResource(hInst, hrsrc);
    if (hres == 0) {
        penvMem = penvMemSav;
        return 0;
    }

    vlpMemStream = (uint8_t *)LockResource(hres);
    if (vlpMemStream == NULL) {
        penvMem = penvMemSav;
        return 0;
    }

    if (cSkip >= (int16_t)(uint16_t)*(uint8_t *)vlpMemStream) {
        vlpMemStream = NULL;
        GlobalUnlock(hres);
        FreeResource(hres);
        penvMem = penvMemSav;
        return 2;
    }

    vlpMemStream++;

    while (cSkip != 0) {
        do {
            const HDR *ph = (const HDR *)vlpMemStream;
            vlpMemStream += (uint16_t)(ph->cb + 2);
        } while (((const HDR *)vlpMemStream)->rt != rtBOF);
        cSkip--;
    }

    cch = CchGetString(idsTutorial, szT);
    if (iTurn == 0x25) {
        strcpy(szT + cch, (char *)MAKEINTRESOURCEA(0x9AA));
    } else {
        strcpy(szT + cch, (char *)MAKEINTRESOURCEA(0x9AF));
    }

    StreamOpen(szT, 0x1012);

    do {
        const HDR *ph = (const HDR *)vlpMemStream;
        RgToStream(vlpMemStream, (uint16_t)(ph->cb + 2));
        vlpMemStream += (uint16_t)(ph->cb + 2);
    } while (((const HDR *)vlpMemStream)->rt != rtBOF);

    StreamClose();
    vlpMemStream = NULL;
    GlobalUnlock(hres);
    FreeResource(hres);
    penvMem = penvMemSav;
    return 1;
#else
    (void)cch;
    (void)cSkip;
    (void)szT;
    penvMem = penvMemSav;
    return 0;
#endif
}

/*
 * EnumLogRts
 *
 * Enumerates records in the in-memory log buffer and invokes a callback
 * for each record. Enumeration stops early if the callback returns 0.
 *
 * pfn    - Callback invoked per record:
 *          pfn(pvData, rt, cb, lpPass, iPass)
 *          pvData points to the record payload (past the HDR).
 * lpPass - Opaque caller-supplied context pointer.
 * iPass  - Small pass identifier forwarded to the callback.
 */
void EnumLogRts(int16_t (*pfn)(void *, int16_t, int16_t, void *, int16_t), void *lpPass, int16_t iPass) {
    int16_t iCur;
    HDR    *lprts;

    if (imemLogCur == 0)
        return;

    for (iCur = 0; iCur < imemLogCur; iCur = (int16_t)(iCur + (int16_t)lprts->cb + 2)) {
        lprts = (HDR *)(lpLog + (uint16_t)iCur);

        if (!pfn((void *)(lpLog + (uint16_t)iCur + 2), (int16_t)lprts->rt, (int16_t)lprts->cb, lpPass, iPass)) {
            return;
        }
    }
}

/*
 * FGetPrevLogRt
 *
 * Retrieves the most recently recorded log entry (if any) from the
 * in-memory log buffer.
 *
 * phdr - Receives the decoded log record header.
 * pb   - Optional buffer to receive the record payload (cb bytes).
 *
 * Returns nonzero if a previous log record exists; zero otherwise.
 */
int16_t FGetPrevLogRt(HDR *phdr, uint8_t *pb) {
    const uint8_t *lpv;

    if (imemLogPrev == (int16_t)-1)
        return 0;

    lpv = (const uint8_t *)lpLog + (uint16_t)imemLogPrev;

    /* Original is effectively a 2-byte copy: *phdr = *(HDR*)lpv */
    memcpy(phdr, lpv, sizeof(*phdr));

    if (phdr->cb != 0) {
        memcpy(pb, lpv + 2, (size_t)phdr->cb);
    }

    return 1;
}

void LogChangeThing(THING *lpth, THING *pthNew) {
    int16_t i;
    int16_t fChg;
    LOGXFER lxNew;

    fChg = 0;
    if (gd.fGeneratingTurn != 0)
        return;

    memset(&lxNew, 0, sizeof(lxNew));
    lxNew.id = (int16_t)pthNew->idFull;
    lxNew.grobj = grobjThing;

    for (i = 0; i < 3; i++) {
        int16_t diff = pthNew->thp.rgwtMin[i] - lpth->thp.rgwtMin[i];
        lxNew.rgdItem[i] = (int32_t)diff;
        if (diff != 0)
            fChg = 1;
    }

    if (fChg) {
        if (fValidLx == 0) {
            memcpy(&lx, &lxNew, sizeof(LOGXFER));
            fValidLx = 1;
        } else {
            LogMakeValidXfer(&lx, &lxNew);
            fValidLx = 0;
        }
    }
}

void LogChangePlanet(PLANET *ppl, PLANET *pplNew) {
    int16_t i;
    int16_t fChg;
    HDR     hdr;
    LOGXFER lxNew;
    int16_t sVar;

    fChg = 0;
    if (gd.fGeneratingTurn != 0)
        return;

    if (ppl == NULL) {
        /* Cancel previous transfer */
        if (fValidLx == 0)
            return;

        lxNew.id = -1;
        lxNew.grobj = grobjOther;
        for (i = 0; i < 5; i++) {
            lxNew.rgdItem[i] = -lx.rgdItem[i];
        }
    } else {
        lxNew.id = ppl->id;
        lxNew.grobj = grobjPlanet;
        for (i = 0; i < 4; i++) {
            lxNew.rgdItem[i] = pplNew->rgwtMin[i] - ppl->rgwtMin[i];
            if (lxNew.rgdItem[i] != 0)
                fChg = 1;
        }
        lxNew.rgdItem[4] = 0;

        if (!fChg)
            goto CheckProdQ;
    }

    /* Mineral change: use LOGXFER path */
    if (fValidLx == 0) {
        memcpy(&lx, &lxNew, sizeof(LOGXFER));
        fValidLx = 1;
    } else {
        LogMakeValidXfer(&lx, &lxNew);
        fValidLx = 0;
    }

CheckProdQ:
    if (ppl == NULL)
        return;

    /* Check production queue changes */
    if (pplNew->lpplprod == NULL && ppl->lpplprod != NULL) {
        /* Queue cleared */
        WriteMemRt(rtLogPlanetProdQ, 2, &lxNew);
    } else if (pplNew->lpplprod != NULL && (ppl->lpplprod == NULL || ppl->lpplprod->iprodMac != pplNew->lpplprod->iprodMac ||
                                            memcmp(ppl->lpplprod->rgprod, pplNew->lpplprod->rgprod, (size_t)ppl->lpplprod->iprodMac * sizeof(PROD)) != 0)) {
        /* Queue changed */
        sVar = FGetPrevLogRt(&hdr, (uint8_t *)rgbCur);
        if (sVar != 0 && hdr.rt == rtLogPlanetProdQ && *(int16_t *)rgbCur == ppl->id) {
            imemLogCur = imemLogPrev;
        }

        *(int16_t *)rgbCur = ppl->id;
        memmove(rgbCur + 2, pplNew->lpplprod->rgprod, (size_t)pplNew->lpplprod->iprodMac * sizeof(PROD));
        WriteMemRt(rtLogPlanetProdQ, (int16_t)((uint16_t)pplNew->lpplprod->iprodMac * sizeof(PROD) + 2), rgbCur);
    }

    /* Check starbase/routing/infrastructure changes */
    if (ppl->fStarbase != pplNew->fStarbase || (ppl->idFling != pplNew->idFling) || (ppl->iWarpFling != pplNew->iWarpFling) ||
        (ppl->idRoute != pplNew->idRoute)) {
        uint32_t packed = 0;

        *(int16_t *)rgbCur = pplNew->id;

        packed |= (uint32_t)(pplNew->fStarbase & 1);
        packed |= (uint32_t)(pplNew->idFling & 0x3FF) << 1;
        packed |= (uint32_t)(pplNew->iWarpFling & 0xF) << 11;
        packed |= (uint32_t)(pplNew->idRoute & 0x3FF) << 15;

        memcpy(rgbCur + 2, &packed, 4);
        WriteMemRt(rtLogPlanetRouting, 6, rgbCur);
    }
}

int16_t FCheckLogFile(int16_t iplr, int16_t *pfError) {
    MemJump *penvMemSav;
    MemJump  env;
    int16_t  fRet;
    int16_t  cbLog;
    int16_t  iCur;

    penvMemSav = penvMem;
    imemLogCur = 0;
    imemLogPrev = -1;
    penvMem = &env;

    if (setjmp(env.env) != 0) {
        if (hf.fp == NULL) {
            fRet = 1;
            penvMem = penvMemSav;
        } else {
            penvMem = penvMemSav;
            StreamClose();
            *pfError = 3;
            fRet = 0;
        }
        return fRet;
    }

    idsFileError = 0;
    if (FOpenFile(dtLog, iplr, 0x20) == 0) {
        if (idsFileError != 4) {
            *pfError = idsFileError;
        }
        fRet = 0;
    } else {
        ReadRt();
        memcpy(&cbLog, rgbCur, sizeof(cbLog));

        for (iCur = 0; iCur < cbLog; iCur = (int16_t)(iCur + hdrCur.cb + 2)) {
            ReadRt();
        }

        ReadRt();
        while (hdrCur.rt == rtPlrMsg) {
            ReadRt();
        }

        if (hdrCur.rt != rtEOF) {
            *pfError = 3;
            fRet = 0;
        } else {
            imemLogCur = cbLog;
            fRet = 1;
        }

        StreamClose();
        penvMem = penvMemSav;
    }

    return fRet;
}

void LogChangeBtlplan(BTLPLAN *pbtlplan) {
    WriteBattlePlan(pbtlplan, 1);

    if (gd.fTutorial && idPlayer == 0) {
        tutor.fChange = 1;
        AdvanceTutor();
    }
}

void LogChangeRelations(void) {
    HDR     hdr;
    int16_t sVar;

    sVar = FGetPrevLogRt(&hdr, (uint8_t *)rgbCur);
    if (sVar != 0 && hdr.rt == rtLogRelations) {
        imemLogCur = imemLogPrev;
    }

    WriteMemRt(rtLogRelations, (int16_t)game.cPlayer, &rgplr[idPlayer].rgmdRelation[0]);

    if (gd.fTutorial && idPlayer == 0) {
        tutor.fChange = 1;
        AdvanceTutor();
    }
}

int16_t FRunLogRecord(RecordType rt, int16_t cb, uint8_t *lpb) {
    int16_t   fExtra;
    int32_t   cXfer;
    XFERFULL *lpxfCur;
    PLANET    pl;
    PLANET   *lppl;
    int32_t   rgcXfer[5];
    XFER      rgxf[2];
    FLEET    *lpfl;
    int16_t   ifl;
    int16_t   i;
    uint16_t  grbit;
    int16_t   rgifl[512];
    SHDEF    *lpshdef;
    int16_t   iPass;
    int16_t   iLook;
    int16_t   iColDrop;
    int32_t   l;
    int16_t   idm;
    THING    *lpth;
    COLDROP  *lpcdT;
    char      szT[33];
    int16_t   cOut;

    lpxfCur = NULL;
    lppl = &pl;

    switch (rt) {
    case rtEOF:
        break;

    case rtLogCargoXfer8:
    case rtLogCargoXfer16:
    case rtLogCargoXfer32: {
        uint8_t    srcdst = lpb[4];
        GrobjClass srcClass = (GrobjClass)(srcdst & (grobjThing | grobjOther | grobjFleet | grobjPlanet));
        GrobjClass dstClass = (GrobjClass)(srcdst >> 4);

        int16_t idSrc = *(int16_t *)lpb;
        int16_t idDst = *(int16_t *)(lpb + 2);

        /* src */
        if (!FLookupObject(srcClass, idSrc, &rgxf[0].fl))
            return 0;

        /* default dst invalid */
        rgxf[1].fl.id = -1;

        /* dst can be "none" (high nibble == grobjOther==4), otherwise must resolve */
        if ((dstClass == grobjOther) || FLookupObject(dstClass, idDst, &rgxf[1].fl)) {
            grbit = (uint16_t)lpb[5];
            iLook = 0;

            for (i = 0; i < 5; i++) {
                if ((grbit & 1u) == 0) {
                    rgcXfer[i] = 0;
                } else {
                    if (rt == rtLogCargoXfer8) {
                        rgcXfer[i] = (int32_t)(int8_t)lpb[6 + iLook];
                    } else if (rt == rtLogCargoXfer16) {
                        rgcXfer[i] = (int32_t)*(int16_t *)(lpb + 6 + 2 * iLook);
                    } else {
                        rgcXfer[i] = *(int32_t *)(lpb + 6 + 4 * iLook);
                    }
                    iLook++;
                }
                grbit >>= 1;
            }

            for (iPass = 0; iPass < 2; iPass++) {
                for (i = 0; i < 5; i++) {
                    cXfer = rgcXfer[i];
                    if (cXfer == 0)
                        continue;

                    /* pass0 handles negative, pass1 handles non-negative */
                    if (((iPass == 0) && (cXfer < 0)) || ((iPass == 1) && (cXfer >= 0))) {
                        l = ChgCargo(srcClass, idSrc, i, cXfer, &rgxf[0].fl);
                        if (l != cXfer) {
                            idm = ((srcdst & 0x0F) == grobjFleet) ? (int16_t)0x8000 : idmColonistsDroppedMassacredGroundTroops;
                            idm = (int16_t)(idm | rgxf[0].th.idFull);

                            FSendPlrMsg(rgxf[0].fl.iPlayer, idmUnableTransferKtKtRequest, idm, idm, (int32_t)cXfer - (int32_t)l, i, cXfer, 0, 0, 0);

                            rgcXfer[i] = l;
                            cXfer = l;
                        }
                    }

                    /* Destination processing happens on the opposite pass (matches decompile). */
                    if ((((iPass == 0) && (cXfer >= 0)) || ((iPass == 1) && (cXfer < 0))) && (dstClass != grobjOther)) {
                        /* Special colonist drop tracking: fleet -> planet with different owners during turn gen. */
                        if ((i == 3) && (cXfer != 0) && gd.fGeneratingTurn && (dstClass == grobjPlanet) && ((srcdst & 0x0F) == grobjFleet) &&
                            (rgxf[0].fl.iPlayer != rgxf[1].fl.iPlayer)) {

                            if (cXfer <= 0) {
                                /* Accumulate (note: decompile subtracts a negative to add). */
                                iColDrop = 0;
                                lpcdT = lpcd;
                                while (iColDrop < cColDrop) {
                                    if ((lpcdT->idFleetSrc == rgxf[0].fl.id) && (lpcdT->idPlanetDst == rgxf[1].fl.id))
                                        break;
                                    lpcdT++;
                                    iColDrop++;
                                }

                                if (iColDrop == cColDrop) {
                                    lpcdT->idFleetSrc = rgxf[0].fl.id;
                                    lpcdT->idPlr = rgxf[0].fl.iPlayer;
                                    lpcdT->idPlanetDst = rgxf[1].fl.id;
                                    lpcdT->cColonist = 0;
                                    lpcdT->fCanColonize = (uint16_t)(rgxf[1].fl.iPlayer != -1);
                                    cColDrop++;
                                }

                                lpcdT->cColonist -= cXfer;
                            } else {
                                /* Consume earlier pending drop records first. */
                                iColDrop = 0;
                                lpcdT = lpcd;
                                while ((iColDrop < cColDrop) && (cXfer > 0)) {
                                    if ((lpcdT->idPlanetDst == rgxf[1].fl.id) && (lpcdT->idPlr == rgxf[0].fl.iPlayer)) {
                                        int32_t take = cXfer;
                                        if (lpcdT->cColonist < take)
                                            take = lpcdT->cColonist;
                                        cXfer -= take;
                                        lpcdT->cColonist -= take;
                                    }
                                    lpcdT++;
                                    iColDrop++;
                                }
                            }
                        } else if ((cXfer == 0) || (!gd.fGeneratingTurn) || (rgxf[1].fl.iPlayer == rgxf[0].fl.iPlayer) || (dstClass == grobjThing)) {
                            /* Straight transfer on destination. */
                            goto PlanetStealCargo;
                        } else {
                            /* XFERFULL bookkeeping (for theft/capture resolution), matches decompile structure. */
                            if (cXfer <= 0) {
                                if (iPass == 1)
                                    goto PlanetStealCargo;

                                if (lpxfCur == NULL) {
                                    XFERFULL *pEnd = lpxf + cXferFull;
                                    lpxfCur = lpxf;
                                    while (lpxfCur < pEnd) {
                                        if (memcmp(lpxfCur, lpb, 5) == 0)
                                            break;
                                        lpxfCur++;
                                    }

                                    if (lpxfCur == pEnd) {
                                        /* New entry. */
                                        cXferFull++;
                                        memset(lpxfCur, 0, sizeof(*lpxfCur));
                                        lpxfCur->id1 = *(uint16_t *)lpb;
                                        lpxfCur->id2 = *(uint16_t *)(lpb + 2);
                                        lpxfCur->wRaw_0004 = lpb[4];
                                    }
                                }

                                lpxfCur->rgcQuan[i] -= cXfer;
                            } else {
                                XFERFULL *p = lpxf;
                                XFERFULL *pEnd = lpxf + cXferFull;
                                uint16_t  id1Masked = (uint16_t)(*(uint16_t *)lpb & 0xFE00u);

                                while ((p < pEnd) && (cXfer > 0)) {
                                    if ((p->grobj2 == dstClass) && (p->id2 == idDst) && (p->grobj1 == grobjFleet) && ((p->id1 & 0xFE00u) == id1Masked)) {

                                        int32_t take = cXfer;
                                        if (p->rgcQuan[i] < take)
                                            take = p->rgcQuan[i];

                                        cXfer -= take;
                                        p->rgcQuan[i] -= take;
                                    }
                                    p++;
                                }
                            }
                        }

                    PlanetStealCargo: {
                        int32_t req = -cXfer;

                        l = ChgCargo(dstClass, idDst, i, req, &rgxf[1].fl);

                        if (l != req) {
                            rgcXfer[i] = -l;

                            if (dstClass == grobjThing) {
                                idm = idmDidntGetAttemptedTransferMineralPacketAnother;
                                if (l == 0)
                                    idm = idmDidntGetAnyAttemptedTransferMineralPacket;

                                FSendPlrMsg(rgxf[0].fl.iPlayer, idm, (int16_t)(rgxf[0].th.idFull | 0x8000), rgxf[0].fl.id, i, -l, i, 0, 0, 0);
                            } else {
                                idm = ((srcdst & 0x0F) == grobjFleet) ? (int16_t)0x8000 : idmColonistsDroppedMassacredGroundTroops;
                                idm = (int16_t)(idm | rgxf[0].th.idFull);

                                FSendPlrMsg(rgxf[0].fl.iPlayer, idmUnableTransferKtKtRequest, idm, idm, req - l, i, req, 0, 0, 0);
                            }
                        }
                    }
                    }
                }
            }

            /* post-cleanup EXACTLY as decompile */
            if ((srcdst & 0x0F) == grobjFleet) {
                FLookupFleet(-1, &rgxf[0].fl);
            } else {
                FLookupPlanet(-1, &rgxf[0].pl);
            }

            if ((srcdst >> 4) == grobjFleet) {
                FLookupFleet(-1, &rgxf[1].fl);
            } else if (((srcdst >> 4) == grobjPlanet) || ((srcdst >> 4) == grobjOther)) {
                FLookupPlanet(-1, &rgxf[1].pl);
            } else if ((srcdst >> 4) == grobjThing) {
                FLookupThing(-1, &rgxf[1].th);
            }
        } else {
            /* decompile: if dst lookup fails, only allow special fleet/player case; otherwise fail */
            if (((lpb[4] >> 4) != grobjFleet) || (((*(uint16_t *)(lpb + 2) >> 9) & 0x0Fu) == (uint16_t)idPlayer)) {
                return 0;
            }
        }
    } break;

    case rtLogFleetOrderDelete: {
        lpfl = LpflFromId(*(int16_t *)lpb);
        if ((lpfl == NULL) || (lpfl->cord < 1))
            return 0;

        ifl = (int16_t)(*(uint16_t *)(lpb + 2) & 0x7FFFu);
        if (lpfl->cord <= ifl)
            return 0;

        fExtra = (int16_t)((*(uint16_t *)(lpb + 2) & 0x8000u) != 0);
        if ((fExtra != 0) && (lpfl->cord <= (int16_t)(ifl + 1)))
            return 0;

        /* delete 1 or 2 orders */
        memmove(&lpfl->lpplord->rgord[ifl], &lpfl->lpplord->rgord[ifl + 1 + fExtra],
                (size_t)(((lpfl->cord - ifl) - fExtra) - 1) * sizeof(lpfl->lpplord->rgord[0]));

        lpfl->cord = (int16_t)(lpfl->cord - (fExtra + 1));

        /* decompile also decrements PLORD.iordMac */
        lpfl->lpplord->iordMac = (uint8_t)(lpfl->lpplord->iordMac - (uint8_t)(fExtra + 1));
    } break;

    case rtLogFleetOrderInsert: {
        lpfl = LpflFromId(*(int16_t *)lpb);
        if (lpfl == NULL)
            return 0;

        ifl = *(int16_t *)(lpb + 2);
        if (ifl < 0)
            return 0;
        if (lpfl->cord < ifl)
            return 0;

        /* decompile: grow if full (cord == iordMax), realloc to cord + 3 */
        if ((uint16_t)lpfl->cord == (uint16_t)lpfl->lpplord->iordMax) {
            lpfl->lpplord = (PLORD *)LpplReAlloc((PL *)lpfl->lpplord, (uint16_t)(lpfl->cord + 3));
        }

        /* make room */
        memmove(&lpfl->lpplord->rgord[ifl + 1], &lpfl->lpplord->rgord[ifl], (size_t)(lpfl->cord - ifl) * sizeof(lpfl->lpplord->rgord[0]));

        /* if short payload, zero full ORDER before copying */
        if ((uint16_t)cb < (uint16_t)(4u + sizeof(lpfl->lpplord->rgord[0]))) {
            memset(&lpfl->lpplord->rgord[ifl], 0, sizeof(lpfl->lpplord->rgord[0]));
        }

        memmove(&lpfl->lpplord->rgord[ifl], lpb + 4, (size_t)(cb - 4));

        /* decompile clears 0x2000 in the word at +10: model as bitfield */
        lpfl->lpplord->rgord[ifl].fNoAutoTrack = 0;

        lpfl->cord++;
        lpfl->lpplord->iordMac = (uint8_t)(lpfl->lpplord->iordMac + 1);
    } break;

    case rtLogFleetOrderUpdate: {
        lpfl = LpflFromId(*(int16_t *)lpb);
        if (lpfl == NULL)
            return 0;

        ifl = *(int16_t *)(lpb + 2);
        if (lpfl->cord < 0)
            return 0;
        if (lpfl->cord <= ifl)
            return 0;

        if ((uint16_t)cb < (uint16_t)(4u + sizeof(lpfl->lpplord->rgord[0]))) {
            memset(&lpfl->lpplord->rgord[ifl], 0, sizeof(lpfl->lpplord->rgord[0]));
        }

        memmove(&lpfl->lpplord->rgord[ifl], lpb + 4, (size_t)(cb - 4));

        lpfl->lpplord->rgord[ifl].fNoAutoTrack = 0;
    } break;

    case rtLogFleetFlagBit9:
    case rtLogFleetOrderAttrNib: {
        lpfl = LpflFromId(*(int16_t *)lpb);
        if (lpfl == NULL)
            return 0;

        if (rt == rtLogFleetFlagBit9) {
            /* decompile: wFlags bit9 => FLEET.fRepOrders */
            lpfl->fRepOrders = (uint16_t)(*(uint16_t *)(lpb + 2) & 1u);
        } else {
            ifl = *(int16_t *)(lpb + 2);
            if (lpfl->cord <= ifl)
                return 0;

            /* decompile rejects >9 */
            if (9 < *(int16_t *)(lpb + 4))
                return 0;

            /* decompile: word at (lpplord + ifl*0x12 + 10) is ORDER.wRaw_0006; low nibble is ORDER.grTask */
            lpfl->lpplord->rgord[ifl].grTask = (uint16_t)(*(uint16_t *)(lpb + 4) & 0x000Fu);
        }
    } break;

        /* --- The remaining cases are unchanged from your prior version (except sizeof cleanups) --- */

    case rtLogFleetCargoXfer:
        if (!FLookupObject(grobjFleet, *(int16_t *)lpb, &rgxf[0].fl))
            return 0;
        if (!FLookupObject(grobjFleet, *(int16_t *)(lpb + 2), &rgxf[1].fl))
            return 0;
        if (rgxf[1].fl.iPlayer != rgxf[0].fl.iPlayer)
            return 0;

        for (iPass = 0; iPass < 2; iPass++) {
            grbit = *(uint16_t *)(lpb + 5);
            iLook = 0;

            for (i = 0; i < 16; i++) {
                if ((grbit & 1u) != 0) {
                    int32_t delta = (int32_t)*(int16_t *)(lpb + 7 + 2 * iLook);

                    if (((iPass == 0) && (delta < 0)) || ((iPass == 1) && (delta >= 0))) {
                        int32_t src = (int32_t)rgxf[0].fl.rgcsh[i];
                        int32_t dst = (int32_t)rgxf[1].fl.rgcsh[i];

                        if (src + delta < 0)
                            delta = -src;
                        else if (src + delta > 0x7FFDu)
                            delta = 0x7FFDu - src;

                        if (dst - delta < 0)
                            delta = dst;
                        else if (dst - delta > 0x7FFDu)
                            delta = dst - 0x7FFDu;

                        rgxf[0].fl.rgcsh[i] = (int16_t)(rgxf[0].fl.rgcsh[i] + (int16_t)delta);
                        rgxf[1].fl.rgcsh[i] = (int16_t)(rgxf[1].fl.rgcsh[i] - (int16_t)delta);
                    }

                    iLook++;
                }
                grbit >>= 1;
            }
        }

        FleetTransferCargoBalance(&rgxf[0].fl, &rgxf[1].fl);

        for (iPass = 0; iPass < 2; iPass++) {
            FLookupFleet(-1, &rgxf[iPass].fl);

            for (i = 0; i < 16; i++) {
                if (rgxf[iPass].fl.rgcsh[i] != 0)
                    break;
            }
            if (i == 16) {
                FDeleteFleet(rgxf[iPass].fl.id, 0, 0);
            }
        }
        break;

    case rtLogFleetSplit:
        LogSplitFleet(*(int16_t *)lpb);
        break;

    case rtLogFleetMerge:
        /* cb==2: merge all at location; cb>2: list of fleet ids */
        if (cb == 2) {
            LogMergeFleet(*(int16_t *)lpb);
        } else {
            int16_t c = (int16_t)((cb - 2) / 2);
            if (c > (int16_t)(sizeof(rgifl) / sizeof(rgifl[0])))
                c = (int16_t)(sizeof(rgifl) / sizeof(rgifl[0]));
            memcpy(rgifl, lpb + 2, (size_t)c * sizeof(rgifl[0]));
            for (i = 0; i < c; i++)
                LogMergeFleet(rgifl[i]);
        }

        break;

    case rtLogShDef: {
        /* Packed: u16 at lpb[0..1] contains (iplr<<4) + (ishdef<<8) + low nibble op */
        uint16_t pack = *(uint16_t *)lpb;
        uint16_t ishdef = (uint16_t)((pack >> 8) & 0x1Fu);
        iLook = (int16_t)((pack >> 4) & 0x0Fu);

        if ((iLook >= game.cPlayer) || (iLook != idPlayer))
            return 0;

        if (ishdef < 0x10) {
            lpshdef = &rglpshdef[iLook][ishdef];
        } else {
            if (ishdef > 0x19)
                return 0;
            lpshdef = &rglpshdefSB[iLook][(int16_t)(ishdef - 0x10)];
        }

        /* types.h: SHDEF "deleted" is bitfield fFree (was wFlags & 0x0200) */
        if ((lpshdef->fFree == 0) && (lpshdef->cExist != 0) && ((pack & 0x000Fu) != 0)) {
            return 0;
        }

        if ((pack & 0x000Fu) == 0) {
            /* delete: only if not already deleted */
            if (lpshdef->fFree == 0) {
                DestroyAllIshdef((int16_t)ishdef, idPlayer);
                lpshdef->fFree = 1;
            }
        } else if ((pack & 0x000Fu) == 1) {
            /* update/create */
            int16_t ok;

            ok = FReadShDef((RTSHDEF *)(lpb + 2), lpshdef, idPlayer);
            if (!ok) {
                return 0;
            }
        }

    } break;

    case rtLogPlanetProdQ: {
        /* lpb[0..1]=planet id, lpb[2..]=PROD entries */
        int16_t idPlanet = *(int16_t *)lpb;
        if (!FLookupPlanet(idPlanet, lppl))
            return 0;

        if (lppl->iPlayer != idPlayer)
            return 0;

        iLook = (int16_t)((cb - 2) / (int16_t)sizeof(PROD));
        if (iLook <= 0) {
            if (lppl->lpplprod != NULL) {
                FreeLp(lppl->lpplprod, htOrd);
                lppl->lpplprod = NULL;
            }
        } else {
            if (lppl->lpplprod == NULL) {
                lppl->lpplprod = (PLPROD *)LpplAlloc((uint16_t)sizeof(PROD), (uint16_t)(iLook + 2), htOrd);
            } else if (lppl->lpplprod->iprodMax < (uint8_t)iLook) {
                lppl->lpplprod = (PLPROD *)LpplReAlloc((PL *)lppl->lpplprod, (uint16_t)(iLook + 2));
            }

            if (lppl->lpplprod != NULL) {
                memmove(lppl->lpplprod->rgprod, lpb + 2, (size_t)iLook * sizeof(lppl->lpplprod->rgprod[0]));
                lppl->lpplprod->iprodMac = (uint8_t)iLook;
            }
        }

    } break;

    case rtBtlPlan:
        UnpackBattlePlan(lpb, NULL, 0);
        break;

    case rtLogResearch: {
        int8_t  pct = (int8_t)lpb[0];
        uint8_t packed = lpb[1];

        if ((pct < 0) || (pct >= (int8_t)'e'))
            return 0;
        if (((packed & 0x0F) >= 6) || (((packed >> 4) & 0x0F) >= 8))
            return 0;

        rgplr[idPlayer].pctResearch = (uint8_t)pct;
        rgplr[idPlayer].iTechCur = packed;
    } break;

    case rtLogPlanetRouting: {
        int16_t idPlanet = *(int16_t *)lpb;
        if (!FLookupPlanet(idPlanet, lppl))
            return 0;

        if (lppl->iPlayer != idPlayer)
            return 0;

        {
            uint16_t pack = *(uint16_t *)(lpb + 2);

            lppl->idFling = (uint16_t)(pack & 0x03FFu);
            lppl->iWarpFling = (uint16_t)((pack >> 10) & 0x000Fu);

            lppl->idRoute = (uint16_t)(pack & 0x03FFu);
        }

    } break;

    case rtChgPassword:
        if (gd.fHostMode) {
            uint16_t lo = *(const uint16_t *)(lpb + 0);
            uint16_t hi = *(const uint16_t *)(lpb + 2);
            rgplr[idPlayer].lSalt = (int32_t)((uint32_t)lo | ((uint32_t)hi << 16));
        }
        break;

    case rtLogRelations:
        memcpy(rgplr[idPlayer].rgmdRelation, lpb, (size_t)game.cPlayer);
        break;

    case rtLogFleetPlan:
        lpfl = LpflFromId(*(int16_t *)lpb);
        if (lpfl == NULL)
            return 0;
        lpfl->iplan = (uint8_t)(*(const uint16_t *)(lpb + 2));
        break;

    case rtLogThingByteParam:
        lpth = LpthFromId(*(int16_t *)lpb);
        if ((lpth == NULL) || (((uint16_t)lpth->idFull >> 13) != 0))
            return 0;
        lpth->rgb[7] = (uint8_t)(*(const uint16_t *)(lpb + 2));
        break;

    case rtLogFleetName: {
        FLEET *pf = LpflFromId(*(int16_t *)lpb);
        if (pf == NULL)
            return 0;

        /* decompile: cOut=0x20, but tie to buffer */
        cOut = (int16_t)(sizeof(szT) - 1);

        if (pf->lpszName != NULL) {
            FreeLp(pf->lpszName, htString);
            pf->lpszName = NULL;
        }

        {
            uint8_t cchComp = lpb[4];

            if ((cchComp == 0) || (FDecompressUserString((char *)(lpb + 5), (uint32_t)cchComp, szT, &cOut) == 0)) {
                if (lpb[5] == 0) {
                    pf->lpszName = NULL;
                } else {
                    size_t cch = strlen((char *)(lpb + 5));
                    pf->lpszName = (char *)LpAlloc((uint16_t)(cch + 1), htString);
                    if (pf->lpszName != NULL) {
                        strcpy(pf->lpszName, (char *)(lpb + 5));
                    }
                }
            } else {
                size_t cch = strlen(szT);
                pf->lpszName = (char *)LpAlloc((uint16_t)(cch + 1), htString);
                if (pf->lpszName != NULL) {
                    strcpy(pf->lpszName, szT);
                }
            }
        }
    } break;

    case rtLogPlayerZpq1:
        if (gd.fHostMode) {
            if ((size_t)cb > sizeof(rgplr[idPlayer].zpq1))
                return 0;
            memcpy(&rgplr[idPlayer].zpq1, lpb, (size_t)cb);
        }
        break;

    default:
        break;
    }

    return 1;
}

int16_t FWriteHistFile(int16_t iPlayer) {
    PLANET   *lppl;
    int16_t   i;
    MemJump  *penvMemSav;
    MemJump   env;
    uint16_t  cTurnBase;
    int16_t   j;
    RTHISTHDR rthh;
    uint8_t  *lpb;
    int16_t   sVar;

    sVar = FCreateFile(dtHist, iPlayer, NULL);
    penvMemSav = penvMem;

    if (sVar == 0) {
        Error(idsUnableCreateHistoryFile);
        return 0;
    }

    penvMem = &env;
    if (setjmp(env.env) != 0) {
        penvMem = penvMemSav;
        StreamClose();
        return 0;
    }

    rthh.cPlanet = cPlanet;
    rthh.cPlanetExtra = (int16_t)(rgplr[iPlayer].wRaw_0004 & 0x0FFF);
    WriteRt(rtHistHdr, 4, &rthh);

    /* Write planets */
    lppl = lpPlanets;
    for (i = 0; i < cPlanet; i++) {
        RecordType rt;
        if ((lppl->det) < 3) {
            rt = (RecordType)(rtPlanetB | rtLogCargoXfer8);
        } else {
            rt = rtPlanetB;
        }
        WritePlanet(lppl, rt, 1);
        lppl++;
    }

    /* Write message filter */
    WriteRt(rtMsgFilt, cbbitfMsg, bitfMsgFiltered);

    /* Write other players' info */
    for (i = 0; i < game.cPlayer; i++) {
        if (i != iPlayer && (rgplr[i].det & 7) != 0) {
            WriteRtPlr(&rgplr[i], NULL);
        }
    }

    /* Write other players' ship defs */
    for (i = 0; i < game.cPlayer; i++) {
        if (rgplr[i].fInclude && i != iPlayer) {
            for (j = 0; j < 16; j++) {
                if (rglpshdef[i][j].fFree == 0) {
                    WriteRtShDef(&rglpshdef[i][j], NULL);
                }
            }
        }
    }

    /* Write other players' starbase defs */
    for (i = 0; i < game.cPlayer; i++) {
        if (rgplr[i].fInclude && i != iPlayer) {
            for (j = 0; j < 10; j++) {
                if (rglpshdefSB[i][j].fFree == 0) {
                    WriteRtShDef(&rglpshdefSB[i][j], NULL);
                }
            }
        }
    }

    /* Write scores */
    if (game.turn < 0x65) {
        cTurnBase = 0;
    } else {
        cTurnBase = (uint16_t)(game.turn - 100);
    }

    for (i = 0; i < game.cPlayer; i++) {
        if (rgsxPlr[i] != NULL) {
            for (j = 0; j < rgcsxPlr[i]; j++) {
                if (cTurnBase <= rgsxPlr[i][j].turn) {
                    WriteRt(rtScore, sizeof(SCOREX), &rgsxPlr[i][j]);
                }
            }
        }
    }

    /* Write AI data */
    if (vlpbAiData != NULL && *(uint16_t *)vlpbAiData > 2) {
        int16_t cbRemain = *(int16_t *)vlpbAiData;
        lpb = vlpbAiData;

        while (cbRemain > 0x3FF) {
            WriteRt(rtAiData, 0x3FF, lpb);
            lpb += 0x3FF;
            cbRemain -= 0x3FF;
        }
        WriteRt(rtAiData, cbRemain, lpb);
    }

    WriteRt(rtEOF, 0, NULL);
    StreamClose();
    penvMem = penvMemSav;
    return 1;
}

void CancelMemRt(RecordType rt) {
    (void)rt;
    imemLogCur = (int16_t)(imemLogCur - (int16_t)((uint16_t)hdrPrev.cb + 2u));
    hdrPrev.rt = 0;
}

void LogMakeValidXferf(LOGXFERF *plxf1, LOGXFERF *plxf2) {
    int16_t  iOff;
    int16_t  i;
    char     rgbuf[41];
    uint16_t grbit;
    int16_t  grFlag;
    int16_t  cb;

    grbit = 0;
    grFlag = 1;
    for (i = 0; i < 16; i++) {
        if (plxf1->rgdItem[i] != 0)
            grbit |= (uint16_t)grFlag;
        grFlag <<= 1;
    }

    if (grbit == 0)
        return;

    rgbuf[4] = (char)((plxf1->grobj & 0x0F) | ((plxf2->grobj & 0x0F) << 4));
    *(int16_t *)rgbuf = plxf1->id;
    *(int16_t *)(rgbuf + 2) = plxf2->id;
    rgbuf[5] = (char)(grbit & 0xFF);
    rgbuf[6] = (char)(grbit >> 8);
    cb = 7;
    iOff = 0;

    for (i = 0; i < 16; i++) {
        if (plxf1->rgdItem[i] != 0) {
            *(int16_t *)(rgbuf + 7 + iOff * 2) = plxf1->rgdItem[i];
            cb += 2;
            iOff++;
        }
    }

    WriteMemRt(rtLogFleetCargoXfer, cb, rgbuf);
}

int16_t FRunLogFile(void) {
    int16_t fLogOffSaved;
    int16_t iCur;
    int16_t fRet;

    fLogOffSaved = fLogOff;
    iCur = 0;
    fRet = 1;

    if (imemLogCur != 0) {
        fLogOff = 1;

        for (; iCur < imemLogCur;) {
            HDR      hdr;
            uint8_t *pb;

            pb = (uint8_t *)lpLog + iCur;

            /* Copy packed header (2 bytes) without alignment assumptions */
            memcpy(&hdr, pb, sizeof(hdr));

            fRet = fRet & FRunLogRecord(hdr.rt, hdr.cb, pb + sizeof(hdr));

            /* Advance: header + payload */
            iCur += hdr.cb + sizeof(hdr);
        }

        /* Clear “fleet link valid” bit (decompile: grBits2 &= ~0x0400) */
        gd.fFleetLinkValid = 0;
    }

    fLogOff = fLogOffSaved;
    return fRet;
}

void LogMakeValidXfer(LOGXFER *plx1, LOGXFER *plx2) {
    int32_t rgQuan[5];
    RTXFER *prt;
    int16_t iOff;
    int16_t rt;
    int16_t i;
    char    rgbuf[28];
    int16_t grbit;
    int16_t grFlag;
    int32_t iBiggest;
    int16_t cb;

    iBiggest = 0;
    grFlag = 1;
    memset(rgQuan, 0, sizeof(rgQuan));

    /* Check if previous log record is a compatible transfer we can merge with */
    RecordType prevRt = (RecordType)(hdrPrev.rt);
    if (prevRt == rtLogCargoXfer8 || prevRt == rtLogCargoXfer16 || prevRt == rtLogCargoXfer32) {
        prt = (RTXFER *)(lpLog + (uint16_t)(imemLogCur - hdrPrev.cb));
    } else {
        prt = NULL;
    }

    if (prt != NULL && (prt->grobj1 == (plx1->grobj & 0x0F)) && (prt->grobj2 == (plx2->grobj & 0x0F)) && prt->id1 == plx1->id && prt->id2 == plx2->id) {

        uint8_t grbitPrev = prt->grbitItems;
        iOff = 0;

        if (prevRt == rtLogCargoXfer8) {
            for (i = 0; i < 5; i++) {
                if ((1 << i) & grbitPrev) {
                    rgQuan[i] = (int32_t)(int8_t)prt->rgcQuan[iOff];
                    iOff++;
                }
            }
        } else if (prevRt == rtLogCargoXfer16) {
            for (i = 0; i < 5; i++) {
                if ((1 << i) & grbitPrev) {
                    rgQuan[i] = (int32_t)*(int16_t *)(&prt->rgcQuan[iOff * 2]);
                    iOff++;
                }
            }
        } else if (prevRt == rtLogCargoXfer32) {
            for (i = 0; i < 5; i++) {
                if ((1 << i) & grbitPrev) {
                    rgQuan[i] = *(int32_t *)(&prt->rgcQuan[iOff * 4]);
                    iOff++;
                }
            }
        }

        CancelMemRt(prevRt);
    }

    /* Accumulate new quantities and find largest absolute value */
    grbit = 0;
    for (i = 0; i < 5; i++) {
        rgQuan[i] += plx1->rgdItem[i];

        if (labs(rgQuan[i]) > iBiggest)
            iBiggest = labs(rgQuan[i]);

        if (rgQuan[i] != 0)
            grbit |= grFlag;

        grFlag <<= 1;
    }

    if (grbit == 0)
        return;

    /* Build the transfer record */
    prt = (RTXFER *)rgbuf;
    rgbuf[4] = (char)((plx1->grobj & 0x0F) | ((plx2->grobj & 0x0F) << 4));
    prt->id1 = (uint16_t)plx1->id;
    prt->id2 = (uint16_t)plx2->id;
    rgbuf[5] = (char)grbit;
    cb = 6;
    iOff = 0;

    if (iBiggest < 0x80) {
        rt = rtLogCargoXfer8;
        for (i = 0; i < 5; i++) {
            if (rgQuan[i] != 0) {
                rgbuf[6 + iOff] = (char)(int16_t)rgQuan[i];
                cb++;
                iOff++;
            }
        }
    } else if (iBiggest < 0x8000) {
        rt = rtLogCargoXfer16;
        for (i = 0; i < 5; i++) {
            if (rgQuan[i] != 0) {
                *(int16_t *)(rgbuf + 6 + iOff * 2) = (int16_t)rgQuan[i];
                cb += 2;
                iOff++;
            }
        }
    } else {
        rt = rtLogCargoXfer32;
        for (i = 0; i < 5; i++) {
            if (rgQuan[i] != 0) {
                *(int32_t *)(rgbuf + 6 + iOff * 4) = rgQuan[i];
                cb += 4;
                iOff++;
            }
        }
    }

    WriteMemRt(rt, cb, rgbuf);
}

void LogChangeFleet(FLEET *pfl, FLEET *pflNew) {
    int16_t   d;
    int16_t   i;
    int16_t   fChg;
    RTWAYPT   rtwp;
    LOGXFER   lxNew;
    RTSHIPINT rtsi;
    int16_t   iordOld;
    int16_t   iordNew;
    int16_t   cbWp;
    HDR       hdr;
    LOGXFERF  lxfNew;

    fChg = 0;
    if (gd.fGeneratingTurn != 0)
        return;

    /* Phase 1: Check ship count changes (LOGXFERF path) */
    lxfNew.id = pfl->id;
    lxfNew.grobj = grobjFleet;
    for (i = 0; i < 16; i++) {
        lxfNew.rgdItem[i] = (int16_t)(pflNew->rgcsh[i] - pfl->rgcsh[i]);
        if (lxfNew.rgdItem[i] != 0)
            fChg = 1;
    }

    if (fChg != 0) {
        if (fValidLxf == 0) {
            memcpy(&lxf, &lxfNew, sizeof(LOGXFERF));
            fValidLxf = 1;
        } else {
            LogMakeValidXferf(&lxf, &lxfNew);
            fValidLxf = 0;
        }
        return;
    }

    /* Phase 2: Check mineral/cargo changes (LOGXFER path) */
    lxNew.id = pfl->id;
    lxNew.grobj = grobjFleet;
    for (i = 0; i < 5; i++) {
        lxNew.rgdItem[i] = pflNew->rgwtMin[i] - pfl->rgwtMin[i];
        if (lxNew.rgdItem[i] != 0)
            fChg = 1;
    }

    if (fChg != 0) {
        if (fValidLx == 0) {
            memcpy(&lx, &lxNew, sizeof(LOGXFER));
            fValidLx = 1;
        } else {
            LogMakeValidXfer(&lx, &lxNew);
            fValidLx = 0;
        }
        return;
    }

    /* Phase 3: Check battle plan change */
    if ((uint8_t)pfl->iplan != pflNew->iplan) {
        rtsi.id = pflNew->id;
        rtsi.i = (int16_t)pflNew->iplan;
        WriteMemRt(rtLogFleetPlan, 4, &rtsi);
    }

    /* Phase 4: Check fRepOrders flag */
    if (pfl->fRepOrders != pflNew->fRepOrders) {
        rtsi.id = pflNew->id;
        rtsi.i = (int16_t)(pflNew->fRepOrders & 1);
        WriteMemRt(rtLogFleetFlagBit9, 4, &rtsi);
    }

    /* Phase 5: Check order changes */
    d = (int16_t)(pflNew->cord - pfl->cord);

    for (iordOld = 0; iordOld < pfl->cord && iordOld < pflNew->cord; iordOld++) {
        if (memcmp(&pfl->lpplord->rgord[iordOld], &pflNew->lpplord->rgord[iordOld], sizeof(ORDER)) != 0)
            break;
    }
    iordNew = iordOld;

    if (iordOld != pfl->cord || d != 0) {
        if (d < 0) {
            /* Orders deleted */
            rtsi.id = pflNew->id;
            rtsi.i = iordOld;
            if (d == -2) {
                rtsi.i = (int16_t)(iordOld | 0x8000);
            }
            WriteMemRt(rtLogFleetOrderDelete, 4, &rtsi);
        } else if (d == 0) {
            /* Order updated */
            cbWp = (int16_t)sizeof(RTWAYPT);

            if (FGetPrevLogRt(&hdr, (uint8_t *)rgbCur) && hdr.rt == rtLogFleetOrderUpdate && *(int16_t *)rgbCur == pflNew->id &&
                *(int16_t *)(rgbCur + 2) == iordNew) {
                imemLogCur = imemLogPrev;
            }

            rtwp.id = pflNew->id;
            rtwp.iWaypt = iordNew;
            memcpy(&rtwp.order, &pflNew->lpplord->rgord[iordNew], sizeof(ORDER));

            while (cbWp > 0 && ((char *)&rtwp)[cbWp - 1] == '\0')
                cbWp--;

            WriteMemRt(rtLogFleetOrderUpdate, cbWp, &rtwp);
        } else {
            /* Orders inserted */
            cbWp = (int16_t)sizeof(RTWAYPT);

            rtwp.id = pflNew->id;
            rtwp.iWaypt = iordOld;
            memcpy(&rtwp.order, &pflNew->lpplord->rgord[iordOld], sizeof(ORDER));

            while (cbWp > 0 && ((char *)&rtwp)[cbWp - 1] == '\0')
                cbWp--;

            WriteMemRt(rtLogFleetOrderInsert, cbWp, &rtwp);
        }
    }
}

void LogChangeName(GrobjClass grobj, int16_t id, char *szName) {
    FLEET    *lpfl;
    int16_t   cOut;
    RTCHGNAME rtchgname;

    lpfl = LpflFromId(id);
    if (lpfl == NULL)
        return;

    if (lpfl->lpszName != NULL) {
        FreeLp(lpfl->lpszName, htString);
    }

    if (szName == NULL || *szName == '\0') {
        rtchgname.rgb[0] = 0;
        rtchgname.rgb[1] = 0;
        cOut = 1;
        lpfl->lpszName = NULL;
    } else {
        cOut = (int16_t)strlen(szName);
        lpfl->lpszName = (char *)LpAlloc((uint16_t)(strlen(szName) + 1), htString);
        strcpy(lpfl->lpszName, szName);

        if (FCompressUserString(szName, (char *)(rtchgname.rgb + 1), &cOut) == 0) {
            rtchgname.rgb[0] = 0;
            strcpy((char *)(rtchgname.rgb + 1), szName);
            cOut = cOut + 1;
        } else {
            rtchgname.rgb[0] = (uint8_t)cOut;
        }
    }

    rtchgname.grobj = grobj;
    rtchgname.id = id;
    WriteMemRt(rtLogFleetName, (int16_t)(cOut + 5), &rtchgname);

    if (gd.fTutorial) {
        AdvanceTutor();
    }
}

void LogChangeShDef(SHDEF *lpshdefNew) {
    uint8_t  rgb[149];
    uint8_t *pb;
    uint16_t pack;

    if (gd.fGeneratingTurn == 0) {
        pack = ((uint16_t)lpshdefNew->ishdef << 8) | ((uint16_t)(idPlayer & 0x0F) << 4);

        if (lpshdefNew->fFree == 0) {
            /* New/update: set low nibble to 1 */
            *(uint16_t *)rgb = pack | 1;
            lpshdefNew->det = 7;
            pb = rgb + 2;
            WriteRtShDef(lpshdefNew, &pb);
            WriteMemRt(rtLogShDef, (int16_t)(pb - rgb), rgb);
        } else {
            /* Delete: low nibble = 0 */
            *(uint16_t *)rgb = pack;
            WriteMemRt(rtLogShDef, 2, rgb);
        }

        if (gd.fTutorial && idPlayer == 0) {
            tutor.fChange = 1;
            AdvanceTutor();
        }
    }
}
