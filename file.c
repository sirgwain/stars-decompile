
#include <errno.h>
#include <stdio.h>

#include "debuglog.h"
#include "globals.h"
#include "port.h"
#include "strings.h"
#include "types.h"

#include "file.h"
#include "log.h"
#include "mdi.h"
#include "memory.h"
#include "msg.h"
#include "parts.h"
#include "planet.h"
#include "platform.h"
#include "produce.h"
#include "race.h"
#include "save.h"
#include "util.h"
#include "utilgen.h"
#include "vcr.h"

static inline uint32_t read_u32_unaligned(const void *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline int16_t i16_max(int16_t a, int16_t b) { return (a > b) ? a : b; }
static inline int16_t i16_min(int16_t a, int16_t b) { return (a < b) ? a : b; }

/* functions */
void FileError(StringId ids) {
    idsFileError = ids;

    if (!fFileErrSilent && !gd.fGeneratingTurn) {
        Error(ids);
    }
}

void StreamOpen(const char *szFile, int16_t mdOpen) {
    uint32_t deadline = 0;

    bool fNoErr = (mdOpen & mdNoOpenErr) != 0;
    mdOpen = (int16_t)(mdOpen & (int16_t)~mdNoOpenErr);

    Assert(hf.fp == NULL); /* faithful to Assert(hf == HFILE_ERROR) */

    for (;;) {
        if (Stars_OpenFile(&hf, szFile, mdOpen) == 0)
            return;

        if (!gd.fRetryOpens)
            break;
        if (hf.last_errno == ENOENT)
            break;

        uint32_t now = PlatformTickMs();
        if (deadline == 0)
            deadline = now + 4000u;
        if (now >= deadline)
            break;

        PlatformSleepMs(500u);
    }

    if (!fNoErr)
        FileError(idsCantOpenFile);

    longjmp(penvMem->env, -1);
}

void UnpackBattlePlan(uint8_t *lpb, BTLPLAN *lpbtlplan, int16_t iplan) {
    char    szTemp[33];
    char    szName[33];
    int16_t cch;
    int16_t cOut;

    /* Copy everything except the trailing 32-byte name field. */
    memmove((uint8_t *)lpbtlplan, lpb, sizeof(BTLPLAN) - 32);

    lpb += (sizeof(BTLPLAN) - 32);

    cch = (int16_t)(*lpb);
    lpb++;

    if (cch == 0) {
        /* Not compressed: NUL-terminated. */
        strcpy(&lpbtlplan->szName[0], (const char *)lpb);
    } else {
        /* Compressed user string. */
        cOut = 32;
        memset(szTemp, 0, sizeof(szTemp));
        memmove(szTemp, lpb, 32);
        FDecompressUserString((uint8_t *)szTemp, cch, szName, &cOut);
        memmove(&lpbtlplan->szName[0], szName, (size_t)cOut);
        lpbtlplan->szName[cOut] = '\0';
    }

    lpbtlplan->iplan = iplan;
}

bool FBadFileError(StringId ids) {

    switch (ids) {
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

/*
 * ReadRt
 *
 * Read the next record from the current Stars! data stream.
 *
 * The function performs the following steps:
 *
 *   1. Reads the record header (HDR) in plaintext.
 *   2. Reads hdrCur.cb bytes of record payload into rgbCur.
 *   3. Applies XOR decoding to the payload when appropriate.
 *
 * Record handling rules:
 *
 *   - rtBOF (begin-of-file):
 *       The payload is NOT XOR-decoded. Instead, it is interpreted as an
 *       RTBOF structure and used to initialize the XOR keystream via
 *       SetFileXorStream(). All subsequent records depend on this state.
 *
 *   - rtEOF (end-of-file):
 *       No XOR decoding is performed.
 *
 *   - All other record types:
 *       The payload is XOR-decoded in place using the current file XOR stream.
 *
 * The record header itself is always unencrypted.
 */
void ReadRtPlr(PLAYER *pplr, uint8_t *pbIn) {
    int16_t iOff;
    PLAYER *pplrRaw;
    int16_t cOut;
    char   *psz;

    pplrRaw = (PLAYER *)pbIn;
    memset(pplr, 0, sizeof(*pplr));

    if (pplrRaw->det == detAll) {
        /* Full player record up to relations, 112 bytes */
        memmove(pplr, pbIn, cbPlayerAll);

        /* pbIn[cbPlayerAll] is the count/size for rgmdRelation */
        memmove(pplr->rgmdRelation, &pbIn[cbPlayerAll + 1], pbIn[cbPlayerAll]);

        iOff = (int16_t)(cbPlayerAll + pbIn[cbPlayerAll] + 1);
    } else {
        /* Partial player record up to before idPlanetHome */
        memmove(pplr, pbIn, cbPlayerSome);
        iOff = (int16_t)cbPlayerSome;
    }

    /* Player singular name */
    if (pbIn[iOff] == 0) {
        /* Not compressed: flag(0), then NUL-terminated string */
        strcpy(pplr->szName, (char *)(pbIn + iOff + 1));
        iOff = (int16_t)(iOff + 2 + (int)strlen(pplr->szName));
    } else {
        /* Compressed: flag is length, bytes follow */
        cOut = 32;
        FDecompressUserString(pbIn + iOff + 1, pbIn[iOff], pplr->szName, &cOut);
        iOff = (int16_t)(iOff + 1 + pbIn[iOff]);
    }

    /* Plural name (szNames) */
    if (((VERS *)(&wVersFile))->verMinor < 55) {
        psz = PszPlayerName(0, isupper((unsigned char)pplr->szName[0]) != 0, true, false, 0, pplr);
        strcpy(pplr->szNames, psz);
    } else {
        if (pbIn[iOff] == 0) {
            strcpy(pplr->szNames, (char *)(pbIn + iOff + 1));
        } else {
            cOut = 32;
            FDecompressUserString(pbIn + iOff + 1, pbIn[iOff], pplr->szNames, &cOut);
        }
    }

    // DBG_LOGD("ReadRtPlr: iPlayer=%d det=%u szName='%s' szNames='%s'", (int)pplr->iPlayer, (unsigned)pplr->det, pplr->szName, pplr->szNames);

    pplr->fLearned = false;
}

void UpdateBattleRecords(void) {
    // UpdateBattleRecords updates save game battle records from older versions
    // to 2.6 versions. We are not implementing this for the port
}

bool FReadFleet(FLEET *lpfl) {
    uint16_t  us;
    uint8_t  *pb;
    uint16_t *pus;
    int16_t   i;
    int16_t   cish = 0;
    bool      fByte;
    int16_t   cord;
    ORDER    *lpord;

    memset(lpfl, 0, sizeof(*lpfl));
    memmove(lpfl, rgbCur, sizeof(FLEETSOME));

    /* Fleet fields frequently reveal stream/XOR/packing issues. */
    // DBG_LOGD("FReadFleet: rt=%d cb=%u FLEETSOME=%zu id=%d iPlayer=%d det=%u idPlanet=%d pt=(%d,%d)", (int)hdrCur.rt, (unsigned)hdrCur.cb, sizeof(FLEETSOME),
    //          (int)lpfl->id, (int)lpfl->iPlayer, (unsigned)lpfl->det, (int)lpfl->idPlanet, (int)lpfl->pt.x, (int)lpfl->pt.y);
    // DBG_HEXDUMP(DBGLOG_TRACE, rgbCur, (size_t)hdrCur.cb, 64, "Fleet record bytes (first 64)");

    /* Load rgcsh, saved as byte or word values depending on fByteCsh. */
    fByte = (((FLEETSOME *)lpfl)->fByteCsh != 0);

    us = Stars_ReadU16Unaligned(rgbCur + sizeof(FLEETSOME));
    pb = rgbCur + sizeof(FLEETSOME) + sizeof(uint16_t);

    if (fByte) {
        for (i = 0; us != 0; i++, us >>= 1) {
            if (us & 1) {
                lpfl->rgcsh[i] = *pb++;
                if (lpfl->rgcsh[i] != 0) {
                    cish++;
                }
            }
        }
    } else {
        pus = (uint16_t *)pb;
        for (i = 0; us != 0; i++, us >>= 1) {
            if (us & 1) {
                lpfl->rgcsh[i] = *pus++;
                if (lpfl->rgcsh[i] != 0) {
                    cish++;
                }
            }
        }
        pb = (uint8_t *)pus;
    }

    if (cish == 0) {
        /* Defensive: fleet with no ships is considered dead. */
        lpfl->fDead = true;
    }

    if (lpfl->det >= detMore) {
        /* Read rgwtMin, packed by size. */
        us = Stars_ReadU16Unaligned(pb);
        pb += sizeof(uint16_t);

        for (i = 0; i < 5; i++, us >>= 2) {
            switch (us & 3) {
            case 1: /* byte */
                lpfl->rgwtMin[i] = *pb++;
                break;
            case 2: /* word */
            {
                uint16_t v = Stars_ReadU16Unaligned(pb);
                lpfl->rgwtMin[i] = v;
                pb += sizeof(uint16_t);
                break;
            }
            case 3: /* long */
            {
                uint32_t v = read_u32_unaligned(pb);
                lpfl->rgwtMin[i] = (int32_t)v;
                pb += sizeof(uint32_t);
                break;
            }
            default:
                /* 0 => leave as 0 */
                break;
            }
        }
    }

    if (lpfl->det < detAll) {
        lpfl->dirLong = (int32_t)read_u32_unaligned(pb);
        pb += 4;
        lpfl->wtFleet = (int32_t)read_u32_unaligned(pb);
        pb += 4;

        ReadRt();
        return true;
    }

    if (hdrCur.rt != rtFleetA) {
        Error(idsCantOpenFile);
        return false;
    }

    /* rgdv saved as small as possible. */
    us = Stars_ReadU16Unaligned(pb);
    pb += sizeof(uint16_t);

    pus = (uint16_t *)pb;
    for (i = 0; us != 0; i++, us >>= 1) {
        if (us & 1) {
            lpfl->rgdv[i].dp = *pus++;
            if (lpfl->rgdv[i].pctDp >= 500) {
                /* Dead but too dangerous to kill. */
                lpfl->rgdv[i].pctDp = 499;
            }
        }
    }
    pb = (uint8_t *)pus;

    lpfl->iplan = *pb++;
    lpfl->cord = *pb++;

    lpfl->lpplord = (PLORD *)LpplAlloc(sizeof(ORDER), (int16_t)(lpfl->cord + 1), htOrd);
    memset(&lpfl->lpplord->rgord[0], 0, sizeof(ORDER) * (size_t)(lpfl->cord + 1));

    for (cord = lpfl->cord, lpord = &lpfl->lpplord->rgord[0]; cord != 0; lpord++, cord--) {
        memset(rgbCur, 0, sizeof(ORDER));
        ReadRt();
        if (hdrCur.rt != rtOrderA && hdrCur.rt != rtOrderB) {
            Error(idsCantOpenFile);
            return false;
        }
        *lpord = *((ORDER *)rgbCur);
        lpord->fNoAutoTrack = false;
    }

    lpfl->lpplord->iordMac = (uint8_t)lpfl->cord;

    /* Verify planet location if a planet id is present. */
    if (lpfl->idPlanet != -1) {
        if (lpfl->idPlanet > game.cPlanMax) {
            lpfl->idPlanet = -1;
        } else if (lpfl->pt.x != rgptPlan[lpfl->idPlanet].x || lpfl->pt.y != rgptPlan[lpfl->idPlanet].y) {
            if (i == 0 && game.turn == 0) {
                lpfl->pt = rgptPlan[lpfl->idPlanet];
            } else {
                Error(idsCantOpenFile);
                return false;
            }
        }
    }

    ReadRt();

    if (hdrCur.rt == rtString) {
        int16_t cch = (int16_t)rgbCur[0];

        if (cch == 0) {
            const char *pszName = (const char *)&rgbCur[1];
            lpfl->lpszName = (char *)LpAlloc((uint16_t)(strlen(pszName) + 1), htString);
            if (lpfl->lpszName != NULL) {
                strcpy(lpfl->lpszName, pszName);
            }
        } else {
            int16_t cOut = 32;
            char    szT[33];

            FDecompressUserString(&rgbCur[1], cch, szT, &cOut);
            lpfl->lpszName = (char *)LpAlloc((uint16_t)(strlen(szT) + 1), htString);
            if (lpfl->lpszName != NULL) {
                strcpy(lpfl->lpszName, szT);
            }
        }
        ReadRt();
    } else {
        lpfl->lpszName = NULL;
    }

    return true;
}

bool FLoadGame(const char *pszFileName, char *pszExt) {
    DtFileType dt;
    int16_t    iPlayer;
    STARPACK   sp;
    PLANET    *lppl;
    PLANET    *lpplMac;
    FLEET     *lpfl;
    THING     *lpth;
    THING     *lpthMac;
    bool       fHaveHistoryData;
    int16_t    i, j;
    int16_t    iplrSav;
    int16_t    x;
    int16_t    grf = 0;
    int16_t    cturn = 0;
    int16_t    cPlanetHist = 0;
    int16_t    cPlanetAlloc = 0;
    int16_t    fSilentSav;
    MemJump    env;
    MemJump   *penvMemSav;

    /* Accept both "HST" and ".HST" styles from callers/CLI. */
    const char *pszExtWork = pszExt;
    if (pszExtWork != NULL && pszExtWork[0] == '.') {
        pszExtWork++;
    }

    DBG_LOGI("FLoadGame: base='%s' ext='%s'", pszFileName ? pszFileName : "(null)", pszExtWork ? pszExtWork : "(null)");

    strncpy(szBase, pszFileName, sizeof(szBase));
    gd.fFleetLinkValid = false;

    penvMemSav = penvMem;
    penvMem = &env;

    if (setjmp(env.env)) {
    LError:
        game.fDirty = false;
        DestroyCurGame();
        StreamClose();

#ifdef _WIN32
        // TODO: refactor away this platform specific popup
        if (!ini.fValidate && !ini.fLogging && hwndTitle == NULL) {
            POINT pt;
            pt.x = GetSystemMetrics(SM_CXSCREEN);
            pt.y = GetSystemMetrics(SM_CYSCREEN);

            hwndTitle = CreateWindow(szTitle, "Stars!", WS_VISIBLE | WS_POPUP, 0, 0, pt.x, pt.y, hwndFrame, NULL, hInst, NULL);

            fFreeingTitle = false;
            ShowWindow(hwndFrame, SW_HIDE);
        }
#endif

        penvMem = penvMemSav;
        return false;
    }

    if (!FOpenFile(dtXY, iPlayerNil, mdRead)) {
        goto LError;
    }

    ReadRt();
    if (hdrCur.rt != rtGame) {
    XYCorrupt:
        Error(idsUniverseCreationFileAppearsInvalid);
        goto LError;
    }

    game = *((GAME *)rgbCur);
    game.fDirty = false;

    dGal = (int16_t)((game.mdSize * 400) + 400);
    dGalInv = (int16_t)(dGal + 2 * dGalOff);

    x = dGalOff;
    for (i = 0; i < game.cPlanMax; i++) {
        RgFromStream(&sp, sizeof(STARPACK));
        x = (int16_t)(x + (int16_t)(uint16_t)sp.dx);
        Assert(x < (int16_t)(dGal + dGalOff));

        rgptPlan[i].x = x;
        rgptPlan[i].y = (int16_t)(uint16_t)sp.y;
        rgidPlan[i] = (int16_t)(uint16_t)sp.id;

        if (x >= (int16_t)(dGal + dGalOff) || rgptPlan[i].y >= (int16_t)(dGal + dGalOff) || rgidPlan[i] > cPlanetAbsMax) {
            goto XYCorrupt;
        }
    }

    ReadRt();
    if (hdrCur.rt != rtEOF) {
        goto XYCorrupt;
    }

    StreamClose();
    DBG_LOGD("FLoadGame: xy dGal: %d dGalInv %d cPlanMax %d", dGal, dGalInv, game.cPlanMax);

    if ((pszExtWork[0] == 'h' || pszExtWork[0] == 'H') && (pszExtWork[1] == 's' || pszExtWork[1] == 'S')) {
        dt = dtHost;
        iPlayer = iPlayerNil;
    } else {
        dt = dtTurn;
        grf = (int16_t)(grf | (bitfMulti | bitfRewind));
        iPlayer = (int16_t)atoi(pszExtWork + 1);
        Assert(iPlayer > 0 && iPlayer <= cPlayerMax);
        iPlayer--;
    }

    /* Reset state in case there isn't a history file. */
    ResetMessages();
    memset(rgplr, 0, sizeof(PLAYER) * (size_t)game.cPlayer);
    ResetHb(htShips);

    idPlayer = iPlayer;

    fSilentSav = fFileErrSilent;
    fFileErrSilent = true;

    if (iPlayer != iPlayerNil && FOpenFile(dtHist, iPlayer, mdRead)) {
        ReadRt();
        if (hdrCur.rt != rtHistHdr) {
            StreamClose();
            Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
            goto LNoHistFile;
        }

        cPlanetHist = (int16_t)((RTHISTHDR *)rgbCur)->cPlanet;
        cPlanetAlloc = (int16_t)(cPlanetHist + ((RTHISTHDR *)rgbCur)->cPlanetExtra);
        if (cPlanetAlloc > 1000) {
            cPlanetAlloc = 1000;
        }

        lpPlanets = (PLANET *)LpAlloc((uint16_t)(sizeof(PLANET) * (size_t)i16_max(1, cPlanetAlloc)), htPlanets);

        ReadRt();
        for (i = 0, lppl = lpPlanets; i < cPlanetHist; i++, lppl++) {
            if (hdrCur.rt == rtPlanetB) {
                if (!FReadPlanet(iPlayer, lppl, true, false)) {
                    StreamClose();
                    Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
                    goto LNoHistFile;
                }

                Assert(i == 0 || lppl->id > lppl[-1].id);

                if (lppl->iPlayer == iPlayer) {
                    lppl->iPlayer = -1;
                    lppl->det = detSome;
                }
                Assert(lppl->det <= detSome);
            } else {
                StreamClose();
                Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
                goto LNoHistFile;
            }

            ReadRt();
        }

        if (hdrCur.rt == rtMsgFilt) {
            if (hdrCur.cb > (uint16_t)cbbitfMsg) {
                StreamClose();
                Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
                goto LNoHistFile;
            }
            memmove(bitfMsgFiltered, rgbCur, hdrCur.cb);
            ReadRt();
        }

        while (hdrCur.rt == rtPlr) {
            i = ((PLAYER *)rgbCur)->iPlayer;
            Assert(i < game.cPlayer && i != iPlayer);

            ReadRtPlr(&rgplr[i], rgbCur);

            rgplr[i].cPlanet = 0;
            rgplr[i].cFleet = 0;

            ReadRt();
        }

        i = 0;
        while (hdrCur.rt == rtShDef) {
            while (i < game.cPlayer && rgplr[i].cShDef == 0) {
                i++;
            }

            Assert(i != iPlayer);
            if (i == game.cPlayer) {
                break;
            }

            if (rglpshdef[i] == NULL) {
                rglpshdef[i] = (SHDEF *)LpAlloc((uint16_t)(sizeof(SHDEF) * ishdefMax), htShips);
                for (j = 0; j < ishdefMax; j++) {
                    rglpshdef[i][j].fFree = true;
                    rglpshdef[i][j].grbitPlr = 0;
                }
            }

            iplrSav = idPlayer;
            if (idPlayer == -1) {
                idPlayer = i;
            } else {
                idPlayer = -1;
            }

            if (!FReadShDef((RTSHDEF *)rgbCur, rglpshdef[i], iplrSav)) {
                StreamClose();
                Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
                goto LNoHistFile;
            }

            idPlayer = iplrSav;
            rgplr[i].cShDef--;
            ReadRt();
        }

        i = 0;
        while (hdrCur.rt == rtShDef) {
            while (i < game.cPlayer && rgplr[i].cshdefSB == 0) {
                i++;
            }

            Assert(i != iPlayer);
            if (i == game.cPlayer) {
                break;
            }

            if (rglpshdefSB[i] == NULL) {
                rglpshdefSB[i] = (SHDEF *)LpAlloc((uint16_t)(sizeof(SHDEF) * ishdefSBMax), htShips);
                for (j = 0; j < ishdefSBMax; j++) {
                    rglpshdefSB[i][j].fFree = true;
                    rglpshdefSB[i][j].grbitPlr = 0;
                }
            }

            iplrSav = idPlayer;
            if (idPlayer == -1) {
                idPlayer = i;
            } else {
                idPlayer = -1;
            }

            if (!FReadShDef((RTSHDEF *)rgbCur, rglpshdefSB[i], iplrSav)) {
                StreamClose();
                Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
                goto LNoHistFile;
            }

            idPlayer = iplrSav;
            rgplr[i].cshdefSB--;
            ReadRt();
        }

        while (hdrCur.rt == rtScore) {
            int16_t iplr = ((SCOREX *)rgbCur)->iPlayer;
            SCOREX  sx = *((SCOREX *)rgbCur);

            if (rgsxPlr[iplr] == NULL) {
                rgsxPlr[iplr] = (SCOREX *)LpAlloc((uint16_t)(sizeof(SCOREX) * 101), htMisc);
                rgcsxPlr[iplr] = 0;
            }

            if (rgsxPlr[iplr] != NULL) {
                int16_t  isx;
                uint16_t turnCur = sx.fHistory ? (uint16_t)sx.turn : (uint16_t)game.turn;

                for (isx = 0; isx < rgcsxPlr[iplr]; isx++) {
                    if (turnCur <= (uint16_t)rgsxPlr[iplr][isx].turn)
                        break;
                }

                if (((isx < rgcsxPlr[iplr]) && (turnCur != (uint16_t)rgsxPlr[iplr][isx].turn)) || isx >= 101) {
                    if (rgcsxPlr[iplr] >= 101) {
                        if (isx > 0) {
                            if (isx > 1) {
                                memmove(rgsxPlr[iplr], &rgsxPlr[iplr][1], sizeof(SCOREX) * (size_t)(isx - 1));
                            }
                            isx--;
                        }
                    } else {
                        memmove(&rgsxPlr[iplr][isx + 1], &rgsxPlr[iplr][isx], sizeof(SCOREX) * (size_t)(rgcsxPlr[iplr] - isx));
                        rgcsxPlr[iplr]++;
                    }
                } else if (isx == rgcsxPlr[iplr]) {
                    rgcsxPlr[iplr]++;
                }

                rgsxPlr[iplr][isx] = sx;
                rgsxPlr[iplr][isx].turn = turnCur;
                rgsxPlr[iplr][isx].fHistory = true;
            }

            ReadRt();
        }

        if (hdrCur.rt == rtAiData) {
            uint8_t *lpb;

            if (rgplr[idPlayer].fAi) {
                if (vlpbAiData == NULL) {
                    vlpbAiData = (uint8_t *)LpAlloc(8096, htMisc);
                    if (vlpbAiData == NULL) {
                        StreamClose();
                        Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
                        goto LNoHistFile;
                    }
                }

                lpb = vlpbAiData;
                while (hdrCur.rt == rtAiData) {
                    memmove(lpb, &rgbCur[0], hdrCur.cb);
                    lpb += hdrCur.cb;
                    ReadRt();
                }
            } else {
                while (hdrCur.rt == rtAiData) {
                    ReadRt();
                }
            }
        }

        if (hdrCur.rt == rtThing) {
            cThing = *((uint16_t *)rgbCur);

            cThingAlloc = (int16_t)(cThing + 10);
            if (cThingAlloc > cThingAbsMax) {
                cThingAlloc = cThingAbsMax;
            }

            lpThings = (THING *)LpAlloc((uint16_t)(sizeof(THING) * (size_t)cThingAlloc), htThings);
            if (lpThings == NULL) {
                StreamClose();
                Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
                goto LNoHistFile;
            }
            memset(lpThings, 0, sizeof(THING) * (size_t)cThingAlloc);

            ReadRt();
            for (i = 0, lpth = lpThings; i < cThing; i++, lpth++) {
                if (hdrCur.rt != rtThing) {
                    StreamClose();
                    Error(idsHistoryFileAppearsCorruptHistoricalDataWill);
                    goto LNoHistFile;
                }

                memmove(lpth, rgbCur, hdrCur.cb);
                ReadRt();
            }
        }

        Assert(hdrCur.rt == rtEOF);
        StreamClose();
    } else {
    LNoHistFile:
        cPlanetHist = 0;
        FreeLp(lpPlanets, htPlanets);
        lpPlanets = NULL;

        cThing = 0;
        FreeLp(lpThings, htThings);
        lpThings = NULL;
    }

    fFileErrSilent = fSilentSav;

    GetFileStatus(dt, iPlayer);
    if (!FOpenFile((DtFileType)(dt | grf), iPlayer, mdRead)) {
        goto LError;
    }

    if (iPlayer == -1) {
        Assert(hdrCur.rt == rtBOF);
        gd.fGameOverMan = ((RTBOF *)rgbCur)->fGameOverMan;
    }

LNextTurn:
    cturn++;
    cFleet = 0;
    cPlanet = 0;

    ReadRt();

    while (hdrCur.rt == rtBtlData || hdrCur.rt == rtContinue) {
        if (hdrCur.rt != rtContinue) {
            if (lpbBattleLog == NULL) {
                lpbBattleLog = (uint8_t *)LpAlloc(cbAllocMac, htBattle);
                lpbBattleCur = lpbBattleLog;
            }

            if ((cbAllocMac - (((uintptr_t)lpbBattleCur) & 0xFFFFu)) < ((BTLDATA *)rgbCur)->cbData) {
                ((BTLDATA *)lpbBattleCur)->id = 0xFFFF;
                lpbBattleCur = (uint8_t *)LpAlloc(cbAllocMac, htBattle);
            }
        }

        memmove(lpbBattleCur, &rgbCur[0], hdrCur.cb);
        lpbBattleCur += hdrCur.cb;
        ReadRt();
    }

    if (lpbBattleCur != NULL) {
        ((BTLDATA *)lpbBattleCur)->id = 0xFFFF;
        if (((VERS *)(&wVersFile))->verMinor < 80) {
            UpdateBattleRecords();
        }
    }

    Assert(hdrCur.rt == rtPlr);

    while (hdrCur.rt == rtPlr) {
        i = ((PLAYER *)rgbCur)->iPlayer;
        Assert(i < game.cPlayer);

        ReadRtPlr(&rgplr[i], rgbCur);

        Assert(rgplr[i].det == detAll || i != iPlayer);

        cPlanet = (int16_t)(cPlanet + rgplr[i].cPlanet);
        rgplr[i].cPlanet = 0;

        cFleet = (int16_t)(cFleet + rgplr[i].cFleet);
        rgplr[i].cFleet = 0;

        DBG_LOGD("Player ID: %d Name: %s Hab: (g: %d-%d (%d), t: %d-%d (%d), r: %d-%d (%d))\n", rgplr[i].iPlayer, rgplr[i].szName, rgplr[i].rgEnvVarMin[0],
                 rgplr[i].rgEnvVarMax[0], rgplr[i].rgEnvVar[0], rgplr[i].rgEnvVarMin[1], rgplr[i].rgEnvVarMax[1], rgplr[i].rgEnvVar[1], rgplr[i].rgEnvVarMin[2],
                 rgplr[i].rgEnvVarMax[2], rgplr[i].rgEnvVar[2]);

        ReadRt();
    }

    if (dt != dtHost) {
        lSaltCur = rgplr[iPlayer].lSalt;
    } else if (hdrCur.rt == rtChgPassword) {
        lSaltCur = *((int32_t *)rgbCur);
        ReadRt();
    } else {
        lSaltCur = 0;
    }

    if (!FCheckPassword()) {
        if (ini.fValidate || ini.fLogging) {
            Error(idsPasswordHaveEnteredIncorrectPleaseTry);
        }
        goto LError;
    }

    ReadPlayerMessages();

    ResetHb(htFleets);
    ResetHb(htOrd);

    FreeLp(rglpfl, htMisc);
    rglpfl = NULL;

    if (lpPlanets == NULL) {
        cPlanetAlloc = i16_max(1, cPlanet);
        lpPlanets = (PLANET *)LpAlloc((uint16_t)(sizeof(PLANET) * (size_t)cPlanetAlloc), htPlanets);
    }

    lppl = lpPlanets;
    j = 0;

    for (i = 0; i < cPlanet; i++) {
        fHaveHistoryData = false;

        if (cPlanetHist) {
            while (j < cPlanetHist && ((RTPLANET *)rgbCur)->id > lppl->id) {
                j++;
                lppl++;
            }

            if (j < cPlanetHist && ((RTPLANET *)rgbCur)->id == lppl->id) {
                fHaveHistoryData = true;
                goto LFoundPlanet;
            }

            if (cPlanetAlloc == cPlanetHist) {
                cPlanetAlloc = (int16_t)(cPlanetAlloc + 8);
                lpPlanets = (PLANET *)LpReAlloc(lpPlanets, (uint32_t)cPlanetAlloc * (uint32_t)sizeof(PLANET), htPlanets);
                lppl = lpPlanets + j;
            }

            if (j < cPlanetHist) {
                memmove((uint8_t *)(lppl + 1), (uint8_t *)lppl, (size_t)(cPlanetHist - j) * sizeof(PLANET));
            }

            cPlanetHist++;
        }

    LFoundPlanet:
        if (!FReadPlanet(iPlayer, lppl, false, fHaveHistoryData)) {
            Error(idsCantOpenFile);
            goto LError;
        }

        if (lppl->iPlayer != -1) {
            rgplr[lppl->iPlayer].cPlanet++;
        }

        ReadRt();

        if (hdrCur.rt == rtProdQ) {
            Assert(lppl->det == detAll);

            if (lppl->lpplprod != NULL && lppl->lpplprod->iprodMax <= (uint16_t)(hdrCur.cb / sizeof(PROD))) {
                FreePl((PL *)lppl->lpplprod);
                lppl->lpplprod = NULL;
            }

            if (lppl->lpplprod == NULL) {
                lppl->lpplprod = (PLPROD *)LpplAlloc(sizeof(PROD), (int16_t)(hdrCur.cb / sizeof(PROD) + 2), htOrd);
            }

            memmove(&lppl->lpplprod->rgprod[0], rgbCur, hdrCur.cb);
            lppl->lpplprod->iprodMac = (uint16_t)(hdrCur.cb / sizeof(PROD));

            ReadRt();
        }

        if (!cPlanetHist) {
            lppl++;
        }
    }

    if (cPlanetHist) {
        cPlanet = cPlanetHist;
    }

    for (i = 0; i < game.cPlayer; i++) {
        if (i == iPlayer) {
            rglpshdef[i] = (SHDEF *)rgshdef;
            goto FreeShdef;
        } else if (rgplr[i].fInclude) {
            if (rglpshdef[i] == NULL) {
                rglpshdef[i] = (SHDEF *)LpAlloc((uint16_t)(sizeof(SHDEF) * ishdefMax), htShips);
            FreeShdef:
                for (j = 0; j < ishdefMax; j++) {
                    rglpshdef[i][j].fFree = true;
                    rglpshdef[i][j].grbitPlr = 0;
                }
            }
        } else {
            continue;
        }

        iplrSav = idPlayer;
        if (idPlayer == -1) {
            idPlayer = i;
        } else if (i != idPlayer) {
            idPlayer = -1;
        }

        for (j = 0; j < rgplr[i].cShDef; j++) {
            if (hdrCur.rt != rtShDef) {
                idPlayer = iplrSav;
                Error(idsCantOpenFile);
                goto LError;
            }

            if (!FReadShDef((RTSHDEF *)rgbCur, rglpshdef[i], iplrSav)) {
                idPlayer = iplrSav;
                Error(idsCantOpenFile);
                goto LError;
            }

            ReadRt();
        }

        idPlayer = iplrSav;
    }

    for (i = 0; i < game.cPlayer; i++) {
        rgplr[i].cShDef = 0;
        if (rglpshdef[i] != NULL) {
            for (j = 0; j < ishdefMax; j++) {
                if (!rglpshdef[i][j].fFree) {
                    if (i != idPlayer && !gd.fGeneratingTurn && rgplr[i].fDead) {
                        rglpshdef[i][j].fFree = true;
                    } else {
                        rgplr[i].cShDef++;
                    }
                }
            }
        }
    }

    /* Load fleets. */
    rglpfl = (FLEET **)LpAlloc((uint16_t)(sizeof(FLEET *) * (size_t)i16_max(1, cFleet)), htMisc);

    for (i = 0; i < cFleet; i++) {
        lpfl = rglpfl[i] = (FLEET *)LpAlloc(sizeof(FLEET), htFleets);
        if (!FReadFleet(lpfl)) {
            goto LError;
        }
        if (lpfl->iPlayer < 0 || lpfl->iPlayer >= game.cPlayer) {
            DBG_LOGE("FLoadGame: bad fleet iPlayer=%d (game.cPlayer=%d) fleet.id=%d", (int)lpfl->iPlayer, (int)game.cPlayer, (int)lpfl->id);
            /* Note: the raw fleet bytes are dumped inside FReadFleet before it advances the stream. */
            Error(idsGameFileAppearsCorruptUnableLoadFile);
            goto LError;
        }
        rgplr[lpfl->iPlayer].cFleet++;
    }

    /* Load starbase shipdefs. */
    for (i = 0; i < game.cPlayer; i++) {
        Assert(rgplr[i].fInclude || i != iPlayer);

        if (rgplr[i].fInclude) {
            if (rglpshdefSB[i] == NULL) {
                rglpshdefSB[i] = (SHDEF *)LpAlloc((uint16_t)(sizeof(SHDEF) * ishdefSBMax), htShips);
                for (j = 0; j < ishdefSBMax; j++) {
                    rglpshdefSB[i][j].fFree = true;
                    rglpshdefSB[i][j].grbitPlr = 0;
                }
            }
        } else {
            continue;
        }

        iplrSav = idPlayer;
        if (idPlayer == -1) {
            idPlayer = i;
        } else if (i != idPlayer) {
            idPlayer = -1;
        }

        for (j = 0; j < (int16_t)(uint16_t)rgplr[i].cshdefSB; j++) {
            if (hdrCur.rt != rtShDef) {
                idPlayer = iplrSav;
                Error(idsCantOpenFile);
                goto LError;
            }

            if (!FReadShDef((RTSHDEF *)rgbCur, rglpshdefSB[i], iplrSav)) {
                idPlayer = iplrSav;
                Error(idsCantOpenFile);
                goto LError;
            }

            ReadRt();
        }

        idPlayer = iplrSav;
    }

    for (i = 0; i < game.cPlayer; i++) {
        rgplr[i].cshdefSB = 0;
        if (rglpshdefSB[i] != NULL) {
            for (j = 0; j < ishdefSBMax; j++) {
                if (!rglpshdefSB[i][j].fFree) {
                    if (i != idPlayer && !gd.fGeneratingTurn && rgplr[i].fDead) {
                        rglpshdefSB[i][j].fFree = true;
                    } else {
                        rgplr[i].cshdefSB++;
                    }
                }
            }
        }
    }

    if (vlprgScoreX == NULL) {
        vlprgScoreX = (SCOREX *)LpAlloc((uint16_t)(sizeof(SCOREX) * (size_t)game.cPlayer), htMisc);
        memset(vlprgScoreX, 0, sizeof(SCOREX) * (size_t)game.cPlayer);
    }

    while (hdrCur.rt == rtScore) {
        int16_t iplr = ((SCOREX *)rgbCur)->iPlayer;

        vlprgScoreX[iplr] = *((SCOREX *)rgbCur);

        if (rgsxPlr[iplr] == NULL) {
            rgsxPlr[iplr] = (SCOREX *)LpAlloc((uint16_t)(sizeof(SCOREX) * 101), htMisc);
            rgcsxPlr[iplr] = 0;
        }

        if (rgsxPlr[iplr] != NULL) {
            int16_t  isx;
            uint16_t turnCur = vlprgScoreX[iplr].fHistory ? (uint16_t)vlprgScoreX[iplr].turn : (uint16_t)game.turn;

            for (isx = 0; isx < rgcsxPlr[iplr]; isx++) {
                if (turnCur <= (uint16_t)rgsxPlr[iplr][isx].turn)
                    break;
            }

            if (((isx < rgcsxPlr[iplr]) && (turnCur != (uint16_t)rgsxPlr[iplr][isx].turn)) || isx >= 101) {
                if (rgcsxPlr[iplr] >= 101) {
                    if (isx > 0) {
                        if (isx > 1) {
                            memmove(rgsxPlr[iplr], &rgsxPlr[iplr][1], sizeof(SCOREX) * (size_t)(isx - 1));
                        }
                        isx--;
                    }
                } else {
                    memmove(&rgsxPlr[iplr][isx + 1], &rgsxPlr[iplr][isx], sizeof(SCOREX) * (size_t)(rgcsxPlr[iplr] - isx));
                    rgcsxPlr[iplr]++;
                }
            } else if (isx == rgcsxPlr[iplr]) {
                rgcsxPlr[iplr]++;
            }

            rgsxPlr[iplr][isx] = vlprgScoreX[iplr];
            rgsxPlr[iplr][isx].turn = turnCur;
            rgsxPlr[iplr][isx].fHistory = true;
        }

        ReadRt();
    }

    /* Load things */
    if (lpThings != NULL) {
        FreeLp(lpThings, htThings);
        lpThings = NULL;
        cThing = 0;
    }

    if (hdrCur.rt == rtThing) {
        bool    fHist = (cThing > 0);
        int16_t cThingFile = *((uint16_t *)rgbCur);

        cThingAlloc = i16_max(10, cThingFile);

        if (lpThings == NULL) {
            lpThings = (THING *)LpAlloc((uint16_t)(sizeof(THING) * (size_t)cThingAlloc), htThings);
            if (lpThings == NULL) {
                goto LError;
            }
            memset(lpThings, 0, sizeof(THING) * (size_t)cThingAlloc);
        }

        ReadRt();

        lpth = lpThings;
        j = 0;

        for (i = 0; i < cThingFile; i++) {
            fHaveHistoryData = false;

            if (fHist) {
                while (j < cThing && ((THING *)rgbCur)->idFull > lpth->idFull) {
                    j++;
                    lpth++;
                }

                if (j < cThing && ((THING *)rgbCur)->idFull == lpth->idFull) {
                    fHaveHistoryData = true;
                    goto LFoundThing;
                }

                if (cThingAlloc == cThing) {
                    cThingAlloc = (int16_t)(cThingAlloc + 8);
                    lpThings = (THING *)LpReAlloc(lpThings, (uint32_t)cThingAlloc * (uint32_t)sizeof(THING), htThings);
                    lpth = lpThings + j;
                }

                if (j < cThing) {
                    memmove((uint8_t *)(lpth + 1), (uint8_t *)lpth, (size_t)(cThing - j) * sizeof(THING));
                    memset(lpth, 0, sizeof(THING));
                }
            }

            cThing++;

        LFoundThing:
            memmove(lpth, rgbCur, hdrCur.cb);
            lpth->turn = game.turn;
            lpth++;
            j++;
            ReadRt();
        }
    } else {
        cThing = 0;
        cThingAlloc = 10;
        lpThings = (THING *)LpAlloc((uint16_t)(sizeof(THING) * (size_t)cThingAlloc), htThings);
    }

    if (hdrCur.rt == rtSel) {
        ReadRt();
    }

    iplrSav = idPlayer;
    while (hdrCur.rt == rtBtlPlan) {
        int16_t iP = ((BTLPLAN *)rgbCur)->iplr;
        idPlayer = iP;

        if (rglpbtlplan[iP] == NULL) {
            rglpbtlplan[iP] = (BTLPLAN *)LpAlloc((uint16_t)(sizeof(BTLPLAN) * BTLPLANMAX), htShips);
        }

        UnpackBattlePlan(rgbCur, &rglpbtlplan[iP][rgcbtlplan[iP]], rgcbtlplan[iP]);
        rgcbtlplan[iP]++;
        ReadRt();
    }
    idPlayer = iplrSav;

    if (hdrCur.rt != rtEOF) {
        Error(idsCantOpenFile);
        goto LError;
    }

    if (!Stars_AtEOF(&hf)) {
        ReadRt();
        if (hdrCur.rt == rtBOF) {
            game.turn = ((RTBOF *)rgbCur)->turn;
            game.wGen = ((RTBOF *)rgbCur)->wGen;

            for (i = 0; i < game.cPlayer; i++) {
                rgplr[i].cShDef = 0;
                rgplr[i].cFleet = 0;
                rgplr[i].cPlanet = 0;
                rgplr[i].cshdefSB = 0;
                rgcbtlplan[i] = 0;
            }

            FORPLANETS(lppl, lpplMac) {
                if (lppl->iPlayer == iPlayer) {
                    lppl->iPlayer = -1;
                    lppl->det = detSome;

                    if (lppl->lpplprod != NULL) {
                        FreePl((PL *)lppl->lpplprod);
                        lppl->lpplprod = NULL;
                    }
                }
            }

            cPlanetHist = cPlanet;
            goto LNextTurn;
        }

        Error(idsWarningIgnoringUnexpectedDataAfterEof);
    }

    StreamClose();

    if (cturn > 1) {
        Assert(iPlayer != -1);
        if (!rgplr[iPlayer].fAi && !ini.fDumpPlanets && !ini.fDumpFleets && !ini.fDumpMap) {
            snprintf(szWork, sizeof(szWork), PszGetCompressedString(idsNoteDYearsDataRead), cturn);
            MessageSz(szWork);
        }
    }

    if (Stars_strnicmp(pszExt, "hst", 3) == 0) {
        goto DoneNow;
    }

    /* Courtesy messages */
    if (idPlayer != -1 && !rgplr[iPlayer].fAi) {
        /* Notify player about dangerous packets. */
        FORTHINGS(lpth, lpthMac) {
            if (lpth->ith == ithMineralPacket && lpth->thp.iWarp != 0) {
                bool    fTwo;
                int16_t iWarp;

                lppl = LpplFromId(lpth->thp.idPlanet);
                if (!lppl || lppl->iPlayer != iPlayer) {
                    continue;
                }

                iWarp = IWarpMAFromLppl(lppl, &fTwo);
                if ((int16_t)(iWarp + (fTwo ? 1 : 0)) < (int16_t)(lpth->thp.iWarp + 4)) {
                    FSendPlrMsg2XGen(0, idmMassPacketAppearsCollisionCourseWhichCurrently, -6, lpth->idFull, lppl->id);
                }
            }
        }

        if (!game.fTutorial) {
            PROD   *lpprod;
            int16_t iprod;
            int16_t iFirst, iLast;

            FORPLANETS(lppl, lpplMac) {
                if (lppl->iPlayer != iPlayer || !lppl->fStarbase || lppl->lpplprod == NULL) {
                    continue;
                }

                if (rglpshdefSB[lppl->iPlayer][lppl->isb].hul.ihuldef == (ihuldefSBOrbitalFort + ihuldefCount)) {
                    continue;
                }

                bool fWorking = false;

                FORPROD(lppl->lpplprod, lpprod, iprod) {
                    EstimateItemProdSched(lppl, NULL, iprod, &iFirst, &iLast);
                    if (iLast > 1) {
                        fWorking = false;
                        break;
                    }

                    if (iLast == 1 && !FIsAutoBuild(lpprod)) {
                        fWorking = true;
                    }
                }

                if (fWorking) {
                    FSendPlrMsg2XGen(0, idmStarbaseScheduledCompleteRemainingProductionItem, lppl->id, lppl->id, 0);
                }
            }

            i = CBattles();
            if (i > 0) {
                FSendPlrMsg2XGen(1, (MessageId)(idmHaveReceivedOneBattleRecordingYear + (i > 1)), -7, i, 0);
            }
        }
    }

    if (!gd.fDontDoLogFiles) {
        snprintf(szWork, sizeof(szWork), "%s.x%s", pszFileName, pszExt + 1);
        if (!FLoadLogFile(szWork) || !FRunLogFile()) {
            Error(idsPlayerLogFileAppearsCorruptUnableLoad);
            goto LError;
        }
    }

    /* Fix planet and fleet counts. */
    for (i = 0; i < game.cPlayer; i++) {
        rgplr[i].cFleet = 0;
        rgplr[i].cPlanet = 0;
    }

    FORPLANETS(lppl, lpplMac) {
        if (lppl->iPlayer != iPlayerNil) {
            rgplr[lppl->iPlayer].cPlanet++;
        } else {
            lppl->fStarbase = false;
        }
    }

    j = 0;
    FORFLEETS(lpfl, i) {
        Assert(lpfl->iPlayer >= j);
        j = lpfl->iPlayer;
        Assert(j < game.cPlayer);
        rgplr[j].cFleet++;
    }

DoneNow:
    idPlayer = iPlayer;

    if (idPlayer != -1 && !rgplr[idPlayer].fAi) {
        if (vrgszMRU) {
            char  szT[256];
            char  szIniFile[16];
            char  szSection[16];
            char  szEntry[16];
            char *psz;

            strcpy(szT, pszFileName);
            strcat(szT, ".");
            strcat(szT, pszExt);

            if (Stars_stricmp(szT, vrgszMRU) != 0) {
                for (i = 1; i < 8; i++) {
                    if (Stars_stricmp(szT, vrgszMRU + 256 * i) == 0)
                        break;
                }

                while (i >= 1) {
                    strcpy(vrgszMRU + 256 * i, vrgszMRU + 256 * (i - 1));
                    i--;
                }
                strcpy(vrgszMRU, szT);

                CchGetString(idsStarsIni, szIniFile);
                CchGetString(idsFiles, szSection);
                CchGetString(idsFile1, szEntry);

                psz = szEntry + strlen(szEntry) - 1;

                for (i = 0; i < 9; i++) {
                    *psz = (char)('1' + i);
                    strcpy(szT, vrgszMRU + 256 * i);
                    PlatformWritePrivateProfileString(szSection, szEntry, szT, szIniFile);
                }
            }
        }
    }

    penvMem = penvMemSav;
    return true;
}

bool FReadShDef(RTSHDEF *lprt, SHDEF *lpshdef, int16_t iplrLoad) {
    SHDEF    shdef;
    uint8_t *lpb;
    int16_t  cch;
    int16_t  ishdef;
    char     szTemp[40];

    memset(&shdef, 0, sizeof(shdef));

    shdef.hul.ihuldef = lprt->ihuldef;
    shdef.wFlags = lprt->wFlags; /* Includes det. */
    shdef.hul.chs = lprt->chs;
    shdef.hul.ibmp = lprt->ibmp;

    if (shdef.det == detAll) {
        shdef.hul.dp = lprt->dp;
        shdef.turn = lprt->turn;
        shdef.cBuilt = lprt->cBuilt;
        shdef.cExist = lprt->cExist;

        lpb = (uint8_t *)(lprt + 1);
        memmove(&shdef.hul.rghs[0], lpb, (size_t)lprt->chs * sizeof(HS));
        lpb += (size_t)lprt->chs * sizeof(HS);
    } else {
        if (shdef.det != detSome) {
            return false;
        }

        shdef.hul.wtEmpty = lprt->wtEmpty;
        lpb = ((uint8_t *)lprt) + cbrtshdefB;
    }

    /* Convert bmp indices if the base hull changed mid-game. */
    {
        int16_t iFirst = (int16_t)LphuldefFromId(shdef.hul.ihuldef)->hul.ibmp;
        if (shdef.hul.ibmp < iFirst || shdef.hul.ibmp >= (int16_t)(iFirst + 4)) {
            shdef.hul.ibmp = (int16_t)(iFirst | (shdef.hul.ibmp & 3));
        }
    }

    cch = (int16_t)(*lpb);
    lpb++;
    if (cch == 0) {
        strcpy(shdef.hul.szClass, (const char *)lpb);
    } else {
        int16_t cOut = 32;
        if (cch > 32) {
            return false;
        }
        memmove(szTemp, lpb, (size_t)cch);
        FDecompressUserString((uint8_t *)szTemp, cch, shdef.hul.szClass, &cOut);
        shdef.hul.szClass[cOut] = '\0';
    }

    ishdef = shdef.ishdef;

    if (ishdef >= ishdefMax) {
        ishdef = (int16_t)(ishdef - ishdefMax);
    }

    if (shdef.det == detAll || lpshdef[ishdef].fFree || lpshdef[ishdef].det < detAll) {
        lpshdef[ishdef] = shdef;
    } else {
        /* Something already exists here; replace only if it changed. */
        if (shdef.hul.ihuldef != lpshdef[ishdef].hul.ihuldef || shdef.hul.ibmp != lpshdef[ishdef].hul.ibmp) {
            lpshdef[ishdef] = shdef;
        }
    }

    if (idPlayer != -1) {
        UpdateShdefCost(&lpshdef[ishdef]);
    }

    /* Fix up hull weight and validate parts. */
    if (lpshdef[ishdef].det == detAll) {
        HUL     *lphul = &lpshdef[ishdef].hul;
        HUL     *lphulBase = &LphuldefFromId(lphul->ihuldef)->hul;
        uint32_t wt = (uint32_t)lphulBase->wtEmpty;

        for (int16_t c = 0; c < lphul->chs; c++) {
            if (lphul->rghs[c].cItem > 0) {
                PART    part;
                int16_t fOkay;

                part.hs = lphul->rghs[c];
                fOkay = FLookupPart(&part);

                if (idPlayer == -1) {
                    /* Doesn't belong to the player; cut them slack. */
                    fOkay = 0;
                }

                if (!(part.hs.grhst & lphulBase->rghs[c].grhst) || (fOkay > 1 && !shdef.fGift) || (part.hs.cItem > lphulBase->rghs[c].cItem)) {
                    lphul->rghs[c].cItem = 0;
                }

                wt += (uint32_t)part.pcom->cMass * (uint32_t)lphul->rghs[c].cItem;
            }

            /* Make sure we don't eat the only engine. */
            if (c == 0 && lphul->rghs[0].cItem == 0 && lphulBase->rghs[0].grhst == hstEngine) {
                PART part;
                lphul->rghs[0].grhst = hstEngine;
                lphul->rghs[0].iItem = iengineQuickJump5;
                lphul->rghs[0].cItem = lphulBase->rghs[0].cItem;
                part.hs = lphul->rghs[0];
                FLookupPart(&part);
                wt += (uint32_t)part.pcom->cMass * (uint32_t)lphul->rghs[0].cItem;
            }
        }

        Assert((wt & 0xFFFF0000u) == 0);
        lphul->wtEmpty = (uint16_t)wt;
    }

    return true;
}

void ReadRt(void) {
    Assert(hf.fp != NULL || vlpMemStream != NULL);

    RgFromStream(&hdrCur, sizeof(HDR));

    // DBG_LOGT("ReadRt: rt=%d cb=%u", (int)hdrCur.rt, (unsigned)hdrCur.cb);

    if (hdrCur.cb != 0) {
        RgFromStream(rgbCur, hdrCur.cb);
    }

    if (hdrCur.rt == rtBOF) {
        RTBOF bof;
        memcpy(&bof, rgbCur, sizeof(bof));

        // DBG_LOGD("ReadRt: BOF ver=%d.%d lid=%ld salt=%d turn=%d iPlayer=%d crippled=%d", (int)bof.verMajor, (int)bof.verMinor, (long)bof.lidGame,
        //          (int)bof.lSaltTime, (int)bof.turn, (int)bof.iPlayer, (int)bof.fCrippled);

        SetFileXorStream(bof.lidGame, bof.lSaltTime, bof.turn, bof.iPlayer, bof.fCrippled);
    } else if (hdrCur.rt != rtEOF) {
        XorFileBuf(rgbCur, hdrCur.cb);
    }
}

bool FOpenFile(DtFileType dt, int16_t iPlayer, int16_t md) {
    MemJump  env;
    MemJump *penvMemSav;
    bool     fSilentSav = fFileErrSilent;
    bool     fCheckMulti;
    bool     fRewind;
    StringId ids = idsCantOpenFile;
    RTBOF    rtbof;

    gd.fPartialTurn = false;

    fCheckMulti = (dt & bitfMulti) != 0;
    fRewind = (dt & bitfRewind) != 0;
    dt &= grbitDtBase; /* Convert to a valid dt. */
    Assert(!fCheckMulti || dt == dtTurn);

    SetSzWorkFromDt(dt, iPlayer);

    penvMemSav = penvMem;
    penvMem = &env;
    if (setjmp(env.env) != 0) {
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

    if (hdrCur.rt != rtBOF) {
        FileError(idsFileDoesBelongVersionStars);
        goto LBadFile;
    }

    const RTBOF *bof = (const RTBOF *)rgbCur;

    if (bof->verMajor != MAJORVER || bof->verMinor < MINORVERMin || bof->verMinor >= MINORVERMax) {
        bool newer = (bof->verMajor > MAJORVER) || (bof->verMajor == MAJORVER && bof->verMinor > MINORVERMax);

        FileError(newer ? idsFileCreatedNewerVersionStarsMustUpgrade : idsSorryFileCreatedOlderVersionStarsIncompatible);
        goto LBadFile;
    }

    rtbof = *bof;

    if (rtbof.iPlayer != iPlayer) {
        FileError(idsGameFileAppearsCorruptUnableLoadFile);
        goto LBadFile;
    }

    if (game.lid != 0) {
        if (rtbof.lidGame != game.lid) {
            FileError(idsFileGame);
            goto LBadFile;
        } else if (dt != dtHist) {
            /* Hist file will always seem to be one turn out of date! */
            if (fCheckMulti && rtbof.fMulti) {
                /* Multi-part file. Let's check the rest of it. */
                Stars_Seek(&hf, -4, SEEK_END);
                ReadRt();
                if (hdrCur.rt != rtEOF && hdrCur.cb != 2) {
                    goto LBadFile;
                }
                rtbof.turn = *(const uint16_t *)rgbCur;
                game.wGen = rtbof.wGen;
            }

            if (game.turn == 0 && game.turn != rtbof.turn) {
                game.turn = rtbof.turn;
                game.wGen = rtbof.wGen;
            } else if (rtbof.turn != game.turn) {
                FileError(idsFileDate);
                goto LBadFile;
            } else if (dt == dtHost && !gd.fHostMode && rtbof.fInUse) {
                if (MsgYesNo(idsHostFileMarkedUseAnotherInstanceStars) != IDYES) {
                    goto LBadFile;
                }
            } else if (!rtbof.fDone && gd.fGeneratingTurn && !gd.fForceTurn) {
                gd.fPartialTurn = true;
                goto LBadFile;
            } else if (dt == dtLog && !game.fTutorial && rtbof.wGen != game.wGen) {
                FileError(idsFileGame);
                goto LBadFile;
            }
        } else if (rtbof.iPlayer != iPlayer) {
            /* Hist file for wrong person */
            goto LBadFile;
        }
    }

    if (fRewind) {
        Stars_Seek(&hf, 0, SEEK_SET);
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

int16_t AskSaveDialog(void) {

    /* TODO: implement */
    return 0;
}

void StreamClose(void) { Stars_CloseFile(&hf); }

bool FNewTurnAvail(int16_t idPlayer) {
    bool     fNew;
    uint16_t turnOld = game.turn;
    uint16_t wGenOld = game.wGen;
    bool     fErrSav = fFileErrSilent;

    Assert(idPlayer != -1);
    Assert(game.lid != 0);

    fFileErrSilent = true;

    /* Force FOpenFile() to populate game.turn from the BOF turn (it only does this when game.turn==0). */
    game.turn = 0;

    fNew = FOpenFile((uint16_t)(dtTurn | bitfMulti), idPlayer, mdRead);
    if (fNew) {
        StreamClose();
        fNew = (game.turn > turnOld);
    }

    game.turn = turnOld;
    game.wGen = wGenOld;
    fFileErrSilent = fErrSav;

    return fNew;
}

void GetFileStatus(int16_t dt, int16_t iPlayer) {
    SetSzWorkFromDt((uint16_t)dt, (int16_t)iPlayer);

    /* fReadOnly is true if we cannot open/write the file. */
    gd.fReadOnly = (Stars_Access(szWork, STARS_ACCESS_WRITE) != 0);
}

bool FReadPlanet(int16_t iPlayer, PLANET *lppl, bool fHistory, bool fPreInited) {
    const RTPLANET *prtplan = (const RTPLANET *)rgbCur;
    uint8_t        *pb;
    uint8_t         bMask;
    int16_t         i;
    bool            fRouting;
    bool            fFirstYear = false;

    if (!fPreInited) {
        memset(lppl, 0, sizeof(PLANET));
    }

    if (!fHistory && iPlayer != -1) {
        if (!fPreInited) {
            fFirstYear = true;
            lppl->fFirstYear = true;
        } else if (lppl->fFirstYear) {
            if (lppl->turn != (int16_t)game.turn) {
                lppl->fFirstYear = false;
            } else {
                fFirstYear = true;
            }
        }
    } else {
        lppl->fFirstYear = prtplan->fFirstYear != 0;
    }

    lppl->id = prtplan->id;
    lppl->iPlayer = prtplan->iPlayer;

    if (lppl->det < prtplan->det) {
        lppl->det = prtplan->det;
    }

    lppl->fInclude = prtplan->fInclude != 0;
    lppl->fStarbase = prtplan->fStarbase != 0;
    lppl->fHomeworld = prtplan->fHomeworld != 0;
    fRouting = (prtplan->fRouting != 0);

    if (lppl->fStarbase && lppl->iPlayer == -1) {
        lppl->fStarbase = false;
    }

    if (!fHistory) {
        lppl->turn = game.turn;
    }

    pb = rgbCur + sizeof(RTPLANET);

    if (prtplan->det < detSome) {
        /* Minimal record (B) - fall through to finish handling. */
        goto LFinishBRecord;
    }

    bMask = *pb++;
    /* Minerals concentration remainders */
    for (i = 0; i < 3; i++, bMask >>= 2) {
        switch (bMask & 3) {
        case 0:
            lppl->rgpctMinLevel[i] = 0;
            break;
        case 1:
            lppl->rgpctMinLevel[i] = *pb++;
            break;
        default:
            return false;
        }
    }

    /* Concentrations */
    for (i = 0; i < 3; i++) {
        lppl->rgMinConc[i] = *pb++;
    }

    /* Environment vars */
    for (i = 0; i < 3; i++) {
        if (*pb > 100) {
            return false;
        }
        lppl->rgEnvVar[i] = *pb;
        lppl->rgEnvVarOrig[i] = *pb;
        pb++;
    }

    if (prtplan->fIncEVO) {
        for (i = 0; i < 3; i++) {
            if (*pb > 100) {
                return false;
            }
            lppl->rgEnvVarOrig[i] = *pb++;
        }
    }

    /* Population guess if occupied */
    if (prtplan->iPlayer != -1) {
        lppl->uGuesses = Stars_ReadU16Unaligned(pb);
        pb += 2;
    }

    if (lppl->det <= detSome) {
        goto LFinishBRecord;
    }

    /* Surface minerals + population */
    if (prtplan->fIncSurfMin) {
        bMask = *pb++;
        for (i = 0; i < 4; i++, bMask >>= 2) {
            switch (bMask & 3) {
            case 0:
                lppl->rgwtMin[i] = 0;
                break;
            case 1:
                lppl->rgwtMin[i] = *pb++;
                break;
            case 2:
                lppl->rgwtMin[i] = Stars_ReadU16Unaligned(pb);
                pb += 2;
                break;
            case 3:
                lppl->rgwtMin[i] = (int32_t)read_u32_unaligned(pb);
                pb += 4;
                break;
            }
        }
    }

    if (hdrCur.rt == rtPlanetB) {
    LFinishBRecord:
        Assert(iPlayer != -1);

        if (lppl->fStarbase) {
            lppl->isb = *pb++;
        }

        if (fHistory) {
            lppl->turn = (uint16_t)Stars_ReadU16Unaligned(pb);
            pb += 2;
        } else if (fFirstYear) {
            if (lppl->iPlayer != -1) {
                Assert(lppl->iPlayer != iPlayer);
                FSendPlrMsg2XGen(0, idmHaveFoundPlanetOccupiedSomeoneElseCurrently, lppl->id, lppl->id, (int16_t)(lppl->iPlayer | 0x30));
            } else if (lppl->det <= detMinimal) {
                FSendPlrMsg2XGen(0, idmHaveFoundNewPlanetDontKnowIf, lppl->id, lppl->id, 0);
            } else {
                if (RaMajor(iPlayer) == raTerra) {
                    int16_t pctOpt = PctPlanetOptValue(lppl, iPlayer);
                    FSendPlrMsg2XGen(0, idmHaveInfoNewPlanetIfColonizeCan, lppl->id, lppl->id, pctOpt);
                } else {
                    int16_t pct = PctPlanetDesirability(lppl, iPlayer);
                    int16_t idm;

                    if (pct > 0) {
                        pct = (int16_t)(pct * PctTrueMaxGrowth(iPlayer));
                        idm = idmHaveFoundNewHabitablePlanetColonistsWill;
                    } else {
                        int16_t pctOpt = PctPlanetOptValue(lppl, iPlayer);
                        if (pctOpt > 0) {
                            pct = (int16_t)(pctOpt * PctTrueMaxGrowth(iPlayer));
                            idm = idmHaveFoundNewPlanetWhichHaveAbility;
                        } else {
                            pct = (int16_t)(pct * 10);
                            idm = idmHaveFoundNewPlanetWhichUnfortunatelyHabitable;
                        }
                    }

                    FSendPlrMsg2XGen(0, idm, lppl->id, (int16_t)abs((int)pct), lppl->id);
                }
            }
        }

        return true;
    }

    Assert(lppl->det == detAll);

    if (prtplan->fIncImp) {
        memmove(lppl->rgbImp, pb, sizeof(lppl->rgbImp));
        pb += sizeof(lppl->rgbImp);
    } else {
        lppl->fArtifact = (prtplan->fIsArtifact != 0);
        lppl->iScanner = iPlanetPartNone;
        lppl->cDefenses = 0;
    }

    /* People / starbase / routing */
    if (lppl->iPlayer != -1) {
        if (lppl->fStarbase) {
            lppl->lStarbase = (int32_t)read_u32_unaligned(pb);
            lppl->fNoHeal = false;
            pb += 4;
        }

        if (fRouting) {
            lppl->wRouting = Stars_ReadU16Unaligned(pb);
            pb += 2;
        }
    }

    return true;
}

void PromptSaveGame(void) {
    int16_t (*lpProc)(void);
    int16_t fRet;

    /* TODO: implement */
}

bool FCheckFile(DtFileType dt, int16_t iPlayer, MdCheckType md) {
    bool     fReturn = false;
    bool     fOpened;
    bool     fErrSav = fFileErrSilent;
    bool     f = false;
    uint16_t wGenOld = game.wGen;

    /* Any preprocessing of global bits should happen here */
    switch (dt) {
    case dtHost:
        /* Checking the host file: ignore fInUse bit */
        Assert(iPlayer == iPlayerNil);
        f = gd.fHostMode;
        gd.fHostMode = true;
        break;

    default:
        break;
    }

    fFileErrSilent = true;

    /* Open file and read BOF */
    fOpened = FOpenFile(dt, iPlayer, mdRead);

    /* Interpret BOF / contents depending on md */
    switch (md) {
    case mdInUse:
        if (!fOpened) {
            fReturn = true;
        } else {
            const RTBOF *bof = (const RTBOF *)rgbCur;
            fReturn = bof->fInUse != 0;
        }
        break;

    case mdDone:
        if (fOpened) {
            const RTBOF *bof = (const RTBOF *)rgbCur;
            fReturn = bof->fDone != 0;
        } else {
            fReturn = false;
        }
        break;

    case mdMulti:
        if (fOpened) {
            const RTBOF *bof = (const RTBOF *)rgbCur;
            fReturn = bof->fMulti != 0;
        } else {
            fReturn = false;
        }
        break;

    case mdPlayerType:
        if (!fOpened) {
            fReturn = false;
        } else {
            /* Scan forward until we find the PLAYER record for iPlayer */
            for (;;) {
                ReadRt();

                if (hdrCur.rt == rtPlr) {
                    const PLAYER *plr = (const PLAYER *)rgbCur;
                    if (plr->iPlayer == iPlayer) {
                        fReturn = plr->fAi != 0;
                        break;
                    }
                }

                if (hdrCur.rt == rtEOF) {
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

    if (fOpened) {
        StreamClose();
    }

    /* Cleanup globals modified during preprocessing */
    if (dt == dtHost) {
        gd.fHostMode = f;
    }

    fFileErrSilent = fErrSav;
    game.wGen = wGenOld;

    return fReturn;
}

bool FValidSerialLong(uint32_t lSerial) {
    // no serials in the port
    return true;
}

void DestroyCurGame(void) {
    int16_t i;

    if (gd.fSendMsgMode) {
        FFinishPlrMsgEntry(0);
    }

    if (idPlayer != iPlayerNil && game.fDirty) {
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

    for (i = 0; i < cPlayerMax; i++) {
        rgsxPlr[i] = NULL;
    }

    lpbBattleCur = NULL;
    lpbBattleLog = NULL;
    lpbBattleT = NULL;

    gd.fAisDone = false;
    gd.fGotoVCR = false;
    gd.fFleetLinkValid = false;

    ResetHb(htBattle);
    if (rglphb[htBattle] != NULL) {
        /* Match original: ((BTLDATA*)((BYTE*)rglphb[htBattle] + sizeof(HB) + sizeof(WORD)))->id = 0xffff; */
        BTLDATA *pbtl = (BTLDATA *)((uint8_t *)rglphb[htBattle] + sizeof(HB) + sizeof(uint16_t));
        pbtl->id = 0xFFFF;
    }

    ResetHb(htMisc);
    ResetHb(htString);
    ResetHb(htShips);
    ResetHb(htOrd);

    ResetHb(htPlrMsg);

    for (i = 0; i < cPlayerMax; i++) {
        rglpshdef[i] = NULL;
        rglpshdefSB[i] = NULL;
        rglpbtlplan[i] = NULL;
        rgcbtlplan[i] = 0;
    }

    /* Cache the selection in case we're coming right back. */
    if (sel.grobj != grobjNone) {
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

#ifdef _WIN32
    if (hwndBrowser != NULL) {
        DestroyWindow(hwndBrowser);
    }

    if (hwndReportDlg != NULL) {
        DestroyWindow(hwndReportDlg);
    }

    if (hwndPopup != NULL) {
        DestroyWindow(hwndPopup);
        hwndPopup = NULL;
    }

    hwndActive = NULL;
#endif

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

    for (i = 0; i < 3; i++) {
        rgdxOrderDD[i] = 0;
    }
}

/*
 * RgFromStream
 *
 * Read a raw byte range from the current input stream into the caller-supplied
 * buffer. The stream may be either:
 *
 *   - a memory-backed stream (vlpMemStream), or
 *   - an open file stream (hf.fp).
 *
 * Exactly cb bytes are copied into rg. The stream cursor is advanced by cb.
 *
 * This function performs no interpretation, decoding, or decryption of data;
 * it only transfers bytes. Higher-level code (e.g. ReadRt) is responsible for
 * interpreting headers and applying XOR decoding when required.
 *
 * On file read failure, the game reports a corruption error and longjmps out
 * via penvMem, matching the original Stars! error-handling behavior.
 */
void RgFromStream(void *rg, uint16_t cb) {
    if (cb == 0) {
        return;
    }

    Assert(rg != NULL);

    if (vlpMemStream != NULL) {
        /* Read from memory */
        memcpy(rg, vlpMemStream, cb);
        vlpMemStream = (uint8_t *)vlpMemStream + cb;
        return;
    }

    Assert(hf.fp != NULL);

    if (Stars_Read(&hf, rg, (size_t)cb) != (size_t)cb) {
        FileError(idsGameFileAppearsCorruptUnableLoadFile);
        Assert(penvMem != NULL);
        longjmp(penvMem->env, -1);
    }
}

bool FBogusLong(uint32_t lSerial) {
    // no serials in the port
    return false;
}
