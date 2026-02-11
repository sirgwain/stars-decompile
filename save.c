
#include "types.h"

#include "battle.h"
#include "log.h"
#include "memory.h"
#include "msg.h"
#include "parts.h"
#include "planet.h"
#include "port.h"
#include "race.h"
#include "save.h"
#include "ship.h"
#include "ship2.h"
#include "util.h"
#include "utilgen.h"

static inline void put_u16(uint8_t *dst, uint16_t v) { memcpy(dst, &v, sizeof(v)); }

static inline void put_u32(uint8_t *dst, uint32_t v) { memcpy(dst, &v, sizeof(v)); }

/* functions */
void WriteRt(RecordType rt, int16_t cb, void *rg) {
    HDR    hdr;
    RTBOF *lprtbof;

    memmove(rgbCur, rg, cb);

    if (rt == rtBOF) {
        lprtbof = (RTBOF *)rgbCur;
        SetFileXorStream(lprtbof->lidGame, lprtbof->lSaltTime, lprtbof->turn, lprtbof->iPlayer, lprtbof->fCrippled);
    } else if (rt != rtEOF) {
        XorFileBuf(rgbCur, cb);
    }

    hdr.cb = cb;
    hdr.rt = rt;
    RgToStream(&hdr, 2);
    RgToStream(rgbCur, cb);
}

void WriteRtString(char *lpsz) {
    uint8_t rgb[33];
    int16_t cOut;

    if (lpsz != NULL && *lpsz != '\0') {
        cOut = 0x1f;
        if (FCompressUserString(lpsz, (char *)(rgb + 1), &cOut) == 0) {
            strcpy((char *)(rgb + 1), lpsz);
            rgb[0] = 0;
            cOut = strlen(lpsz) + 1;
        } else {
            rgb[0] = (uint8_t)cOut;
        }
        WriteRt(rtString, cOut + 1, rgb);
    }
}

void WriteBOF(int16_t iPlayer, int16_t dt, int16_t fMulti) {
    RTBOF    rtbof;
    int16_t  saltRand;
    uint32_t tickCount;
    uint16_t salt11;
    uint16_t w0c;
    uint16_t w0e;
    int16_t  fGameOver;

    memset(&rtbof, 0, sizeof(rtbof));
    memcpy(rtbof.rgid, "J3J3", 4);

    rtbof.lidGame = game.lid;
    rtbof.wVersion = 0x2a60;
    rtbof.turn = game.turn;

    /* Original stores wGen in the top 3 bits of the +0x000e word. */
    /* Keep it in the struct too (harmless), but we also pack it explicitly below. */
    rtbof.wGen = (uint16_t)(game.wGen & 7);

    saltRand = Random(2000);
    tickCount = GetTickCount();
    salt11 = (uint16_t)(tickCount + (uint16_t)saltRand); /* low 16 like Win16 AX */

    /* Original: (dt == dtHost) && gd.fGameOverMan (dtHost is 2 in the asm/decompile path). */
    fGameOver = (dt == dtHost && gd.fGameOverMan) ? 1 : 0;

    /* Pack +0x000c: iPlayer:5 | lSaltTime:11 (salt is masked to 11 bits, then << 5). */
    w0c = (uint16_t)((iPlayer & 0x1F) | ((salt11 & 0x07FFu) << 5));

    /* Pack +0x000e: dt:8, fDone:1, fInUse:1, fMulti:1, fGameOverMan:1, fCrippled:1, wGen:3 */
    w0e = (uint16_t)(dt & 0x00FFu);
    w0e |= (uint16_t)((gd.fSubmit ? 1u : 0u) << 8);
    w0e |= (uint16_t)((gd.fHostMode ? 1u : 0u) << 9);
    w0e |= (uint16_t)(((fMulti != 0) ? 1u : 0u) << 10);
    w0e |= (uint16_t)(((fGameOver != 0) ? 1u : 0u) << 11);
    w0e |= (uint16_t)((gd.fFileCrippled ? 1u : 0u) << 12);
    w0e |= (uint16_t)((game.wGen & 7u) << 13);

    /* Write the packed words into the struct at the exact offsets (+0x000c, +0x000e). */
    memcpy((uint8_t *)&rtbof + 0x0c, &w0c, sizeof(w0c));
    memcpy((uint8_t *)&rtbof + 0x0e, &w0e, sizeof(w0e));

    WriteRt(rtBOF, (int16_t)sizeof(rtbof), &rtbof);
}

void WriteRtShDef(SHDEF *lpshdef, uint8_t **ppbStore) {
    uint8_t  rgb[147];
    char     szHulName[32];
    uint8_t *pb;
    int16_t  cOut;
    int16_t  fCompressed;
    uint16_t cbName;
    HULDEF  *lphuldef;

    /* Pack common header fields */
    put_u16(&rgb[0], lpshdef->wFlags);
    rgb[2] = (uint8_t)lpshdef->hul.ihuldef;
    rgb[3] = (uint8_t)lpshdef->hul.ibmp;
    rgb[6] = lpshdef->hul.chs;

    if (lpshdef->det == detAll) {
        /* Full ship definition: dp, chs, turn, cBuilt, cExist, then slots */
        put_u16(&rgb[4], (uint16_t)lpshdef->hul.dp);
        put_u16(&rgb[7], (uint16_t)lpshdef->turn);

        put_u16(&rgb[9], (uint16_t)lpshdef->cBuilt);
        put_u16(&rgb[11], (uint16_t)((uint32_t)lpshdef->cBuilt >> 16));

        put_u16(&rgb[13], (uint16_t)lpshdef->cExist);
        put_u16(&rgb[15], (uint16_t)((uint32_t)lpshdef->cExist >> 16));

        pb = rgb + 0x11;
        memmove(pb, lpshdef->hul.rghs, (uint16_t)rgb[6] << 2);
        pb = pb + (uint16_t)rgb[6] * 4;
    } else {
        /* Partial definition: just wtEmpty */
        put_u16(&rgb[4], lpshdef->hul.wtEmpty);
        pb = rgb + 6;
    }

    /* Get hull name - from shdef if full detail, otherwise from base HULDEF */
    if (lpshdef->det == detAll) {
        strcpy(szHulName, lpshdef->hul.szClass);
    } else {
        lphuldef = LphuldefFromId(lpshdef->hul.ihuldef);
        strcpy(szHulName, lphuldef->hul.szClass);
    }

    /* Try to compress the name, fall back to uncompressed if empty or fails */
    cOut = 0x1f;
    if (szHulName[0] == '\0' || (fCompressed = FCompressUserString(szHulName, (char *)(pb + 1), &cOut), fCompressed == 0)) {

        strcpy((char *)(pb + 1), szHulName);
        *pb = 0;
        cbName = (uint16_t)strlen(szHulName);
        pb = pb + cbName + 2;
    } else {
        *pb = (uint8_t)cOut;
        pb = pb + cOut + 1;
    }

    /* Write to stream or copy to store buffer */
    if (ppbStore == NULL) {
        WriteRt(rtShDef, (int16_t)(pb - rgb), rgb);
    } else {
        memmove(*ppbStore, rgb, (size_t)(pb - rgb));
        *ppbStore = *ppbStore + (pb - rgb);
    }
}

void WriteBattles(int16_t iPlayer) {
    int16_t  ctok;
    int16_t  cbRec;
    PLANET  *lppl;
    int16_t  i;
    FLEET   *lpfl;
    int16_t  cbT;
    BTLREC  *lpbtlrec;
    uint8_t *lpbBattle;
    HB      *lphb;
    BTLDATA *lpbtldata;
    int16_t  cb;
    TOK     *lptok;
    SHDEF   *lpshdef;

    /* Early return if no player or no battle data */
    if (iPlayer == iNoPlayer || lpbBattleLog == lpbBattleCur) {
        return;
    }

    lphb = rglphb[htBattle];
    lpbBattle = (uint8_t *)lphb + sizeof(HB);

    while (lphb != NULL) {
        lpbtldata = (BTLDATA *)lpbBattle;

        /* Skip to next valid battle data or next heap block */
        while (lphb->ibTop <= sizeof(HB) || lpbtldata->id == 0xffff) {
            lphb = lphb->lphbNext;
            if (lphb == NULL) {
                return;
            }
            lpbBattle = (uint8_t *)lphb + sizeof(HB);
            lpbtldata = (BTLDATA *)lpbBattle;
        }

        /* Check if this player was involved in the battle */
        if ((lpbtldata->grfPlr & (1 << iPlayer)) == 0) {
            /* Player not involved - skip this battle */
            lpbBattle += lpbtldata->cbData;
        } else {
            /* Mark other players involved as visible */
            for (i = 0; i < game.cPlayer; i++) {
                if (i != iPlayer && rgplr[i].fInclude == 0 && (lpbtldata->grfPlr & (1 << i)) != 0) {
                    rgplr[i].fInclude = 1;
                    rgplr[i].det = 3;
                }
            }

            /* Process each token in the battle */
            for (i = 0; i < lpbtldata->ctok; i++) {
                lptok = &lpbtldata->rgtok[i];

                if (lptok->iplr != iPlayer) {
                    if (lptok->grobj == 1) {
                        /* Starbase token */
                        LpplFromId(lptok->id);
                        lpshdef = &rglpshdefSB[lptok->iplr][lptok->ishdef - 16];

                        if (lpshdef->fInclude == 0) {
                            lpshdef->fInclude = 1;
                            rgplr[lptok->iplr].cshdefSB++;
                        }
                        lpshdef->det = 7;
                    } else {
                        /* Fleet token */
                        lpfl = LpflFromId(lptok->id);

                        if (lpfl->iPlayer != iPlayer && rgplr[lpfl->iPlayer].fInclude == 0) {
                            rgplr[lpfl->iPlayer].fInclude = 1;
                            rgplr[lpfl->iPlayer].det = 3;
                        }

                        lpshdef = &rglpshdef[lpfl->iPlayer][lptok->ishdef];
                        if (lpshdef->fInclude == 0) {
                            lpshdef->fInclude = 1;
                            rgplr[lpfl->iPlayer].cShDef++;
                        }
                        lpshdef->det = 7;

                        if (lpfl->fDead == 0) {
                            if (lpfl->fInclude == 0) {
                                rgplr[lpfl->iPlayer].cFleet++;
                                lpfl->fInclude = 1;
                                lpfl->det = 0;
                            }
                            if (lpfl->det < 3) {
                                lpfl->det = 3;
                            }
                        }
                    }
                }
            }

            /* Mark planet at battle location */
            if (lpbtldata->idPlanet != 0xffff) {
                lppl = LpplFromId(lpbtldata->idPlanet);
                MarkPlanet(lppl, iPlayer, 1);
            }

            /* Write the battle record */
            if (lpbtldata->cbData < 0x400) {
                /* Small record - write in one piece */
                WriteRt(rtBtlData, lpbtldata->cbData, lpbBattle);
                lpbBattle += lpbtldata->cbData;
            } else {
                /* Large record - split into multiple records */
                uint16_t cbTokens = (uint16_t)lpbtldata->ctok * sizeof(TOK) + sizeof(BTLDATA);
                lpbtlrec = (BTLREC *)(lpbBattle + cbTokens);

                if (cbTokens < 0x400) {
                    /* Tokens fit in one record */
                    WriteRt(rtBtlData, cbTokens, lpbBattle);
                    lpbBattle += cbTokens;
                } else {
                    /* Tokens need splitting too */
                    ctok = (lpbtldata->ctok < 0x23) ? lpbtldata->ctok : 0x22;
                    if (lpbtldata->ctok < ctok) {
                        ctok = lpbtldata->ctok;
                    }

                    WriteRt(rtBtlData, ctok * sizeof(TOK) + sizeof(BTLDATA), lpbBattle);
                    lpbBattle += ctok * sizeof(TOK) + sizeof(BTLDATA);
                    ctok = lpbtldata->ctok - ctok;

                    while (ctok > 0) {
                        if (ctok < 0x24) {
                            WriteRt(rtContinue, ctok * sizeof(TOK), lpbBattle);
                            lpbBattle += ctok * sizeof(TOK);
                            ctok = 0;
                        } else {
                            WriteRt(rtContinue, 0x3f7, lpbBattle);
                            lpbBattle += 0x3f7;
                            ctok -= 0x23;
                        }
                    }
                }

                /* Write battle action records */
                cb = lpbtldata->cbData - sizeof(BTLDATA) - lpbtldata->ctok * sizeof(TOK);

                if (cb < 0x400) {
                    WriteRt(rtContinue, cb, lpbtlrec);
                    lpbBattle += cb;
                } else {
                    while (cb != 0) {
                        cbRec = lpbtlrec->ctok * sizeof(KILL) + sizeof(BTLREC);

                        if (cbRec < 0x400) {
                            cbT = 0;
                            do {
                                cbT += cbRec;
                                lpbtlrec = (BTLREC *)((uint8_t *)lpbtlrec + cbRec);
                                cb -= cbRec;
                                if (cb == 0)
                                    break;
                                cbRec = lpbtlrec->ctok * sizeof(KILL) + sizeof(BTLREC);
                            } while (cbT + cbRec < 0x400);

                            WriteRt(rtContinue, cbT, lpbBattle);
                        } else {
                            cb -= cbRec;
                            while (cbRec >= 0x400) {
                                WriteRt(rtContinue, 0x3ff, lpbtlrec);
                                lpbtlrec = (BTLREC *)((uint8_t *)lpbtlrec + 0x3ff);
                                cbRec -= 0x3ff;
                            }
                            if (cbRec != 0) {
                                WriteRt(rtContinue, cbRec, lpbtlrec);
                                lpbtlrec = (BTLREC *)((uint8_t *)lpbtlrec + cbRec);
                            }
                        }
                        lpbBattle = (uint8_t *)lpbtlrec;
                    }
                }
            }
        }
    }
}

void WriteFleet(FLEET *lpfl) {
    uint16_t *pus;
    uint8_t   rgb[134];
    uint16_t  us;
    int16_t   i;
    uint8_t  *pb;
    int16_t   fByte;
    uint16_t  grMask;
    int32_t   wt;
    uint8_t  *pbCargoMask;
    uint16_t  wFlags;
    int16_t  *prgcshSB;

    /* Copy first 12 bytes: id, iPlayer, wFlags, idPlanet, pt */
    memmove(rgb, lpfl, 12);

    /* Scan ship counts to determine encoding and build presence mask */
    fByte = 1;
    grMask = 1;
    us = 0;
    for (i = 0; i < 16; i++) {
        if (lpfl->rgcsh[i] > 0) {
            us |= grMask;
            if (lpfl->rgcsh[i] > 255) {
                fByte = 0;
            }
        }
        grMask <<= 1;
    }

    /* Set/clear bit 11 (fDone) of wFlags based on byte encoding flag */
    memcpy(&wFlags, &rgb[4], sizeof(wFlags));
    wFlags = (wFlags & 0xf7ff) | ((uint16_t)fByte << 11);
    put_u16(&rgb[4], wFlags);

    /* Store ship presence mask at offset 12 */
    rgb[12] = (uint8_t)us;
    rgb[13] = (uint8_t)(us >> 8);

    pb = rgb + 14;
    if (fByte == 0) {
        /* Word encoding for ship counts */
        pus = (uint16_t *)pb;
        for (i = 0; i < 16; i++) {
            if (lpfl->rgcsh[i] > 0) {
                *pus = (uint16_t)lpfl->rgcsh[i];
                pus++;
            }
        }
        pb = (uint8_t *)pus;
    } else {
        /* Byte encoding for ship counts */
        for (i = 0; i < 16; i++) {
            if (lpfl->rgcsh[i] > 0) {
                *pb = (uint8_t)lpfl->rgcsh[i];
                pb++;
            }
        }
    }

    pbCargoMask = pb;
    if (lpfl->det > 3) {
        /* Reserve space for cargo size mask */
        grMask = 3;
        pb += 2;
        us = 0;

        for (i = 0; i < 5; i++) {
            int16_t hiWord = (int16_t)(lpfl->rgwtMin[i] >> 16);
            /* Check if cargo present and should be written */
            /* Skip colonists (i==3) and fuel (i==4) unless starbase (det==7) */
            if (hiWord >= 0 && (hiWord > 0 || lpfl->rgwtMin[i] != 0) && (lpfl->det == 7 || (i != 4 && i != 3))) {
                if (hiWord < 1 && (uint32_t)lpfl->rgwtMin[i] < 0x100) {
                    /* Byte encoding */
                    us |= grMask & 0x155;
                    *pb = (uint8_t)lpfl->rgwtMin[i];
                    pb++;
                } else if (hiWord < 1) {
                    /* Word encoding */
                    us |= grMask & 0x2aa;
                    put_u16(pb, (uint16_t)lpfl->rgwtMin[i]);
                    pb += 2;
                } else {
                    /* Dword encoding */
                    us |= grMask & 0x3ff;
                    put_u32(pb, (uint32_t)lpfl->rgwtMin[i]);
                    pb += 4;
                }
            }
            grMask <<= 2;
        }
        put_u16(pbCargoMask, us);
    }

    if (lpfl->det < 7) {
        /* Non-starbase fleet */
        /* Store dirLong */
        put_u32(pb, (uint32_t)lpfl->dirLong);

        /* Calculate total fleet weight from ship masses */
        wt = 0;
        for (i = 0; i < 16; i++) {
            if (lpfl->rgcsh[i] > 0) {
                wt += (uint32_t)lpfl->rgcsh[i] * (uint32_t)rglpshdef[lpfl->iPlayer][i].hul.wtEmpty;
            }
        }

        /* Add cargo weights (first 4 cargo types: ironium, boranium, germanium, colonists) */
        for (i = 0; i < 4; i++) {
            wt += lpfl->rgwtMin[i];
        }

        put_u32(pb + 4, (uint32_t)wt);
        WriteRt(rtFleetB, (int16_t)(pb + 8 - rgb), rgb);
    } else {
        /* Starbase fleet */
        /* Build mask for secondary ship counts (starbase designs in rgdv area) */
        grMask = 1;
        us = 0;
        prgcshSB = (int16_t *)lpfl->rgdv;
        for (i = 0; i < 16; i++) {
            if (prgcshSB[i] != 0) {
                us |= grMask;
            }
            grMask <<= 1;
        }
        put_u16(pb, us);

        pus = (uint16_t *)(pb + 2);
        for (i = 0; i < 16; i++) {
            if (prgcshSB[i] != 0) {
                *pus = (uint16_t)prgcshSB[i];
                pus++;
            }
        }

        *(uint8_t *)pus = lpfl->iplan;
        *((uint8_t *)pus + 1) = (uint8_t)lpfl->cord;

        WriteRt(rtFleetA, (int16_t)((uint8_t *)pus + 2 - rgb), rgb);
        WriteOrders(lpfl);

        if (lpfl->lpszName != NULL) {
            WriteRtString(lpfl->lpszName);
        }
    }
}

void WriteOrders(FLEET *lpfl) {
    int16_t cord;
    ORDER  *lpord;

    if (lpfl->cord != 0) {
        cord = lpfl->cord;
        lpord = lpfl->lpplord->rgord;

        for (; cord != 0; cord--) {
            if (lpord->grTask == 0) {
                /* Simple waypoint - just pt, id, and flags (8 bytes) */
                WriteRt(rtOrderB, 8, lpord);
            } else {
                /* Full order with task data (18 bytes) */
                WriteRt(rtOrderA, sizeof(ORDER), lpord);
            }
            lpord++;
        }
    }
}

/*
 * RgToStream
 *
 * Write a raw byte range from the caller-supplied buffer to the current
 * output stream.
 *
 * Exactly cb bytes are written from rg. This function performs no encoding
 * or interpretation; higher-level code is responsible for record framing
 * and any XOR/compression logic.
 *
 * On write failure, the game alerts and longjmps out via penvMem, matching
 * the original Stars! error-handling behavior.
 */
void RgToStream(const void *rg, uint16_t cb) {
    if (cb == 0) {
        return;
    }

    Assert(rg != NULL);
    Assert(hf.fp != NULL);

    if (Stars_Write(&hf, rg, (size_t)cb) != (size_t)cb) {
        Error(idsErrorWritingFile);
        Assert(penvMem != NULL);
        longjmp(penvMem->env, -1);
    }
}

/* Build szWork from szBase and dt/iPlayer.
 * Behavior from decompile:
 *  - strip extension from szBase if the last '.' is after the last '\\'
 *  - copy base into szWork
 *  - dt==2: append fixed host suffix and return
 *  - dt in {1,3,4}: append a player-specific extension using 'x','m','h' selector
 *  - otherwise: append fallback suffix
 */
void SetSzWorkFromDt(DtFileType dt, int16_t iPlayer) {
    char  *pchDot;
    char  *pchSlash;
    size_t len;

    /* Strip extension from szBase if '.' is after the last path separator */
    pchDot = strrchr(szBase, '.');
    if (pchDot != NULL && szBase[0] != '.') {
        pchSlash = strrchr(szBase, '\\');
        if (pchSlash == NULL || pchSlash < pchDot) {
            *pchDot = '\0';
        }
    }

    /* Start szWork with base name */
    strncpy(szWork, szBase, sizeof(szBase));
    len = strlen(szWork);

    switch (dt) {
    case dtTurn: /* Log file */
        snprintf(szWork + len, sizeof(szWork) - len, ".m%d", iPlayer + 1);
        break;

    case dtHost:
        strcat(szWork, ".hst");
        break;

    case dtXY: /* Universe file */
        strcat(szWork, ".xy");
        break;

    case dtLog: /* Turn file */
        snprintf(szWork + len, sizeof(szWork) - len, ".x%d", iPlayer + 1);
        break;

    case dtHist: /* History file */
        snprintf(szWork + len, sizeof(szWork) - len, ".h%d", iPlayer + 1);
        break;

    default:
        /* Defensive fallback: behave like universe */
        strncat(szWork, ".xy", sizeof(szWork));
        break;
    }
}

int16_t FMarkFile(DtFileType dt, int16_t iPlayer, int16_t mdMark, int16_t f) {
    RTBOF    rtbof;
    MemJump *penvMemSav;
    MemJump  env;
    int16_t  fChange;
    int16_t  fSuccess;
    int16_t  fSilentSav;
    int32_t  lSeedSav2;
    int32_t  lSeedSav1;
    uint16_t cbRec;
    PLAYER  *pplr;

    fSilentSav = fFileErrSilent;
    fSuccess = 0;
    SetSzWorkFromDt(dt & 0xff, iPlayer);

    penvMemSav = penvMem;
    penvMem = &env;

    if (setjmp(env.env) != 0) {
        fFileErrSilent = fSilentSav;
        StreamClose();
        penvMem = penvMemSav;
        return 0;
    }

    fFileErrSilent = 1;
    StreamOpen((char *)szWork, mdReadWrite);
    fFileErrSilent = fSilentSav;

    ReadRt();

    /* Validate BOF record */
    if (hdrCur.rt != rtBOF) {
        FileError(idsFileDoesBelongVersionStars);
        goto LBadFile;
    }

    /* Check version: wVersion is at rgbCur[8..9] */
    {
        RTBOF *lpBof = (RTBOF *)rgbCur;
        if (lpBof->verMajor < MAJORVER || (lpBof->verMajor == MAJORVER && lpBof->verMinor < MINORVERMin)) {
            FileError(idsSorryFileCreatedOlderVersionStarsIncompatible);
            goto LBadFile;
        }
        if (lpBof->verMajor > MAJORVER || (lpBof->verMajor == MAJORVER && lpBof->verMinor >= MINORVERMax)) {
            FileError(idsFileCreatedNewerVersionStarsMustUpgrade);
            goto LBadFile;
        }
    }

    /* Copy BOF record */
    memcpy(&rtbof, rgbCur, sizeof(RTBOF));

    /* Verify game ID matches */
    if (game.lid == 0) {
        goto LBadFile;
    }
    if (rtbof.lidGame != game.lid) {
        FileError(idsFileGame);
        goto LBadFile;
    }

    fChange = 0;

    if (mdMark == mdInUse) {
        /* Toggle fInUse (bit 9 of +0x0e word) */
        fChange = (rtbof.fInUse != f) ? 1 : 0;
        if (fChange) {
            rtbof.fInUse = f & 1;
        }
    } else if (mdMark == mdDone) {
        /* Toggle fDone (bit 8 of +0x0e word) */
        fChange = (rtbof.fDone != f) ? 1 : 0;
        if (fChange) {
            rtbof.fDone = f & 1;
        }
    } else if (mdMark == mdMulti) {
        /* Toggle fMulti (bit 10 of +0x0e word) */
        fChange = (rtbof.fMulti != f) ? 1 : 0;
        if (fChange) {
            rtbof.fMulti = f & 1;
        }
    } else if (mdMark == mdPlayerType) {
        /* Find the player record */
        do {
            do {
                GetFileSeeds(&lSeedSav1, &lSeedSav2);
                ReadRt();
            } while (hdrCur.rt != rtPlr);
        } while (rgbCur[0] != (uint8_t)iPlayer);

        cbRec = hdrCur.cb;
        pplr = (PLAYER *)rgbCur;

        if (pplr->fAi != f) {
            if (pplr->fAi == 0) {
                /* Turning AI on: set fAi=1, lvlAi=1, idAi=7 */
                pplr->fAi = 1;
                pplr->lvlAi = 1;
                pplr->idAi = 7;
            } else {
                /* Turning AI off: only allowed if idAi==7 */
                if (pplr->idAi != 7) {
                    goto LBadFile;
                }
                pplr->fAi = 0;
            }

            /* Flip salt bytes for re-encryption */
            {
                uint16_t *pSalt0 = (uint16_t *)(rgbCur + offsetof(PLAYER, lSalt));
                uint16_t *pSalt1 = (uint16_t *)(rgbCur + offsetof(PLAYER, lSalt) + 2);
                *pSalt0 = ~(*pSalt0);
                *pSalt1 = ~(*pSalt1);
            }

            /* Seek back to start of this record and rewrite */
            Stars_Seek(&hf, -(int32_t)(cbRec + 2), SEEK_CUR);
            SetFileSeeds(lSeedSav2, lSeedSav2);
            WriteRt(rtPlr, cbRec, rgbCur);

            fChange = (dt == dtTurn) ? 1 : 0;
            rtbof.fDone = 0;
        }
    }

    if (fChange != 0) {
        /* Rewrite BOF at start of file */
        Stars_Seek(&hf, 0, SEEK_SET);
        WriteRt(rtBOF, sizeof(RTBOF), &rtbof);
    }

    fSuccess = 1;

LBadFile:
    if ((dt & bitfMulti) == 0 || fSuccess == 0) {
        StreamClose();
    } else {
        /* Position at end for appending */
        Stars_Seek(&hf, 0, SEEK_END);
    }

    penvMem = penvMemSav;
    return fSuccess;
}

void SetVisPFInit(int16_t iPlr) {
    PLANET  *lpplMac;
    uint16_t detNew;
    PLANET  *lppl;
    int16_t  j;
    FLEET   *lpfl;
    THING   *lpth;
    int16_t  ifl;
    int16_t  i;
    THING   *lpthMac;
    int16_t  raMajor;
    uint16_t grbitPlr;
    int16_t  iSteal;

    raMajor = GetRaceStat(&rgplr[iPlr], rsMajorAdv);
    if (iPlr == -1) {
        grbitPlr = 0;
    } else {
        grbitPlr = 1 << (iPlr & 0x1f);
    }

    /* Clear planet counts */
    for (i = 0; i < game.cPlayer; i++) {
        rgplr[i].cPlanet = 0;
    }

    /* Initialize player visibility and ship design counts */
    for (i = 0; i < game.cPlayer; i++) {
        if (iPlr == -1 || iPlr == i || rgplr[i].fDead) {
            rgplr[i].fInclude = 1;
            rgplr[i].det = detAll;
        } else {
            rgplr[i].fInclude = 0;
        }

        rgplr[i].cFleet = 0;
        rgplr[i].cShDef = 0;
        rgplr[i].cshdefSB = 0;

        /* Ship designs (regular hulls) */
        for (j = 0; j < cShdefMax; j++) {
            SHDEF *lpshdef = &rglpshdef[i][j];
            if ((iPlr == -1 || iPlr == i) && !lpshdef->fFree) {
                lpshdef->fInclude = 1;
                lpshdef->det = detAll;
                lpshdef->cExist = 0;
                rgplr[i].cShDef++;
            } else {
                lpshdef->fInclude = 0;
            }
        }

        /* Ship designs (starbase hulls) */
        for (j = 0; j < ishdefSBMax; j++) {
            SHDEF *lpshdefSB = &rglpshdefSB[i][j];
            if ((iPlr == -1 || iPlr == i) && !lpshdefSB->fFree) {
                lpshdefSB->fInclude = 1;
                lpshdefSB->det = detAll;
                lpshdefSB->cExist = 0;
                rgplr[i].cshdefSB++;
            } else {
                lpshdefSB->fInclude = 0;
            }
        }
    }

    /* Planet visibility */
    FORPLANETS(lppl, lpplMac) {
        if (iPlr == -1 || iPlr == lppl->iPlayer) {
            lppl->fInclude = 1;
            lppl->det = detAll;
            if (iPlr != -1) {
                rgplr[iPlr].cPlanet++;
            }
            if (lppl->fStarbase) {
                SHDEF *lpshdefSB = &rglpshdefSB[lppl->iPlayer][lppl->isb];
                lpshdefSB->cExist++;
            }
        } else {
            lppl->fInclude = 0;
        }
    }

    /* Fleet visibility */
    FORFLEETS(lpfl, ifl) {
        lpfl->fTargeted = 0;
        lpfl->fMark = 0;
        if ((iPlr == -1 || iPlr == lpfl->iPlayer) && !lpfl->fDead) {
            lpfl->fInclude = 1;
            lpfl->det = detAll;
            rgplr[lpfl->iPlayer].cFleet = (rgplr[lpfl->iPlayer].cFleet + 1) & 0xfff;

            /* Accumulate ship counts into ship designs */
            for (j = 0; j < cShdefMax; j++) {
                if (lpfl->rgcsh[j] != 0) {
                    SHDEF *lpshdef = &rglpshdef[lpfl->iPlayer][j];
                    lpshdef->cExist += (uint16_t)lpfl->rgcsh[j];
                }
            }

            /* Check scanner range for fleet at planet */
            if (iPlr != -1 && lpfl->idPlanet != -1) {
                lppl = &lpPlanets[lpfl->idPlanet];
                int16_t scanRange = GetCachedFleetScannerRange(lpfl, NULL, NULL, &iSteal);
                if (scanRange < 0) {
                    detNew = detMinimal;
                } else {
                    detNew = detSome;
                }
                if (iSteal > 1) {
                    detNew = detMore;
                }
                if (lpfl->fHereAllTurn && lppl->iPlayer == iNoPlayer && lpfl->lpplord->rgord[0].grTask == 3 && CMineFromLpfl(lpfl) > 0) {
                    detNew = detMore;
                }
                MarkPlanet(lppl, iPlr, detNew);
            }
        } else {
            lpfl->fInclude = 0;
        }
    }

    /* Thing visibility */
    FORTHINGS(lpth, lpthMac) {
        if (lpth->ith == ithMineralPacket) {
            /* Mineral packets */
            if (iPlr == -1 || raMajor == raMassAccel) {
                lpth->thp.fInclude = 1;
                if (!rgplr[lpth->iplr].fInclude) {
                    rgplr[lpth->iplr].fInclude = 1;
                    rgplr[lpth->iplr].det = detSome;
                }
            } else {
                lpth->thp.fInclude = 0;
            }
        } else if (lpth->ith == ithWormhole) {
            /* Wormholes */
            lpth->thw.fInclude = (iPlr == -1) ? 1 : 0;
        } else if (lpth->ith == ithMysteryTrader) {
            /* Mystery traders */
            lpth->tht.fInclude = 1;
        } else if (lpth->ith == ithMinefield) {
            /* Minefields */
            if ((lpth->thm.grbitPlrNow & grbitPlr) != 0 && !rgplr[lpth->iplr].fInclude) {
                rgplr[lpth->iplr].fInclude = 1;
                rgplr[lpth->iplr].det = detSome;
            }
        }
    }
}

void WriteBattlePlan(BTLPLAN *lpbtlplan, int16_t fLog) {
    uint8_t  rgb[36];
    uint8_t *pb;
    char     szPlanName[32];
    int16_t  cOut;

    /* Copy first 4 bytes: wRaw_0000 and wRaw_0002 */
    memmove(rgb, lpbtlplan, 4);

    if (lpbtlplan->fDelete == 0) {
        /* Copy plan name to local buffer */
        strcpy(szPlanName, lpbtlplan->szName);

        cOut = 0x1f;
        if (szPlanName[0] == '\0' || FCompressUserString(szPlanName, (char *)(rgb + 5), &cOut) == 0) {
            /* Name empty or compression failed - store uncompressed */
            strcpy((char *)(rgb + 5), szPlanName);
            rgb[4] = 0;
            pb = rgb + strlen(szPlanName) + 6;
        } else {
            /* Compressed successfully */
            rgb[4] = (uint8_t)cOut;
            pb = rgb + cOut + 5;
        }
    } else {
        /* Deleted plan - only write first 2 bytes */
        pb = rgb + 2;
    }

    if (fLog == 0) {
        WriteRt(rtBtlPlan, (int16_t)(pb - rgb), rgb);
    } else {
        WriteMemRt(rtBtlPlan, (int16_t)(pb - rgb), rgb);
    }
}

int16_t FWriteDataFile(char *pszFileBase, int16_t iPlayer, int16_t fAppend) {
    int16_t    iMax;
    FLEET     *lpflT;
    int16_t    fNoAutoTrack;
    BTLPLAN   *lpbtlplan;
    int16_t    j;
    MemJump   *penvMemSav;
    int16_t    i;
    ORDER     *lpord;
    THING     *lpth;
    FLEET     *lpfl;
    MemJump    env;
    int16_t    iord;
    SHDEF     *lpshdef;
    int16_t    fRet;
    PLANET    *lpplT;
    SCAN       scan;
    int16_t    mdTarget;
    FLEET     *lpflTarget;
    STARSPOINT pt;
    int32_t    dy;
    int16_t    iflT;
    FLEET     *lpflBest;
    int16_t    fFoundIdeal;
    int32_t    dx;
    int32_t    lBest;
    int32_t    l;
    PLANET     pl;
    int16_t    iWarp;
    DtFileType dt;
    char      *pcVar;

    fRet = 1;
    SetVisiblePlanFleet(iPlayer);

    /* Fix up fleet waypoints for patrolling fleets during turn generation */
    if (gd.fGeneratingTurn && iPlayer != iNoPlayer) {
        for (i = 0; i < cFleet; i++) {
            lpfl = rglpfl[i];
            if (lpfl == NULL)
                break;
            if (!lpfl->fDead && lpfl->iplr == iPlayer) {
                /* Check if fleet has any ships */
                for (j = 0; j < 16 && lpfl->rgcsh[j] == 0; j++)
                    ;
                if (j == 16) {
                    /* No ships - mark as dead */
                    lpfl->fDead = 1;
                } else {
                    lpord = lpfl->lpplord->rgord;

                    /* Fix up intercept waypoints that are now out of range */
                    if (lpord->grobj == 2) { /* grobjFleet */
                        pt.y = lpord->pt.y;
                        pt.x = lpord->pt.x;
                        if (!FFindNearestObject(pt, grobjPlanet | mdExact, &scan)) {
                            lpord->grobj = 4; /* grobjOther - go to position */
                            lpord->id = 0;
                        } else {
                            lpord->grobj = 1; /* grobjPlanet */
                            lpord->id = scan.idpl;
                        }
                    }

                    /* Handle patrol task with no destination */
                    if (lpord->grTask == 0 && lpfl->cord > 1 && lpord[1].grTask == 7) {
                        lpord->grTask = 7; /* patrol */
                        lpord->tptl.iWarp = lpord[1].tptl.iWarp;
                        lpord->tptl.iDist = lpord[1].tptl.iDist;
                    }

                    /* Handle patrol task - find targets */
                    if (lpord->grTask == 7 && (lpfl->cord < 2 || lpord[1].grobj != grobjFleet)) {
                        lpflBest = NULL;
                        lBest = 100000000;
                        fFoundIdeal = 0;
                        int32_t xStart, yStart;

                        if (lpfl->idPlanet == -1 && lpfl->cord > 1 && lpfl->fRepOrders) {
                            xStart = lpord[1].pt.x;
                            yStart = lpord[1].pt.y;
                        } else {
                            xStart = lpfl->pt.x;
                            yStart = lpfl->pt.y;
                        }

                        lpbtlplan = rglpbtlplan[lpfl->iPlayer] + lpfl->iplan;
                        mdTarget = lpbtlplan->mdTarget1;

                        for (iflT = 0; iflT < cFleet; iflT++) {
                            lpflTarget = rglpfl[iflT];
                            if (lpflTarget == NULL)
                                break;
                            if (lpflTarget->fInclude && lpflTarget->iPlayer != iPlayer) {
                                dx = lpflTarget->pt.x - xStart;
                                dy = lpflTarget->pt.y - yStart;
                                l = (int32_t)dx * dx + (int32_t)dy * dy;

                                if ((fFoundIdeal == 0 && !lpflTarget->fMark) || (l < lBest && (fFoundIdeal == 0 || !lpflTarget->fMark))) {
                                    if (FMatchTarget(lpflTarget, mdTarget, 0)) {
                                        if (FAttackPlayer(lpfl, lpflTarget->iPlayer)) {
                                            lpflBest = lpflTarget;
                                            lBest = l;
                                            if (!lpflTarget->fMark) {
                                                fFoundIdeal = 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (fFoundIdeal && !gd.fTutorial) {
                            lpflBest->fMark = 1;
                        }

                        iWarp = lpord->tptl.iDist * 50 + 50;
                        if (iWarp == 550) {
                            iWarp = 10000;
                        }

                        if (lpflBest != NULL && lBest != 0) {
                            if (lBest <= (int32_t)iWarp * iWarp) {
                                /* Expand orders if needed */
                                if (lpfl->lpplord->iordMax <= lpfl->cord + 1) {
                                    lpfl->lpplord = (PLORD *)LpplReAlloc((PL *)lpfl->lpplord, lpfl->cord + 2);
                                    lpord = lpfl->lpplord->rgord;
                                }

                                /* Shift existing orders */
                                if (lpfl->cord > 1) {
                                    memmove(&lpord[2], &lpord[1], (lpfl->cord - 1) * sizeof(ORDER));
                                }

                                if (lpfl->cord == 1) {
                                    /* Set up return waypoint */
                                    memset(&lpord[1], 0, sizeof(ORDER));
                                    lpord[1].fValidTask = 1;
                                    lpord[1].grTask = 7; /* patrol */
                                    lpord[1].tptl.iWarp = lpord->tptl.iWarp;
                                    lpord[1].tptl.iDist = lpord->tptl.iDist;

                                    if (lpord[1].tlm.cTime == 0) {
                                        iWarp = IFindIdealWarp(lpfl, 0);
                                        lpord[1].iWarp = iWarp & 0xf;
                                    } else {
                                        iWarp = lpord[1].tlm.cTime;
                                        lpord[1].iWarp = iWarp & 0xf;
                                    }

                                    if (lpfl->fRepOrders) {
                                        /* Copy first waypoint to third */
                                        memmove(&lpord[2], &lpord[0], sizeof(ORDER));
                                        iWarp = IFindIdealWarp(lpfl, 0);
                                        lpord[2].iWarp = iWarp & 0xf;
                                        lpfl->cord++;
                                        lpfl->lpplord->iordMac++;
                                    }
                                } else {
                                    if (lpord[1].tlm.cTime == 0) {
                                        iWarp = IFindIdealWarp(lpfl, 0);
                                        lpord[1].iWarp = iWarp & 0xf;
                                    } else {
                                        iWarp = lpord[1].tlm.cTime;
                                        lpord[1].iWarp = iWarp & 0xf;
                                    }
                                }

                                /* Set intercept waypoint */
                                lpord[1].pt.x = lpflBest->pt.x;
                                lpord[1].pt.y = lpflBest->pt.y;
                                lpord[1].id = lpflBest->id;
                                lpord[1].grobj = 2; /* grobjFleet */
                                lpfl->cord++;
                                lpfl->lpplord->iordMac++;

                                FSendPlrMsg(iPlayer, idmPatrollingHasTargetedIntercept, lpfl->id | 0x8000, lpfl->id, lpflBest->id, 0, 0, 0, 0, 0);
                            }
                        }
                    }

                    /* Check for invalid waypoints */
                    if (lpord->grTask != 1 && lpfl->cord > 1) {
                        for (iord = 1; iord < lpfl->cord; iord++) {
                            if (lpord[iord].grobj == 8) { /* heading to thing */
                                lpth = LpthFromId(lpord[iord].id);
                                if (lpth == NULL || (lpth->ith == ithMysteryTrader && !lpth->tht.fInclude) ||    /* Mystery Trader gone */
                                    (lpth->ith == ithMinefield && ((1 << iPlayer) & lpth->thm.grbitPlr) == 0) || /* Minefield invisible */
                                    (lpth->ith == ithWormhole && !lpth->thw.fInclude)) {                         /* Wormhole gone */

                                    if (lpth == NULL || lpth->ith != ithWormhole) {
                                        if (lpth == NULL || lpth->ith != ithMysteryTrader) {
                                            if (lpth != NULL && lpth->ith == ithMinefield) {
                                                FSendPlrMsg2(lpfl->iPlayer, idmMineFieldHeadingHasVanishedOrdersHave, lpfl->id | 0x8000, lpfl->id, 0);
                                            }
                                        } else {
                                            FSendPlrMsg2(lpfl->iPlayer, idmMysteryTraderHeadingHasVanishedOrdersHave, lpfl->id | 0x8000, lpfl->id, 0);
                                        }
                                    } else {
                                        FSendPlrMsg2(lpfl->iPlayer, idmWormholeHeadingHasVanishedOrdersHaveChanged, lpfl->id | 0x8000, lpfl->id, 0);
                                    }

                                    lpord[iord].grobj = grobjOther; /* go to position */
                                    lpord[iord].id = iord;
                                }
                            } else if (lpord[iord].grobj == grobjFleet) { /* intercept fleet */
                                fNoAutoTrack = lpord[iord].fNoAutoTrack;
                                if (fNoAutoTrack) {
                                    lpord[iord].fNoAutoTrack = 0;
                                }

                                lpflT = LpflFromId(lpord[iord].id);
                                if (lpflT == NULL || lpflT->fDead) {
                                    FSendPlrMsg(iPlayer, idmSWaypointAppearsHaveDestroyedHasDisappeared, lpfl->id | 0x8000, lpfl->id, lpord[iord].id, 0, 0, 0,
                                                0, 0);
                                } else {
                                    if (lpflT->fInclude)
                                        continue;
                                    if (lpflT->idPlanet == -1 || fNoAutoTrack) {
                                        FSendPlrMsg(iPlayer, idmFleetTrackingAppearsHaveOutrunRangeScanners, lpfl->id | 0x8000, lpfl->id, 0, 0, 0, 0, 0, 0);
                                    } else {
                                        FSendPlrMsg(iPlayer, idmFleetTrackingAppearsHaveDuckedBehindOrders, lpfl->id | 0x8000, lpfl->id, lpflT->idPlanet, 0, 0,
                                                    0, 0, 0);
                                    }
                                }

                                lpord[iord].grobj = 4; /* go to position */
                                lpord[iord].id = iord;

                                pt.y = lpord[iord].pt.y;
                                pt.x = lpord[iord].pt.x;
                                if (FFindNearestObject(pt, grobjPlanet | mdExact, &scan)) {
                                    lpord[iord].grobj = 1; /* grobjPlanet */
                                    lpord[iord].id = scan.idpl;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    MarkPlayersThatSentMsgs(iPlayer);
    MarkPlanetsPlayerLost(iPlayer);

    /* Build filename */
    if (iPlayer == iNoPlayer) {
        sprintf(szWork, "%s.hst", pszFileBase);
    } else {
        sprintf(szWork, "%s.m%d", pszFileBase, iPlayer + 1);
    }

    penvMemSav = penvMem;
    penvMem = &env;

    if (setjmp(env.env) == 0) {
        /* Try append or create new file */
        if (fAppend == 0) {
        LAB_CreateFile:
            if (iPlayer == iNoPlayer) {
                dt = dtHost;
            } else {
                dt = dtTurn;
            }
            if (!FCreateFile(dt, iPlayer, NULL))
                goto LAB_Fail;
        } else {
            if (!FAppendFile(iPlayer))
                goto LAB_CreateFile;
        }

        WriteBattles(iPlayer);

        /* Write players */
        for (i = 0; i < game.cPlayer; i++) {
            if (rgplr[i].fInclude || rgplr[i].fDead) {
                if (GetRaceStat(&rgplr[iPlayer], rsMajorAdv) == raTerra) {
                    rgplr[i].det = 7;
                }
                WriteRtPlr(&rgplr[i], NULL);
            }
        }

        /* Write salt for host mode */
        if (iPlayer == iNoPlayer && lSaltCur != 0) {
            WriteRt(rtChgPassword, 4, &lSaltCur);
        }

        WritePlayerMessages(iPlayer);

        /* Write planets */
        lpplT = lpPlanets;
        for (i = 0; i < cPlanet; i++) {
            if (lpplT->fInclude) {
                if (lpplT->det == 7) {
                    WritePlanet(lpplT, 0xd, 0);
                    if (lpplT->lpplprod != NULL) {
                        WriteRt(rtProdQ, lpplT->lpplprod->iprodMac << 2, &lpplT->lpplprod->rgprod[0]);
                    }
                } else if (lpplT->det == 2) {
                    /* Save and restore planet data for minimal write */
                    memcpy(&pl, lpplT, sizeof(PLANET));
                    lpplT->fInclude = 0;
                    lpplT->det = 3;
                    WritePlanet(lpplT, 0xe, 0);
                    memcpy(lpplT, &pl, sizeof(PLANET));
                } else {
                    WritePlanet(lpplT, 0xe, 0);
                }
            }
            lpplT++;
        }

        /* Write ship definitions */
        for (i = 0; i < game.cPlayer; i++) {
            if (rgplr[i].fInclude) {
                lpshdef = rglpshdef[i];
                for (j = 0; j < 16; j++) {
                    if (!lpshdef[j].fFree && lpshdef[j].fInclude) {
                        WriteRtShDef(&lpshdef[j], NULL);
                    }
                }
            }
        }

        /* Write fleets */
        for (i = 0; i < cFleet; i++) {
            lpflT = rglpfl[i];
            if (lpflT == NULL)
                break;
            if (lpflT->fInclude) {
                WriteFleet(lpflT);
            }
        }

        /* Write starbase definitions */
        for (i = 0; i < game.cPlayer; i++) {
            if (rgplr[i].fInclude) {
                lpshdef = rglpshdefSB[i];
                for (j = 0; j < 10; j++) {
                    if (!lpshdef[j].fFree && lpshdef[j].fInclude) {
                        WriteRtShDef(&lpshdef[j], NULL);
                    }
                }
            }
        }

        /* Write scores */
        if (iPlayer != iNoPlayer && vlprgScoreX != NULL) {
            for (i = 0; i < game.cPlayer; i++) {
                if (gd.fGameOverMan || i == iPlayer || rgplr[i].fDead || (game.fVisScores && game.turn > 0x13)) {
                    WriteRt(rtScore, 0x18, &vlprgScoreX[i]);
                }
            }
        }

        /* Count and write things */
        i = 0;
        lpth = lpThings;
        while (lpth < lpThings + cThing) {
            if (iPlayer == iNoPlayer || (iPlayer == lpth->iplr && lpth->ith != ithMineralPacket && lpth->ith != ithMysteryTrader && lpth->ith != ithWormhole) ||
                (lpth->ith == ithMinefield && ((1 << iPlayer) & lpth->thm.grbitPlr) != 0) || (lpth->ith == ithMineralPacket && lpth->tht.ptDest.x < 0) ||
                (lpth->ith == ithMysteryTrader && lpth->tht.fInclude) || (lpth->ith == ithWormhole && lpth->thw.fInclude)) {
                i++;
            }
            lpth++;
        }

        if (i > 0) {
            WriteRt(rtLogThingByteParam, 2, &i);
            lpth = lpThings;
            while (lpth < lpThings + cThing) {
                if (iPlayer == iNoPlayer ||
                    (iPlayer == lpth->iplr && lpth->ith != ithMineralPacket && lpth->ith != ithMysteryTrader && lpth->ith != ithWormhole) ||
                    (lpth->ith == ithMinefield && ((1 << iPlayer) & lpth->thm.grbitPlr) != 0) || (lpth->ith == ithMineralPacket && lpth->tht.ptDest.x < 0) ||
                    (lpth->ith == ithMysteryTrader && lpth->tht.fInclude) || (lpth->ith == ithWormhole && lpth->thw.fInclude)) {
                    WriteRt(rtLogThingByteParam, sizeof(THING), lpth);
                }
                lpth++;
            }
        }

        /* Write battle plans */
        if (iPlayer == iNoPlayer) {
            i = 0;
            iMax = game.cPlayer;
        } else {
            i = iPlayer;
            iMax = iPlayer + 1;
        }
        for (; i < iMax; i++) {
            lpbtlplan = rglpbtlplan[i];
            for (j = 0; j < rgcbtlplan[i]; j++) {
                WriteBattlePlan(lpbtlplan, 0);
                lpbtlplan++;
            }
        }

        WriteRt(rtEOF, 2, &game.turn);
        StreamClose();
    } else {
    LAB_Fail:
        idPlayer = iPlayer;
        if (fAppend == 0) {
            if (iPlayer == iNoPlayer) {
                idPlayer = -1;
                pcVar = PszFormatIds(idsUnableCreateHostFile, NULL);
                AlertSz(pcVar, 0x10);
            } else {
                pcVar = PszFormatIds(idsUnableCreateNewTurnFile, NULL);
                AlertSz(pcVar, 0x10);
            }
        } else {
            pcVar = PszFormatIds(idsUnableUpdateTurnFile, NULL);
            AlertSz(pcVar, 0x10);
        }
        idPlayer = -1;
        fRet = 0;
    }

    penvMem = penvMemSav;
    SetVisiblePlanFleet(-1);
    return fRet;
}

int16_t FAppendFile(int16_t iPlayer) {
    int16_t fOk;

    fOk = FMarkFile(dtTurn | bitfMulti, iPlayer, mdMulti, 1);
    if (fOk != 0) {
        WriteBOF(iPlayer, dtTurn, 1);
    }
    return (int16_t)(fOk != 0);
}

void SetVisPFFinish(int16_t iPlr) {
    uint16_t detMajor;
    int16_t  j;
    int16_t  i;
    SHDEF   *lpshdef;

    if (GetRaceStat(&rgplr[iPlr], rsMajorAdv) == raAttack) {
        detMajor = detAll;
    } else {
        detMajor = detSome;
    }

    for (i = 0; i < game.cPlayer; i++) {
        if (i == iPlr)
            continue;

        /* Regular ship designs */
        rgplr[i].cShDef = 0;
        for (j = 0; j < cShdefMax; j++) {
            lpshdef = &rglpshdef[i][j];
            if ((lpshdef->grbitPlr & (1 << (iPlr & 0x1f))) == 0) {
                /* Player hasn't seen this design before */
                if (lpshdef->fInclude) {
                    /* Was marked visible this pass - cap det level */
                    lpshdef->det = detMajor;
                    goto LFinShdef;
                }
            } else {
                /* Player has seen this design before - full include */
                lpshdef->fInclude = 1;
                lpshdef->det = detAll;
            LFinShdef:
                rgplr[i].det = detSome;
                rgplr[i].fInclude = 1;
                rgplr[i].cShDef++;
            }
        }

        /* Starbase ship designs */
        rgplr[i].cshdefSB = 0;
        for (j = 0; j < ishdefSBMax; j++) {
            lpshdef = &rglpshdefSB[i][j];
            if ((lpshdef->grbitPlr & (1 << (iPlr & 0x1f))) == 0) {
                /* Player hasn't seen this design before */
                if (lpshdef->fInclude) {
                    /* Was marked visible this pass - cap det level */
                    lpshdef->det = detMajor;
                    goto LFinShdefSB;
                }
            } else {
                /* Player has seen this design before - full include */
                lpshdef->fInclude = 1;
                lpshdef->det = detAll;
            LFinShdefSB:
                rgplr[i].fInclude = 1;
                rgplr[i].det = detSome;
                rgplr[i].cshdefSB++;
            }
        }
    }
}

int16_t FCreateFile(DtFileType dt, int16_t iPlayer, char *szForceName) {
    MemJump *penvMemSav;
    MemJump  env;
    char    *psz;
    int      jmp_rc;

    if (szForceName == NULL) {
        SetSzWorkFromDt(dt, iPlayer);
        psz = (char *)szWork;
    } else {
        psz = szForceName;
    }

    penvMemSav = penvMem;
    penvMem = &env;

    jmp_rc = setjmp(env.env);
    if (jmp_rc == 0) {
        StreamOpen(psz, mdCreate);
        WriteBOF(iPlayer, dt, 0);
    }

    penvMem = penvMemSav;
    return (int16_t)(jmp_rc == 0);
}

void SetVisPFPlanets(int16_t iPlr) {
    int32_t  lRadPlanet2;
    int16_t  iRadPlanet;
    int16_t  pctCloak;
    PLANET  *lppl2;
    int16_t  dy;
    FLEET   *lpfl2;
    int32_t  d2;
    PLANET  *lppl;
    int16_t  j;
    THING   *lpth;
    int32_t  lRadius2;
    int16_t  i;
    THING   *lpthMac;
    int16_t  iRadius;
    bool     fStargateView;
    int16_t  dx;
    uint16_t grbitPlr;
    int16_t  rgStargateRange[16];

    if (iPlr == -1) {
        grbitPlr = 0;
    } else {
        grbitPlr = 1 << (iPlr & 0x1f);
    }

    /* Check for IT stargate scanning ability */
    fStargateView = false;
    if (GetRaceStat(&rgplr[iPlr], rsMajorAdv) == raStargate) {
        for (i = 0; i < ishdefSBMax; i++) {
            rgStargateRange[i] = 0;
            if (!rglpshdefSB[iPlr][i].fFree) {
                rgStargateRange[i] = StargateRangeFromLppl(NULL, iPlr, i);
                if (rgStargateRange[i] > 0) {
                    fStargateView = true;
                }
            }
        }
    }

    if (iPlr != -1) {
        UpdateProgressGauge(pctProgressStepSmall);
    }

    /* Pass 1: Planet scans fleets */
    for (lppl = lpPlanets; lppl < lpPlanets + cPlanet; lppl++) {
        if (lppl->iPlayer != iPlr)
            continue;

        iRadius = GetPlanetScannerRange(lppl, &iRadPlanet);
        lRadius2 = (uint32_t)iRadius * (uint32_t)iRadius;
        lRadPlanet2 = (uint32_t)iRadPlanet * (uint32_t)iRadPlanet;
        int16_t ptx = rgptPlan[lppl->id].x;
        int16_t pty = rgptPlan[lppl->id].y;

        for (j = 0; j < cFleet; j++) {
            lpfl2 = rglpfl[j];
            if (lpfl2 == NULL)
                break;

            if (lpfl2->fInclude || lpfl2->fDead)
                continue;

            dx = abs(ptx - lpfl2->pt.x);
            if (dx > iRadius)
                continue;
            dy = abs(pty - lpfl2->pt.y);
            if (dy > iRadius)
                continue;

            d2 = (int32_t)dy * dy + (int32_t)dx * dx;
            if (d2 > lRadius2)
                continue;
            if (lpfl2->idPlanet != -1 && d2 > lRadPlanet2)
                continue;

            pctCloak = PctCloakFromLpfl(lpfl2);
            if (pctCloak == 0) {
                MarkFleet(lpfl2, detSome);
            } else {
                int32_t lEffective = (uint32_t)lRadius2 * (uint32_t)(100 - pctCloak) / 100;
                lEffective = (uint32_t)lEffective * (uint32_t)(100 - pctCloak) / 100;
                if (d2 <= lEffective) {
                    if (lpfl2->idPlanet != -1) {
                        int32_t lEffPlanet = (uint32_t)lRadPlanet2 * (uint32_t)(100 - pctCloak) / 100;
                        lEffPlanet = (uint32_t)lEffPlanet * (uint32_t)(100 - pctCloak) / 100;
                        if (lEffPlanet < d2)
                            continue;
                    }
                    MarkFleet(lpfl2, detSome);
                }
            }
        }
    }

    if (iPlr != -1) {
        UpdateProgressGauge(pctProgressStepSmall);
    }

    /* Pass 2: Stargate scanning of other planets */
    for (lppl = lpPlanets; lppl < lpPlanets + cPlanet; lppl++) {
        if (lppl->iPlayer != iPlr)
            continue;

        iRadius = GetPlanetScannerRange(lppl, &iRadPlanet);
        lRadPlanet2 = (uint32_t)iRadPlanet * (uint32_t)iRadPlanet;
        int16_t ptx = rgptPlan[lppl->id].x;
        int16_t pty = rgptPlan[lppl->id].y;

        if (fStargateView && lppl->fStarbase && rgStargateRange[lppl->isb] > 0) {
            int16_t sgRange = rgStargateRange[lppl->isb];
            int32_t lSgRange2 = (uint32_t)sgRange * (uint32_t)sgRange;

            for (lppl2 = lpPlanets; lppl2 < lpPlanets + cPlanet; lppl2++) {
                if (lppl2->fInclude && lppl2->det >= detSome)
                    continue;
                if (!lppl2->fStarbase)
                    continue;

                if (StargateRangeFromLppl(lppl2, 0, 0) == 0)
                    continue;

                if (sgRange > 9999) {
                    goto LMarkStargate;
                }

                dx = abs(rgptPlan[lppl2->id].x - ptx);
                if (dx > sgRange)
                    continue;
                dy = abs(rgptPlan[lppl2->id].y - pty);
                if (dy > sgRange)
                    continue;

                d2 = (int32_t)dy * dy + (int32_t)dx * dx;
                if (d2 > lSgRange2)
                    continue;

                /* Check starbase cloak */
                if (lppl2->iPlayer != iNoPlayer) {
                    SHDEF  *lpshdefSB = &rglpshdefSB[lppl2->iPlayer][lppl2->isb];
                    int32_t lVisible = lpshdefSB->lVisible;
                    int16_t hiVis = (int16_t)(lVisible >> 16);
                    if (hiVis < 1 && (hiVis < 0 || (uint16_t)lVisible < 10000)) {
                        int32_t lEffSg = (uint32_t)lSgRange2 * (uint32_t)lVisible / 10000;
                        if (lEffSg < d2)
                            continue;
                    }
                }

            LMarkStargate:
                MarkPlanet(lppl2, iPlr, detSome);
            }
        }
    }

    if (iPlr != -1) {
        UpdateProgressGauge(pctProgressStepSmall);
    }

    /* Pass 3: Planet scans things */
    for (lppl = lpPlanets; lppl < lpPlanets + cPlanet; lppl++) {
        if (lppl->iPlayer != iPlr)
            continue;

        iRadius = GetPlanetScannerRange(lppl, &iRadPlanet);
        lRadius2 = (uint32_t)iRadius * (uint32_t)iRadius;
        lRadPlanet2 = (uint32_t)iRadPlanet * (uint32_t)iRadPlanet;
        int16_t ptx = rgptPlan[lppl->id].x;
        int16_t pty = rgptPlan[lppl->id].y;

        lpthMac = lpThings + cThing;
        for (lpth = lpThings; lpth < lpthMac; lpth++) {
            if (iPlr == -1)
                continue;
            if (lpth->ith != ithMinefield && lpth->ith != ithMineralPacket && lpth->ith != ithMysteryTrader && lpth->ith != ithWormhole)
                continue;
            if (lpth->ith == ithMinefield && (lpth->thm.grbitPlrNow & grbitPlr) != 0)
                continue;
            if (lpth->ith == ithMysteryTrader && lpth->tht.fInclude)
                continue;
            if (lpth->ith == ithMineralPacket && lpth->tht.ptDest.x < 0)
                continue;
            if (lpth->ith == ithWormhole && lpth->thw.fInclude)
                continue;

            dx = abs(ptx - lpth->pt.x);
            if (dx > iRadius)
                continue;
            dy = abs(pty - lpth->pt.y);
            if (dy > iRadius)
                continue;

            d2 = (int32_t)dy * dy + (int32_t)dx * dx;
            if (d2 > lRadius2)
                continue;

            if (lpth->ith == ithMineralPacket) {
                lpth->thp.fInclude = 1;
            LThIncPlr2:
                if (!rgplr[lpth->iplr].fInclude) {
                    rgplr[lpth->iplr].fInclude = 1;
                    rgplr[lpth->iplr].det = detSome;
                }
            } else if (lpth->ith == ithMysteryTrader) {
                lpth->tht.fInclude = 1;
            } else if (lpth->ith == ithWormhole) {
                if ((lpth->thw.grbitPlr & grbitPlr) == 0) {
                    /* Check minefield-like range */
                    if (d2 > lRadPlanet2) {
                        int32_t lMineRad = lpth->thm.cMines;
                        if (lMineRad < d2 && lRadPlanet2 < d2)
                            continue;
                    }
                }
                lpth->thw.grbitPlrTrav |= grbitPlr;
                lpth->thw.fInclude = 1;
            } else {
                /* Minefield */
                if ((lpth->thm.grbitPlr & grbitPlr) == 0 && d2 > lRadPlanet2) {
                    int32_t lMineRad = lpth->thm.cMines;
                    if (lMineRad < d2)
                        continue;
                }
                lpth->thm.grbitPlr |= grbitPlr;
                lpth->thm.grbitPlrNow |= grbitPlr;
                goto LThIncPlr2;
            }
        }
    }

    if (iPlr != -1) {
        UpdateProgressGauge(pctProgressStepSmall);
    }

    /* Pass 4: Planet pen scans other planets */
    for (lppl = lpPlanets; lppl < lpPlanets + cPlanet; lppl++) {
        if (lppl->iPlayer != iPlr)
            continue;

        iRadius = GetPlanetScannerRange(lppl, &iRadPlanet);
        lRadius2 = (uint32_t)iRadPlanet * (uint32_t)iRadPlanet;
        int16_t ptx = rgptPlan[lppl->id].x;
        int16_t pty = rgptPlan[lppl->id].y;

        if (iRadPlanet <= 0)
            continue;

        for (lppl2 = lpPlanets; lppl2 < lpPlanets + cPlanet; lppl2++) {
            if (lppl2->fInclude && lppl2->det >= detSome)
                continue;

            dx = abs(rgptPlan[lppl2->id].x - ptx);
            if (dx > iRadPlanet)
                continue;
            dy = abs(rgptPlan[lppl2->id].y - pty);
            if (dy > iRadPlanet)
                continue;

            d2 = (int32_t)dy * dy + (int32_t)dx * dx;
            if (d2 > lRadius2)
                continue;

            /* Check starbase cloak on target */
            if (lppl2->fStarbase && lppl2->iPlayer != iNoPlayer) {
                SHDEF  *lpshdefSB = &rglpshdefSB[lppl2->iPlayer][lppl2->isb];
                int32_t lVisible = lpshdefSB->lVisible;
                int16_t hiVis = (int16_t)(lVisible >> 16);
                if (hiVis < 1 && (hiVis < 0 || (uint16_t)lVisible < 10000)) {
                    int32_t lEffPlanet = (uint32_t)lRadius2 * (uint32_t)lVisible / 10000;
                    if (lEffPlanet < d2) {
                        MarkPlanet(lppl2, iPlr, detObscure);
                        continue;
                    }
                }
            }

            MarkPlanet(lppl2, iPlr, detSome);
        }
    }
}

void SetVisPFFleets(int16_t iPlr) {
    STARSPOINT pt;
    int16_t    pctCloak;
    int16_t    dy;
    FLEET     *lpfl2;
    int32_t    d2;
    PLANET    *lppl;
    int16_t    j;
    FLEET     *lpfl;
    THING     *lpth;
    int32_t    lRadius2;
    int16_t    ifl;
    THING     *lpthMac;
    int16_t    iRadius;
    int16_t    dx;
    uint16_t   grbitPlr;
    int32_t    lRadPlanet2;
    int16_t    iRadPlanet;
    int16_t    iSteal;
    int16_t    pctDetect;

    if (iPlr == -1) {
        grbitPlr = 0;
    } else {
        grbitPlr = 1 << (iPlr & 0x1f);
    }

    for (ifl = 0; ifl < cFleet; ifl++) {
        lpfl = rglpfl[ifl];
        if (lpfl == NULL)
            return;

        if (lpfl->fDead)
            continue;

        if (lpfl->iPlayer == iPlr) {
            /* Own fleet - scan for other fleets and things */

            /* Mark planet if fleet has been orbiting all turn */
            if (lpfl->fHereAllTurn && lpfl->idPlanet != -1) {
                MarkPlanet(&lpPlanets[lpfl->idPlanet], iPlr, detSome);
            }

            iRadius = GetCachedFleetScannerRange(lpfl, &iRadPlanet, &pctDetect, &iSteal);
            if (iRadius < 0) {
                iRadius = 0;
            }
            lRadius2 = (uint32_t)iRadius * (uint32_t)iRadius;
            lRadPlanet2 = (uint32_t)iRadPlanet * (uint32_t)iRadPlanet;

            pt.x = lpfl->pt.x;
            pt.y = lpfl->pt.y;

            /* Scan for other fleets */
            for (j = 0; j < cFleet; j++) {
                lpfl2 = rglpfl[j];
                if (lpfl2 == NULL)
                    break;

                if (lpfl2->fDead)
                    continue;

                /* Steal tech: mark fleets at same location */
                if ((iSteal & 1) && pt.x == lpfl2->pt.x && pt.y == lpfl2->pt.y && (!lpfl2->fInclude || lpfl2->det < detMore)) {
                    MarkFleet(lpfl2, detMore);
                }

                if (lpfl2->fInclude)
                    continue;

                dx = abs(pt.x - lpfl2->pt.x);
                if (dx > iRadius)
                    continue;
                dy = abs(pt.y - lpfl2->pt.y);
                if (dy > iRadius)
                    continue;

                d2 = (int32_t)dy * dy + (int32_t)dx * dx;
                if (d2 > lRadius2)
                    continue;

                /* If fleet is at a planet, use planet scan range */
                if (lpfl2->idPlanet != -1 && d2 > lRadPlanet2)
                    continue;

                pctCloak = PctCloakFromLpfl(lpfl2);
                if (pctDetect != 100) {
                    pctCloak = (int16_t)((int16_t)(pctCloak * pctDetect) / 100);
                }

                if (pctCloak == 0) {
                    MarkFleet(lpfl2, detSome);
                } else {
                    /* Reduce scan range by cloak percentage */
                    int32_t lEffective = (int32_t)((uint32_t)lRadius2 * (uint32_t)(100 - pctCloak) / 100);
                    lEffective = (int32_t)((uint32_t)lEffective * (uint32_t)(100 - pctCloak) / 100);
                    if (d2 <= lEffective) {
                        if (lpfl2->idPlanet != -1) {
                            int32_t lEffPlanet = (int32_t)((uint32_t)lRadPlanet2 * (uint32_t)(100 - pctCloak) / 100);
                            lEffPlanet = (int32_t)((uint32_t)lEffPlanet * (uint32_t)(100 - pctCloak) / 100);
                            if (lEffPlanet < d2)
                                continue;
                        }
                        MarkFleet(lpfl2, detSome);
                    }
                }
            }

            /* Scan for things */
            lpthMac = lpThings + cThing;
            for (lpth = lpThings; lpth < lpthMac; lpth++) {
                /* Skip things already visible or not applicable */
                if (iPlr == -1)
                    continue;
                if (lpth->ith != ithMinefield && lpth->ith != ithMineralPacket && lpth->ith != ithMysteryTrader && lpth->ith != ithWormhole)
                    continue;
                /* Skip minefields already known to this player */
                if (lpth->ith == ithMinefield && (lpth->thm.grbitPlrNow & grbitPlr) != 0)
                    continue;
                /* Skip mystery traders already included */
                if (lpth->ith == ithMysteryTrader && lpth->tht.fInclude)
                    continue;
                /* Skip mineral packets with negative dest (already visible) */
                if (lpth->ith == ithMineralPacket && lpth->tht.ptDest.x < 0)
                    continue;
                /* Skip wormholes already included */
                if (lpth->ith == ithWormhole && lpth->thw.fInclude)
                    continue;

                dx = abs(pt.x - lpth->pt.x);
                dy = abs(pt.y - lpth->pt.y);
                d2 = (int32_t)dy * dy + (int32_t)dx * dx;

                if (d2 <= lRadius2 || lpth->ith == ithMinefield) {
                    if (lpth->ith == ithMineralPacket) {
                        /* Mark packet as visible */
                        lpth->thp.fInclude = 1;
                    LThIncPlr:
                        if (!rgplr[lpth->iplr].fInclude) {
                            rgplr[lpth->iplr].fInclude = 1;
                            rgplr[lpth->iplr].det = detSome;
                        }
                    } else if (lpth->ith == ithMysteryTrader) {
                        lpth->tht.fInclude = 1;
                    } else if (lpth->ith == ithWormhole) {
                        /* Check if wormhole is in range */
                        if ((lpth->thw.grbitPlrTrav & grbitPlr) == 0) {
                            if (d2 > lRadPlanet2 && lRadPlanet2 < d2)
                                continue;
                        }
                        lpth->thw.grbitPlrTrav |= grbitPlr;
                        lpth->thw.fInclude = 1;
                    } else {
                        /* Minefield */
                        if ((lpth->thm.grbitPlr & grbitPlr) == 0 || d2 > lRadius2) {
                            if (d2 > lRadPlanet2) {
                                /* Check minefield's own radius */
                                if (lpth->thm.cMines < d2)
                                    continue;
                            }
                        }
                        lpth->thm.grbitPlr |= grbitPlr;
                        lpth->thm.grbitPlrNow |= grbitPlr;
                        goto LThIncPlr;
                    }
                }
            }

            /* Steal tech: mark planet if fleet has iSteal >= 2 */
            if ((iSteal & 2) && lpfl->idPlanet != -1) {
                MarkPlanet(&lpPlanets[lpfl->idPlanet], iPlr, detMore);
            }

            /* Scan for planets with pen scanner */
            if (iRadPlanet > 0) {
                iRadius = iRadPlanet;
                lRadius2 = (uint32_t)iRadPlanet * (uint32_t)iRadPlanet;
                pt.x = lpfl->pt.x;
                pt.y = lpfl->pt.y;

                for (lppl = lpPlanets; lppl < lpPlanets + cPlanet; lppl++) {
                    if (lppl->fInclude && lppl->det >= detSome)
                        continue;

                    dx = abs(rgptPlan[lppl->id].x - pt.x);
                    if (dx > iRadius)
                        continue;
                    dy = abs(rgptPlan[lppl->id].y - pt.y);
                    if (dy > iRadius)
                        continue;

                    d2 = (int32_t)dy * dy + (int32_t)dx * dx;
                    if (d2 > lRadius2)
                        continue;

                    /* Check starbase cloak */
                    if (lppl->fStarbase && lppl->iPlayer != iNoPlayer) {
                        SHDEF  *lpshdefSB = &rglpshdefSB[lppl->iPlayer][lppl->isb];
                        int32_t lVisible = lpshdefSB->lVisible;
                        int16_t hiVis = (int16_t)(lVisible >> 16);
                        if (hiVis < 1 && (hiVis < 0 || (uint16_t)lVisible < 10000)) {
                            int32_t lEffPlanet = (uint32_t)lRadius2 * (uint32_t)lVisible / 10000;
                            if (lEffPlanet < d2) {
                                MarkPlanet(lppl, iPlr, detObscure);
                                continue;
                            }
                        }
                    }

                    MarkPlanet(lppl, iPlr, detSome);
                }
            }
        } else {
            /* Not our fleet - check if it's at one of our planets */
            if (!lpfl->fInclude && lpfl->idPlanet != -1 && lpPlanets[lpfl->idPlanet].iPlayer == iPlr) {
                MarkFleet(lpfl, detSome);
            }
        }
    }
}

void WritePlanet(PLANET *lppl, RecordType rt, int16_t fHistory) {
    uint8_t  bMask;
    uint8_t  rgb[80];
    uint8_t *pbBase;
    int16_t  i;
    uint8_t *pb;
    uint16_t w0;
    uint16_t w2;
    uint16_t detPacked;
    uint16_t fHasRouting;
    int16_t  hiWord;
    bool     fHasImp;

    memset(rgb, 0, 80);

    /* Pack first word: planet id (11 bits) | player (upper bits) */
    w0 = (lppl->id & 0x7ff) | ((uint16_t)lppl->iPlayer << 11);
    put_u16(&rgb[0], w0);

    /* Start packing second word with det field (7 bits) */
    detPacked = lppl->det & 0x7f;

    /* For rtPlanetB, clamp det if > 3 */
    if (rt == rtPlanetB && lppl->det > 3) {
        detPacked = fHistory ? 3 : 4;
    }

    /* Check if routing is set */
    fHasRouting = (lppl->wRouting & 0x3ff) != 0 ? 1 : 0;

    /* Pack flags into second word:
     * bits 0-6: det
     * bit 7: fHomeworld
     * bit 8: fInclude
     * bit 9: fStarbase
     * bit 14: hasRouting
     * bit 15: fFirstYear
     */
    w2 = detPacked | ((uint16_t)lppl->fHomeworld << 7) | ((uint16_t)lppl->fInclude << 8) | ((uint16_t)lppl->fStarbase << 9) | (fHasRouting << 14) |
         ((uint16_t)lppl->fFirstYear << 15);
    put_u16(&rgb[2], w2);

    pb = rgb + 4;

    if (detPacked > 1) {
        pb = rgb + 5;
        bMask = 3;

        /* Write mineral levels with presence mask */
        for (i = 0; i < 3; i++) {
            if (lppl->rgpctMinLevel[i] != 0) {
                rgb[4] |= bMask & 0x55;
                *pb = lppl->rgpctMinLevel[i];
                pb++;
            }
            bMask <<= 2;
        }

        /* Write mineral concentrations */
        for (i = 0; i < 3; i++) {
            *pb = lppl->rgMinConc[i];
            pb++;
        }

        /* Write environment variables and check if changed */
        for (i = 0; i < 3; i++) {
            *pb = lppl->rgEnvVar[i];
            if (lppl->rgEnvVar[i] != lppl->rgEnvVarOrig[i]) {
                /* Set bit 10 to indicate original env is included */
                w2 = (w2 & 0xfbff) | 0x400;
                put_u16(&rgb[2], w2);
            }
            pb++;
        }

        /* Write original environment if changed */
        if ((w2 >> 10) & 1) {
            for (i = 0; i < 3; i++) {
                *pb = lppl->rgEnvVarOrig[i];
                pb++;
            }
        }

        /* Write population/defense guesses if owned */
        if (lppl->iPlayer != iNoPlayer) {
            put_u16(pb, lppl->uGuesses);
            pb += 2;
        }

        pbBase = pb;

        if ((w2 & 0x7f) > 3) {
            pb++;
            bMask = 3;

            /* Write cargo amounts with variable-width encoding */
            for (i = 0; i < 4; i++) {
                /* Skip colonists (i==3) unless det > 6 */
                if (i != 3 || lppl->det > 6) {
                    hiWord = (int16_t)(lppl->rgwtMin[i] >> 16);
                    /* Check if cargo present (value > 0) */
                    if (hiWord >= 0 && (hiWord > 0 || lppl->rgwtMin[i] != 0)) {
                        if (hiWord < 1 && (uint32_t)lppl->rgwtMin[i] < 0x100) {
                            /* Byte encoding */
                            *pbBase |= bMask & 0x55;
                            *pb = (uint8_t)lppl->rgwtMin[i];
                            pb++;
                        } else if (hiWord < 1) {
                            /* Word encoding */
                            *pbBase |= bMask & 0xaa;
                            put_u16(pb, (uint16_t)lppl->rgwtMin[i]);
                            pb += 2;
                        } else {
                            /* Dword encoding */
                            *pbBase |= bMask;
                            put_u32(pb, (uint32_t)lppl->rgwtMin[i]);
                            pb += 4;
                        }
                    }
                }
                bMask <<= 2;
            }

            /* If any cargo was written, set bit 13 */
            if (*pbBase != 0) {
                w2 = (w2 & 0xdfff) | 0x2000;
                put_u16(&rgb[2], w2);
                pbBase = pb;
            }
            pb = pbBase;

            if (rt != rtPlanetB) {
                /* Check if improvements should be written */
                /* bit 12 is fArtifact */
                w2 = (w2 & 0xefff) | ((uint16_t)(lppl->fArtifact & 1) << 12);
                put_u16(&rgb[2], w2);

                /* decide whether to write the 8-byte rgbImp block */
                fHasImp = (lppl->iPlayer != iNoPlayer && lppl->iDeltaPop != 0) || lppl->cMines != 0 || lppl->cFactories != 0 || lppl->cDefenses != 0 ||
                          lppl->iScanner != 0x1f || lppl->fArtifact != 0 || /* optional: include if you consider this “imp data” */
                          lppl->fNoResearch != 0;                           /* optional */

                if (fHasImp) {
                    w2 = (w2 & 0xf7ff) | 0x0800; /* bit 11 */
                    put_u16(&rgb[2], w2);
                    memmove(pb, lppl->rgbImp, 8);
                    pb += 8;
                }

                if (lppl->iPlayer != iNoPlayer) {
                    /* Write starbase info if present */
                    if (lppl->fStarbase) {
                        put_u32(pb, (uint32_t)lppl->lStarbase);
                        pb += 4;
                    }
                    /* Write routing if present */
                    if ((lppl->wRouting & 0x3ff) != 0) {
                        put_u16(pb, lppl->wRouting);
                        pb += 2;
                    }
                }

                WriteRt(rtPlanet, (int16_t)(pb - rgb), rgb);
                return;
            }
        }
    }

    /* rtPlanetB path */
    if (lppl->fStarbase) {
        *pb = (uint8_t)(lppl->lStarbase & 0xf);
        pb++;
    }

    if (fHistory) {
        put_u16(pb, (uint16_t)lppl->turn);
        pb += 2;
    }

    WriteRt(rtPlanetB, (int16_t)(pb - rgb), rgb);
}

/* Mark a fleet as visible to the current player at the given detail level.
   On first inclusion, registers the fleet and its ship designs as visible
   and increments the owner's fleet count. Upgrades detail if det exceeds
   the current level. */
void MarkFleet(FLEET *lpfl, int16_t det) {
    int16_t i;

    if (!lpfl->fInclude) {
        lpfl->fInclude = 1;
        lpfl->det = 0;
        lpfl->fTargeted = 1;
        rgplr[lpfl->iPlayer].cFleet = (rgplr[lpfl->iPlayer].cFleet + 1) & 0xfff;

        for (i = 0; i < cShdefMax; i++) {
            if (lpfl->rgcsh[i] != 0) {
                rglpshdef[lpfl->iPlayer][i].fInclude = 1;
            }
        }
    }
    if (lpfl->det < (uint16_t)det) {
        lpfl->det = det;
    }
}

/* Mark a planet as visible to the current player at the given detail level.
   On first inclusion, increments the player's planet count. Upgrades detail
   if det exceeds current level. Also marks the planet owner and any starbase
   ship design as visible. */
void MarkPlanet(PLANET *lppl, int16_t iPlr, uint16_t det) {
    SHDEF *lpshdef;

    if (!lppl->fInclude) {
        lppl->fInclude = 1;
        lppl->det = 0;
        rgplr[iPlr].cPlanet++;
    }
    if (lppl->det < det) {
        lppl->det = det;
    }

    /* Mark planet owner as known */
    if (lppl->iPlayer != iNoPlayer && !rgplr[lppl->iPlayer].fInclude) {
        rgplr[lppl->iPlayer].fInclude = 1;
        rgplr[lppl->iPlayer].det = detSome;
    }

    /* Mark starbase design as visible */
    if (det != detObscure && lppl->iPlayer != iNoPlayer && lppl->fStarbase) {
        lpshdef = &rglpshdefSB[lppl->iPlayer][lppl->isb];
        if (!lpshdef->fInclude) {
            lpshdef->fInclude = 1;
            lpshdef->det = 0;
            rgplr[lppl->iPlayer].cshdefSB++;
        }
        if (lpshdef->det < detSome) {
            lpshdef->det = detSome;
        }
    }
}

void SetVisPFThings(int16_t iPlr) {
    int16_t  pctCloak;
    int16_t  dy;
    FLEET   *lpfl2;
    int32_t  d2;
    int16_t  j;
    THING   *lpth;
    int32_t  lRadius2;
    THING   *lpthMac;
    int16_t  dx;
    uint16_t grbitPlr;
    PLANET  *lppl2;
    THING   *lpth2;
    int16_t  raMajor;

    if (iPlr == -1) {
        grbitPlr = 0;
    } else {
        grbitPlr = 1 << (iPlr & 0x1f);
    }

    raMajor = GetRaceStat(&rgplr[iPlr], rsMajorAdv);

    if (raMajor == raMassAccel) {
        /* PP (Packet Physics): mineral packets act as scanners */
        lpthMac = lpThings + cThing;
        for (lpth = lpThings; lpth < lpthMac; lpth++) {
            if (lpth->ith != ithMineralPacket || lpth->iplr != iPlr)
                continue;

            /* Packet must have warp speed set (bits 10-13 of thp.wRaw_0000) */
            int16_t iWarp = lpth->thp.iWarp;
            if (iWarp == 0)
                continue;

            lpth->thp.fInclude = 1;

            /* Scanner range = (iWarp + 4)^2 squared */
            int16_t scanBase = iWarp + 4;
            int16_t scanRange = scanBase * scanBase;
            lRadius2 = (uint32_t)scanRange * (uint32_t)scanRange;

            int16_t ptx = lpth->pt.x;
            int16_t pty = lpth->pt.y;

            /* Scan fleets */
            for (j = 0; j < cFleet; j++) {
                lpfl2 = rglpfl[j];
                if (lpfl2 == NULL)
                    break;

                if (lpfl2->fInclude || lpfl2->fDead)
                    continue;

                dx = abs(ptx - lpfl2->pt.x);
                if (dx > scanRange)
                    continue;
                dy = abs(pty - lpfl2->pt.y);
                if (dy > scanRange)
                    continue;

                d2 = (int32_t)dy * dy + (int32_t)dx * dx;
                if (d2 > lRadius2)
                    continue;

                pctCloak = PctCloakFromLpfl(lpfl2);
                if (pctCloak == 0) {
                    MarkFleet(lpfl2, detSome);
                } else {
                    int32_t lEffective = (uint32_t)lRadius2 * (uint32_t)(100 - pctCloak) / 100;
                    lEffective = (uint32_t)lEffective * (uint32_t)(100 - pctCloak) / 100;
                    if (d2 <= lEffective) {
                        MarkFleet(lpfl2, detSome);
                    }
                }
            }

            /* Scan things */
            for (lpth2 = lpThings; lpth2 < lpthMac; lpth2++) {
                if (iPlr == -1)
                    continue;
                if (lpth2->ith != ithMinefield && lpth2->ith != ithMineralPacket && lpth2->ith != ithMysteryTrader && lpth2->ith != ithWormhole)
                    continue;
                if (lpth2->ith == ithMinefield && (lpth2->thm.grbitPlrNow & grbitPlr) != 0)
                    continue;
                if (lpth2->ith == ithMysteryTrader && lpth2->tht.fInclude)
                    continue;
                if (lpth2->ith == ithMineralPacket && lpth2->tht.ptDest.x < 0)
                    continue;
                if (lpth2->ith == ithWormhole && lpth2->thw.fInclude)
                    continue;

                dx = abs(ptx - lpth2->pt.x);
                if (dx > scanRange)
                    continue;
                dy = abs(pty - lpth2->pt.y);
                if (dy > scanRange)
                    continue;

                d2 = (int32_t)dy * dy + (int32_t)dx * dx;
                if (d2 > lRadius2)
                    continue;

                if (lpth2->ith == ithMineralPacket) {
                    lpth2->thp.fInclude = 1;
                LThIncPlr3:
                    if (!rgplr[lpth2->iplr].fInclude) {
                        rgplr[lpth2->iplr].fInclude = 1;
                        rgplr[lpth2->iplr].det = detSome;
                    }
                } else if (lpth2->ith == ithMysteryTrader) {
                    lpth2->tht.fInclude = 1;
                } else if (lpth2->ith == ithWormhole) {
                    if ((lpth2->thw.grbitPlr & grbitPlr) != 0 || d2 <= lRadius2) {
                        lpth2->thw.grbitPlrTrav |= grbitPlr;
                        lpth2->thw.fInclude = 1;
                    }
                } else {
                    /* Minefield */
                    lpth2->thm.grbitPlr |= grbitPlr;
                    lpth2->thm.grbitPlrNow |= grbitPlr;
                    goto LThIncPlr3;
                }
            }

            /* Scan planets */
            for (lppl2 = lpPlanets; lppl2 < lpPlanets + cPlanet; lppl2++) {
                if (lppl2->fInclude && lppl2->det >= detSome)
                    continue;

                dx = abs(rgptPlan[lppl2->id].x - ptx);
                if (dx > scanRange)
                    continue;
                dy = abs(rgptPlan[lppl2->id].y - pty);
                if (dy > scanRange)
                    continue;

                d2 = (int32_t)dy * dy + (int32_t)dx * dx;
                if (d2 > lRadius2)
                    continue;

                /* Check starbase cloak */
                if (lppl2->fStarbase && lppl2->iPlayer != iNoPlayer) {
                    SHDEF  *lpshdefSB = &rglpshdefSB[lppl2->iPlayer][lppl2->isb];
                    int32_t lVisible = lpshdefSB->lVisible;
                    int16_t hiVis = (int16_t)(lVisible >> 16);
                    if (hiVis < 1 && (hiVis < 0 || (uint16_t)lVisible < 10000)) {
                        int32_t lEffPlanet = (uint32_t)lRadius2 * (uint32_t)lVisible / 10000;
                        if (lEffPlanet < d2) {
                            MarkPlanet(lppl2, iPlr, detObscure);
                            continue;
                        }
                    }
                }

                MarkPlanet(lppl2, iPlr, detSome);
            }
        }
    } else if (raMajor == raMines) {
        /* SD (Space Demolition): minefields detect fleets */
        lpthMac = lpThings + cThing;
        for (lpth = lpThings; lpth < lpthMac; lpth++) {
            if (lpth->ith != ithMinefield || lpth->iplr != iPlr)
                continue;

            /* Use the minefield's radius as detection range */
            uint16_t wRadius = (uint16_t)lpth->thm.cMines;
            int16_t  hiRadius = (int16_t)(lpth->thm.cMines >> 16);
            int32_t  lMineRadius2 = lpth->thm.cMines;

            int16_t ptx = lpth->pt.x;
            int16_t pty = lpth->pt.y;

            for (j = 0; j < cFleet; j++) {
                lpfl2 = rglpfl[j];
                if (lpfl2 == NULL)
                    break;

                if (lpfl2->fInclude || lpfl2->fDead || lpfl2->idPlanet != -1)
                    continue;

                dx = abs(ptx - lpfl2->pt.x);
                if ((int16_t)(dx >> 15) > hiRadius || ((int16_t)(dx >> 15) == hiRadius && dx > wRadius))
                    continue;
                dy = abs(pty - lpfl2->pt.y);
                if ((int16_t)(dy >> 15) > hiRadius || ((int16_t)(dy >> 15) == hiRadius && dy > wRadius))
                    continue;

                d2 = (int32_t)(uint32_t)dy * (uint32_t)dy + (int32_t)(uint32_t)dx * (uint32_t)dx;
                if (d2 > lMineRadius2)
                    continue;

                pctCloak = PctCloakFromLpfl(lpfl2);
                if (pctCloak == 0 || Random(100) >= pctCloak) {
                    MarkFleet(lpfl2, detSome);
                }
            }
        }
    }
}

void WriteRtPlr(PLAYER *pplr, uint8_t *pbStore) {
    uint8_t  rgb[sizeof(PLAYER) + 72];
    uint8_t *pb;
    int16_t  cOut;
    int      i;

    if (pbStore == NULL)
        pbStore = rgb;

    if (pplr->fDead)
        pplr->det = detAll;

    memmove(pbStore, pplr, sizeof(PLAYER));

    if (pplr->det == detAll) {
        for (i = 15; i >= 0; i--)
            if (pplr->rgmdRelation[i])
                break;
        i++;
        pb = ((PLAYER *)pbStore)->rgmdRelation;
        *pb++ = (uint8_t)i;
        memmove(pb, pplr->rgmdRelation, i);
        pb += i;
    } else
        pb = pbStore + cbPlayerSome;

    cOut = 31;
    if (*pplr->szName && FCompressUserString(pplr->szName, pb + 1, &cOut)) {
        pb[0] = (char)cOut;
        pb += cOut + 1;
    } else {
        strcpy(pb + 1, pplr->szName);
        pb[0] = 0;
        pb += strlen(pplr->szName) + 2;
    }

    cOut = 31;
    if (*pplr->szNames && FCompressUserString(pplr->szNames, pb + 1, &cOut)) {
        pb[0] = (char)cOut;
        pb += cOut + 1;
    } else {
        strcpy(pb + 1, pplr->szNames);
        pb[0] = 0;
        pb += strlen(pplr->szNames) + 2;
    }

    WriteRt(rtPlr, pb - pbStore, pbStore);
}

void SetVisiblePlanFleet(int16_t iPlr) {
    SetVisPFInit(iPlr);
    if (iPlr == -1) {
        rgplr[0].cPlanet = game.cPlanMax;
    } else {
        if (iPlr != -1) {
            UpdateProgressGauge(pctProgressStepSmall);
        }
        SetVisPFFleets(iPlr);
        if (iPlr != -1) {
            UpdateProgressGauge(pctProgressStepSmall);
        }
        SetVisPFPlanets(iPlr);
        if (iPlr != -1) {
            UpdateProgressGauge(pctProgressStepSmall);
        }
        SetVisPFThings(iPlr);
        SetVisPFFinish(iPlr);
    }
    return;
}
