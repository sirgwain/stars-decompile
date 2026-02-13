
#include "globals.h"
#include "resource.h"
#include "types.h"

#include "file.h"
#include "memory.h"
#include "msg.h"
#include "parts.h"
#include "planet.h"
#include "save.h"
#include "strings.h"
#include "util.h"
#include "utilgen.h"

/* globals */
char    aMSGCmpr[22836] = {0};
uint8_t acMSG[387] = {
    0x62, 0xa5, 0x7c, 0x63, 0x69, 0x99, 0x6c, 0x9b, 0x7c, 0x83, 0x2d, 0x84, 0x5a, 0x53, 0x6f, 0x49, 0x43, 0x44, 0x31, 0x4f, 0x5e, 0x6e, 0x6d, 0x5f, 0x37, 0x37,
    0x54, 0x3d, 0x70, 0x69, 0x56, 0x53, 0x67, 0x65, 0x4b, 0x59, 0x84, 0x42, 0x56, 0x1a, 0xa6, 0x9e, 0xcc, 0x26, 0x24, 0x24, 0x20, 0x2f, 0x37, 0x4f, 0x58, 0x6b,
    0x73, 0x26, 0x28, 0x22, 0x24, 0x2e, 0x30, 0x47, 0xb1, 0x98, 0x48, 0x2e, 0x5f, 0x69, 0x33, 0x2f, 0x34, 0x30, 0x5d, 0x97, 0x71, 0xa9, 0x5f, 0x98, 0x6e, 0xc0,
    0x29, 0x69, 0x89, 0x71, 0x6f, 0x87, 0x8c, 0xaa, 0xba, 0xb5, 0x6c, 0x56, 0x57, 0x49, 0xed, 0xee, 0x75, 0x4e, 0x33, 0x36, 0x4a, 0x5b, 0x6b, 0x6e, 0x75, 0x79,
    0x97, 0xa6, 0x42, 0x4a, 0x59, 0x71, 0x84, 0x87, 0x8f, 0x9e, 0xba, 0xc9, 0x45, 0x7c, 0x81, 0x6c, 0xf4, 0x26, 0x2a, 0x43, 0x2f, 0x5b, 0x74, 0xe1, 0xd6, 0xb3,
    0xc7, 0x6e, 0x7b, 0x91, 0x90, 0xb1, 0xc6, 0xd5, 0xca, 0x55, 0x82, 0x78, 0x7c, 0x42, 0x3a, 0x54, 0x62, 0x71, 0x6d, 0x61, 0x60, 0x6e, 0x7d, 0x79, 0x7b, 0x83,
    0x7a, 0x9d, 0xb5, 0xaf, 0x6c, 0x6c, 0x87, 0xa2, 0x8d, 0x8b, 0xb8, 0x9d, 0x84, 0x78, 0x5d, 0x9e, 0x82, 0xb8, 0xc5, 0x85, 0x6a, 0x8d, 0x72, 0x8b, 0x70, 0xa6,
    0xad, 0xd3, 0x5c, 0x5c, 0xcc, 0x62, 0x84, 0x6f, 0x4c, 0x7d, 0x7b, 0x5e, 0x41, 0x1e, 0x30, 0x3a, 0x94, 0x91, 0x42, 0x39, 0xa2, 0x99, 0x3f, 0x1c, 0x73, 0x50,
    0xfe, 0x73, 0xcb, 0x48, 0x6c, 0x6e, 0xdb, 0xdd, 0x7b, 0x99, 0x5e, 0xae, 0x7f, 0x4b, 0x4c, 0x78, 0x42, 0x5b, 0x83, 0x73, 0x7a, 0xc1, 0x89, 0xab, 0xad, 0xa8,
    0xac, 0xa8, 0x68, 0x64, 0x7e, 0x69, 0x78, 0x78, 0x9d, 0x54, 0x55, 0x65, 0x66, 0x21, 0x90, 0x65, 0x4f, 0x7b, 0x57, 0x9e, 0x93, 0x38, 0xcc, 0xf6, 0xc1, 0xd3,
    0xc6, 0xb6, 0x8d, 0x90, 0xb0, 0xdf, 0x7e, 0xc2, 0xb6, 0x7f, 0xd4, 0xc6, 0x92, 0x8c, 0x55, 0x63, 0x64, 0x99, 0x82, 0x8f, 0x97, 0x26, 0x11, 0x36, 0x78, 0x72,
    0x4f, 0x5e, 0x5d, 0xab, 0xb5, 0x57, 0x5d, 0x59, 0x24, 0x2c, 0xb7, 0xb0, 0x99, 0x6f, 0x3b, 0x4a, 0x48, 0x84, 0x84, 0x53, 0x51, 0x39, 0x37, 0xa3, 0x97, 0x4e,
    0x5f, 0xe4, 0x7a, 0x65, 0x94, 0x96, 0xd8, 0xd2, 0x54, 0x55, 0xeb, 0xec, 0x6e, 0xb3, 0xb2, 0x78, 0x40, 0x5a, 0x7e, 0x85, 0x3c, 0x2d, 0x1e, 0x9f, 0xc1, 0x87,
    0x61, 0x38, 0x38, 0x3f, 0x38, 0xb4, 0x7c, 0x93, 0x39, 0x48, 0x59, 0x63, 0x72, 0x3e, 0xa2, 0xa1, 0x3d, 0xb0, 0xa7, 0x53, 0x44, 0x47, 0x5b, 0x6c, 0x7c, 0x7f,
    0x86, 0x8a, 0xa8, 0xb7, 0x49, 0x51, 0x60, 0x78, 0x8b, 0x8e, 0x96, 0xa5, 0xc1, 0xd0, 0x59, 0x54, 0x53, 0x46, 0x46, 0x4c, 0xce, 0x6f, 0x82};
char    rgMSGLookupTable[72] = " eotasnirldh\\ucpfybm.gvwk,YT0'AzPMSXFxOIj%UVL-CDEN!GHq*W()25:QR1B/46Z78?";
int16_t aiMSGChunkOffset[7] = {0, 2854, 6582, 10933, 14692, 18914, 22612};
char    rgcMsgArgs[387] = {4, 5, 3, 4, 4, 2, 2, 4, 2, 3, 1, 1, 2, 1, 4, 3, 3, 3, 2, 2, 4, 4, 3, 3, 4, 4, 4, 3, 3, 3, 3, 4, 4, 3, 3, 1, 1, 5, 3, 1, 2, 2, 1, 6,
                           6, 6, 6, 2, 3, 3, 4, 3, 4, 1, 2, 1, 2, 1, 2, 4, 5, 5, 1, 1, 1, 1, 5, 5, 5, 5, 7, 7, 7, 7, 5, 5, 5, 5, 1, 2, 3, 1, 3, 2, 3, 2, 2, 1,
                           1, 4, 4, 2, 6, 6, 3, 3, 3, 2, 3, 4, 4, 4, 4, 4, 5, 5, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 2, 2, 2, 1, 3, 5, 5, 4, 3, 6, 2, 0, 0, 0, 0, 1,
                           1, 1, 1, 2, 3, 4, 4, 2, 2, 5, 5, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 6, 4, 4, 5, 5, 7, 5, 5, 6, 6, 4, 5, 5, 6, 7, 1, 2, 2, 2, 1, 2, 1,
                           1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 3, 1, 0, 2, 6, 1, 1, 3, 7, 3, 3, 5, 6, 7, 6, 4, 5, 6, 5, 2, 3, 2, 3, 1, 1, 2, 2, 4, 5, 6, 5, 6, 2, 4,
                           2, 4, 3, 1, 2, 1, 4, 3, 4, 4, 3, 3, 4, 4, 4, 5, 4, 4, 6, 5, 5, 5, 1, 2, 7, 1, 1, 2, 1, 1, 3, 2, 1, 2, 2, 2, 0, 1, 1, 0, 1, 2, 2, 3,
                           1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 5, 5, 6, 6, 0, 1, 5, 1, 1, 2, 2, 2, 2, 2, 6, 6, 2, 5, 5, 3, 3, 3, 1, 1, 1, 4, 3, 3, 1, 1, 4, 4, 4,
                           4, 2, 3, 1, 1, 4, 2, 2, 4, 5, 6, 7, 4, 4, 6, 6, 5, 3, 4, 3, 1, 1, 2, 1, 1, 2, 2, 2, 1, 2, 1, 0, 1, 1, 2, 3, 4, 2, 4, 3, 2, 2, 2, 5,
                           6, 7, 4, 5, 6, 1, 3, 2, 3, 4, 4, 4, 4, 4, 5, 5, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 3, 3, 2, 2, 1, 1, 2, 4, 1}; /* 1030:5b0e */

extern const char *const aMSGUncompressed[];

/* functions */
int16_t FFindPlayerMessage(int16_t iPlr, int16_t iMsg, int16_t iObj) {
    uint8_t *lpb = (uint8_t *)lpMsg;
    uint8_t *lpbMax = (uint8_t *)lpMsg + (uint32_t)imemMsgCur * 2u;

    for (;;) {
        if (lpb >= lpbMax) {
            return 0;
        }

        if (((lpb[0] & 0x0F) == (uint8_t)iPlr) && (((*(uint16_t *)(lpb + 1)) & 0x01FFu) == (uint16_t)iMsg) && (*(int16_t *)(lpb + 3) == iObj)) {
            return 1;
        }

        lpb += (lpb[0] >> 4) + 5u;
    }
}

int16_t FGetNMsgbig(int16_t iMsg, MSGBIG *pmb) {
    const uint8_t *lpb;
    const uint8_t *end;

    if (iMsg < 0 || iMsg >= cMsg || pmb == NULL) {
        return 0;
    }

    lpb = (const uint8_t *)lpMsg;
    end = (const uint8_t *)lpMsg + imemMsgCur;

    /* Walk forward iMsg records; when iMsg==0, decode into *pmb. */
    for (;;) {
        if (lpb + sizeof(MSGHDR) > end) {
            /* Shouldn’t happen if cMsg/imemMsgCur are consistent. */
            return 0;
        }

        const MSGHDR *mh = (const MSGHDR *)lpb;
        uint16_t      idm = (uint16_t)mh->iMsg; /* 9-bit id */
        uint16_t      u = (uint16_t)mh->grWord; /* 7-bit “param is word” bitfield */
        lpb += sizeof(MSGHDR);

        if (iMsg == 0) {
            pmb->iMsg = (int16_t)idm;
            pmb->wGoto = mh->wGoto;
            for (int k = 0; k < 7; k++)
                pmb->rgParam[k] = 0;
        }

        /* Param count comes from rgcMsgArgs[idm] (asm proves this). */
        uint8_t cParam = 0;
        if (idm < (uint16_t)sizeof(rgcMsgArgs)) {
            cParam = (uint8_t)rgcMsgArgs[idm];
        }

        /* Safety: MSGBIG only has 7 params. Stars messages should never exceed that. */
        if (cParam > 7) {
            cParam = 7;
        }

        for (uint8_t i = 0; i < cParam; ++i) {
            if (lpb >= end)
                return 0;

            if (iMsg == 0) {
                if ((u & 1u) == 0) {
                    /* byte param */
                    pmb->rgParam[i] = (int16_t)(uint16_t)(*lpb);
                } else {
                    /* word param */
                    if (lpb + 2 > end)
                        return 0;
                    pmb->rgParam[i] = *(const int16_t *)lpb;
                }
            }

            lpb += ((u & 1u) ? 2u : 1u);
            u >>= 1;
        }

        if (iMsg == 0) {
            return 1;
        }

        /* next record */
        --iMsg;
    }
}

int16_t PackageUpMsg(uint8_t *pb, int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6,
                     int16_t p7) {
    int16_t *pi;
    int16_t  i;
    uint16_t grbit;
    MSGTURN *lpmt;
    uint8_t *lpb;
    uint8_t *lpbBase;

    if (iPlr == -1)
        return 0;

    /* gate message creation based on player state / message kind */
    {
        const PLAYER *pplr = &rgplr[iPlr];

        if (!((pplr->fAi == 0) || (pplr->idAi == 7) || (iMsg == idmHasBombedKillingOffEnemyColonists) ||
              (iMsg == idmHaveAttackedFirstRateStormTroopersThough) || (iMsg == idmColonistsHaveDiedOffLongerControlPlanet) ||
              (iMsg == idmColonistsHaveJumpedShipLongerControlPlanet))) {
            return 0;
        }
    }

    /* ensure we have room for worst-case (header + 7 params as words) */
    if ((uint16_t)(imemMsgCur + cbPackedMsgSize) > cbPackedMsgAllocSize)
        return -1;

    lpmt = (MSGTURN *)pb;

    /* write header */
    lpmt->iPlr = (uint8_t)iPlr;
    lpmt->msghdr.iMsg = (uint16_t)iMsg; /* 9-bit field */
    lpmt->msghdr.wGoto = iObj;

    /* pack params */
    lpbBase = pb + sizeof(MSGTURN); /* == pb + 5 */
    lpb = lpbBase;

    grbit = 1;

    /* IMPORTANT: params are not guaranteed to be contiguous on modern ABIs. */
    {
        int16_t rgParam[7] = {p1, p2, p3, p4, p5, p6, p7};
        pi = rgParam;

        for (i = 0; i < (int16_t)((const uint8_t *)rgcMsgArgs)[(uint16_t)iMsg]; i++) {
            if (((uint16_t)*pi & 0xFF00u) == 0u) {
                /* param fits in byte */
                *lpb++ = (uint8_t)*pi;
            } else {
                /* param needs a word; mark it in grWord and write 16-bit value */
                lpmt->msghdr.grWord |= grbit;

                *(uint16_t *)lpb = (uint16_t)*pi; /* little-endian write */
                lpb += 2;
            }

            pi++;
            grbit <<= 1;
        }
    }

    /* cbParams is number of bytes written after the MSGTURN header */
    lpmt->cbParams = (uint8_t)(lpb - lpbBase);

    /* return total packed size */
    return (int16_t)(lpb - pb);
}

char *PszGetMessageN(int16_t iMsg) {
    MSGBIG mb;

    if (FGetNMsgbig(iMsg, &mb) == 0) {
        szMsgBuf[0] = '\0';
        return szMsgBuf;
    }
    return PszFormatMessage(mb.iMsg, mb.rgParam);
}

int16_t IdmGetMessageN(int16_t iMsg) {
    MSGBIG mb;
    if (!FGetNMsgbig(iMsg, &mb)) {
        return -1;
    }
    return mb.iMsg;
}

int16_t FFinishPlrMsgEntry(int16_t dInc) {
    uint8_t *lpbMsg;
    int16_t  i;
    int16_t  cbNew;
    int16_t  iPlrTo;
    MSGPLR  *lpmpCur;
    MSGPLR  *lpmpPrev;
    int16_t  cb;

    /* TODO: implement */
    return 0;
}

void MarkPlanetsPlayerLost(int16_t iPlayer) {
    uint8_t *lpbMax;
    PLANET  *lppl;
    uint8_t *lpbT;
    uint16_t w;
    uint8_t *lpb;

    lpb = (uint8_t *)lpMsg;
    lpbMax = (uint8_t *)lpMsg + imemMsgCur;

    // TODO: update these iMsg constants to enums
    while (lpb < lpbMax) {
        if ((*lpb & 0xf) == iPlayer) {
            uint16_t iMsg = *(uint16_t *)(lpb + 1) & 0x1ff;
            if (iMsg == 7 || iMsg == 0x23 || iMsg == 0x40) {
                w = *(uint16_t *)(lpb + 3);
            } else if (iMsg == 0x8f) {
                uint16_t grWord = *(uint16_t *)(lpb + 1) >> 9;
                lpbT = lpb + 6 + ((grWord & 1) == 1);
                if ((grWord & 2) == 0) {
                    w = (uint16_t)*lpbT;
                } else {
                    w = *(uint16_t *)lpbT;
                }
            } else {
                goto LNext;
            }
            lppl = LpplFromId((int16_t)w);
            if (lppl != NULL) {
                MarkPlanet(lppl, iPlayer, 3);
            }
        }
    LNext:
        lpb += (*lpb >> 4) + 5;
    }
}

char *PszFormatMessage(MessageId idm, int16_t *pParams) {
    char *psz;

    psz = PszGetCompressedMessage(idm);
    psz = PszFormatString(psz, pParams);
    return psz;
}

void SetFilteringGroups(MessageId idm, int16_t fSet) {
    int16_t i;
    uint8_t bit = (fSet != 0);
    int16_t companion;

    /* Set/clear bit for idm itself */
    bitfMsgFiltered[idm >> 3] = (bitfMsgFiltered[idm >> 3] & ~(1 << (idm & 7))) | (bit << (idm & 7));

    if (idm == idmHaveBuiltFactory || idm == idmHaveBuiltFactories) {
        companion = idm ^ 3;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm == idmHaveBuiltMine || idm == idmHaveBuiltMines) {
        companion = idm ^ 0xF;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm == idmHaveBuiltDefenseOutpost || idm == idmHaveBuiltDefenseOutposts) {
        companion = idm ^ 3;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm >= idmHasLoaded && idm <= idmHasBeamed2) {
        for (i = idmHasLoaded; i <= idmHasBeamed2; i++) {
            bitfMsgFiltered[i >> 3] = (bitfMsgFiltered[i >> 3] & ~(1 << (i & 7))) | (bit << (i & 7));
        }
    } else if (idm == idmStarbaseHasBuiltNew || idm == idmStarbaseHasBuiltNewShips) {
        companion = idm ^ 0x1F;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm == idmSuccessfullyTransferred || idm == idmSuccessfullyTransferred2) {
        companion = idm ^ 1;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm == idmSuccessfullyReceived || idm == idmSuccessfullyReceived2) {
        companion = idm ^ 1;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm == idmAttemptedTransferSuccessfullyReceived || idm == idmAttemptedTransferColonistsSuccessfullyReceivedRe) {
        companion = idm ^ 1;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm == idmReceivedHoweverSentRemainderLostSpace || idm == idmReceivedHoweverColonistsSentRemainsOtherColonist) {
        companion = idm ^ 1;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm == idmAttemptedTransferNoneSuccessfullyReceived || idm == idmAttemptedTransferNoneColonistsSuccessfullyReceiv) {
        companion = idm ^ 1;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm == idmAttemptedReceiveHoweverLostDeepSpace || idm == idmAttemptedReceiveHoweverNoneColonistsSuccessfully) {
        companion = idm ^ 1;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm >= idmHasBombedKillingColonists && idm <= idmHasBombedKillingColonistsDestroyingDefensesFacto) {
        for (i = idmHasBombedKillingColonists; i <= idmHasBombedKillingColonistsDestroyingDefensesFacto; i++) {
            bitfMsgFiltered[i >> 3] = (bitfMsgFiltered[i >> 3] & ~(1 << (i & 7))) | (bit << (i & 7));
        }
    } else if (idm >= idmHasBombedKillingColonists2 && idm <= idmHasBombedKillingColonistsDestroyingDefensesFacto3) {
        for (i = idmHasBombedKillingColonists2; i <= idmHasBombedKillingColonistsDestroyingDefensesFacto3; i++) {
            bitfMsgFiltered[i >> 3] = (bitfMsgFiltered[i >> 3] & ~(1 << (i & 7))) | (bit << (i & 7));
        }
    } else if (idm == idmHasLoaded2 || idm == idmHasBeamed3) {
        companion = idm ^ 3;
        bitfMsgFiltered[companion >> 3] = (bitfMsgFiltered[companion >> 3] & ~(1 << (companion & 7))) | (bit << (companion & 7));
    } else if (idm > idmHasBombedKillingColonists3 && idm < idmHomePlanetPeopleReadyLeaveNestExplore) {
        for (i = idmBattleTookPlaceDestroyedTakingDamage; i < idmHomePlanetPeopleReadyLeaveNestExplore; i++) {
            bitfMsgFiltered[i >> 3] = (bitfMsgFiltered[i >> 3] & ~(1 << (i & 7))) | (bit << (i & 7));
        }
    }
}

int16_t FSendPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7) {
    uint8_t  rgbWork[40];
    int16_t  cbMsg;
    uint8_t *lpb;

    cbMsg = PackageUpMsg(rgbWork, iPlr, iMsg, iObj, p1, p2, p3, p4, p5, p6, p7);

    /* ASM behavior:
       - cbMsg > 0: appended => return 1
       - cbMsg == 0: gated off / not queued => return 1
       - cbMsg < 0: no room / failure => return 0
    */
    if (cbMsg <= 0)
        return (cbMsg == 0) ? 1 : 0;

    /* In Win16 this was a far pointer add: lpMsg:imemMsgCur.
       In the port, lpMsg is a flat pointer to the message buffer. */
    lpb = (uint8_t *)lpMsg + (uint16_t)imemMsgCur;

    memmove(lpb, rgbWork, (size_t)(uint16_t)cbMsg);

    imemMsgCur = (int16_t)((uint16_t)imemMsgCur + (uint16_t)cbMsg);
    cMsg = (int16_t)((uint16_t)cMsg + 1u);

    return 1;
}

int16_t FSendPlrMsg2(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2) { return FSendPlrMsg(iPlr, iMsg, iObj, p1, p2, 0, 0, 0, 0, 0); }

int16_t FSendPlrMsg2XGen(int16_t fPrepend, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2) {
    int16_t  sVar1;
    MSGHDR  *pmsghdr;
    uint16_t cSize;
    uint8_t *pb;
    uint16_t grbit;
    int16_t  i;
    int16_t *pi;
    uint8_t  rgb[64];

    /* Ensure room for worst-case packed message. */
    if ((uint16_t)(imemMsgCur + (uint16_t)cbPackedMsgSize) > (uint16_t)cbPackedMsgAllocSize)
        return 0;

    pmsghdr = (MSGHDR *)rgb;

    /* Set message id; clear grWord initially; store goto/object. */
    pmsghdr->iMsg = (uint16_t)iMsg;
    pmsghdr->grWord = 0;
    pmsghdr->wGoto = iObj;

    /* Mark this message as “sent” in the bitset. */
    ((uint8_t *)bitfMsgSent)[(uint16_t)iMsg >> 3] |= (uint8_t)(1u << ((uint8_t)iMsg & 7u));

    pb = rgb + sizeof(MSGHDR);
    grbit = 1;

    /* IMPORTANT: params are not guaranteed to be contiguous on modern ABIs. */
    {
        int16_t rgParam[2] = {p1, p2};
        pi = rgParam;

        for (i = 0; i < (int16_t)((const uint8_t *)rgcMsgArgs)[(uint16_t)iMsg]; i++) {
            if (((uint16_t)*pi & 0xFF00u) == 0u) {
                *pb++ = (uint8_t)*pi;
            } else {
                pmsghdr->grWord |= grbit;
                *(uint16_t *)pb = (uint16_t)*pi; /* little-endian */
                pb += 2;
            }

            pi++;
            grbit <<= 1;
        }
    }

    cSize = (uint16_t)(pb - rgb);

    if (fPrepend == 0) {
        /* append at end */
        memmove((uint8_t *)lpMsg + (uint16_t)imemMsgCur, rgb, (size_t)cSize);
    } else {
        /* prepend: shift existing messages forward by cSize, then copy new to front */
        memmove((uint8_t *)lpMsg + cSize, (uint8_t *)lpMsg, (size_t)(uint16_t)imemMsgCur);
        memmove((uint8_t *)lpMsg, rgb, (size_t)cSize);
    }

    imemMsgCur = (int16_t)((uint16_t)imemMsgCur + cSize);
    cMsg = (int16_t)((uint16_t)cMsg + 1u);

    iMsgCur = -1;
    iMsgCur = IMsgNext(0);

    sVar1 = 1;
    return sVar1;
}

void ReadPlayerMessages(void) {
    MemJump  env;
    MemJump *penvMemSav = penvMem;

    // Stage 1: append rt==0x0c payload blocks into lpMsg
    uint16_t bytesAppended = 0;
    bool     oomHappened = false;

    uint8_t *writeBase = (uint8_t *)lpMsg + imemMsgCur;

    while (hdrCur.rt == rtMsg) { // was: (wFlags >> 10) == 0x0c
        uint16_t cb = hdrCur.cb; // was: (wFlags & 0x03ff)

        if (cb != 0) {
            // Preserve the original weird bounds check shape exactly
            int32_t cur = (int32_t)(uint16_t)(imemMsgCur + bytesAppended);
            int32_t limit = (int32_t)(-(int32_t)cb - 0x38);
            if (cur < limit) {
                memmove(writeBase + bytesAppended, rgbCur, cb);
                bytesAppended = (uint16_t)(bytesAppended + cb);
            }
        }

        ReadRt();
    }

    imemMsgCur = (uint16_t)(imemMsgCur + bytesAppended);

    // Stage 2: walk the newly appended bytes and parse MSGHDR + arg payloads
    uint8_t *p = writeBase;
    uint8_t *pEnd = writeBase + bytesAppended;

    while (p < pEnd) {
        MSGHDR *mh = (MSGHDR *)p;

        // bitfMsgSent[msgId] = 1
        uint16_t msgId = (uint16_t)mh->iMsg; // was: (wFlags & 0x01ff)
        bitfMsgSent[msgId >> 3] |= (uint8_t)(1u << (msgId & 7));

        cMsg++;

        // After MSGHDR comes a packed args blob; bit 0 of grWord controls +1 byte per arg
        uint16_t argBits = (uint16_t)mh->grWord; // was: (wFlags >> 9)
        p += sizeof(MSGHDR);

        for (int16_t ai = 0; ai < (int16_t)rgcMsgArgs[msgId]; ai++) {
            p += 1u + (uint8_t)(argBits & 1u);
            argBits >>= 1;
        }
    }

    // Stage 3: find tail of incoming MSGPLR list
    MSGPLR *tail = (MSGPLR *)&vlpmsgplrIn;
    while (tail->lpmsgplrNext != NULL) {
        tail = tail->lpmsgplrNext;
    }

    // Stage 4: guarded alloc loop for rt==0x28 records
    penvMem = &env;

    if (setjmp(env.env) != 0) {
        oomHappened = true;
        penvMem = penvMemSav;
    }

    while (true) {
        if (hdrCur.rt != rtPlrMsg) { // was: (wFlags >> 10) != 0x28
            break;
        }

        if (!oomHappened) {
            uint16_t cb = hdrCur.cb; // was: (wFlags & 0x03ff)

            MSGPLR *node = (MSGPLR *)LpAlloc(cb, htPlrMsg);
            tail->lpmsgplrNext = node;
            tail = node;

            memcpy(node, rgbCur, cb);
            tail->lpmsgplrNext = NULL;

            vcmsgplrIn++;
        }

        ReadRt();
    }

    iMsgCur = -1;
    iMsgCur = IMsgNext(0);
}

int16_t FSendPrependedPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7) {
    uint8_t  rgbWork[40];
    uint16_t cbMsg;

    cbMsg = PackageUpMsg(rgbWork, iPlr, iMsg, iObj, p1, p2, p3, p4, p5, p6, p7);
    if (cbMsg < 1) {
        return cbMsg == 0;
    }
    memmove((uint8_t *)lpMsg + cbMsg, lpMsg, imemMsgCur);
    memmove(lpMsg, rgbWork, cbMsg);
    imemMsgCur = imemMsgCur + cbMsg;
    cMsg++;
    return 1;
}

void MarkPlayersThatSentMsgs(int16_t iPlayer) {
    MSGPLR *lpmp;

    if (iPlayer == -1)
        return;

    for (lpmp = vlpmsgplrOut; lpmp != NULL; lpmp = lpmp->lpmsgplrNext) {
        if ((lpmp->iPlrTo == 0 && lpmp->iPlrFrom != iPlayer) || (lpmp->iPlrTo - 1 == iPlayer && !rgplr[lpmp->iPlrFrom].fInclude)) {
            rgplr[lpmp->iPlrFrom].fInclude = 1;
            rgplr[lpmp->iPlrFrom].det = 3;
        }
    }
}

void ResetMessages(void) {
    imemMsgCur = 0;
    iMsgCur = -1;
    cMsg = 0;
    iMsgSendCur = 0;

    memset(bitfMsgSent, 0, sizeof(bitfMsgSent));
    memset(bitfMsgFiltered, 0, sizeof(bitfMsgFiltered));

    vlpmsgplrIn = NULL;
    vlpmsgplrOut = NULL;
    vcmsgplrIn = 0;
    vcmsgplrOut = 0;
}

int16_t FRemovePlayerMessage(int16_t iPlr, MessageId iMsg, int16_t iObj) {
    uint8_t *lpb;
    uint8_t *lpbMax;
    int16_t  cDel = 0;

    lpbMax = (uint8_t *)lpMsg + (uint16_t)imemMsgCur;

    for (lpb = (uint8_t *)lpMsg; lpb < lpbMax; lpb += (int16_t)((lpb[0] >> 4) + 5)) {
        MSGHDR *pmsghdr = (MSGHDR *)(lpb + 1);
        int16_t iObjRec = *(int16_t *)(lpb + 3);

        if (((lpb[0] & 0x0F) == (uint8_t)iPlr) && ((uint16_t)pmsghdr->iMsg == (uint16_t)iMsg) && (iObjRec == iObj)) {
            cDel++;
            pmsghdr->iMsg = 0x01FFu; /* deleted marker */
        }
    }

    return cDel;
}

char *PszFormatString(char *pszFormat, int16_t *pParamsReal) {
    char    *pch;
    char    *pchT;
    int16_t *pParams;
    uint16_t w;
    int16_t  i;
    int16_t  c;
    int16_t  cOut;
    int16_t  iMineral;
    char     szBuf[480];

    iMineral = -1;
    pParams = pParamsReal;
    pch = szMsgBuf;

    for (;;) {
        char esc;

        if (*pszFormat == '\0') {
            *pch = '\0';
            return szMsgBuf;
        }

        if (*pszFormat != '\\') {
            *pch++ = *pszFormat++;
            continue;
        }

        /* escape */
        pszFormat++;
        esc = *pszFormat;

        switch (esc) {
        case 'E': /* Env var */
            pchT = PszCalcEnvVar((int16_t)((uint16_t)pParams[0] >> 8), (int16_t)(pParams[0] & 0xff));
            break;

        case 'F': /* Fleet name from word */
            pchT = PszFleetNameFromWord((uint16_t)pParams[0]);
            break;

        case 'G': /* String id offset by idsMineField */
            w = (uint16_t)pParams[0];
            c = (int16_t)CchGetString((int16_t)(w + idsMineField), pch);
            pch += c;
            pParams += 1;
            pszFormat++;
            continue;

        case 'I': /* Compressed string idsDecreased + param */
            pchT = PszGetCompressedString((int16_t)(pParams[0] + idsDecreased));
            break;

        case 'L':
        case 'l': /* Player name with flags in param; 'L' capitalizes */
            pchT = PszPlayerName((int16_t)(pParams[0] & 15), (int16_t)(esc == 'L'), (int16_t)((pParams[0] & 0x10) != 0), (int16_t)((pParams[0] & 0x20) != 0),
                                 (int16_t)((pParams[0] & 0x00c0) >> 6), (PLAYER *)0);
            break;

        case 'M': /* rgszMineField / table at 0x1120:04f2 */
            pchT = rgszMineField[pParams[0]];
            break;

        case 'O': /* Player name from packed owner bits */
            w = (uint16_t)pParams[0];
            w = (uint16_t)((w >> 9) & 15);
            pchT = PszPlayerName((int16_t)w, 0, 0, 0, 0, (PLAYER *)0);
            break;

        case 'P': { /* Percent, prints x% or x.y% depending on remainder */
            int16_t v = pParams[0];
            int16_t whole = (int16_t)(v / 100);
            int16_t frac = (int16_t)(v - (int16_t)(whole * 100));

            if (frac != 0) {
                if (frac < 0)
                    frac = (int16_t)-frac;
                /* s_%d.%d%%_1120_01c8 */
                c = (int16_t)sprintf(pch, "%d.%d%%", whole, frac);
            } else {
                /* s__%dkT_1120_01b8 (name from your symbol dump; string is "%d%%" style) */
                c = (int16_t)sprintf(pch, "%dkT", whole);
            }

            pch += c;
            pParams += 1;
            pszFormat++;
            continue;
        }

        case 'S': /* "of <player>'s origin" unless self */
            if (pParams[0] != idPlayer) {
                (void)CchGetString(idsOf2, szBuf);
                pchT = PszPlayerName(pParams[0], 0, 0, 0, 0, (PLAYER *)0);
                strcat(szBuf, pchT);
                pchT = PszGetCompressedString(idsOrigin);
                strcat(szBuf, pchT);
                pchT = szBuf;
                break;
            }
            /* do nothing but consume */
            pParams += 1;
            pszFormat++;
            continue;

        case 'U':
        case 'V':
        case 'v': { /* 32-bit number, maybe append units/mineral name */
            int32_t  l;
            uint16_t lo = (uint16_t)pParams[0];
            uint16_t hi = (uint16_t)pParams[1];

            l = (int32_t)((uint32_t)lo | ((uint32_t)hi << 16));
            pParams += 2;

            c = (int16_t)sprintf(pch, PCTLD, l);
            pch += c;

            if (esc != 'v') {
                if (esc == 'V') {
                    iMineral = pParams[0];
                    /* NOTE: original does NOT consume here unless 'V' */
                    /* it reads iMineral from current pParams and then falls through */
                }
                /* vrgszUnits (comment in your decompile) */
                pchT = vrgszUnits[iMineral];
                strcpy(pch, pchT);
                pch += (int16_t)strlen(pchT);
            }

            pszFormat++;
            continue;
        }

        case 'X': /* explicit do nothing */
            pParams += 1;
            pszFormat++;
            continue;

        case 'Z': { /* player bitmask -> list of names, with "and" */
            w = (uint16_t)pParams[0];

            if (w != 0) {
                if (((w - 1) & w) == 0) {
                    c = 0;
                    while ((w & 1) == 0) {
                        w >>= 1;
                        c++;
                    }
                    pchT = PszPlayerName(c, 0, 1, 1, 0, (PLAYER *)0);
                    break;
                }

                cOut = 0;
                for (i = 0; i < game.cPlayer; i++) {
                    if ((w & 1) != 0) {
                        if (cOut > 0) {
                            if ((w & 0xfffe) == 0) {
                                c = (int16_t)CchGetString(idsAnd, pch);
                                pch += c;
                            } else {
                                *pch++ = ',';
                                *pch++ = ' ';
                            }
                        }

                        pchT = PszPlayerName(i, 0, 1, 1, 0, (PLAYER *)0);
                        strcpy(pch, pchT);
                        pch += (int16_t)strlen(pchT);
                        cOut++;
                    }
                    w >>= 1;
                }

                /* consume and continue */
                pParams += 1;
                pszFormat++;
                continue;
            }

            /* consume and continue */
            pParams += 1;
            pszFormat++;
            continue;
        }

        case 'e': /* table at 0x1120:047e */
            pchT = rgszPlanetAttr[pParams[0]];
            break;

        case 'f':
        case 'h':
        case 'r':
        case 't':
        case 'y': {
            /* base path */
            strcpy(pch, szBase);
            pch += (int16_t)strlen(szBase);

            if (esc == 'f') {
                if (idPlayer == -1) {
                    /* ".x%d" then fall into DoInt */
                    c = (int16_t)sprintf(pch, ".x%d", (int)(idPlayer + 1));
                } else {
                    /* ".m%d" */
                    c = (int16_t)sprintf(pch, ".m%d", (int)(idPlayer + 1));
                }
                pch += c;
                pParams += 1;
                pszFormat++;
                continue;
            }

            if (esc == 'h') {
                strcat(pch, ".h");
                pch += 4;
                pszFormat++;
                continue;
            }

            if (esc == 'r') {
                c = (int16_t)sprintf(pch, ".h%d", (int)(idPlayer + 1));
                pch += c;
                pParams += 1;
                pszFormat++;
                continue;
            }

            if (esc == 't') {
                if (idPlayer == -1) {
                    strcat(pch, ".hst");
                    pch += 4;
                } else {
                    c = (int16_t)sprintf(pch, ".m%d", (int)(idPlayer + 1));
                    pch += c;
                    pParams += 1;
                }
                pszFormat++;
                continue;
            }

            /* '.xy' */
            strcat(pch, ".xy");
            pch += 3;
            pszFormat++;
            continue;
        }

        case 'g': /* thing name */
            pchT = PszGetThingName(pParams[0]);
            break;

        case 'i': /* int */
            c = (int16_t)sprintf(pch, PCTD, (int)pParams[0]);
            pch += c;
            pParams += 1;
            pszFormat++;
            continue;

        case 'j': /* compressed string idsEnergy + param */
            pchT = PszGetCompressedString((int16_t)(pParams[0] + idsEnergy));
            break;

        case 'k': { /* part name from 2 params */
            PART     part;
            uint16_t w1 = (uint16_t)pParams[0];
            uint16_t w2 = (uint16_t)pParams[1];

            part.hs.grhst = (HullSlotType)w1;
            part.hs.iItem = (uint8_t)(w2 & 0xff);
            part.hs.cItem = (uint8_t)((w2 >> 8) & 0xff);
            part.pcom = 0;

            pParams += 2;

            (void)FLookupPart(&part);

            pchT = (char *)((uint8_t *)part.pcom + hstArmor);
            strcpy(pch, pchT);
            pch += (int16_t)strlen(pchT);

            pszFormat++;
            continue;
        }

        case 'm': /* mineral name table at 0x1120:04cc */
            iMineral = pParams[0];
            pchT = rgszMinerals[iMineral];
            break;

        case 'n': /* loc name, thing name, or planet/fleet depending on sentinel */
            if (pParams[0] == -2) {
                pParams += 1;
                pchT = PszGetThingName(pParams[0]);
                break;
            }
            if (pParams[0] == -1) {
                pParams += 1;
                /* fall through to 'o' behavior using new current param */
                if (((uint16_t)pParams[0] & 0x8000) != 0) {
                    w = (uint16_t)pParams[0] | 0x8000;
                    pchT = PszGetFleetName((int16_t)w);
                } else {
                    pchT = PszGetPlanetName(pParams[0]);
                }
                break;
            }

            pchT = PszGetLocName(grobjNone, -1, pParams[0], pParams[1]);
            pParams += 1; /* net +2 with the consume below */
            break;

        case 'o': /* planet-or-fleet depending on high bit */
            if (((uint16_t)pParams[0] & 0x8000) != 0) {
                w = (uint16_t)pParams[0] | 0x8000;
                pchT = PszGetFleetName((int16_t)w);
            } else {
                pchT = PszGetPlanetName(pParams[0]);
            }
            break;

        case 'p': /* planet */
            pchT = PszGetPlanetName(pParams[0]);
            break;

        case 's': /* force fleet */
            w = (uint16_t)pParams[0] | 0x8000;
            pchT = PszGetFleetName((int16_t)w);
            break;

        case 'u': /* "%u" */
            c = (int16_t)sprintf(pch, "%u", (unsigned)(uint16_t)pParams[0]);
            pch += c;
            pParams += 1;
            pszFormat++;
            continue;

        case 'w': /* copy szWork into output */
            strcpy(pch, szWork);
            pch += (int16_t)strlen(szWork);
            pszFormat++;
            continue;

        case 'z': { /* ship design name from packed (iplr<<5)|ish */
            int16_t iplr = (int16_t)((uint16_t)pParams[0] >> 5);
            int16_t ish = (int16_t)((uint16_t)pParams[0] & 31);
            SHDEF  *lpshdef;

            if (ish < 16) {
                lpshdef = &rglpshdef[iplr][ish];
            } else {
                lpshdef = &rglpshdefSB[iplr][ish - 16];
            }

            if (iplr == idPlayer) {
                strcpy(pch, lpshdef->hul.szClass);
            } else {
                char *szPlayerName = PszPlayerName(iplr, 0, 0, 1, 0, (PLAYER *)0);
                (void)sprintf(pch, "%s %s", szPlayerName, lpshdef->hul.szClass);
            }

            pch += (int16_t)strlen(pch);
            pParams += 1;
            pszFormat++;
            continue;
        }

        default:
            /* unknown escape: emit literally */
            *pch++ = *pszFormat++;
            continue;
        }

        /* common string copy for pchT cases */
        strcpy(pch, pchT);
        pch += (int16_t)strlen(pchT);

        /* MSG_DoNothing */
        pParams += 1;
        pszFormat++;
    }
}

char *PszGetCompressedMessage(MessageId idm) {
    if (iLastMsgGet == idm) {
        return szLastMsgGet;
    }
    iLastMsgGet = idm;
    strncpy(szLastMsgGet, aMSGUncompressed[idm], sizeof(szLastMsgGet));
    return szLastMsgGet;
}

void WritePlayerMessages(int16_t iPlayer) {
    uint8_t *lpbMax;
    uint8_t  rgb[1024];
    int16_t  cbMsg;
    MSGPLR  *lpmp;
    uint8_t *lpb;

    cbMsg = 0;
    if (iPlayer == -1)
        return;

        // TODO: verify this and check sizeofs
    lpbMax = (uint8_t *)lpMsg + imemMsgCur;
    for (lpb = (uint8_t *)lpMsg; lpb < lpbMax; lpb += (*lpb >> 4) + 5) {
        if (cbMsg + 0x14 > 0x3ff) {
            WriteRt(rtMsg, cbMsg, rgb);
            cbMsg = 0;
        }
        if ((*lpb & 0xf) == iPlayer && (*(uint16_t *)(lpb + 1) & 0x1ff) != 0x1ff) {
            int16_t cbEntry = (*lpb >> 4) + 4;
            memcpy(rgb + cbMsg, lpb + 1, cbEntry);
            cbMsg += cbEntry;
        }
    }
    if (cbMsg != 0) {
        WriteRt(rtMsg, cbMsg, rgb);
    }

    for (lpmp = vlpmsgplrOut; lpmp != NULL; lpmp = lpmp->lpmsgplrNext) {
        if ((lpmp->iPlrTo == 0 && lpmp->iPlrFrom != iPlayer) || (lpmp->iPlrTo - 1 == iPlayer)) {
            int16_t cbLen = (int16_t)abs(lpmp->cLen);
            WriteRt(rtPlrMsg, cbLen + 12, lpmp);
        }
    }
}

int16_t IMsgPrev(int16_t fFilteredOnly) {
    int16_t i = iMsgCur;

    if (fViewFilteredMsg == 0 || fFilteredOnly != 0) {
        /* If we're in the "incoming player msg" region (iMsgCur > cMsg), just step back. */
        if (cMsg < iMsgCur) {
            i = (int16_t)(iMsgCur - 1);
        } else {
            for (;;) {
                int16_t idm;
                int     not_set;

                i = (int16_t)(i - 1);
                if (i < 0) {
                    return -1;
                }

                idm = IdmGetMessageN(i);

                /* Inline bit test: bitfMsgFiltered[idm] */
                not_set = ((bitfMsgFiltered[(uint16_t)idm >> 3] & (uint8_t)(1u << ((uint16_t)idm & 7u))) == 0);

                /* If fFilteredOnly==1: skip until bit is set.
                   If fFilteredOnly==0: skip while bit is set. */
                if (not_set != (fFilteredOnly != 0)) {
                    break;
                }
            }
        }
    } else {
        /* Viewing filtered messages normally: no filtering logic, just step back. */
        if (iMsgCur < 1) {
            i = -1;
        } else {
            i = (int16_t)(iMsgCur - 1);
        }
    }

    return i;
}

int16_t IMsgNext(int16_t fFilteredOnly) {
    int16_t i = iMsgCur;

    if (fViewFilteredMsg == 0 || fFilteredOnly != 0) {
        for (;;) {
            ++i;

            if ((int16_t)cMsg <= i) {
                /* Past end of normal messages: allow “incoming player messages” region. */
                if (i < (int16_t)(cMsg + vcmsgplrIn)) {
                    return i;
                }
                return -1;
            }

            {
                int16_t idm = IdmGetMessageN(i);
                int     filtered = (bitfMsgFiltered[idm >> 3] & (1 << (idm & 7))) != 0;

                /* Decompile does: while ( (filtered==0) == fFilteredOnly ) keep looping.
                   That means:
                   - if fFilteredOnly==0: stop when filtered==0 (i.e., NOT filtered out)
                   - if fFilteredOnly==1: stop when filtered!=0 (i.e., filtered)
                 */
                if ((filtered ? 1 : 0) == (fFilteredOnly ? 1 : 0)) {
                    return i;
                }
            }
        }
    }

    /* Not filtering-only, but the view is filtered: just step within the extended range. */
    if (iMsgCur < (int16_t)(cMsg + vcmsgplrIn - 1)) {
        return (int16_t)(iMsgCur + 1);
    }
    return -1;
}

char *PszFormatIds(StringId ids, int16_t *pParams) {
    char *psz;

    psz = PszGetCompressedString(ids);
    psz = PszFormatString(psz, pParams);
    return psz;
}

#ifdef _WIN32

void DecorateMsgTitleBar(HDC hdc, RECT *prc) {
    int16_t  xDst;
    int16_t  ySrcMask;
    uint16_t hbrSav;
    uint16_t hbmpSav;
    int16_t  dySrc;
    int16_t  i;
    HDC      hdcMem;
    int16_t  idm;
    int16_t  ySrc;
    int16_t  yDst;
    int16_t  dxSrc;
    int16_t  xyStart;
    uint32_t crBkSav;
    uint32_t crTextSav;

    /* debug symbols */
    /* label Cleanup @ MEMORY_MSG:0x7cbf */
    /* label DoMinMax @ MEMORY_MSG:0x7b18 */

    /* TODO: implement */
}

int16_t HtMsgBox(POINT pt) {
    int16_t i;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x7e19 */

    /* TODO: implement */
    return 0;
}

void SetMsgTitle(HWND hwnd) {
    int16_t cMsgTot;
    int16_t i;
    MSGBIG  mb;
    char    ch;
    char    szT[80];
    int16_t sw;
    MSGPLR *lpmp;
    RECT    rc;

    if (hwnd == NULL)
        return;
    if (fAi)
        return;

    sw = gd.fSendMsgMode ? SW_SHOW : SW_HIDE;
    ShowWindow(hwndMsgEdit, sw);
    ShowWindow(hwndMsgDrop, sw);
    ShowWindow(rghwndMsgBtn[3], sw);

    if (gd.fSendMsgMode)
        ShowWindow(hwndMsgScroll, SW_HIDE);

    cMsgTot = cMsg + vcmsgplrIn;

    if (gd.fSendMsgMode) {
        i = idsDone;
    } else {
        if (iMsgCur < cMsg)
            i = gd.fGotoVCR ? idsView : idsGoto3;
        else
            i = idsReply;
    }
    SetWindowText(rghwndMsgBtn[1], PszGetCompressedString(i));

    if (gd.fSendMsgMode) {
        wsprintf(szWork, PszGetCompressedString(idsSendMessagesDD), iMsgSendCur + 1, vcmsgplrOut);

        rc = rcMsgText;
        ExpandRc(&rc, -4, -4);

        SetWindowPos(hwndMsgDrop, NULL, rc.left + 0x1e, rc.top, (rc.right - rc.left) - 0x54, rc.bottom - rc.top, SWP_NOZORDER | SWP_NOACTIVATE);
        SetWindowPos(rghwndMsgBtn[3], NULL, rc.right - 0x32, rc.top, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

        rc.top = rc.top + dyShipDD + 3;
        SetWindowPos(hwndMsgEdit, NULL, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER | SWP_NOACTIVATE);

        EnableWindow(rghwndMsgBtn[0], iMsgSendCur > 0);
        EnableWindow(rghwndMsgBtn[1], TRUE);
        EnableWindow(rghwndMsgBtn[2], TRUE);

        lpmp = vlpmsgplrOut;
        i = iMsgSendCur;
        while (i-- > 0)
            lpmp = lpmp->lpmsgplrNext;

        if (lpmp == NULL) {
            SendMessage(hwndMsgDrop, CB_SETCURSEL, viInRe, 0);
            SetWindowText(hwndMsgEdit, "");
        } else {
            SendMessage(hwndMsgDrop, CB_SETCURSEL, lpmp->iPlrTo, 0);
            if (lpmp->cLen < 0) {
                SetWindowText(hwndMsgEdit, (LPCSTR)(lpmp + 1));
            } else {
                i = 1000;
                FDecompressUserString((char *)(lpmp + 1), lpmp->cLen, (char *)lpb2k, &i);
                SetWindowText(hwndMsgEdit, (LPCSTR)lpb2k);
            }
        }
        goto FinishUp;
    }

    if (cMsgTot == 0) {
        CchGetString(idsYearDCMessagesNone, szT);
        wsprintf(szWork, szT, game.turn + 2400, ch);
    } else {
        CchGetString(idsYearDCMessagesDD, szT);
        wsprintf(szWork, szT, game.turn + 2400, ch, iMsgCur + 1, cMsgTot);
    }

    EnableWindow(rghwndMsgBtn[0], IMsgPrev(0) != -1);
    EnableWindow(rghwndMsgBtn[2], IMsgNext(0) != -1);

    if (iMsgCur >= cMsg) {
        EnableWindow(rghwndMsgBtn[1], TRUE);
        goto FinishUp;
    }

    if (cMsg != 0 && iMsgCur < cMsg && FGetNMsgbig(iMsgCur, &mb)) {
        if (mb.wGoto == -1) {
            mdMsgObj = 0;
        } else {
            idMsgObj = mb.wGoto & 0x7fff;
            if (mb.wGoto == -2) {
                mdMsgObj = 3;
            } else if (mb.wGoto == -3) {
                mdMsgObj = 5;
            } else if (mb.wGoto == -4) {
                mdMsgObj = 8;
            } else if (mb.wGoto == -5) {
                mdMsgObj = 9;
            } else if (mb.wGoto == -6) {
                mdMsgObj = 10;
                vptMsg.x = mb.rgParam[0];
            } else if (mb.wGoto == -7) {
                mdMsgObj = 0xb;
            } else if ((mb.wGoto & 0xc000) == 0xc000) {
                mdMsgObj = 4;
            } else if ((mb.wGoto & 0x4000) == 0) {
                if (mb.wGoto < 0) {
                    FLEET *lpfl = LpflFromId(idMsgObj);
                    mdMsgObj = (lpfl != NULL) ? 2 : 0;
                } else {
                    mdMsgObj = 1;
                }
            } else {
                idMsgObj = mb.wGoto & 0x3fff;
                if (idMsgObj == 0x800) {
                    mdMsgObj = 7;
                } else {
                    mdMsgObj = 6;
                    vptMsg.x = mb.rgParam[0];
                    vptMsg.y = mb.rgParam[1];
                }
            }
        }
    }

    if (mdMsgObj != 0) {
        if (iMsgCur < 0) {
            mdMsgObj = 0;
        } else if (!fViewFilteredMsg) {
            int16_t idm = IdmGetMessageN(iMsgCur);
            if (bitfMsgFiltered[idm >> 3] & (1 << (idm & 7)))
                mdMsgObj = 0;
        }
    }

    EnableWindow(rghwndMsgBtn[1], mdMsgObj != 0);

FinishUp:
    strcpy(szMsgTitle, szWork);
    InvalidateRect(hwndMessage, &rcMsgTitle, TRUE);
}

INT_PTR CALLBACK SerialDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC         hdc = BeginPaint(hwnd, &ps);

        RECT rcClient;
        GetClientRect(hwnd, &rcClient);

        /* Position the prompt rectangle below the serial-number edit control. */
        HWND hwndEdit = GetDlgItem(hwnd, IDC_EDITTEXT);

        RECT  rcEditScreen;
        POINT ptBR;
        RECT  rcText;
        char  szT[256];
        short cch;

        GetWindowRect(hwndEdit, &rcEditScreen);

        /* Use the edit control's bottom-right, converted to client coords. */
        ptBR.x = rcEditScreen.right;
        ptBR.y = rcEditScreen.bottom;
        ScreenToClient(hwnd, &ptBR);

        rcText.left = 8;
        rcText.right = rcClient.right - 8;
        rcText.top = ptBR.y + 8;
        rcText.bottom = ptBR.y + 0x6c; /* fixed height, matches original */

        SelectObject(hdc, rghfontArial8[1]);
        SetBkColor(hdc, crButtonFace);
        SetTextColor(hdc, RGB(0, 0, 0));

        cch = CchGetString((int)szWork[200] + idsPleaseEnterUniqueEightCharacterSerialNumber, szT);
        DrawTextA(hdc, szT, (int)cch, &rcText, DT_NOPREFIX | DT_WORDBREAK);

        EndPaint(hwnd, &ps);
        return (INT_PTR)1;
    }

    case WM_ERASEBKGND: {
        HDC  hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, hbrButtonFace);
        return (INT_PTR)1;
    }

    case WM_CTLCOLORSTATIC: {
        /* Win32: no Win16 ctl-type encoding; just color statics. */
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, crButtonFace);
        SetTextColor(hdc, RGB(0, 0, 0));
        return (INT_PTR)hbrButtonFace;
    }

    case WM_INITDIALOG: {
        /*
         * Decompile passes a stack temp that is effectively a sentinel (-1)
         * into StickyDlgPos. In Win32, keep an explicit local rather than
         * relying on stack-overlap artifacts.
         */
        short ySticky = -1;

        szWork[0] = '\0';

        /* Limit serial entry to 8 chars and clear the edit. */
        SendDlgItemMessageA(hwnd, IDC_EDITTEXT, EM_LIMITTEXT, (WPARAM)8, (LPARAM)0);
        SetWindowTextA(GetDlgItem(hwnd, IDC_EDITTEXT), szWork);

        /*
         * If your StickyDlgPos truly wants a Win32 POINT*, pass a dummy POINT
         * with y initialized from the sentinel. If it only uses y (as callsite
         * evidence suggests), this preserves behavior without UB.
         */
        {
            POINT pt;
            pt.x = 0;
            pt.y = (LONG)ySticky;
            StickyDlgPos(hwnd, &pt, 1);
        }

        return (INT_PTR)1;
    }

    case WM_COMMAND: {
        UINT id = LOWORD(wParam);

        if (id == IDOK || id == IDCANCEL) {
            if (id == IDOK) {
                GetDlgItemTextA(hwnd, IDC_EDITTEXT, szWork, 9);

                if (FValidSerialNo((char *)szWork, NULL) == 0) {
                    /* Project idiom: string id + alert + early return */
                    Error(idsSerialNumberHaveEnteredValid);
                    SetFocus(GetDlgItem(hwnd, IDC_EDITTEXT));
                    return (INT_PTR)0;
                }
            }

            EndDialog(hwnd, (INT_PTR)(id == IDOK));
            return (INT_PTR)1;
        }

        if (id == IDC_HELP) {
            WinHelpA(hwnd, szHelpFile, HELP_CONTEXT, (DWORD)0x0dbc);
            return (INT_PTR)1;
        }

        return (INT_PTR)0;
    }

    default:
        return (INT_PTR)0;
    }
}

LRESULT CALLBACK MessageWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    int16_t     i;
    char       *psz;
    PAINTSTRUCT ps;
    int16_t     dy;
    int16_t     idm;
    int16_t     dx;
    POINT       pt;
    char       *lpsz;
    THING      *lpth;
    int16_t (*lpProc)(void);
    uint16_t hcs;
    int16_t  ht;
    uint16_t hbrSav;
    int16_t  fRet;
    RECT     rc;
    int16_t  fSet;
    MSGPLR  *lpmp;
    uint32_t crFore;
    int32_t  lSerial;
    int16_t  dxMax;
    MSGPLR  *lpmpSrc;
    uint32_t crBack;
    SCAN     scan;
    RECT     rcActual;
    int16_t  cch;
    int16_t  iMode;
    char     szT[32];
    MSGPLR  *lpmsgplr;

    switch (msg) {
    case WM_CREATE:
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC         hdc = BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        /* if you paint the whole client yourself, returning 1 avoids flicker */
        return 0;

    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);

    /* TODO: implement */
    return 0;
}

#endif
