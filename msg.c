
#include "types.h"
#include "globals.h"

#include "msg.h"
#include "strings.h"
#include "util.h"
#include "utilgen.h"
#include "planet.h"
#include "parts.h"

/* globals */
char aMSGCmpr[22836] = {0};
uint8_t acMSG[387] = {0x62, 0xa5, 0x7c, 0x63, 0x69, 0x99, 0x6c, 0x9b, 0x7c, 0x83, 0x2d, 0x84, 0x5a, 0x53, 0x6f, 0x49, 0x43, 0x44, 0x31, 0x4f, 0x5e, 0x6e, 0x6d, 0x5f, 0x37, 0x37, 0x54, 0x3d, 0x70, 0x69, 0x56, 0x53, 0x67, 0x65, 0x4b, 0x59, 0x84, 0x42, 0x56, 0x1a, 0xa6, 0x9e, 0xcc, 0x26, 0x24, 0x24, 0x20, 0x2f, 0x37, 0x4f, 0x58, 0x6b, 0x73, 0x26, 0x28, 0x22, 0x24, 0x2e, 0x30, 0x47, 0xb1, 0x98, 0x48, 0x2e, 0x5f, 0x69, 0x33, 0x2f, 0x34, 0x30, 0x5d, 0x97, 0x71, 0xa9, 0x5f, 0x98, 0x6e, 0xc0, 0x29, 0x69, 0x89, 0x71, 0x6f, 0x87, 0x8c, 0xaa, 0xba, 0xb5, 0x6c, 0x56, 0x57, 0x49, 0xed, 0xee, 0x75, 0x4e, 0x33, 0x36, 0x4a, 0x5b, 0x6b, 0x6e, 0x75, 0x79, 0x97, 0xa6, 0x42, 0x4a, 0x59, 0x71, 0x84, 0x87, 0x8f, 0x9e, 0xba, 0xc9, 0x45, 0x7c, 0x81, 0x6c, 0xf4, 0x26, 0x2a, 0x43, 0x2f, 0x5b, 0x74, 0xe1, 0xd6, 0xb3, 0xc7, 0x6e, 0x7b, 0x91, 0x90, 0xb1, 0xc6, 0xd5, 0xca, 0x55, 0x82, 0x78, 0x7c, 0x42, 0x3a, 0x54, 0x62, 0x71, 0x6d, 0x61, 0x60, 0x6e, 0x7d, 0x79, 0x7b, 0x83, 0x7a, 0x9d, 0xb5, 0xaf, 0x6c, 0x6c, 0x87, 0xa2, 0x8d, 0x8b, 0xb8, 0x9d, 0x84, 0x78, 0x5d, 0x9e, 0x82, 0xb8, 0xc5, 0x85, 0x6a, 0x8d, 0x72, 0x8b, 0x70, 0xa6, 0xad, 0xd3, 0x5c, 0x5c, 0xcc, 0x62, 0x84, 0x6f, 0x4c, 0x7d, 0x7b, 0x5e, 0x41, 0x1e, 0x30, 0x3a, 0x94, 0x91, 0x42, 0x39, 0xa2, 0x99, 0x3f, 0x1c, 0x73, 0x50, 0xfe, 0x73, 0xcb, 0x48, 0x6c, 0x6e, 0xdb, 0xdd, 0x7b, 0x99, 0x5e, 0xae, 0x7f, 0x4b, 0x4c, 0x78, 0x42, 0x5b, 0x83, 0x73, 0x7a, 0xc1, 0x89, 0xab, 0xad, 0xa8, 0xac, 0xa8, 0x68, 0x64, 0x7e, 0x69, 0x78, 0x78, 0x9d, 0x54, 0x55, 0x65, 0x66, 0x21, 0x90, 0x65, 0x4f, 0x7b, 0x57, 0x9e, 0x93, 0x38, 0xcc, 0xf6, 0xc1, 0xd3, 0xc6, 0xb6, 0x8d, 0x90, 0xb0, 0xdf, 0x7e, 0xc2, 0xb6, 0x7f, 0xd4, 0xc6, 0x92, 0x8c, 0x55, 0x63, 0x64, 0x99, 0x82, 0x8f, 0x97, 0x26, 0x11, 0x36, 0x78, 0x72, 0x4f, 0x5e, 0x5d, 0xab, 0xb5, 0x57, 0x5d, 0x59, 0x24, 0x2c, 0xb7, 0xb0, 0x99, 0x6f, 0x3b, 0x4a, 0x48, 0x84, 0x84, 0x53, 0x51, 0x39, 0x37, 0xa3, 0x97, 0x4e, 0x5f, 0xe4, 0x7a, 0x65, 0x94, 0x96, 0xd8, 0xd2, 0x54, 0x55, 0xeb, 0xec, 0x6e, 0xb3, 0xb2, 0x78, 0x40, 0x5a, 0x7e, 0x85, 0x3c, 0x2d, 0x1e, 0x9f, 0xc1, 0x87, 0x61, 0x38, 0x38, 0x3f, 0x38, 0xb4, 0x7c, 0x93, 0x39, 0x48, 0x59, 0x63, 0x72, 0x3e, 0xa2, 0xa1, 0x3d, 0xb0, 0xa7, 0x53, 0x44, 0x47, 0x5b, 0x6c, 0x7c, 0x7f, 0x86, 0x8a, 0xa8, 0xb7, 0x49, 0x51, 0x60, 0x78, 0x8b, 0x8e, 0x96, 0xa5, 0xc1, 0xd0, 0x59, 0x54, 0x53, 0x46, 0x46, 0x4c, 0xce, 0x6f, 0x82};
char rgMSGLookupTable[72] = " eotasnirldh\\ucpfybm.gvwk,YT0'AzPMSXFxOIj%UVL-CDEN!GHq*W()25:QR1B/46Z78?";
int16_t aiMSGChunkOffset[7] = {0, 2854, 6582, 10933, 14692, 18914, 22612};

extern const char *const aMSGUncompressed[];

/* functions */
int16_t FFindPlayerMessage(int16_t iPlr, MessageId iMsg, int16_t iObj)
{
    uint8_t *lpbMax;
    uint8_t *lpb;

    /* TODO: implement */
    return 0;
}

int16_t FGetNMsgbig(int16_t iMsg, MSGBIG *pmb)
{
    uint8_t *lpbMax;
    int16_t iMax;
    MSGHDR *lpmh;
    int16_t i;
    uint8_t *lpb;
    uint16_t u;

    /* TODO: implement */
    return 0;
}

void DecorateMsgTitleBar(uint16_t hdc, RECT *prc)
{
    int16_t xDst;
    int16_t ySrcMask;
    uint16_t hbrSav;
    uint16_t hbmpSav;
    int16_t dySrc;
    int16_t i;
    uint16_t hdcMem;
    int16_t idm;
    int16_t ySrc;
    int16_t yDst;
    int16_t dxSrc;
    int16_t xyStart;
    uint32_t crBkSav;
    uint32_t crTextSav;

    /* debug symbols */
    /* label Cleanup @ MEMORY_MSG:0x7cbf */
    /* label DoMinMax @ MEMORY_MSG:0x7b18 */

    /* TODO: implement */
}

int16_t PackageUpMsg(uint8_t *pb, int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7)
{
    int16_t *pi;
    int16_t i;
    uint16_t grbit;
    MSGTURN *lpmt;
    uint8_t *lpb;
    uint8_t *lpbBase;

    /* TODO: implement */
    return 0;
}

char *PszGetMessageN(int16_t iMsg)
{
    MSGBIG mb;
    char *psz;

    /* TODO: implement */
    return NULL;
}

int16_t IdmGetMessageN(int16_t iMsg)
{
    MSGBIG mb;

    /* TODO: implement */
    return 0;
}

int16_t FFinishPlrMsgEntry(int16_t dInc)
{
    uint8_t *lpbMsg;
    int16_t i;
    int16_t cbNew;
    int16_t iPlrTo;
    MSGPLR *lpmpCur;
    MSGPLR *lpmpPrev;
    int16_t cb;

    /* TODO: implement */
    return 0;
}

void SetMsgTitle(uint16_t hwnd)
{
    int16_t cMsgTot;
    int16_t i;
    MSGBIG mb;
    char ch;
    char szT[80];
    int16_t sw;
    MSGPLR *lpmp;
    RECT rc;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x732e */
    /* label FinishUp @ MEMORY_MSG:0x77de */

    /* TODO: implement */
}

void MarkPlanetsPlayerLost(int16_t iPlayer)
{
    uint8_t *lpbMax;
    PLANET *lppl;
    uint8_t *lpbT;
    uint16_t w;
    uint8_t *lpb;

    /* debug symbols */
    /* label LLookupPlanet @ MEMORY_MSG:0x9489 */

    /* TODO: implement */
}

char *PszFormatMessage(MessageId idm, int16_t *pParams)
{

    /* TODO: implement */
    return NULL;
}

int16_t FSendPlrMsg2XGen(int16_t fPrepend, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2)
{
    uint8_t rgb[64];
    int16_t *pi;
    int16_t i;
    uint16_t grbit;
    uint8_t *pb;
    uint16_t cSize;
    MSGHDR *pmsghdr;

    /* TODO: implement */
    return 0;
}

void SetFilteringGroups(MessageId idm, int16_t fSet)
{
    int16_t i;

    /* TODO: implement */
}

int16_t FSendPlrMsg2(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2)
{

    /* TODO: implement */
    return 0;
}

void ReadPlayerMessages(void)
{
    uint8_t *lpbMax;
    int16_t iMax;
    int16_t fOOM;
    int16_t (*penvMemSav)[9];
    MSGHDR *lpmh;
    uint16_t imemMsgT;
    int16_t i;
    int16_t env[9];
    MSGPLR *lpmp;
    uint8_t *lpb;
    uint16_t u;

    /* debug symbols */
    /* label LOutOfMem @ MEMORY_MSG:0x9bb2 */

    /* TODO: implement */
}

int16_t FSendPrependedPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7)
{
    uint8_t rgbWork[40];
    int16_t cbMsg;

    /* TODO: implement */
    return 0;
}

void MarkPlayersThatSentMsgs(int16_t iPlayer)
{
    MSGPLR *lpmp;

    /* TODO: implement */
}

void ResetMessages(void)
{
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

int16_t FRemovePlayerMessage(int16_t iPlr, MessageId iMsg, int16_t iObj)
{
    uint8_t *lpbMax;
    uint8_t *lpb;
    int16_t cDel;

    /* TODO: implement */
    return 0;
}

char *PszFormatString(char *pszFormat, int16_t *pParamsReal)
{
    char *pch;
    char *pchT;
    int16_t *pParams;
    uint16_t w;
    int16_t i;
    int16_t c;
    int16_t cOut;
    int16_t iMineral;
    char szBuf[480];

    iMineral = -1;
    pParams = pParamsReal;
    pch = szMsgBuf;

    for (;;)
    {
        char esc;

        if (*pszFormat == '\0')
        {
            *pch = '\0';
            return szMsgBuf;
        }

        if (*pszFormat != '\\')
        {
            *pch++ = *pszFormat++;
            continue;
        }

        /* escape */
        pszFormat++;
        esc = *pszFormat;

        switch (esc)
        {
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
            pchT = PszPlayerName(
                (int16_t)(pParams[0] & 15),
                (int16_t)(esc == 'L'),
                (int16_t)((pParams[0] & 0x10) != 0),
                (int16_t)((pParams[0] & 0x20) != 0),
                (int16_t)((pParams[0] & 0x00c0) >> 6),
                (PLAYER *)0);
            break;

        case 'M': /* rgszMineField / table at 0x1120:04f2 */
            pchT = rgszMineField[pParams[0]];
            break;

        case 'O': /* Player name from packed owner bits */
            w = (uint16_t)pParams[0];
            w = (uint16_t)((w >> 9) & 15);
            pchT = PszPlayerName((int16_t)w, 0, 0, 0, 0, (PLAYER *)0);
            break;

        case 'P':
        { /* Percent, prints x% or x.y% depending on remainder */
            int16_t v = pParams[0];
            int16_t whole = (int16_t)(v / 100);
            int16_t frac = (int16_t)(v - (int16_t)(whole * 100));

            if (frac != 0)
            {
                if (frac < 0)
                    frac = (int16_t)-frac;
                /* s_%d.%d%%_1120_01c8 */
                c = (int16_t)sprintf(pch, "%d.%d%%", whole, frac);
            }
            else
            {
                /* s__%dkT_1120_01b8 (name from your symbol dump; string is "%d%%" style) */
                c = (int16_t)sprintf(pch, "%dkT", whole);
            }

            pch += c;
            pParams += 1;
            pszFormat++;
            continue;
        }

        case 'S': /* "of <player>'s origin" unless self */
            if (pParams[0] != idPlayer)
            {
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
        case 'v':
        { /* 32-bit number, maybe append units/mineral name */
            int32_t l;
            uint16_t lo = (uint16_t)pParams[0];
            uint16_t hi = (uint16_t)pParams[1];

            l = (int32_t)((uint32_t)lo | ((uint32_t)hi << 16));
            pParams += 2;

            c = (int16_t)sprintf(pch, PCTLD, l);
            pch += c;

            if (esc != 'v')
            {
                if (esc == 'V')
                {
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

        case 'Z':
        { /* player bitmask -> list of names, with "and" */
            w = (uint16_t)pParams[0];

            if (w != 0)
            {
                if (((w - 1) & w) == 0)
                {
                    c = 0;
                    while ((w & 1) == 0)
                    {
                        w >>= 1;
                        c++;
                    }
                    pchT = PszPlayerName(c, 0, 1, 1, 0, (PLAYER *)0);
                    break;
                }

                cOut = 0;
                for (i = 0; i < game.cPlayer; i++)
                {
                    if ((w & 1) != 0)
                    {
                        if (cOut > 0)
                        {
                            if ((w & 0xfffe) == 0)
                            {
                                c = (int16_t)CchGetString(idsAnd, pch);
                                pch += c;
                            }
                            else
                            {
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
        case 'y':
        {
            /* base path */
            strcpy(pch, szBase);
            pch += (int16_t)strlen(szBase);

            if (esc == 'f')
            {
                if (idPlayer == -1)
                {
                    /* ".x%d" then fall into DoInt */
                    c = (int16_t)sprintf(pch, ".x%d", (int)(idPlayer + 1));
                }
                else
                {
                    /* ".m%d" */
                    c = (int16_t)sprintf(pch, ".m%d", (int)(idPlayer + 1));
                }
                pch += c;
                pParams += 1;
                pszFormat++;
                continue;
            }

            if (esc == 'h')
            {
                strcat(pch, ".h");
                pch += 4;
                pszFormat++;
                continue;
            }

            if (esc == 'r')
            {
                c = (int16_t)sprintf(pch, ".h%d", (int)(idPlayer + 1));
                pch += c;
                pParams += 1;
                pszFormat++;
                continue;
            }

            if (esc == 't')
            {
                if (idPlayer == -1)
                {
                    strcat(pch, ".hst");
                    pch += 4;
                }
                else
                {
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

        case 'k':
        { /* part name from 2 params */
            PART part;
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
            if (pParams[0] == -2)
            {
                pParams += 1;
                pchT = PszGetThingName(pParams[0]);
                break;
            }
            if (pParams[0] == -1)
            {
                pParams += 1;
                /* fall through to 'o' behavior using new current param */
                if (((uint16_t)pParams[0] & 0x8000) != 0)
                {
                    w = (uint16_t)pParams[0] | 0x8000;
                    pchT = PszGetFleetName((int16_t)w);
                }
                else
                {
                    pchT = PszGetPlanetName(pParams[0]);
                }
                break;
            }

            pchT = PszGetLocName(grobjNone, -1, pParams[0], pParams[1]);
            pParams += 1; /* net +2 with the consume below */
            break;

        case 'o': /* planet-or-fleet depending on high bit */
            if (((uint16_t)pParams[0] & 0x8000) != 0)
            {
                w = (uint16_t)pParams[0] | 0x8000;
                pchT = PszGetFleetName((int16_t)w);
            }
            else
            {
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

        case 'z':
        { /* ship design name from packed (iplr<<5)|ish */
            int16_t iplr = (int16_t)((uint16_t)pParams[0] >> 5);
            int16_t ish = (int16_t)((uint16_t)pParams[0] & 31);
            SHDEF *lpshdef;

            if (ish < 16)
            {
                lpshdef = &rglpshdef[iplr][ish];
            }
            else
            {
                lpshdef = &rglpshdefSB[iplr][ish - 16];
            }

            if (iplr == idPlayer)
            {
                strcpy(pch, lpshdef->hul.szClass);
            }
            else
            {
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

char *PszGetCompressedMessage(MessageId idm)
{
    if (iLastMsgGet == idm)
    {
        return szLastMsgGet;
    }
    iLastMsgGet = idm;
    strncpy(szLastMsgGet, aMSGUncompressed[idm], sizeof(szLastMsgGet));
    return szLastMsgGet;
}

int16_t MsgDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    RECT rc;
    uint16_t hdc;
    POINT pt;
    RECT rcEdit;
    int16_t cch;
    char szT[256];
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x8f77 */
    /* block (block) @ MEMORY_MSG:0x9031 */

    /* TODO: implement */
    return 0;
}

void WritePlayerMessages(int16_t iPlayer)
{
    uint8_t *lpbMax;
    uint8_t rgb[1024];
    int16_t cbMsg;
    MSGPLR *lpmp;
    uint8_t *lpb;

    /* TODO: implement */
}

int16_t HtMsgBox(POINT pt)
{
    int16_t i;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x7e19 */

    /* TODO: implement */
    return 0;
}

int16_t IMsgPrev(int16_t fFilteredOnly)
{
    int16_t i;
    int16_t idm;

    /* TODO: implement */
    return 0;
}

int16_t IMsgNext(int16_t fFilteredOnly)
{
    int16_t i;
    int16_t idm;

    /* TODO: implement */
    return 0;
}

char *PszFormatIds(StringId ids, int16_t *pParams)
{
    char *psz;

    psz = PszGetCompressedString(ids);
    psz = PszFormatString(psz, pParams);
    return psz;
}

int16_t FSendPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7)
{
    uint8_t rgbWork[40];
    int16_t cbMsg;
    uint8_t *lpb;

    /* TODO: implement */
    return 0;
}

int32_t MessageWndProc(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    int16_t i;
    char *psz;
    PAINTSTRUCT ps;
    int16_t dy;
    int16_t idm;
    int16_t dx;
    POINT pt;
    char *lpsz;
    THING *lpth;
    int16_t (*lpProc)(void);
    uint16_t hcs;
    int16_t ht;
    uint16_t hbrSav;
    int16_t fRet;
    RECT rc;
    int16_t fSet;
    MSGPLR *lpmp;
    uint32_t crFore;
    int32_t lSerial;
    int16_t dxMax;
    MSGPLR *lpmpSrc;
    uint32_t crBack;
    SCAN scan;
    RECT rcActual;
    int16_t cch;
    int16_t iMode;
    char szT[32];
    MSGPLR *lpmsgplr;

    /* debug symbols */
    /* block (block) @ MEMORY_MSG:0x5ef1 */
    /* block (block) @ MEMORY_MSG:0x6059 */
    /* block (block) @ MEMORY_MSG:0x6084 */
    /* block (block) @ MEMORY_MSG:0x60cf */
    /* block (block) @ MEMORY_MSG:0x6109 */
    /* block (block) @ MEMORY_MSG:0x62c6 */
    /* block (block) @ MEMORY_MSG:0x643a */
    /* block (block) @ MEMORY_MSG:0x65ec */
    /* block (block) @ MEMORY_MSG:0x6aff */
    /* block (block) @ MEMORY_MSG:0x6db8 */
    /* block (block) @ MEMORY_MSG:0x6ea6 */
    /* block (block) @ MEMORY_MSG:0x6eca */
    /* block (block) @ MEMORY_MSG:0x6fee */
    /* block (block) @ MEMORY_MSG:0x704c */
    /* block (block) @ MEMORY_MSG:0x70fd */
    /* label SetupNewMsg @ MEMORY_MSG:0x6c2a */
    /* label Default @ MEMORY_MSG:0x718a */
    /* label CheckBox @ MEMORY_MSG:0x6109 */
    /* label ZoomBox @ MEMORY_MSG:0x61cc */
    /* label NextMsg @ MEMORY_MSG:0x6ca9 */
    /* label PrevMsg @ MEMORY_MSG:0x6ba0 */
    /* label ToggleMsgMode @ MEMORY_MSG:0x6298 */
    /* label GotoMsg @ MEMORY_MSG:0x6d8d */

    /* TODO: implement */
    return 0;
}
