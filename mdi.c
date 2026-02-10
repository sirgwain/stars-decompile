
#include "debuglog.h"
#include "globals.h"
#include "port.h"
#include "resource.h"
#include "types.h"

#include "ai.h"
#include "create.h"
#include "file.h"
#include "init.h"
#include "log.h"
#include "mdi.h"
#include "mine.h"
#include "msg.h"
#include "planet.h"
#include "platform.h"
#include "popup.h"
#include "produce.h"
#include "race.h"
#include "report.h"
#include "research.h"
#include "save.h"
#include "scan.h"
#include "ship.h"
#include "stars.h"
#include "tb.h"
#include "turn.h"
#include "tutor.h"
#include "util.h"
#include "utilgen.h"

/* globals */
char    rgTOWidth[2][2] = {{-3, 0}, {2, 1}}; /* 1020:7702 */
uint8_t vrgbShuffleSerial[21] = {0x0b, 0x04, 0x05, 0x10, 0x11, 0x0c, 0x13, 0x0f, 0x0a, 0x01, 0x0e,
                                 0x0d, 0x03, 0x12, 0x02, 0x14, 0x09, 0x07, 0x00, 0x08, 0x06}; /* 1020:2870 */

const char szBrowser[] = "starsbrowser";
const char szFrame[] = "starsframe";
const char szMessage[] = "starsmessage";
const char szMine[] = "starsmine";
const char szPlanet[] = "starsplanet";
const char szPopup[] = "starspopup";
const char szScan[] = "starsscan";
const char szTb[] = "starstb";
const char szTitle[] = "starstitle";
const char szTooltip[] = "starstt";
const char szReport[] = "starsreport";

/* functions */
void VerifyTurns(void) {
    int16_t idsError;
    int16_t idCur;
    int16_t cAi;
    int16_t i;
    int16_t cOut;
    int16_t fOut;

    /* TODO: implement */
}

int16_t FSerialAndEnvFromSz(int32_t *plSerial, uint8_t *pbEnv, char *pszIn) {
    bool    bNibHi = false;
    int16_t fSuccess = 0;

    uint8_t rgbRaw2[21];
    uint8_t rgbRaw[21];

    int16_t  iRaw = 0;
    int16_t  cBits = 0;
    uint32_t tank = 0;

    *plSerial = 0;
    memset(pbEnv, 0, 0x0B);

    /* Decode 21 bytes from custom base64-ish stream */
    for (int16_t i = 0; i < 0x15; i++) {
        while (cBits < 8) {
            uint8_t b64;
            char    ch = *pszIn++;

            if (ch >= 'A' && ch <= 'Z')
                b64 = (uint8_t)(ch - 'A');
            else if (ch >= 'a' && ch <= 'z')
                b64 = (uint8_t)(ch - 'a' + 26);
            else if (ch >= '0' && ch <= '9')
                b64 = (uint8_t)(ch - '0' + 52);
            else if (ch == '-')
                b64 = 62;
            else
                b64 = 63;

            tank |= (uint32_t)b64 << (cBits & 0x1F);
            cBits = (int16_t)(cBits + 6);
        }

        rgbRaw2[iRaw++] = (uint8_t)tank;
        cBits = (int16_t)(cBits - 8);
        tank >>= 8;
    }

    /* Unshuffle */
    for (int16_t i = 0; i < 0x15; i++)
        rgbRaw[(uint8_t)vrgbShuffleSerial[i]] = rgbRaw2[i];

    /* Serial is first 4 bytes, little-endian (matches Win16 stores) */
    {
        uint32_t lSerial = ((uint32_t)rgbRaw[0]) | ((uint32_t)rgbRaw[1] << 8) | ((uint32_t)rgbRaw[2] << 16) | ((uint32_t)rgbRaw[3] << 24);

        if (!FValidSerialLong(lSerial))
            return 0;

        fSuccess = 1;

        /* prototypes: PushRandom(int32_t, int32_t), Randomize(uint32_t) */
        PushRandom(0x11000B, (int32_t)lSerial);
        Randomize(lSerial);

        iRaw = 0x0F;
        for (int16_t i = 0; i < 0x0B; i++) {
            for (int16_t j = (int16_t)rgbRaw[i + 4]; j > 0; j--)
                (void)Random(0x10);

            if (bNibHi) {
                uint16_t want = (uint16_t)(rgbRaw[iRaw] >> 4);
                uint16_t got = (uint16_t)Random(0x10) & 0xFFu;
                if (want != got)
                    fSuccess = 0;
                iRaw = (int16_t)(iRaw + 1);
            } else {
                uint16_t want = (uint16_t)(rgbRaw[iRaw] & 0x0Fu);
                uint16_t got = (uint16_t)Random(0x10) & 0xFFu;
                if (want != got)
                    fSuccess = 0;
            }

            bNibHi = (bool)(((uint16_t)bNibHi + 1u) & 1u);
        }

        {
            uint8_t bXor = 0;
            for (int16_t i = 0; i < 0x0F; i++)
                bXor ^= rgbRaw[i];

            if ((uint16_t)(rgbRaw[iRaw] >> 4) != (uint16_t)(bXor & 0x0Fu))
                fSuccess = 0;
        }

        PopRandom();

        if (fSuccess != 0) {
            *plSerial = (int32_t)lSerial;
            memcpy(pbEnv, rgbRaw + 4, 0x0B);
        }
    }

    return fSuccess;
}

/*
 * FormatSerialAndEnv
 * - Produces a 28-character ASCII encoding (plus NUL) from lSerial + 11-byte pbEnv.
 * - Preserves original 16-bit-ish RNG flow and packing (nibbles, XOR check nibble, shuffle, 6-bit encoding).
 */
void FormatSerialAndEnv(int32_t lSerial, const uint8_t *pbEnv, char *pszOut) {
    uint8_t rgbRaw[21];
    uint8_t rgbRaw2[21];
    uint8_t bXor;
    int16_t iRaw;
    int16_t i, j;
    int     packHighNibble = 0;

    /* Win16 code passed caller SI:DI as an extra cookie; in Win32 we don't have that. */
    PushRandom(0x0011000bU, 0);

    Randomize(lSerial);

    /* raw[0..3] = lSerial (little-endian) */
    rgbRaw[0] = (uint8_t)((uint32_t)lSerial >> 0);
    rgbRaw[1] = (uint8_t)((uint32_t)lSerial >> 8);
    rgbRaw[2] = (uint8_t)((uint32_t)lSerial >> 16);
    rgbRaw[3] = (uint8_t)((uint32_t)lSerial >> 24);

    /* raw[4..14] = pbEnv[0..10] */
    memcpy(&rgbRaw[4], pbEnv, 11);

    /* Append 11 random nibbles, packed two per byte starting at raw[15]. */
    iRaw = 0x0f;
    for (i = 0; i < 11; i++) {
        for (j = (int16_t)pbEnv[i]; j > 0; j--) {
            (void)Random(0x10);
        }

        if (packHighNibble) {
            uint16_t r = Random(0x10);
            rgbRaw[iRaw] = (uint8_t)(rgbRaw[iRaw] | (uint8_t)((r & 0x0fU) << 4));
            iRaw++;
        } else {
            rgbRaw[iRaw] = (uint8_t)Random(0x10); /* low nibble only (0..15) */
        }

        packHighNibble ^= 1;
    }

    /* XOR of the first 15 bytes (0..14), stored as the high nibble of current byte. */
    bXor = 0;
    for (i = 0; i < 0x0f; i++) {
        bXor ^= rgbRaw[i];
    }
    rgbRaw[iRaw] = (uint8_t)(rgbRaw[iRaw] | (uint8_t)(bXor << 4));

    PopRandom();

    /* Permute into rgbRaw2 using vrgbShuffleSerial. */
    for (i = 0; i < 21; i++) {
        rgbRaw2[i] = rgbRaw[vrgbShuffleSerial[i]];
    }

    /*
     * Emit 28 chars from 21 bytes (168 bits) in 6-bit chunks (28 * 6 = 168).
     * Bits are consumed LSB-first from a little-endian bit bucket.
     */
    {
        int      bits = 0;
        int      rawIndex = 0;
        uint32_t tank = 0;

        for (i = 0; i < 0x1c; i++) {
            while (bits < 6) {
                tank |= (uint32_t)rgbRaw2[rawIndex++] << (uint32_t)bits;
                bits += 8;
            }

            {
                uint8_t b64 = (uint8_t)(tank & 0x3fU);
                tank >>= 6;
                bits -= 6;

                if (b64 < 0x1a) {
                    *pszOut = (char)('A' + b64);
                } else if (b64 < 0x34) {
                    *pszOut = (char)('a' + (b64 - 0x1a));
                } else if (b64 < 0x3e) {
                    *pszOut = (char)('0' + (b64 - 0x34));
                } else if (b64 == 0x3e) {
                    *pszOut = '-';
                } else {
                    *pszOut = '*';
                }

                pszOut++;
            }
        }
    }

    *pszOut = '\0';
}

int16_t FWasRaceFile(char *szFile, int16_t fChkPass) {
    int16_t  fileErrSilentSav;
    PLAYER   plr;
    MemJump *penvMemSav;
    int16_t  idsError;
    int16_t  fRet;
    MemJump  env;
    uint16_t versSav;
    uint16_t w8;
    uint16_t checksum;
    char    *psz;
    int      i;
    int32_t  lSaltSav;
    int16_t  fSav;

    fileErrSilentSav = fFileErrSilent;
    penvMemSav = penvMem;

    idsError = -1;
    fRet = 0;

    fFileErrSilent = 1;
    penvMem = &env;

    versSav = wVersFile;

    if (setjmp(env.env) != 0)
        goto LError;

    StreamOpen(szFile, 0x20);
    ReadRt();

    w8 = (uint16_t)rgbCur[8] | ((uint16_t)rgbCur[9] << 8);

    if ((hdrCur.rt == rtBOF) && ((w8 >> 12) == 2) && (0x30 < ((w8 >> 5) & 0x7f)) && (((w8 >> 5) & 0x7f) < 0x54)) {
        wVersFile = (uint16_t)rgbCur[8] | ((uint16_t)rgbCur[9] << 8);
        versSav = wVersFile;

        if ((rgbCur[14] == 5) && (ReadRt(), hdrCur.rt == rtPlr)) {
            idsError = 3;

            ReadRtPlr(&plr, (uint8_t *)rgbCur);
            ReadRt();

            if (hdrCur.rt == 0) {
                checksum = (uint16_t)rgbCur[0] | ((uint16_t)rgbCur[1] << 8);

                lSaltSav = lSaltCur;

                if (checksum == IRaceChecksum(&plr)) {
                    lSaltCur = plr.lSalt;

                    if ((fChkPass == 0) || (FCheckPassword() != 0)) {
                        if (plr.lSalt == 0) {
                            szRacePass[0] = '\0';
                            lSaltCur = lSaltSav;
                        } else {
                            lSaltCur = lSaltSav;
                            strncpy(szRacePass, szPassLast, sizeof(szRacePass));
                        }

                        vplr = plr;
                        strncpy(szRaceFile, szFile, sizeof(szRaceFile));

                        StreamClose();
                        penvMem = (MemJump *)penvMemSav;
                        fFileErrSilent = fileErrSilentSav;
                        return 1;
                    }

                    fRet = -1;
                    lSaltCur = lSaltSav;
                    versSav = wVersFile;
                } else {
                    lSaltCur = lSaltSav;
                }
            }
        }
    } else {
        idsError = 0x0d;
        fRet = -1;
        versSav = wVersFile;
    }

LError:
    wVersFile = versSav;

    /* per project idiom: clear active jump env before cleanup that might longjmp */
    penvMem = NULL;
    StreamClose();

    penvMem = (MemJump *)penvMemSav;
    fFileErrSilent = fileErrSilentSav;

    if ((fileErrSilentSav == 0) && (idsError != -1)) {
        Error(idsError);
    }

    return fRet;
}

void EnsureAis(void) {
    int16_t fHostSav;
    int16_t fErrSav;
    int16_t fOpened;
    int16_t fWorkDone;
    int16_t fSubmitSav;
    int16_t iPlayer;
    MDPLR   rgmdplr[16];
    int16_t pctProgress;

    fSubmitSav = gd.fSubmit;
    fWorkDone = false;

    if (!gd.fAisDone) {
        fHostSav = gd.fHostMode;

        if (!gd.fHostMode) {
            DestroyCurGame();
            FLoadGame(szBase, mpdtsz[dtHost]);
        }

        fErrSav = fFileErrSilent;

        for (iPlayer = 0; iPlayer < game.cPlayer; iPlayer++) {
            rgmdplr[iPlayer].wRaw_0000 = rgplr[iPlayer].wMdPlr;
        }

        gd.fSubmit = 1;
        fFileErrSilent = 1;

        for (iPlayer = 0; iPlayer < game.cPlayer; iPlayer++) {
            pctProgress = MulDiv(340, iPlayer + 1, game.cPlayer);
            UpdateProgressGauge(pctProgress);

            if (rgmdplr[iPlayer].fAi) {
                fWorkDone = true;
                gd.fGeneratingTurn = 1;
                gd.fHostMode = 1;
                fOpened = FOpenFile(dtLog, iPlayer, 0x20);
                gd.fGeneratingTurn = 0;
                gd.fHostMode = fHostSav;

                if (!fOpened) {
                    DoAiTurn(iPlayer, rgmdplr[iPlayer].wRaw_0000);
                } else {
                    StreamClose();
                }
            }
        }

        gd.fSubmit = fSubmitSav;

        if (fWorkDone) {
            DestroyCurGame();
            FLoadGame(szBase, mpdtsz[dtHost]);
        }

        gd.fAisDone = 1;
        fFileErrSilent = fErrSav;
    }
}

int16_t CTurnsOutSafe(void) {
    int16_t  idPlayerSav = idPlayer;
    uint16_t fGeneratingTurnSav = gd.fGeneratingTurn;
    uint16_t fHostModeSav = gd.fHostMode;

    idPlayer = -1;

    /* decompile: (gd.grBits & 0xfff5) | 8  => clear bit1/bit3, set bit3 */
    gd.fGeneratingTurn = 0;
    gd.fHostMode = 1;

    int16_t cOut = CFindTurnsOutstanding();

    gd.fGeneratingTurn = fGeneratingTurnSav;
    gd.fHostMode = fHostModeSav;
    idPlayer = idPlayerSav;

    return cOut;
}

int16_t CFindTurnsOutstanding(void) {
    int16_t cOut = 0;
    int16_t cAi = 0;
    int16_t i = 0;

    /* keep same scalar type as ctickLast so we don't need casts when assigning */
    int32_t tick = ctickLast;

    fFileErrSilent = 1;

    /* decompile: (gd.grBits & 0xfffd) | 2 => set bit1 */
    gd.fGeneratingTurn = 1;

    for (;;) {
        if (game.cPlayer <= i) {
            gd.fGeneratingTurn = 0;

            /* decompile: high-word bit4 = fAllAis */
            gd.fAllAis = (cAi == game.cPlayer);

            fFileErrSilent = 0;
            return cOut;
        }

        int16_t prev = ((int16_t *)rgOut)[i];
        int16_t idsError = 0;

        if (!rgplr[i].fAi) {
            ctickLast = tick;

            if (FCheckLogFile(i, &idsError) == 0) {
                if (idsError == 0) {
                    if (!rgplr[i].fDead) {
                        /* decompile: (gd.grBits high-word >> 7)&1 => fPartialTurn */
                        ((int16_t *)rgOut)[i] = gd.fPartialTurn ? 2 : 1;
                        cOut++;
                    } else {
                        ((int16_t *)rgOut)[i] = -1;
                    }
                } else {
                    if (idsError == 0x1c)
                        ((int16_t *)rgOut)[i] = 4;
                    else if (idsError == 0x1d)
                        ((int16_t *)rgOut)[i] = 5;
                    else
                        ((int16_t *)rgOut)[i] = 3;

                    cOut++;
                }
            } else {
                goto LAiOrIgnored;
            }
        } else {
        LAiOrIgnored:
            if (rgplr[i].fAi)
                cAi++;

            ctickLast = tick;
            ((int16_t *)rgOut)[i] = 0;
        }

        if (tick == 0 || ((int16_t *)rgOut)[i] != prev) {
            ctickLast = tick;
            tick = PlatformTickMs();
        }

        i++;
    }
}

#ifdef _WIN32

INT_PTR CALLBACK HostModeDialog(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    UINT    menuFlags;
    HWND    hwndCtrl;
    BOOL    fEnable;
    short   result;
    char   *psz;
    FARPROC dlgProc;

    HDC   hdcPaint;
    HMENU hmenuPopup;
    int   iPlayer;
    int   iCurrentMode;
    int   iNewMode;
    int   iMenu;
    UINT  popupFlags;
    POINT ptClient;
    RECT  rcClient;

    PAINTSTRUCT ps;
    MSG         msg;

    (void)lParam;

    switch (message) {
    case WM_DESTROY:
        KillTimer(hwnd, uTimerId);
        uTimerId = 0;
        return 0;

    case WM_PAINT:
        hdcPaint = BeginPaint(hwnd, &ps);

        if ((int)ctickLast == 0 && (int)((UINT_PTR)ctickLast >> 16) == 0) {
            CFindTurnsOutstanding();
        }

        if (gd.fReadOnly == 0) {
            hwndCtrl = GetDlgItem(hwnd, IDC_HOST_AUTO_GENERATE);
            if ((gd.fAllAis == 0) && ((vtimer.fAutoGenWhenIn != 0) || (vtimer.mdForce != 0))) {
                fEnable = TRUE;
            } else {
                fEnable = FALSE;
            }
            EnableWindow(hwndCtrl, fEnable);
        }

        DrawHostDialog2(hwnd, hdcPaint);
        EndPaint(hwnd, &ps);
        return 1;

    case WM_ERASEBKGND:
        GetClientRect(hwnd, &rcClient);
        FillRect((HDC)wParam, &rcClient, hbrButtonFace);
        return 1;

    case WM_CTLCOLORSTATIC:
        SetBkColor((HDC)wParam, RGB((BYTE)crButtonFace, (BYTE)((UINT)crButtonFace >> 8), (BYTE)((UINT)crButtonFace >> 16)));
        return (INT_PTR)hbrButtonFace;

    case WM_SETCURSOR: {
        /* Only set the hand cursor when hovering the player-mode column. */
        GetCursorPos(&ptClient);
        ScreenToClient(hwnd, &ptClient);

        if (((5 < ptClient.x) && (ptClient.x < dyArial8 + 7)) && (0x2f < ptClient.y) &&
            ((iPlayer = (ptClient.y - 0x30) / (dyArial8 + 4), iPlayer < game.cPlayer) && (((ptClient.y - 0x30) % (dyArial8 + 4)) < dyArial8 + 1))) {
            SetCursor(hcurHand);
            return 1;
        }
        return 0;
    }

    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN: {
        GetCursorPos(&ptClient);
        ScreenToClient(hwnd, &ptClient);

        if (!(((5 < ptClient.x) && (ptClient.x < dyArial8 + 7)) && (0x2f < ptClient.y) &&
              ((iPlayer = (ptClient.y - 0x30) / (dyArial8 + 4), iPlayer < game.cPlayer) && (((ptClient.y - 0x30) % (dyArial8 + 4)) < dyArial8 + 1)))) {
            return 0;
        }

        {
            PLAYER *pl = &rgplr[iPlayer];

            /* determine current player mode */
            if (pl->fAi == 0)
                iCurrentMode = 0;
            else if (pl->idAi == 7)
                iCurrentMode = 2;
            else
                iCurrentMode = 1;

            hmenuPopup = CreatePopupMenu();
            iPopMenuSel = -1;

            for (iMenu = 0; iMenu < 3; iMenu++) {
                CchGetString(iMenu + idsHumanControlled, szWork);

                if (iMenu == 1) {
                    if ((pl->fAi == 0) || (pl->idAi == 7))
                        menuFlags = MF_GRAYED;
                    else
                        menuFlags = 0;
                } else if ((pl->fAi == 0) || (pl->idAi == 7)) {
                    menuFlags = 0;
                } else {
                    menuFlags = MF_GRAYED;
                }

                if (iMenu == iCurrentMode)
                    menuFlags |= MF_CHECKED;

                AppendMenu(hmenuPopup, menuFlags, IDM_POPUP_BASE + (UINT)iMenu, szWork);
            }

            ClientToScreen(hwnd, &ptClient);

            popupFlags = (message == WM_LBUTTONDOWN) ? TPM_LEFTBUTTON : TPM_RIGHTBUTTON;

            TrackPopupMenu(hmenuPopup, popupFlags | TPM_LEFTALIGN, ptClient.x, ptClient.y, 0, hwnd, NULL);

            DestroyMenu(hmenuPopup);

            iNewMode = -1;
            fEnable = PeekMessage(&msg, hwnd, WM_COMMAND, WM_COMMAND, PM_REMOVE);

            if ((fEnable != 0) && (msg.wParam >= IDM_POPUP_BASE) && (msg.wParam < (IDM_POPUP_BASE + 3))) {
                iNewMode = (int)(msg.wParam - IDM_POPUP_BASE);
            }

            if ((iNewMode != -1) && (iCurrentMode != iNewMode)) {
                pl->fAi = (iNewMode != 0);
                if (iNewMode == 2)
                    pl->idAi = 7;

                /* salt flip: decompile shows uint* +2, but the real intent is 16-bit word ops on lSalt */
                {
                    uint16_t *pSalt = (uint16_t *)&rgplr[iPlayer].lSalt; /* [0]=low, [1]=high */
                    uint16_t  hi = pSalt[1];
                    pSalt[0] = (uint16_t)~pSalt[0];
                    pSalt[1] = (uint16_t)~hi;
                }

                FMarkFile(dtTurn, (short)iPlayer, 8, (UINT)(iNewMode != 0));
                FMarkFile(dtHost, (short)iPlayer, 8, (UINT)(iNewMode != 0));

                gd.fAisDone = 0;

                fProcessingTimer = 1;
                CFindTurnsOutstanding();

                hwndCtrl = GetDlgItem(hwnd, IDC_HOST_AUTO_GENERATE);
                if ((gd.fAllAis == 0) && ((vtimer.fAutoGenWhenIn != 0) || (vtimer.mdForce != 0)))
                    fEnable = TRUE;
                else
                    fEnable = FALSE;

                EnableWindow(hwndCtrl, fEnable);
                DrawHostDialog2(hwnd, NULL);
                fProcessingTimer = 0;
            }
        }

        return 0;
    }

    case WM_INITDIALOG:
        StickyDlgPos(hwnd, (POINT *)&ptStickyHostModeDlg, 1);

        hwndCtrl = GetDlgItem(hwnd, IDC_HOST_GAME_NAME_TEXT);
        SetWindowText(hwndCtrl, game.szName);

        hwndCtrl = GetDlgItem(hwnd, IDC_HOST_FILE_TEXT);
        SetWindowText(hwndCtrl, szBase);

        hwndCtrl = GetDlgItem(hwnd, IDC_HOST_AUTO_GENERATE);
        fEnable = ((gd.fReadOnly == 0) && ((vtimer.fAutoGenWhenIn != 0) || (vtimer.mdForce != 0)));
        EnableWindow(hwndCtrl, fEnable);

        hwndCtrl = GetDlgItem(hwnd, IDC_HOST_GENERATE_NOW);
        EnableWindow(hwndCtrl, (gd.fReadOnly == 0));

        hwndCtrl = GetDlgItem(hwnd, IDC_HOST_PASSWORD);
        EnableWindow(hwndCtrl, (gd.fReadOnly == 0));

        /* Win32: attach timer to this dialog, not a magic HWND literal */
        uTimerId = SetTimer(hwnd, 0, 10000, NULL);
        return 1;

    case WM_COMMAND: {
        const int id = (int)LOWORD(wParam);
        const int code = (int)HIWORD(wParam);

        /* Only treat actual activations as commands (buttons, etc.) */
        if (code != 0 && code != BN_CLICKED)
            return 0;

        if ((id == IDC_HOST_GENERATE_NOW) || (id == IDC_HOST_CLOSE) || (id == IDC_HOST_AUTO_GENERATE) || (id == IDCANCEL)) {

            if (id == IDC_HOST_GENERATE_NOW) {
                /* Shift/Ctrl affect iPassCnt exactly as in the decompile */
                if (GetAsyncKeyState(VK_SHIFT) < 0) {
                    if (GetAsyncKeyState(VK_CONTROL) < 0)
                        iPassCnt = 999;
                    else
                        iPassCnt = 9;
                } else {
                    if (GetAsyncKeyState(VK_CONTROL) < 0)
                        iPassCnt = 99;
                    else
                        iPassCnt = 0;
                }

                if (iPassCnt == 0) {
                    result = CFindTurnsOutstanding();
                    if (result != 0) {
                        psz = PszFormatIds(idsSureWishGenerateOptionDoesGuaranteePlayers, NULL);
                        result = AlertSz(psz, 0x1024);
                        if (result != IDYES)
                            return 1;
                    }
                } else {
                    psz = PszGetCompressedString(idsSureWantForceGenerateDTurnsRow);
                    snprintf(szWork, sizeof(szWork), psz);

                    hwndCtrl = GetFocus();
                    result = (short)MessageBox(hwndCtrl, szWork, "Stars!", MB_TASKMODAL | MB_ICONEXCLAMATION | MB_YESNO);
                    if (result != IDYES) {
                        iPassCnt = 0;
                        return 1;
                    }
                }
            }

            /* persist dialog position on exit (fInit=0) */
            StickyDlgPos(hwnd, (POINT *)&ptStickyHostModeDlg, 0);

            /*
             * Side-effects associated with closing/auto-gen should happen
             * BEFORE EndDialog() (modal loop exits immediately).
             */
            if (id == IDC_HOST_AUTO_GENERATE) {
                EnsureAis();
            } else if ((id == IDC_HOST_CLOSE || id == IDCANCEL) && gd.fClose && ini.fCmdLine) {
                PostQuitMessage(vretExitValue);
            }

            if (id == IDCANCEL || id == IDC_HOST_CLOSE)
                EndDialog(hwnd, 0);
            else if (id == IDC_HOST_AUTO_GENERATE)
                EndDialog(hwnd, (INT_PTR)-1);
            else
                EndDialog(hwnd, 1);

            return 1;
        }

        if (id == IDC_HOST_PASSWORD) {
            result = FCheckPassword();
            if (result == 0)
                return 0;

            dlgProc = MakeProcInstance(NewPasswordDlg, hInst);
            result = (short)DialogBox(hInst, MAKEINTRESOURCE(IDD_NEW_PASSWORD), hwnd, (DLGPROC)dlgProc);
            FreeProcInstance(dlgProc);
            SetFocus(hwnd);
            return result;
        }

        if (id == IDC_HELP) {
            WinHelp(hwnd, szHelpFile, HELP_CONTEXT, 0x440);
            return 1;
        }

        if (id == IDC_HOST_OPTIONS) {
            dlgProc = MakeProcInstance(HostOptionsDialog, hInst);
            result = (short)DialogBox(hInst, MAKEINTRESOURCE(IDD_HOST_OPTIONS), hwnd, (DLGPROC)dlgProc);
            FreeProcInstance(dlgProc);
            SetFocus(hwnd);

            if (result == 0)
                return 0;

            /* decompile refresh: may re-enable Auto Generate after options */
            if (gd.fReadOnly == 0) {
                hwndCtrl = GetDlgItem(hwnd, IDC_HOST_AUTO_GENERATE);
                if ((gd.fAllAis == 0) && ((vtimer.fAutoGenWhenIn != 0) || (vtimer.mdForce != 0)))
                    fEnable = TRUE;
                else
                    fEnable = FALSE;
                EnableWindow(hwndCtrl, fEnable);
            }

            return result;
        }

        return 0;
    }

    case WM_TIMER:
        if (fProcessingTimer == 0) {
            fProcessingTimer = 1;
            CFindTurnsOutstanding();
            DrawHostDialog2(hwnd, NULL);
            fProcessingTimer = 0;
        }
        return 0;
    case WM_CLOSE:
        StickyDlgPos(hwnd, (POINT *)&ptStickyHostModeDlg, 0);
        EndDialog(hwnd, 0);
        return 1;
    }

    return 0;
}

int16_t FFindSomethingAndSelectIt(void) {
    PLANET *lpplMac;
    PLANET *lppl;
    int16_t i;
    FLEET  *lpfl;

    /* TODO: implement */
    return 0;
}

LRESULT CALLBACK TitleWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC         hdc;
    int16_t     i;
    HPALETTE    hpalSav;
    RECT        rc;
    int16_t     dy;
    int16_t     dxGap;
    int16_t     dx;
    int16_t     xCur;
    char       *psz;
    PAINTSTRUCT ps;
    RECT        rcWnd;
    HBRUSH      hbrSav;
    RECT        rcT;
    LOGFONT    *plf;
    HFONT       hfont;
    HFONT       hfontSav;

    /* --------------------------------------------------------------------
     * Notes:
     * - This is a direct translation of the Win16 TitleWndProc (1020:9126).
     * - Button commands (New / Load / Continue / Exit) call existing stubs.
     * - Palette handling matches WM_QUERYNEWPALETTE / WM_PALETTECHANGED logic.
     * -------------------------------------------------------------------- */

    switch (msg) {
    case WM_CREATE: {
        DBG_LOGD("WM_CREATE: vcScreenColors=%d vhdibTitle=%p vhpalSplash=%p dyArial8=%d", (int)vcScreenColors, (void *)vhdibTitle, (void *)vhpalSplash,
                 (int)dyArial8);

        /* Load splash (256+ colors only) and palette. */
        if (vcScreenColors >= 8) {
            DBG_LOGD("WM_CREATE: loading splash resource IDDIB_SPLASH=%d", (int)IDDIB_SPLASH);
            vhdibTitle = HdibLoadBigResource(IDDIB_SPLASH);
            DBG_LOGD("WM_CREATE: HdibLoadBigResource -> vhdibTitle=%p", (void *)vhdibTitle);

            if (vhpalSplash == NULL && vhdibTitle != NULL) {
                vhpalSplash = HpalFromDib(vhdibTitle);
                DBG_LOGD("WM_CREATE: HpalFromDib(%p) -> vhpalSplash=%p", (void *)vhdibTitle, (void *)vhpalSplash);
            }
        } else {
            DBG_LOGD("WM_CREATE: skipping splash load (vcScreenColors=%d < 8)", (int)vcScreenColors);
        }

        GetClientRect(hwnd, &rc);
        DBG_LOGD("WM_CREATE: client rc: L=%d T=%d R=%d B=%d", (int)rc.left, (int)rc.top, (int)rc.right, (int)rc.bottom);

        /* Use the same 4:3 letterboxed “content rect” as the splash so buttons stay inside it. */
        {
            const int32_t srcW = 800;
            const int32_t srcH = 600;

            const int32_t fullW = (int32_t)(rc.right - rc.left);
            const int32_t fullH = (int32_t)(rc.bottom - rc.top);

            int32_t contentW = fullW;
            int32_t contentH = (contentW * srcH) / srcW;
            if (contentH > fullH) {
                contentH = fullH;
                contentW = (contentH * srcW) / srcH;
            }

            const int32_t contentX = (fullW - contentW) / 2;
            const int32_t contentY = (fullH - contentH) / 2;

            /* Log so you can confirm the math matches WM_PAINT */
            DBG_LOGD("WM_CREATE: content rc: X=%ld Y=%ld W=%ld H=%ld", (long)contentX, (long)contentY, (long)contentW, (long)contentH);

            /* Now base layout off contentW/contentH, but keep everything in 32-bit until the end. */

            /* dx: max(120, contentW/8) */
            {
                int32_t dx32 = (contentW >> 3);
                DBG_LOGD("WM_CREATE: dx init contentW>>3=%ld", (long)dx32);

                if (dx32 < 120)
                    dx32 = 120;
                DBG_LOGD("WM_CREATE: dx clamped=%ld", (long)dx32);

                /* if short content window, add dx/6 */
                if (contentH < 650) {
                    int32_t add32 = dx32 / 6;
                    dx32 += add32;
                    DBG_LOGD("WM_CREATE: short contentH=%ld -> dx += dx/6 (%ld) => %ld", (long)contentH, (long)add32, (long)dx32);
                }

                /* dxGap = (contentW - dx*4)/4 */
                {
                    int32_t dxGap32 = (contentW - (dx32 * 4)) / 4;
                    if (dxGap32 < 0)
                        dxGap32 = 0; /* avoid negative gaps if window is very narrow */

                    /* xCur starts at left edge of content rect + half gap */
                    int32_t xCur32 = contentX + (dxGap32 / 2);

                    dx = (int16_t)dx32;
                    dxGap = (int16_t)dxGap32;
                    xCur = (int16_t)xCur32;

                    DBG_LOGD("WM_CREATE: dxGap=%ld xCur(start)=%ld (contentX=%ld)", (long)dxGap32, (long)xCur32, (long)contentX);
                }
            }

            /* dy for buttons: base on contentH, not full client height */
            if (contentH > 500)
                dy = (int16_t)((5 * dyArial8) / 2);
            else
                dy = (int16_t)(dyArial8 << 1);

            DBG_LOGD("WM_CREATE: dy=%d (contentH=%ld)", (int)dy, (long)contentH);

            /* If you also compute a Y position for the buttons elsewhere,
               anchor it to contentY+contentH (bottom of the splash area) instead of rc.bottom. */
            /* Example:
               yButtons = (int16_t)(contentY + contentH - dy - margin);
            */
        }

        /* Create 4 buttons */
        for (i = 0; i < 4; i++) {
            psz = PszGetCompressedString(idsNewGame + i);
            DBG_LOGD("WM_CREATE: button[%d] text id=%d psz=%p '%s'", (int)i, (int)(idsNewGame + i), (void *)psz, (psz ? psz : "(null)"));

            rghwndBtnSplash[i] = CreateWindow("BUTTON", psz, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, xCur, (int16_t)(rc.bottom - dy - ((5 * dyArial8) / 2)), dx,
                                              dy, hwnd, (HMENU)(uintptr_t)i, hInst, NULL);

            DBG_LOGD("WM_CREATE: CreateWindow BUTTON[%d] -> hwnd=%p at x=%d y=%d w=%d h=%d", (int)i, (void *)rghwndBtnSplash[i], (int)xCur,
                     (int)(rc.bottom - dy - ((5 * dyArial8) / 2)), (int)dx, (int)dy);

            if (rghwndBtnSplash[i] == NULL) {
                DBG_LOGD("WM_CREATE: ERROR: CreateWindow failed for button[%d]", (int)i);
            }

            if (i == 2) {
                DBG_LOGD("WM_CREATE: button[2] continue check: szBase[0]=0x%02x szBase='%s'", (unsigned)(uint8_t)szBase[0], szBase);

                /* Default: disable unless we prove the file exists. */
                bool enable = false;

                if (szBase[0] != '\0') {
                    int acc = Stars_Access(szBase, STARS_ACCESS_OK); /* mode should be 0 like __access(path,0) */
                    DBG_LOGD("WM_CREATE: Stars_Access('%s', mode=%d) -> %d", szBase, (int)STARS_ACCESS_OK, (int)acc);

                    if (acc != -1) {
                        enable = true; /* file exists -> keep enabled */
                        DBG_LOGD("WM_CREATE: button[2] enabled (file exists)");
                    } else {
                        DBG_LOGD("WM_CREATE: button[2] will disable (file missing/unreadable)");
                    }
                } else {
                    DBG_LOGD("WM_CREATE: button[2] will disable (empty szBase)");
                }

                EnableWindow(rghwndBtnSplash[2], enable ? TRUE : FALSE);
                if (!enable) {
                    DBG_LOGD("WM_CREATE: disabled button[2]");
                }
            }

            if (rc.bottom < 500) {
                DBG_LOGD("WM_CREATE: setting font for button[%d] font=%p", (int)i, (void *)rghfontArial8[1]);
                SendMessage(rghwndBtnSplash[i], WM_SETFONT, (WPARAM)rghfontArial8[1], MAKELPARAM(TRUE, 0));
            }

            xCur = (int16_t)(xCur + dx + dxGap);
        }

        DBG_LOGD("WM_CREATE: done");
        return 0;
    }

    case WM_DESTROY: {
        DBG_LOGD("WM_DESTROY: vhdibTitle=%p vhpalSplash=%p fFreeingTitle=%d gd.fExitWindows=%d vretExitValue=%d", (void *)vhdibTitle, (void *)vhpalSplash,
                 (int)fFreeingTitle, (int)gd.fExitWindows, (int)vretExitValue);

        if (vhdibTitle != NULL) {
            DBG_LOGD("WM_DESTROY: freeing DIB %p", (void *)vhdibTitle);
            GlobalUnlock(vhdibTitle);
            FreeResource(vhdibTitle);
            vhdibTitle = NULL;
        }

        if (!fFreeingTitle) {
            DBG_LOGD("WM_DESTROY: normal exit path");
            if (gd.fExitWindows) {
                DBG_LOGD("WM_DESTROY: ExitWindows(%u)", (unsigned)(uint16_t)vretExitValue);
                ExitWindows((DWORD)(uint16_t)vretExitValue, 0);
            } else {
                DBG_LOGD("WM_DESTROY: WriteIniSettings(); PostQuitMessage(%d)", (int)vretExitValue);
                WriteIniSettings();
                PostQuitMessage(vretExitValue);
            }
        } else {
            DBG_LOGD("WM_DESTROY: fFreeingTitle=1 => skipping exit path");
        }

        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    case WM_QUERYNEWPALETTE:
        DBG_LOGD("WM_QUERYNEWPALETTE: vcScreenColors=%d vhpalSplash=%p", (int)vcScreenColors, (void *)vhpalSplash);
        /* fallthrough */
    case WM_PALETTECHANGED: {
        DBG_LOGD("WM_PALETTECHANGED: wParam(hwndChanged)=%p self=%p vcScreenColors=%d vhpalSplash=%p", (void *)(HWND)wParam, (void *)hwnd, (int)vcScreenColors,
                 (void *)vhpalSplash);

        if (msg == WM_PALETTECHANGED && (HWND)wParam == hwnd) {
            DBG_LOGD("WM_PALETTECHANGED: ignoring (we caused it)");
            return 0;
        }

        if (vcScreenColors < 8 || vhpalSplash == NULL) {
            DBG_LOGD("WM_PALETTE*: skipping realize (colors=%d pal=%p)", (int)vcScreenColors, (void *)vhpalSplash);
            return 0;
        }

        hdc = GetDC(hwnd);
        DBG_LOGD("WM_PALETTE*: GetDC -> %p", (void *)hdc);

        hpalSav = SelectPalette(hdc, vhpalSplash, FALSE);
        DBG_LOGD("WM_PALETTE*: SelectPalette -> old=%p new=%p", (void *)hpalSav, (void *)vhpalSplash);

        i = (int16_t)RealizePalette(hdc);
        DBG_LOGD("WM_PALETTE*: RealizePalette -> %d", (int)i);

        SelectPalette(hdc, hpalSav, FALSE);
        ReleaseDC(hwnd, hdc);

        if (i != 0) {
            DBG_LOGD("WM_PALETTE*: invalidating (palette changed)");
            InvalidateRect(hwnd, NULL, TRUE);
            return 1;
        }

        return 0;
    }

    case WM_COMMAND: {
        DBG_LOGD("WM_COMMAND: wParam=0x%lx lParam=0x%lx (id=%lu) fFreeingTitle=%d", (unsigned long)wParam, (unsigned long)lParam,
                 (unsigned long)(uint16_t)wParam, (int)fFreeingTitle);

        switch ((uint16_t)wParam) {
        case IDM_TITLE_NEW_GAME:
            NewGameWizard(hwnd, 0);

            /* Original: if lpPlanets==NULL AND game.lid==0, keep title focus. */
            if (lpPlanets == NULL && game.lid == 0) {
                DBG_LOGD("WM_COMMAND: new game failed -> SetFocus(title)");
                SetFocus(hwnd);
            } else {
                if (!fFreeingTitle) {
                    DBG_LOGD("WM_COMMAND: destroying title window hwndTitle=%p hwndFrame=%p", (void *)hwndTitle, (void *)hwndFrame);
                    fFreeingTitle = 1;
                    DestroyWindow(hwndTitle);
                    hwndTitle = NULL;
                }

                DBG_LOGD("WM_COMMAND: ShowWindow(hwndFrame, SW_SHOW)");
                ShowWindow(hwndFrame, SW_SHOW);
            }
            break;

        case IDM_TITLE_OPEN_GAME:
        case IDM_TITLE_CONTINUE: {
            ini.fStartupFile = (wParam == IDM_TITLE_CONTINUE) ? 1 : 0;

            if (FOpenGame(hwnd, 0)) {
                if (!fFreeingTitle) {
                    DBG_LOGD("WM_COMMAND: destroying title window hwndTitle=%p", (void *)hwndTitle);
                    fFreeingTitle = 1;
                    DestroyWindow(hwndTitle);
                    hwndTitle = NULL;
                }

                if (idPlayer != -1) {
                    DBG_LOGD("WM_COMMAND: ShowWindow(hwndFrame, SW_SHOW)");
                    ShowWindow(hwndFrame, SW_SHOW);
                }

                InitializeMenu(NULL);

                PostMessage(hwndFrame, WM_COMMAND, (WPARAM)IDM_FRAME_POST_OPEN, 0);

                if (game.fTutorial && idPlayer == 0) {
                    StartTutor(0);
                }
            } else {
                DBG_LOGD("WM_COMMAND: open failed -> SetFocus(title)");
                SetFocus(hwnd);
            }

            ini.fStartupFile = 0;
            break;
        }

        case IDM_TITLE_EXIT:
            DBG_LOGD("WM_COMMAND: Exit path gd.fExitWindows=%d vretExitValue=%d", (int)gd.fExitWindows, (int)vretExitValue);

            if (gd.fExitWindows) {
                ExitWindows((DWORD)(uint16_t)vretExitValue, 0);
            } else {
                WriteIniSettings();
                PostQuitMessage(vretExitValue);
            }
            break;

        default:
            return 0;
        }

        return 0;
    }

    case WM_PAINT: {
        DBG_LOGD("WM_PAINT: IsIconic=%d vcScreenColors=%d vhdibTitle=%p vhpalSplash=%p", (int)IsIconic(hwnd), (int)vcScreenColors, (void *)vhdibTitle,
                 (void *)vhpalSplash);

        if (IsIconic(hwnd)) {
            hdc = BeginPaint(hwnd, &ps);
            DBG_LOGD("WM_PAINT(iconic): BeginPaint hdc=%p hiconStars=%p", (void *)hdc, (void *)hiconStars);
            DrawIcon(hdc, 2, 2, hiconStars);
            EndPaint(hwnd, &ps);
            return 0;
        }

        hdc = BeginPaint(hwnd, &ps);
        DBG_LOGD("WM_PAINT: BeginPaint hdc=%p", (void *)hdc);

        hbrSav = (HBRUSH)SelectObject(hdc, hbrButtonFace);
        DBG_LOGD("WM_PAINT: SelectObject(hbrButtonFace=%p) -> old=%p", (void *)hbrButtonFace, (void *)hbrSav);

        GetClientRect(hwnd, &rcWnd);
        DBG_LOGD("WM_PAINT: client rcWnd: L=%d T=%d R=%d B=%d", (int)rcWnd.left, (int)rcWnd.top, (int)rcWnd.right, (int)rcWnd.bottom);

        if (vcScreenColors >= 8 && vhdibTitle != NULL) {
            /* source is 800x600 (4:3) */
            const int32_t srcW = 800;
            const int32_t srcH = 600;

            RECT rc;
            GetClientRect(hwnd, &rc);

            const int32_t fullW = (int32_t)(rc.right - rc.left);
            const int32_t fullH = (int32_t)(rc.bottom - rc.top);

            /* fit with preserved aspect (integer, 32-bit intermediates) */
            int32_t dstW = fullW;
            int32_t dstH = (dstW * srcH) / srcW;
            if (dstH > fullH) {
                dstH = fullH;
                dstW = (dstH * srcW) / srcH;
            }

            /* center in client */
            const int32_t dstX = (fullW - dstW) / 2;
            const int32_t dstY = (fullH - dstH) / 2;

            /* (optional) clear bars so you don’t see junk from previous frames */
            PatBlt(hdc, 0, 0, fullW, fullH, BLACKNESS);

            DibBlt(hdc, dstX, dstY, dstW, dstH, vhdibTitle, 0, 0, srcW, srcH, SRCCOPY);
        } else {
            DBG_LOGD("WM_PAINT: fallback stars: colors=%d vhdibTitle=%p", (int)vcScreenColors, (void *)vhdibTitle);
            /* ... existing fallback ... */
        }

        psz = SzVersion();
        DBG_LOGD("WM_PAINT: SzVersion -> %p '%s'", (void *)psz, (psz ? psz : "(null)"));

        if (rghwndBtnSplash[0] == NULL)
            DBG_LOGD("WM_PAINT: WARNING: rghwndBtnSplash[0]==NULL (buttons not created?)");
        else
            DBG_LOGD("WM_PAINT: rghwndBtnSplash[0]=%p", (void *)rghwndBtnSplash[0]);

        GetWindowRect(rghwndBtnSplash[0], &rc);
        DBG_LOGD("WM_PAINT: button0 rect (screen coords): L=%d T=%d R=%d B=%d", (int)rc.left, (int)rc.top, (int)rc.right, (int)rc.bottom);

        rcWnd.top = (int16_t)(rc.top - ((9 * dyArial8) / 2));
        rcWnd.bottom = (int16_t)(rcWnd.top + ((3 * dyArial8) / 2));

        DBG_LOGD("WM_PAINT: version rcWnd (mixed coords!): L=%d T=%d R=%d B=%d dyArial8=%d", (int)rcWnd.left, (int)rcWnd.top, (int)rcWnd.right,
                 (int)rcWnd.bottom, (int)dyArial8);

        RcCtrTextOut(hdc, &rcWnd, psz, (int16_t)strlen(psz));
        DBG_LOGD("WM_PAINT: RcCtrTextOut done");

        SelectObject(hdc, hbrSav);
        EndPaint(hwnd, &ps);
        DBG_LOGD("WM_PAINT: EndPaint done");
        return 0;
    }

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

void CommandHandler(HWND hwnd, WPARAM wParam) {
    POINT pt;
    HMENU hmenu;
    int16_t (*lpProc)(void);
    int16_t  dy;
    char     szExt[4];
    int16_t  dx;
    int16_t  fRet;
    RECT     rc;
    int16_t  iplrOld;
    int16_t  cPageX;
    int16_t  idCur;
    int16_t  mf;
    int16_t  id;
    char    *psz;
    uint16_t hcurSav;
    int16_t  ids;
    PLANET  *lpplMac;
    int16_t  cObj;
    int16_t  ifl;
    PLANET  *lppl;
    FLEET   *lpfl;
    int16_t  i;
    // TIMERINFO ti;
    uint32_t dwTickCur;
    uint32_t dwTickBase;
    // PD pd;
    int16_t  cPageY;
    int16_t  xPage;
    int16_t  dxMax;
    int16_t  dxDPI;
    int16_t  dyPrintTiny;
    int16_t  dMargin;
    int16_t  y;
    int32_t  ldx;
    uint16_t hfontPrintTiny;
    uint16_t hfontPrint;
    POINT    ptLegendB;
    POINT    ptLegendA;
    int16_t  dyPrint;
    int16_t  dyMax;
    uint16_t hfontSav;
    int16_t  dSize;
    int16_t  yPage;
    int16_t  cch;
    int32_t  ldy;
    int16_t  dyDPI;
    int16_t  yOff;
    int16_t  xOff;
    int32_t  x;
    char     szT[256];

    /* Popup menus use temporary IDs 15000..15099. Convert to 0x10000..0x10063 */
    if (wParam >= 15000 && wParam < 15100) {
        // TODO: figure out how these map up to tooltips
        iPopMenuSel = 0x10000 + (wParam - 15000);
        return;
    }
    switch (wParam) {

    case IDM_FRAME_POST_OPEN:
        if (hwndScanner == NULL) {
            return;
        }

        /* Temporarily suppress scanner drawing while we rebuild selection/layout. */
        gd.fNoScannerDraw = 1;
        RestoreSelection();
        RefitFrameChildren();
        gd.fNoScannerDraw = 0;

        InvalidateRect(hwndScanner, NULL, TRUE);
        UpdateWindow(hwndScanner);
        return;

    /* =======================
     * File
     * ======================= */
    case IDM_FILE_HOST_GAME:
        /* TODO */
        break;
    case IDM_FILE_NEW_GAME:
        /* TODO */
        break;

    case IDM_FILE_OPEN_GAME:
        /* TODO */
        break;

    case IDM_FILE_RETURN_TO_TITLE:
        /* TODO */
        break;

    case IDM_FILE_MRU1:
    case IDM_FILE_MRU2:
    case IDM_FILE_MRU3:
    case IDM_FILE_MRU4:
    case IDM_FILE_MRU5:
    case IDM_FILE_MRU6:
    case IDM_FILE_MRU7:
    case IDM_FILE_MRU8:
    case IDM_FILE_MRU9:
        /* TODO: open MRU slot (idCmd tells which) */
        break;

    /* =======================
     * Tools
     * ======================= */
    case IDM_TOOL_NEW_GAME:
        /* TODO */
        break;

    case IDM_TOOL_OPEN_GAME:
        /* TODO */
        break;

    /* =======================
     * Turn / Game flow
     * ======================= */
    case IDM_TURN_END_A:
        /* TODO */
        break;

    case IDM_TURN_END_B:
        /* TODO */
        break;

    case IDM_GAME_WAIT_FOR_TURN:
        /* TODO */
        break;

    /* =======================
     * Game dialogs / reports
     * ======================= */
    case IDM_GAME_RESEARCH:
        /* TODO */
        break;

    case IDM_GAME_SHIP_BUILDER:
        /* TODO */
        break;

    case IDM_GAME_BATTLE_PLANS1:
    case IDM_GAME_BATTLE_PLANS2:
        /* TODO */
        break;

    case IDM_GAME_RELATIONS:
    case IDM_GAME_RELATIONS2:
        /* TODO */
        break;

    case IDM_GAME_SCORE:
    case IDM_GAME_SCORE2:
        /* TODO */
        break;

    /* =======================
     * Race
     * ======================= */
    case IDM_RACE_CREATE:
        /* TODO */
        break;

    case IDM_RACE_EDIT1:
    case IDM_RACE_EDIT2:
        /* TODO */
        break;

    /* =======================
     * Reports
     * ======================= */
    case IDM_REPORT_PLANET:
        /* TODO */
        break;

    case IDM_REPORT_FLEET:
        /* TODO */
        break;

    case IDM_REPORT_ENEMY_FLEET:
        /* TODO */
        break;

    case IDM_REPORT_BATTLE:
        /* TODO */
        break;

    case IDM_REPORT_CYCLE:
        /* TODO */
        break;

    /* =======================
     * View
     * ======================= */
    case IDM_VIEW_LAYOUT_0:
    case IDM_VIEW_LAYOUT_1:
    case IDM_VIEW_LAYOUT_2:
        /* TODO */
        break;

    case IDM_VIEW_BROWSER_TOGGLE:
    case IDM_VIEW_BROWSER_TOGGLE2:
        if (game.lid == 0)
            break; /* no game loaded */

        if (idPlayer == (int16_t)-1)
            break; /* no active player */

        bool fShow = false;

        if (hwndBrowser == NULL) {
            /* Create modeless dialog; BrowserDlgProc should set hwndBrowser on WM_INITDIALOG */
            hwndBrowser = CreateDialogA(hInst,                         /* your HINSTANCE */
                                        MAKEINTRESOURCEA(IDD_BROWSER), /* TODO: replace with your real dialog resource id */
                                        hwndFrame,                     /* parent */
                                        BrowserWndProc);               /* your dialog proc */

            fShow = (hwndBrowser != NULL);
        } else {
            DestroyWindow(hwndBrowser);
            hwndBrowser = NULL;
            fShow = false;
        }

        /* Update menu check state: View submenu index 5, command id 0x100 in original */
        {
            HMENU hmenuSub = GetASubMenu(hwnd, 5);
            if (hmenuSub != NULL) {
                CheckMenuItem(hmenuSub, IDM_HELP_TECH_BROWSER, MF_BYCOMMAND | (fShow ? MF_CHECKED : MF_UNCHECKED));
            }
        }

        break;

    /* =======================
     * Scan zoom
     * ======================= */
    case IDM_SCAN_ZOOM_0:
    case IDM_SCAN_ZOOM_1:
    case IDM_SCAN_ZOOM_2:
    case IDM_SCAN_ZOOM_3:
    case IDM_SCAN_ZOOM_4:
    case IDM_SCAN_ZOOM_5:
    case IDM_SCAN_ZOOM_6:
    case IDM_SCAN_ZOOM_7:
    case IDM_SCAN_ZOOM_8:
        /* TODO: set scan zoom level */
        break;

    /* =======================
     * Fleet waypoint editing
     * ======================= */
    case IDM_FLEET_INSERT_WAYPOINT:
        /* TODO */
        break;

    case IDM_FLEET_DELETE_WAYPOINT:
        /* TODO */
        break;

    /* =======================
     * Help
     * ======================= */
    case IDM_HELP_CONTENTS:
    case IDM_HELP_CONTENTS2:
        /* TODO */
        break;

    case IDM_HELP_ABOUT:
        /* TODO */
        break;

    /* =======================
     * Debug
     * ======================= */
    case IDM_DEBUG_DUMP_UNIVERSE:
    case IDM_DEBUG_DUMP_PLANETS:
    case IDM_DEBUG_DUMP_FLEETS:
        /* TODO */
        break;

    case IDM_DEBUG_GEN_10_TURNS:
    case IDM_DEBUG_GEN_100_TURNS:
        /* TODO */
        break;

    default:
        DBG_LOGE("CommandHandler: unhandled command %u\n", (unsigned)wParam);
        break;
    }

    /* TODO: implement */
}

LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HDC      hdc;
    int16_t  i;
    HPALETTE hpalSav;
    int      ich;
    int16_t  fErrSav;
    int16_t  idCur;
    int16_t  iOffset;
    HCURSOR  hcs;
    int16_t  id;
    int16_t  idPlanet;
    POINT    ptOld;
    POINT    pt;
    UINT_PTR uTimerIdOld;
    int16_t  grSel;
    char    *pch;
    RECT     rc;
    char     szExt[8];
    int16_t (*lpProc)(void);
    int16_t     fRet;
    POINT       ptAct;
    RECT        rc2;
    int32_t     lSerial;
    POINT       ptD;
    HBRUSH      hbrSav;
    POINT       ptStart;
    POINT       ptChg;
    TEXTMETRIC  tm;
    PAINTSTRUCT ps;
    int16_t     yOffset;
    char        szTemp[256];
    MINMAXINFO *pmmi;
    HWND        hWndParent;
    FARPROC     dlgProc;
    int16_t     result;

    switch (msg) {
    case WM_CREATE:
        hdc = GetDC(hwnd);
        if (hdc != NULL) {
            (void)FCreateFonts(hdc);
            GetTextMetrics(hdc, &tm);
            dySysFont = (int16_t)tm.tmHeight;
            dySBar = (int16_t)((int32_t)(dyArial8 + 0x0c) * 2);
            ReleaseDC(hwnd, hdc);
        } else {
            dySysFont = 0;
            dySBar = (int16_t)((int32_t)(dyArial8 + 0x0c) * 2);
        }

        InitTiles();
        EnsureTileSize(iWindowLayout == 2);
        DBG_LOGD("WM_CREATE");
        return 0;

    case WM_SIZE:
        if ((wParam == SIZE_MAXIMIZED) || (wParam == SIZE_RESTORED)) {
            /* match Win16: take low/high 16 bits */
            vfs.dx = (int16_t)(uint16_t)LOWORD(lParam);
            vfs.dy = (int16_t)(uint16_t)HIWORD(lParam);
            RefitFrameChildren();
        }
        return 0;

    case WM_ACTIVATE:
        /* decompile returns 0 */
        return 0;

    case WM_CLOSE:
        /* from decompile */
        DestroyWindow(hwnd);
        return 0;

    case WM_ERASEBKGND: {
        /* from decompile */
        RECT rcClient;
        HDC  hdcErase = (HDC)wParam;

        GetClientRect(hwnd, &rcClient);

        if (IsIconic(hwnd) != 0) {
            FillRect(hdcErase, &rcClient, hbrDesktop);
            return 0; /* iconic case returns 0 */
        }

        if (hwndScanner != NULL) {
            RECT  rcScan;
            POINT pts[2];

            GetClientRect(hwndScanner, &rcScan);
            pts[0].x = rcScan.left;
            pts[0].y = rcScan.top;
            pts[1].x = rcScan.right;
            pts[1].y = rcScan.bottom;

            MapWindowPoints(hwndScanner, hwnd, pts, 2);
            ExcludeClipRect(hdcErase, pts[0].x, pts[0].y, pts[1].x, pts[1].y);
        }

        FillRect(hdcErase, &rcClient, hbrButtonFace);
        return 1;
    }

    case WM_SYSCOLORCHANGE:
    case WM_WININICHANGE:
        /* from decompile */
        FGetSystemColors();
        return 0;

    case WM_PAINT: {
        /* from decompile */
        PAINTSTRUCT psLocal;
        HDC         hdcPaint;
        HGDIOBJ     hOld;

        if (IsIconic(hwnd) == 0) {
            hdcPaint = BeginPaint(hwnd, &psLocal);

            hOld = SelectObject(hdcPaint, hbrButtonShadow);

            if (iWindowLayout == 0 || (iWindowLayout != 1 && iWindowLayout != 2)) {
                PatBlt(hdcPaint, vfs.xTop + 5, 0, 2, vfs.dy, PATCOPY);
                PatBlt(hdcPaint, 0, vfs.y1 + 5, vfs.xTop + 2, 2, PATCOPY);
                PatBlt(hdcPaint, 0, vfs.y2 + 5, vfs.xTop + 2, 2, PATCOPY);

                SelectObject(hdcPaint, hbrButtonHilite);
                PatBlt(hdcPaint, vfs.xTop + 1, 0, 1, vfs.y1 + 2, PATCOPY);
                PatBlt(hdcPaint, 0, vfs.y1 + 1, vfs.xTop + 1, 1, PATCOPY);
                PatBlt(hdcPaint, vfs.xTop + 1, vfs.y1 + 6, 1, (vfs.y2 - vfs.y1) - 4, PATCOPY);
                PatBlt(hdcPaint, 0, vfs.y2 + 1, vfs.xTop + 1, 1, PATCOPY);
                PatBlt(hdcPaint, vfs.xTop + 1, vfs.y2 + 6, 1, (vfs.dy - vfs.y2) - 6, PATCOPY);
            } else {
                /* decompile uses sign of gd.grBits2 upper word to decide toolbar offset */
                int yTop = ((int16_t)gd.grBits2 < 0) ? 0x24 : 0;

                PatBlt(hdcPaint, vfs.xTop + 5, yTop, 2, (vfs.y2 + 2) - yTop, PATCOPY);
                PatBlt(hdcPaint, 0, vfs.y1 + 5, vfs.xTop + 2, 2, PATCOPY);
                PatBlt(hdcPaint, vfs.xTop + 5, vfs.y2 + 5, (vfs.dx - vfs.xTop) - 5, 2, PATCOPY);
                PatBlt(hdcPaint, vfs.xTop + 5, vfs.y2 + 6, 2, (vfs.dy - vfs.y2) - 5, PATCOPY);

                SelectObject(hdcPaint, hbrButtonHilite);
                PatBlt(hdcPaint, vfs.xTop + 1, yTop, 1, (vfs.y1 + 2) - yTop, PATCOPY);
                PatBlt(hdcPaint, 0, vfs.y1 + 1, vfs.xTop + 1, 1, PATCOPY);
                PatBlt(hdcPaint, vfs.xTop + 1, vfs.y1 + 6, 1, (vfs.dy - vfs.y1) - 6, PATCOPY);
                PatBlt(hdcPaint, vfs.xTop + 6, vfs.y2 + 1, (vfs.dx - vfs.xTop) - 6, 1, PATCOPY);
            }

            SelectObject(hdcPaint, hOld);
            EndPaint(hwnd, &psLocal);
            return 0;
        }

        hdcPaint = BeginPaint(hwnd, &psLocal);
        {
            HICON hico = hiconHost;

            /* decompile:
               if (idPlayer != -1 || game.lid != 0) -> stars, and if timer -> wait */
            if ((idPlayer != -1) || (game.lid != 0))
                hico = hiconStars;
            if (uTimerId != 0)
                hico = hiconWait;

            DrawIcon(hdcPaint, 2, 2, hico);
        }
        EndPaint(hwnd, &psLocal);
        return 0;
    }

    case WM_SETCURSOR:
        /* from decompile: pass NULL out-param here */
        if (IsIconic(hwnd) == 0) {
            POINT ptCur;
            RECT  rcClient;

            GetCursorPos(&ptCur);
            ScreenToClient(hwndFrame, &ptCur);
            GetClientRect(hwnd, &rcClient);

            if (PtInRect(&rcClient, ptCur)) {
                HCURSOR hcsLocal = (HCURSOR)(uintptr_t)HcrsFromFrameWindowPt(ptCur, NULL);
                if (hcsLocal != NULL) {
                    SetCursor(hcsLocal);
                    return 1;
                }
            }
        }
        break;

    case WM_GETMINMAXINFO:
        pmmi = (MINMAXINFO *)lParam;
        pmmi->ptMinTrackSize.x = 0x208;
        pmmi->ptMinTrackSize.y = 0x17c;
        return 0;

    case WM_QUERYDRAGICON: {
        /* from decompile */
        HICON hico = hiconHost;

        if (idPlayer != -1) {
            hico = hiconStars;
            if (uTimerId != 0)
                hico = hiconWait;
        }

        return (LRESULT)(intptr_t)hico;
    }

    case WM_SYSCOMMAND: {
        /* from decompile (maximize/restore path) */
        const uint16_t sc = (uint16_t)(wParam & 0xFFF0u);

        if (sc == SC_MAXIMIZE || sc == SC_RESTORE) {
            int16_t  idPlayerSav = idPlayer;
            UINT_PTR uTimerSav = uTimerId;

            if (uTimerId != 0) {
                KillTimer(NULL, uTimerId);
                uTimerId = 0;
                CreateChildWindows();
            }

            if (idPlayerSav != -1) {
                int16_t fNew = FNewTurnAvail(idPlayerSav);
                if (fNew != 0) {
                    int16_t idAns;

                    if (uTimerSav == 0) {
                        char *psz = PszFormatIds(idsNewTurnAvailableWouldLikeLoad, NULL);
                        idAns = AlertSz(psz, MB_ICONQUESTION | MB_YESNOCANCEL);
                    } else {
                        char *psz = PszFormatIds(idsNewTurnAvailable, NULL);
                        (void)AlertSz(psz, MB_ICONASTERISK);
                        idAns = IDYES;
                    }

                    if (idAns == IDYES) {
                        char szExtLocal[8];

                        snprintf(szExtLocal, sizeof(szExtLocal), "m%d", (int)(idPlayerSav + 1));
                        DestroyCurGame();

                        if (FLoadGame(szBase, szExtLocal) == 0) {
                            char *psz = PszFormatIds(idsUnableOpenNewTurnFile, NULL);
                            AlertSz(psz, MB_ICONHAND);
                        } else {
                            CreateChildWindows();
                        }
                    } else if (idAns == IDCANCEL) {
                        if (uTimerSav == 0)
                            PostMessage(hwndFrame, WM_SYSCOMMAND, SC_MINIMIZE, 0);
                        else
                            PostMessage(hwndFrame, WM_COMMAND, WMX_UNKNOWN_006A, 0);
                        return 1;
                    }

                    SendMessage(hwndFrame, WM_COMMAND, IDM_FRAME_POST_OPEN, 0);
                    break; /* fall through to DefWindowProc */
                }
            }

            if (uTimerSav != 0) {
                if (uTimerType == 0x0d) {
                    PostMessage(hwnd, WM_STARS_HOST, 0, 0);
                    break;
                }

                if (uTimerType == 0x0e) {
                    char   *psz = PszFormatIds(idsTurnHasSubmittedChangesMadeAfterTurn, NULL);
                    int16_t idAns = AlertSz(psz, MB_ICONQUESTION | MB_YESNOCANCEL);

                    if (idAns == IDYES) {
                        if (FMarkFile(dtLog, idPlayerSav, 2, 0) == 0) {
                            char *psz2 = PszFormatIds(idsNewTurnCurrentlyGeneratedHostNewTurn, NULL);
                            AlertSz(psz2, MB_ICONHAND);

                            {
                                char szExtLocal[8];
                                snprintf(szExtLocal, sizeof(szExtLocal), "m%d", (int)(idPlayerSav + 1));
                                DestroyCurGame();

                                if (FLoadGame(szBase, szExtLocal) == 0) {
                                    char *psz3 = PszFormatIds(idsUnableOpenNewTurnFile, NULL);
                                    AlertSz(psz3, MB_ICONHAND);
                                } else {
                                    CreateChildWindows();
                                }
                            }
                        }
                    } else if (idAns == IDCANCEL) {
                        PostMessage(hwndFrame, WM_COMMAND, WMX_UNKNOWN_006A, 0);
                        return 1;
                    }
                }

                SendMessage(hwndFrame, WM_COMMAND, IDM_FRAME_POST_OPEN, 0);

                if (sel.pt.x > 1000 && sel.pt.y > 1000) {
                    CtrPointScan(sel.pt, 1);
                }
            }
        }

        break; /* default handling */
    }

    case WM_TIMER:
        if (uTimerId != 0) {
            uTimerIdOld = uTimerId;
            if (uTimerType == 1) {
                ich = 0;
                while (ich < 3) {
                    snprintf(szExt, sizeof(szExt), "m%d", (int)(idPlayer + 1));
                    if (FLoadGame(szBase, szExt) != 0) {
                        KillTimer(NULL, uTimerIdOld);
                        uTimerId = 0;
                        CreateChildWindows();
                        break;
                    }
                    ich++;
                }
                if (ich == 3) {
                    KillTimer(NULL, uTimerIdOld);
                    uTimerId = 0;
                    AlertSz(PszGetCompressedString(idsCantFindHostFile), MB_ICONHAND);
                }
            } else {
                if (uTimerType == 2) {
                    if (FLoadGame(szBase, mpdtsz[dtHost]) != 0) {
                        KillTimer(NULL, uTimerIdOld);
                        uTimerId = 0;
                        EnsureAis();
                        FGenerateTurn();
                        CreateChildWindows();
                    }
                }
            }
        }
        return 0;

    case WM_CHAR: {
        /* from decompile */
        if (hwndScanner != NULL && (wParam == (WPARAM)'-' || wParam == (WPARAM)'+')) {
            SendMessage(hwndScanner, WM_CHAR, wParam, lParam);
            return 0;
        }

        if (hwndMessage != NULL && ((wParam == (WPARAM)'-' || wParam == (WPARAM)'+') || (wParam == (WPARAM)'\r'))) {
            SendMessage(hwndMessage, WM_CHAR, wParam, lParam);
            return 0;
        }

        if (hwndPlanet != NULL && (wParam == (WPARAM)'f' || wParam == (WPARAM)'F')) {
            SendMessage(hwndPlanet, WM_CHAR, wParam, lParam);
            return 0;
        }

        if (hwndPlanet != NULL && sel.grobj == grobjPlanet && (wParam == (WPARAM)'q' || wParam == (WPARAM)'Q')) {
            ChangeProduction(0);
            return 0;
        }

        if ((sel.grobj & (grobjFleet | grobjPlanet)) == grobjNone)
            return 0;

        int16_t dir = 0;
        int16_t idAdj = 0;

        if (wParam == (WPARAM)'n') {
            dir = 1;
        } else if (wParam == (WPARAM)'p') {
            dir = -1;
        } else if (wParam == (WPARAM)'N' || wParam == (WPARAM)'P') {
            if (sel.grobj == grobjPlanet) {
                idAdj = IdFindAdjStarbase(sel.pl.id, (wParam == (WPARAM)'N') ? 1 : 0);
            } else if (wParam == (WPARAM)'N') {
                dir = 1;
            } else {
                dir = -1;
            }
        } else if ((wParam == (WPARAM)'r' || wParam == (WPARAM)'R') && sel.grobj == grobjFleet) {
            ShipCommandProc(hwndPlanet, 0, (uintptr_t)rghwndBtn[6]);
        }

        if (dir == 0 && idAdj == 0)
            return 0;

        if (sel.grobj != grobjFleet) {
            SelectAdjPlanet(dir, idAdj);
            return 0;
        }

        SelectAdjFleet(dir, idAdj);
        return 0;
    }

    case WM_COMMAND:
        CommandHandler(hwnd, wParam);
        return 0;

    case WM_DESTROY:
        if (uTimerId != 0) {
            KillTimer(NULL, uTimerId);
            uTimerId = 0;
        }

        WriteIniSettings();

        if (gd.fHostMode != 0) {
            (void)FMarkFile(dtHost, -1, 1, 0);
        }

        DestroyCurGame();

        if (gd.fExitWindows == 0) {
            PostQuitMessage(vretExitValue);
        } else {
            ExitWindows((DWORD)(uint16_t)vretExitValue, 0);
        }
        return 0;

    case WM_INITMENU:
        InitializeMenu((HMENU)wParam);
        return 0;

    case WM_ENTERIDLE:
        if ((gd.fTutorial != 0) && (tutor.fTurnDone != 0)) {
            AdvanceTutor();
        }
        return 0;

    case WM_LBUTTONDOWN:
        pt.x = (int16_t)(int32_t)(int16_t)LOWORD(lParam);
        pt.y = (int16_t)(int32_t)(int16_t)HIWORD(lParam);

        grSel = 0;
        hcs = (HCURSOR)(uintptr_t)HcrsFromFrameWindowPt(pt, &grSel);
        if (hcs == NULL) {
            return 0;
        }

        hdc = GetDC(hwnd);
        hbrSav = (HBRUSH)SelectObject(hdc, hbr50Screen);

        ptChg.x = 0;
        ptChg.y = 0;
        InvertPaneBorder(hdc, grSel, (POINT){0, 0}, NULL);

        ptStart = pt;
        SetCapture(hwnd);

        ptOld = pt;
        while (FGetMouseMove(&ptAct) != 0) {
            if ((ptAct.x != ptOld.x) || (ptAct.y != ptOld.y)) {
                ptD.x = (int16_t)(ptAct.x - ptStart.x);
                ptD.y = (int16_t)(ptAct.y - ptStart.y);

                ptChg.x = (int16_t)(ptAct.x - ptOld.x);
                ptChg.y = (int16_t)(ptAct.y - ptOld.y);

                InvertPaneBorder(hdc, grSel, ptD, &ptChg);
                ptOld = ptAct;
            }
        }

        InvertPaneBorder(hdc, grSel, ptD, NULL);

        ReleaseCapture();
        SelectObject(hdc, hbrSav);
        ReleaseDC(hwnd, hdc);

        if ((ptD.x == 0) && (ptD.y == 0)) {
            return 0;
        }

        if ((grSel & 1) != 0) {
            if (iWindowLayout == 0)
                vfs.dxPlanWant = (int16_t)(vfs.xTop + ptD.x);
            else
                vfs.dx2PlanWant = (int16_t)(vfs.xTop + ptD.x);
        }

        if ((grSel & 2) != 0) {
            if (iWindowLayout == 0)
                vfs.dyMsgWant = (int16_t)(((vfs.y2 - vfs.y1) - 8) - ptD.y);
            else
                vfs.dy2MsgWant = (int16_t)(((vfs.dy - vfs.y1) - 8) - ptD.y);
        }

        if ((grSel & 4) != 0) {
            if (iWindowLayout == 0) {
                vfs.dyMsgWant = (int16_t)((vfs.y2 - vfs.y1) - 8 + ptD.y);
                vfs.dyMinWant = (int16_t)(((vfs.dy - vfs.y2) - 8) - ptD.y);
            } else {
                vfs.dy2MinWant = (int16_t)(((vfs.dy - vfs.y2) - 8) - ptD.y);
            }
        }

        InvalidateRect(hwnd, NULL, TRUE);
        RefitFrameChildren();
        return 0;

    case WM_QUERYNEWPALETTE:
        if (hwndTitle != NULL) {
            return SendMessage(hwndTitle, msg, wParam, lParam);
        }
        hdc = GetDC(hwnd);
        hpalSav = SelectPalette(hdc, vhpal, FALSE);
        i = (int16_t)RealizePalette(hdc);
        SelectPalette(hdc, hpalSav, FALSE);
        ReleaseDC(hwnd, hdc);
        if (i != 0) {
            InvalidateRect(hwnd, NULL, TRUE);
            return 1;
        }
        return 0;

    case WM_PALETTECHANGED:
        if ((HWND)wParam == hwnd) {
            return 0;
        }
        return SendMessage(hwnd, WM_QUERYNEWPALETTE, 0, 0);

    case WM_STARS_HOST:
        BringUpHostDlg();
        return 1;

    case WM_STARS_CONTINUE:
        ShowTutor(0);
        game.fDirty = 0;
        DestroyCurGame();

        fErrSav = fFileErrSilent;
        fFileErrSilent = 1;

        gd.fDontDoLogFiles = 1;
        fRet = (int16_t)FLoadGame(szBase, mpdtsz[dtHost]);
        if (fRet != 0) {
            gd.fDontDoLogFiles = 0;
            fFileErrSilent = fErrSav;
            idPlayer = 0;

            if (wParam == 0x09ca) {
                gd.fGeneratingTurn = 1;
                snprintf(szWork, sizeof(szWork), "%s.x1", szBase);
                if (FLoadLogFile(szWork) != 0) {
                    FRunLogFile();
                }
                gd.fGeneratingTurn = 0;
            }

            CreateChildWindows();
            SendMessage(hwndFrame, WM_COMMAND, IDM_FRAME_POST_OPEN, 0);
            if (wParam == 0x09ca) {
                SendMessage(hwndMessage, WM_KEYDOWN, VK_END, 0);
            }

            tutor.idt = 0;
            tutor.fAutoComplete = (wParam == 0x09ca) ? 1 : 0;
            AdvanceTutor();
            return 0;
        }

        fFileErrSilent = fErrSav;
    case WM_STARS_STARTUP:
        /*
         * Original Win16 behavior: this is the “startup trampoline” that processes
         * command-line driven modes (validate/new-game/gen), attempts auto-open,
         * ensures the title window exists, and then enforces the serial-number check.
         */
        idPlayer = -1;

        if (ini.fCmdLine) {
            ini.fCmdLine = 0;

            /* Validate mode: produce .chk output and exit. */
            if (ini.fValidate) {
                fFileErrSilent = 1;
                ClearFile(7);

                if (FLoadGame(szBase, "chk") != 0) {
                    VerifyTurns();
                    DestroyCurGame();
                    EnsureAis();

                    snprintf(szTemp, sizeof(szTemp), "\n%s  Year %d", szBase, (int)game.turn);
                    OutputSz(7, szTemp);

                    for (i = 0; i < game.cPlayer; i++) {
                        /* Start line with either N: or Error N: based on rgOut. */
                        if ((int16_t)(rgOut[i] + 1) < 4) {
                            ich = snprintf(szTemp, sizeof(szTemp), "%d", (int)(i + 1));
                        } else {
                            ich = snprintf(szTemp, sizeof(szTemp), "Error %d:", (int)(i + 1));
                        }

                        /* Optionally include player name (host names not hidden). */
                        if (!gd.fNoHostNames) {
                            (void)PszPlayerName(i, 1, 1, 1, 0, NULL);
                            ich += snprintf(szTemp + ich, sizeof(szTemp) - (size_t)ich, " %s", szWork);
                        }

                        /* Append turned-in status string based on rgOut. */
                        pch = PszGetCompressedString((int16_t)(rgOut[i] + idsTurned));
                        strncat(szTemp, pch, sizeof(szTemp) - strlen(szTemp) - 1);

                        /* Mark hackers. */
                        if (rgplr[i].fHacker) {
                            strncat(szTemp, "   HACKER", sizeof(szTemp) - strlen(szTemp) - 1);
                        }

                        OutputSz(7, szTemp);
                    }
                }

            MDI_LExit:
                if (!gd.fExitWindows) {
                    PostQuitMessage(vretExitValue);
                } else {
                    ExitWindows((UINT)vretExitValue, 0);
                }
                return 0;
            }

            /* New-game-from-file mode. */
            if (ini.fNewGame) {
                if (vSerialNumber != 0) {
                    GenNewGameFromFile(szBase);
                }
                goto MDI_LExit;
            }

            /* Autogenerate turns / batch processing mode. */
            if (ini.fGen) {
                while (1) {
                    while ((!ini.fWait && !ini.fTry) || CTurnsOutSafe() == 0) {
                        EnsureAis();
                        FGenerateTurn();

                        if (ini.fBatch && (lpchBatch < lpchBatchMac)) {
                            goto MDI_LTryNextBatch;
                        }
                        if (ini.cTurnGen == 0) {
                            goto MDI_LExit;
                        }
                        ini.cTurnGen--;
                    }

                    if (!ini.fTry) {
                        goto MDI_OpenGame;
                    }

                    if (!ini.fBatch || (lpchBatchMac <= lpchBatch)) {
                        break;
                    }

                MDI_LTryNextBatch:
                    DestroyCurGame();

                    /* Copy next batch filename line into szBase (NUL-terminated). */
                    pch = szBase;
                    while (1) {
                        if ((*lpchBatch == '\n') || ((lpchBatch == lpchBatchMac) && (lpchBatch[2] == lpchBatchMac[2]))) {
                            break;
                        }
                        *pch++ = *lpchBatch++;
                    }
                    lpchBatch++; /* skip '\n' */
                    *(pch - 1) = '\0';

                    ini.fStartupFile = 1;
                }
                goto MDI_LExit;
            }

        MDI_OpenGame:
            CommandHandler(hwnd, IDM_TOOL_OPEN_GAME);

            if (ini.fTry) {
                goto MDI_LExit;
            }
            if (ini.fGen) {
                goto MDI_LNop;
            }

            if (game.lid != 0) {
                if ((idPlayer != -1) && (ini.fDumpMap || ini.fDumpPlanets || ini.fDumpFleets)) {
                    if (ini.fDumpMap) {
                        PostMessage(hwndFrame, WM_COMMAND, IDM_DEBUG_DUMP_UNIVERSE, 0);
                    }
                    if (ini.fDumpPlanets) {
                        PostMessage(hwndFrame, WM_COMMAND, IDM_DEBUG_DUMP_PLANETS, 0);
                    }
                    if (ini.fDumpFleets) {
                        PostMessage(hwndFrame, WM_COMMAND, IDM_DEBUG_DUMP_FLEETS, 0);
                    }
                    goto MDI_LExit;
                }

                ShowWindow(hwndFrame, SW_SHOW);
                InitializeMenu(0);
                PostMessage(hwndFrame, WM_COMMAND, IDM_FRAME_POST_OPEN, 0);

                if (ini.fWait) {
                    ini.fWait = 0;
                    CommandHandler(hwnd, WMX_UNKNOWN_006A);
                }
                goto MDI_LNop;
            }
        }

        /* Ensure the title window exists. */
        if (hwndTitle == NULL) {
            int cx = GetSystemMetrics(SM_CXSCREEN);
            int cy = GetSystemMetrics(SM_CYSCREEN);
            hwndTitle = CreateWindowA(szTitle, "Stars!", WS_POPUP | WS_VISIBLE, 0, 0, cx, cy, hwndFrame, NULL, hInst, NULL);
            fFreeingTitle = 0;
        }

        ini.fStartupFile = 0;
        DestroyCurGame();

    MDI_LNop:
        /* If the serial number is valid for this machine, do nothing. */
        // vSerialNumber is always 0, no worries
        if (/*vSerialNumber != 0 && */ memcmp(vrgbMachineConfig, vrgbEnvCur, 11) == 0) {
            return 0;
        }

        /* SerialDlg uses szWork[200] as a “previously registered” flag. */
        szWork[200] = (vSerialNumber == 0) ? '\0' : '\x01';

        dlgProc = MakeProcInstance((FARPROC)SerialDlg, hInst);
        hWndParent = (hwndTitle != NULL) ? hwndTitle : hwndFrame;

        result = (int16_t)DialogBox(0, MAKEINTRESOURCE(IDD_SERIAL), hWndParent, (DLGPROC)dlgProc);
        FreeProcInstance((FARPROC)dlgProc);

        if (result == 0) {
            vSerialNumber = 0;
            memcpy(vrgbMachineConfig, vrgbEnvCur, 11);
            PostQuitMessage(vretExitValue);
        } else {
            lSerial = 0;
            if (!FValidSerialNo(szWork, &lSerial)) {
                if (vSerialNumber == 0) {
                    memcpy(vrgbMachineConfig, vrgbEnvCur, 11);
                    PostQuitMessage(vretExitValue);
                }
            } else {
                vSerialNumber = lSerial;
                memcpy(vrgbMachineConfig, vrgbEnvCur, 11);
            }
        }

        WriteIniSettings();
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void GetWindowRc(HWND hwnd, RECT *prc) {
    WINDOWPLACEMENT wndpl;

    wndpl.length = sizeof(wndpl);
    GetWindowPlacement(hwnd, &wndpl);

    prc->left = wndpl.rcNormalPosition.left;
    prc->top = wndpl.rcNormalPosition.top;
    prc->right = (int16_t)(wndpl.rcNormalPosition.right - wndpl.rcNormalPosition.left);
    prc->bottom = (int16_t)(wndpl.rcNormalPosition.bottom - wndpl.rcNormalPosition.top);
}

void DrawHostDialog2(HWND hwnd, HDC hdcIn) {
    uint32_t dsec;
    HDC      hdc;
    uint16_t dhour;
    int      bkMode; /* Win32: SetBkMode returns int */
    int      yCur;
    int16_t  i;
    uint16_t dmin;
    int16_t  dday;
    int      cch;
    RECT     rcDiamond;
    COLORREF crBackSav; /* Win32: SetBkColor returns COLORREF */
    int16_t  x;
    char     szStat[30];

    /* block (block) @ MEMORY_MDI:0x6300 */

    if (hdcIn == NULL) {
        hdc = GetDC(hwnd);
    } else {
        hdc = hdcIn;
    }

    bkMode = SetBkMode(hdc, TRANSPARENT);
    crBackSav = SetBkColor(hdc, crButtonFace);

    SelectObject(hdc, rghfontArial8[1]);

    {
        const char *psz = PszGetCompressedString(idsN16);
        SIZE        sz;

        GetTextExtentPoint32A(hdc, psz, 4, &sz);
        x = (int16_t)(dyArial8 + 10 + sz.cx);
    }

    yCur = 48;
    SetRect(&rcDiamond, 6, 48, dyArial8 + 7, dyArial8 + 0x31);

    for (i = 0; i < game.cPlayer; i++) {
        DrawDiamond(hdc, &rcDiamond, hbrBBlue);

        {
            const char *pszFmt = PszGetCompressedString(idsD2);
            cch = snprintf(szWork, sizeof(szWork), pszFmt, (int)i + 1);
            RightTextOut(hdc, x, yCur, szWork, cch, 0);
        }

        /* Win16 used raw COLORREFs 0x7F00 / 0x7F (dark green / dark red) */
        SetTextColor(hdc, (rgOut[i] < 1) ? RGB(0, 127, 0) : RGB(127, 0, 0));

        CchGetString(rgOut[i] + idsTurned, szStat);

        if (!gd.fNoHostNames) {
            const char *pszName = PszPlayerName(i, 1, 1, 1, 0, (PLAYER *)0);
            const char *pszFmt = PszGetCompressedString(idsSS);
            cch = snprintf(szWork, sizeof(szWork), pszFmt, pszName, szStat);
        } else {
            cch = snprintf(szWork, sizeof(szWork), " %s", szStat);
        }

        if (rgplr[i].fHacker) {
            strncat(szWork, " - HACKER", sizeof(szWork));
            cch += 9;
        }

        TextOutA(hdc, x + 4, yCur, szWork, cch);

        SetTextColor(hdc, crWindowText);

        OffsetRect(&rcDiamond, 0, dyArial8 + 4);
        yCur = yCur + dyArial8 + 4;
    }

    snprintf(szWork, sizeof(szWork), PCTD, (int)game.turn + 0x961);
    SetWindowTextA(GetDlgItem(hwnd, IDC_HOST_NEXT_YEAR_TEXT), szWork);

    dsec = (uint32_t)((GetTickCount() - ctickLast) / 1000u);

    if (dsec < 60u) {
        snprintf(szWork, sizeof(szWork), PszGetCompressedString(idsDSeconds), (unsigned)dsec);
    } else {
        uint32_t minutes = dsec / 60u;
        uint32_t sec_rem = dsec - minutes * 60u;

        if (minutes < 60u) {
            snprintf(szWork, sizeof(szWork), PszGetCompressedString(idsD02d), (unsigned)minutes, (unsigned)sec_rem);
        } else {
            uint32_t hours = minutes / 60u;
            uint32_t min_rem = minutes % 60u;

            if (hours < 24u) {
                snprintf(szWork, sizeof(szWork), PszGetCompressedString(idsD02d02d), (unsigned)hours, (unsigned)min_rem, (unsigned)sec_rem);
            } else {
                uint32_t days = hours / 24u;
                uint32_t hour_rem = hours % 24u;

                snprintf(szWork, sizeof(szWork), PszGetCompressedString(idsDDaysD02d02d), (unsigned)days, (unsigned)hour_rem, (unsigned)min_rem,
                         (unsigned)sec_rem);
            }
        }
    }

    SetWindowTextA(GetDlgItem(hwnd, IDC_HOST_TIME_SINCE_TEXT), szWork);

    SetBkMode(hdc, bkMode);
    SetBkColor(hdc, crBackSav);

    if (hdcIn == NULL) {
        ReleaseDC(hwnd, hdc);
    }
}

void DrawHostOptions(HWND hwnd, HDC hdc, int16_t iDraw) {

    // Stars! original: trivial prologue/epilogue only (no-op).
    (void)hwnd;
    (void)hdc;
    (void)iDraw;
}

void WriteIniSettings(void) {
    char szSection[16];
    char szIniFile[256];
    char szEntry[16];

    CchGetString(idsWindows, szSection);
    CchGetString(idsStarsIni, szIniFile);

    /* prepend user AppData path */
    {
        char szTmp[256];

        lstrcpyA(szTmp, szStarsPath); /* "%APPDATA%\Stars\" */
        lstrcatA(szTmp, szIniFile);   /* "Stars.ini" */
        lstrcpyA(szIniFile, szTmp);
    }

    /* [Windows] GlobalSettings = "<serial/env>" */
    CchGetString(idsGlobalsettings, szEntry);
    FormatSerialAndEnv((uint32_t)vSerialNumber, (uint8_t *)vrgbMachineConfig, (char *)szWork);
    WINBOOL result = WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
    DBG_LOGD("Writing %s to %s-%s %s: result=%d", szWork, szSection, szEntry, szIniFile, result);

    /* [Windows] Resolution = flags */
    CchGetString(idsResolution, szEntry);
    {
        int16_t i = (int16_t)((vcScreenColors < 5) ? 1 : 0);
        if (gd.mdScreenSize == 0) {
            i = (int16_t)(i | 2);
        }
        (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)i);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
    }

    /* [Windows] Main = window-state string */
    CchGetString(idsMain, szEntry);
    SetWindowIniString((char *)szWork, hwndFrame);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    /* report windows: idsC04d04d04d04d format */
    {
        const char *pszFmt = PszGetCompressedString(idsC04d04d04d04d);

        CchGetString(idsReportfleetwin, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), pszFmt, 0x4d, (int)vrptFleet.ptDlg.x, (int)vrptFleet.ptDlg.y,
                       (int)vrptFleet.ptDlg.x + (int)vrptFleet.ptSize.x, (int)vrptFleet.ptDlg.y + (int)vrptFleet.ptSize.y);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        CchGetString(idsReportefleetwin, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), pszFmt, 0x4d, (int)vrptEFleet.ptDlg.x, (int)vrptEFleet.ptDlg.y,
                       (int)vrptEFleet.ptDlg.x + (int)vrptEFleet.ptSize.x, (int)vrptEFleet.ptDlg.y + (int)vrptEFleet.ptSize.y);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        CchGetString(idsReportbtlwin, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), pszFmt, 0x4d, (int)vrptBattle.ptDlg.x, (int)vrptBattle.ptDlg.y,
                       (int)vrptBattle.ptDlg.x + (int)vrptBattle.ptSize.x, (int)vrptBattle.ptDlg.y + (int)vrptBattle.ptSize.y);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        CchGetString(idsReportplanwin, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), pszFmt, 0x4d, (int)vrptPlanet.ptDlg.x, (int)vrptPlanet.ptDlg.y,
                       (int)vrptPlanet.ptDlg.x + (int)vrptPlanet.ptSize.x, (int)vrptPlanet.ptDlg.y + (int)vrptPlanet.ptSize.y);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
    }

    CchGetString(idsLayout, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)iWindowLayout);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    CchGetString(idsStyle1width, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)vfs.dxPlanWant);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    CchGetString(idsStyle1height, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)vfs.dyMsgWant);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    CchGetString(idsStyle1height2, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)vfs.dyMinWant);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    CchGetString(idsStyle2width, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)vfs.dx2PlanWant);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    CchGetString(idsStyle2height, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)vfs.dy2MsgWant);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    CchGetString(idsStyle2height2, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)vfs.dy2MinWant);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    /* toolbar visible */
    CchGetString(idsToolbar, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%d", (int)(gd.fToolbar != 0));
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    /* tile layout strings */
    {
        int16_t iPass = 2;
        TILE   *rgtile = (TILE *)&rgtilePlanet;
        int16_t ctile = 6;

        CchGetString(idsPlanettiles, szEntry);

        while (iPass != 0) {
            char    *psz = (char *)szWork;
            uint16_t iCol = 0;

            for (int16_t i = 0; i < ctile; i++) {
                while (iCol < (uint16_t)rgtile[i].iCol) {
                    iCol++;
                    *psz++ = '*';
                }

                {
                    char ch = (rgtile[i].fPopped == 0) ? 'a' : 'A';
                    ch = (char)(ch + (char)rgtile[i].id);
                    *psz++ = ch;
                }
            }

            *psz = '\0';
            WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

            /* pass 2 writes PlanetTiles, pass 1 writes ShipTiles */
            CchGetString(idsShiptiles, szEntry);
            rgtile = (TILE *)&rgtileShip;
            ctile = 7;
            iPass--;
        }
    }

    /* selection */
    CchGetString(idsSelection, szEntry);
    {
        char ch;
        if (sel.grobj == grobjNone) {
            ch = 'N';
        } else if (sel.grobj == grobjPlanet) {
            ch = 'P';
        } else if (sel.grobj == grobjFleet) {
            ch = 'S';
        } else if (sel.grobj == grobjOther) {
            ch = 'E';
        } else {
            ch = 'N';
        }

        (void)snprintf((char *)szWork, sizeof(szWork), PszGetCompressedString(idsCCD), (int)ch, (int)((char)idPlayer + 'B'), (int)sel.id);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
    }

    /* message cursor */
    CchGetString(idsMessage, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)iMsgCur);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    /* game id (format is "%lx") */
    CchGetString(idsGameid, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), "%lx", (uint32_t)game.lid);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    /* scan zoom */
    CchGetString(idsScanzoom, szEntry);
    ((char *)szWork)[0] = (char)(iScanZoom + '5');
    ((char *)szWork)[1] = '\0';
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    /* v2.5 scanner options */
    if (gd.fChgScanner != 0) {
        (void)snprintf((char *)szWork, sizeof(szWork), "%u", (unsigned)grbitScan);
        CchGetString(idsScanmodev25, szEntry);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        (void)snprintf((char *)szWork, sizeof(szWork), "%u", (unsigned)grbitScanShip);
        CchGetString(idsScanfilterv25, szEntry);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        (void)snprintf((char *)szWork, sizeof(szWork), "%u", (unsigned)grbitScanEShip);
        CchGetString(idsScanefilterv25, szEntry);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        (void)snprintf((char *)szWork, sizeof(szWork), "%u", (unsigned)grbitScanMines);
        CchGetString(idsScanmines, szEntry);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        (void)snprintf((char *)szWork, sizeof(szWork), "%u", (unsigned)vpctRadarView);
        CchGetString(idsScanradar, szEntry);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
    }

    /* mineral scale */
    (void)snprintf((char *)szWork, sizeof(szWork), "%u", (unsigned)cMinGrafMax);
    CchGetString(idsMineralscale, szEntry);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    /* per-player file settings */
    if (idPlayer != -1) {
        CchGetString(idsFiles, szSection);

        CchGetString(idsWait2, szEntry);
        ((char *)szWork)[0] = (char)(((uTimerId != 0) ? 1 : 0) + '0');
        ((char *)szWork)[1] = '\0';
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        if (gd.fWriteTurnNum != 0) {
            (void)snprintf((char *)szWork, sizeof(szWork), "%u", (unsigned)game.turn);
            CchGetString(idsTurn, szEntry);
            WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

            /* matches: gd.grBits2 &= 0xfeff */
            gd.fWriteTurnNum = 0;
        }

        CchGetString(idsFile1, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), "%s.m%d", (char *)szBase, 0x1120, (int)(idPlayer + 1));
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
    }

    /* misc report state */
    CchGetString(idsMisc, szSection);

    if (gd.fChgReports != 0) {
        CchGetString(idsReportplanfld, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)vrptPlanet.grbitVisible);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        CchGetString(idsReportplansort, szEntry);
        {
            int16_t i = vrptPlanet.icolSort;
            if (vrptPlanet.fAscending != 0) {
                i = (int16_t)(i | 0x0100);
            }
            (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)i);
            WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
        }

        CchGetString(idsReportfleetfld, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)vrptFleet.grbitVisible);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        CchGetString(idsReportfleetsort, szEntry);
        {
            int16_t i = vrptFleet.icolSort;
            if (vrptFleet.fAscending != 0) {
                i = (int16_t)(i | 0x0100);
            }
            (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)i);
            WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
        }

        CchGetString(idsReportefleetfld, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)vrptEFleet.grbitVisible);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        CchGetString(idsReportefltsort, szEntry);
        {
            int16_t i = vrptEFleet.icolSort;
            if (vrptEFleet.fAscending != 0) {
                i = (int16_t)(i | 0x0100);
            }
            (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)i);
            WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
        }

        CchGetString(idsReportbtlfld, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)vrptBattle.grbitVisible);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

        CchGetString(idsReportbtlsort, szEntry);
        {
            int16_t i = vrptBattle.icolSort;
            if (vrptBattle.fAscending != 0) {
                i = (int16_t)(i | 0x0100);
            }
            (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)i);
            WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
        }

        CchGetString(idsReportdefgraph, szEntry);
        (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)gd.iCurGraph);
        WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
    }

    CchGetString(idsHistoryinfo, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)uDateInstalled);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    CchGetString(idsVcrspeed, szEntry);
    (void)snprintf((char *)szWork, sizeof(szWork), PCTD, (int)viSpeedVCR);
    WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);

    /* zip orders */
    if (gd.fChgZipOrd != 0) {
        CchGetString(idsZiporders, szSection);

        for (int16_t i = 0; i < 4; i++) {
            size_t cch;

            strncpy(szEntry, szSection, sizeof(szEntry) - 1);
            szEntry[sizeof(szEntry) - 1] = '\0';

            cch = strlen(szEntry);
            if (cch + 2 <= sizeof(szEntry)) {
                szEntry[cch] = (char)('1' + i);
                szEntry[cch + 1] = '\0';
            }

            if (vrgZip[i].fValid == 0) {
                ((char *)szWork)[0] = '\0';
            } else {
                char *psz = (char *)szWork;

                for (int16_t j = 0; j < 5; j++) {
                    uint16_t cQuan = (uint16_t)vrgZip[i].txp.rgia[j].cQuan;
                    uint16_t iAction = (uint16_t)vrgZip[i].txp.rgia[j].iAction;

                    psz[0] = (char)((iAction & 0x000F) + 0x61);
                    psz[1] = (char)(((cQuan >> 0) & 0x000F) + 0x61);
                    psz[2] = (char)(((cQuan >> 4) & 0x000F) + 0x61);
                    psz[3] = (char)(((cQuan >> 8) & 0x000F) + 0x61);
                    psz += 4;
                }

                /* szName is fixed-width in the struct; copy bounded */
                strncpy(psz, vrgZip[i].szName, sizeof(vrgZip[i].szName));
                psz[sizeof(vrgZip[i].szName)] = '\0';
            }

            WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
        }
    }

    /* zip production queues */
    if (gd.fChgZipProd != 0) {
        for (int16_t i = 0; i < 5; i++) {
            size_t cch;

            CchGetString(idsZiporders, szSection);

            strncpy(szEntry, szSection, sizeof(szEntry) - 1);
            szEntry[sizeof(szEntry) - 1] = '\0';

            cch = strlen(szEntry);
            if (cch + 3 <= sizeof(szEntry)) {
                szEntry[cch] = 'P';
                szEntry[cch + 1] = (char)('1' + i);
                szEntry[cch + 2] = '\0';
            }

            if (vrgZipProd[i].fValid == 0) {
                ((char *)szWork)[0] = '\0';
            } else {
                char *psz;

                ((char *)szWork)[0] = (char)(vrgZipProd[i].zpq1.fNoResearch + 'a');
                ((char *)szWork)[1] = (char)(vrgZipProd[i].zpq1.cpq + 'a');

                psz = (char *)szWork + 2;
                for (int16_t j = 0; j < (int16_t)(uint8_t)vrgZipProd[i].zpq1.cpq; j++) {
                    uint16_t w = vrgZipProd[i].rgpq[j].w;

                    psz[0] = (char)(((w >> 0) & 0x000F) + 0x61);
                    psz[1] = (char)(((w >> 4) & 0x000F) + 0x61);
                    psz[2] = (char)(((w >> 8) & 0x000F) + 0x61);
                    psz[3] = (char)(((w >> 12) & 0x000F) + 0x61);
                    psz += 4;
                }

                strncpy(psz, vrgZipProd[i].szName, sizeof(vrgZipProd[i].szName));
                psz[sizeof(vrgZipProd[i].szName)] = '\0';
            }

            WritePrivateProfileStringA(szSection, szEntry, (char *)szWork, szIniFile);
        }
    }
}

/*
 * HostTimerProc
 * -------------
 * Timer callback that drives host-mode background work:
 *
 *   - Polls for newly available turns for the current player.
 *   - Updates the frame title and host status text to reflect
 *     how many turns are outstanding.
 *   - Generates AI turns when no human turns are pending.
 *   - Flashes the frame window and notifies the user when a
 *     new turn becomes available.
 *
 * Original Win16 behavior:
 *   In the 16-bit version, this routine could loop internally
 *   and generate multiple turns in a single invocation. This
 *   was safe under cooperative multitasking and modal UI flow.
 *
 * Win32 adaptation:
 *   In the Win32 port, this function is intentionally limited
 *   to generating at most ONE turn per timer tick. Allowing the
 *   original tight loop would block the message pump, preventing
 *   WM_PAINT and other UI messages from being processed, causing
 *   the main window to never repaint.
 *
 * Concurrency / reentrancy:
 *   The global flag fProcessingTimer guards against re-entrant
 *   timer callbacks while work is in progress.
 *
 * Exit and suppression conditions:
 *   - If all players are AI-controlled (gd.fAllAis), auto-
 *     generation is disabled and the relevant UI control is
 *     disabled.
 *   - If ini.fGen is set, the application exits after turn
 *     generation completes.
 *
 * Side effects:
 *   - May destroy and reload the current game when a new turn
 *     file is detected.
 *   - Updates window text, invalidates child windows for redraw,
 *     and may post a quit message.
 *
 * This function is called both by WM_TIMER events and indirectly
 * after entering host mode to prime the UI state.
 */
VOID CALLBACK HostTimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    HWND    hwndPrev;
    char    newTurnExt[4];
    int     turnsOutstanding;
    int16_t savedFileErrSilent;
    int16_t savedIdPlayer;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x7756 */
    /* label Done @ MEMORY_MDI:0x7997 */
    /* label RedrawText @ MEMORY_MDI:0x7906 */
    /* label Loop @ MEMORY_MDI:0x784a */

    (void)uMsg;
    (void)idEvent;
    (void)dwTime;

    savedFileErrSilent = fFileErrSilent;

    if (!fProcessingTimer) {
        fProcessingTimer = 1;

        if (uTimerType == 0x0E) {
            savedIdPlayer = idPlayer;

            if (FNewTurnAvail(idPlayer) != 0) {
                KillTimer(hwnd, uTimerId);

                snprintf(newTurnExt, sizeof(newTurnExt), "%s", MPCTD);

                DestroyCurGame();

                if (FLoadGame((char *)szBase, newTurnExt) != 0) {
                    idPlayer = savedIdPlayer;
                    CreateChildWindows();

                    uTimerId = (uint16_t)SetTimer(hwndFrame, (UINT_PTR)0x0F, 1000, HostTimerProc);
                    uTimerType = 0x0F;

                    FlashWindow(hwndFrame, TRUE);
                    SetWindowTextA(hwndFrame, PszGetCompressedString(idsNewTurnAvailable2));
                    MessageBeep(MB_ICONEXCLAMATION);

                    turnsOutstanding = 1;
                    goto RedrawText;
                }

                Error(idsUnableOpenNewTurnFile);
            }

        } else if (uTimerType == 0x0F) {
            FlashWindow(hwndFrame, TRUE);

        } else {

        Loop:
            turnsOutstanding = CFindTurnsOutstanding();

            /* Original: if (gd.grBits highword bit4) break; then show error/disable after loop */
            if (gd.fAllAis) {
                Error(idsAutoGenerateDisabledBecauseHumanPlayersDead);
                EnableWindow(GetDlgItem(hwnd ? hwnd : hwndFrame, 0x0408), FALSE);
                goto Done;
            }

            /* 0x031B: format string, expects cOut as the %d argument. */
            snprintf(szWork, sizeof(szWork), PszGetCompressedString(idsHostModeDPlayer), turnsOutstanding);

            /* 0x0421: "s" suffix when cOut != 1 */
            if (turnsOutstanding != 1) {
                strcat(szWork, "s");
            }

            /* 0x031C: trailing text, appended unconditionally */
            strcat(szWork, PszGetCompressedString(idsOut));

            SetWindowTextA(hwndFrame, szWork);

        RedrawText:
            hwndPrev = GetWindow(hwndFrame, GW_HWNDPREV);
            if (GetWindow(hwndPrev, GW_OWNER) == hwndFrame) {
                InvalidateRect(hwndPrev, NULL, TRUE);
            }

            if (turnsOutstanding != 0) {
                goto Done;
            }

            if (gd.fProgressTxt) {
                ShowProgressGauge();
            }

            EnsureAis();
            FGenerateTurn();
            HideProgressGauge();

            if (ini.fGen) {
                PostQuitMessage(vretExitValue);
                goto Done;
            }

            EnsureAis();

            /* IMPORTANT FIX:
             * Do NOT goto Loop here.
             * Let the next WM_TIMER tick continue generation.
             */
        }

    Done:
        fProcessingTimer = 0;
    }

    fFileErrSilent = savedFileErrSilent;
}

HMENU GetASubMenu(HWND hwnd, int16_t iMenu) {
    int16_t iOffset = 0;

    /* If an MDI child is active and maximized, the frame menu has an extra item. */
    if (hwndActive != NULL && IsZoomed(hwndActive)) {
        iOffset = 1;
    }

    {
        HMENU hmenu = GetMenu(hwnd);
        return GetSubMenu(hmenu, (int)(iMenu + iOffset));
    }
}

int16_t FOpenGame(HWND hwnd, int16_t fRaceOnly) {
    StringId ids;
    int16_t  fRet;
    int16_t  grobjIni;

    char  szFilter[256];
    char  szFileTitle[256];
    char  szFile[256];
    char *pch;

    OPENFILENAMEA ofn;

    if (!ini.fStartupFile) {
        /* Manual Open Game flow: ensure host-mode "close" does not exit the app. */
        gd.fClose = 0;

        szFile[0] = '\0';

        ids = (!fRaceOnly) ? idsStarsGameFilesMHstRStars : idsStarsGameFilesRFiles;
        CchGetString(ids, szFilter);

        /* resource filter uses '|' separators; Win32 wants embedded NULs */
        for (uint16_t i = 0; szFilter[i] != '\0'; ++i) {
            if (szFilter[i] == '|')
                szFilter[i] = '\0';
        }

        memset(&ofn, 0, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd;
        ofn.lpstrFilter = szFilter;
        ofn.nFilterIndex = 1;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = (DWORD)sizeof(szFile);
        ofn.lpstrFileTitle = szFileTitle;
        ofn.nMaxFileTitle = (DWORD)sizeof(szFileTitle);
        ofn.lpstrInitialDir = szDirName;

        /* 0x1804 = OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST */
        ofn.Flags = OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

        if (!GetOpenFileNameA(&ofn))
            return 0;
    } else {
        /* startup file path: szBase holds full path; also mutate szBase into directory */
        lstrcpyA(szFile, szBase);

        pch = strrchr(szBase, '\\');
        if (pch != NULL)
            *pch = '\0';

        pch = strrchr(szFile, '.');
        if (pch == NULL) {
            SetSzWorkFromDt(dtHost, -1);
            lstrcpyA(szFile, szWork);
            pch = strrchr(szFile, '.');
        }

        ofn.nFileOffset = 0;
        ofn.nFileExtension = (pch != NULL) ? (WORD)((pch - szFile) + 1) : 0;

        fFileErrSilent = 1;
    }

    /* common tail */
    szDirName[0] = '\0';

    fRet = FWasRaceFile(szFile + ofn.nFileOffset, (int16_t)(!fRaceOnly));

    if (!fRaceOnly) {
        if (!fRet) {
            if (ofn.nFileExtension != 0)
                szFile[ofn.nFileExtension - 1] = '\0';

            DestroyCurGame();

            /* base name (no extension) becomes szBase */
            lstrcpyA(szBase, szFile);

            if (!FLoadGame(szFile, szFile + ofn.nFileExtension)) {
                if (ini.fStartupFile) {
                    ini.wFlags = 0;
                    fFileErrSilent = 0;
                }
                return 0;
            }

            if (ini.fStartupFile != 0) {
                fFileErrSilent = 0;
                ini.fStartupFile = 0;

                /* derive directory into szDirName */
                pch = strrchr(szFile, '\\');
                if (pch != NULL) {
                    size_t n = (size_t)(pch - szFile);
                    if (n >= sizeof(szDirName))
                        n = sizeof(szDirName) - 1;
                    memcpy(szDirName, szFile, n);
                    szDirName[n] = '\0';
                }

                /* if hosting and NOT generating turn, set gd.grBits2 bit2 (fClose) */
                if (idPlayer == -1 && ini.fGen == 0) {
                    gd.fClose = 1;
                }

                /* if ini.lid != game.lid OR ini.turn < game.turn => clear ini.fTry */
                if (ini.lid != game.lid || ini.turn < game.turn) {
                    ini.fTry = 0;
                }
            }

            /* reset selection state */
            sel.grobjFull = grobjNone;
            sel.grobj = grobjNone;
            sel.iwpAct = -1;
            sel.id = -1;

            sel.scan.grobjFull = grobjNone;
            sel.scan.grobj = grobjNone;
            sel.scan.iwp = -1;
            sel.scan.ifl = -1;
            sel.scan.idpl = -1;

            fOrdersVis = 0;

            CreateChildWindows();

            if (idPlayer == -1) {
                if (hwndTitle != NULL && fFreeingTitle == 0) {
                    fFreeingTitle = 1;
                    DestroyWindow(hwndTitle);
                    hwndTitle = NULL;
                }

                BringUpHostDlg();
                return 0;
            }

            /* snapshot grobjSel nibble, then send WM_COMMAND 0x0FA1 */
            grobjIni = (int16_t)ini.grobjSel;

            SendMessageA(hwndFrame, WM_COMMAND, (WPARAM)0x0FA1, 0);

            /*
             * ASM behavior:
             * - if grobjIni != 0 AND now grobjSel == 0 => return 1
             * - else clear grobjSel and maybe auto-select something
             */
            if (grobjIni != 0 && ini.grobjSel == 0)
                return 1;

            ini.grobjSel = 0;

            if (ini.grobjSel == 0) {
                if (cPlanet != 0)
                    (void)FFindSomethingAndSelectIt();
            }

            return 1;
        }

        /* race file picked when expecting game file */
        if (ini.fStartupFile != 0 && vSerialNumber == 0)
            fRet = -1;

        fFileErrSilent = 0;
        ini.fStartupFile = 0;

        if (fRet == -1)
            return -1;

        (void)RaceCreationWizard(hwnd, 0, 0);
        return 0;
    }

    /* fRaceOnly */
    if (fRet > 0) {
        /* NOTE: szRaceFile is declared [0] in NB09; must be backed by real storage. */
        lstrcpyA(szRaceFile, szFile + ofn.nFileOffset);
    }

    return fRet;
}

void InitializeMenu(HMENU hmenu) {
    HMENU   hmenuFile;
    HMENU   hmenuView;
    HMENU   hmenuTurn;
    HMENU   hmenuFrame;
    UINT    uFlags;
    int16_t i;

    if (hmenu == NULL) {
        hmenu = GetMenu(hwndFrame);
    }

    /* In your menu.rc: submenu order is File=0, View=1, Turn=2, Commands=3, Report=4, Help=5 */
    hmenuFile = GetSubMenu(hmenu, 0);
    hmenuView = GetSubMenu(hmenu, 1);
    hmenuTurn = GetSubMenu(hmenu, 2);
    hmenuFrame = hmenu;

    /* ---------------- File menu: rebuild MRU block ----------------
       Your Win32 menu has no MRU block yet; we insert it after "Save And Submit". */
    {
        const UINT idMruBase = 0x10cc; /* keep legacy command-id range for MRU dispatch */

        /* Find insertion point: after IDM_FILE_SAVE_SUBMIT */
        int posSubmit = -1;
        int cItems = GetMenuItemCount(hmenuFile);
        for (int pos = 0; pos < cItems; pos++) {
            UINT id = GetMenuItemID(hmenuFile, pos);
            if (id == IDM_FILE_SAVE_SUBMIT) {
                posSubmit = pos;
                break;
            }
        }

        /* Insert right after submit; if not found, insert near top */
        int posInsert = (posSubmit >= 0) ? (posSubmit + 1) : 0;

        /* First delete any existing MRU items (0x10cc..0x10d4) */
        for (UINT id = idMruBase; id < idMruBase + (UINT)cMaxMru; id++) {
            DeleteMenu(hmenuFile, id, MF_BYCOMMAND);
        }

        /* Also remove any extra separator we might have inserted previously (by position near insertion). */
        /* (Optional) You can make this smarter later; safe enough if you don't spam separators. */

        /* Insert MRUs */
        /* MRU list layout: 9 entries * 0x100 bytes each */

        i = 0;
        while (i < cMaxMru) {
            const char *pszMru = vrgszMRU + (i * cbMruEntry);

            if (pszMru[0] == '\0') {
                break;
            }

            szWork[0] = '&';
            szWork[1] = (char)('1' + i);
            szWork[2] = ' ';
            /* Copy at most 0xFF chars from the slot, and force NUL */
            lstrcpynA(szWork + 3, pszMru, 0x100); /* copies up to 0xFF + NUL */

            InsertMenuA(hmenuFile, (UINT)(posInsert + i), MF_BYPOSITION | MF_STRING, (UINT)(idMruBase + (UINT)i), szWork);
            i++;
        }
    }

    /* ---------------- Enable/disable items using your IDM_* ----------------
       Win16 used "3" for disabled; Win32 uses MF_GRAYED|MF_DISABLED. */

    uFlags = (szBase[0] == '\0' || game.fSinglePlr) ? (MF_BYCOMMAND | MF_GRAYED | MF_DISABLED) : (MF_BYCOMMAND | MF_ENABLED);

    /* Close */
    EnableMenuItem(hmenuFrame, IDM_FILE_CLOSE, uFlags);

    /* Open is disabled if no base (matches original 0x0069 logic) */
    uFlags = (szBase[0] == '\0') ? (MF_BYCOMMAND | MF_GRAYED | MF_DISABLED) : (MF_BYCOMMAND | MF_ENABLED);
    EnableMenuItem(hmenuFrame, IDM_FILE_OPEN, uFlags);

    /* Turn items (these are under the Turn popup in menu.rc, but EnableMenuItem works with BYCOMMAND on the frame menu) */
    uFlags = (szBase[0] == '\0' || game.fSinglePlr) ? (MF_BYCOMMAND | MF_GRAYED | MF_DISABLED) : (MF_BYCOMMAND | MF_ENABLED);
    EnableMenuItem(hmenuFrame, IDM_TURN_WAIT_NEW, uFlags);

    uFlags = (szBase[0] == '\0' || (game.fSinglePlr && (lSaltCur <= 0))) ? (MF_BYCOMMAND | MF_GRAYED | MF_DISABLED) : (MF_BYCOMMAND | MF_ENABLED);
    EnableMenuItem(hmenuFrame, IDM_TURN_GENERATE, uFlags);

    /* Submit (Save And Submit) */
    uFlags = (szBase[0] == '\0' || game.fSinglePlr) ? (MF_BYCOMMAND | MF_GRAYED | MF_DISABLED) : (MF_BYCOMMAND | MF_ENABLED);
    EnableMenuItem(hmenuFrame, IDM_FILE_SAVE_SUBMIT, uFlags);

    /* ---------------- View checks using your IDM_* ---------------- */

    CheckMenuItem(hmenuFrame, IDM_VIEW_TOOLBAR, gd.fToolbar ? (MF_BYCOMMAND | MF_CHECKED) : (MF_BYCOMMAND | MF_UNCHECKED));

    CheckMenuItem(hmenuFrame, IDM_VIEW_FIND, ((grbitScan & 0x2000) != 0) ? (MF_BYCOMMAND | MF_CHECKED) : (MF_BYCOMMAND | MF_UNCHECKED));

    /* ---------------- Zoom/layout checks using your command IDs ---------------- */
    {
        UINT idZoom = 0;
        switch (iScanZoom) {
        case 0:
            idZoom = IDM_VIEW_ZOOM_25;
            break;
        case 1:
            idZoom = IDM_VIEW_ZOOM_38;
            break;
        case 2:
            idZoom = IDM_VIEW_ZOOM_50;
            break;
        case 3:
            idZoom = IDM_VIEW_ZOOM_75;
            break;
        case 4:
            idZoom = IDM_VIEW_ZOOM_100;
            break;
        case 5:
            idZoom = IDM_VIEW_ZOOM_125;
            break;
        case 6:
            idZoom = IDM_VIEW_ZOOM_150;
            break;
        case 7:
            idZoom = IDM_VIEW_ZOOM_200;
            break;
        case 8:
            idZoom = IDM_VIEW_ZOOM_400;
            break;
        default:
            idZoom = IDM_VIEW_ZOOM_100;
            break;
        }

        /* Radio-check the whole zoom range */
        CheckMenuRadioItem(hmenuView, IDM_VIEW_ZOOM_25, IDM_VIEW_ZOOM_400, idZoom, MF_BYCOMMAND);
    }

    {
        UINT idLayout = IDM_VIEW_LAYOUT_LARGE;
        switch (iWindowLayout) {
        case 0:
            idLayout = IDM_VIEW_LAYOUT_LARGE;
            break;
        case 1:
            idLayout = IDM_VIEW_LAYOUT_MEDIUM;
            break;
        case 2:
            idLayout = IDM_VIEW_LAYOUT_SMALL;
            break;
        default:
            idLayout = IDM_VIEW_LAYOUT_LARGE;
            break;
        }

        CheckMenuRadioItem(hmenuView, IDM_VIEW_LAYOUT_LARGE, IDM_VIEW_LAYOUT_SMALL, idLayout, MF_BYCOMMAND);
    }

    DrawMenuBar(hwndFrame);
}

uint16_t HcrsFromFrameWindowPt(POINT pt, int16_t *pgrSel) {
    uint16_t hcs;
    int16_t  fInHBar2;
    int16_t  fInHBar1;
    int16_t  fInVBar;

    /* TODO: implement */
    return 0;
}

POINT InvertPaneBorder(HDC hdc, int16_t grSel, POINT dpt, POINT *pdptPrev) {
    int16_t notMin;
    int16_t dChg;
    POINT   dptT;
    POINT   dptPrev;
    int16_t dyAboveMinCur;
    POINT   dptOld;
    int16_t dyMsgCur;
    int16_t dyMinAboveH2;
    int16_t dyPlanMin;
    int16_t dxScanMin;
    int16_t x;
    int16_t dyMin;
    POINT   pt;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x1e63 */
    /* block (block) @ MEMORY_MDI:0x1f93 */
    /* block (block) @ MEMORY_MDI:0x1fe4 */
    /* block (block) @ MEMORY_MDI:0x20ba */
    /* block (block) @ MEMORY_MDI:0x210e */

    /* TODO: implement */
    return pt;
}

void BringUpHostDlg(void) {
    int16_t screenWidth;
    int16_t screenHeight;
    int16_t dlgResult;
    POINT   pt; /* present in original frame; not directly used here */

Top: /* was a default auto-label around the main dialog loop */

    /* gd.grBits bit 3 => gd.fHostMode (see types.h GDATA bitfields). */
    if (!gd.fHostMode) {
        /* gd.grBits high-word bit 5 => bit 21 overall => gd.fReadOnly. */
        if (!gd.fReadOnly) {
            FMarkFile(dtHost, (int16_t)-1, (int16_t)1, (int16_t)1);
        }
        gd.fHostMode = 1;
    }

    ShowWindow(hwndFrame, SW_HIDE);

    /* ini.wFlags bit 2 => ini.fWait (see types.h INI bitfields). */
    if (!ini.fWait) {
        for (;;) {
            /*
             * Win16 used MakeProcInstance/FreeProcInstance around the dialog proc.
             * Win32 does not require that; pass the proc directly.
             *
             */
            dlgResult = (int16_t)DialogBox(hInst, MAKEINTRESOURCEA(IDD_HOST_MODE), hwndFrame, HostModeDialog);

            if (dlgResult == (int16_t)-1) {
                break;
            }

            if (dlgResult == (int16_t)0) {
                /* When leaving host mode (cancel/exit): mark file and teardown. */

                if (!gd.fReadOnly) {
                    /*
                     * Decompile pushed:
                     *   dt = 2, id = -1, fWrite = 1, fRead = 0  (ordering per FMarkFile signature)
                     * The enum name for dt=2 wasn’t present in nb09_ghidra_globals.json.
                     */
                    FMarkFile((DtFileType)2, (int16_t)-1, (int16_t)1, (int16_t)0);
                }

                gd.fHostMode = 0;

                DestroyCurGame();

                /* ini.wFlags bit 3 => ini.fGen. */
                if (ini.fGen) {
                    return;
                }

                /* Recreate the title window full-screen. */
                screenWidth = (int16_t)GetSystemMetrics(SM_CXSCREEN);
                screenHeight = (int16_t)GetSystemMetrics(SM_CYSCREEN);

                /*
                 * Decompile built:
                 *   class = far ptr 1120:022A  -> this *does* resolve to szTitle ("starstitle")
                 *   style = 0x9000:0000        -> 0x90000000 (high:low 16-bit halves)
                 *
                 */
                hwndTitle = CreateWindowA(szTitle, "Stars!", 0x90000000u, 0, 0, (int)screenWidth, (int)screenHeight, hwndFrame, NULL, hInst, NULL);

                fFreeingTitle = 0; /* global at 1120:0354 per nb09_ghidra_globals.json */
                return;
            }

        LAutoMode: /* was a default auto-label at the start of the batch-generate loop */

            /* dlgResult != 0: generate turns (possibly multiple passes). */
            for (;;) {
                if (gd.fProgressTxt) {
                    ShowProgressGauge();
                }

                EnsureAis();

            LNextGen: /* was a default auto-label right before generating the next turn */

                FGenerateTurn();

                if (iPassCnt == 0) {
                    break;
                }
                iPassCnt = (int16_t)(iPassCnt - 1);

                /* Stop batch if Shift (VK_SHIFT=0x10) or Ctrl (VK_CONTROL=0x11) is pressed. */
                if ((int16_t)GetAsyncKeyState(0x10) < 0) {
                    break;
                }
                if ((int16_t)GetAsyncKeyState(0x11) < 0) {
                    break;
                }
            }

            iPassCnt = 0;
            HideProgressGauge();
        }
    } else {
        /* Clear ini.fWait (bit 2). */
        ini.fWait = 0;
    }

    ShowWindow(hwndFrame, SW_SHOW);

    /*
     * Set a host timer and immediately fire it once.
     *
     * Globals (nb09_ghidra_globals.json):
     *   uTimerId   at 1120:01A2
     *   uTimerType at 1120:01A4
     *
     * The decompile arguments line up with:
     *   SetTimer(NULL, 0x0D, 10000, HostTimerProc)
     */
    uTimerId = (uint16_t)SetTimer(NULL, (UINT_PTR)0x0D, (UINT)10000, HostTimerProc);
    uTimerType = 0x0D;

    HostTimerProc(NULL, 0, (UINT_PTR)uTimerId, 0);
}

INT_PTR CALLBACK HostOptionsDialog(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RECT        rc;
    HDC         hdc;
    PAINTSTRUCT ps;

    /* debug symbols */
    /* block (block) @ MEMORY_MDI:0x761b */

    /* TODO: implement */
    return 0;
}

short InitMDIApp(void) {
    ATOM      atom;
    short     fOk;
    WNDCLASSA wc;

    /* Frame window class */
    wc.style = CS_VREDRAW | CS_HREDRAW | CS_DBLCLKS; /* 0x000B */
    wc.lpfnWndProc = FrameWndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInst;
    wc.hIcon = NULL;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);           /* 0x7F00 */
    wc.hbrBackground = (HBRUSH)(COLOR_APPWORKSPACE + 1); /* 0x000D */
    wc.lpszMenuName = "StarsMenu";
    wc.lpszClassName = szFrame;

    atom = RegisterClassA(&wc);
    if (atom == 0) {
        fOk = 0;
    } else {
        /* Message window class */
        wc.style = CS_NOCLOSE | CS_VREDRAW | CS_HREDRAW | CS_DBLCLKS; /* 0x020B */
        wc.lpfnWndProc = MessageWndProc;
        wc.hIcon = NULL;
        wc.lpszMenuName = NULL;
        wc.hbrBackground = GetStockObject(LTGRAY_BRUSH); /* GetStockObject(1) */
        wc.lpszClassName = szMessage;

        atom = RegisterClassA(&wc);
        if (atom == 0) {
            fOk = 0;
        } else {
            /* Scan window class */
            wc.style = CS_NOCLOSE | CS_VREDRAW | CS_HREDRAW | CS_DBLCLKS; /* 0x020B */
            wc.lpfnWndProc = ScannerWndProc;
            wc.hbrBackground = GetStockObject(BLACK_BRUSH); /* GetStockObject(4) */
            wc.lpszClassName = szScan;

            atom = RegisterClassA(&wc);
            if (atom == 0) {
                fOk = 0;
            } else {
                /* Mine window class */
                wc.style = CS_NOCLOSE | CS_VREDRAW | CS_HREDRAW | CS_DBLCLKS; /* 0x020B */
                wc.lpfnWndProc = MineWndProc;
                wc.hbrBackground = GetStockObject(LTGRAY_BRUSH); /* GetStockObject(1) */
                wc.lpszClassName = szMine;

                atom = RegisterClassA(&wc);
                if (atom == 0) {
                    fOk = 0;
                } else {
                    /* Toolbar window class */
                    wc.style = CS_NOCLOSE | CS_DBLCLKS; /* 0x0208 */
                    wc.lpfnWndProc = TbWndProc;
                    wc.hbrBackground = GetStockObject(LTGRAY_BRUSH); /* GetStockObject(1) */
                    wc.lpszClassName = szTb;

                    atom = RegisterClassA(&wc);
                    if (atom == 0) {
                        fOk = 0;
                    } else {
                        /* Planet window class */
                        wc.style = CS_NOCLOSE; /* 0x0200 */
                        wc.lpfnWndProc = PlanetWndProc;
                        wc.hbrBackground = GetStockObject(LTGRAY_BRUSH); /* GetStockObject(1) */
                        wc.hIcon = NULL;
                        wc.lpszClassName = szPlanet;

                        atom = RegisterClassA(&wc);
                        if (atom == 0) {
                            fOk = 0;
                        } else {
                            /* Popup window class */
                            wc.style = CS_NOCLOSE | CS_SAVEBITS; /* 0x0A00 */
                            wc.lpfnWndProc = PopupWndProc;
                            wc.hbrBackground = GetStockObject(WHITE_BRUSH); /* GetStockObject(0) */
                            wc.hIcon = NULL;
                            wc.lpszClassName = szPopup;

                            atom = RegisterClassA(&wc);
                            if (atom == 0) {
                                fOk = 0;
                            } else {
                                /* Tooltip window class */
                                wc.style = CS_NOCLOSE | CS_SAVEBITS; /* 0x0A00 */
                                wc.lpfnWndProc = TooltipWndProc;
                                wc.hbrBackground = GetStockObject(WHITE_BRUSH); /* GetStockObject(0) */
                                wc.hIcon = NULL;
                                wc.lpszClassName = szTooltip;

                                atom = RegisterClassA(&wc);
                                if (atom == 0) {
                                    fOk = 0;
                                } else {
                                    /* Browser window class */
                                    wc.style = CS_NOCLOSE; /* 0x0200 */
                                    wc.lpfnWndProc = BrowserWndProc;
                                    wc.hbrBackground = GetStockObject(LTGRAY_BRUSH); /* GetStockObject(1) */
                                    wc.hIcon = NULL;
                                    wc.lpszClassName = szBrowser;

                                    atom = RegisterClassA(&wc);
                                    if (atom == 0) {
                                        fOk = 0;
                                    } else {
                                        /* Title window class */
                                        wc.style = 0;
                                        wc.lpfnWndProc = TitleWndProc;
                                        wc.cbClsExtra = 0;
                                        wc.cbWndExtra = 0;
                                        wc.hInstance = hInst;
                                        wc.hIcon = NULL;
                                        wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
                                        wc.hbrBackground = GetStockObject(BLACK_BRUSH); /* GetStockObject(4) */
                                        wc.lpszMenuName = NULL;
                                        wc.lpszClassName = szTitle;

                                        atom = RegisterClassA(&wc);
                                        if (atom == 0) {
                                            fOk = 0;
                                        } else {
                                            /* Report window class */
                                            wc.style = CS_VREDRAW | CS_HREDRAW | CS_DBLCLKS; /* 0x000B */
                                            wc.lpfnWndProc = ReportWndProc;
                                            wc.cbClsExtra = 0;
                                            wc.cbWndExtra = 0;
                                            wc.hInstance = hInst;
                                            wc.hIcon = NULL;
                                            wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
                                            wc.hbrBackground = GetStockObject(LTGRAY_BRUSH); /* GetStockObject(1) */
                                            wc.lpszMenuName = NULL;
                                            wc.lpszClassName = szReport;

                                            atom = RegisterClassA(&wc);
                                            if (atom == 0)
                                                fOk = 0;
                                            else
                                                fOk = 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return fOk;
}

void CreateChildWindows(void) {
    char        szGame[15];
    const char *psz;
    POINT       pt;
    RECT        rcClient;
    char        szData[100];

    if (idPlayer == -1) {
        CchGetString(idsStarsSHostMode, szWork);
        /* Win16 code used _wsprintf(szData, szWork) with no varargs. */
        lstrcpynA(szData, szWork, (int)sizeof(szData));
    } else {
        /* Find start of the leaf name in szBase (walk backwards to '\' or ':'). */
        psz = szBase + lstrlenA(szBase);
        while (psz > szBase && psz[-1] != '\\' && psz[-1] != ':')
            --psz;

        /* Copy up to 8 chars, lowercase it. */
        lstrcpynA(szGame, psz, 9);
        CharLowerA(szGame);

        lstrcpynA(szGame + lstrlenA(szGame), ".m%d", (int)sizeof(szGame) - lstrlenA(szGame));

        char *pszPlr = PszPlayerName(idPlayer, 0, 1, 0, 0, (PLAYER *)0);

        wsprintfA(szData, "Stars! -- %s -- %s -- %s", game.szName, pszPlr, szGame);
    }

    SetWindowTextA(hwndFrame, szData);

    if (idPlayer == -1)
        return;

    /* pt in the decompile is used for the Mine window size; make it deterministic from the frame client. */
    GetClientRect(hwndFrame, &rcClient);
    pt.x = rcClient.right - rcClient.left;
    pt.y = rcClient.bottom - rcClient.top;

    /* Scanner window */
    if (hwndScanner == NULL) {
        hwndScanner = CreateWindowA(szScan,                      /* class (DS:01e2) */
                                    NULL, WS_CHILD | WS_VISIBLE, /* decompile showed 0x50000000 here already */
                                    -200, -200, 10, 10, hwndFrame, NULL, hInst, NULL);
    } else {
        InvalidateRect(hwndScanner, NULL, TRUE);
        yScanTop = 1000;
        xScanTop = 1000;
        SetScanScrollBars(hwndScanner);
    }

    /* Mine window */
    if (hwndMine == NULL) {
        hwndMine = CreateWindowA(szMine,                      /* class (DS:01ec) */
                                 NULL, WS_CHILD | WS_VISIBLE, /* decompile’s 0x5000 is a truncated style */
                                 -500, -500,                  /* decompile’s 0xfe0c (int16_t) */
                                 pt.x, pt.y, hwndFrame, NULL, hInst, NULL);
    } else {
        InvalidateRect(hwndMine, NULL, TRUE);
    }

    /* Planet window */
    if (hwndPlanet == NULL) {
        hwndPlanet = CreateWindowA(szPlanet,                                /* class (DS:01f6) */
                                   NULL, WS_CHILD | WS_VISIBLE, -500, -500, /* 0xfe0c */
                                   10, 10, hwndFrame, NULL, hInst, NULL);
    } else {
        InvalidateRect(hwndPlanet, NULL, TRUE);
    }

    /* Toolbar (?) window */
    if (hwndTb == NULL) {
        hwndTb = CreateWindowA(szTb,                                    /* class (DS:0242) */
                               NULL, WS_CHILD | WS_VISIBLE, -500, -500, /* 0xfe0c */
                               10, 10, hwndFrame, NULL, hInst, NULL);
    } else {
        InvalidateRect(hwndTb, NULL, TRUE);
    }

    /* Message window: always recreated */
    if (hwndMessage != NULL) {
        DestroyWindow(hwndMessage);
        hwndMessage = NULL;
    }

    hwndMessage = CreateWindowA(szMessage,                               /* class (DS:0202) */
                                NULL, WS_CHILD | WS_VISIBLE, -500, -500, /* 0xfe0c */
                                10, 10, hwndFrame, NULL, hInst, NULL);

    RefitFrameChildren();
}

/*
 * SetWindowIniString
 *
 * Builds an INI value string representing a window's placement:
 *   ch = 'M' (maximized), 'I' (iconic/minimized), 'R' (restored)
 *   plus rc.left/top/right/bottom
 *
 *
 * NOTE: The provided decompile shows the arguments for _wsprintf were pushed but not visible.
 * This function assumes the format string expects: (char state, int left, int top, int right, int bottom)
 * which matches the data marshaling in the decompile.
 */
void SetWindowIniString(const char *sz /*unused in the snippet*/, HWND hwnd) {
    (void)sz; /* appears unused in the provided decompile */

    RECT rc;
    char ch;

    if (IsZoomed(hwnd)) {
        ch = 'M';
    } else if (IsIconic(hwnd)) {
        ch = 'I';
    } else {
        ch = 'R';
    }

    GetWindowRc(hwnd, &rc);

    const char *pszFmt = PszGetCompressedString(idsC04d04d04d04d);
    snprintf(szWork, sizeof(szWork), pszFmt, ch, rc.left, rc.top, rc.right, rc.bottom);
}

void RestoreSelection(void) {
    PLANET *lppl;

    /* TODO: implement */
}

void RefitFrameChildren(void) {
    if (hwndFrame == NULL)
        return;

    if (IsIconic(hwndFrame))
        return;

    /* Common derived minimums based on font height */
    const int dyMsgFloor = ((dyArial8 * 13) >> 1) + 10;
    const int dyMinFloor = (dyArial8 * 13) - 0x24;

    int dyMsg;
    int dyMin;
    int yToolbar = 0;

    if (iWindowLayout != 1 && iWindowLayout != 2) {
        /* Single-column layout: Planet/Message/Mine on left; Scanner on right */

        /* Clamp xTop */
        if (vfs.dx - vfs.dxPlanWant < 100)
            vfs.xTop = vfs.dx - 100;
        else
            vfs.xTop = vfs.dxPlanWant;

        if (vfs.xTop < 199)
            vfs.xTop = 0xC6;

        /* Clamp wanted heights */
        if (vfs.dyMsgWant < dyMsgFloor)
            vfs.dyMsgWant = (int16_t)dyMsgFloor;

        if (vfs.dyMinWant < dyMinFloor)
            vfs.dyMinWant = (int16_t)dyMinFloor;

        dyMsg = vfs.dyMsgWant;
        dyMin = vfs.dyMinWant;

        /* If there isn't enough vertical room, proportionally scale dyMsg/dyMin. */
        if (vfs.dy - (dyMsg + dyMin + 0x10) < 0x32) {
            const int avail = vfs.dy - 0x42;
            const int denom = dyMsg + dyMin;

            if (denom > 0) {
                int newMsg = MulDiv(avail, dyMsg, denom);
                int newMin = MulDiv(avail, dyMin, denom);

                if (newMsg < dyMsgFloor) {
                    newMin -= (dyMsgFloor - newMsg);
                    newMsg = dyMsgFloor;
                } else if (newMin < dyMinFloor) {
                    const int d = dyMinFloor - newMin;
                    newMin = dyMinFloor;
                    newMsg -= d;
                }

                dyMsg = newMsg;
                dyMin = newMin;
            }
        }

        vfs.y1 = (int16_t)((vfs.dy - dyMin - dyMsg) - 0x10);
        vfs.y2 = (int16_t)(vfs.y1 + dyMsg + 8);

        if (hwndScanner != NULL) {
            /* Toolbar visible only when "gd.grBits high word" is negative (Win16 artifact). */
            if ((int16_t)((uint32_t)gd.grBits >> 16) < 0) {
                MoveWindow(hwndTb, vfs.xTop + 8, 0, (vfs.dx - vfs.xTop) - 8, 0x24, TRUE);
                yToolbar = 0x24;
            } else {
                /* Hide offscreen */
                MoveWindow(hwndTb, 0, -100, 0x32, 0x32, TRUE);
                yToolbar = 0;
            }

            MoveWindow(hwndScanner, vfs.xTop + 8, yToolbar, (vfs.dx - vfs.xTop) - 8, vfs.dy - yToolbar, TRUE);

            MoveWindow(hwndPlanet, 0, 0, vfs.xTop, vfs.y1, TRUE);
            MoveWindow(hwndMessage, 0, vfs.y1 + 8, vfs.xTop, dyMsg, TRUE);
            MoveWindow(hwndMine, 0, vfs.y2 + 8, vfs.xTop, dyMin, TRUE);
        }
    } else {
        /* Split layout: Scanner+Mine on right; Planet+Message on left */

        if (vfs.dx - vfs.dx2PlanWant < 200)
            vfs.xTop = vfs.dx - 200;
        else
            vfs.xTop = vfs.dx2PlanWant;

        if (vfs.xTop < 199)
            vfs.xTop = 0xC6;

        if (vfs.dy2MsgWant < dyMsgFloor)
            vfs.dy2MsgWant = (int16_t)dyMsgFloor;

        if (vfs.dy2MinWant < dyMinFloor)
            vfs.dy2MinWant = (int16_t)dyMinFloor;

        dyMsg = vfs.dy2MsgWant;
        if (vfs.dy - (dyMsg + 8) < 100)
            dyMsg = vfs.dy - 0x6C;

        dyMin = vfs.dy2MinWant;
        if (vfs.dy - (dyMin + 8) < 100)
            dyMin = vfs.dy - 0x6C;

        vfs.y1 = (int16_t)((vfs.dy - dyMsg) - 8);
        vfs.y2 = (int16_t)((vfs.dy - dyMin) - 8);

        if (hwndScanner != NULL) {
            if ((int16_t)((uint32_t)gd.grBits >> 16) < 0) {
                MoveWindow(hwndTb, 0, 0, vfs.dx, 0x24, TRUE);
                yToolbar = 0x24;
            } else {
                MoveWindow(hwndTb, 0, -100, 0x32, 0x32, TRUE);
                yToolbar = 0;
            }

            MoveWindow(hwndScanner, vfs.xTop + 8, yToolbar, (vfs.dx - vfs.xTop) - 8, vfs.y2 - yToolbar, TRUE);

            MoveWindow(hwndPlanet, 0, yToolbar, vfs.xTop, vfs.y1 - yToolbar, TRUE);

            MoveWindow(hwndMessage, 0, vfs.y1 + 8, vfs.xTop, dyMsg, TRUE);

            MoveWindow(hwndMine, vfs.xTop + 8, vfs.y2 + 8, (vfs.dx - vfs.xTop) - 8, dyMin, TRUE);
        }
    }

    /* Update View->Layout checkmarks */
    {
        HMENU hmenuBar = (HMENU)GetASubMenu(hwndFrame, 1);
        HMENU hmenuView = GetSubMenu(hmenuBar, 4);

        for (int id = 0x82; id < 0x85; ++id) {
            const UINT f = MF_BYCOMMAND | (((id - 0x82) == iWindowLayout) ? MF_CHECKED : MF_UNCHECKED);
            CheckMenuItem(hmenuView, (UINT)id, f);
        }
    }
}

#endif /* _WIN32 */