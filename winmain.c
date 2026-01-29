#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string.h>

#include "types.h"
#include "globals.h"
#include "resource.h"

#include "init.h"
#include "mdi.h"
#include "stars.h"
#include "utilgen.h"

/*
 * WinMain (Stars! MEMORY_MAIN:0x0000).
 *
 * This is the real Stars! entrypoint, translated from the Win16 decompile.
 * We intentionally keep the init path + message loop, but avoid implementing
 * deep UI behaviors (FrameWndProc, menus, etc.) at this stage.
 */

static void ParseCmdLine(char *lpCmdLine)
{
    char *lpT = lpCmdLine;

    while (*lpT != '\0') {
        /* skip leading spaces */
        while (*lpT == ' ') {
            lpT++;
        }
        if (*lpT == '\0') {
            break;
        }

        if ((*lpT == '-') || (*lpT == '/')) {
            lpT++;

            while ((*lpT != '\0') && (*lpT != ' ')) {
                switch (*lpT) {
                case 'A':
                case 'a':
                    /* decompile: ini.wFlags = (ini.wFlags & 0xfbff) | 0x0400; */
                    ini.fNewGame = 1;
                    break;

                case 'B':
                case 'b': {
                    /* batch file: take next token as szBase */
                    char *pch;

                    lpT++;
                    while (*lpT == ' ') {
                        lpT++;
                    }

                    pch = szBase;
                    while ((*lpT != '\0') && (*lpT != ' ')) {
                        *pch++ = *lpT++;
                    }
                    *pch = '\0';

                    /* lpT will be incremented again by the outer loop */
                    lpT--;

                    if (FSetUpBatchProcessing() != 0) {
                        /*
                         * decompile: ini.wFlags = (ini.wFlags & 0xfdf4) | 0x20b;
                         *   => fStartupFile=1, fCmdLine=1, fGen=1, fBatch=1
                         */
                        ini.fStartupFile = 1;
                        ini.fCmdLine = 1;
                        ini.fGen = 1;
                        ini.fBatch = 1;
                        ini.fWait = 0;
                        ini.fTry = 0;
                    }
                } break;

                case 'C':
                case 'c':
                    /* decompile: set fCmdLine based on whether szBase has a token */
                    ini.fCmdLine = (szBase[0] != '\0');
                    break;

                case 'D':
                case 'd':
                    /* dump flags until space */
                    lpT++;
                    while ((*lpT != '\0') && (*lpT != ' ')) {
                        switch (*lpT) {
                        case 'F':
                        case 'f':
                            ini.fDumpFleets = 1;
                            break;
                        case 'P':
                        case 'p':
                            ini.fDumpPlanets = 1;
                            break;
                        case 'M':
                        case 'm':
                            ini.fDumpMap = 1;
                            break;
                        default:
                            break;
                        }
                        lpT++;
                    }
                    lpT--; /* outer loop increments */
                    break;

                case 'G':
                case 'g': {
                    /* generate N turns; cap at 1000 */
                    int16_t i = 0;

                    ini.fGen = 1;
                    while (i < 1000) {
                        char ch = lpT[1];
                        if ((ch < '0') || (ch > '9')) {
                            break;
                        }
                        lpT++;
                        i = (int16_t)(i * 10 + (int16_t)(*lpT - '0'));
                    }
                    if (i >= 1000) {
                        i = 1000;
                        while (true) {
                            char ch = lpT[1];
                            if ((ch < '0') || (ch > '9')) {
                                break;
                            }
                            lpT++;
                        }
                    }
                    if (i > 0) {
                        ini.cTurnGen = (int16_t)(i - 1);
                    }
                } break;

                case 'H':
                case 'h':
                    /* decompile: gd.grBits2 low word bit9 (0x0200) */
                    gd.fHotSeat = 1;
                    break;

                case 'L':
                case 'l':
                    ini.fLogging = 1;
                    break;

                case 'P':
                case 'p': {
                    /* password */
                    char *pch;

                    lpT++;
                    while (*lpT == ' ') {
                        lpT++;
                    }

                    pch = szPassLast;
                    while ((*lpT != '\0') && (*lpT != ' ') && (pch < (szPassLast + 0x0e))) {
                        *pch++ = *lpT++;
                    }
                    *pch = '\0';

                    lpT--; /* outer loop increments */
                    lSaltLast = LSaltFromSz(szPassLast);
                } break;

                case 'T':
                case 't':
                    ini.fTry = 1;
                    break;

                case 'V':
                case 'v':
                    ini.fValidate = 1;
                    break;

                case 'W':
                case 'w':
                    ini.fWait = 1;
                    break;

                case 'X':
                case 'x':
                    /* decompile: gd.grBits high word bit6 (0x0040) */
                    gd.fExitWindows = 1;
                    break;

                default:
                    break;
                }

                lpT++;
            }
        } else {
            /* bare token: startup file name -> szBase */
            char *pch = szBase;
            while ((*lpT != '\0') && (*lpT != ' ')) {
                *pch++ = *lpT++;
            }
            *pch = '\0';

            ini.fStartupFile = 1;
            ini.fCmdLine = 1;
        }
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    MSG msg;

    hInst = hInstance;
    (void)hPrevInstance;

    szBase[0] = '\0';
    ini.wFlags = 0;
    memset(&tutor, 0, sizeof(tutor));
    memset(&vtimer, 0, sizeof(vtimer));
    vtimer.fAutoGenWhenIn = 1;

    /* Win16: only call InitMDIApp when hPrevInstance == 0. In Win32, it's always 0. */
    if ((hPrevInstance == 0) && (InitMDIApp() == 0)) {
        MessageBoxA(NULL, "Unable to initialize Stars (InitMDIApp)", "Stars!", MB_ICONERROR | MB_OK);
        return 0;
    }

    Randomize2((uint32_t)GetTickCount());

    if (!FCreateStuff()) {
        MessageBoxA(NULL, "Unable to initialize Stars (FCreateStuff)", "Stars!", MB_ICONERROR | MB_OK);
        return 0;
    }

    if (FGetSystemColors() == 0) {
        MessageBoxA(NULL, "Unable to initialize Stars (FGetSystemColors)", "Stars!", MB_ICONERROR | MB_OK);
        return 0;
    }

    if (InitInstance((int16_t)nShowCmd) == 0) {
        MessageBoxA(NULL, "Unable to initialize Stars (InitInstance)", "Stars!", MB_ICONERROR | MB_OK);
        return 0;
    }

    ParseCmdLine(lpCmdLine);

    /* Win16 posts a private message (0x0464) to kick startup. Keep as-is for now. */
    if (hwndFrame != NULL) {
        PostMessage(hwndFrame, WM_STARS_STARTUP, 0, 0);
    }

    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        if ((hwndTitle != NULL) && (hAccelTitle != NULL) && TranslateAccelerator(hwndTitle, hAccelTitle, &msg))
        {
            continue;
        }
        if ((hAccel != NULL) && (hwndFrame != NULL) && TranslateAccelerator(hwndFrame, hAccel, &msg))
        {
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    FreeStuff();
    return (int)msg.wParam;
}
