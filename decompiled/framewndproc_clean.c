/*
 * Win32 first-pass translation of FrameWndProc.
 *
 * Conventions:
 *  - No namespaces.
 *  - Globals referenced directly (no c_common./_DATA. prefixes).
 *  - Prefer bitfields where we *know* the field name; otherwise use the raw word.
 *
 * Notes:
 *  - This is the *frame* window proc; if you have an MDI client window, you may
 *    want DefFrameProc(hwnd, hwndMDIClient, ...) instead of DefWindowProc.
 *    The decompile used DefWindowProc in the default path, so this keeps that.
 *  - Win16 MakeProcInstance/FreeProcInstance removed (Win32 uses raw function ptrs).
 *  - WM_SIZE uses LOWORD/HIWORD(lParam).
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* ----- external globals (declared elsewhere in your project) ----- */
extern HWND hwndFrame;
extern HWND hwndTitle;
extern HWND hwndScanner;
extern HWND hwndMessage;
extern HWND hwndPlanet;
extern HWND rghwndBtn[/*?*/];

extern HBRUSH hbrButtonShadow;
extern HBRUSH hbrButtonHilite;
extern HBRUSH hbrButtonFace;
extern HBRUSH hbrDesktop;

extern HBRUSH hbr50Screen;
extern HPALETTE vhpal;

extern HICON hiconHost;
extern HICON hiconStars;
extern HICON hiconWait;

extern uint16_t uTimerId;
extern uint16_t uTimerType;
extern int16_t  idPlayer;
extern int16_t  vretExitValue;
extern int16_t  fFileErrSilent;
extern int32_t  vSerialNumber; /* treat as 32-bit serial */

extern char szBase[];
extern char szWork[];

/* Struct globals (from your types.h) */
extern struct INI   ini;
extern struct GDATA gd;
extern struct TUTOR tutor;

/* frame sizing globals */
extern struct {
    int16_t dx, dy;
    int16_t xTop;
    int16_t y1, y2;
    int16_t dxPlanWant, dx2PlanWant;
    int16_t dyMsgWant, dy2MsgWant;
    int16_t dyMinWant, dy2MinWant;
} vfs;

extern int16_t iWindowLayout;

/* metrics */
extern int16_t dySysFont;
extern int16_t dySBar;
extern int16_t dyArial8;

/* selection globals */
typedef struct SEL {
    int16_t grobj;
    struct { int16_t id; } pl;
    POINT pt;
} SEL;
extern SEL sel;

/* enums */
enum { grobjNone = 0, grobjPlanet = 1, grobjFleet = 2 /* etc */ };

/* ----- external functions ----- */
extern int16_t FCreateFonts(HDC hdc);
extern void    InitTiles(void);
extern void    EnsureTileSize(uint32_t fLayout2);
extern void    RefitFrameChildren(void);
extern void    WriteIniSettings(void);

extern int16_t FMarkFile(int dt, int16_t idplr, int16_t op, int16_t flags);
extern void    DestroyCurGame(void);
extern int16_t FNewTurnAvail(int16_t idplr);
extern int16_t FLoadGame(char *pszBase, char *pszTurn);
extern void    CreateChildWindows(void);
extern void    InitializeMenu(WPARAM hMenu);
extern void    AdvanceTutor(void);
extern void    ShowTutor(int16_t fShow);
extern void    BringUpHostDlg(void);

extern void    VerifyTurns(void);
extern void    EnsureAis(void);
extern int16_t CTurnsOutSafe(void);
extern void    FGenerateTurn(void);

extern void    CommandHandler(HWND hwnd, WPARAM wParam);

extern int16_t ChangeProduction(int16_t dir);
extern int16_t IdFindAdjStarbase(int16_t idpl, uint32_t fPrev);
extern void    SelectAdjPlanet(int16_t dir, int16_t idStarbase);
extern void    SelectAdjFleet(int16_t dir, int16_t idStarbase);
extern void    ShipCommandProc(HWND hwndParent, WPARAM wParam, LPARAM lParam);

extern int16_t HcrsFromFrameWindowPt(POINT ptClient, int16_t *pgrSel /*nullable*/);
extern void    Setcursor(int16_t hcrs); /* your wrapper that sets cursor */
extern int16_t FGetMouseMove(POINT *pptClient);
extern POINT   InvertPaneBorder(HDC hdc, int16_t grSel, POINT dpt, POINT *pptChg /*nullable*/);

extern int16_t AlertSz(const char *psz, int flags);
extern char   *PszFormatIds(int16_t ids, int16_t *pParams);
extern int16_t FValidSerialNo(char *psz, int32_t *plSerialOut);

/* ids used in this proc (declare in your ids enum) */
extern const int16_t idsTurnHasSubmittedChangesMadeAfterTurn;
extern const int16_t idsNewTurnCurrentlyGeneratedHostNewTurn;
extern const int16_t idsUnableOpenNewTurnFile;
extern const int16_t idsNewTurnAvailableWouldLikeLoad;
extern const int16_t idsNewTurnAvailable;

/* Startup message numbers from earlier */
#ifndef WM_STARS_STARTUP
#define WM_STARS_STARTUP (WM_USER + 0x64) /* 0x464 */
#endif
#ifndef WM_STARS_HOSTDLG
#define WM_STARS_HOSTDLG (WM_USER + 0x65) /* 0x465 */
#endif
#ifndef WM_STARS_TUTORLOAD
#define WM_STARS_TUTORLOAD (WM_USER + 0x66) /* 0x466 */
#endif

/* helper: low/high word extraction */
#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))
#endif

LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_CREATE:
        {
            HDC hdc = GetDC(hwnd);
            TEXTMETRIC tm;

            (void)FCreateFonts(hdc);
            GetTextMetrics(hdc, &tm);

            dySysFont = (int16_t)tm.tmHeight;
            dySBar = (int16_t)((dyArial8 + 0x0c) * 2);

            ReleaseDC(hwnd, hdc);

            InitTiles();
            EnsureTileSize((uint32_t)(iWindowLayout == 2));
            return 0;
        }

        case WM_DESTROY:
        {
            if (uTimerId != 0) {
                KillTimer(NULL, (UINT_PTR)uTimerId);
            }

            WriteIniSettings();
            uTimerId = 0;

            /* decompile: if (gd._0_2_ >> 3 & 1) IO::FMarkFile(dtHost,-1,1,0); */
            /* If you have a named bitfield for this, use it. Otherwise keep raw. */
            if (((gd.wFlags >> 3) & 1u) != 0) {
                (void)FMarkFile(/*dtHost*/ 0, -1, 1, 0);
            }

            DestroyCurGame();

            /* decompile: if (((gd.wFlags >> 6) & 1) == 0) PostQuitMessage(vretExitValue); else ExitWindows(...) */
            if (((gd.wFlags >> 6) & 1u) == 0) {
                PostQuitMessage((int)vretExitValue);
                return 0;
            }

#ifdef _WIN32
            /* Win16: ExitWindows(exitCode,0). Win32 equivalent is ExitWindowsEx.
             * Keeping intent: request logoff/shutdown with return code carried elsewhere.
             * If you don’t want OS logoff behavior, replace with PostQuitMessage.
             */
            ExitWindowsEx(0, 0);
#endif
            return 0;
        }

        case WM_SIZE:
        {
            if (wParam == SIZE_MAXIMIZED || wParam == SIZE_RESTORED) {
                vfs.dx = (int16_t)LOWORD(lParam);
                vfs.dy = (int16_t)HIWORD(lParam);
                RefitFrameChildren();
                return 0;
            }
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }

        case WM_ACTIVATE:
            return 0;

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            if (!IsIconic(hwnd))
            {
                HGDIOBJ hSav = SelectObject(hdc, hbrButtonShadow);

                /* decompile does two layout paths */
                if (iWindowLayout == 0 || (iWindowLayout != 1 && iWindowLayout != 2))
                {
                    PatBlt(hdc, vfs.xTop + 5, 0, 2, vfs.dy, PATCOPY);
                    PatBlt(hdc, 0, vfs.y1 + 5, vfs.xTop + 2, 2, PATCOPY);
                    PatBlt(hdc, 0, vfs.y2 + 5, vfs.xTop + 2, 2, PATCOPY);

                    SelectObject(hdc, hbrButtonHilite);
                    PatBlt(hdc, vfs.xTop + 1, 0, 1, vfs.y1 + 2, PATCOPY);
                    PatBlt(hdc, 0, vfs.y1 + 1, vfs.xTop + 1, 1, PATCOPY);
                    PatBlt(hdc, vfs.xTop + 1, vfs.y1 + 6, 1, (vfs.y2 - vfs.y1) - 4, PATCOPY);
                    PatBlt(hdc, 0, vfs.y2 + 1, vfs.xTop + 1, 1, PATCOPY);
                    PatBlt(hdc, vfs.xTop + 1, vfs.y2 + 6, 1, (vfs.dy - vfs.y2) - 6, PATCOPY);
                }
                else
                {
                    int yOffset = (gd.wFlags & 0x8000u) ? 0x24 : 0; /* decompile: if gd.wFlags < 0 */

                    PatBlt(hdc, vfs.xTop + 5, yOffset, 2, (vfs.y2 + 2) - yOffset, PATCOPY);
                    PatBlt(hdc, 0, vfs.y1 + 5, vfs.xTop + 2, 2, PATCOPY);
                    PatBlt(hdc, vfs.xTop + 5, vfs.y2 + 5, (vfs.dx - vfs.xTop) - 5, 2, PATCOPY);
                    PatBlt(hdc, vfs.xTop + 5, vfs.y2 + 6, 2, (vfs.dy - vfs.y2) - 5, PATCOPY);

                    SelectObject(hdc, hbrButtonHilite);
                    PatBlt(hdc, vfs.xTop + 1, yOffset, 1, (vfs.y1 + 2) - yOffset, PATCOPY);
                    PatBlt(hdc, 0, vfs.y1 + 1, vfs.xTop + 1, 1, PATCOPY);
                    PatBlt(hdc, vfs.xTop + 1, vfs.y1 + 6, 1, (vfs.dy - vfs.y1) - 6, PATCOPY);
                    PatBlt(hdc, vfs.xTop + 6, vfs.y2 + 1, (vfs.dx - vfs.xTop) - 6, 1, PATCOPY);
                }

                SelectObject(hdc, hSav);
                EndPaint(hwnd, &ps);
                return 0;
            }

            /* iconic paint: choose icon based on state */
            {
                HICON hico = hiconHost;
                /* decompile: if idPlayer != -1 OR (game.lid==0) ... then Stars icon;
                 * then if uTimerId != 0 -> Wait icon.
                 * You can refine this once game.lid is global in scope here.
                 */
                if (idPlayer != -1) {
                    hico = hiconStars;
                }
                if (uTimerId != 0) {
                    hico = hiconWait;
                }
                DrawIcon(hdc, 2, 2, hico);
            }

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_ERASEBKGND:
        {
            HDC hdc = (HDC)wParam;
            RECT rc;
            GetClientRect(hwnd, &rc);

            if (IsIconic(hwnd)) {
                FillRect(hdc, &rc, hbrDesktop);
                return 0;
            }

            /* Exclude scanner rect from erase */
            if (hwndScanner != NULL) {
                RECT rScan;
                GetClientRect(hwndScanner, &rScan);

                POINT tl = { rScan.left,  rScan.top };
                POINT br = { rScan.right, rScan.bottom };
                MapWindowPoints(hwndScanner, hwnd, &tl, 1);
                MapWindowPoints(hwndScanner, hwnd, &br, 1);
                ExcludeClipRect(hdc, tl.x, tl.y, br.x, br.y);
            }

            FillRect(hdc, &rc, hbrButtonFace);
            return 1;
        }

        case WM_SYSCOLORCHANGE:
        case WM_WININICHANGE:
            /* your global function from earlier pass */
            (void)FGetSystemColors();
            return 0;

        case WM_SETCURSOR:
        {
            if (!IsIconic(hwnd))
            {
                POINT pt;
                RECT rc;
                int16_t hcrs = 0;

                GetCursorPos(&pt);
                ScreenToClient(hwndFrame, &pt);

                GetClientRect(hwnd, &rc);
                if (PtInRect(&rc, pt)) {
                    hcrs = (int16_t)HcrsFromFrameWindowPt(pt, NULL);
                    if (hcrs != 0) {
                        Setcursor(hcrs);
                        return TRUE;
                    }
                }
            }
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }

        case WM_GETMINMAXINFO:
        {
            MINMAXINFO *p = (MINMAXINFO *)lParam;
            /* decompile wrote 0x208 and 0x17c into struct at offsets 0x0c/0x0e (min track size). */
            p->ptMinTrackSize.x = 0x208;
            p->ptMinTrackSize.y = 0x17c;
            return 0;
        }

        case WM_QUERYDRAGICON:
        {
            HICON hico = hiconHost;
            if (idPlayer != -1) {
                hico = hiconStars;
                if (uTimerId != 0) {
                    hico = hiconWait;
                }
            }
            return (LRESULT)hico;
        }

        case WM_CHAR:
        {
            /* forward special keys to child windows */
            if (hwndScanner != NULL && (wParam == '-' || wParam == '+')) {
                SendMessage(hwndScanner, WM_CHAR, wParam, lParam);
                return 0;
            }
            if (hwndMessage != NULL && ((wParam == '-' || wParam == '+' || wParam == '\r'))) {
                SendMessage(hwndMessage, WM_CHAR, wParam, lParam);
                return 0;
            }
            if (hwndPlanet != NULL && (wParam == 'f' || wParam == 'F')) {
                SendMessage(hwndPlanet, WM_CHAR, wParam, lParam);
                return 0;
            }

            if (hwndPlanet != NULL && sel.grobj == grobjPlanet && (wParam == 'q' || wParam == 'Q')) {
                (void)ChangeProduction(0);
                return 0;
            }

            if ((sel.grobj & (grobjPlanet | grobjFleet)) == grobjNone) {
                return 0;
            }

            int16_t dir = 0;
            int16_t idStarbase = 0;

            if (wParam == 'n') {
                dir = 1;
            } else if (wParam == 'N' || wParam == 'P') {
                if (sel.grobj == grobjPlanet) {
                    idStarbase = (int16_t)IdFindAdjStarbase(sel.pl.id, (wParam == 'N') ? 1u : 0u);
                } else if (wParam == 'N') {
                    dir = 1;
                } else {
                    dir = -1;
                }
            } else if (wParam == 'p') {
                dir = -1;
            } else if ((wParam == 'r' || wParam == 'R') && sel.grobj == grobjFleet) {
                ShipCommandProc(hwndPlanet, 0, (LPARAM)rghwndBtn[6]);
                return 0;
            }

            if (dir == 0 && idStarbase == 0) {
                return 0;
            }

            if (sel.grobj != grobjFleet) {
                SelectAdjPlanet(dir, idStarbase);
                return 0;
            }
            SelectAdjFleet(dir, idStarbase);
            return 0;
        }

        case WM_COMMAND:
            CommandHandler(hwnd, wParam);
            return 0;

        case WM_SYSCOMMAND:
        {
            /* decompile checks SC_MAXIMIZE (0xF030) or SC_RESTORE (0xF120) */
            switch (wParam & 0xFFF0u) {
                case SC_MAXIMIZE:
                case SC_RESTORE:
                    /* Huge block in decompile: timer stop, check new turn availability, prompt, reload, etc.
                     * Keeping structure but calling into your existing helpers.
                     */
                    if (uTimerId != 0) {
                        KillTimer(NULL, (UINT_PTR)uTimerId);
                        uTimerId = 0;
                        CreateChildWindows();
                    }

                    if (idPlayer == -1 || !FNewTurnAvail(idPlayer)) {
                        /* fall through to your existing command */
                        SendMessage(hwndFrame, WM_COMMAND, 0x0FA1, 0);
                    } else {
                        /* new turn available path (prompt / reload) */
                        int16_t r = 6; /* IDYES style */
                        if (uTimerId == 0) {
                            r = (int16_t)AlertSz(PszFormatIds(idsNewTurnAvailableWouldLikeLoad, NULL),
                                                 MB_ICONQUESTION | MB_YESNO);
                        } else {
                            (void)AlertSz(PszFormatIds(idsNewTurnAvailable, NULL), MB_ICONINFORMATION);
                            r = 6;
                        }

                        if (r == 6) {
                            /* turn filename build was wsprintf with player+1; replace with your helper */
                            char szTurn[64];
                            /* TODO: use your real format; placeholder: "P1" etc */
                            (void)snprintf(szTurn, sizeof(szTurn), "P%u", (unsigned)(idPlayer + 1));

                            DestroyCurGame();
                            if (!FLoadGame(szBase, szTurn)) {
                                (void)AlertSz(PszFormatIds(idsUnableOpenNewTurnFile, NULL), MB_ICONERROR);
                            } else {
                                CreateChildWindows();
                            }
                        } else if (r == 2) {
                            /* IDCANCEL-ish behavior from decompile */
                            if (uTimerId == 0) {
                                PostMessage(hwndFrame, WM_SYSCOMMAND, SC_CLOSE, 0);
                            } else {
                                PostMessage(hwndFrame, WM_COMMAND, 0x006A, 0);
                            }
                            return 1;
                        }

                        SendMessage(hwndFrame, WM_COMMAND, 0x0FA1, 0);
                    }

                    return DefWindowProc(hwnd, msg, wParam, lParam);
            }

            return DefWindowProc(hwnd, msg, wParam, lParam);
        }

        case WM_INITMENU:
            InitializeMenu(wParam);
            return 0;

        case WM_ENTERIDLE:
            /* decompile: if (gd bit11) && (tutor bit2) AdvanceTutor(); */
            if (((gd.wFlags >> 11) & 1u) != 0 && ((tutor.wFlags >> 2) & 1u) != 0) {
                AdvanceTutor();
            }
            return 0;

        case WM_LBUTTONDOWN:
        {
            /* pane splitter dragging */
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            int16_t grSel = 0;
            int16_t hcrs = (int16_t)HcrsFromFrameWindowPt(pt, &grSel);
            if (hcrs == 0) {
                return 0;
            }

            HDC hdc = GetDC(hwnd);
            HGDIOBJ hSav = SelectObject(hdc, hbr50Screen);

            InvertPaneBorder(hdc, grSel, (POINT){0,0}, NULL);

            POINT ptLast = pt;
            POINT ptBase = pt;
            POINT ptAct  = {0,0};

            SetCapture(hwnd);

            while (FGetMouseMove(&pt)) {
                if (pt.x != ptLast.x || pt.y != ptLast.y) {
                    POINT dpt = { pt.x - ptBase.x, pt.y - ptBase.y };
                    POINT chg = { pt.x - ptLast.x, pt.y - ptLast.y };
                    ptAct = InvertPaneBorder(hdc, grSel, dpt, &chg);
                    ptLast = pt;
                }
            }

            /* erase last */
            InvertPaneBorder(hdc, grSel, (POINT){ pt.x - ptBase.x, pt.y - ptBase.y }, NULL);

            ReleaseCapture();
            SelectObject(hdc, hSav);
            ReleaseDC(hwnd, hdc);

            if (ptAct.x == 0 && ptAct.y == 0) {
                return 0;
            }

            /* apply deltas based on which splitter(s) moved */
            if (grSel & 1) {
                if (iWindowLayout == 0) vfs.dxPlanWant = (int16_t)(vfs.xTop + ptAct.x);
                else                    vfs.dx2PlanWant = (int16_t)(vfs.xTop + ptAct.x);
            }
            if (grSel & 2) {
                if (iWindowLayout == 0) vfs.dyMsgWant = (int16_t)(((vfs.y2 - vfs.y1) - 8) - ptAct.y);
                else                    vfs.dy2MsgWant = (int16_t)(((vfs.dy - vfs.y1) - 8) - ptAct.y);
            }
            if (grSel & 4) {
                if (iWindowLayout == 0) {
                    vfs.dyMsgWant = (int16_t)((vfs.y2 - vfs.y1) - 8 + ptAct.y);
                    vfs.dyMinWant = (int16_t)(((vfs.dy - vfs.y2) - 8) - ptAct.y);
                } else {
                    vfs.dy2MinWant = (int16_t)(((vfs.dy - vfs.y2) - 8) - ptAct.y);
                }
            }

            InvalidateRect(hwnd, NULL, TRUE);
            RefitFrameChildren();
            return 0;
        }

        case WM_QUERYNEWPALETTE:
        case WM_PALETTECHANGED:
        {
            if (msg == WM_PALETTECHANGED && (HWND)wParam == hwnd) {
                return 0;
            }

            if (hwndTitle != NULL) {
                return SendMessage(hwndTitle, msg, wParam, lParam);
            }

            HDC hdc = GetDC(hwnd);
            HPALETTE hpalSav = SelectPalette(hdc, vhpal, FALSE);
            int changed = RealizePalette(hdc);
            SelectPalette(hdc, hpalSav, FALSE);
            ReleaseDC(hwnd, hdc);

            if (changed != 0) {
                InvalidateRect(hwnd, NULL, TRUE);
                return 1;
            }
            return 0;
        }

        case WM_STARS_HOSTDLG:
            BringUpHostDlg();
            return 1;

        case WM_STARS_TUTORLOAD:
        {
            /* decompile: ShowTutor(0); destroy game; temporarily silence file errors; load base; create windows; etc.
             * This is big and very game-specific; keep the observable control flow.
             */
            ShowTutor(0);

            /* game.fDirty = 0; */
            /* TODO: set your game dirty bitfield here if global */

            DestroyCurGame();

            int16_t fSav = fFileErrSilent;
            fFileErrSilent = 1;

            /* decompile toggles gd.wFlags bit1 around load; keep raw until you confirm bitfield name */
            gd.wFlags = (uint16_t)((gd.wFlags & ~0x0002u) | 0x0002u);

            if (FLoadGame(szBase, (char *)0x3c8 /* placeholder; replace with real */)) {
                gd.wFlags = (uint16_t)(gd.wFlags & ~0x0002u);
                fFileErrSilent = fSav;
                idPlayer = 0;

                CreateChildWindows();
                SendMessage(hwndFrame, WM_COMMAND, 0x0FA1, 0);

                tutor.idt = 0;
                /* decompile: tutor.wFlags = (tutor.wFlags & 0xfdf7) | ((wParam==0x9ca)<<9) */
                /* keep raw */
                tutor.wFlags = (uint16_t)((tutor.wFlags & 0xfdf7u) | (((wParam == 0x9CA) ? 1u : 0u) << 9));

                AdvanceTutor();
            } else {
                fFileErrSilent = fSav;
                gd.wFlags = (uint16_t)(gd.wFlags & ~0x0002u);
            }

            return 0;
        }

        case WM_STARS_STARTUP:
        default:
            break;
    }

    /* ---- WM_STARS_STARTUP is huge in the decompile.
     * For a first-run Win32 translation, keep the entry point and push the heavy logic
     * into a helper you can port in stages.
     */
    if (msg == WM_STARS_STARTUP) {
        /* Original begins with: idPlayer = -1; then checks ini flags and branches
         * into validate/newgame/batch/gen or normal UI bring-up.
         *
         * Put the decompiled startup state machine here once you want it fully wired.
         */
        idPlayer = -1;

        /* Example of converting a couple obvious INI bit tests to bitfields:
         * decompile: (ini.wFlags >> 1 & 1) == 1  -> ini.fCmdLine
         */
        if (ini.fCmdLine) {
            /* TODO: port the rest of the startup state machine */
        }

        /* Ensure title window exists / show dialog / etc: TODO */
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}
