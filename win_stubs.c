/*
 * win_stubs.c - Windows API stub implementations for non-Windows builds
 *
 * These stub functions allow Stars! code to compile and link on Linux/macOS.
 * They return appropriate default values but do NOT provide real functionality.
 *
 * For actual Windows builds, link against the real Windows libraries instead.
 *
 * This file compiles when:
 * - Not on Windows (_WIN32 not defined), OR
 * - STARS_USE_WIN_STUBS is defined (to test Windows code paths on other platforms)
 */

#if !defined(_WIN32) || defined(STARS_USE_WIN_STUBS)

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "win_stubs.h"

/* ========================================================================
 * COMMDLG Stubs
 * ======================================================================== */

BOOL WINAPI GetOpenFileName(OPENFILENAME FAR *lpofn) {
    (void)lpofn;
    return FALSE;
}

BOOL WINAPI GetSaveFileName(OPENFILENAME FAR *lpofn) {
    (void)lpofn;
    return FALSE;
}

BOOL WINAPI PrintDlg(PRINTDLG FAR *lppd) {
    (void)lppd;
    return FALSE;
}

/* ========================================================================
 * GDI Stubs
 * ======================================================================== */

BOOL WINAPI BitBlt(HDC hdcDest, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop) {
    (void)hdcDest;
    (void)x;
    (void)y;
    (void)cx;
    (void)cy;
    (void)hdcSrc;
    (void)x1;
    (void)y1;
    (void)rop;
    return TRUE;
}

int WINAPI SetStretchBltMode(HDC hdc, int mode) {
    (void)hdc;
    (void)mode;
    return 0;
}

HBITMAP WINAPI CreateCompatibleBitmap(HDC hdc, int cx, int cy) {
    (void)hdc;
    (void)cx;
    (void)cy;
    return (HBITMAP)(uintptr_t)1; /* Non-zero handle */
}

HDC WINAPI CreateCompatibleDC(HDC hdc) {
    (void)hdc;
    return (HDC)(uintptr_t)1; /* Non-zero handle */
}

HFONT WINAPI CreateFontIndirect(const LOGFONT FAR *lplf) {
    (void)lplf;
    return (HFONT)(uintptr_t)1;
}

HPALETTE WINAPI CreatePalette(const LOGPALETTE FAR *lplgpl) {
    (void)lplgpl;
    return (HPALETTE)(uintptr_t)1;
}

HBRUSH WINAPI CreatePatternBrush(HBITMAP hbm) {
    (void)hbm;
    return (HBRUSH)(uintptr_t)1;
}

HPEN WINAPI CreatePen(int iStyle, int cWidth, COLORREF color) {
    (void)iStyle;
    (void)cWidth;
    (void)color;
    return (HPEN)(uintptr_t)1;
}

HRGN WINAPI CreateRectRgn(int x1, int y1, int x2, int y2) {
    (void)x1;
    (void)y1;
    (void)x2;
    (void)y2;
    return (HRGN)(uintptr_t)1;
}

HBRUSH WINAPI CreateSolidBrush(COLORREF color) {
    (void)color;
    return (HBRUSH)(uintptr_t)1;
}

BOOL WINAPI DeleteDC(HDC hdc) {
    (void)hdc;
    return TRUE;
}

BOOL WINAPI DeleteObject(HGDIOBJ ho) {
    (void)ho;
    return TRUE;
}

BOOL WINAPI Ellipse(HDC hdc, int left, int top, int right, int bottom) {
    (void)hdc;
    (void)left;
    (void)top;
    (void)right;
    (void)bottom;
    return TRUE;
}

int WINAPI Escape(HDC hdc, int iEscape, int cjIn, LPCSTR lpIn, void FAR *lpOut) {
    (void)hdc;
    (void)iEscape;
    (void)cjIn;
    (void)lpIn;
    (void)lpOut;
    return 0;
}

int WINAPI ExcludeClipRect(HDC hdc, int left, int top, int right, int bottom) {
    (void)hdc;
    (void)left;
    (void)top;
    (void)right;
    (void)bottom;
    return 1; /* SIMPLEREGION */
}

BOOL WINAPI ExtTextOut(HDC hdc, int x, int y, UINT options, const RECT FAR *lprect, LPCSTR lpString, UINT c, int FAR *lpDx) {
    (void)hdc;
    (void)x;
    (void)y;
    (void)options;
    (void)lprect;
    (void)lpString;
    (void)c;
    (void)lpDx;
    return TRUE;
}

COLORREF WINAPI GetBkColor(HDC hdc) {
    (void)hdc;
    return 0xFFFFFF; /* White */
}

int WINAPI GetDeviceCaps(HDC hdc, int index) {
    (void)hdc;
    switch (index) {
    case HORZRES:
        return 640;
    case VERTRES:
        return 480;
    case BITSPIXEL:
        return 8;
    case PLANES:
        return 1;
    case NUMCOLORS:
        return 256;
    case LOGPIXELSX:
        return 96;
    case LOGPIXELSY:
        return 96;
    default:
        return 0;
    }
}

int WINAPI GetDIBits(HDC hdc, HBITMAP hbm, UINT start, UINT cLines, void FAR *lpvBits, BITMAPINFO FAR *lpbmi, UINT usage) {
    (void)hdc;
    (void)hbm;
    (void)start;
    (void)cLines;
    (void)lpvBits;
    (void)lpbmi;
    (void)usage;
    return 0;
}

int WINAPI GetObject(HGDIOBJ h, int c, void FAR *pv) {
    (void)h;
    (void)c;
    (void)pv;
    return 0;
}

int WINAPI GetROP2(HDC hdc) {
    (void)hdc;
    return R2_COPYPEN;
}

HGDIOBJ WINAPI GetStockObject(int i) {
    (void)i;
    return (HGDIOBJ)(uintptr_t)1;
}

DWORD WINAPI GetTextExtent(HDC hdc, LPCSTR lpString, int c) {
    (void)hdc;
    (void)lpString;
    /* Return width in low word, height in high word */
    /* Estimate: 8 pixels per character, 16 pixels high */
    return MAKELONG(c * 8, 16);
}

BOOL WINAPI GetTextExtentPoint32A(HDC hdc, LPCSTR lpString, int c, LPSIZE lpSize) {
    (void)hdc;
    (void)lpString;
    if (lpSize) {
        lpSize->cx = (LONG)(c * 8);
        lpSize->cy = 16;
    }
    return TRUE;
}

BOOL WINAPI GetTextExtentPointA(HDC hdc, LPCSTR lpString, int c, LPSIZE lpSize) { return GetTextExtentPoint32A(hdc, lpString, c, lpSize); }

BOOL WINAPI GetTextMetrics(HDC hdc, TEXTMETRIC FAR *lptm) {
    (void)hdc;
    if (lptm) {
        memset(lptm, 0, sizeof(*lptm));
        lptm->tmHeight = 16;
        lptm->tmAscent = 12;
        lptm->tmDescent = 4;
        lptm->tmAveCharWidth = 8;
        lptm->tmMaxCharWidth = 12;
    }
    return TRUE;
}

int WINAPI IntersectClipRect(HDC hdc, int left, int top, int right, int bottom) {
    (void)hdc;
    (void)left;
    (void)top;
    (void)right;
    (void)bottom;
    return 1; /* SIMPLEREGION */
}

BOOL WINAPI LineTo(HDC hdc, int x, int y) {
    (void)hdc;
    (void)x;
    (void)y;
    return TRUE;
}

DWORD WINAPI MoveTo(HDC hdc, int x, int y) {
    (void)hdc;
    (void)x;
    (void)y;
    return 0;
}

int WINAPI MulDiv(int nNumber, int nNumerator, int nDenominator) {
    if (nDenominator == 0)
        return -1;
    return (int)(((long long)nNumber * nNumerator) / nDenominator);
}

BOOL WINAPI PatBlt(HDC hdc, int x, int y, int w, int h, DWORD rop) {
    (void)hdc;
    (void)x;
    (void)y;
    (void)w;
    (void)h;
    (void)rop;
    return TRUE;
}

BOOL WINAPI Rectangle(HDC hdc, int left, int top, int right, int bottom) {
    (void)hdc;
    (void)left;
    (void)top;
    (void)right;
    (void)bottom;
    return TRUE;
}

int WINAPI SelectClipRgn(HDC hdc, HRGN hrgn) {
    (void)hdc;
    (void)hrgn;
    return 1; /* SIMPLEREGION */
}

HGDIOBJ WINAPI SelectObject(HDC hdc, HGDIOBJ h) {
    (void)hdc;
    (void)h;
    return (HGDIOBJ)(uintptr_t)1; /* Previous object */
}

COLORREF WINAPI SetBkColor(HDC hdc, COLORREF color) {
    (void)hdc;
    (void)color;
    return 0xFFFFFF;
}

int WINAPI SetBkMode(HDC hdc, int mode) {
    (void)hdc;
    (void)mode;
    return OPAQUE;
}

DWORD WINAPI SetBrushOrg(HDC hdc, int x, int y) {
    (void)hdc;
    (void)x;
    (void)y;
    return 0;
}

COLORREF WINAPI SetPixel(HDC hdc, int x, int y, COLORREF color) {
    (void)hdc;
    (void)x;
    (void)y;
    (void)color;
    return color;
}

int WINAPI SetROP2(HDC hdc, int rop2) {
    (void)hdc;
    (void)rop2;
    return R2_COPYPEN;
}

COLORREF WINAPI SetTextColor(HDC hdc, COLORREF color) {
    (void)hdc;
    (void)color;
    return 0;
}

DWORD WINAPI SetWindowOrg(HDC hdc, int x, int y) {
    (void)hdc;
    (void)x;
    (void)y;
    return 0;
}

int WINAPI StretchDIBits(HDC hdc, int xDest, int yDest, int DestWidth, int DestHeight, int xSrc, int ySrc, int SrcWidth, int SrcHeight, const void FAR *lpBits,
                         const BITMAPINFO FAR *lpbmi, UINT iUsage, DWORD rop) {
    (void)hdc;
    (void)xDest;
    (void)yDest;
    (void)DestWidth;
    (void)DestHeight;
    (void)xSrc;
    (void)ySrc;
    (void)SrcWidth;
    (void)SrcHeight;
    (void)lpBits;
    (void)lpbmi;
    (void)iUsage;
    (void)rop;
    return 0;
}

BOOL WINAPI TextOut(HDC hdc, int x, int y, LPCSTR lpString, int c) {
    (void)hdc;
    (void)x;
    (void)y;
    (void)lpString;
    (void)c;
    return TRUE;
}

BOOL WINAPI TextOutA(HDC hdc, int x, int y, LPCSTR lpString, int c) { return TextOut(hdc, x, y, lpString, c); }

BOOL WINAPI UnrealizeObject(HGDIOBJ h) {
    (void)h;
    return TRUE;
}

/* ========================================================================
 * KERNEL Stubs
 * ======================================================================== */

HFILE WINAPI _lclose(HFILE hFile) {
    (void)hFile;
    return 0;
}

UINT WINAPI _lread(HFILE hFile, void FAR *lpBuffer, UINT uBytes) {
    (void)hFile;
    (void)lpBuffer;
    (void)uBytes;
    return 0;
}

UINT WINAPI _lwrite(HFILE hFile, const void FAR *lpBuffer, UINT uBytes) {
    (void)hFile;
    (void)lpBuffer;
    (void)uBytes;
    return 0;
}

int WINAPI AccessResource(HINSTANCE hInstance, HRSRC hResInfo) {
    (void)hInstance;
    (void)hResInfo;
    return -1;
}

HGLOBAL WINAPI AllocResource(HINSTANCE hInstance, HRSRC hResInfo, DWORD dwSize) {
    (void)hInstance;
    (void)hResInfo;
    (void)dwSize;
    return 0;
}

void WINAPI FatalAppExit(UINT uAction, LPCSTR lpMessageText) {
    (void)uAction;
    fprintf(stderr, "FatalAppExit: %s\n", lpMessageText ? lpMessageText : "(null)");
    exit(1);
}

void WINAPI FatalExit(int code) {
    fprintf(stderr, "FatalExit: %d\n", code);
    exit(code);
}

HRSRC WINAPI FindResource(HINSTANCE hInstance, LPCSTR lpName, LPCSTR lpType) {
    (void)hInstance;
    (void)lpName;
    (void)lpType;
    return 0;
}

void WINAPI FreeProcInstance(FARPROC lpProc) { (void)lpProc; }

BOOL WINAPI FreeResource(HGLOBAL hResData) {
    (void)hResData;
    return TRUE;
}

LPSTR WINAPI GetDOSEnvironment(void) { return NULL; }

UINT WINAPI GetDriveType(int nDrive) {
    (void)nDrive;
    return 0; /* Unknown */
}

int WINAPI GetModuleFileName(HINSTANCE hInstance, LPSTR lpFilename, int nSize) {
    (void)hInstance;
    if (lpFilename && nSize > 0) {
        lpFilename[0] = '\0';
    }
    return 0;
}

UINT WINAPI GetCurrentDirectory(UINT nBufferLength, LPSTR lpBuffer) {
    /* Best-effort: map to POSIX getcwd(). Return length excluding NUL like Win32. */
    if (lpBuffer == NULL || nBufferLength == 0) {
        return 0;
    }

    if (getcwd(lpBuffer, (size_t)nBufferLength) == NULL) {
        lpBuffer[0] = '\0';
        return 0;
    }

    return (UINT)strlen(lpBuffer);
}

UINT WINAPI GetPrivateProfileInt(LPCSTR lpAppName, LPCSTR lpKeyName, int nDefault, LPCSTR lpFileName) {
    (void)lpAppName;
    (void)lpKeyName;
    (void)lpFileName;
    return nDefault;
}

int WINAPI GetPrivateProfileString(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault, LPSTR lpReturnedString, int nSize, LPCSTR lpFileName) {
    (void)lpAppName;
    (void)lpKeyName;
    (void)lpFileName;
    if (lpReturnedString && nSize > 0) {
        if (lpDefault) {
            strncpy(lpReturnedString, lpDefault, nSize - 1);
            lpReturnedString[nSize - 1] = '\0';
            return (int)strlen(lpReturnedString);
        }
        lpReturnedString[0] = '\0';
    }
    return 0;
}

DWORD WINAPI GetVersion(void) {
    /* Return Windows 3.1 version (3.10) */
    return 0x0A03;
}

HGLOBAL WINAPI GlobalAlloc(UINT uFlags, DWORD dwBytes) {
    (void)uFlags;
    return (HGLOBAL)(uintptr_t)malloc((size_t)dwBytes);
}

HGLOBAL WINAPI GlobalFree(HGLOBAL hMem) {
    free((void *)(uintptr_t)hMem);
    return 0;
}

void FAR *WINAPI GlobalLock(HGLOBAL hMem) { return (void *)(uintptr_t)hMem; }

HGLOBAL WINAPI GlobalReAlloc(HGLOBAL hMem, DWORD dwBytes, UINT uFlags) {
    (void)uFlags;
    return (HGLOBAL)(uintptr_t)realloc((void *)(uintptr_t)hMem, (size_t)dwBytes);
}

DWORD WINAPI GlobalSize(HGLOBAL hMem) {
    (void)hMem;
    return 0; /* Cannot determine size of malloc'd block portably */
}

BOOL WINAPI GlobalUnlock(HGLOBAL hMem) {
    (void)hMem;
    return FALSE; /* Lock count is zero */
}

HGLOBAL WINAPI LoadResource(HINSTANCE hInstance, HRSRC hResInfo) {
    (void)hInstance;
    (void)hResInfo;
    return 0;
}

HLOCAL WINAPI LocalAlloc(UINT uFlags, UINT uBytes) {
    (void)uFlags;
    return (HLOCAL)(uintptr_t)malloc(uBytes);
}

HLOCAL WINAPI LocalFree(HLOCAL hMem) {
    free((void *)(uintptr_t)hMem);
    return 0;
}

HLOCAL WINAPI LocalReAlloc(HLOCAL hMem, UINT uBytes, UINT uFlags) {
    (void)uFlags;
    return (HLOCAL)(uintptr_t)realloc((void *)(uintptr_t)hMem, uBytes);
}

UINT WINAPI LocalSize(HLOCAL hMem) {
    (void)hMem;
    return 0;
}

void FAR *WINAPI LockResource(HGLOBAL hResData) { return (void *)(uintptr_t)hResData; }

HGLOBAL WINAPI LockSegment(UINT wSegment) {
    (void)wSegment;
    return 0;
}

LPSTR WINAPI lstrcat(LPSTR lpString1, LPCSTR lpString2) { return strcat(lpString1, lpString2); }

LPSTR WINAPI lstrcpy(LPSTR lpString1, LPCSTR lpString2) { return strcpy(lpString1, lpString2); }

LPSTR WINAPI lstrcpyn(LPSTR lpString1, LPCSTR lpString2, int iMaxLength) {
    if (iMaxLength <= 0) {
        return lpString1;
    }
    if (lpString1 == NULL) {
        return NULL;
    }
    /* Windows behavior: copies up to iMaxLength-1 chars and always NUL terminates. */
    if (lpString2 == NULL) {
        lpString1[0] = '\0';
        return lpString1;
    }
    strncpy(lpString1, lpString2, (size_t)(iMaxLength - 1));
    lpString1[iMaxLength - 1] = '\0';
    return lpString1;
}

LPSTR WINAPI CharLowerA(LPSTR lpsz) {
    if (!lpsz) {
        return NULL;
    }
    for (char *p = lpsz; *p; ++p) {
        *p = (char)tolower((unsigned char)*p);
    }
    return lpsz;
}

int WINAPI lstrlen(LPCSTR lpString) { return lpString ? (int)strlen(lpString) : 0; }

int WINAPI lstrlenA(LPCSTR lpString) { return lstrlen(lpString); }

FARPROC WINAPI MakeProcInstance(FARPROC lpProc, HINSTANCE hInstance) {
    (void)hInstance;
    return lpProc;
}

HFILE WINAPI OpenFile(LPCSTR lpFileName, OFSTRUCT FAR *lpReOpenBuff, UINT uStyle) {
    (void)lpFileName;
    (void)lpReOpenBuff;
    (void)uStyle;
    return HFILE_ERROR;
}

DWORD WINAPI SizeofResource(HINSTANCE hInstance, HRSRC hResInfo) {
    (void)hInstance;
    (void)hResInfo;
    return 0;
}

void WINAPI UnlockSegment(UINT wSegment) { (void)wSegment; }

BOOL WINAPI WritePrivateProfileString(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName) {
    (void)lpAppName;
    (void)lpKeyName;
    (void)lpString;
    (void)lpFileName;
    return FALSE;
}

void WINAPI Yield(void) { /* No-op on non-Windows */ }

/* ========================================================================
 * TOOLHELP Stubs
 * ======================================================================== */

BOOL WINAPI TimerCount(TIMERINFO FAR *lpti) {
    if (lpti && lpti->dwSize >= sizeof(TIMERINFO)) {
        lpti->dwmsSinceStart = (DWORD)(clock() * 1000 / CLOCKS_PER_SEC);
        lpti->dwmsThisVM = lpti->dwmsSinceStart;
        return TRUE;
    }
    return FALSE;
}

/* ========================================================================
 * USER Stubs
 * ======================================================================== */

int FAR __cdecl wsprintf(LPSTR lpOut, LPCSTR lpFmt, ...) {
    va_list args;
    int     ret;
    va_start(args, lpFmt);
    ret = vsprintf(lpOut, lpFmt, args);
    va_end(args);
    return ret;
}

BOOL WINAPI AppendMenu(HMENU hMenu, UINT uFlags, UINT uIDNewItem, LPCSTR lpNewItem) {
    (void)hMenu;
    (void)uFlags;
    (void)uIDNewItem;
    (void)lpNewItem;
    return TRUE;
}

HDC WINAPI BeginPaint(HWND hWnd, PAINTSTRUCT FAR *lpPaint) {
    (void)hWnd;
    if (lpPaint) {
        memset(lpPaint, 0, sizeof(*lpPaint));
        lpPaint->hdc = (HDC)(uintptr_t)1;
    }
    return (HDC)(uintptr_t)1;
}

LRESULT WINAPI CallWindowProc(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (lpPrevWndFunc)
        return lpPrevWndFunc(hWnd, Msg, wParam, lParam);
    return 0;
}

void WINAPI CheckDlgButton(HWND hDlg, int nIDButton, UINT uCheck) {
    (void)hDlg;
    (void)nIDButton;
    (void)uCheck;
}

BOOL WINAPI CheckMenuItem(HMENU hMenu, UINT uIDCheckItem, UINT uCheck) {
    (void)hMenu;
    (void)uIDCheckItem;
    (void)uCheck;
    return 0;
}

void WINAPI CheckRadioButton(HWND hDlg, int nIDFirstButton, int nIDLastButton, int nIDCheckButton) {
    (void)hDlg;
    (void)nIDFirstButton;
    (void)nIDLastButton;
    (void)nIDCheckButton;
}

void WINAPI ClientToScreen(HWND hWnd, POINT FAR *lpPoint) {
    (void)hWnd;
    (void)lpPoint;
}

void WINAPI CopyRect(RECT FAR *lprcDst, const RECT FAR *lprcSrc) {
    if (lprcDst && lprcSrc)
        *lprcDst = *lprcSrc;
}

HWND WINAPI CreateDialog(HINSTANCE hInstance, LPCSTR lpTemplate, HWND hWndParent, DLGPROC lpDialogFunc) {
    (void)hInstance;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    return 0;
}

HMENU WINAPI CreatePopupMenu(void) { return (HMENU)(uintptr_t)1; }

HWND WINAPI CreateWindow(LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
                         HINSTANCE hInstance, void FAR *lpParam) {
    (void)lpClassName;
    (void)lpWindowName;
    (void)dwStyle;
    (void)x;
    (void)y;
    (void)nWidth;
    (void)nHeight;
    (void)hWndParent;
    (void)hMenu;
    (void)hInstance;
    (void)lpParam;
    return 0;
}

LRESULT WINAPI DefWindowProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    (void)hWnd;
    (void)Msg;
    (void)wParam;
    (void)lParam;
    return 0;
}

BOOL WINAPI DeleteMenu(HMENU hMenu, UINT uPosition, UINT uFlags) {
    (void)hMenu;
    (void)uPosition;
    (void)uFlags;
    return TRUE;
}

BOOL WINAPI DestroyCursor(HCURSOR hCursor) {
    (void)hCursor;
    return TRUE;
}

BOOL WINAPI DestroyIcon(HICON hIcon) {
    (void)hIcon;
    return TRUE;
}

BOOL WINAPI DestroyMenu(HMENU hMenu) {
    (void)hMenu;
    return TRUE;
}

BOOL WINAPI DestroyWindow(HWND hWnd) {
    (void)hWnd;
    return TRUE;
}

int WINAPI DialogBox(HINSTANCE hInstance, LPCSTR lpTemplate, HWND hWndParent, DLGPROC lpDialogFunc) {
    (void)hInstance;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    return -1;
}

LONG WINAPI DispatchMessage(const MSG FAR *lpMsg) {
    (void)lpMsg;
    return 0;
}

BOOL WINAPI DrawIcon(HDC hDC, int x, int y, HICON hIcon) {
    (void)hDC;
    (void)x;
    (void)y;
    (void)hIcon;
    return TRUE;
}

void WINAPI DrawMenuBar(HWND hWnd) { (void)hWnd; }

int WINAPI DrawText(HDC hdc, LPCSTR lpchText, int cchText, RECT FAR *lprc, UINT format) {
    (void)hdc;
    (void)lpchText;
    (void)cchText;
    (void)lprc;
    (void)format;
    return 0;
}

BOOL WINAPI EnableMenuItem(HMENU hMenu, UINT uIDEnableItem, UINT uEnable) {
    (void)hMenu;
    (void)uIDEnableItem;
    (void)uEnable;
    return FALSE;
}

BOOL WINAPI EnableWindow(HWND hWnd, BOOL bEnable) {
    (void)hWnd;
    (void)bEnable;
    return FALSE;
}

void WINAPI EndDialog(HWND hDlg, int nResult) {
    (void)hDlg;
    (void)nResult;
}

void WINAPI EndPaint(HWND hWnd, const PAINTSTRUCT FAR *lpPaint) {
    (void)hWnd;
    (void)lpPaint;
}

BOOL WINAPI EqualRect(const RECT FAR *lprc1, const RECT FAR *lprc2) {
    if (!lprc1 || !lprc2)
        return FALSE;
    return (lprc1->left == lprc2->left && lprc1->top == lprc2->top && lprc1->right == lprc2->right && lprc1->bottom == lprc2->bottom);
}

BOOL WINAPI ExitWindows(DWORD dwReserved, UINT uReserved) {
    (void)dwReserved;
    (void)uReserved;
    exit(0);
    return TRUE;
}

int WINAPI FillRect(HDC hDC, const RECT FAR *lprc, HBRUSH hbr) {
    (void)hDC;
    (void)lprc;
    (void)hbr;
    return 1;
}

BOOL WINAPI FlashWindow(HWND hWnd, BOOL bInvert) {
    (void)hWnd;
    (void)bInvert;
    return FALSE;
}

int WINAPI FrameRect(HDC hDC, const RECT FAR *lprc, HBRUSH hbr) {
    (void)hDC;
    (void)lprc;
    (void)hbr;
    return 1;
}

HWND WINAPI GetActiveWindow(void) { return 0; }

int WINAPI GetAsyncKeyState(int vKey) {
    (void)vKey;
    return 0;
}

void WINAPI GetClientRect(HWND hWnd, RECT FAR *lpRect) {
    (void)hWnd;
    if (lpRect) {
        lpRect->left = 0;
        lpRect->top = 0;
        lpRect->right = 640;
        lpRect->bottom = 480;
    }
}

DWORD WINAPI GetCurrentTime(void) { return GetTickCount(); }

void WINAPI GetCursorPos(POINT FAR *lpPoint) {
    if (lpPoint) {
        lpPoint->x = 0;
        lpPoint->y = 0;
    }
}

HDC WINAPI GetDC(HWND hWnd) {
    (void)hWnd;
    return (HDC)(uintptr_t)1;
}

HWND WINAPI GetDlgItem(HWND hDlg, int nIDDlgItem) {
    (void)hDlg;
    (void)nIDDlgItem;
    return 0;
}

int WINAPI GetDlgItemText(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax) {
    (void)hDlg;
    (void)nIDDlgItem;
    if (lpString && cchMax > 0)
        lpString[0] = '\0';
    return 0;
}

int WINAPI GetDlgCtrlID(HWND hwnd) {
    (void)hwnd;
    /* Without a real UI backend there is no control ID. */
    return 0;
}

HWND WINAPI GetFocus(void) { return 0; }

int WINAPI GetKeyState(int nVirtKey) {
    (void)nVirtKey;
    return 0;
}

HMENU WINAPI GetMenu(HWND hWnd) {
    (void)hWnd;
    return 0;
}

int WINAPI GetMenuItemCount(HMENU hMenu) {
    (void)hMenu;
    return 0;
}

BOOL WINAPI GetMessage(MSG FAR *lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax) {
    (void)lpMsg;
    (void)hWnd;
    (void)wMsgFilterMin;
    (void)wMsgFilterMax;
    return FALSE; /* WM_QUIT */
}

HWND WINAPI GetParent(HWND hWnd) {
    (void)hWnd;
    return 0;
}

int WINAPI GetScrollPos(HWND hWnd, int nBar) {
    (void)hWnd;
    (void)nBar;
    return 0;
}

HMENU WINAPI GetSubMenu(HMENU hMenu, int nPos) {
    (void)hMenu;
    (void)nPos;
    return 0;
}

COLORREF WINAPI GetSysColor(int nIndex) {
    (void)nIndex;
    return 0xC0C0C0; /* Light gray */
}

int WINAPI GetSystemMetrics(int nIndex) {
    switch (nIndex) {
    case SM_CXSCREEN:
        return 640;
    case SM_CYSCREEN:
        return 480;
    case SM_CXVSCROLL:
        return 16;
    case SM_CYHSCROLL:
        return 16;
    case SM_CXBORDER:
        return 1;
    case SM_CYBORDER:
        return 1;
    case SM_CXICON:
        return 32;
    case SM_CYICON:
        return 32;
    default:
        return 0;
    }
}

HMONITOR WINAPI MonitorFromWindow(HWND hwnd, DWORD dwFlags) {
    (void)hwnd;
    (void)dwFlags;
    return 0;
}

BOOL WINAPI GetMonitorInfoA(HMONITOR hMonitor, MONITORINFO *lpmi) {
    (void)hMonitor;
    if (lpmi) {
        memset(lpmi, 0, sizeof(*lpmi));
        lpmi->cbSize = (DWORD)sizeof(*lpmi);
        /* Provide a plausible default work area. */
        lpmi->rcMonitor.left = 0;
        lpmi->rcMonitor.top = 0;
        lpmi->rcMonitor.right = 640;
        lpmi->rcMonitor.bottom = 480;
        lpmi->rcWork = lpmi->rcMonitor;
    }
    return TRUE;
}

BOOL WINAPI SystemParametersInfoA(UINT uiAction, UINT uiParam, void *pvParam, UINT fWinIni) {
    (void)uiParam;
    (void)fWinIni;
    if (uiAction == SPI_GETWORKAREA && pvParam) {
        RECT *prc = (RECT *)pvParam;
        prc->left = 0;
        prc->top = 0;
        prc->right = 640;
        prc->bottom = 480;
        return TRUE;
    }
    return FALSE;
}

DWORD WINAPI GetTickCount(void) { return (DWORD)(clock() * 1000 / CLOCKS_PER_SEC); }

HWND WINAPI GetWindow(HWND hWnd, UINT uCmd) {
    (void)hWnd;
    (void)uCmd;
    return 0;
}

LONG WINAPI GetWindowLong(HWND hWnd, int nIndex) {
    (void)hWnd;
    (void)nIndex;
    return 0;
}

BOOL WINAPI GetWindowPlacement(HWND hWnd, WINDOWPLACEMENT FAR *lpwndpl) {
    (void)hWnd;
    if (lpwndpl)
        memset(lpwndpl, 0, sizeof(*lpwndpl));
    return FALSE;
}

void WINAPI GetWindowRect(HWND hWnd, RECT FAR *lpRect) {
    (void)hWnd;
    if (lpRect) {
        lpRect->left = 0;
        lpRect->top = 0;
        lpRect->right = 640;
        lpRect->bottom = 480;
    }
}

int WINAPI GetWindowText(HWND hWnd, LPSTR lpString, int nMaxCount) {
    (void)hWnd;
    if (lpString && nMaxCount > 0)
        lpString[0] = '\0';
    return 0;
}

void WINAPI InflateRect(RECT FAR *lprc, int dx, int dy) {
    if (lprc) {
        lprc->left -= dx;
        lprc->top -= dy;
        lprc->right += dx;
        lprc->bottom += dy;
    }
}

BOOL WINAPI InsertMenu(HMENU hMenu, UINT uPosition, UINT uFlags, UINT uIDNewItem, LPCSTR lpNewItem) {
    (void)hMenu;
    (void)uPosition;
    (void)uFlags;
    (void)uIDNewItem;
    (void)lpNewItem;
    return TRUE;
}

BOOL WINAPI IntersectRect(RECT FAR *lprcDst, const RECT FAR *lprcSrc1, const RECT FAR *lprcSrc2) {
    if (!lprcDst || !lprcSrc1 || !lprcSrc2)
        return FALSE;
    lprcDst->left = (lprcSrc1->left > lprcSrc2->left) ? lprcSrc1->left : lprcSrc2->left;
    lprcDst->top = (lprcSrc1->top > lprcSrc2->top) ? lprcSrc1->top : lprcSrc2->top;
    lprcDst->right = (lprcSrc1->right < lprcSrc2->right) ? lprcSrc1->right : lprcSrc2->right;
    lprcDst->bottom = (lprcSrc1->bottom < lprcSrc2->bottom) ? lprcSrc1->bottom : lprcSrc2->bottom;
    return (lprcDst->left < lprcDst->right && lprcDst->top < lprcDst->bottom);
}

void WINAPI InvalidateRect(HWND hWnd, const RECT FAR *lpRect, BOOL bErase) {
    (void)hWnd;
    (void)lpRect;
    (void)bErase;
}

UINT WINAPI IsDlgButtonChecked(HWND hDlg, int nIDButton) {
    (void)hDlg;
    (void)nIDButton;
    return 0;
}

BOOL WINAPI IsIconic(HWND hWnd) {
    (void)hWnd;
    return FALSE;
}

BOOL WINAPI IsWindowVisible(HWND hWnd) {
    (void)hWnd;
    return TRUE;
}

BOOL WINAPI IsZoomed(HWND hWnd) {
    (void)hWnd;
    return FALSE;
}

BOOL WINAPI KillTimer(HWND hWnd, UINT uIDEvent) {
    (void)hWnd;
    (void)uIDEvent;
    return TRUE;
}

HACCEL WINAPI LoadAccelerators(HINSTANCE hInstance, LPCSTR lpTableName) {
    (void)hInstance;
    (void)lpTableName;
    return 0;
}

HBITMAP WINAPI LoadBitmap(HINSTANCE hInstance, LPCSTR lpBitmapName) {
    (void)hInstance;
    (void)lpBitmapName;
    return 0;
}

HCURSOR WINAPI LoadCursor(HINSTANCE hInstance, LPCSTR lpCursorName) {
    (void)hInstance;
    (void)lpCursorName;
    return (HCURSOR)(uintptr_t)1;
}

HICON WINAPI LoadIcon(HINSTANCE hInstance, LPCSTR lpIconName) {
    (void)hInstance;
    (void)lpIconName;
    return (HICON)(uintptr_t)1;
}

void WINAPI MapWindowPoints(HWND hWndFrom, HWND hWndTo, POINT FAR *lpPoints, UINT cPoints) {
    (void)hWndFrom;
    (void)hWndTo;
    (void)lpPoints;
    (void)cPoints;
}

void WINAPI MessageBeep(UINT uType) { (void)uType; }

int WINAPI MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    (void)hWnd;
    (void)uType;
    fprintf(stderr, "MessageBox [%s]: %s\n", lpCaption ? lpCaption : "", lpText ? lpText : "");
    return IDOK;
}

BOOL WINAPI MoveWindow(HWND hWnd, int x, int y, int nWidth, int nHeight, BOOL bRepaint) {
    (void)hWnd;
    (void)x;
    (void)y;
    (void)nWidth;
    (void)nHeight;
    (void)bRepaint;
    return TRUE;
}

void WINAPI OffsetRect(RECT FAR *lprc, int dx, int dy) {
    if (lprc) {
        lprc->left += dx;
        lprc->top += dy;
        lprc->right += dx;
        lprc->bottom += dy;
    }
}

BOOL WINAPI PeekMessage(MSG FAR *lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg) {
    (void)lpMsg;
    (void)hWnd;
    (void)wMsgFilterMin;
    (void)wMsgFilterMax;
    (void)wRemoveMsg;
    return FALSE;
}

BOOL WINAPI PostMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    (void)hWnd;
    (void)Msg;
    (void)wParam;
    (void)lParam;
    return TRUE;
}

void WINAPI PostQuitMessage(int nExitCode) { (void)nExitCode; }

BOOL WINAPI PtInRect(const RECT FAR *lprc, POINT pt) {
    if (!lprc)
        return FALSE;
    return (pt.x >= lprc->left && pt.x < lprc->right && pt.y >= lprc->top && pt.y < lprc->bottom);
}

UINT WINAPI RealizePalette(HDC hdc) {
    (void)hdc;
    return 0;
}

ATOM WINAPI RegisterClass(const WNDCLASS FAR *lpWndClass) {
    (void)lpWndClass;
    return 1;
}

void WINAPI ReleaseCapture(void) {}

int WINAPI ReleaseDC(HWND hWnd, HDC hDC) {
    (void)hWnd;
    (void)hDC;
    return 1;
}

void WINAPI ScreenToClient(HWND hWnd, POINT FAR *lpPoint) {
    (void)hWnd;
    (void)lpPoint;
}

void WINAPI ScrollWindow(HWND hWnd, int dx, int dy, const RECT FAR *lpRect, const RECT FAR *lpClipRect) {
    (void)hWnd;
    (void)dx;
    (void)dy;
    (void)lpRect;
    (void)lpClipRect;
}

HPALETTE WINAPI SelectPalette(HDC hdc, HPALETTE hPal, BOOL bForceBkgd) {
    (void)hdc;
    (void)hPal;
    (void)bForceBkgd;
    return 0;
}

LRESULT WINAPI SendDlgItemMessage(HWND hDlg, int nIDDlgItem, UINT Msg, WPARAM wParam, LPARAM lParam) {
    (void)hDlg;
    (void)nIDDlgItem;
    (void)Msg;
    (void)wParam;
    (void)lParam;
    return 0;
}

LRESULT WINAPI SendMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    (void)hWnd;
    (void)Msg;
    (void)wParam;
    (void)lParam;
    return 0;
}

HWND WINAPI SetCapture(HWND hWnd) {
    (void)hWnd;
    return 0;
}

HCURSOR WINAPI SetCursor(HCURSOR hCursor) {
    (void)hCursor;
    return 0;
}

void WINAPI SetDlgItemText(HWND hDlg, int nIDDlgItem, LPCSTR lpString) {
    (void)hDlg;
    (void)nIDDlgItem;
    (void)lpString;
}

HWND WINAPI SetFocus(HWND hWnd) {
    (void)hWnd;
    return 0;
}

void WINAPI SetRect(RECT FAR *lprc, int xLeft, int yTop, int xRight, int yBottom) {
    if (lprc) {
        lprc->left = xLeft;
        lprc->top = yTop;
        lprc->right = xRight;
        lprc->bottom = yBottom;
    }
}

int WINAPI SetScrollPos(HWND hWnd, int nBar, int nPos, BOOL bRedraw) {
    (void)hWnd;
    (void)nBar;
    (void)nPos;
    (void)bRedraw;
    return 0;
}

void WINAPI SetScrollRange(HWND hWnd, int nBar, int nMinPos, int nMaxPos, BOOL bRedraw) {
    (void)hWnd;
    (void)nBar;
    (void)nMinPos;
    (void)nMaxPos;
    (void)bRedraw;
}

UINT WINAPI SetTimer(HWND hWnd, UINT nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc) {
    (void)hWnd;
    (void)uElapse;
    (void)lpTimerFunc;
    return nIDEvent;
}

LONG WINAPI SetWindowLong(HWND hWnd, int nIndex, LONG dwNewLong) {
    (void)hWnd;
    (void)nIndex;
    (void)dwNewLong;
    return 0;
}

BOOL WINAPI SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int x, int y, int cx, int cy, UINT uFlags) {
    (void)hWnd;
    (void)hWndInsertAfter;
    (void)x;
    (void)y;
    (void)cx;
    (void)cy;
    (void)uFlags;
    return TRUE;
}

void WINAPI SetWindowText(HWND hWnd, LPCSTR lpString) {
    (void)hWnd;
    (void)lpString;
}

BOOL WINAPI ShowWindow(HWND hWnd, int nCmdShow) {
    (void)hWnd;
    (void)nCmdShow;
    return FALSE;
}

BOOL WINAPI TrackPopupMenu(HMENU hMenu, UINT uFlags, int x, int y, int nReserved, HWND hWnd, const RECT FAR *prcRect) {
    (void)hMenu;
    (void)uFlags;
    (void)x;
    (void)y;
    (void)nReserved;
    (void)hWnd;
    (void)prcRect;
    return FALSE;
}

int WINAPI TranslateAccelerator(HWND hWnd, HACCEL hAccTable, MSG FAR *lpMsg) {
    (void)hWnd;
    (void)hAccTable;
    (void)lpMsg;
    return 0;
}

BOOL WINAPI TranslateMessage(const MSG FAR *lpMsg) {
    (void)lpMsg;
    return FALSE;
}

void WINAPI UpdateWindow(HWND hWnd) { (void)hWnd; }

void WINAPI ValidateRect(HWND hWnd, const RECT FAR *lpRect) {
    (void)hWnd;
    (void)lpRect;
}

HWND WINAPI WindowFromPoint(POINT pt) {
    (void)pt;
    return 0;
}

BOOL WINAPI WinHelp(HWND hWndMain, LPCSTR lpszHelp, UINT uCommand, DWORD dwData) {
    (void)hWndMain;
    (void)lpszHelp;
    (void)uCommand;
    (void)dwData;
    return FALSE;
}

/* ---- Added for ini/serial work (menu/string stubs) ---- */
UINT WINAPI GetMenuItemID(HMENU hMenu, int nPos) {
    (void)hMenu;
    (void)nPos;
    return (UINT)-1;
}

LPSTR WINAPI lstrcpynA(LPSTR dst, LPCSTR src, int maxLen) {
    int i;
    if (!dst || maxLen <= 0)
        return dst;
    if (!src) {
        dst[0] = '\0';
        return dst;
    }
    for (i = 0; i < maxLen - 1 && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
    return dst;
}

BOOL WINAPI CheckMenuRadioItem(HMENU hMenu, UINT idFirst, UINT idLast, UINT idCheck, UINT uFlags) {
    (void)hMenu;
    (void)idFirst;
    (void)idLast;
    (void)idCheck;
    (void)uFlags;
    return TRUE;
}

int localtime_s(struct tm *result, const time_t *timep) {
    if (!result || !timep) {
        return 1;
    }
    /* localtime_r is the POSIX thread-safe equivalent. */
    if (localtime_r(timep, result) == NULL) {
        memset(result, 0, sizeof(*result));
        return 1;
    }
    return 0;
}

LPARAM MAKELPARAM(WORD lo, WORD hi) { return (LPARAM)(((DWORD)lo) | (((DWORD)hi) << 16)); }

#endif /* !_WIN32 || STARS_USE_WIN_STUBS */
