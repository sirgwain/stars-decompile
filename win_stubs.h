/*
 * win_stubs.h - Windows API stubs for non-Windows builds
 *
 * These definitions allow Stars! code to compile on Linux/macOS.
 * They provide type definitions and stub function declarations
 * for Win16/Win32 API calls used in the codebase.
 *
 * DO NOT rely on these for actual functionality - they exist only
 * to allow compilation and testing of non-UI game logic.
 */

#ifndef WIN_STUBS_H
#define WIN_STUBS_H

#include <stdint.h>

/* ========================================================================
 * Basic Windows Types
 * ======================================================================== */

/*
 * Handle types
 *
 * For the purposes of the portable (non-Windows) build we model Win32 handle
 * types as opaque pointers. This helps catch signature/type mismatches earlier
 * when the real target is Win32.
 */
typedef void *HANDLE;
typedef HANDLE HWND;
typedef HANDLE HDC;
typedef HANDLE HMENU;
typedef HANDLE HINSTANCE;
typedef HANDLE HMODULE;
typedef HANDLE HICON;
typedef HANDLE HCURSOR;
typedef HANDLE HBITMAP;
typedef HANDLE HBRUSH;
typedef HANDLE HPEN;
typedef HANDLE HFONT;
typedef HANDLE HPALETTE;
typedef HANDLE HRGN;
typedef HANDLE HGLOBAL;
typedef HANDLE HLOCAL;
typedef HANDLE HRSRC;
typedef HANDLE HACCEL;
typedef HANDLE HGDIOBJ;
typedef int HFILE;

/* Pointer types */
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef void *LPVOID;
typedef const void *LPCVOID;

/* Resource identifier helpers (Win32-style).
 * Many legacy Win16 APIs accept either a pointer to a string or a small
 * integer ID encoded as a pointer.
 */
#ifndef MAKEINTRESOURCE
#define MAKEINTRESOURCE(i) ((LPCSTR)(uintptr_t)(uint16_t)(i))
#endif

/* Common predefined resource types (subset). */
#ifndef RT_BITMAP
#define RT_CURSOR MAKEINTRESOURCE(1)
#define RT_BITMAP MAKEINTRESOURCE(2)
#define RT_ICON MAKEINTRESOURCE(3)
#define RT_MENU MAKEINTRESOURCE(4)
#define RT_DIALOG MAKEINTRESOURCE(5)
#define RT_STRING MAKEINTRESOURCE(6)
#define RT_RCDATA MAKEINTRESOURCE(10)
#endif

/* Integer types */
typedef int BOOL;
typedef unsigned char BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int16_t SHORT;
typedef int32_t LONG;
typedef unsigned int UINT;
typedef int INT;
typedef uint16_t ATOM;

/* Pointer-sized integer types (Win32 compatibility) */
typedef intptr_t INT_PTR;
typedef uintptr_t UINT_PTR;
typedef intptr_t LONG_PTR;
typedef uintptr_t ULONG_PTR;

/* Windows message parameter/result types (Win32-style widths) */
typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef LONG_PTR LRESULT;
typedef DWORD COLORREF;

/* VOID is just void */
#define VOID void

/* Function pointer types */
typedef LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef INT (*DLGPROC)(HWND, UINT, WPARAM, LPARAM);
typedef void (*TIMERPROC)(HWND, UINT, UINT, DWORD);
typedef int (*FARPROC)(void);

/* FAR/NEAR pointer modifiers (no-op on modern systems) */
#define FAR
#define NEAR
#define PASCAL
#define WINAPI
#define CALLBACK
#define _huge

/* Calling convention tokens used in some Win16-era signatures.
 * On non-Windows hosts they must be defined as no-ops so the code parses.
 */
#ifndef __cdecl
#define __cdecl
#endif

/* Boolean constants */
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* Null handle values */
#define NULL_HANDLE ((HANDLE)0)

/* ========================================================================
 * MessageBox Flags
 * ======================================================================== */
typedef enum MBFlags
{
    MB_OK = 0x0000,
    MB_OKCANCEL = 0x0001,
    MB_ABORTRETRYIGNORE = 0x0002,
    MB_YESNOCANCEL = 0x0003,
    MB_YESNO = 0x0004,
    MB_RETRYCANCEL = 0x0005,
    MB_ICONHAND = 0x0010,
    MB_ICONQUESTION = 0x0020,
    MB_ICONEXCLAMATION = 0x0030,
    MB_ICONASTERISK = 0x0040,
    MB_ICONERROR = MB_ICONHAND,
    MB_ICONWARNING = MB_ICONEXCLAMATION,
    MB_ICONINFORMATION = MB_ICONASTERISK,
    MB_DEFBUTTON1 = 0x0000,
    MB_DEFBUTTON2 = 0x0100,
    MB_DEFBUTTON3 = 0x0200,
} MBFlags;

/* MessageBox return values */
#define IDOK 1
#define IDCANCEL 2
#define IDABORT 3
#define IDRETRY 4
#define IDIGNORE 5
#define IDYES 6
#define IDNO 7

/* ========================================================================
 * Structures
 * ======================================================================== */

/* POINT - 2D point.
 * NOTE: Many Stars! structs and file formats assume 16-bit point fields.
 * Keep this Win16-style even when stubbing Win32 builds so non-UI logic
 * and tests remain stable.
 */
typedef struct tagPOINT
{
    int16_t x;
    int16_t y;
} POINT;

/* RECT - Win16-style (see note on POINT above). */
typedef struct tagRECT
{
    int16_t left;
    int16_t top;
    int16_t right;
    int16_t bottom;
} RECT;

/* SIZE - used by GetTextExtentPoint* */
typedef struct tagSIZE
{
    LONG cx;
    LONG cy;
} SIZE;
typedef SIZE *LPSIZE;

/* MSG - Windows message */
typedef struct tagMSG
{
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
} MSG;
typedef MSG *LPMSG;

/* PAINTSTRUCT - for BeginPaint/EndPaint */
typedef struct tagPAINTSTRUCT
{
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    BYTE rgbReserved[16];
} PAINTSTRUCT;

/* LOGFONT - logical font definition */
typedef struct tagLOGFONT
{
    LONG lfHeight;
    LONG lfWidth;
    LONG lfEscapement;
    LONG lfOrientation;
    LONG lfWeight;
    BYTE lfItalic;
    BYTE lfUnderline;
    BYTE lfStrikeOut;
    BYTE lfCharSet;
    BYTE lfOutPrecision;
    BYTE lfClipPrecision;
    BYTE lfQuality;
    BYTE lfPitchAndFamily;
    char lfFaceName[32];
} LOGFONT;

/* TEXTMETRIC - text metrics */
typedef struct tagTEXTMETRIC
{
    LONG tmHeight;
    LONG tmAscent;
    LONG tmDescent;
    LONG tmInternalLeading;
    LONG tmExternalLeading;
    LONG tmAveCharWidth;
    LONG tmMaxCharWidth;
    LONG tmWeight;
    BYTE tmItalic;
    BYTE tmUnderlined;
    BYTE tmStruckOut;
    BYTE tmFirstChar;
    BYTE tmLastChar;
    BYTE tmDefaultChar;
    BYTE tmBreakChar;
    BYTE tmPitchAndFamily;
    BYTE tmCharSet;
    LONG tmOverhang;
    LONG tmDigitizedAspectX;
    LONG tmDigitizedAspectY;
} TEXTMETRIC;

/* WNDCLASS - window class registration */
typedef struct tagWNDCLASS
{
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCSTR lpszMenuName;
    LPCSTR lpszClassName;
} WNDCLASS;

/* WINDOWPLACEMENT - window position info */
typedef struct tagWINDOWPLACEMENT
{
    UINT length;
    UINT flags;
    UINT showCmd;
    POINT ptMinPosition;
    POINT ptMaxPosition;
    RECT rcNormalPosition;
} WINDOWPLACEMENT;

/* DRAWITEMSTRUCT - owner-draw item info */
typedef struct tagDRAWITEMSTRUCT
{
    UINT CtlType;
    UINT CtlID;
    UINT itemID;
    UINT itemAction;
    UINT itemState;
    HWND hwndItem;
    HDC hDC;
    RECT rcItem;
    DWORD itemData;
} DRAWITEMSTRUCT;

/* Owner-draw item state flags */
#define ODS_SELECTED 0x0001
#define ODS_GRAYED 0x0002
#define ODS_DISABLED 0x0004
#define ODS_CHECKED 0x0008
#define ODS_FOCUS 0x0010

/* MEASUREITEMSTRUCT - measure owner-draw item */
typedef struct tagMEASUREITEMSTRUCT
{
    UINT CtlType;
    UINT CtlID;
    UINT itemID;
    UINT itemWidth;
    UINT itemHeight;
    DWORD itemData;
} MEASUREITEMSTRUCT;

/* OPENFILENAME - common file dialog */
typedef struct tagOPENFILENAME
{
    DWORD lStructSize;
    HWND hwndOwner;
    HINSTANCE hInstance;
    LPCSTR lpstrFilter;
    LPSTR lpstrCustomFilter;
    DWORD nMaxCustFilter;
    DWORD nFilterIndex;
    LPSTR lpstrFile;
    DWORD nMaxFile;
    LPSTR lpstrFileTitle;
    DWORD nMaxFileTitle;
    LPCSTR lpstrInitialDir;
    LPCSTR lpstrTitle;
    DWORD Flags;
    WORD nFileOffset;
    WORD nFileExtension;
    LPCSTR lpstrDefExt;
    LPARAM lCustData;
    void *lpfnHook;
    LPCSTR lpTemplateName;
} OPENFILENAME;
typedef OPENFILENAME OFN;

/* PRINTDLG - print dialog */
typedef struct tagPD
{
    DWORD lStructSize;
    HWND hwndOwner;
    HANDLE hDevMode;
    HANDLE hDevNames;
    HDC hDC;
    DWORD Flags;
    WORD nFromPage;
    WORD nToPage;
    WORD nMinPage;
    WORD nMaxPage;
    WORD nCopies;
    HINSTANCE hInstance;
    LPARAM lCustData;
    void *lpfnPrintHook;
    void *lpfnSetupHook;
    LPCSTR lpPrintTemplateName;
    LPCSTR lpSetupTemplateName;
    HANDLE hPrintTemplate;
    HANDLE hSetupTemplate;
} PRINTDLG;
typedef PRINTDLG PD;

/* BITMAP - bitmap info */
typedef struct tagBITMAP
{
    LONG bmType;
    LONG bmWidth;
    LONG bmHeight;
    LONG bmWidthBytes;
    WORD bmPlanes;
    WORD bmBitsPixel;
    LPVOID bmBits;
} BITMAP;

/* BITMAPINFOHEADER */
typedef struct tagBITMAPINFOHEADER
{
    DWORD biSize;
    LONG biWidth;
    LONG biHeight;
    WORD biPlanes;
    WORD biBitCount;
    DWORD biCompression;
    DWORD biSizeImage;
    LONG biXPelsPerMeter;
    LONG biYPelsPerMeter;
    DWORD biClrUsed;
    DWORD biClrImportant;
} BITMAPINFOHEADER;

/* RGBQUAD */
typedef struct tagRGBQUAD
{
    BYTE rgbBlue;
    BYTE rgbGreen;
    BYTE rgbRed;
    BYTE rgbReserved;
} RGBQUAD;

/* BITMAPINFO */
typedef struct tagBITMAPINFO
{
    BITMAPINFOHEADER bmiHeader;
    RGBQUAD bmiColors[1];
} BITMAPINFO;

/* BITMAPCOREHEADER */
typedef struct tagBITMAPCOREHEADER
{
    DWORD bcSize;
    WORD bcWidth;
    WORD bcHeight;
    WORD bcPlanes;
    WORD bcBitCount;
} BITMAPCOREHEADER;

/* LOGPALETTE */
typedef struct tagPALETTEENTRY
{
    BYTE peRed;
    BYTE peGreen;
    BYTE peBlue;
    BYTE peFlags;
} PALETTEENTRY;

typedef struct tagLOGPALETTE
{
    WORD palVersion;
    WORD palNumEntries;
    PALETTEENTRY palPalEntry[1];
} LOGPALETTE;

/* OFSTRUCT - OpenFile structure */
typedef struct tagOFSTRUCT
{
    BYTE cBytes;
    BYTE fFixedDisk;
    WORD nErrCode;
    WORD Reserved1;
    WORD Reserved2;
    char szPathName[128];
} OFSTRUCT;

/* TIMERINFO - for TimerCount (TOOLHELP) */
typedef struct tagTIMERINFO
{
    DWORD dwSize;
    DWORD dwmsSinceStart;
    DWORD dwmsThisVM;
} TIMERINFO;

/* ========================================================================
 * Window Style Constants
 * ======================================================================== */
#define WS_OVERLAPPED 0x00000000L
#define WS_POPUP 0x80000000L
#define WS_CHILD 0x40000000L
#define WS_VISIBLE 0x10000000L
#define WS_DISABLED 0x08000000L
#define WS_CAPTION 0x00C00000L
#define WS_BORDER 0x00800000L
#define WS_SYSMENU 0x00080000L

/* GetWindow() constants */
#define GW_HWNDFIRST 0
#define GW_HWNDLAST 1
#define GW_HWNDNEXT 2
#define GW_HWNDPREV 3
#define GW_OWNER 4
#define GW_CHILD 5

/* Get/SetWindowLong indices */
#define GWL_WNDPROC (-4)
#define GWL_HINSTANCE (-6)
#define GWL_HWNDPARENT (-8)
#define GWL_STYLE (-16)
#define GWL_EXSTYLE (-20)
#define GWL_USERDATA (-21)
#define GWL_ID (-12)

/* ShowWindow() commands */
#define SW_HIDE 0
#define SW_SHOWNORMAL 1
#define SW_NORMAL 1
#define SW_SHOWMINIMIZED 2
#define SW_SHOWMAXIMIZED 3
#define SW_MAXIMIZE 3
#define SW_SHOWNOACTIVATE 4
#define SW_SHOW 5
#define SW_MINIMIZE 6
#define SW_SHOWMINNOACTIVE 7
#define SW_SHOWNA 8
#define SW_RESTORE 9

/* SetWindowPos() flags */
#define SWP_NOSIZE 0x0001
#define SWP_NOMOVE 0x0002
#define SWP_NOZORDER 0x0004
#define SWP_NOREDRAW 0x0008
#define SWP_NOACTIVATE 0x0010
#define SWP_SHOWWINDOW 0x0040
#define SWP_HIDEWINDOW 0x0080

/* HWND special values */
#define HWND_TOP ((HWND)0)
#define HWND_BOTTOM ((HWND)1)
#define HWND_TOPMOST ((HWND)-1)
#define HWND_NOTOPMOST ((HWND)-2)

/* ========================================================================
 * Message Constants
 * ======================================================================== */
#define WM_NULL 0x0000
#define WM_CREATE 0x0001
#define WM_DESTROY 0x0002
#define WM_MOVE 0x0003
#define WM_SIZE 0x0005
#define WM_ACTIVATE 0x0006
#define WM_SETFOCUS 0x0007
#define WM_KILLFOCUS 0x0008
#define WM_ENABLE 0x000A
#define WM_PAINT 0x000F
#define WM_CLOSE 0x0010
#define WM_QUIT 0x0012
#define WM_ERASEBKGND 0x0014
#define WM_SHOWWINDOW 0x0018
#define WM_SETCURSOR 0x0020
#define WM_KEYDOWN 0x0100
#define WM_KEYUP 0x0101
#define WM_CHAR 0x0102
#define WM_COMMAND 0x0111
#define WM_TIMER 0x0113
#define WM_HSCROLL 0x0114
#define WM_VSCROLL 0x0115
#define WM_MOUSEMOVE 0x0200
#define WM_LBUTTONDOWN 0x0201
#define WM_LBUTTONUP 0x0202
#define WM_LBUTTONDBLCLK 0x0203
#define WM_RBUTTONDOWN 0x0204
#define WM_RBUTTONUP 0x0205
#define WM_RBUTTONDBLCLK 0x0206
#define WM_USER 0x0400

/* ========================================================================
 * GDI Constants
 * ======================================================================== */

/* Stock objects */
#define WHITE_BRUSH 0
#define LTGRAY_BRUSH 1
#define GRAY_BRUSH 2
#define DKGRAY_BRUSH 3
#define BLACK_BRUSH 4
#define NULL_BRUSH 5
#define HOLLOW_BRUSH NULL_BRUSH
#define WHITE_PEN 6
#define BLACK_PEN 7
#define NULL_PEN 8
#define SYSTEM_FONT 13
#define SYSTEM_FIXED_FONT 16

/* Background modes */
#define TRANSPARENT 1
#define OPAQUE 2

/* Raster operations */
#define SRCCOPY 0x00CC0020
#define SRCPAINT 0x00EE0086
#define SRCAND 0x008800C6
#define SRCINVERT 0x00660046
#define SRCERASE 0x00440328
#define NOTSRCCOPY 0x00330008
#define NOTSRCERASE 0x001100A6
#define MERGECOPY 0x00C000CA
#define MERGEPAINT 0x00BB0226
#define PATCOPY 0x00F00021
#define PATPAINT 0x00FB0A09
#define PATINVERT 0x005A0049
#define DSTINVERT 0x00550009
#define BLACKNESS 0x00000042
#define WHITENESS 0x00FF0062

/* ROP2 modes */
#define R2_BLACK 1
#define R2_NOTMERGEPEN 2
#define R2_MASKNOTPEN 3
#define R2_NOTCOPYPEN 4
#define R2_MASKPENNOT 5
#define R2_NOT 6
#define R2_XORPEN 7
#define R2_NOTMASKPEN 8
#define R2_MASKPEN 9
#define R2_NOTXORPEN 10
#define R2_NOP 11
#define R2_MERGENOTPEN 12
#define R2_COPYPEN 13
#define R2_MERGEPENNOT 14
#define R2_MERGEPEN 15
#define R2_WHITE 16

/* Pen styles */
#define PS_SOLID 0
#define PS_DASH 1
#define PS_DOT 2
#define PS_DASHDOT 3
#define PS_DASHDOTDOT 4
#define PS_NULL 5
#define PS_INSIDEFRAME 6

/* Device capabilities */
#define HORZRES 8
#define VERTRES 10
#define BITSPIXEL 12
#define PLANES 14
#define NUMCOLORS 24
#define LOGPIXELSX 88
#define LOGPIXELSY 90

/* DIB color modes */
#define DIB_RGB_COLORS 0
#define DIB_PAL_COLORS 1

/* ========================================================================
 * File I/O Constants
 * ======================================================================== */
#define HFILE_ERROR ((HFILE)-1)
#define OF_READ 0x0000
#define OF_WRITE 0x0001
#define OF_READWRITE 0x0002
#define OF_CREATE 0x1000

/* ========================================================================
 * Memory Allocation Constants
 * ======================================================================== */
#define GMEM_FIXED 0x0000
#define GMEM_MOVEABLE 0x0002
#define GMEM_ZEROINIT 0x0040
#define GPTR (GMEM_FIXED | GMEM_ZEROINIT)
#define GHND (GMEM_MOVEABLE | GMEM_ZEROINIT)

#define LMEM_FIXED 0x0000
#define LMEM_MOVEABLE 0x0002
#define LMEM_ZEROINIT 0x0040
#define LPTR (LMEM_FIXED | LMEM_ZEROINIT)

/* ========================================================================
 * Menu Constants
 * ======================================================================== */
#define MF_STRING 0x0000
#define MF_ENABLED 0x0000
#define MF_GRAYED 0x0001
#define MF_DISABLED 0x0002
#define MF_CHECKED 0x0008
#define MF_POPUP 0x0010
#define MF_SEPARATOR 0x0800
#define MF_BYCOMMAND 0x0000
#define MF_BYPOSITION 0x0400

/* ========================================================================
 * Scroll Bar Constants
 * ======================================================================== */
#define SB_HORZ 0
#define SB_VERT 1
#define SB_CTL 2
#define SB_BOTH 3

/* ========================================================================
 * Virtual Key Codes
 * ======================================================================== */
#define VK_LBUTTON 0x01
#define VK_RBUTTON 0x02
#define VK_CANCEL 0x03
#define VK_BACK 0x08
#define VK_TAB 0x09
#define VK_RETURN 0x0D
#define VK_SHIFT 0x10
#define VK_CONTROL 0x11
#define VK_MENU 0x12
#define VK_ESCAPE 0x1B
#define VK_SPACE 0x20
#define VK_LEFT 0x25
#define VK_UP 0x26
#define VK_RIGHT 0x27
#define VK_DOWN 0x28
#define VK_DELETE 0x2E
#define VK_F1 0x70
#define VK_F2 0x71
#define VK_F3 0x72
#define VK_F4 0x73
#define VK_F5 0x74
#define VK_F6 0x75
#define VK_F7 0x76
#define VK_F8 0x77
#define VK_F9 0x78
#define VK_F10 0x79
#define VK_F11 0x7A
#define VK_F12 0x7B

/* ========================================================================
 * System Metrics
 * ======================================================================== */
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define SM_CXVSCROLL 2
#define SM_CYHSCROLL 3
#define SM_CXBORDER 5
#define SM_CYBORDER 6
#define SM_CXICON 11
#define SM_CYICON 12

/* ========================================================================
 * WinHelp Commands
 * ======================================================================== */
#define HELP_CONTEXT 0x0001
#define HELP_QUIT 0x0002
#define HELP_INDEX 0x0003
#define HELP_CONTENTS 0x0003
#define HELP_HELPONHELP 0x0004
#define HELP_SETINDEX 0x0005

/* ========================================================================
 * Escape Codes (for Escape() GDI function)
 * ======================================================================== */
#define NEWFRAME 1
#define ABORTDOC 2
#define NEXTBAND 3
#define SETCOLORTABLE 4
#define GETCOLORTABLE 5
#define FLUSHOUTPUT 6
#define DRAFTMODE 7
#define QUERYESCSUPPORT 8
#define SETABORTPROC 9
#define STARTDOC 10
#define ENDDOC 11
#define GETPHYSPAGESIZE 12
#define GETPRINTINGOFFSET 13
#define GETSCALINGFACTOR 14

/* ========================================================================
 * Stub Function Declarations
 *
 * All functions return appropriate default values (0, NULL, FALSE, etc.)
 * ======================================================================== */

/* ----- COMMDLG ----- */
BOOL WINAPI GetOpenFileName(OPENFILENAME FAR *lpofn);
BOOL WINAPI GetSaveFileName(OPENFILENAME FAR *lpofn);
BOOL WINAPI PrintDlg(PRINTDLG FAR *lppd);

/* ----- GDI ----- */
BOOL WINAPI BitBlt(HDC hdcDest, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);
HBITMAP WINAPI CreateCompatibleBitmap(HDC hdc, int cx, int cy);
HDC WINAPI CreateCompatibleDC(HDC hdc);
HFONT WINAPI CreateFontIndirect(const LOGFONT FAR *lplf);
HPALETTE WINAPI CreatePalette(const LOGPALETTE FAR *lplgpl);
HBRUSH WINAPI CreatePatternBrush(HBITMAP hbm);
HPEN WINAPI CreatePen(int iStyle, int cWidth, COLORREF color);
HRGN WINAPI CreateRectRgn(int x1, int y1, int x2, int y2);
HBRUSH WINAPI CreateSolidBrush(COLORREF color);
BOOL WINAPI DeleteDC(HDC hdc);
BOOL WINAPI DeleteObject(HGDIOBJ ho);
BOOL WINAPI Ellipse(HDC hdc, int left, int top, int right, int bottom);
int WINAPI Escape(HDC hdc, int iEscape, int cjIn, LPCSTR lpIn, void FAR *lpOut);
int WINAPI ExcludeClipRect(HDC hdc, int left, int top, int right, int bottom);
BOOL WINAPI ExtTextOut(HDC hdc, int x, int y, UINT options, const RECT FAR *lprect, LPCSTR lpString, UINT c, int FAR *lpDx);
COLORREF WINAPI GetBkColor(HDC hdc);
int WINAPI GetDeviceCaps(HDC hdc, int index);
int WINAPI GetDIBits(HDC hdc, HBITMAP hbm, UINT start, UINT cLines, void FAR *lpvBits, BITMAPINFO FAR *lpbmi, UINT usage);
int WINAPI GetObject(HGDIOBJ h, int c, void FAR *pv);
int WINAPI GetROP2(HDC hdc);
HGDIOBJ WINAPI GetStockObject(int i);
DWORD WINAPI GetTextExtent(HDC hdc, LPCSTR lpString, int c);
/* Win32 API variant; useful for the Win32 port. */
BOOL WINAPI GetTextExtentPoint32A(HDC hdc, LPCSTR lpString, int c, LPSIZE lpSize);
/* Another common Win32 name used by some call sites. */
BOOL WINAPI GetTextExtentPointA(HDC hdc, LPCSTR lpString, int c, LPSIZE lpSize);
BOOL WINAPI GetTextMetrics(HDC hdc, TEXTMETRIC FAR *lptm);
int WINAPI IntersectClipRect(HDC hdc, int left, int top, int right, int bottom);
BOOL WINAPI LineTo(HDC hdc, int x, int y);
DWORD WINAPI MoveTo(HDC hdc, int x, int y);
int WINAPI MulDiv(int nNumber, int nNumerator, int nDenominator);
BOOL WINAPI PatBlt(HDC hdc, int x, int y, int w, int h, DWORD rop);
BOOL WINAPI Rectangle(HDC hdc, int left, int top, int right, int bottom);
int WINAPI SelectClipRgn(HDC hdc, HRGN hrgn);
HGDIOBJ WINAPI SelectObject(HDC hdc, HGDIOBJ h);
COLORREF WINAPI SetBkColor(HDC hdc, COLORREF color);
int WINAPI SetBkMode(HDC hdc, int mode);
DWORD WINAPI SetBrushOrg(HDC hdc, int x, int y);
COLORREF WINAPI SetPixel(HDC hdc, int x, int y, COLORREF color);
int WINAPI SetROP2(HDC hdc, int rop2);
COLORREF WINAPI SetTextColor(HDC hdc, COLORREF color);
DWORD WINAPI SetWindowOrg(HDC hdc, int x, int y);
int WINAPI StretchDIBits(HDC hdc, int xDest, int yDest, int DestWidth, int DestHeight,
                         int xSrc, int ySrc, int SrcWidth, int SrcHeight,
                         const void FAR *lpBits, const BITMAPINFO FAR *lpbmi, UINT iUsage, DWORD rop);
BOOL WINAPI TextOut(HDC hdc, int x, int y, LPCSTR lpString, int c);
BOOL WINAPI TextOutA(HDC hdc, int x, int y, LPCSTR lpString, int c);
BOOL WINAPI UnrealizeObject(HGDIOBJ h);

/* ----- KERNEL ----- */
HFILE WINAPI _lclose(HFILE hFile);
UINT WINAPI _lread(HFILE hFile, void FAR *lpBuffer, UINT uBytes);
UINT WINAPI _lwrite(HFILE hFile, const void FAR *lpBuffer, UINT uBytes);
int WINAPI AccessResource(HINSTANCE hInstance, HRSRC hResInfo);
HGLOBAL WINAPI AllocResource(HINSTANCE hInstance, HRSRC hResInfo, DWORD dwSize);
void WINAPI FatalAppExit(UINT uAction, LPCSTR lpMessageText);
void WINAPI FatalExit(int code);
HRSRC WINAPI FindResource(HINSTANCE hInstance, LPCSTR lpName, LPCSTR lpType);
void WINAPI FreeProcInstance(FARPROC lpProc);
BOOL WINAPI FreeResource(HGLOBAL hResData);
LPSTR WINAPI GetDOSEnvironment(void);
UINT WINAPI GetDriveType(int nDrive);
int WINAPI GetModuleFileName(HINSTANCE hInstance, LPSTR lpFilename, int nSize);
UINT WINAPI GetPrivateProfileInt(LPCSTR lpAppName, LPCSTR lpKeyName, int nDefault, LPCSTR lpFileName);
int WINAPI GetPrivateProfileString(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault, LPSTR lpReturnedString, int nSize, LPCSTR lpFileName);
DWORD WINAPI GetVersion(void);
HGLOBAL WINAPI GlobalAlloc(UINT uFlags, DWORD dwBytes);
HGLOBAL WINAPI GlobalFree(HGLOBAL hMem);
void FAR *WINAPI GlobalLock(HGLOBAL hMem);
HGLOBAL WINAPI GlobalReAlloc(HGLOBAL hMem, DWORD dwBytes, UINT uFlags);
DWORD WINAPI GlobalSize(HGLOBAL hMem);
BOOL WINAPI GlobalUnlock(HGLOBAL hMem);
HGLOBAL WINAPI LoadResource(HINSTANCE hInstance, HRSRC hResInfo);
HLOCAL WINAPI LocalAlloc(UINT uFlags, UINT uBytes);
HLOCAL WINAPI LocalFree(HLOCAL hMem);
HLOCAL WINAPI LocalReAlloc(HLOCAL hMem, UINT uBytes, UINT uFlags);
UINT WINAPI LocalSize(HLOCAL hMem);
void FAR *WINAPI LockResource(HGLOBAL hResData);
HGLOBAL WINAPI LockSegment(UINT wSegment);
LPSTR WINAPI lstrcat(LPSTR lpString1, LPCSTR lpString2);
LPSTR WINAPI lstrcpy(LPSTR lpString1, LPCSTR lpString2);
int WINAPI lstrlen(LPCSTR lpString);
/* Win32 ANSI-suffixed variants sometimes appear in ported codepaths. */
int WINAPI lstrlenA(LPCSTR lpString);
FARPROC WINAPI MakeProcInstance(FARPROC lpProc, HINSTANCE hInstance);
HFILE WINAPI OpenFile(LPCSTR lpFileName, OFSTRUCT FAR *lpReOpenBuff, UINT uStyle);
DWORD WINAPI SizeofResource(HINSTANCE hInstance, HRSRC hResInfo);
void WINAPI UnlockSegment(UINT wSegment);
BOOL WINAPI WritePrivateProfileString(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName);
void WINAPI Yield(void);

/* ----- TOOLHELP ----- */
BOOL WINAPI TimerCount(TIMERINFO FAR *lpti);

/* ----- USER ----- */
int FAR __cdecl wsprintf(LPSTR lpOut, LPCSTR lpFmt, ...);
BOOL WINAPI AppendMenu(HMENU hMenu, UINT uFlags, UINT uIDNewItem, LPCSTR lpNewItem);
HDC WINAPI BeginPaint(HWND hWnd, PAINTSTRUCT FAR *lpPaint);
LRESULT WINAPI CallWindowProc(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
void WINAPI CheckDlgButton(HWND hDlg, int nIDButton, UINT uCheck);
BOOL WINAPI CheckMenuItem(HMENU hMenu, UINT uIDCheckItem, UINT uCheck);
void WINAPI CheckRadioButton(HWND hDlg, int nIDFirstButton, int nIDLastButton, int nIDCheckButton);
void WINAPI ClientToScreen(HWND hWnd, POINT FAR *lpPoint);
void WINAPI CopyRect(RECT FAR *lprcDst, const RECT FAR *lprcSrc);
HWND WINAPI CreateDialog(HINSTANCE hInstance, LPCSTR lpTemplate, HWND hWndParent, DLGPROC lpDialogFunc);
HMENU WINAPI CreatePopupMenu(void);
HWND WINAPI CreateWindow(LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle,
                         int x, int y, int nWidth, int nHeight,
                         HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, void FAR *lpParam);
LRESULT WINAPI DefWindowProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
BOOL WINAPI DeleteMenu(HMENU hMenu, UINT uPosition, UINT uFlags);
BOOL WINAPI DestroyCursor(HCURSOR hCursor);
BOOL WINAPI DestroyIcon(HICON hIcon);
BOOL WINAPI DestroyMenu(HMENU hMenu);
BOOL WINAPI DestroyWindow(HWND hWnd);
int WINAPI DialogBox(HINSTANCE hInstance, LPCSTR lpTemplate, HWND hWndParent, DLGPROC lpDialogFunc);
LONG WINAPI DispatchMessage(const MSG FAR *lpMsg);
BOOL WINAPI DrawIcon(HDC hDC, int x, int y, HICON hIcon);
void WINAPI DrawMenuBar(HWND hWnd);
int WINAPI DrawText(HDC hdc, LPCSTR lpchText, int cchText, RECT FAR *lprc, UINT format);
BOOL WINAPI EnableMenuItem(HMENU hMenu, UINT uIDEnableItem, UINT uEnable);
BOOL WINAPI EnableWindow(HWND hWnd, BOOL bEnable);
void WINAPI EndDialog(HWND hDlg, int nResult);
void WINAPI EndPaint(HWND hWnd, const PAINTSTRUCT FAR *lpPaint);
BOOL WINAPI EqualRect(const RECT FAR *lprc1, const RECT FAR *lprc2);
BOOL WINAPI ExitWindows(DWORD dwReserved, UINT uReserved);
int WINAPI FillRect(HDC hDC, const RECT FAR *lprc, HBRUSH hbr);
BOOL WINAPI FlashWindow(HWND hWnd, BOOL bInvert);
int WINAPI FrameRect(HDC hDC, const RECT FAR *lprc, HBRUSH hbr);
HWND WINAPI GetActiveWindow(void);
int WINAPI GetAsyncKeyState(int vKey);
void WINAPI GetClientRect(HWND hWnd, RECT FAR *lpRect);
DWORD WINAPI GetCurrentTime(void);
void WINAPI GetCursorPos(POINT FAR *lpPoint);
HDC WINAPI GetDC(HWND hWnd);
HWND WINAPI GetDlgItem(HWND hDlg, int nIDDlgItem);
int WINAPI GetDlgItemText(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax);
HWND WINAPI GetFocus(void);
int WINAPI GetKeyState(int nVirtKey);
HMENU WINAPI GetMenu(HWND hWnd);
int WINAPI GetMenuItemCount(HMENU hMenu);
BOOL WINAPI GetMessage(MSG FAR *lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
HWND WINAPI GetParent(HWND hWnd);
int WINAPI GetScrollPos(HWND hWnd, int nBar);
HMENU WINAPI GetSubMenu(HMENU hMenu, int nPos);
COLORREF WINAPI GetSysColor(int nIndex);
int WINAPI GetSystemMetrics(int nIndex);
DWORD WINAPI GetTickCount(void);
HWND WINAPI GetWindow(HWND hWnd, UINT uCmd);
LONG WINAPI GetWindowLong(HWND hWnd, int nIndex);
BOOL WINAPI GetWindowPlacement(HWND hWnd, WINDOWPLACEMENT FAR *lpwndpl);
void WINAPI GetWindowRect(HWND hWnd, RECT FAR *lpRect);
int WINAPI GetWindowText(HWND hWnd, LPSTR lpString, int nMaxCount);
void WINAPI InflateRect(RECT FAR *lprc, int dx, int dy);
BOOL WINAPI InsertMenu(HMENU hMenu, UINT uPosition, UINT uFlags, UINT uIDNewItem, LPCSTR lpNewItem);
BOOL WINAPI IntersectRect(RECT FAR *lprcDst, const RECT FAR *lprcSrc1, const RECT FAR *lprcSrc2);
void WINAPI InvalidateRect(HWND hWnd, const RECT FAR *lpRect, BOOL bErase);
UINT WINAPI IsDlgButtonChecked(HWND hDlg, int nIDButton);
BOOL WINAPI IsIconic(HWND hWnd);
BOOL WINAPI IsWindowVisible(HWND hWnd);
BOOL WINAPI IsZoomed(HWND hWnd);
BOOL WINAPI KillTimer(HWND hWnd, UINT uIDEvent);
HACCEL WINAPI LoadAccelerators(HINSTANCE hInstance, LPCSTR lpTableName);
HBITMAP WINAPI LoadBitmap(HINSTANCE hInstance, LPCSTR lpBitmapName);
HCURSOR WINAPI LoadCursor(HINSTANCE hInstance, LPCSTR lpCursorName);
HICON WINAPI LoadIcon(HINSTANCE hInstance, LPCSTR lpIconName);
void WINAPI MapWindowPoints(HWND hWndFrom, HWND hWndTo, POINT FAR *lpPoints, UINT cPoints);
void WINAPI MessageBeep(UINT uType);
int WINAPI MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
BOOL WINAPI MoveWindow(HWND hWnd, int x, int y, int nWidth, int nHeight, BOOL bRepaint);
void WINAPI OffsetRect(RECT FAR *lprc, int dx, int dy);
BOOL WINAPI PeekMessage(MSG FAR *lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
BOOL WINAPI PostMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
void WINAPI PostQuitMessage(int nExitCode);
BOOL WINAPI PtInRect(const RECT FAR *lprc, POINT pt);
UINT WINAPI RealizePalette(HDC hdc);
ATOM WINAPI RegisterClass(const WNDCLASS FAR *lpWndClass);
void WINAPI ReleaseCapture(void);
int WINAPI ReleaseDC(HWND hWnd, HDC hDC);
void WINAPI ScreenToClient(HWND hWnd, POINT FAR *lpPoint);
void WINAPI ScrollWindow(HWND hWnd, int dx, int dy, const RECT FAR *lpRect, const RECT FAR *lpClipRect);
HPALETTE WINAPI SelectPalette(HDC hdc, HPALETTE hPal, BOOL bForceBkgd);
LRESULT WINAPI SendDlgItemMessage(HWND hDlg, int nIDDlgItem, UINT Msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI SendMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
HWND WINAPI SetCapture(HWND hWnd);
HCURSOR WINAPI SetCursor(HCURSOR hCursor);
void WINAPI SetDlgItemText(HWND hDlg, int nIDDlgItem, LPCSTR lpString);
HWND WINAPI SetFocus(HWND hWnd);
void WINAPI SetRect(RECT FAR *lprc, int xLeft, int yTop, int xRight, int yBottom);
int WINAPI SetScrollPos(HWND hWnd, int nBar, int nPos, BOOL bRedraw);
void WINAPI SetScrollRange(HWND hWnd, int nBar, int nMinPos, int nMaxPos, BOOL bRedraw);
UINT WINAPI SetTimer(HWND hWnd, UINT nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc);
LONG WINAPI SetWindowLong(HWND hWnd, int nIndex, LONG dwNewLong);
BOOL WINAPI SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int x, int y, int cx, int cy, UINT uFlags);
void WINAPI SetWindowText(HWND hWnd, LPCSTR lpString);
BOOL WINAPI ShowWindow(HWND hWnd, int nCmdShow);
BOOL WINAPI TrackPopupMenu(HMENU hMenu, UINT uFlags, int x, int y, int nReserved, HWND hWnd, const RECT FAR *prcRect);
int WINAPI TranslateAccelerator(HWND hWnd, HACCEL hAccTable, MSG FAR *lpMsg);
BOOL WINAPI TranslateMessage(const MSG FAR *lpMsg);
void WINAPI UpdateWindow(HWND hWnd);
void WINAPI ValidateRect(HWND hWnd, const RECT FAR *lpRect);
HWND WINAPI WindowFromPoint(POINT pt);
BOOL WINAPI WinHelp(HWND hWndMain, LPCSTR lpszHelp, UINT uCommand, DWORD dwData);

/* Helper macro for RGB color */
#define RGB(r, g, b) ((COLORREF)(((BYTE)(r) | ((WORD)((BYTE)(g)) << 8)) | (((DWORD)(BYTE)(b)) << 16)))

/* Helper macros for message parameters */
#define LOWORD(l) ((WORD)((DWORD)(l) & 0xffff))
#define HIWORD(l) ((WORD)(((DWORD)(l) >> 16) & 0xffff))
#define LOBYTE(w) ((BYTE)((WORD)(w) & 0xff))
#define HIBYTE(w) ((BYTE)(((WORD)(w) >> 8) & 0xff))

#define MAKELONG(a, b) ((LONG)(((WORD)(a)) | ((DWORD)((WORD)(b))) << 16))
#define MAKEWORD(a, b) ((WORD)(((BYTE)(a)) | ((WORD)((BYTE)(b))) << 8))

#endif /* WIN_STUBS_H */
