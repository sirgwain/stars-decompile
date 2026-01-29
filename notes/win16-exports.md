# Win16 API Imports

Stars! 2.60j imports from the following Win16 DLLs.

## COMMDLG (Common Dialogs)

| Function | Ordinal | Signature |
|----------|---------|-----------|
| `GetOpenFileName` | 1 | `BOOL WINAPI GetOpenFileName(OPENFILENAME FAR*)` |
| `GetSaveFileName` | 2 | `BOOL WINAPI GetSaveFileName(OPENFILENAME FAR*)` |
| `PrintDlg` | 20 | `BOOL WINAPI PrintDlg(PRINTDLG FAR*)` |

## GDI (Graphics Device Interface)

| Function | Ordinal | Signature |
|----------|---------|-----------|
| `BitBlt` | 34 | `BOOL WINAPI BitBlt(HDC, int, int, int, int, HDC, int, int, DWORD)` |
| `CreateCompatibleBitmap` | 51 | `HBITMAP WINAPI CreateCompatibleBitmap(HDC, int, int)` |
| `CreateCompatibleDC` | 52 | `HDC WINAPI CreateCompatibleDC(HDC)` |
| `CreateFontIndirect` | 57 | `HFONT WINAPI CreateFontIndirect(const LOGFONT FAR*)` |
| `CreatePalette` | 360 | `HPALETTE WINAPI CreatePalette(const LOGPALETTE FAR*)` |
| `CreatePatternBrush` | 60 | `HBRUSH WINAPI CreatePatternBrush(HBITMAP)` |
| `CreatePen` | 61 | `HPEN WINAPI CreatePen(int, int, COLORREF)` |
| `CreateRectRgn` | 64 | `HRGN WINAPI CreateRectRgn(int, int, int, int)` |
| `CreateSolidBrush` | 66 | `HBRUSH WINAPI CreateSolidBrush(COLORREF)` |
| `DeleteDC` | 68 | `BOOL WINAPI DeleteDC(HDC)` |
| `DeleteObject` | 69 | `BOOL WINAPI DeleteObject(HGDIOBJ)` |
| `Ellipse` | 24 | `BOOL WINAPI Ellipse(HDC, int, int, int, int)` |
| `Escape` | 38 | `int WINAPI Escape(HDC, int, int, LPCSTR, void FAR*)` |
| `ExcludeClipRect` | 21 | `int WINAPI ExcludeClipRect(HDC, int, int, int, int)` |
| `ExtTextOut` | 351 | `BOOL WINAPI ExtTextOut(HDC, int, int, UINT, const RECT FAR*, LPCSTR, UINT, int FAR*)` |
| `GetBkColor` | 75 | `COLORREF WINAPI GetBkColor(HDC)` |
| `GetDeviceCaps` | 80 | `int WINAPI GetDeviceCaps(HDC, int)` |
| `GetDIBits` | 441 | `int WINAPI GetDIBits(HDC, HBITMAP, UINT, UINT, void FAR*, BITMAPINFO FAR*, UINT)` |
| `GetObject` | 82 | `int WINAPI GetObject(HGDIOBJ, int, void FAR*)` |
| `GetROP2` | 85 | `int WINAPI GetROP2(HDC)` |
| `GetStockObject` | 87 | `HGDIOBJ WINAPI GetStockObject(int)` |
| `GetTextExtent` | 91 | `DWORD WINAPI GetTextExtent(HDC, LPCSTR, int)` |
| `GetTextMetrics` | 93 | `BOOL WINAPI GetTextMetrics(HDC, TEXTMETRIC FAR*)` |
| `IntersectClipRect` | 22 | `int WINAPI IntersectClipRect(HDC, int, int, int, int)` |
| `LineTo` | 19 | `BOOL WINAPI LineTo(HDC, int, int)` |
| `MoveTo` | 20 | `DWORD WINAPI MoveTo(HDC, int, int)` |
| `MulDiv` | 128 | `int WINAPI MulDiv(int, int, int)` |
| `PatBlt` | 29 | `BOOL WINAPI PatBlt(HDC, int, int, int, int, DWORD)` |
| `Rectangle` | 27 | `BOOL WINAPI Rectangle(HDC, int, int, int, int)` |
| `SelectClipRgn` | 44 | `int WINAPI SelectClipRgn(HDC, HRGN)` |
| `SelectObject` | 45 | `HGDIOBJ WINAPI SelectObject(HDC, HGDIOBJ)` |
| `SetBkColor` | 1 | `COLORREF WINAPI SetBkColor(HDC, COLORREF)` |
| `SetBkMode` | 2 | `int WINAPI SetBkMode(HDC, int)` |
| `SetBrushOrg` | 148 | `DWORD WINAPI SetBrushOrg(HDC, int, int)` |
| `SetPixel` | 31 | `COLORREF WINAPI SetPixel(HDC, int, int, COLORREF)` |
| `SetROP2` | 4 | `int WINAPI SetROP2(HDC, int)` |
| `SetTextColor` | 9 | `COLORREF WINAPI SetTextColor(HDC, COLORREF)` |
| `SetWindowOrg` | 11 | `DWORD WINAPI SetWindowOrg(HDC, int, int)` |
| `StretchDIBits` | 439 | `int WINAPI StretchDIBits(HDC, int, int, int, int, int, int, int, int, void FAR*, BITMAPINFO FAR*, UINT, DWORD)` |
| `TextOut` | 33 | `BOOL WINAPI TextOut(HDC, int, int, LPCSTR, int)` |
| `UnrealizeObject` | 150 | `BOOL WINAPI UnrealizeObject(HGDIOBJ)` |

## KERNEL

| Function | Ordinal | Signature |
|----------|---------|-----------|
| `__AHINCR` | 114 | *(internal: huge pointer increment value)* |
| `__AHSHIFT` | 113 | *(internal: huge pointer shift value)* |
| `__WINFLAGS` | 178 | *(internal: Windows flags)* |
| `_lclose` | 81 | `HFILE WINAPI _lclose(HFILE)` |
| `_lread` | 82 | `UINT WINAPI _lread(HFILE, void _huge*, UINT)` |
| `_lwrite` | 86 | `UINT WINAPI _lwrite(HFILE, const void _huge*, UINT)` |
| `AccessResource` | 64 | `int WINAPI AccessResource(HINSTANCE, HRSRC)` |
| `AllocResource` | 66 | `HGLOBAL WINAPI AllocResource(HINSTANCE, HRSRC, DWORD)` |
| `DOS3CALL` | 102 | *(internal: DOS interrupt 21h call)* |
| `FatalAppExit` | 137 | `void WINAPI FatalAppExit(UINT, LPCSTR)` |
| `FatalExit` | 1 | `void WINAPI FatalExit(int)` |
| `FindResource` | 60 | `HRSRC WINAPI FindResource(HINSTANCE, LPCSTR, LPCSTR)` |
| `FreeProcInstance` | 52 | `void WINAPI FreeProcInstance(FARPROC)` |
| `FreeResource` | 63 | `BOOL WINAPI FreeResource(HGLOBAL)` |
| `GetDOSEnvironment` | 131 | `LPSTR WINAPI GetDOSEnvironment(void)` |
| `GetDriveType` | 136 | `UINT WINAPI GetDriveType(int)` |
| `GetModuleFileName` | 49 | `int WINAPI GetModuleFileName(HINSTANCE, LPSTR, int)` |
| `GetPrivateProfileInt` | 127 | `UINT WINAPI GetPrivateProfileInt(LPCSTR, LPCSTR, int, LPCSTR)` |
| `GetPrivateProfileString` | 128 | `int WINAPI GetPrivateProfileString(LPCSTR, LPCSTR, LPCSTR, LPSTR, int, LPCSTR)` |
| `GetVersion` | 3 | `DWORD WINAPI GetVersion(void)` |
| `GlobalAlloc` | 15 | `HGLOBAL WINAPI GlobalAlloc(UINT, DWORD)` |
| `GlobalFree` | 17 | `HGLOBAL WINAPI GlobalFree(HGLOBAL)` |
| `GlobalLock` | 18 | `void FAR* WINAPI GlobalLock(HGLOBAL)` |
| `GlobalReAlloc` | 16 | `HGLOBAL WINAPI GlobalReAlloc(HGLOBAL, DWORD, UINT)` |
| `GlobalSize` | 20 | `DWORD WINAPI GlobalSize(HGLOBAL)` |
| `GlobalUnlock` | 19 | `BOOL WINAPI GlobalUnlock(HGLOBAL)` |
| `INITTASK` | 91 | *(internal: task initialization)* |
| `LoadResource` | 61 | `HGLOBAL WINAPI LoadResource(HINSTANCE, HRSRC)` |
| `LocalAlloc` | 5 | `HLOCAL WINAPI LocalAlloc(UINT, UINT)` |
| `LocalFree` | 7 | `HLOCAL WINAPI LocalFree(HLOCAL)` |
| `LocalReAlloc` | 6 | `HLOCAL WINAPI LocalReAlloc(HLOCAL, UINT, UINT)` |
| `LocalSize` | 10 | `UINT WINAPI LocalSize(HLOCAL)` |
| `LockResource` | 62 | `void FAR* WINAPI LockResource(HGLOBAL)` |
| `LockSegment` | 23 | `HGLOBAL WINAPI LockSegment(UINT)` |
| `lstrcat` | 89 | `LPSTR WINAPI lstrcat(LPSTR, LPCSTR)` |
| `lstrcpy` | 88 | `LPSTR WINAPI lstrcpy(LPSTR, LPCSTR)` |
| `lstrlen` | 90 | `int WINAPI lstrlen(LPCSTR)` |
| `MakeProcInstance` | 51 | `FARPROC WINAPI MakeProcInstance(FARPROC, HINSTANCE)` |
| `OpenFile` | 74 | `HFILE WINAPI OpenFile(LPCSTR, OFSTRUCT FAR*, UINT)` |
| `SizeofResource` | 65 | `DWORD WINAPI SizeofResource(HINSTANCE, HRSRC)` |
| `UnlockSegment` | 24 | `void WINAPI UnlockSegment(UINT)` |
| `WAITEVENT` | 30 | *(internal: wait for event)* |
| `WritePrivateProfileString` | 129 | `BOOL WINAPI WritePrivateProfileString(LPCSTR, LPCSTR, LPCSTR, LPCSTR)` |
| `Yield` | 29 | `void WINAPI Yield(void)` |

## TOOLHELP

| Function | Ordinal | Signature |
|----------|---------|-----------|
| `TimerCount` | 80 | `BOOL WINAPI TimerCount(TIMERINFO FAR*)` |

## USER

| Function | Ordinal | Signature |
|----------|---------|-----------|
| `_wsprintf` | 420 | `int FAR CDECL wsprintf(LPSTR, LPCSTR, ...)` |
| `AppendMenu` | 411 | `BOOL WINAPI AppendMenu(HMENU, UINT, UINT, LPCSTR)` |
| `BeginPaint` | 39 | `HDC WINAPI BeginPaint(HWND, PAINTSTRUCT FAR*)` |
| `CallWindowProc` | 122 | `LRESULT WINAPI CallWindowProc(WNDPROC, HWND, UINT, WPARAM, LPARAM)` |
| `CheckDlgButton` | 97 | `void WINAPI CheckDlgButton(HWND, int, UINT)` |
| `CheckMenuItem` | 154 | `BOOL WINAPI CheckMenuItem(HMENU, UINT, UINT)` |
| `CheckRadioButton` | 96 | `void WINAPI CheckRadioButton(HWND, int, int, int)` |
| `ClientToScreen` | 28 | `void WINAPI ClientToScreen(HWND, POINT FAR*)` |
| `CopyRect` | 74 | `void WINAPI CopyRect(RECT FAR*, const RECT FAR*)` |
| `CreateDialog` | 89 | `HWND WINAPI CreateDialog(HINSTANCE, LPCSTR, HWND, DLGPROC)` |
| `CreatePopupMenu` | 415 | `HMENU WINAPI CreatePopupMenu(void)` |
| `CreateWindow` | 41 | `HWND WINAPI CreateWindow(LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, void FAR*)` |
| `DefWindowProc` | 107 | `LRESULT WINAPI DefWindowProc(HWND, UINT, WPARAM, LPARAM)` |
| `DeleteMenu` | 413 | `BOOL WINAPI DeleteMenu(HMENU, UINT, UINT)` |
| `DestroyCursor` | 458 | `BOOL WINAPI DestroyCursor(HCURSOR)` |
| `DestroyIcon` | 457 | `BOOL WINAPI DestroyIcon(HICON)` |
| `DestroyMenu` | 152 | `BOOL WINAPI DestroyMenu(HMENU)` |
| `DestroyWindow` | 53 | `BOOL WINAPI DestroyWindow(HWND)` |
| `DialogBox` | 87 | `int WINAPI DialogBox(HINSTANCE, LPCSTR, HWND, DLGPROC)` |
| `DispatchMessage` | 114 | `LONG WINAPI DispatchMessage(const MSG FAR*)` |
| `DrawIcon` | 84 | `BOOL WINAPI DrawIcon(HDC, int, int, HICON)` |
| `DrawMenuBar` | 160 | `void WINAPI DrawMenuBar(HWND)` |
| `DRAWTEXT` | 85 | `int WINAPI DrawText(HDC, LPCSTR, int, RECT FAR*, UINT)` |
| `EnableMenuItem` | 155 | `BOOL WINAPI EnableMenuItem(HMENU, UINT, UINT)` |
| `EnableWindow` | 34 | `BOOL WINAPI EnableWindow(HWND, BOOL)` |
| `EndDialog` | 88 | `void WINAPI EndDialog(HWND, int)` |
| `EndPaint` | 40 | `void WINAPI EndPaint(HWND, const PAINTSTRUCT FAR*)` |
| `EqualRect` | 244 | `BOOL WINAPI EqualRect(const RECT FAR*, const RECT FAR*)` |
| `ExitWindows` | 7 | `BOOL WINAPI ExitWindows(DWORD, UINT)` |
| `FillRect` | 81 | `int WINAPI FillRect(HDC, const RECT FAR*, HBRUSH)` |
| `FlashWindow` | 105 | `BOOL WINAPI FlashWindow(HWND, BOOL)` |
| `FrameRect` | 83 | `int WINAPI FrameRect(HDC, const RECT FAR*, HBRUSH)` |
| `GetActiveWindow` | 60 | `HWND WINAPI GetActiveWindow(void)` |
| `GetAsyncKeyState` | 249 | `int WINAPI GetAsyncKeyState(int)` |
| `GetClientRect` | 33 | `void WINAPI GetClientRect(HWND, RECT FAR*)` |
| `GetCurrentTime` | 15 | `DWORD WINAPI GetCurrentTime(void)` |
| `GetCursorPos` | 17 | `void WINAPI GetCursorPos(POINT FAR*)` |
| `GetDC` | 66 | `HDC WINAPI GetDC(HWND)` |
| `GetDlgItem` | 91 | `HWND WINAPI GetDlgItem(HWND, int)` |
| `GetDlgItemText` | 93 | `int WINAPI GetDlgItemText(HWND, int, LPSTR, int)` |
| `GetFocus` | 23 | `HWND WINAPI GetFocus(void)` |
| `GetKeyState` | 106 | `int WINAPI GetKeyState(int)` |
| `GetMenu` | 157 | `HMENU WINAPI GetMenu(HWND)` |
| `GetMenuItemCount` | 263 | `int WINAPI GetMenuItemCount(HMENU)` |
| `GetMessage` | 108 | `BOOL WINAPI GetMessage(MSG FAR*, HWND, UINT, UINT)` |
| `GetParent` | 46 | `HWND WINAPI GetParent(HWND)` |
| `GetScrollPos` | 63 | `int WINAPI GetScrollPos(HWND, int)` |
| `GetSubMenu` | 159 | `HMENU WINAPI GetSubMenu(HMENU, int)` |
| `GetSysColor` | 180 | `COLORREF WINAPI GetSysColor(int)` |
| `GetSystemMetrics` | 179 | `int WINAPI GetSystemMetrics(int)` |
| `GetTickCount` | 13 | `DWORD WINAPI GetTickCount(void)` |
| `GetWindow` | 262 | `HWND WINAPI GetWindow(HWND, UINT)` |
| `GetWindowLong` | 135 | `LONG WINAPI GetWindowLong(HWND, int)` |
| `GetWindowPlacement` | 370 | `BOOL WINAPI GetWindowPlacement(HWND, WINDOWPLACEMENT FAR*)` |
| `GetWindowRect` | 32 | `void WINAPI GetWindowRect(HWND, RECT FAR*)` |
| `GetWindowText` | 36 | `int WINAPI GetWindowText(HWND, LPSTR, int)` |
| `InflateRect` | 78 | `void WINAPI InflateRect(RECT FAR*, int, int)` |
| `INITAPP` | 5 | *(internal: application initialization)* |
| `InsertMenu` | 410 | `BOOL WINAPI InsertMenu(HMENU, UINT, UINT, UINT, LPCSTR)` |
| `IntersectRect` | 79 | `BOOL WINAPI IntersectRect(RECT FAR*, const RECT FAR*, const RECT FAR*)` |
| `InvalidateRect` | 125 | `void WINAPI InvalidateRect(HWND, const RECT FAR*, BOOL)` |
| `IsDlgButtonChecked` | 98 | `UINT WINAPI IsDlgButtonChecked(HWND, int)` |
| `IsIconic` | 31 | `BOOL WINAPI IsIconic(HWND)` |
| `IsWindowVisible` | 49 | `BOOL WINAPI IsWindowVisible(HWND)` |
| `IsZoomed` | 272 | `BOOL WINAPI IsZoomed(HWND)` |
| `KillTimer` | 12 | `BOOL WINAPI KillTimer(HWND, UINT)` |
| `LoadAccelerators` | 177 | `HACCEL WINAPI LoadAccelerators(HINSTANCE, LPCSTR)` |
| `LoadBitmap` | 175 | `HBITMAP WINAPI LoadBitmap(HINSTANCE, LPCSTR)` |
| `LoadCursor` | 173 | `HCURSOR WINAPI LoadCursor(HINSTANCE, LPCSTR)` |
| `LoadIcon` | 174 | `HICON WINAPI LoadIcon(HINSTANCE, LPCSTR)` |
| `MapWindowPoints` | 258 | `void WINAPI MapWindowPoints(HWND, HWND, POINT FAR*, UINT)` |
| `MessageBeep` | 104 | `void WINAPI MessageBeep(UINT)` |
| `MessageBox` | 1 | `int WINAPI MessageBox(HWND, LPCSTR, LPCSTR, UINT)` |
| `MoveWindow` | 56 | `BOOL WINAPI MoveWindow(HWND, int, int, int, int, BOOL)` |
| `OffsetRect` | 77 | `void WINAPI OffsetRect(RECT FAR*, int, int)` |
| `PeekMessage` | 109 | `BOOL WINAPI PeekMessage(MSG FAR*, HWND, UINT, UINT, UINT)` |
| `PostMessage` | 110 | `BOOL WINAPI PostMessage(HWND, UINT, WPARAM, LPARAM)` |
| `PostQuitMessage` | 6 | `void WINAPI PostQuitMessage(int)` |
| `PtInRect` | 76 | `BOOL WINAPI PtInRect(const RECT FAR*, POINT)` |
| `RealizePalette` | 283 | `UINT WINAPI RealizePalette(HDC)` |
| `RegisterClass` | 57 | `ATOM WINAPI RegisterClass(const WNDCLASS FAR*)` |
| `ReleaseCapture` | 19 | `void WINAPI ReleaseCapture(void)` |
| `ReleaseDC` | 68 | `int WINAPI ReleaseDC(HWND, HDC)` |
| `ScreenToClient` | 29 | `void WINAPI ScreenToClient(HWND, POINT FAR*)` |
| `ScrollWindow` | 61 | `void WINAPI ScrollWindow(HWND, int, int, const RECT FAR*, const RECT FAR*)` |
| `SelectPalette` | 282 | `HPALETTE WINAPI SelectPalette(HDC, HPALETTE, BOOL)` |
| `SendDlgItemMessage` | 101 | `LRESULT WINAPI SendDlgItemMessage(HWND, int, UINT, WPARAM, LPARAM)` |
| `SendMessage` | 111 | `LRESULT WINAPI SendMessage(HWND, UINT, WPARAM, LPARAM)` |
| `SetCapture` | 18 | `HWND WINAPI SetCapture(HWND)` |
| `SetCursor` | 69 | `HCURSOR WINAPI SetCursor(HCURSOR)` |
| `SetDlgItemText` | 92 | `void WINAPI SetDlgItemText(HWND, int, LPCSTR)` |
| `SetFocus` | 22 | `HWND WINAPI SetFocus(HWND)` |
| `SetRect` | 72 | `void WINAPI SetRect(RECT FAR*, int, int, int, int)` |
| `SetScrollPos` | 62 | `int WINAPI SetScrollPos(HWND, int, int, BOOL)` |
| `SetScrollRange` | 64 | `void WINAPI SetScrollRange(HWND, int, int, int, BOOL)` |
| `SetTimer` | 10 | `UINT WINAPI SetTimer(HWND, UINT, UINT, TIMERPROC)` |
| `SetWindowLong` | 136 | `LONG WINAPI SetWindowLong(HWND, int, LONG)` |
| `SetWindowPos` | 232 | `BOOL WINAPI SetWindowPos(HWND, HWND, int, int, int, int, UINT)` |
| `SetWindowText` | 37 | `void WINAPI SetWindowText(HWND, LPCSTR)` |
| `ShowWindow` | 42 | `BOOL WINAPI ShowWindow(HWND, int)` |
| `TrackPopupMenu` | 416 | `BOOL WINAPI TrackPopupMenu(HMENU, UINT, int, int, int, HWND, const RECT FAR*)` |
| `TranslateAccelerator` | 178 | `int WINAPI TranslateAccelerator(HWND, HACCEL, MSG FAR*)` |
| `TranslateMessage` | 113 | `BOOL WINAPI TranslateMessage(const MSG FAR*)` |
| `UpdateWindow` | 124 | `void WINAPI UpdateWindow(HWND)` |
| `ValidateRect` | 127 | `void WINAPI ValidateRect(HWND, const RECT FAR*)` |
| `WindowFromPoint` | 30 | `HWND WINAPI WindowFromPoint(POINT)` |
| `WinHelp` | 171 | `BOOL WINAPI WinHelp(HWND, LPCSTR, UINT, DWORD)` |

## WIN87EM (Math Coprocessor Emulation)

| Function | Ordinal | Signature |
|----------|---------|-----------|
| `__FPMATH` | 1 | *(internal: floating-point math support)* |

## Summary

| DLL | Import Count |
|-----|--------------|
| COMMDLG | 3 |
| GDI | 37 |
| KERNEL | 41 |
| TOOLHELP | 1 |
| USER | 100 |
| WIN87EM | 1 |
| **Total** | **183** |
