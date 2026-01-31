# TODO

- [] Need to change all char slices that aren't strings to int8_t. char was signed -128...127 on win16. Not always signed on every platform.
- [] Update sig of DialogBox/CreateDialog to `short DialogBox (HINSTANCE hInst, DialogId lpTemplate, HWND hWndParent, FARPROC lpDlgProc)`
- [] Update sig of GetDlgItem to `HWND GetDlgItem (HWND param_1, ControlId param_2)`
- [] Update sig of GetDlgItemText same way
- [] Update sig of SendMessage to `LRESULT SendMessage (HWND param_1, WMType param_2, WPARAM param_3, LPARAM param_4)`
- [] Update sig of PostMessage to `BOOL PostMessage (HWND param_1, WMType param_2, WPARAM param_3, LPARAM param_4)`
- [] Update sig of _Draw3DFrame. Not being set
- [] Update MSG.message to be WMType
- [] fix `s_Stars_1120_.* \+ \d+` pattern. This is actually just the number 5000 (0x1387) `<= (char *)s_Stars_1120_1385 + 2)`
