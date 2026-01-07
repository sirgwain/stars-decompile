#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const char g_szClassName[] = "StarsHelloWindow";

/* Window procedure */
static LRESULT CALLBACK StarsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine,
                   int nShowCmd)
{
    (void)hPrevInstance;
    (void)lpCmdLine;

    WNDCLASS wc;
    HWND hwnd;
    MSG msg;

    /* Register window class */
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = StarsWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = g_szClassName;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClass(&wc))
    {
        MessageBox(NULL, "RegisterClass failed", "Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    /* Create window */
    hwnd = CreateWindow(
        g_szClassName,
        "Hello, Stars!",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        640, 480,
        NULL, NULL,
        hInstance,
        NULL);

    if (!hwnd)
    {
        MessageBox(NULL, "CreateWindow failed", "Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    ShowWindow(hwnd, nShowCmd);
    UpdateWindow(hwnd);

    /* Message loop */
    while (GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
