#include <windows.h>
#include "Logger.h"
#include "ProxyExport.h"

static Logger g_logger;

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"user32.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" HWND WINAPI Proxy_CreateWindowExW(
    DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
    int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
    HINSTANCE hInstance, LPVOID lpParam)
{
    typedef HWND (WINAPI* Real_t)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int,
        int, int, HWND, HMENU, HINSTANCE, LPVOID);
    static Real_t real = (Real_t)GetRealProc("CreateWindowExW");
    return real ? real(dwExStyle, lpClassName, lpWindowName, dwStyle,
        X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam) : nullptr;
}

extern "C" int WINAPI Proxy_MessageBoxW(
    HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    typedef int (WINAPI* Real_t)(HWND, LPCWSTR, LPCWSTR, UINT);
    static Real_t real = (Real_t)GetRealProc("MessageBoxW");
    return real ? real(hWnd, lpText, lpCaption, uType) : 0;
}

extern "C" BOOL WINAPI Proxy_GetMessageW(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax)
{
    typedef BOOL (WINAPI* Real_t)(LPMSG, HWND, UINT, UINT);
    static Real_t real = (Real_t)GetRealProc("GetMessageW");
    return real ? real(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax) : FALSE;
}

extern "C" BOOL WINAPI Proxy_PeekMessageW(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
    typedef BOOL (WINAPI* Real_t)(LPMSG, HWND, UINT, UINT, UINT);
    static Real_t real = (Real_t)GetRealProc("PeekMessageW");
    return real ? real(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg) : FALSE;
}

extern "C" BOOL WINAPI Proxy_TranslateMessage(const MSG* lpMsg)
{
    typedef BOOL (WINAPI* Real_t)(const MSG*);
    static Real_t real = (Real_t)GetRealProc("TranslateMessage");
    return real ? real(lpMsg) : FALSE;
}

extern "C" LRESULT WINAPI Proxy_DispatchMessageW(const MSG* lpMsg)
{
    typedef LRESULT (WINAPI* Real_t)(const MSG*);
    static Real_t real = (Real_t)GetRealProc("DispatchMessageW");
    return real ? real(lpMsg) : 0;
}

PROXY_EXPORT(CreateWindowExW,  Proxy_CreateWindowExW,  48) // 12 params
PROXY_EXPORT(MessageBoxW,      Proxy_MessageBoxW,      16) // 4
PROXY_EXPORT(GetMessageW,      Proxy_GetMessageW,      16) // 4
PROXY_EXPORT(PeekMessageW,     Proxy_PeekMessageW,     20) // 5
PROXY_EXPORT(TranslateMessage, Proxy_TranslateMessage,  4) // 1
PROXY_EXPORT(DispatchMessageW, Proxy_DispatchMessageW,  4) // 1

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            g_logger.Init();
            g_logger.Trace(LOG_PROXY, "user32_proxy loaded");
            DisableThreadLibraryCalls(hModule);
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
