#include <windows.h>
#include "Logger.h"
#include "ProxyExport.h"

static Logger g_logger;

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"kernelbase.dll");
    if (!hReal) hReal = LoadLibraryW(L"C:\\Windows\\System32\\kernelbase.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" void WINAPI Proxy_GetSystemInfo(LPSYSTEM_INFO lpInfo)
{
    typedef void (WINAPI* Real_t)(LPSYSTEM_INFO);
    static Real_t real = (Real_t)GetRealProc("GetSystemInfo");
    g_logger.Trace(LOG_PROXY, "CAPTURE GetSystemInfo called");
    if (real) {
        real(lpInfo);
        g_logger.Trace(LOG_PROXY, "CAPTURE GetSystemInfo: cores=%u page=0x%X min=%p max=%p",
            lpInfo->dwNumberOfProcessors, lpInfo->dwPageSize,
            lpInfo->lpMinimumApplicationAddress, lpInfo->lpMaximumApplicationAddress);
    }
}

extern "C" void WINAPI Proxy_GetNativeSystemInfo(LPSYSTEM_INFO lpInfo)
{
    typedef void (WINAPI* Real_t)(LPSYSTEM_INFO);
    static Real_t real = (Real_t)GetRealProc("GetNativeSystemInfo");
    g_logger.Trace(LOG_PROXY, "CAPTURE GetNativeSystemInfo called");
    if (real) {
        real(lpInfo);
        g_logger.Trace(LOG_PROXY, "CAPTURE GetNativeSystemInfo: cores=%u page=0x%X",
            lpInfo->dwNumberOfProcessors, lpInfo->dwPageSize);
    }
}

extern "C" BOOL WINAPI Proxy_QueryPerformanceCounter(LARGE_INTEGER* lpQpc)
{
    typedef BOOL (WINAPI* Real_t)(LARGE_INTEGER*);
    static Real_t real = (Real_t)GetRealProc("QueryPerformanceCounter");
    return real ? real(lpQpc) : FALSE;
}

extern "C" BOOL WINAPI Proxy_QueryPerformanceFrequency(LARGE_INTEGER* lpFreq)
{
    typedef BOOL (WINAPI* Real_t)(LARGE_INTEGER*);
    static Real_t real = (Real_t)GetRealProc("QueryPerformanceFrequency");
    return real ? real(lpFreq) : FALSE;
}

PROXY_EXPORT(GetSystemInfo,             Proxy_GetSystemInfo,              4) // 1
PROXY_EXPORT(GetNativeSystemInfo,       Proxy_GetNativeSystemInfo,        4) // 1
PROXY_EXPORT(QueryPerformanceCounter,   Proxy_QueryPerformanceCounter,    4) // 1
PROXY_EXPORT(QueryPerformanceFrequency, Proxy_QueryPerformanceFrequency,  4) // 1

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            g_logger.Init();
            g_logger.Trace(LOG_PROXY, "kernelbase_proxy loaded");
            DisableThreadLibraryCalls(hModule);
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
