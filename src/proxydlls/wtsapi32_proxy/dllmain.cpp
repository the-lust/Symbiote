#include <windows.h>
#include <wtsapi32.h>
#include <string>
#include "Logger.h"
#include "ProxyExport.h"

#pragma comment(lib, "wtsapi32.lib")

PROXY_EXPORT(WTSQuerySessionInformationA, proxy_WTSQuerySessionInformationA, 20) // HANDLE,DWORD,DWORD,LPSTR*,DWORD*
PROXY_EXPORT(WTSQuerySessionInformationW, proxy_WTSQuerySessionInformationW, 20) // HANDLE,DWORD,DWORD,LPWSTR*,DWORD*
PROXY_EXPORT(WTSFreeMemory,               proxy_WTSFreeMemory,                4) // LPVOID
PROXY_EXPORT(WTSEnumerateSessionsW,       proxy_WTSEnumerateSessionsW,       20) // HANDLE,DWORD,DWORD,PWTS_SESSION_INFOW*,DWORD*
PROXY_EXPORT(WTSGetActiveConsoleSessionId,proxy_WTSGetActiveConsoleSessionId, 0) // void

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"wtsapi32.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" BOOL WINAPI proxy_WTSQuerySessionInformationA(HANDLE hServer, DWORD SessionId, DWORD WTSInfoClass, LPSTR* ppBuffer, DWORD* pBytesReturned) {
    typedef BOOL (WINAPI* Real_t)(HANDLE, DWORD, DWORD, LPSTR*, DWORD*);
    static Real_t real = (Real_t)GetRealProc("WTSQuerySessionInformationA");
    return real ? real(hServer, SessionId, WTSInfoClass, ppBuffer, pBytesReturned) : FALSE;
}

extern "C" BOOL WINAPI proxy_WTSQuerySessionInformationW(HANDLE hServer, DWORD SessionId, DWORD WTSInfoClass, LPWSTR* ppBuffer, DWORD* pBytesReturned) {
    typedef BOOL (WINAPI* Real_t)(HANDLE, DWORD, DWORD, LPWSTR*, DWORD*);
    static Real_t real = (Real_t)GetRealProc("WTSQuerySessionInformationW");
    return real ? real(hServer, SessionId, WTSInfoClass, ppBuffer, pBytesReturned) : FALSE;
}

extern "C" void WINAPI proxy_WTSFreeMemory(LPVOID pMemory) {
    typedef void (WINAPI* Real_t)(LPVOID);
    static Real_t real = (Real_t)GetRealProc("WTSFreeMemory");
    if (real) real(pMemory);
}

extern "C" BOOL WINAPI proxy_WTSEnumerateSessionsW(HANDLE hServer, DWORD Reserved, DWORD Version, PWTS_SESSION_INFOW* ppSessionInfo, DWORD* pCount) {
    typedef BOOL (WINAPI* Real_t)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW*, DWORD*);
    static Real_t real = (Real_t)GetRealProc("WTSEnumerateSessionsW");
    return real ? real(hServer, Reserved, Version, ppSessionInfo, pCount) : FALSE;
}

extern "C" DWORD WINAPI proxy_WTSGetActiveConsoleSessionId() {
    typedef DWORD (WINAPI* Real_t)();
    static Real_t real = (Real_t)GetRealProc("WTSGetActiveConsoleSessionId");
    return real ? real() : 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD, LPVOID) { DisableThreadLibraryCalls(hModule); return TRUE; }
