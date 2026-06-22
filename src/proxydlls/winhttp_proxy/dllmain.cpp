#include <windows.h>
#include <winhttp.h>
#include "Logger.h"
#include "ProxyExport.h"

// argbytes = paramCount * 4
PROXY_EXPORT(WinHttpOpen,              proxy_WinHttpOpen,               20) // 5
PROXY_EXPORT(WinHttpCloseHandle,       proxy_WinHttpCloseHandle,         4) // 1
PROXY_EXPORT(WinHttpConnect,           proxy_WinHttpConnect,            16) // 4
PROXY_EXPORT(WinHttpOpenRequest,       proxy_WinHttpOpenRequest,        28) // 7
PROXY_EXPORT(WinHttpSendRequest,       proxy_WinHttpSendRequest,        28) // 7
PROXY_EXPORT(WinHttpReceiveResponse,   proxy_WinHttpReceiveResponse,     8) // 2
PROXY_EXPORT(WinHttpReadData,          proxy_WinHttpReadData,           16) // 4
PROXY_EXPORT(WinHttpQueryDataAvailable,proxy_WinHttpQueryDataAvailable,  8) // 2
PROXY_EXPORT(WinHttpQueryHeaders,      proxy_WinHttpQueryHeaders,       24) // 6
PROXY_EXPORT(WinHttpSetOption,         proxy_WinHttpSetOption,          16) // 4
PROXY_EXPORT(WinHttpAddRequestHeaders, proxy_WinHttpAddRequestHeaders,  16) // 4

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"winhttp.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" HINTERNET WINAPI proxy_WinHttpOpen(LPCWSTR pwszUserAgent, DWORD dwAccessType, LPCWSTR pwszProxyName, LPCWSTR pwszProxyBypass, DWORD dwFlags) {
    typedef HINTERNET (WINAPI* Real_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    static Real_t real = (Real_t)GetRealProc("WinHttpOpen");
    return real ? real(pwszUserAgent, dwAccessType, pwszProxyName, pwszProxyBypass, dwFlags) : NULL;
}
extern "C" BOOL WINAPI proxy_WinHttpCloseHandle(HINTERNET hInternet) {
    typedef BOOL (WINAPI* Real_t)(HINTERNET);
    static Real_t real = (Real_t)GetRealProc("WinHttpCloseHandle");
    return real ? real(hInternet) : FALSE;
}
extern "C" HINTERNET WINAPI proxy_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
    typedef HINTERNET (WINAPI* Real_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    static Real_t real = (Real_t)GetRealProc("WinHttpConnect");
    return real ? real(hSession, pswzServerName, nServerPort, dwReserved) : NULL;
}
extern "C" HINTERNET WINAPI proxy_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags) {
    typedef HINTERNET (WINAPI* Real_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    static Real_t real = (Real_t)GetRealProc("WinHttpOpenRequest");
    return real ? real(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags) : NULL;
}
extern "C" BOOL WINAPI proxy_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
    typedef BOOL (WINAPI* Real_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    static Real_t real = (Real_t)GetRealProc("WinHttpSendRequest");
    return real ? real(hRequest, lpwszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext) : FALSE;
}
extern "C" BOOL WINAPI proxy_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved) {
    typedef BOOL (WINAPI* Real_t)(HINTERNET, LPVOID);
    static Real_t real = (Real_t)GetRealProc("WinHttpReceiveResponse");
    return real ? real(hRequest, lpReserved) : FALSE;
}
extern "C" BOOL WINAPI proxy_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    typedef BOOL (WINAPI* Real_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("WinHttpReadData");
    return real ? real(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead) : FALSE;
}
extern "C" BOOL WINAPI proxy_WinHttpQueryDataAvailable(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable) {
    typedef BOOL (WINAPI* Real_t)(HINTERNET, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("WinHttpQueryDataAvailable");
    return real ? real(hRequest, lpdwNumberOfBytesAvailable) : FALSE;
}
extern "C" BOOL WINAPI proxy_WinHttpQueryHeaders(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) {
    typedef BOOL (WINAPI* Real_t)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("WinHttpQueryHeaders");
    return real ? real(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex) : FALSE;
}
extern "C" BOOL WINAPI proxy_WinHttpSetOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) {
    typedef BOOL (WINAPI* Real_t)(HINTERNET, DWORD, LPVOID, DWORD);
    static Real_t real = (Real_t)GetRealProc("WinHttpSetOption");
    return real ? real(hInternet, dwOption, lpBuffer, dwBufferLength) : FALSE;
}
extern "C" BOOL WINAPI proxy_WinHttpAddRequestHeaders(HINTERNET hRequest, LPCWSTR lpwszHeaders, DWORD dwHeadersLength, DWORD dwModifiers) {
    typedef BOOL (WINAPI* Real_t)(HINTERNET, LPCWSTR, DWORD, DWORD);
    static Real_t real = (Real_t)GetRealProc("WinHttpAddRequestHeaders");
    return real ? real(hRequest, lpwszHeaders, dwHeadersLength, dwModifiers) : FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD, LPVOID) { DisableThreadLibraryCalls(hModule); return TRUE; }
