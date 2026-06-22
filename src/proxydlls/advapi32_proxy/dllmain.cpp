#include <windows.h>
#include "Logger.h"
#include "ProxyExport.h"

static Logger g_logger;

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"advapi32.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

// ── Registry spoofing for CPU brand string ──────────────────────────────
static const WCHAR* SPOOFED_BRAND = L"Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz";
static const WCHAR TARGET_PATH[] = L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
static const WCHAR TARGET_VALUE[] = L"ProcessorNameString";

// Track opened key handles -> wheter they match the target path
struct KeyEntry { bool matched; };
static KeyEntry keyMap[64];
static int keyCount = 0;

static int FindKeySlot(HKEY hKey)
{
    for (int i = 0; i < keyCount; i++)
        if (&keyMap[i] == (KeyEntry*)hKey) return i;
    return -1;
}

extern "C" LSTATUS WINAPI Proxy_RegOpenKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    typedef LSTATUS (WINAPI* Real_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    static Real_t real = (Real_t)GetRealProc("RegOpenKeyExW");
    LSTATUS ret = real ? real(hKey, lpSubKey, ulOptions, samDesired, phkResult) : ERROR_FILE_NOT_FOUND;
    if (ret == ERROR_SUCCESS && phkResult && lpSubKey && keyCount < 64) {
        bool matched = (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE,
            lpSubKey, -1, TARGET_PATH, -1) == CSTR_EQUAL);
        keyMap[keyCount].matched = matched;
        *phkResult = (HKEY)&keyMap[keyCount];
        keyCount++;
    }
    return ret;
}

extern "C" LSTATUS WINAPI Proxy_RegQueryValueExW(
    HKEY hKey, LPCWSTR lpValue, LPDWORD lpReserved, LPDWORD lpType,
    LPBYTE lpData, LPDWORD lpcbData)
{
    // Check if this handle is one of our tracked keys
    int slot = FindKeySlot(hKey);
    if (slot >= 0 && keyMap[slot].matched && lpValue &&
        CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, lpValue, -1, TARGET_VALUE, -1) == CSTR_EQUAL) {
        DWORD needed = (DWORD)((wcslen(SPOOFED_BRAND) + 1) * sizeof(WCHAR));
        if (lpType) *lpType = REG_SZ;
        if (lpcbData) {
            if (lpData && *lpcbData >= needed)
                wcscpy((WCHAR*)lpData, SPOOFED_BRAND);
            *lpcbData = needed;
        }
        return ERROR_SUCCESS;
    }

    typedef LSTATUS (WINAPI* Real_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("RegQueryValueExW");
    return real ? real(hKey, lpValue, lpReserved, lpType, lpData, lpcbData) : ERROR_FILE_NOT_FOUND;
}

extern "C" LSTATUS WINAPI Proxy_RegCloseKey(HKEY hKey)
{
    typedef LSTATUS (WINAPI* Real_t)(HKEY);
    static Real_t real = (Real_t)GetRealProc("RegCloseKey");
    return real ? real(hKey) : ERROR_SUCCESS;
}

extern "C" LSTATUS WINAPI Proxy_RegCreateKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions,
    REGSAM samDesired, LPSECURITY_ATTRIBUTES lpAttr, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    typedef LSTATUS (WINAPI* Real_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
        LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("RegCreateKeyExW");
    return real ? real(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
        lpAttr, phkResult, lpdwDisposition) : ERROR_FILE_NOT_FOUND;
}

extern "C" LSTATUS WINAPI Proxy_RegEnumKeyExW(
    HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved,
    LPWSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWrite)
{
    typedef LSTATUS (WINAPI* Real_t)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD,
        LPWSTR, LPDWORD, PFILETIME);
    static Real_t real = (Real_t)GetRealProc("RegEnumKeyExW");
    return real ? real(hKey, dwIndex, lpName, lpcchName, lpReserved,
        lpClass, lpcchClass, lpftLastWrite) : ERROR_NO_MORE_ITEMS;
}

extern "C" LSTATUS WINAPI Proxy_RegEnumValueW(
    HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    typedef LSTATUS (WINAPI* Real_t)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD,
        LPDWORD, LPBYTE, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("RegEnumValueW");
    return real ? real(hKey, dwIndex, lpName, lpcchName, lpReserved,
        lpType, lpData, lpcbData) : ERROR_NO_MORE_ITEMS;
}

// argbytes = paramCount * 4 (all params are 4-byte scalars/pointers)
PROXY_EXPORT(RegOpenKeyExW,     Proxy_RegOpenKeyExW,     20) // HKEY,LPCWSTR,DWORD,REGSAM,PHKEY
PROXY_EXPORT(RegQueryValueExW,  Proxy_RegQueryValueExW,  24) // HKEY,LPCWSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD
PROXY_EXPORT(RegCloseKey,       Proxy_RegCloseKey,        4) // HKEY
PROXY_EXPORT(RegCreateKeyExW,   Proxy_RegCreateKeyExW,   36) // HKEY,LPCWSTR,DWORD,LPWSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD
PROXY_EXPORT(RegEnumKeyExW,     Proxy_RegEnumKeyExW,     32) // HKEY,DWORD,LPWSTR,LPDWORD,LPDWORD,LPWSTR,LPDWORD,PFILETIME
PROXY_EXPORT(RegEnumValueW,     Proxy_RegEnumValueW,     32) // HKEY,DWORD,LPWSTR,LPDWORD,LPDWORD,LPDWORD,LPBYTE,LPDWORD

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            g_logger.Init();
            g_logger.Trace(LOG_PROXY, "advapi32_proxy loaded");
            DisableThreadLibraryCalls(hModule);
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}