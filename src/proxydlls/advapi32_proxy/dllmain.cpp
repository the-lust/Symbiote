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

// Track opened key handles -> whether they match the target path.
// A prior version replaced *phkResult with a fabricated pointer into this array instead of
// returning the real HKEY, which: (a) leaked the real handle forever (RegCloseKey forwarded
// the fake pointer to the real RegCloseKey, which just failed on it), (b) broke every other
// registry call on that "handle" since it was never valid to begin with — querying any value
// other than the one intercepted one under the spoofed key forwarded to the real API with a
// bogus pointer, guaranteed to fail, and (c) filled from every RegOpenKeyExW in the whole
// process (not just the CPU key), silently exhausting the table and disabling the spoof.
// Track by the *real* HKEY instead and always return it unmodified to the caller.
struct KeyEntry { HKEY realHandle; bool matched; };
static KeyEntry keyMap[64];
static int keyCount = 0;
static CRITICAL_SECTION s_keyMapCs;
static INIT_ONCE s_keyMapCsInitOnce = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK InitKeyMapCsOnce(PINIT_ONCE, PVOID, PVOID*) { InitializeCriticalSection(&s_keyMapCs); return TRUE; }
static void EnsureKeyMapCsInit() { InitOnceExecuteOnce(&s_keyMapCsInitOnce, InitKeyMapCsOnce, nullptr, nullptr); }

static int FindKeySlot(HKEY hKey)
{
    for (int i = 0; i < keyCount; i++)
        if (keyMap[i].realHandle == hKey) return i;
    return -1;
}

extern "C" LSTATUS WINAPI Proxy_RegOpenKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    typedef LSTATUS (WINAPI* Real_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    static Real_t real = (Real_t)GetRealProc("RegOpenKeyExW");
    LSTATUS ret = real ? real(hKey, lpSubKey, ulOptions, samDesired, phkResult) : ERROR_FILE_NOT_FOUND;
    if (ret == ERROR_SUCCESS && phkResult && lpSubKey) {
        EnsureKeyMapCsInit();
        bool matched = (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE,
            lpSubKey, -1, TARGET_PATH, -1) == CSTR_EQUAL);
        EnterCriticalSection(&s_keyMapCs);
        if (keyCount < 64) {
            keyMap[keyCount].realHandle = *phkResult;
            keyMap[keyCount].matched = matched;
            keyCount++;
        }
        LeaveCriticalSection(&s_keyMapCs);
        // *phkResult is intentionally left untouched — it's the real handle from the real call.
    }
    return ret;
}

extern "C" LSTATUS WINAPI Proxy_RegQueryValueExW(
    HKEY hKey, LPCWSTR lpValue, LPDWORD lpReserved, LPDWORD lpType,
    LPBYTE lpData, LPDWORD lpcbData)
{
    // Check if this handle is one of our tracked keys
    EnsureKeyMapCsInit();
    EnterCriticalSection(&s_keyMapCs);
    int slot = FindKeySlot(hKey);
    bool isMatchedSlot = (slot >= 0 && keyMap[slot].matched);
    LeaveCriticalSection(&s_keyMapCs);
    if (isMatchedSlot && lpValue &&
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

    // Free this handle's tracking slot (swap-with-last) so a long-running process's ordinary
    // registry traffic doesn't permanently exhaust the 64-slot table.
    EnsureKeyMapCsInit();
    EnterCriticalSection(&s_keyMapCs);
    int slot = FindKeySlot(hKey);
    if (slot >= 0) {
        keyMap[slot] = keyMap[keyCount - 1];
        keyCount--;
    }
    LeaveCriticalSection(&s_keyMapCs);

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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
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