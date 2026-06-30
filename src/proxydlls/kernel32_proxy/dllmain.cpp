#include <windows.h>
#include "Logger.h"
#include "ProxyExport.h"

static Logger g_logger;

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"kernel32.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" BOOL WINAPI Proxy_CreateProcessW(
    LPCWSTR lpApp, LPWSTR lpCmd, LPSECURITY_ATTRIBUTES pProc,
    LPSECURITY_ATTRIBUTES pThread, BOOL bInherit, DWORD dwFlags,
    LPVOID lpEnv, LPCWSTR lpDir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    typedef BOOL (WINAPI* Real_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    static Real_t real = (Real_t)GetRealProc("CreateProcessW");
    return real ? real(lpApp, lpCmd, pProc, pThread, bInherit, dwFlags, lpEnv, lpDir, si, pi) : FALSE;
}

extern "C" HMODULE WINAPI Proxy_GetModuleHandleW(LPCWSTR lpName)
{
    typedef HMODULE (WINAPI* Real_t)(LPCWSTR);
    static Real_t real = (Real_t)GetRealProc("GetModuleHandleW");
    return real ? real(lpName) : nullptr;
}

extern "C" LPVOID WINAPI Proxy_VirtualAllocEx(
    HANDLE hProc, LPVOID lpAddr, SIZE_T sz, DWORD allocType, DWORD protect)
{
    typedef LPVOID (WINAPI* Real_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    static Real_t real = (Real_t)GetRealProc("VirtualAllocEx");
    return real ? real(hProc, lpAddr, sz, allocType, protect) : nullptr;
}

extern "C" BOOL WINAPI Proxy_WriteProcessMemory(
    HANDLE hProc, LPVOID lpAddr, LPCVOID lpBuf, SIZE_T sz, SIZE_T* lpBytes)
{
    typedef BOOL (WINAPI* Real_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    static Real_t real = (Real_t)GetRealProc("WriteProcessMemory");
    return real ? real(hProc, lpAddr, lpBuf, sz, lpBytes) : FALSE;
}

extern "C" BOOL WINAPI Proxy_GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize)
{
    // capture: log before spoofing
    typedef BOOL (WINAPI* Real_t)(LPWSTR, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("GetComputerNameW");
    g_logger.Trace(LOG_PROXY, "CAPTURE GetComputerNameW called");

    // spoof computer name to hide real hostname
    static const wchar_t spoofed[] = L"DESKTOP-ABCDEFG";
    DWORD len = (DWORD)wcslen(spoofed);
    if (*nSize < len + 1) {
        *nSize = len + 1;
        return FALSE;
    }
    wcscpy_s(lpBuffer, *nSize, spoofed);
    *nSize = len;
    return TRUE;
}

extern "C" BOOL WINAPI Proxy_GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{
    // capture: log before spoofing
    typedef BOOL (WINAPI* Real_t)(LPWSTR, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("GetUserNameW");
    g_logger.Trace(LOG_PROXY, "CAPTURE GetUserNameW called");

    // spoof username
    static const wchar_t spoofed[] = L"User";
    DWORD len = (DWORD)wcslen(spoofed);
    if (*pcbBuffer < len + 1) {
        *pcbBuffer = len + 1;
        return FALSE;
    }
    wcscpy_s(lpBuffer, *pcbBuffer, spoofed);
    *pcbBuffer = len;
    return TRUE;
}

extern "C" HANDLE WINAPI Proxy_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    typedef HANDLE (WINAPI* Real_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    static Real_t real = (Real_t)GetRealProc("CreateFileW");

    g_logger.Trace(LOG_PROXY, "CAPTURE CreateFileW: %ls", lpFileName ? lpFileName : L"(null)");

    // block physical drive access - reveal serial
    if (lpFileName && wcsstr(lpFileName, L"\\\\.\\PhysicalDrive") != nullptr) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    return real ? real(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) : INVALID_HANDLE_VALUE;
}

extern "C" HANDLE WINAPI Proxy_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    typedef HANDLE (WINAPI* Real_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    static Real_t real = (Real_t)GetRealProc("CreateFileA");

    g_logger.Trace(LOG_PROXY, "CAPTURE CreateFileA: %s", lpFileName ? lpFileName : "(null)");

    if (lpFileName && strstr(lpFileName, "\\\\.\\PhysicalDrive") != nullptr) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    return real ? real(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) : INVALID_HANDLE_VALUE;
}

extern "C" BOOL WINAPI Proxy_GetVolumeInformationW(
    LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
    LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
    LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    typedef BOOL (WINAPI* Real_t)(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);
    static Real_t real = (Real_t)GetRealProc("GetVolumeInformationW");
    g_logger.Trace(LOG_PROXY, "CAPTURE GetVolumeInformationW: %ls", lpRootPathName ? lpRootPathName : L"(null)");

    if (!lpRootPathName || lpRootPathName[0] == L'\0') {
        return real ? real(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize,
            lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags,
            lpFileSystemNameBuffer, nFileSystemNameSize) : FALSE;
    }

    // Only spoof for root drive paths (C:\, D:\, etc.)
    if (lpRootPathName[0] >= L'A' && lpRootPathName[0] <= L'Z' && lpRootPathName[1] == L':' && lpRootPathName[2] == L'\\') {
        if (lpVolumeSerialNumber) *lpVolumeSerialNumber = 0x1A2B3C4D;
        if (lpMaximumComponentLength) *lpMaximumComponentLength = 255;
        if (lpFileSystemFlags) *lpFileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
            FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS | FILE_FILE_COMPRESSION |
            FILE_VOLUME_QUOTAS | FILE_SUPPORTS_SPARSE_FILES | FILE_SUPPORTS_REPARSE_POINTS |
            FILE_SUPPORTS_EXTENDED_ATTRIBUTES | FILE_NAMED_STREAMS | FILE_READ_ONLY_VOLUME;
        if (lpVolumeNameBuffer && nVolumeNameSize > 0) {
            wcscpy_s(lpVolumeNameBuffer, nVolumeNameSize, L"System");
        }
        if (lpFileSystemNameBuffer && nFileSystemNameSize > 0) {
            wcscpy_s(lpFileSystemNameBuffer, nFileSystemNameSize, L"NTFS");
        }
        return TRUE;
    }

    return real ? real(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize,
        lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags,
        lpFileSystemNameBuffer, nFileSystemNameSize) : FALSE;
}

extern "C" UINT WINAPI Proxy_GetWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize)
{
    typedef UINT (WINAPI* Real_t)(LPWSTR, UINT);
    static Real_t real = (Real_t)GetRealProc("GetWindowsDirectoryW");
    g_logger.Trace(LOG_PROXY, "CAPTURE GetWindowsDirectoryW called");

    static const wchar_t spoofedPath[] = L"C:\\Windows";
    DWORD len = (DWORD)wcslen(spoofedPath);
    if (uSize < len + 1) {
        return len + 1;
    }
    wcscpy_s(lpBuffer, uSize, spoofedPath);
    return len;
}

extern "C" HANDLE WINAPI Proxy_CreateRemoteThread(
    HANDLE hProc, LPSECURITY_ATTRIBUTES attr, SIZE_T stack, LPTHREAD_START_ROUTINE start,
    LPVOID param, DWORD flags, LPDWORD tid)
{
    typedef HANDLE (WINAPI* Real_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
        LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("CreateRemoteThread");
    return real ? real(hProc, attr, stack, start, param, flags, tid) : nullptr;
}

// argbytes = paramCount * 4
PROXY_EXPORT(CreateProcessW,     Proxy_CreateProcessW,     40) // 10 params
PROXY_EXPORT(GetModuleHandleW,   Proxy_GetModuleHandleW,    4) // 1
PROXY_EXPORT(VirtualAllocEx,     Proxy_VirtualAllocEx,     20) // 5
PROXY_EXPORT(WriteProcessMemory, Proxy_WriteProcessMemory, 20) // 5
PROXY_EXPORT(CreateRemoteThread, Proxy_CreateRemoteThread, 28) // 7
PROXY_EXPORT(GetComputerNameW,   Proxy_GetComputerNameW,    8) // 2
PROXY_EXPORT(GetUserNameW,       Proxy_GetUserNameW,        8) // 2
PROXY_EXPORT(CreateFileW,        Proxy_CreateFileW,        28) // 7
PROXY_EXPORT(CreateFileA,        Proxy_CreateFileA,        28) // 7
PROXY_EXPORT(GetVolumeInformationW, Proxy_GetVolumeInformationW, 32) // 8
PROXY_EXPORT(GetWindowsDirectoryW,  Proxy_GetWindowsDirectoryW,   8) // 2

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            g_logger.Init();
            g_logger.Trace(LOG_PROXY, "kernel32_proxy loaded");
            DisableThreadLibraryCalls(hModule);
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
