#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <string>
#include <algorithm>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include "Logger.h"
#include "ProxyExport.h"

// KEY_VALUE_PARTIAL_INFORMATION from ntddk.h
typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

static Logger g_logger;

// load real ntdll for passthru
static HMODULE GetRealNtdll()
{
    static HMODULE realNtdll = nullptr;
    if (!realNtdll) {
        wchar_t sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring path = std::wstring(sysDir) + L"\\ntdll.dll";
        realNtdll = LoadLibraryW(path.c_str());
    }
    return realNtdll;
}

typedef bool (__stdcall* RouteSyscall_t)(uint64_t, uint64_t*, uint64_t*);
static RouteSyscall_t GetRouteSyscall()
{
    static RouteSyscall_t route = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE hEngine = GetModuleHandleW(L"engine.dll");
        if (hEngine) {
            route = (RouteSyscall_t)GetProcAddress(hEngine, "RouteSyscall");
        }
    }
    return route;
}

extern "C" NTSTATUS NTAPI Proxy_NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions)
{
    static decltype(&Proxy_NtCreateFile) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtCreateFile))GetProcAddress(realNtdll, "NtCreateFile");
    }

    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
        std::wstring path(ObjectAttributes->ObjectName->Buffer,
            ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
        std::transform(path.begin(), path.end(), path.begin(), ::towlower);

        if (path.find(L"\\device\\physicaldrive") != std::wstring::npos ||
            path.find(L"vmware") != std::wstring::npos ||
            path.find(L"vbox") != std::wstring::npos) {
            g_logger.Trace(LOG_PROXY, "NtCreateFile BLOCKED: %ls", path.c_str());
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    if (realFunc) {
        return realFunc(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                        AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions);
    }
    return STATUS_UNSUCCESSFUL;
}

struct NtQuerySystemInfoArgs {
    ULONG InfoClass;
    PVOID Info;
    ULONG Length;
    PULONG ReturnLength;
};

extern "C" NTSTATUS NTAPI Proxy_NtQuerySystemInformation(
    ULONG InfoClass, PVOID Info, ULONG Length, PULONG ReturnLength)
{
    RouteSyscall_t route = GetRouteSyscall();
    if (route) {
        uint64_t args[4] = { InfoClass, (uint64_t)Info, Length, (uint64_t)ReturnLength };
        uint64_t result = 0;
        if (route(0x0001, args, &result)) {
            return (NTSTATUS)result;
        }
    }

    static decltype(&Proxy_NtQuerySystemInformation) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtQuerySystemInformation))GetProcAddress(realNtdll, "NtQuerySystemInformation");
    }
    if (realFunc) return realFunc(InfoClass, Info, Length, ReturnLength);
    return STATUS_UNSUCCESSFUL;
}

struct NtQueryInformationProcessArgs {
    HANDLE ProcessHandle;
    ULONG InfoClass;
    PVOID Info;
    ULONG Length;
    PULONG ReturnLength;
};

extern "C" NTSTATUS NTAPI Proxy_NtQueryInformationProcess(
    HANDLE ProcessHandle, ULONG InfoClass, PVOID Info, ULONG Length, PULONG ReturnLength)
{
    RouteSyscall_t route = GetRouteSyscall();
    if (route) {
        uint64_t args[5] = { (uint64_t)ProcessHandle, InfoClass, (uint64_t)Info, Length, (uint64_t)ReturnLength };
        uint64_t result = 0;
        if (route(0x0002, args, &result)) {
            return (NTSTATUS)result;
        }
    }

    static decltype(&Proxy_NtQueryInformationProcess) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtQueryInformationProcess))GetProcAddress(realNtdll, "NtQueryInformationProcess");
    }
    if (realFunc) return realFunc(ProcessHandle, InfoClass, Info, Length, ReturnLength);
    return STATUS_UNSUCCESSFUL;
}

// ── Registry spoofing for CPU brand string ──────────────────────────────
static const WCHAR* SPOOFED_BRAND = L"Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz";

struct TrackedKey {
    HANDLE realHandle;
    bool isCentralProcessor;
};
static TrackedKey s_trackedKeys[64];
static int s_trackedCount = 0;
static CRITICAL_SECTION s_trackedCs;

static int FindTrackedSlot(HANDLE h)
{
    for (int i = 0; i < s_trackedCount; i++)
        if (s_trackedKeys[i].realHandle == h) return i;
    return -1;
}

extern "C" NTSTATUS NTAPI Proxy_NtOpenKey(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
    static decltype(&Proxy_NtOpenKey) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        InitializeCriticalSection(&s_trackedCs);
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtOpenKey))GetProcAddress(realNtdll, "NtOpenKey");
    }

    if (!realFunc) return STATUS_UNSUCCESSFUL;
    NTSTATUS status = realFunc(KeyHandle, DesiredAccess, ObjectAttributes);

    if (NT_SUCCESS(status) && KeyHandle && *KeyHandle &&
        ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer) {
        std::wstring path(ObjectAttributes->ObjectName->Buffer,
            ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
        std::transform(path.begin(), path.end(), path.begin(), ::towlower);

        // Track HARDWARE\DESCRIPTION\System\CentralProcessor\0
        bool match = (path.find(L"hardware\\description\\system\\centralprocessor\\0") != std::wstring::npos);
        if (match && s_trackedCount < 64) {
            EnterCriticalSection(&s_trackedCs);
            s_trackedKeys[s_trackedCount].realHandle = *KeyHandle;
            s_trackedKeys[s_trackedCount].isCentralProcessor = true;
            s_trackedCount++;
            LeaveCriticalSection(&s_trackedCs);
            g_logger.Trace(LOG_PROXY, "NtOpenKey: tracking CentralProcessor handle %p", *KeyHandle);
        }
    }
    return status;
}

extern "C" NTSTATUS NTAPI Proxy_NtQueryValueKey(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG KeyValueInformationLength, PULONG ResultLength)
{
    // Check if this is our tracked CentralProcessor key
    EnterCriticalSection(&s_trackedCs);
    int slot = FindTrackedSlot(KeyHandle);
    bool isCp = (slot >= 0 && s_trackedKeys[slot].isCentralProcessor);
    LeaveCriticalSection(&s_trackedCs);

    if (isCp && ValueName && ValueName->Buffer && ValueName->Length > 0) {
        std::wstring valName(ValueName->Buffer, ValueName->Length / sizeof(wchar_t));
        if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE,
            valName.c_str(), -1, L"ProcessorNameString", -1) == CSTR_EQUAL) {

            DWORD brandLen = (DWORD)((wcslen(SPOOFED_BRAND) + 1) * sizeof(WCHAR));
            if (ResultLength) *ResultLength = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + brandLen;

            if (KeyValueInformation && KeyValueInformationLength >= sizeof(KEY_VALUE_PARTIAL_INFORMATION)) {
                PKEY_VALUE_PARTIAL_INFORMATION pvi = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;
                ULONG needed = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + brandLen;
                if (KeyValueInformationLength >= needed) {
                    pvi->Type = REG_SZ;
                    pvi->DataLength = brandLen;
                    memcpy(pvi->Data, SPOOFED_BRAND, brandLen);
                    if (ResultLength) *ResultLength = needed;
                    g_logger.Trace(LOG_PROXY, "NtQueryValueKey: spoofed ProcessorNameString");
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_BUFFER_TOO_SMALL;
        }
    }

    static decltype(&Proxy_NtQueryValueKey) realFunc = nullptr;
    static bool init2 = false;
    if (!init2) {
        init2 = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtQueryValueKey))GetProcAddress(realNtdll, "NtQueryValueKey");
    }
    return realFunc ? realFunc(KeyHandle, ValueName, KeyValueInformationClass,
        KeyValueInformation, KeyValueInformationLength, ResultLength) : STATUS_UNSUCCESSFUL;
}

// argbytes = paramCount * 4 (NTAPI == __stdcall on x86)
PROXY_EXPORT(NtCreateFile,                Proxy_NtCreateFile,                36) // PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG
PROXY_EXPORT(NtQuerySystemInformation,    Proxy_NtQuerySystemInformation,    16) // ULONG,PVOID,ULONG,PULONG
PROXY_EXPORT(NtQueryInformationProcess,   Proxy_NtQueryInformationProcess,   20) // HANDLE,ULONG,PVOID,ULONG,PULONG
PROXY_EXPORT(NtOpenKey,                   Proxy_NtOpenKey,                   12) // PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES
PROXY_EXPORT(NtQueryValueKey,             Proxy_NtQueryValueKey,             24) // HANDLE,PUNICODE_STRING,ULONG,PVOID,ULONG,PULONG

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            g_logger.Init();
            g_logger.Trace(LOG_PROXY, "ntdll_proxy loaded");
            DisableThreadLibraryCalls(hModule);
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
