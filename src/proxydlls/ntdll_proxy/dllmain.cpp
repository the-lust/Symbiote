// Credits: IPC filtering adapted from Sandboxie (https://github.com/sandboxie-plus/Sandboxie)
// Registry redirection adapted from Sandboxie (https://github.com/sandboxie-plus/Sandboxie)
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

// ── IpcFilter exports (lazy-loaded from engine.dll) ──────────────────────
typedef BOOL (__stdcall* IpcFilter_ShouldBlockAlpc_t)(const wchar_t*);
typedef BOOL (__stdcall* IpcFilter_ShouldBlockPipe_t)(const wchar_t*);

static IpcFilter_ShouldBlockAlpc_t g_fnBlockAlpc = nullptr;
static IpcFilter_ShouldBlockPipe_t g_fnBlockPipe = nullptr;

static void InitIpcFilter()
{
    static bool init = false;
    if (init) return;
    init = true;
    HMODULE hEngine = GetModuleHandleW(L"engine.dll");
    if (hEngine) {
        g_fnBlockAlpc = (IpcFilter_ShouldBlockAlpc_t)GetProcAddress(hEngine, "IpcFilter_ShouldBlockAlpc");
        g_fnBlockPipe = (IpcFilter_ShouldBlockPipe_t)GetProcAddress(hEngine, "IpcFilter_ShouldBlockPipe");
    }
}

// ── NtAlpcConnectPort hook ──────────────────────────────────────────────
// Forward declarations for types not in winternl.h
typedef struct _ALPC_PORT_ATTRIBUTES* PALPC_PORT_ATTRIBUTES;

typedef NTSTATUS (NTAPI* RealNtAlpcConnectPort_t)(
    PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID,
    PALPC_PORT_ATTRIBUTES, PVOID, PVOID, PULONG);

extern "C" NTSTATUS NTAPI Proxy_NtAlpcConnectPort(
    PHANDLE PortHandle, PUNICODE_STRING PortName, POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Flags, ULONG RequiredServerSid, PVOID ConnectionMessage,
    PALPC_PORT_ATTRIBUTES PortAttributes, PVOID TargetSid, PVOID ConnectionContext,
    PULONG MaxMessageLength)
{
    InitIpcFilter();
    if (g_fnBlockAlpc && PortName && PortName->Buffer && PortName->Length > 0) {
        std::wstring name(PortName->Buffer, PortName->Length / sizeof(wchar_t));
        if (g_fnBlockAlpc(name.c_str())) {
            g_logger.Trace(LOG_PROXY, "NtAlpcConnectPort BLOCKED: %ls", name.c_str());
            return STATUS_ACCESS_DENIED;
        }
    }

    static RealNtAlpcConnectPort_t realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (RealNtAlpcConnectPort_t)GetProcAddress(realNtdll, "NtAlpcConnectPort");
    }
    return realFunc ? realFunc(PortHandle, PortName, ObjectAttributes, Flags,
        RequiredServerSid, ConnectionMessage, PortAttributes, TargetSid, ConnectionContext, MaxMessageLength)
        : STATUS_UNSUCCESSFUL;
}

// ── NtCreateNamedPipeFile hook ─────────────────────────────────────────
extern "C" NTSTATUS NTAPI Proxy_NtCreateNamedPipeFile(
    PHANDLE NamedPipeHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, ULONG WriteMode, ULONG ReadMode, ULONG NonBlockingMode,
    ULONG MaxInstances, ULONG InBufferSize, ULONG OutBufferSize,
    PLARGE_INTEGER DefaultTimeout)
{
    InitIpcFilter();
    if (g_fnBlockPipe && ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer) {
        std::wstring path(ObjectAttributes->ObjectName->Buffer,
            ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
        if (g_fnBlockPipe(path.c_str())) {
            g_logger.Trace(LOG_PROXY, "NtCreateNamedPipeFile BLOCKED: %ls", path.c_str());
            return STATUS_ACCESS_DENIED;
        }
    }

    static decltype(&Proxy_NtCreateNamedPipeFile) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtCreateNamedPipeFile))GetProcAddress(realNtdll, "NtCreateNamedPipeFile");
    }
    return realFunc ? realFunc(NamedPipeHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        ShareAccess, CreateDisposition, CreateOptions, WriteMode, ReadMode, NonBlockingMode,
        MaxInstances, InBufferSize, OutBufferSize, DefaultTimeout)
        : STATUS_UNSUCCESSFUL;
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
    static const char* sysInfoClasses[] = {
        "SystemBasicInformation", "SystemProcessorInformation",
        "SystemPerformanceInformation", "SystemTimeOfDayInformation",
        "SystemNotImplemented1", "SystemProcessInformation",
        "SystemProcessorPerformanceInformation", "SystemInterruptInformation",
        "SystemExceptionInformation", "SystemNotImplemented2"
    };
    g_logger.Trace(LOG_PROXY, "CAPTURE NtQuerySystemInformation class=%u (%s) len=%u",
        InfoClass,
        InfoClass < 10 ? sysInfoClasses[InfoClass] : "unknown",
        Length);

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
    NTSTATUS ret = realFunc ? realFunc(InfoClass, Info, Length, ReturnLength) : STATUS_UNSUCCESSFUL;
    if (InfoClass == 0x8 && ReturnLength) {
        g_logger.Trace(LOG_PROXY, "CAPTURE NtQuerySysInfo[SystemProcessorPerf] result=0x%X retLen=%u",
            ret, ReturnLength ? *ReturnLength : 0);
    }
    return ret;
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

// ── PEB debug flags ─────────────────────────────────────────────────────
static void FixPebDebugFlags()
{
    uint8_t* peb = (uint8_t*)__readgsqword(0x60);
    if (!peb) return;

    peb[0x02] = 0;

#ifdef _WIN64
    *(uint32_t*)(peb + 0xBC) = 0;
#else
    *(uint32_t*)(peb + 0x68) = 0;
#endif

    void* heapPtr = nullptr;
#ifdef _WIN64
    heapPtr = *(void**)(peb + 0x30);
#else
    heapPtr = *(void**)(peb + 0x18);
#endif
    if (heapPtr) {
        uint8_t* heap = (uint8_t*)heapPtr;
#ifdef _WIN64
        *(uint32_t*)(heap + 0x44) = 0x00000002;
        *(uint32_t*)(heap + 0x48) = 0;
#else
        *(uint32_t*)(heap + 0x0C) = 0x00000002;
        *(uint32_t*)(heap + 0x10) = 0;
#endif
    }
}

// ── NtSetInformationProcess (anti-debug: block instrumentation callback) ─
extern "C" NTSTATUS NTAPI Proxy_NtSetInformationProcess(
    HANDLE ProcessHandle, ULONG InfoClass, PVOID Info, ULONG Length)
{
    if (InfoClass == 0x28) {
        g_logger.Trace(LOG_PROXY, "NtSetInformationProcess: blocked ProcessInstrumentationCallback");
        return STATUS_ACCESS_DENIED;
    }

    static decltype(&Proxy_NtSetInformationProcess) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtSetInformationProcess))GetProcAddress(realNtdll, "NtSetInformationProcess");
    }
    return realFunc ? realFunc(ProcessHandle, InfoClass, Info, Length) : STATUS_UNSUCCESSFUL;
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

// ── RegistryRedirection hooks (route through engine's RegistryEmu) ──────

extern "C" NTSTATUS NTAPI Proxy_NtCreateKey(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition)
{
    RouteSyscall_t route = GetRouteSyscall();
    if (route) {
        uint64_t args[7] = { (uint64_t)KeyHandle, DesiredAccess, (uint64_t)ObjectAttributes,
            TitleIndex, (uint64_t)Class, CreateOptions, (uint64_t)Disposition };
        uint64_t result = 0;
        if (route(0x0014, args, &result))
            return (NTSTATUS)result;
    }

    static decltype(&Proxy_NtCreateKey) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtCreateKey))GetProcAddress(realNtdll, "NtCreateKey");
    }
    return realFunc ? realFunc(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition)
        : STATUS_UNSUCCESSFUL;
}

extern "C" NTSTATUS NTAPI Proxy_NtEnumerateKey(
    HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass, PVOID KeyInformation,
    ULONG Length, PULONG ResultLength)
{
    RouteSyscall_t route = GetRouteSyscall();
    if (route) {
        uint64_t args[6] = { (uint64_t)KeyHandle, Index, KeyInformationClass, (uint64_t)KeyInformation, Length, (uint64_t)ResultLength };
        uint64_t result = 0;
        if (route(0x0012, args, &result))
            return (NTSTATUS)result;
    }

    static decltype(&Proxy_NtEnumerateKey) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtEnumerateKey))GetProcAddress(realNtdll, "NtEnumerateKey");
    }
    return realFunc ? realFunc(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength)
        : STATUS_UNSUCCESSFUL;
}

extern "C" NTSTATUS NTAPI Proxy_NtEnumerateValueKey(
    HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength)
{
    RouteSyscall_t route = GetRouteSyscall();
    if (route) {
        uint64_t args[6] = { (uint64_t)KeyHandle, Index, KeyValueInformationClass, (uint64_t)KeyValueInformation, Length, (uint64_t)ResultLength };
        uint64_t result = 0;
        if (route(0x0013, args, &result))
            return (NTSTATUS)result;
    }

    static decltype(&Proxy_NtEnumerateValueKey) realFunc = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE realNtdll = GetRealNtdll();
        if (realNtdll) realFunc = (decltype(&Proxy_NtEnumerateValueKey))GetProcAddress(realNtdll, "NtEnumerateValueKey");
    }
    return realFunc ? realFunc(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)
        : STATUS_UNSUCCESSFUL;
}

// argbytes = paramCount * 4 (NTAPI == __stdcall on x86)
PROXY_EXPORT(NtCreateFile,                Proxy_NtCreateFile,                36)
PROXY_EXPORT(NtQuerySystemInformation,    Proxy_NtQuerySystemInformation,    16)
PROXY_EXPORT(NtQueryInformationProcess,   Proxy_NtQueryInformationProcess,   20)
PROXY_EXPORT(NtSetInformationProcess,     Proxy_NtSetInformationProcess,     16)
PROXY_EXPORT(NtOpenKey,                   Proxy_NtOpenKey,                   12)
PROXY_EXPORT(NtQueryValueKey,             Proxy_NtQueryValueKey,             24)
PROXY_EXPORT(NtAlpcConnectPort,           Proxy_NtAlpcConnectPort,           40)
PROXY_EXPORT(NtCreateNamedPipeFile,       Proxy_NtCreateNamedPipeFile,       56)
PROXY_EXPORT(NtCreateKey,                 Proxy_NtCreateKey,                 28)
PROXY_EXPORT(NtEnumerateKey,              Proxy_NtEnumerateKey,              24)
PROXY_EXPORT(NtEnumerateValueKey,         Proxy_NtEnumerateValueKey,         24)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            g_logger.Init();
            g_logger.Trace(LOG_PROXY, "ntdll_proxy loaded");
            DisableThreadLibraryCalls(hModule);
            FixPebDebugFlags();
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
