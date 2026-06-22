#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <string>
#include "Main.h"
#include "Logger.h"
#include "ConfigParser.h"
#include "whp/Partition.h"
#include "whp/VcpuManager.h"
#include "whp/ExitDispatcher.h"
#include "whp/CpuidHandler.h"
#include "whp/RdtscHandler.h"
#include "whp/MsrHandler.h"
#include "whp/EptHook.h"
#include "whp/KuserSync.h"
#include "whp/KuserHook.h"
#include "whp/CodePatcher.h"
#include "whp/MsrPatcher.h"
#include "whp/MagicCpuid.h"
#include "whp/ExceptionHandler.h"
#include "whp/ThreadScheduler.h"
#include "profile/CpuProfile.h"
#include "profile/GpuProfile.h"
#include "profile/StorageProfile.h"
#include "profile/TimingProfile.h"
#include "sogen/SyscallDispatcher.h"
#include "sogen/ProcessEmu.h"
#include "sogen/MemoryEmu.h"
#include "sogen/FileEmu.h"
#include "sogen/TimingEmu.h"
#include "sogen/RegistryEmu.h"
#include "sogen/CryptoEmu.h"
#include "sogen/VirtualState.h"
#include "sogen/ThreadManager.h"
#include "sogen/SoGenEmulator.h"
#include "sogen/SectionEmu.h"
#include "sogen/ObjectEmu.h"
#include "sogen/PeLoader.h"
#include "proxy/IatPatch.h"
#include "proxy/SoGenBridge.h"
#include "proxy/GpuBridge.h"
#include "proxy/InlineHook.h"

static Logger g_logger;
static Partition* g_partition = nullptr;
static VcpuManager* g_vcpuManager = nullptr;
static ExitDispatcher* g_exitDispatcher = nullptr;
static CpuidHandler* g_cpuidHandler = nullptr;
static RdtscHandler* g_rdtscHandler = nullptr;
static MsrHandler* g_msrHandler = nullptr;
static EptHook* g_eptHook = nullptr;
static KuserSync* g_kuserSync = nullptr;
static MagicCpuid* g_magicCpuid = nullptr;
static CpuProfile* g_cpuProfile = nullptr;
static GpuProfile* g_gpuProfile = nullptr;
static StorageProfile* g_storageProfile = nullptr;
static TimingProfile* g_timingProfile = nullptr;
static SyscallDispatcher* g_syscallDispatcher = nullptr;
static ProcessEmu* g_processEmu = nullptr;
static MemoryEmu* g_memoryEmu = nullptr;
static FileEmu* g_fileEmu = nullptr;
static TimingEmu* g_timingEmu = nullptr;
static RegistryEmu* g_registryEmu = nullptr;
static CryptoEmu* g_cryptoEmu = nullptr;
static VirtualState* g_virtualState = nullptr;
static ThreadManager* g_threadManager = nullptr;
static SoGenEmulator* g_soGenEmulator = nullptr;
static HMODULE g_engineModule = nullptr;
static IatPatch* g_iatPatch = nullptr;
static CodePatcher* g_codePatcher = nullptr;
static KuserHook* g_kuserHook = nullptr;
static MsrPatcher* g_msrPatcher = nullptr;
static ExceptionHandler* g_exceptionHandler = nullptr;
extern GpuBridge* g_gpuBridge;
static ThreadScheduler* g_threadScheduler = nullptr;
static SectionEmu* g_sectionEmu = nullptr;
static ObjectEmu* g_objectEmu = nullptr;
static PeLoader* g_peLoader = nullptr;
static HANDLE g_engineReadyEvent = nullptr;
static HANDLE g_engineActiveEvent = nullptr;

// inline hooks for ntdll functions (catch calls via GetProcAddress)
static InlineHook g_ntqiHook; // NtQueryInformationProcess
static void* g_ntqiTrampoline = nullptr;
static InlineHook g_ntqsiHook; // NtQuerySystemInformation
static void* g_ntqsiTrampoline = nullptr;

typedef NTSTATUS (NTAPI* NtQuerySysInfoFunc)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtQueryInfoProcessFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);

#pragma pack(push, 1)
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG ProviderSignature;
    BOOLEAN ProviderSpecific;
    BOOLEAN ACPIBufferTooSmall;
    UCHAR Reserved[2];
    ULONG FirmwareTableID;
    PVOID FirmwareTableBuffer;
    ULONG FirmwareTableBufferLength;
} SYSTEM_FIRMWARE_TABLE_INFORMATION;
#pragma pack(pop)

static void SpoofAcpiMadt(void* tableData, ULONG* tableLen)
{
    // Verify its the MADT ('APIC') table
    char* sig = (char*)tableData;
    if (sig[0] != 'A' || sig[1] != 'P' || sig[2] != 'I' || sig[3] != 'C')
        return;

    ULONG originalLen = *(ULONG*)(sig + 4);
    if (originalLen < 44 || *tableLen < 44)
        return;

    // Count existing processor entries (Type 0) and save non-processor entries
    struct SavedEntry { uint8_t data[256]; uint8_t type; uint8_t length; };
    SavedEntry saved[32];
    int savedCount = 0;
    int origProcCount = 0;

    uint8_t* pos = (uint8_t*)tableData + 44;
    uint8_t* end = (uint8_t*)tableData + originalLen;

    while (pos + 2 <= end) {
        uint8_t type = pos[0];
        uint8_t len = pos[1];
        if (len < 2 || pos + len > end) break;
        if (type == 0) {
            origProcCount++;
        } else if (savedCount < 32) {
            memcpy(saved[savedCount].data, pos, len);
            saved[savedCount].type = type;
            saved[savedCount].length = len;
            savedCount++;
        }
        pos += len;
    }

    // Build new MADT with 20 proccessor entries
    const int targetCount = 20;
    uint8_t newTable[4096];

    // Copy ACPI header (36 bytes) + LAPIC addr (4 bytes) + flags (4 bytes)
    memcpy(newTable, tableData, 44);
    uint8_t* wp = newTable + 44;

    // Write 20 processor entries (Type 0, Length 8)
    for (int i = 0; i < targetCount; i++) {
        wp[0] = 0;                     // Type = Processor Local APIC
        wp[1] = 8;                     // Length
        wp[2] = (uint8_t)i;            // ACPI Processor ID
        wp[3] = (uint8_t)i;            // APIC ID
        *(uint32_t*)(wp + 4) = 1;      // Flags = enabled
        wp += 8;
    }

    // Copy saved non-processor entrys (IO APIC, interrupt overrides, etc.)
    for (int i = 0; i < savedCount; i++) {
        memcpy(wp, saved[i].data, saved[i].length);
        wp += saved[i].length;
    }

    ULONG newLen = (ULONG)(wp - newTable);

    // Update length field in header
    *(ULONG*)(newTable + 4) = newLen;

    // Fix checkcum: sum of all bytes must be 0
    uint8_t sum = 0;
    for (ULONG i = 0; i < newLen; i++) sum += newTable[i];
    newTable[9] = (uint8_t)((uint8_t)newTable[9] - sum); // Adjust checksum byte

    if (*tableLen >= newLen) {
        memcpy(tableData, newTable, newLen);
        *tableLen = newLen;
    } else {
        *tableLen = newLen; // Indicate required size
    }
}

static NTSTATUS NTAPI HookedNtQueryInformationProcess(
    HANDLE ProcessHandle, ULONG InfoClass, PVOID Info, ULONG InfoLen, PULONG RetLen)
{
    // Intercept ProcessDebugPort (class 7) - return -1 = no debuger
    if (InfoClass == 7) {
        if (Info && InfoLen >= sizeof(int32_t)) {
            *(int32_t*)Info = -1; // 0xFFFFFFFF
            if (RetLen) *RetLen = sizeof(int32_t);
        }
        return 0; // STATUS_SUCCESS
    }

    // Intercept ProcessDebugFlags (class 31) - return 1 = no debugger
    if (InfoClass == 31) {
        if (Info && InfoLen >= sizeof(uint32_t)) {
            *(uint32_t*)Info = 1;
            if (RetLen) *RetLen = sizeof(uint32_t);
        }
        return 0;
    }

    // Intercept ProcessDebugObjectHandle (class 30 = 0x1E) - return NULL lol
    if (InfoClass == 30) {
        if (Info && InfoLen >= sizeof(HANDLE)) {
            *(HANDLE*)Info = nullptr;
            if (RetLen) *RetLen = sizeof(HANDLE);
        }
        return 0;
    }

    // Intercept ProcessBasicInformation (class 0) - return real PEB via direct syscall
    if (InfoClass == 0) {
        // Use direct syscall to avoid the broken InlineHook trampoline lol
        // Read real PEB from TEB
        uint64_t peb = (uint64_t)__readgsqword(0x60);
        if (Info && InfoLen >= sizeof(uintptr_t) * 4) {
            // Fill in a minimal ProcessBasicInformation
            memset(Info, 0, InfoLen);
            *(uintptr_t*)((uint8_t*)Info + 8) = peb; // PebBaseAddress offset
            if (RetLen) *RetLen = sizeof(uintptr_t) * 6;
        }
        return 0; // STATUS_SUCCESS
    }

    // fall through to original via trampoline
    auto realFunc = (NtQueryInfoProcessFunc)g_ntqiTrampoline;
    if (realFunc) return realFunc(ProcessHandle, InfoClass, Info, InfoLen, RetLen);
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI HookedNtQuerySystemInformation(
    ULONG InfoClass, PVOID Info, ULONG InfoLen, PULONG RetLen)
{
    uint64_t args[4] = { InfoClass, (uint64_t)Info, InfoLen, (uint64_t)RetLen };
    uint64_t result = 0;
    if (SoGenRouteSyscall(0x0001, args, &result)) {
        return (NTSTATUS)result;
    }

    // SystemKernelDebuggerInformation (35 / 0x23)
    if (InfoClass == 35 || InfoClass == 0x23) {
        if (Info && InfoLen >= 2) {
            uint8_t* kd = (uint8_t*)Info;
            kd[0] = 0; // KernelDebuggerEnabled = FALSE
            kd[1] = 1; // KernelDebuggerNotPresent = TRUE
            if (RetLen) *RetLen = 2;
        } else if (RetLen) {
            *RetLen = 2;
        }
        return STATUS_SUCCESS;
    }

    // SystemCodeIntegrityInformation (103 / 0x67)
    if (InfoClass == 103 || InfoClass == 0x67) {
        if (Info && InfoLen >= 8) {
            *(ULONG*)Info = 8;
            *(ULONG*)((uint8_t*)Info + 4) = 0; // CodeIntegrityOptions = 0 (clean)
            if (RetLen) *RetLen = 8;
        }
        return STATUS_SUCCESS;
    }

    // SystemModuleInformation (11 / 0x0B) — empty list hides unsigned drivers
    if (InfoClass == 11 || InfoClass == 0x0B) {
        if (InfoLen >= sizeof(ULONG)) {
            if (Info) *(ULONG*)Info = 0;
            if (RetLen) *RetLen = sizeof(ULONG);
        }
        return STATUS_SUCCESS;
    }

    auto realFunc = (NtQuerySysInfoFunc)g_ntqsiTrampoline;
    if (realFunc) {
        NTSTATUS status = realFunc(InfoClass, Info, InfoLen, RetLen);

        // ACPI MADT spoofing: modify processor entries to match 10C/20T
        if (InfoClass == 75 && Info && InfoLen >= sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION)) {
            SYSTEM_FIRMWARE_TABLE_INFORMATION* fti = (SYSTEM_FIRMWARE_TABLE_INFORMATION*)Info;
            if (fti->ProviderSignature == 0x49435041 &&       // 'ACPI'
                fti->FirmwareTableID == 0x43495041 &&          // 'APIC'
                fti->FirmwareTableBuffer && fti->FirmwareTableBufferLength >= 44) {
                g_logger.Trace(LOG_SOGEN, "ACPI MADT table detected - spoofing to %d processor entries", 20);
                SpoofAcpiMadt(fti->FirmwareTableBuffer, &fti->FirmwareTableBufferLength);
            }
        }

        // Also handle size-query case for ACPI MADT (buffer was NULL)
        if (InfoClass == 75 && Info && RetLen &&
            status == STATUS_BUFFER_TOO_SMALL) {
            SYSTEM_FIRMWARE_TABLE_INFORMATION* fti = (SYSTEM_FIRMWARE_TABLE_INFORMATION*)Info;
            if (fti->ProviderSignature == 0x49435041 &&
                fti->FirmwareTableID == 0x43495041 &&
                fti->ACPIBufferTooSmall) {
                // Bump required size to accommodate 20 APIC entries (vs real 4)
                ULONG needed = fti->FirmwareTableBufferLength + (20 * 8);
                if (needed > fti->FirmwareTableBufferLength) {
                    fti->FirmwareTableBufferLength = needed;
                    g_logger.Trace(LOG_SOGEN, "ACPI MADT size-query: bumped to %u bytes", needed);
                }
            }
        }

        return status;
    }
    return STATUS_NOT_IMPLEMENTED;
}

static void CleanupAll()
{
    delete g_vcpuManager; g_vcpuManager = nullptr;
    delete g_soGenEmulator; g_soGenEmulator = nullptr;
    delete g_syscallDispatcher; g_syscallDispatcher = nullptr;
    delete g_threadManager; g_threadManager = nullptr;
    delete g_virtualState; g_virtualState = nullptr;
    delete g_cryptoEmu; g_cryptoEmu = nullptr;
    delete g_registryEmu; g_registryEmu = nullptr;
    delete g_timingEmu; g_timingEmu = nullptr;
    delete g_fileEmu; g_fileEmu = nullptr;
    delete g_memoryEmu; g_memoryEmu = nullptr;
    delete g_processEmu; g_processEmu = nullptr;
    delete g_kuserSync; g_kuserSync = nullptr;
    delete g_eptHook; g_eptHook = nullptr;
    delete g_exitDispatcher; g_exitDispatcher = nullptr;
    delete g_magicCpuid; g_magicCpuid = nullptr;
    delete g_msrHandler; g_msrHandler = nullptr;
    delete g_rdtscHandler; g_rdtscHandler = nullptr;
    delete g_cpuidHandler; g_cpuidHandler = nullptr;
    delete g_timingProfile; g_timingProfile = nullptr;
    delete g_storageProfile; g_storageProfile = nullptr;
    delete g_gpuProfile; g_gpuProfile = nullptr;
    delete g_cpuProfile; g_cpuProfile = nullptr;
    delete g_partition; g_partition = nullptr;
    delete g_iatPatch; g_iatPatch = nullptr;
    delete g_codePatcher; g_codePatcher = nullptr;
    delete g_kuserHook; g_kuserHook = nullptr;
    delete g_msrPatcher; g_msrPatcher = nullptr;
    delete g_exceptionHandler; g_exceptionHandler = nullptr;
    delete g_threadScheduler; g_threadScheduler = nullptr;
    delete g_sectionEmu; g_sectionEmu = nullptr;
    delete g_objectEmu; g_objectEmu = nullptr;
    delete g_peLoader; g_peLoader = nullptr;
    g_ntqiHook.Remove();
    g_ntqsiHook.Remove();
    delete g_gpuBridge; g_gpuBridge = nullptr;
}

static wchar_t g_engineDir[MAX_PATH] = {0};

static void SetupIatHooks()
{
    g_iatPatch = new IatPatch(&g_logger);

    // Get engine DLL directory for loading proxy DLLs with full paths
    if (!g_engineDir[0] && g_engineModule) {
        wchar_t modPath[MAX_PATH];
        GetModuleFileNameW(g_engineModule, modPath, MAX_PATH);
        wchar_t* lastSlash = wcsrchr(modPath, L'\\');
        if (lastSlash) *lastSlash = 0;
        wcscpy_s(g_engineDir, modPath);
    }

    struct ProxyDll {
        const wchar_t* name;
        const char* exports[16][2]; // {dllName, funcName} pairs
        int exportCount;
    };

    ProxyDll dlls[] = {
        { L"ntdll_proxy.dll",        {{"ntdll.dll", "NtCreateFile"}, {"ntdll.dll", "NtQuerySystemInformation"}, {"ntdll.dll", "NtQueryInformationProcess"}, {"ntdll.dll", "NtOpenKey"}, {"ntdll.dll", "NtQueryValueKey"}}, 5 },
        { L"kernel32_proxy.dll",     {{"kernel32.dll", "CreateProcessW"}, {"kernel32.dll", "VirtualAllocEx"}, {"kernel32.dll", "GetComputerNameW"}, {"kernel32.dll", "GetUserNameW"}, {"kernel32.dll", "CreateFileW"}, {"kernel32.dll", "CreateFileA"}}, 6 },
        { L"kernelbase_proxy.dll",   {{"kernelbase.dll", "GetSystemInfo"}, {"kernelbase.dll", "GetNativeSystemInfo"}}, 2 },
        { L"advapi32_proxy.dll",     {{"advapi32.dll", "RegOpenKeyExW"}, {"advapi32.dll", "RegQueryValueExW"}}, 2 },
        { L"user32_proxy.dll",       {{"user32.dll", "CreateWindowExW"}}, 1 },
        { L"wbem_proxy.dll",         {{"ole32.dll", "CoCreateInstance"}}, 1 },
        { L"wtsapi32_proxy.dll",     {{"wtsapi32.dll", "WTSQuerySessionInformationW"}, {"wtsapi32.dll", "WTSEnumerateSessionsW"}, {"wtsapi32.dll", "WTSGetActiveConsoleSessionId"}}, 3 },
        { L"secur32_proxy.dll",      {{"secur32.dll", "InitializeSecurityContextW"}, {"secur32.dll", "AcquireCredentialsHandleW"}, {"secur32.dll", "GetUserNameExW"}}, 3 },
        { L"crypt32_proxy.dll",      {{"crypt32.dll", "CertOpenSystemStoreW"}, {"crypt32.dll", "CertCloseStore"}, {"crypt32.dll", "CryptAcquireContextW"}, {"crypt32.dll", "CryptReleaseContext"}, {"crypt32.dll", "CryptGenKey"}, {"crypt32.dll", "CryptDestroyKey"}}, 6 },
        { L"winhttp_proxy.dll",      {{"winhttp.dll", "WinHttpOpen"}, {"winhttp.dll", "WinHttpCloseHandle"}, {"winhttp.dll", "WinHttpConnect"}, {"winhttp.dll", "WinHttpOpenRequest"}, {"winhttp.dll", "WinHttpSendRequest"}, {"winhttp.dll", "WinHttpReceiveResponse"}, {"winhttp.dll", "WinHttpReadData"}}, 7 },
        { L"dnsapi_proxy.dll",       {{"dnsapi.dll", "DnsQuery_W"}, {"dnsapi.dll", "DnsRecordListFree"}}, 2 },
        { L"iphlpapi_proxy.dll",     {{"iphlpapi.dll", "GetAdaptersInfo"}, {"iphlpapi.dll", "GetAdaptersAddresses"}, {"iphlpapi.dll", "GetNetworkParams"}}, 3 },
        { L"ws2_32_proxy.dll",       {{"ws2_32.dll", "socket"}, {"ws2_32.dll", "connect"}, {"ws2_32.dll", "send"}, {"ws2_32.dll", "recv"}, {"ws2_32.dll", "closesocket"}, {"ws2_32.dll", "gethostbyname"}, {"ws2_32.dll", "getaddrinfo"}, {"ws2_32.dll", "WSAStartup"}, {"ws2_32.dll", "WSACleanup"}}, 9 },
    };

    for (auto& dll : dlls) {
        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, L"%s\\%s", g_engineDir, dll.name);
        g_logger.Trace(LOG_PROXY, "Loading proxy DLL: %ls", fullPath);
        HMODULE hProxy = LoadLibraryW(fullPath);
        if (!hProxy) {
            g_logger.Trace(LOG_ERROR, "Failed to load proxy DLL: %ls", fullPath);
            continue;
        }
        g_logger.Trace(LOG_PROXY, "Loaded %ls", dll.name);
        for (int i = 0; i < dll.exportCount; i++) {
            // skip GPU DLLs - always fall through to real system
            if (g_gpuBridge && g_gpuBridge->IsGpuDll(dll.exports[i][0])) {
                g_logger.Trace(LOG_PROXY, "Skipping GPU DLL %s - always fallthrough", dll.exports[i][0]);
                continue;
            }
            FARPROC proc = GetProcAddress(hProxy, dll.exports[i][1]);
            if (proc) {
                g_iatPatch->PatchIAT(dll.exports[i][0], dll.exports[i][1], (void*)proc);
            }
        }
    }
}

static std::wstring GetConfigPath(HMODULE hModule)
{
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(hModule, modulePath, MAX_PATH);
    std::wstring path = modulePath;
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) path = path.substr(0, pos);
    path += L"\\config\\config.ini";
    return path;
}

LONG CALLBACK EngineVehHandler(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION ||
        ep->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
        ULONG_PTR info0 = ep->ExceptionRecord->ExceptionInformation[0]; // 0=read, 1=write, 8=dep
        ULONG_PTR info1 = ep->ExceptionRecord->ExceptionInformation[1]; // target addr
        g_logger.Trace(LOG_ERROR, "CRASH: code=0x%08X op=%s addr=%p ip=%p",
            ep->ExceptionRecord->ExceptionCode,
            info0 == 0 ? "READ" : info0 == 1 ? "WRITE" : "DEP",
            (void*)info1,
            ep->ExceptionRecord->ExceptionAddress);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI EngineThread(LPVOID lpParam)
{
    AddVectoredExceptionHandler(1, EngineVehHandler);

    g_logger.Trace(LOG_INFO, "Engine thread started");

    HMODULE hModule = (HMODULE)lpParam;
    g_engineModule = hModule;

    std::wstring configPath = GetConfigPath(hModule);
    std::string configPathA;
    if (!configPath.empty()) {
        int len = WideCharToMultiByte(CP_UTF8, 0, configPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        configPathA.resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, configPath.c_str(), -1, configPathA.data(), len, nullptr, nullptr);
    }
    ConfigParser configParser(configPathA);
    if (!configParser.Load()) {
        g_logger.Trace(LOG_WARNING, "Failed to load %s, using defualts lol", 
            configPathA.c_str());
    } else {
        g_logger.Trace(LOG_INFO, "Config loaded from %s", configPathA.c_str());
    }

    // check spoof toggles from config
    bool spoofCpuid   = configParser.GetBool("spoof", "cpuid", true);
    bool spoofRdtsc   = configParser.GetBool("spoof", "rdtsc", true);
    bool spoofMsr     = configParser.GetBool("spoof", "msr", true);
    bool spoofKuser   = configParser.GetBool("spoof", "kuser", true);
    bool spoofProcess = configParser.GetBool("spoof", "process_info", true);
    bool spoofRegistry = configParser.GetBool("spoof", "registry", true);
    bool spoofFile    = configParser.GetBool("spoof", "file", true);
    bool spoofTiming  = configParser.GetBool("spoof", "timing", true);
    bool spoofGpu     = configParser.GetBool("spoof", "gpu", true);
    bool spoofToken   = configParser.GetBool("spoof", "token", true);
    bool spoofThread  = configParser.GetBool("spoof", "thread", true);
    bool cloakModule  = configParser.GetBool("spoof", "module_cloak", true);

    // profile init lol
    g_cpuProfile = new CpuProfile();
    g_gpuProfile = new GpuProfile();
    g_storageProfile = new StorageProfile();
    g_timingProfile = new TimingProfile();

    // load config into profiles
    g_cpuProfile->LoadFromConfig(&configParser);
    g_gpuProfile->LoadFromConfig(&configParser);
    g_storageProfile->LoadFromConfig(&configParser);
    g_timingProfile->LoadFromConfig(&configParser);

    // CPUID vendor - overrides individual leafs
    std::string cpuType = configParser.GetString("cpuid", "vendor", "intel");
    if (cpuType == "amd" || cpuType == "AMD") {
        g_cpuProfile->LoadAmdProfile();
        // re-apply config on top AMD
        g_cpuProfile->LoadFromConfig(&configParser);
        g_logger.Trace(LOG_INFO, "Using AMD CPU profile with config overrides");
    } else {
        g_logger.Trace(LOG_INFO, "Using Intel CPU profile with config overrides");
    }

    // GPU bridge - always initialized so GPU calls never intercepted
    g_gpuBridge = new GpuBridge(&g_logger);
    g_gpuBridge->Initialize();

    // exit handlers for CPUID, RDTSC, MSR, memory
    if (spoofCpuid) {
        g_cpuidHandler = new CpuidHandler(&g_logger, g_cpuProfile);
        g_cpuidHandler->LoadSpoofs();
    } else {
        g_logger.Trace(LOG_INFO, "CPUID spoofing disabled by config");
    }

    g_magicCpuid = new MagicCpuid(&g_logger);

    if (spoofRdtsc) {
        g_rdtscHandler = new RdtscHandler(&g_logger, g_cpuProfile, g_timingProfile);
        uint32_t tscNoise = (uint32_t)configParser.GetUint64("timing", "tsc_noise", 100);
        g_rdtscHandler->SetNoiseEnabled(tscNoise > 0);
        g_rdtscHandler->SetNoiseAmplitude(tscNoise);
    } else {
        g_logger.Trace(LOG_INFO, "RDTSC spoofing disabled by config");
    }

    if (spoofMsr) {
        g_msrHandler = new MsrHandler(&g_logger);
    } else {
        g_logger.Trace(LOG_INFO, "MSR spoofing disabled by config");
    }

    // SoGen syscall emulators init (conditionally based on config)
    g_processEmu = new ProcessEmu(&g_logger, nullptr);
    g_processEmu->LoadFromConfig(&configParser);
    g_memoryEmu = new MemoryEmu(&g_logger);
    g_fileEmu = new FileEmu(&g_logger);
    g_timingEmu = new TimingEmu(&g_logger, g_timingProfile);
    g_registryEmu = new RegistryEmu(&g_logger);
    g_cryptoEmu = new CryptoEmu(&g_logger);
    g_virtualState = new VirtualState(&g_logger);
    g_threadManager = new ThreadManager(&g_logger);

    // new extended SoGen modules
    g_sectionEmu = new SectionEmu(&g_logger);
    g_objectEmu = new ObjectEmu(&g_logger);
    g_peLoader = new PeLoader(&g_logger);

    // route syscall nums to handlers
    g_syscallDispatcher = new SyscallDispatcher(&g_logger);
    g_syscallDispatcher->RegisterHandlers(g_processEmu, g_memoryEmu, g_fileEmu,
        g_timingEmu, g_registryEmu, g_cryptoEmu, g_virtualState, g_threadManager);
    g_syscallDispatcher->RegisterExtendedHandlers(g_sectionEmu, g_objectEmu);

    g_soGenEmulator = new SoGenEmulator(&g_logger, g_syscallDispatcher);
    SetSoGenBridge(g_soGenEmulator);

    // build virtual process list (spoofing)
    if (g_processEmu) {
        g_processEmu->BuildVirtualProcessList();
    }

    // Phase 2: patching native code w/ VEH
    if (spoofCpuid || spoofRdtsc) {
        g_codePatcher = new CodePatcher(&g_logger, g_cpuProfile, g_timingProfile);
        if (g_codePatcher->Initialize()) {
            g_logger.Trace(LOG_INFO, "CodePatcher initialized");
        }
    }

    if (spoofMsr) {
        g_msrPatcher = new MsrPatcher(&g_logger, g_cpuProfile, g_timingProfile);
        if (g_msrPatcher->Initialize()) {
            g_logger.Trace(LOG_INFO, "MsrPatcher initialized");
        }
    }

    if (spoofKuser) {
        g_kuserHook = new KuserHook(&g_logger);
        if (g_kuserHook->Initialize()) {
            g_logger.Trace(LOG_INFO, "KuserHook initialized (active=%d)", g_kuserHook->IsActive());
        }
    } else {
        g_logger.Trace(LOG_INFO, "KUSER spoofing disabled by config");
    }

    // try to create WHP partition - not fatal if fails (IAT-only mode)
    bool whpAvailable = false;
    g_partition = new Partition(&g_logger);
    if (g_partition->Create()) {
        uint32_t cpuCount = (uint32_t)configParser.GetUint64("vm", "cpu_count", 1);
        uint32_t memoryMb = (uint32_t)configParser.GetUint64("vm", "memory_size_mb", 512);
        g_partition->SetupCpuCount(cpuCount);
        g_partition->SetupMemory(memoryMb);
        if (g_partition->Init()) {
            whpAvailable = true;
            g_logger.Trace(LOG_INFO, "WHP partition created - full virtualization mode (VCPUs=%u)", cpuCount);
        } else {
            g_logger.Trace(LOG_WARNING, "WHP partition init failed - running IAT-only mode");
        }
    } else {
        g_logger.Trace(LOG_WARNING, "WHP partition creation failed - running IAT-only mode");
    }

    if (whpAvailable) {
        // EPT hook for KUSER page + kernel memory hooks
        g_eptHook = new EptHook(&g_logger, g_partition);
        g_kuserSync = new KuserSync(&g_logger, g_partition);

        g_exitDispatcher = new ExitDispatcher(&g_logger);
        g_exitDispatcher->RegisterHandler(WHvRunVpExitReasonMemoryAccess, g_eptHook);

        // install kernel memory hooks (WinVisor upgrade)
        g_eptHook->InstallKernelMemoryHooks();
        g_eptHook->InstallMsrBitmapHook();

        if (g_kuserSync->Initialize(&configParser)) {
            g_logger.Trace(LOG_INFO, "KUSER_SHARED_DATA spoofing initialized");
        } else {
            g_logger.Trace(LOG_WARNING, "KUSER_SHARED_DATA spoofing failed to initialize");
        }

        // handler for VM exceptions (GP, UD)
        g_exceptionHandler = new ExceptionHandler(&g_logger);

        // VCPU manager w/ all handlers
        g_vcpuManager = new VcpuManager(&g_logger, g_partition, g_exitDispatcher,
            g_cpuidHandler, g_rdtscHandler, g_msrHandler, g_cpuProfile);
        g_vcpuManager->SetMagicCpuid(g_magicCpuid);
        g_vcpuManager->SetSoGenEmulator(g_soGenEmulator);
        g_vcpuManager->SetExceptionHandler(g_exceptionHandler);

        // start kuser sync (1ms update)
        if (g_kuserSync) {
            g_kuserSync->StartSyncThread();
        }
    }

    // IAT hooks for proxy DLLs
    if (spoofProcess || spoofRegistry || spoofFile || spoofTiming) {
        SetupIatHooks();
    } else {
        g_logger.Trace(LOG_INFO, "Proxy hooks disabled by config");
    }

    // Inline hooks for ntdll functions (catches calls via GetProcAddress)
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (spoofProcess || spoofThread) {
        if (hNtdll) {
        void* ntqiAddr = GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (ntqiAddr) {
            g_ntqiHook.Install(ntqiAddr, (void*)HookedNtQueryInformationProcess);
            g_ntqiTrampoline = g_ntqiHook.GetTrampoline();
            if (g_ntqiTrampoline) {
                g_logger.Trace(LOG_INFO, "InlineHook: NtQueryInformationProcess hooked at %p", ntqiAddr);
            }
        }

        void* ntqsiAddr = GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (ntqsiAddr) {
            g_ntqsiHook.Install(ntqsiAddr, (void*)HookedNtQuerySystemInformation);
            g_ntqsiTrampoline = g_ntqsiHook.GetTrampoline();
            if (g_ntqsiTrampoline) {
                g_logger.Trace(LOG_INFO, "InlineHook: NtQuerySystemInformation hooked at %p", ntqsiAddr);
            }
        }
        }
    } else {
        g_logger.Trace(LOG_INFO, "Inline hooks disabled by config");
    }

    // Signal launcher / PoC that hooks, patches, and shared KUSER are ready
    if (g_engineReadyEvent) {
        SetEvent(g_engineReadyEvent);
        g_logger.Trace(LOG_INFO, "Engine ready — hooks active");
    }
    if (g_engineActiveEvent) {
        SetEvent(g_engineActiveEvent);
    }

    // start thread scheduler for multi-VCPU if WHP available
    if (whpAvailable && g_vcpuManager) {
        uint32_t cpuCount = (uint32_t)configParser.GetUint64("vm", "cpu_count", 1);
        g_threadScheduler = new ThreadScheduler(&g_logger, g_vcpuManager, (int)cpuCount);
        g_threadScheduler->Start();
    }

    if (g_vcpuManager) {
        // create all VCPUs specified in config
        uint32_t cpuCount = (uint32_t)configParser.GetUint64("vm", "cpu_count", 1);
        if (cpuCount > 4) cpuCount = 4;
        if (cpuCount < 1) cpuCount = 1;

        for (uint32_t i = 0; i < cpuCount; i++) {
            if (!g_vcpuManager->CreateVcpu(i)) {
                g_logger.Trace(LOG_ERROR, "Failed to create VCPU %u", i);
            }
        }

        // sync all VCPUs at barrier before starting
        if (g_threadScheduler && g_threadScheduler->GetBarrier()) {
            g_threadScheduler->GetBarrier()->Wait(5000);
        }

        g_logger.Trace(LOG_INFO, "Starting VM execution loop (%u VCPUs)", cpuCount);
        g_vcpuManager->Run(0);
    } else {
        g_logger.Trace(LOG_INFO, "IAT-only mode: engine running without WHP virtualization");
    }

    g_logger.Trace(LOG_INFO, "Engine thread finished");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            wchar_t logPath[MAX_PATH];
            GetModuleFileNameW(hModule, logPath, MAX_PATH);
            std::wstring path = logPath;
            size_t pos = path.find_last_of(L"\\/");
            if (pos != std::wstring::npos) path = path.substr(0, pos);
            path += L"\\emu.log";
            g_logger.Init(path);
            g_logger.Trace(LOG_INFO, "Engine loaded");

            // create event so PoC can detect bypass is active
            g_engineActiveEvent = CreateEventW(NULL, TRUE, FALSE, L"LustResearch_EngineActive");
            break;
        }
        case DLL_PROCESS_DETACH:
            g_logger.Trace(LOG_INFO, "Engine unloaded");
            CleanupAll();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

ENGINE_DLL_EXPORT void Engine_SetDebug()
{
    g_logger.SetVerbose(true);
}

ENGINE_DLL_EXPORT void Engine_Init()
{
    g_logger.Trace(LOG_INFO, "Engine_Init called");

    if (!g_engineReadyEvent) {
        g_engineReadyEvent = CreateEventW(NULL, TRUE, FALSE, L"LustResearch_EngineReady");
    } else {
        ResetEvent(g_engineReadyEvent);
    }

    HMODULE hModule = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCWSTR)Engine_Init, &hModule);

    HANDLE hThread = CreateThread(NULL, 0, EngineThread, hModule, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    } else {
        g_logger.Trace(LOG_ERROR, "Engine_Init: failed to spawn engine thread (%u)", GetLastError());
    }
}