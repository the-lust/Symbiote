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
#include "whp/EptExecHook.h"
#include "whp/KuserSync.h"
#include "whp/KuserHook.h"
#include "whp/MagicCpuid.h"
#include "whp/AllocTracker.h"
#include "whp/ExceptionHandler.h"
#include "whp/ThreadScheduler.h"
#include "whp/TimingCoordinator.h"
#include "whp/Canary.h"
#include "whp/SystemSpoofer.h"
#include "whp/WatchdogTracker.h"
#include "whp/EptSplitView.h"
#include "whp/GuestPageTable.h"
#include "whp/AcpiTimerHandler.h"
#include "whp/EptPageProtect.h"
#include "emu/DeviceIoEmu.h"
#include "emu/StackSpoofer.h"
#include "emu/TimingEmu.h"
#include "emu/ProcessEmu.h"
#include "whp/IndirectSyscall.h"
#include "whp/Snapshot.h"
#include "whp/VeSimulation.h"
#include "whp/ConsistencyVerifier.h"
#include "emu/ThreadHider.h"
#include "profile/GpuProfile.h"
#include "profile/StorageProfile.h"
#include "kernel/MinimalKernel.h"
#include "proxy/IatPatch.h"
#include "proxy/SyscallBridge.h"
#include "proxy/GpuBridge.h"
#include "kernel/SystemProfile.h"
#include "kernel/KernelBackend.h"
#include "util/HwDetect.h"
#include <tlhelp32.h>
#include "capture/CaptureLogger.h"

static Logger g_logger;
static TimingCoordinator g_timingCoordinator;
static AcpiTimerHandler* g_acpiTimerHandler = nullptr;
static ThreadHider* g_threadHider = nullptr;
static Partition* g_partition = nullptr;
static VcpuManager* g_vcpuManager = nullptr;
static ExitDispatcher* g_exitDispatcher = nullptr;
static CpuidHandler* g_cpuidHandler = nullptr;
static RdtscHandler* g_rdtscHandler = nullptr;
static MsrHandler* g_msrHandler = nullptr;
static EptHook* g_eptHook = nullptr;
static EptExecHook* g_eptExecHook = nullptr;
static KuserSync* g_kuserSync = nullptr;
static MagicCpuid* g_magicCpuid = nullptr;
static GpuProfile* g_gpuProfile = nullptr;
static StorageProfile* g_storageProfile = nullptr;
static MinimalKernel* g_minimalKernel = nullptr;
static HMODULE g_engineModule = nullptr;
static IatPatch* g_iatPatch = nullptr;
static KuserHook* g_kuserHook = nullptr;
static ExceptionHandler* g_exceptionHandler = nullptr;
static SystemProfile* g_systemProfile = nullptr;
static KernelBackend* g_kernelBackend = nullptr;
static SystemSpoofer* g_systemSpoofer = nullptr;
extern GpuBridge* g_gpuBridge;
static ThreadScheduler* g_threadScheduler = nullptr;
static WatchdogTracker* g_watchdogTracker = nullptr;
static EptSplitView* g_eptSplitView = nullptr;
static EptPageProtect* g_eptPageProtect = nullptr;
static VeSimulation* g_veSimulation = nullptr;
static ConsistencyVerifier* g_consistencyVerifier = nullptr;
static StackSpoofer* g_stackSpoofer = nullptr;
static IndirectSyscall* g_indirectSyscall = nullptr;
static Snapshot* g_snapshot = nullptr;

// PEB anti-debug restoration thread: continuously monitors BeingDebugged
// (offset 0x02) and NtGlobalFlag (offset 0xBC) for overwrite by protection
// threads, restoring them to safe values every 500ms.
static std::thread g_pebRestoreThread;
static std::atomic<bool> g_pebRestoreRunning{false};

static HANDLE g_engineReadyEvent = nullptr;
static HANDLE g_engineActiveEvent = nullptr;

CaptureLogger* g_captureLogger = nullptr;

// Ghost Sandbox: original game entry point (saved before trampoline)
static uint64_t g_originalEntryRip = 0;
static bool g_guestPageTableBuilt = false;

static void CleanupDenuvoState()
{
    // Clean up common Denuvo persistence vectors that may store blacklist state
    wchar_t gameDir[MAX_PATH];
    GetModuleFileNameW(NULL, gameDir, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(gameDir, L'\\');
    if (lastSlash) *lastSlash = 0;

    // Denuvo cache files in game directory
    const wchar_t* patterns[] = {
        L"\\Denuvo*.bin", L"\\Denuvo*.dat", L"\\Denuvo*.lic",
        L"\\*.dvl", L"\\Steam*_Denuvo*"
    };
    for (auto pattern : patterns) {
        wchar_t search[MAX_PATH];
        swprintf_s(search, L"%s%s", gameDir, pattern);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(search, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                wchar_t fullPath[MAX_PATH];
                swprintf_s(fullPath, L"%s\\%s", gameDir, fd.cFileName);
                DeleteFileW(fullPath);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    // Check %appdata% for Denuvo state
    wchar_t appData[MAX_PATH];
    if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH)) {
        wchar_t denuvoDir[MAX_PATH];
        swprintf_s(denuvoDir, L"%s\\Denuvo", appData);
        DWORD attr = GetFileAttributesW(denuvoDir);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            // Delete known Denuvo state files
            WIN32_FIND_DATAW fd;
            wchar_t search[MAX_PATH];
            swprintf_s(search, L"%s\\*", denuvoDir);
            HANDLE hFind = FindFirstFileW(search, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                    wchar_t fullPath[MAX_PATH];
                    swprintf_s(fullPath, L"%s\\%s", denuvoDir, fd.cFileName);
                    DeleteFileW(fullPath);
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // Clear temp directory files matching Denuvo patterns
    wchar_t tempDir[MAX_PATH];
    if (GetEnvironmentVariableW(L"TEMP", tempDir, MAX_PATH)) {
        wchar_t search[MAX_PATH];
        swprintf_s(search, L"%s\\dns*", tempDir);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(search, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                wchar_t fullPath[MAX_PATH];
                swprintf_s(fullPath, L"%s\\%s", tempDir, fd.cFileName);
                DeleteFileW(fullPath);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
}

// PEB restoration thread: background monitor that restores anti-debug fields
static void PebRestoreLoop()
{
    while (g_pebRestoreRunning.load()) {
        uint8_t* peb = (uint8_t*)__readgsqword(0x60);
        if (peb) {
            peb[0x02] = 0; // BeingDebugged = FALSE
            *(uint32_t*)(peb + 0xBC) = 0; // NtGlobalFlag = 0
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

static void CleanupAll()
{
    // Stop PEB restoration thread
    if (g_pebRestoreRunning.load()) {
        g_pebRestoreRunning.store(false);
        if (g_pebRestoreThread.joinable()) {
            g_pebRestoreThread.join();
        }
    }

    CleanupDenuvoState();
    delete g_vcpuManager; g_vcpuManager = nullptr;
    delete g_minimalKernel; g_minimalKernel = nullptr;
    delete g_kuserSync; g_kuserSync = nullptr;
    delete g_eptHook; g_eptHook = nullptr;
    delete g_eptExecHook; g_eptExecHook = nullptr;
    delete g_exitDispatcher; g_exitDispatcher = nullptr;
    delete g_magicCpuid; g_magicCpuid = nullptr;
    delete g_msrHandler; g_msrHandler = nullptr;
    delete g_rdtscHandler; g_rdtscHandler = nullptr;
    delete g_cpuidHandler; g_cpuidHandler = nullptr;

    delete g_storageProfile; g_storageProfile = nullptr;
    delete g_gpuProfile; g_gpuProfile = nullptr;
    delete g_kernelBackend; g_kernelBackend = nullptr;
    delete g_systemProfile; g_systemProfile = nullptr;
    delete g_partition; g_partition = nullptr;
    delete g_iatPatch; g_iatPatch = nullptr;
    delete g_kuserHook; g_kuserHook = nullptr;
    delete g_systemSpoofer; g_systemSpoofer = nullptr;
    delete g_exceptionHandler; g_exceptionHandler = nullptr;
    delete g_allocTracker; g_allocTracker = nullptr;
    delete g_threadScheduler; g_threadScheduler = nullptr;
    delete g_gpuBridge; g_gpuBridge = nullptr;
    delete g_canary; g_canary = nullptr;
    delete g_watchdogTracker; g_watchdogTracker = nullptr;
    delete g_eptSplitView; g_eptSplitView = nullptr;
    delete g_captureLogger; g_captureLogger = nullptr;
    delete g_threadHider; g_threadHider = nullptr;
    delete g_acpiTimerHandler; g_acpiTimerHandler = nullptr;
    delete g_consistencyVerifier; g_consistencyVerifier = nullptr;
    delete g_veSimulation; g_veSimulation = nullptr;
    delete g_eptPageProtect; g_eptPageProtect = nullptr;
    delete g_stackSpoofer; g_stackSpoofer = nullptr;
    delete g_indirectSyscall; g_indirectSyscall = nullptr;
    delete g_snapshot; g_snapshot = nullptr;
}

static wchar_t g_engineDir[MAX_PATH] = {0};

static void SetupIatHooks(bool enableEat = false)
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
        { L"ntdll.dll",        {{"ntdll.dll", "NtCreateFile"}, {"ntdll.dll", "NtQuerySystemInformation"}, {"ntdll.dll", "NtQueryInformationProcess"}, {"ntdll.dll", "NtOpenKey"}, {"ntdll.dll", "NtQueryValueKey"}}, 5 },
        { L"kernel32.dll",     {{"kernel32.dll", "CreateProcessW"}, {"kernel32.dll", "VirtualAllocEx"}, {"kernel32.dll", "GetComputerNameW"}, {"kernel32.dll", "GetUserNameW"}, {"kernel32.dll", "CreateFileW"}, {"kernel32.dll", "CreateFileA"}, {"kernel32.dll", "GetVolumeInformationW"}, {"kernel32.dll", "GetWindowsDirectoryW"}}, 8 },
        { L"kernelbase.dll",   {{"kernelbase.dll", "GetSystemInfo"}, {"kernelbase.dll", "GetNativeSystemInfo"}}, 2 },
        { L"advapi32.dll",     {{"advapi32.dll", "RegOpenKeyExW"}, {"advapi32.dll", "RegQueryValueExW"}}, 2 },
        { L"user32.dll",       {{"user32.dll", "CreateWindowExW"}}, 1 },
        { L"wbem.dll",        {{"ole32.dll", "CoCreateInstance"}}, 1 },
        { L"wtsapi32.dll",     {{"wtsapi32.dll", "WTSQuerySessionInformationW"}, {"wtsapi32.dll", "WTSEnumerateSessionsW"}, {"wtsapi32.dll", "WTSGetActiveConsoleSessionId"}}, 3 },
        { L"secur32.dll",      {{"secur32.dll", "InitializeSecurityContextW"}, {"secur32.dll", "AcquireCredentialsHandleW"}, {"secur32.dll", "GetUserNameExW"}}, 3 },
        { L"crypt32.dll",      {{"crypt32.dll", "CertOpenSystemStoreW"}, {"crypt32.dll", "CertCloseStore"}, {"crypt32.dll", "CryptAcquireContextW"}, {"crypt32.dll", "CryptReleaseContext"}, {"crypt32.dll", "CryptGenKey"}, {"crypt32.dll", "CryptDestroyKey"}, {"crypt32.dll", "CryptGetProvParam"}}, 7 },
        { L"winhttp.dll",      {{"winhttp.dll", "WinHttpOpen"}, {"winhttp.dll", "WinHttpCloseHandle"}, {"winhttp.dll", "WinHttpConnect"}, {"winhttp.dll", "WinHttpOpenRequest"}, {"winhttp.dll", "WinHttpSendRequest"}, {"winhttp.dll", "WinHttpReceiveResponse"}, {"winhttp.dll", "WinHttpReadData"}}, 7 },
        { L"dnsapi.dll",       {{"dnsapi.dll", "DnsQuery_W"}, {"dnsapi.dll", "DnsRecordListFree"}}, 2 },
        { L"iphlpapi.dll",     {{"iphlpapi.dll", "GetAdaptersInfo"}, {"iphlpapi.dll", "GetAdaptersAddresses"}, {"iphlpapi.dll", "GetNetworkParams"}}, 3 },
        { L"ws2_32.dll",       {{"ws2_32.dll", "socket"}, {"ws2_32.dll", "connect"}, {"ws2_32.dll", "send"}, {"ws2_32.dll", "recv"}, {"ws2_32.dll", "closesocket"}, {"ws2_32.dll", "gethostbyname"}, {"ws2_32.dll", "getaddrinfo"}, {"ws2_32.dll", "WSAStartup"}, {"ws2_32.dll", "WSACleanup"}}, 9 },
    };

    HMODULE hNtdllProxy = NULL, hKernel32Proxy = NULL;

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
        if (wcscmp(dll.name, L"ntdll.dll") == 0) hNtdllProxy = hProxy;
        if (wcscmp(dll.name, L"kernel32.dll") == 0) hKernel32Proxy = hProxy;
    }

    // EAT (Export Address Table) patching
    if (enableEat) {
        g_logger.Trace(LOG_PROXY, "EAT patching enabled");
        for (auto& dll : dlls) {
            HMODULE hProxy = GetModuleHandleW(dll.name);
            if (!hProxy) continue;
            for (int i = 0; i < dll.exportCount; i++) {
                FARPROC proc = GetProcAddress(hProxy, dll.exports[i][1]);
                if (proc) {
                    g_iatPatch->PatchEAT(dll.exports[i][0], dll.exports[i][1], (void*)proc);
                }
            }
        }
    } else {
        g_logger.Trace(LOG_PROXY, "EAT patching disabled by config");
    }

    // Register proxy function addresses with kernel32_proxy's GetProcAddress hook
    // so dynamic lookups (e.g., GetProcAddress("kernel32.dll", "GetComputerNameW"))
    // return our proxy addresses without needing name-based module lookup.
    if (hKernel32Proxy) {
        typedef void (WINAPI* RegFunc_t)(const char*, const char**, FARPROC*, int);
        RegFunc_t regFunc = (RegFunc_t)GetProcAddress(hKernel32Proxy, "RegisterProxyFunctions");
        if (regFunc) {
            auto registerProxy = [&](HMODULE hProxy, const char* dllName, const char** funcs, int count) {
                FARPROC addrs[32];
                for (int i = 0; i < count; i++) {
                    addrs[i] = GetProcAddress(hProxy, funcs[i]);
                }
                regFunc(dllName, funcs, addrs, count);
            };

            // Register ntdll proxy functions
            const char* ntdlFuncs[] = {"NtCreateFile", "NtQuerySystemInformation",
                "NtQueryInformationProcess", "NtOpenKey", "NtQueryValueKey"};
            if (hNtdllProxy)
                registerProxy(hNtdllProxy, "ntdll.dll", ntdlFuncs, 5);

            // Register kernel32 proxy functions
            const char* k32Funcs[] = {"GetComputerNameW", "GetUserNameW",
                "GetVolumeInformationW", "GetWindowsDirectoryW", "CreateFileW", "CreateFileA"};
            registerProxy(hKernel32Proxy, "kernel32.dll", k32Funcs, 6);
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
    // Guard page violations are handled by AllocTracker - skip logging
    if (ep->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        ULONG_PTR info0 = ep->ExceptionRecord->ExceptionInformation[0];
        ULONG_PTR info1 = ep->ExceptionRecord->ExceptionInformation[1];
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

    // check spoof toggles from config (supports both new [feature].status and old [spoof].feature format)
    auto CheckSpoof = [&](const char* section, bool defaultVal) -> bool {
        std::string raw = configParser.GetString(section, "status", "");
        if (!raw.empty()) return configParser.GetBool(section, "status", defaultVal);
        return configParser.GetBool("spoof", section, defaultVal);
    };
    bool spoofCpuid   = CheckSpoof("cpuid", true);
    bool spoofRdtsc   = CheckSpoof("rdtsc", true);
    bool spoofMsr     = CheckSpoof("msr", true);
    bool spoofKuser   = CheckSpoof("kuser", true);
    bool spoofProcess = CheckSpoof("process", true);
    bool spoofRegistry = CheckSpoof("registry", true);
    bool spoofFile    = CheckSpoof("file", true);
    bool spoofTiming  = CheckSpoof("timing", true);

    g_gpuProfile = new GpuProfile();
    g_storageProfile = new StorageProfile();
    g_gpuProfile->LoadFromConfig(&configParser);
    g_storageProfile->LoadFromConfig(&configParser);

    // Create SystemProfile + KernelBackend (unified spoof data source)
    g_systemProfile = new SystemProfile();
    g_kernelBackend = new KernelBackend(g_systemProfile);

    // CPUID vendor - overrides individual leafs
    std::string cpuType = configParser.GetString("cpuid", "vendor", "intel");
    if (cpuType == "amd" || cpuType == "AMD") {
        g_systemProfile->LoadAmdRyzen9_5950X();
        g_logger.Trace(LOG_INFO, "Using AMD CPU profile with config overrides");
    } else {
        g_systemProfile->LoadIntelI9_10900K();
        g_logger.Trace(LOG_INFO, "Using Intel CPU profile with config overrides");
    }

    g_systemProfile->LoadFromConfig(&configParser);

    // Auto-detect host TSC frequency (from libkrun: CPUID 0x15/0x16/QPC)
    uint64_t detectedTsc = DetectTscFrequency();
    uint64_t configTsc = configParser.GetUint64("timing", "tsc_frequency", 0);
    if (configTsc == 0) {
        // No config override — use detected value
        g_systemProfile->SetTscFrequency(detectedTsc);
        g_logger.Trace(LOG_INFO, "TSC frequency auto-detected: %llu Hz (%.2f GHz)",
            detectedTsc, (double)detectedTsc / 1000000000.0);
    } else {
        g_logger.Trace(LOG_INFO, "TSC frequency from config: %llu Hz (detected: %llu Hz)",
            configTsc, detectedTsc);
    }

    // Capture mode: log all queries without spoofing (for fingerprint collection)
    bool captureMode = configParser.GetBool("capture", "enabled", false);
    if (captureMode) {
        wchar_t capturePath[MAX_PATH];
        GetModuleFileNameW(hModule, capturePath, MAX_PATH);
        std::wstring capPath = capturePath;
        size_t pos = capPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) capPath = capPath.substr(0, pos);
        capPath += L"\\capture.log";
        g_captureLogger = new CaptureLogger();
        if (g_captureLogger->Open(capPath.c_str())) {
            g_logger.Trace(LOG_INFO, "Capture mode enabled — logging all queries to %ls", capPath.c_str());
        } else {
            g_logger.Trace(LOG_WARNING, "Capture mode: failed to open %ls", capPath.c_str());
            delete g_captureLogger;
            g_captureLogger = nullptr;
        }
    }

    // GPU bridge - always initialized so GPU calls never intercepted
    g_gpuBridge = new GpuBridge(&g_logger);
    g_gpuBridge->Initialize();

    // exit handlers for CPUID, RDTSC, MSR, memory
    if (spoofCpuid || captureMode) {
        g_cpuidHandler = new CpuidHandler(&g_logger, g_kernelBackend);
        g_cpuidHandler->SetTimingCoordinator(&g_timingCoordinator);
        if (g_captureLogger) g_cpuidHandler->SetCaptureLogger(g_captureLogger);

        // Load brand string from config (leaves 0x80000002-0x80000004)
        std::string brandStr = configParser.GetString("cpuid", "brand_string", "");
        if (!brandStr.empty()) {
            g_cpuidHandler->SetBrandString(brandStr.c_str());
            g_logger.Trace(LOG_INFO, "CPUID brand string set: '%s'", brandStr.c_str());
        }
        std::string enhancedBrand = configParser.GetString("cpuid", "enhanced_brand_string", "");
        if (!enhancedBrand.empty()) {
            g_cpuidHandler->SetEnhancedBrandString(enhancedBrand.c_str());
            g_logger.Trace(LOG_INFO, "CPUID enhanced brand string set: '%s'", enhancedBrand.c_str());
        }

        // Auto-generate brand string from vendor + detected frequency if none configured
        // (from libkrun's brand_string.rs: constructs "Intel(R) Core(TM) Processor @ X.XXGHz")
        uint64_t tscFreq = g_systemProfile->GetTscFrequency();
        g_cpuidHandler->AutoGenerateBrandString(tscFreq);
    } else {
        g_logger.Trace(LOG_INFO, "CPUID spoofing disabled by config");
    }

    bool spoofMagicCpuid = CheckSpoof("magic", false);
    if (spoofMagicCpuid) {
        g_magicCpuid = new MagicCpuid(&g_logger);
        g_logger.Trace(LOG_INFO, "MagicCpuid enabled by config");
    } else {
        g_logger.Trace(LOG_INFO, "MagicCpuid disabled by config");
    }

    if (spoofRdtsc || captureMode) {
        g_rdtscHandler = new RdtscHandler(&g_logger, g_kernelBackend);
        g_rdtscHandler->SetTimingCoordinator(&g_timingCoordinator);
        if (g_captureLogger) g_rdtscHandler->SetCaptureLogger(g_captureLogger);
        uint32_t tscNoise = (uint32_t)configParser.GetUint64("timing", "tsc_noise", 100);
        g_rdtscHandler->SetNoiseEnabled(tscNoise > 0);
        g_rdtscHandler->SetNoiseAmplitude(tscNoise);
    } else {
        g_logger.Trace(LOG_INFO, "RDTSC spoofing disabled by config");
    }

    if (spoofMsr || captureMode) {
        g_msrHandler = new MsrHandler(&g_logger);
        if (g_captureLogger) g_msrHandler->SetCaptureLogger(g_captureLogger);
    } else {
        g_logger.Trace(LOG_INFO, "MSR spoofing disabled by config");
    }

    // MinimalKernel: unified syscall handler owns all emulator instances
    g_minimalKernel = new MinimalKernel(&g_logger, g_kernelBackend);
    g_minimalKernel->Initialize();
    g_minimalKernel->LoadFromConfig(&configParser);
    if (g_minimalKernel && g_minimalKernel->GetDeviceIoEmu()) {
        g_minimalKernel->GetDeviceIoEmu()->Initialize();
    }
    g_minimalKernel->BuildVirtualProcessList();
    SetSyscallHandler(MinimalKernel::DispatchThunk);

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
        // Pre-populate WHP CPUID result list — ALWAYS creates anti-detection
        // entries (leaf 1 ECX[31]=0, hypervisor range zeroed) even when CPUID
        // spoofing is disabled. This prevents trivial hypervisor detection via
        // CPUID leaf 0x40000000 ("Microsoft Hv") or leaf 1 ECX[31] (hypervisor bit).
        if (!g_partition->SetupCpuidResultList(g_cpuidHandler)) {
            g_logger.Trace(LOG_WARNING, "CPUID result list setup failed — hypervisor may be detectable via CPUID");
        }
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

        // install kernel memory hooks via WHP
        g_eptHook->InstallKernelMemoryHooks();
        g_eptHook->InstallMsrBitmapHook();

        // EPT-based execution hook single-step system (replaces AllocTracker VEH)
        g_eptExecHook = new EptExecHook(&g_logger, g_partition);
        g_vcpuManager->SetEptExecHook(g_eptExecHook);

        // P0.3: Denuvo threaded integrity watchdog detection via EPT exec hooks
        bool watchdogEnabled = configParser.GetBool("watchdog", "enabled", true);
        if (watchdogEnabled) {
            g_watchdogTracker = new WatchdogTracker(&g_logger, g_partition, g_eptExecHook);
            if (g_watchdogTracker->Initialize()) {
                g_logger.Trace(LOG_INFO, "WatchdogTracker initialized");
            } else {
                g_logger.Trace(LOG_WARNING, "WatchdogTracker failed to initialize");
                delete g_watchdogTracker;
                g_watchdogTracker = nullptr;
            }
        } else {
            g_logger.Trace(LOG_INFO, "WatchdogTracker disabled by config");
        }

        // P2.10: EPT split-view for per-VCPU process cloaking
        bool splitViewEnabled = configParser.GetBool("ept_split_view", "enabled", true);
        if (splitViewEnabled) {
            g_eptSplitView = new EptSplitView(&g_logger, g_partition);
            if (g_eptSplitView->Initialize()) {
                g_logger.Trace(LOG_INFO, "EptSplitView initialized");
            } else {
                g_logger.Trace(LOG_WARNING, "EptSplitView failed to initialize");
                delete g_eptSplitView;
                g_eptSplitView = nullptr;
            }
        } else {
            g_logger.Trace(LOG_INFO, "EptSplitView disabled by config");
        }

        if (g_kuserSync->Initialize(&configParser)) {
            g_logger.Trace(LOG_INFO, "KUSER_SHARED_DATA spoofing initialized");
        } else {
            g_logger.Trace(LOG_WARNING, "KUSER_SHARED_DATA spoofing failed to initialize");
        }

        // handler for VM exceptions (GP, UD)
        g_exceptionHandler = new ExceptionHandler(&g_logger);

        // VCPU manager w/ all handlers
        g_vcpuManager = new VcpuManager(&g_logger, g_partition, g_exitDispatcher,
            g_cpuidHandler, g_rdtscHandler, g_msrHandler);
        g_vcpuManager->SetMagicCpuid(g_magicCpuid);
        g_vcpuManager->SetSyscallHandler(MinimalKernel::DispatchThunk);
        g_vcpuManager->SetExceptionHandler(g_exceptionHandler);

        // Build guest page tables for identity-mapped WHP execution (Ghost Sandbox)
        bool forwardingEnabled = configParser.GetBool("forwarding", "enabled", true);
        if (forwardingEnabled) {
            g_logger.Trace(LOG_INFO, "Building guest page tables...");
            if (g_partition->MapProcessMemory(GetCurrentProcess())) {
                g_guestPageTableBuilt = true;
                g_logger.Trace(LOG_INFO, "Guest page tables built: CR3=0x%llX",
                    g_partition->GetPageTable()->GetPml4Gpa());
            } else {
                g_logger.Trace(LOG_WARNING, "Failed to build guest page tables — running IAT-only mode");
            }
        }

        // start kuser sync (1ms update)
        if (g_kuserSync) {
            g_kuserSync->StartSyncThread();
        }
    }

    bool spoofEat = configParser.GetBool("eat", "enabled", false);

    // IAT hooks for proxy DLLs (always in capture mode to intercept game calls)
    if (captureMode || spoofProcess || spoofRegistry || spoofFile || spoofTiming) {
        SetupIatHooks(spoofEat);
    } else {
        g_logger.Trace(LOG_INFO, "Proxy hooks disabled by config");
    }



    // AllocTracker for allocated-memory CPUID interception (gated by hypervisor_hiding config)
    bool allocTrackerEnabled = configParser.GetBool("hypervisor_hiding", "alloc_tracker", false);
    if (allocTrackerEnabled) {
        // EptExecHook supersedes AllocTracker — EPT-based execution interception is more
        // efficient and undetectable than VEH guard pages. Warn and skip if EPT hooks active.
        if (g_eptExecHook) {
            g_logger.Trace(LOG_WARNING,
                "AllocTracker requested but EptExecHook is active — superseding. "
                "Set hypervisor_hiding.alloc_tracker=false in config to suppress this warning.");
        } else {
            g_allocTracker = new AllocTracker(&g_logger);
            if (g_captureLogger) g_allocTracker->SetCaptureLogger(g_captureLogger);
            if (g_allocTracker->Initialize()) {
                g_logger.Trace(LOG_INFO, "AllocTracker initialized - tracking executable allocations");
            } else {
                g_logger.Trace(LOG_WARNING, "AllocTracker failed to initialize");
                delete g_allocTracker;
                g_allocTracker = nullptr;
            }
        }
    } else {
        g_logger.Trace(LOG_DEBUG, "AllocTracker disabled by config (hypervisor_hiding.alloc_tracker=false)");
    }

    // Init Canary for memory scanner detection and handshake page
    Canary* canary = new Canary(&g_logger);
    if (g_captureLogger) canary->SetCaptureLogger(g_captureLogger);
    if (canary->Initialize()) {
        g_logger.Trace(LOG_INFO, "Canary initialized at %p", canary->GetCanaryPage());
    } else {
        g_logger.Trace(LOG_WARNING, "Canary failed to initialize");
        delete canary;
        canary = nullptr;
    }

    // Spoof PEB anti-debug fields (BeingDebugged, NtGlobalFlag)
    // NOTE: ProcessHeap.Flags/ForceFlags offsets differ per Windows version.
    // On Win10 22H2+ the classic offsets (0x1C/0x20) collide with critical
    // heap metadata. Skip them — BeingDebugged + NtGlobalFlag is sufficient.
    if (spoofProcess) {
        uint8_t* peb = (uint8_t*)__readgsqword(0x60);
        if (peb) {
            peb[0x02] = 0; // BeingDebugged = FALSE
            *(uint32_t*)(peb + 0xBC) = 0; // NtGlobalFlag = 0
            g_logger.Trace(LOG_INFO, "PEB: BeingDebugged=0, NtGlobalFlag=0 set (spoofProcess)");
        }

        // PEB restoration thread: background monitor that restores anti-debug
        // fields every 500ms in case a protection thread overwrites them.
        g_pebRestoreRunning.store(true);
        g_pebRestoreThread = std::thread(PebRestoreLoop);
        g_logger.Trace(LOG_INFO, "PEB: restoration thread started (500ms interval)");
    }

    // Init SystemSpoofer for SGDT/SIDT/SLDT/STR/XGETBV interception
    // Primary check: hypervisor_hiding.system_spoofer; fallback: system_spoofer.enabled
    bool spoofSystemSpoofer = configParser.GetBool("hypervisor_hiding", "system_spoofer", false);
    if (!spoofSystemSpoofer) {
        spoofSystemSpoofer = configParser.GetBool("system_spoofer", "enabled", false);
    }
    if (spoofSystemSpoofer) {
        g_logger.Trace(LOG_INFO, "SystemSpoofer: creating instance...");
        g_systemSpoofer = new SystemSpoofer(&g_logger);
        g_systemSpoofer->SetGdtBase(0x807F900000ULL);
        g_systemSpoofer->SetGdtLimit(0xFFFF);
        g_systemSpoofer->SetIdtBase(0xFFFFF80000000000ULL);
        g_systemSpoofer->SetIdtLimit(0xFFF);
        g_systemSpoofer->SetXgetbvResult(0x0000000000000007ULL);
        g_logger.Trace(LOG_INFO, "SystemSpoofer: calling Initialize...");
        if (g_systemSpoofer->Initialize()) {
            g_logger.Trace(LOG_INFO, "SystemSpoofer initialized");
        } else {
            g_logger.Trace(LOG_WARNING, "SystemSpoofer failed to initialize");
        }
    } else {
        g_logger.Trace(LOG_INFO, "SystemSpoofer disabled by config");
    }

    // Phase B: Wire SystemSpoofer to VcpuManager for EPT dispatch
    if (g_vcpuManager) {
        g_vcpuManager->SetSystemSpoofer(g_systemSpoofer);
    }

    // Phase B: StackSpoofer (call-stack return address protection)
    bool spoofStackSpoofer = configParser.GetBool("stack_spoofer", "enabled", true);
    if (spoofStackSpoofer && g_vcpuManager) {
        g_stackSpoofer = new StackSpoofer(&g_logger);
        if (g_stackSpoofer->Initialize()) {
            g_vcpuManager->SetStackSpoofer(g_stackSpoofer);
            g_logger.Trace(LOG_INFO, "StackSpoofer initialized — return address protection active");
        } else {
            g_logger.Trace(LOG_WARNING, "StackSpoofer failed to initialize");
            delete g_stackSpoofer;
            g_stackSpoofer = nullptr;
        }
    } else {
        g_logger.Trace(LOG_INFO, "StackSpoofer disabled by config (requires WHP)");
    }

    // Phase B: IndirectSyscall (EPT execute-disabled ntdll syscall stubs)
    bool spoofIndirectSyscall = configParser.GetBool("indirect_syscall", "enabled", false);
    if (spoofIndirectSyscall && g_eptExecHook) {
        g_indirectSyscall = new IndirectSyscall(&g_logger);
        if (g_indirectSyscall->Initialize(g_eptExecHook)) {
            if (g_vcpuManager) g_vcpuManager->SetIndirectSyscall(g_indirectSyscall);
            g_logger.Trace(LOG_INFO, "IndirectSyscall initialized — EPT syscall stubs active");
        } else {
            g_logger.Trace(LOG_WARNING, "IndirectSyscall failed to initialize");
            delete g_indirectSyscall;
            g_indirectSyscall = nullptr;
        }
    } else {
        g_logger.Trace(LOG_INFO, "IndirectSyscall disabled by config (requires EptExecHook)");
    }

    // Phase B: Snapshot for VCPU save/restore
    bool snapshotEnabled = configParser.GetBool("snapshot", "enabled", false);
    if (snapshotEnabled && g_partition) {
        g_snapshot = new Snapshot(&g_logger);
        g_logger.Trace(LOG_INFO, "Snapshot instance created (save/restore API ready)");
        // Snapshot usage: g_snapshot->Create(...), g_snapshot->WriteToFile(...),
        //                g_snapshot->LoadFromFile(...), g_snapshot->Restore(...)
    } else {
        g_logger.Trace(LOG_INFO, "Snapshot disabled by config (requires WHP)");
    }

    // Phase B: Wire synthetic TSC source to TimingEmu and SystemSpoofer
    // Both derive from the same CounterUpdater TSC for coherent timing
    if (g_minimalKernel && g_minimalKernel->GetTimingEmu()) {
        TimingEmu* timingEmu = g_minimalKernel->GetTimingEmu();
        timingEmu->SetSyntheticTscSource(RdtscHandler::GetCounterUpdaterTscPtr());
        // Use detected host TSC frequency instead of hardcoded 3.7 GHz default
        uint64_t detectedFreq = g_systemProfile->GetTscFrequency();
        if (detectedFreq > 100000000 && detectedFreq < 10000000000ULL) {
            timingEmu->SetSyntheticTscFreq(detectedFreq);
            g_logger.Trace(LOG_INFO, "TimingEmu: synthetic TSC freq set to %llu Hz", detectedFreq);
        }
        g_logger.Trace(LOG_INFO, "TimingEmu: synthetic TSC source set to CounterUpdater");
    }
    if (g_systemSpoofer) {
        g_systemSpoofer->m_syntheticTsc = RdtscHandler::GetCounterUpdaterTscPtr();
        g_logger.Trace(LOG_INFO, "SystemSpoofer: synthetic TSC source set to CounterUpdater");
    }

    // Initialize ACPI PM timer / HPET spoofing
    g_acpiTimerHandler = new AcpiTimerHandler(&g_logger);
    if (g_acpiTimerHandler) {
        g_acpiTimerHandler->Initialize();
    }

    // Initialize thread hider
    g_threadHider = new ThreadHider(&g_logger);
    if (g_threadHider) {
        g_threadHider->Initialize();
        // Hide engine's own threads from toolhelp32 enumeration
        g_threadHider->HideThread(GetCurrentThreadId());
        // Also enumerate and hide all threads in the current process
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                            sizeof(te.th32OwnerProcessID)) {
                        if (te.th32OwnerProcessID == GetCurrentProcessId()) {
                            g_threadHider->HideThread(te.th32ThreadID);
                        }
                    }
                    te.dwSize = sizeof(te);
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }
        g_logger.Trace(LOG_INFO, "ThreadHider: engine threads registered as hidden");

        // Wire ThreadHider into ProcessEmu for NtQuerySystemInformation thread filtering
        if (g_minimalKernel && g_minimalKernel->GetProcessEmu()) {
            g_minimalKernel->GetProcessEmu()->SetThreadHider(g_threadHider);
            g_logger.Trace(LOG_INFO, "ThreadHider: wired to ProcessEmu NtQuerySystemInformation path");
        }
    }

    // Initialize EPT page protection (hide engine/patch pages from Denuvo)
    if (g_partition) {
        g_eptPageProtect = new EptPageProtect(&g_logger, g_partition);
        if (g_eptPageProtect && g_eptPageProtect->Initialize()) {
            g_eptPageProtect->ProtectEngineDll();
            g_logger.Trace(LOG_INFO, "EptPageProtect: engine DLL pages hidden from guest");
        }
    }

    // Initialize #VE simulation
    g_veSimulation = new VeSimulation(&g_logger);
    if (g_veSimulation) {
        g_veSimulation->Initialize();
    }

    // Initialize consistency verifier
    g_consistencyVerifier = new ConsistencyVerifier(&g_logger);
    if (g_consistencyVerifier) {
        g_consistencyVerifier->Initialize();
        g_consistencyVerifier->VerifyAll();
    }

    // Signal launcher / target that hooks, patches, and shared KUSER are ready
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
        g_threadScheduler = new ThreadScheduler(&g_logger, g_vcpuManager, (int)cpuCount,
            g_vcpuManager ? g_vcpuManager->GetKernelLock() : nullptr);
        g_threadScheduler->Start();
    }

    if (g_vcpuManager) {
        uint32_t cpuCount = (uint32_t)configParser.GetUint64("vm", "cpu_count", 1);
        if (cpuCount > 4) cpuCount = 4;
        if (cpuCount < 1) cpuCount = 1;

        for (uint32_t i = 0; i < cpuCount; i++) {
            if (!g_vcpuManager->CreateVcpu(i)) {
                g_logger.Trace(LOG_ERROR, "Failed to create VCPU %u", i);
            }
        }

        // Sync timing across all VCPUs to ensure consistent cross-VCPU measurements
        if (g_rdtscHandler) {
            g_rdtscHandler->StartCounterUpdater();
            g_logger.Trace(LOG_TIMING, "Cross-VCPU timing sync: CounterUpdater active");
        }

        if (g_guestPageTableBuilt) {
            // Ghost Sandbox mode: engine thread does NOT enter VCPU.
            // The game thread enters VCPU via BootstrapFromContext when
            // it hits the entry point trampoline (Engine_VcpuEntry).
            g_logger.Trace(LOG_INFO, "Ghost Sandbox mode: engine waiting (game thread enters VCPU)");
            // Engine thread stays alive but idle
            while (g_vcpuManager) {
                Sleep(1000);
            }
        } else {
            // Legacy mode: enter VCPU with boot code
            if (g_threadScheduler && g_threadScheduler->GetBarrier()) {
                g_threadScheduler->GetBarrier()->Wait(5000);
            }
            g_logger.Trace(LOG_INFO, "Starting VM execution loop (%u VCPUs)", cpuCount);
            g_vcpuManager->Run(0);
        }
    } else {
        g_logger.Trace(LOG_INFO, "IAT-only mode: engine running without WHP virtualization");
    }

    g_logger.Trace(LOG_INFO, "Engine thread finished");
    return 0;
}

// ─── Ghost Sandbox: Entry point interception ──────────────────────────

// Called by launcher AFTER Engine_Init, BEFORE ResumeThread.
// Modifies the game's PE entry point to jump to Engine_VcpuEntry,
// which captures the thread context and enters the WHP VCPU.
ENGINE_DLL_EXPORT void Engine_InterceptEntryPoint()
{
    uint8_t* base = (uint8_t*)GetModuleHandleW(NULL);
    if (!base) {
        g_logger.Trace(LOG_ERROR, "InterceptEntryPoint: cannot get module base");
        return;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    uint32_t entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    uint8_t* entryPoint = base + entryRva;

    g_originalEntryRip = (uint64_t)entryPoint;
    g_logger.Trace(LOG_INFO, "InterceptEntryPoint: original entry at %p (RVA=0x%X)", entryPoint, entryRva);

    // Write trampoline:
    //   mov rax, Engine_VcpuEntry  ; 48 B8 <8-byte addr>
    //   jmp rax                    ; FF E0
    DWORD oldProtect;
    if (!VirtualProtect(entryPoint, 12, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_logger.Trace(LOG_ERROR, "InterceptEntryPoint: VirtualProtect failed");
        return;
    }

    entryPoint[0] = 0x48; entryPoint[1] = 0xB8;
    *(uint64_t*)(entryPoint + 2) = (uint64_t)&Engine_VcpuEntry;
    entryPoint[10] = 0xFF; entryPoint[11] = 0xE0;

    VirtualProtect(entryPoint, 12, oldProtect, &oldProtect);
    g_logger.Trace(LOG_INFO, "InterceptEntryPoint: trampoline written at %p → Engine_VcpuEntry", entryPoint);
}

// Called when the game's main thread starts execution.
// The entry point trampoline jumps here. We capture the current thread
// context and enter the WHP VCPU with identity-mapped guest page tables.
ENGINE_DLL_EXPORT void Engine_VcpuEntry()
{
    g_logger.Trace(LOG_INFO, "Engine_VcpuEntry: game thread entered VCPU bootstrap");

    // Capture thread context (all GP registers via intrinsics)
    ThreadContext ctx;
    ctx.rax = __readgsqword(0);   // placeholder — actual capture happens via context
    ctx.rbx = 0;
    ctx.rcx = 0;
    ctx.rdx = 0;
    ctx.rsi = 0;
    ctx.rdi = 0;
    ctx.rbp = 0;
    ctx.rsp = 0;
    ctx.r8  = 0;
    ctx.r9  = 0;
    ctx.r10 = 0;
    ctx.r11 = 0;
    ctx.r12 = 0;
    ctx.r13 = 0;
    ctx.r14 = 0;
    ctx.r15 = 0;
    ctx.rip = g_originalEntryRip;
    ctx.rflags = 0x202; // IF enabled
    ctx.cs = 0x33;
    ctx.ds = 0x2B;
    ctx.es = 0x2B;
    ctx.fs = 0x2B;
    ctx.gs = 0x2B;
    ctx.ss = 0x2B;

    // Capture actual registers using inline assembly via wrapper call
    // RAX, RCX, RDX, R8, R9 contain the loader's entry point arguments
    // RSP/RBP point to the initial thread stack
    CONTEXT captureCtx;
    captureCtx.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&captureCtx);

    ctx.rax = captureCtx.Rax;
    ctx.rbx = captureCtx.Rbx;
    ctx.rcx = captureCtx.Rcx;
    ctx.rdx = captureCtx.Rdx;
    ctx.rsi = captureCtx.Rsi;
    ctx.rdi = captureCtx.Rdi;
    ctx.rbp = captureCtx.Rbp;
    ctx.rsp = captureCtx.Rsp;
    ctx.r8  = captureCtx.R8;
    ctx.r9  = captureCtx.R9;
    ctx.r10 = captureCtx.R10;
    ctx.r11 = captureCtx.R11;
    ctx.r12 = captureCtx.R12;
    ctx.r13 = captureCtx.R13;
    ctx.r14 = captureCtx.R14;
    ctx.r15 = captureCtx.R15;
    ctx.rflags = captureCtx.EFlags;

    g_logger.Trace(LOG_INFO, "VCPU entry: RIP=0x%llX RSP=0x%llX RAX=0x%llX RCX=0x%llX",
        ctx.rip, ctx.rsp, ctx.rax, ctx.rcx);

    if (!g_vcpuManager || !g_partition || !g_partition->GetPageTable()) {
        g_logger.Trace(LOG_ERROR, "VCPU entry: not ready (no VCPU manager or page tables)");
        // Fall through to original entry point
        typedef void (*EntryPoint_t)();
        ((EntryPoint_t)g_originalEntryRip)();
        return;
    }

    g_logger.Trace(LOG_INFO, "VCPU entry: entering bootstrap with CR3=0x%llX",
        g_partition->GetPageTable()->GetPml4Gpa());

    // Enter the WHP VCPU — this function blocks until the VCPU stops
    g_vcpuManager->BootstrapFromContext(0, ctx, g_partition->GetPageTable());

    g_logger.Trace(LOG_INFO, "VCPU entry: VCPU stopped, game thread exiting");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
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

            // create event to signal engine active to target process
            g_engineActiveEvent = CreateEventW(NULL, TRUE, FALSE, L"Symbiote_EngineActive");
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
        g_engineReadyEvent = CreateEventW(NULL, TRUE, FALSE, L"Symbiote_EngineReady");
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