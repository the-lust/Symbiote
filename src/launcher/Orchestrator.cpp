#include "Orchestrator.h"
#include "ProcessUtils.h"
#include "../engine/byovd/ByovdDetect.h"
#include "../kernelproxy/KernelProxy.h"
#include "../engine/whp/ConfigSnapshot.h"
#include "../shared/SharedMemory.h"
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

static ConfigSnapshot g_bakedConfig;
static uint8_t g_sharedMemPool[0x10000]; // 64KB pool for shared memory

Orchestrator::Orchestrator()
    : m_config(&g_bakedConfig)
    , m_driver(nullptr)
    , m_hTargetProcess(nullptr)
    , m_hTargetThread(nullptr)
    , m_targetPid(0)
    , m_seed(0)
    , m_active(false)
    , m_hSharedMem(nullptr)
    , m_hSharedMemMap(nullptr)
{}

Orchestrator::~Orchestrator() { Shutdown(); }

uint64_t Orchestrator::GenerateSeed() {
    uint64_t seed = 0;
    BCryptGenRandom(nullptr, (PUCHAR)&seed, sizeof(seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return seed;
}

const ConfigSnapshot* Orchestrator::Run() {
    m_seed = GenerateSeed();

    PhaseResult r0 = Phase0_BakeConfig(L"config\\config.ini");
    if (!r0.success) return nullptr;

    PhaseResult r1 = Phase1_ByovdDetect();
    // Non-fatal if BYOVD fails

    PhaseResult r2 = Phase2_KernelProxyInject();
    // Non-fatal

    PhaseResult r3 = Phase3_SandboxSetup();
    // Non-fatal

    PhaseResult r4 = Phase4_PartitionCreate();
    // Non-fatal (engine will create its own if needed)

    PhaseResult r5 = Phase5_RenameDlls();
    if (!r5.success) return nullptr;

    PhaseResult r6 = Phase6_InjectEngine();
    if (!r6.success) return nullptr;

    PhaseResult r7 = Phase7_ResumeTarget();

    m_active = true;
    return m_config;
}

// ── Phase 0: bake config ──────────────────────────────────────────────────

static void DetectCpuVendorBackend(wchar_t* out, size_t outLen)
{
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    if (_stricmp(vendor, "AuthenticAMD") == 0) {
        wcscpy_s(out, outLen, L"SimpleSVM-style (AMD)");
    } else {
        wcscpy_s(out, outLen, L"HyperDbg-style (Intel)");
    }
}

PhaseResult Orchestrator::Phase0_BakeConfig(const wchar_t* iniPath) {
    PhaseResult r = {true, 0, L""};
    memset(m_config, 0, sizeof(ConfigSnapshot));
    m_config->version = 1;
    m_config->runSeed = m_seed;

    // Stealth mode: always-on by default ("stealth unless turned off").
    // When always_on=1 a spoof section is enabled unless it explicitly
    // sets status=0; when always_on=0 everything passes through unless
    // a section explicitly opts in.
    bool stealthAlwaysOn = GetPrivateProfileIntW(L"stealth", L"always_on", 1, iniPath) != 0;
    m_config->stealth.alwaysOn = stealthAlwaysOn;

    auto SpoofFlag = [&](LPCWSTR section, bool defaultVal) -> bool {
        wchar_t buf[8] = {0};
        if (GetPrivateProfileStringW(section, L"status", L"", buf, 8, iniPath) > 0) {
            return _wtoi(buf) != 0;
        }
        if (!stealthAlwaysOn) return false;
        if (GetPrivateProfileStringW(L"spoof", section, L"", buf, 8, iniPath) > 0) {
            return _wtoi(buf) != 0;
        }
        return defaultVal;
    };

    GetPrivateProfileStringW(L"backend", L"type", L"whp", m_config->backendType, 32, iniPath);
    GetPrivateProfileStringW(L"hypervisor", L"mode", L"whp", m_config->hypervisor.mode, 16, iniPath);
    m_config->hypervisor.enabled = GetPrivateProfileIntW(L"hypervisor", L"enabled", 1, iniPath) != 0;
    DetectCpuVendorBackend(m_config->hypervisor.vendorBackend, 32);
    if (_wcsicmp(m_config->hypervisor.mode, L"driver") == 0) {
        // Informational: which ring -1 backend family this CPU maps to.
        wcscpy_s(r.errorMsg, L"Hypervisor driver rail requested (NOT BUILT)");
    }
    m_config->byovd.enabled = GetPrivateProfileIntW(L"byovd", L"enabled", 1, iniPath) != 0;
    m_config->kernelProxy.enabled = GetPrivateProfileIntW(L"kernel_proxy", L"enabled", 0, iniPath) != 0;
    m_config->kernelProxy.hookSstd = GetPrivateProfileIntW(L"kernel_proxy", L"hook_ssdt", 1, iniPath) != 0;
    m_config->kernelProxy.hookEprocess = GetPrivateProfileIntW(L"kernel_proxy", L"hook_eprocess", 1, iniPath) != 0;
    m_config->kernelProxy.hookLstar = GetPrivateProfileIntW(L"kernel_proxy", L"hook_lstar", 1, iniPath) != 0;
    m_config->kernelProxy.hookIdt = GetPrivateProfileIntW(L"kernel_proxy", L"hook_idt", 1, iniPath) != 0;

    m_config->cpu.isHybrid = GetPrivateProfileIntW(L"cpuid.0x1A", L"is_hybrid", 0, iniPath) != 0;
    m_config->cpu.nativeModelId = GetPrivateProfileIntW(L"cpuid.0x1A", L"native_model_id", 0, iniPath);
    m_config->cpu.coreType = GetPrivateProfileIntW(L"cpuid.0x1A", L"core_type", 0, iniPath);
    m_config->cpu.hybridCoreCount = GetPrivateProfileIntW(L"cpuid.0x1A", L"core_count", 0, iniPath);

    m_config->memory.sizeMb = (uint32_t)GetPrivateProfileIntW(L"vm", L"memory_size_mb", 2048, iniPath);
    m_config->memory.cpuCount = (uint32_t)GetPrivateProfileIntW(L"vm", L"cpu_count", 0, iniPath);

    GetPrivateProfileStringW(L"hardware", L"bios_vendor", L"American Megatrends Inc.",
        m_config->bios.biosVendor, 64, iniPath);
    GetPrivateProfileStringW(L"hardware", L"bios_version", L"F15",
        m_config->bios.biosVersion, 64, iniPath);
    GetPrivateProfileStringW(L"hardware", L"system_manufacturer", L"Gigabyte Technology Co., Ltd.",
        m_config->bios.systemManufacturer, 64, iniPath);
    GetPrivateProfileStringW(L"hardware", L"product", L"Z590 AORUS MASTER",
        m_config->bios.systemProductName, 64, iniPath);
    GetPrivateProfileStringW(L"hardware", L"system_uuid", L"00000000-0000-0000-0000-000000000000",
        m_config->bios.systemUuid, 48, iniPath);

    m_config->spoofCpuid = SpoofFlag(L"cpuid", true);
    m_config->spoofRdtsc = SpoofFlag(L"rdtsc", true);
    m_config->spoofMsr = SpoofFlag(L"msr", true);
    m_config->spoofKuser = SpoofFlag(L"kuser", true);
    m_config->spoofStackSpoofer = SpoofFlag(L"process", true);
    m_config->captureMode = GetPrivateProfileIntW(L"capture", L"enabled", 0, iniPath) != 0;
    m_config->sandboxEnabled = GetPrivateProfileIntW(L"sandbox", L"enabled", 0, iniPath) != 0;
    m_config->snapshotEnabled = GetPrivateProfileIntW(L"snapshot", L"enabled", 0, iniPath) != 0;

    wcscpy_s(r.errorMsg, L"Config baked");
    return r;
}

// ── Phase 1: BYOVD detection + installation ───────────────────────────────

PhaseResult Orchestrator::Phase1_ByovdDetect() {
    PhaseResult r = {true, 1, L""};
    if (!m_config->byovd.enabled) {
        wcscpy_s(r.errorMsg, L"BYOVD disabled");
        return r;
    }

    wchar_t launcherDir[MAX_PATH];
    GetModuleFileNameW(nullptr, launcherDir, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(launcherDir, L'\\');
    if (lastSlash) *lastSlash = L'\0';

    ByovdDetect det;
    det.SetDriversDir((std::wstring(launcherDir) + L"\\drivers").c_str());
    DetectedDriver dr = det.DetectAndOpen();

    if (dr.deviceHandle && dr.deviceHandle != INVALID_HANDLE_VALUE) {
        m_driver = new DetectedDriver(dr);
        m_config->byovd.deviceHandle = dr.deviceHandle;
        m_config->byovd.capabilities = dr.capabilities;
        wcscpy_s(m_config->byovd.driverPath, dr.driverPath);
        wcscpy_s(r.errorMsg, L"BYOVD: driver opened");
    } else {
        wcscpy_s(r.errorMsg, L"BYOVD: no driver available");
    }
    return r;
}

// ── Phase 2: kernel proxy injection ────────────────────────────────────────

PhaseResult Orchestrator::Phase2_KernelProxyInject() {
    PhaseResult r = {true, 2, L""};
    if (!m_config->kernelProxy.enabled || !m_driver) {
        wcscpy_s(r.errorMsg, L"Kernel proxy disabled or no BYOVD");
        return r;
    }

    KernelProxy kp;
    kp.Initialize(m_driver->deviceHandle, m_driver->capabilities);

    EprocessSanitizerParams sp = {};
    sp.hideProcFromDbgk = true;
    sp.hideProcFromPeb = true;
    sp.hideThreads = true;
    sp.spoofCreateTime = true;
    sp.spoofParentPid = true;
    sp.spoofedParentPid = 4;
    kp.DeployEprocessSanitizer(sp);

    LstarMonitorParams lp = {};
    kp.InstallLstarMonitor(lp);
    kp.HideDriverList();

    wcscpy_s(r.errorMsg, L"Kernel proxy deployed");
    return r;
}

// ── Phase 3: sandbox setup ─────────────────────────────────────────────────

PhaseResult Orchestrator::Phase3_SandboxSetup() {
    PhaseResult r = {true, 3, L""};

    if (!m_config->sandboxEnabled) {
        wcscpy_s(r.errorMsg, L"Sandbox disabled");
        return r;
    }

    // VHDX mount if configured
    if (m_config->sandbox.vhdxPath[0]) {
        // Mount VHDX via Win32 API
        HANDLE hVhd = CreateFileW(m_config->sandbox.vhdxPath, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hVhd != INVALID_HANDLE_VALUE) {
            // Attach via IOCTL_VOLUME_ATTACH — stub
            CloseHandle(hVhd);
        }
    }

    wcscpy_s(r.errorMsg, L"Sandbox ready");
    return r;
}

// ── Phase 4: WHP partition creation ─────────────────────────────────────────

PhaseResult Orchestrator::Phase4_PartitionCreate() {
    PhaseResult r = {true, 4, L""};

    // WHP partition pre-creation is deferred to the engine.
    // The launcher doesn't create it directly because the partition
    // needs to be in the target process's address space.
    //
    // Instead, we set up the config so the engine knows what to create.

    wcscpy_s(r.errorMsg, L"Partition config ready (deferred to engine)");
    return r;
}

// ── Phase 5: proxy DLL renaming ────────────────────────────────────────────

PhaseResult Orchestrator::Phase5_RenameDlls() {
    PhaseResult r = {true, 5, L""};

    wchar_t launcherDir[MAX_PATH];
    GetModuleFileNameW(nullptr, launcherDir, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(launcherDir, L'\\');
    if (lastSlash) *lastSlash = L'\0';

    // The proxy DLLs are in the same directory as the launcher
    m_renamer.Init(m_seed);

    // Register all proxy DLLs for renaming
    struct ProxyEntry { const wchar_t* name; };
    ProxyEntry proxies[] = {
        {L"engine.dll"}, {L"ntdll.dll"}, {L"kernel32.dll"}, {L"kernelbase.dll"},
        {L"advapi32.dll"}, {L"user32.dll"}, {L"wbem.dll"}, {L"wtsapi32.dll"},
        {L"secur32.dll"}, {L"crypt32.dll"}, {L"winhttp.dll"}, {L"dnsapi.dll"},
        {L"iphlpapi.dll"}, {L"ws2_32.dll"}, {L"xgameruntime.dll"},
    };
    for (auto& p : proxies) m_renamer.RegisterDll(p.name);
    m_renamer.GenerateNames();

    // Copy renamed DLLs to target directory
    if (!m_config->targetDirectory[0]) wcscpy_s(m_config->targetDirectory, launcherDir);

    if (!m_renamer.ApplyRenames(m_config->targetDirectory[0] ? m_config->targetDirectory : launcherDir)) {
        wcscpy_s(r.errorMsg, L"Proxy DLL rename copies failed");
        r.success = false;
        return r;
    }

    // Build rename table into config
    m_config->proxyRenameCount = 15;
    m_renamer.BuildTable((RenameTable*)&m_config->proxyRenames);

    wcscpy_s(r.errorMsg, L"Proxy DLLs renamed");
    return r;
}

// ── Phase 6: engine injection with shared memory ───────────────────────────

PhaseResult Orchestrator::Phase6_InjectEngine() {
    PhaseResult r = {true, 6, L""};

    // Step 1: create target process suspended
    if (!CreateSuspendedProcess(std::wstring(m_config->targetPath),
                                std::wstring(m_config->targetArgs),
                                m_si, m_pi)) {
        wcscpy_s(r.errorMsg, L"Failed to create suspended process");
        r.success = false;
        return r;
    }
    m_targetPid = GetProcessId(m_pi.hProcess);
    m_hTargetProcess = m_pi.hProcess;
    m_hTargetThread = m_pi.hThread;

    // Step 2: build shared memory with ConfigSnapshot + export table + rename table
    if (!CreateSharedMemory()) {
        wcscpy_s(r.errorMsg, L"Failed to create shared memory");
        r.success = false;
        return r;
    }

    // Step 3: inject engine.dll
    wchar_t engineDllPath[MAX_PATH];
    GetModuleFileNameW(nullptr, engineDllPath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(engineDllPath, L'\\');
    if (lastSlash) *(lastSlash + 1) = L'\0';
    wcscat_s(engineDllPath, L"engine.dll");

    if (!InjectDll(m_hTargetProcess, std::wstring(engineDllPath))) {
        wcscpy_s(r.errorMsg, L"Failed to inject engine.dll");
        r.success = false;
        return r;
    }

    // Step 4: call Engine_Init
    DWORD initResult = 0;
    if (!CallRemoteFunctionWithResult(m_hTargetProcess, std::wstring(engineDllPath),
                                       "Engine_Init", &initResult) || initResult == 0) {
        wcscpy_s(r.errorMsg, L"Engine_Init failed");
        r.success = false;
        return r;
    }

    // Step 5: call Engine_InterceptEntryPoint
    CallRemoteFunction(m_hTargetProcess, std::wstring(engineDllPath), "Engine_InterceptEntryPoint");

    // Step 6: wait for engine ready event
    HANDLE hReady = OpenEventW(EVENT_ALL_ACCESS, FALSE, L"Symbiote_EngineReady");
    if (hReady) {
        WaitForSingleObject(hReady, 5000);
        CloseHandle(hReady);
    }

    wcscpy_s(r.errorMsg, L"Engine injected");
    return r;
}

// ── Phase 7: resume target ─────────────────────────────────────────────────

PhaseResult Orchestrator::Phase7_ResumeTarget() {
    PhaseResult r = {true, 7, L""};

    if (!m_hTargetThread) {
        wcscpy_s(r.errorMsg, L"No target thread to resume");
        r.success = false;
        return r;
    }

    ResumeThread(m_hTargetThread);

    // Wait for process to exit if configured
    if (m_config->waitForExit) {
        WaitForSingleObject(m_hTargetProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(m_hTargetProcess, &exitCode);
    }

    wcscpy_s(r.errorMsg, L"Target resumed");
    return r;
}

// ── Shared memory management ───────────────────────────────────────────────

bool Orchestrator::CreateSharedMemory() {
    wchar_t memName[64];
    BuildSharedMemName(m_seed, memName, 64);

    size_t totalSize = sizeof(SharedMemoryHeader) + sizeof(ConfigSnapshot) +
                       sizeof(ExportEntry) * 256 + sizeof(RenameTable);

    m_hSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, (DWORD)totalSize, memName);
    if (!m_hSharedMem) return false;

    m_hSharedMemMap = MapViewOfFile(m_hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, totalSize);
    if (!m_hSharedMemMap) {
        CloseHandle(m_hSharedMem);
        m_hSharedMem = nullptr;
        return false;
    }

    SharedMemoryHeader* hdr = (SharedMemoryHeader*)m_hSharedMemMap;
    hdr->magic = kSharedMemMagic;
    hdr->version = kSharedMemVersion;
    hdr->totalSize = (uint32_t)totalSize;
    hdr->runSeed = m_seed;

    // ConfigSnapshot at fixed offset from header
    hdr->configSnapshotOffset = sizeof(SharedMemoryHeader);
    memcpy((uint8_t*)m_hSharedMemMap + hdr->configSnapshotOffset, m_config, sizeof(ConfigSnapshot));

    // Export table
    hdr->exportTableOffset = hdr->configSnapshotOffset + sizeof(ConfigSnapshot);
    // Align to 8 bytes
    hdr->exportTableOffset = (hdr->exportTableOffset + 7) & ~7;

    ExportEntry* exports = (ExportEntry*)((uint8_t*)m_hSharedMemMap + hdr->exportTableOffset);
    (void)exports;
    // Populate with the engine's actual export table
    // These are filled by the engine at init; we pre-populate with placeholder IDs
    hdr->exportTableCount = 0;

    // Rename table
    hdr->renameTableOffset = hdr->exportTableOffset + sizeof(ExportEntry) * 256;
    hdr->renameTableOffset = (hdr->renameTableOffset + 7) & ~7;

    RenameTable* rt = (RenameTable*)((uint8_t*)m_hSharedMemMap + hdr->renameTableOffset);
    m_renamer.BuildTable(rt);
    hdr->renameTableEntryCount = (uint32_t)rt->entryCount;

    return true;
}

void Orchestrator::DestroySharedMemory() {
    if (m_hSharedMemMap) {
        UnmapViewOfFile(m_hSharedMemMap);
        m_hSharedMemMap = nullptr;
    }
    if (m_hSharedMem) {
        CloseHandle(m_hSharedMem);
        m_hSharedMem = nullptr;
    }
}

// ── Shutdown ────────────────────────────────────────────────────────────────

void Orchestrator::Shutdown() {
    if (m_hTargetProcess) {
        CloseHandle(m_hTargetProcess);
        m_hTargetProcess = nullptr;
    }
    if (m_hTargetThread) {
        CloseHandle(m_hTargetThread);
        m_hTargetThread = nullptr;
    }
    if (m_driver) {
        if (m_driver->deviceHandle) CloseHandle(m_driver->deviceHandle);
        delete m_driver;
        m_driver = nullptr;
    }
    DestroySharedMemory();
    m_active = false;
}