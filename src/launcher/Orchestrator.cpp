#include "Orchestrator.h"
#include "../engine/byovd/ByovdDetect.h"
#include "../kernelproxy/KernelProxy.h"
#include <cstdio>
#include <cstring>

// Config file baked by launcher
static ConfigSnapshot g_bakedConfig;

Orchestrator::Orchestrator()
    : m_config(&g_bakedConfig)
    , m_driver(nullptr)
    , m_hTargetProcess(nullptr)
    , m_hTargetThread(nullptr)
    , m_targetPid(0)
    , m_seed(0)
    , m_active(false)
{}

Orchestrator::~Orchestrator() { Shutdown(); }

uint64_t Orchestrator::GenerateSeed() {
    // Use BCryptGenRandom for cryptographic-quality seed
    uint64_t seed = 0;
    BCryptGenRandom(nullptr, (PUCHAR)&seed, sizeof(seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return seed;
}

const ConfigSnapshot* Orchestrator::Run() {
    m_seed = GenerateSeed();

    // Phase 0: Config bake
    PhaseResult r0 = Phase0_BakeConfig(L"config.ini");
    if (!r0.success) return nullptr;

    // Phase 1: BYOVD detection
    PhaseResult r1 = Phase1_ByovdDetect();
    if (!r1.success) return nullptr;

    // Phase 2: Kernel proxy injection
    PhaseResult r2 = Phase2_KernelProxyInject();
    // Non-fatal — continue without kernel proxy if it fails

    // Phase 3: Sandbox / VHDX setup
    PhaseResult r3 = Phase3_SandboxSetup();

    // Phase 4: WHP partition creation
    PhaseResult r4 = Phase4_PartitionCreate();
    if (!r4.success) return nullptr;

    // Phase 5: DLL renaming
    PhaseResult r5 = Phase5_RenameDlls();
    if (!r5.success) return nullptr;

    // Phase 6: Inject engine + snapshot into target process
    PhaseResult r6 = Phase6_InjectEngine();
    if (!r6.success) return nullptr;

    // Phase 7: Resume target
    PhaseResult r7 = Phase7_ResumeTarget();

    m_active = true;
    return m_config;
}

PhaseResult Orchestrator::Phase0_BakeConfig(const wchar_t* iniPath) {
    PhaseResult r = {true, 0, L""};
    memset(m_config, 0, sizeof(ConfigSnapshot));
    m_config->version = 1;
    m_config->runSeed = m_seed;

    // Read [backend] section
    wchar_t backendType[32] = L"whp";
    GetPrivateProfileStringW(L"backend", L"type", L"whp", backendType, 32, iniPath);

    // Read [byovd] section
    m_config->byovd.enabled = GetPrivateProfileIntW(L"byovd", L"enabled", 1, iniPath) != 0;

    // Read [kernel_proxy] section
    m_config->kernelProxy.enabled = GetPrivateProfileIntW(L"kernel_proxy", L"enabled", 0, iniPath) != 0;
    m_config->kernelProxy.hookSstd = GetPrivateProfileIntW(L"kernel_proxy", L"hook_ssdt", 1, iniPath) != 0;
    m_config->kernelProxy.hookEprocess = GetPrivateProfileIntW(L"kernel_proxy", L"hook_eprocess", 1, iniPath) != 0;
    m_config->kernelProxy.hookLstar = GetPrivateProfileIntW(L"kernel_proxy", L"hook_lstar", 1, iniPath) != 0;
    m_config->kernelProxy.hookIdt = GetPrivateProfileIntW(L"kernel_proxy", L"hook_idt", 1, iniPath) != 0;

    // Read CPU profile
    m_config->cpu.isHybrid = GetPrivateProfileIntW(L"cpuid.0x1A", L"is_hybrid", 0, iniPath) != 0;
    m_config->cpu.nativeModelId = GetPrivateProfileIntW(L"cpuid.0x1A", L"native_model_id", 0, iniPath);
    m_config->cpu.coreType = GetPrivateProfileIntW(L"cpuid.0x1A", L"core_type", 0, iniPath);
    m_config->cpu.hybridCoreCount = GetPrivateProfileIntW(L"cpuid.0x1A", L"core_count", 0, iniPath);

    // Read memory config
    m_config->memory.sizeMb = GetPrivateProfileIntW(L"memory", L"size_mb", 2048, iniPath);
    m_config->memory.cpuCount = GetPrivateProfileIntW(L"memory", L"cpu_count", 0, iniPath);

    // Read BIOS info
    GetPrivateProfileStringW(L"bios", L"vendor", L"American Megatrends Inc.", m_config->bios.biosVendor, 64, iniPath);
    GetPrivateProfileStringW(L"bios", L"version", L"F15", m_config->bios.biosVersion, 64, iniPath);
    GetPrivateProfileStringW(L"bios", L"system_manufacturer", L"Gigabyte Technology Co., Ltd.", m_config->bios.systemManufacturer, 64, iniPath);
    GetPrivateProfileStringW(L"bios", L"system_product", L"Z590 AORUS MASTER", m_config->bios.systemProductName, 64, iniPath);

    // Read rename config
    GetPrivateProfileStringW(L"rename", L"prefix", L"", nullptr, 0, iniPath);

    // Compute feature flags
    m_config->spoofCpuid = true;
    m_config->spoofRdtsc = true;
    m_config->spoofMsr = true;
    m_config->spoofKuser = true;
    m_config->spoofStackSpoofer = true;
    m_config->captureMode = true;
    m_config->sandboxEnabled = GetPrivateProfileIntW(L"sandbox", L"enabled", 0, iniPath) != 0;

    wcscpy_s(r.errorMsg, L"Config baked");
    return r;
}

PhaseResult Orchestrator::Phase1_ByovdDetect() {
    PhaseResult r = {true, 1, L""};
    if (!m_config->byovd.enabled) {
        wcscpy_s(r.errorMsg, L"BYOVD disabled in config");
        return r;
    }

    // Set drivers directory relative to launcher
    wchar_t launcherDir[MAX_PATH];
    GetModuleFileNameW(nullptr, launcherDir, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(launcherDir, L'\\');
    if (lastSlash) *lastSlash = L'\0';

    ByovdDetect* det = new ByovdDetect();
    det->SetDriversDir((std::wstring(launcherDir) + L"\\drivers").c_str());
    DetectedDriver dr = det->DetectAndOpen();

    if (dr.deviceHandle && dr.deviceHandle != INVALID_HANDLE_VALUE) {
        m_driver = new DetectedDriver(dr);
        m_config->byovd.deviceHandle = dr.deviceHandle;
        m_config->byovd.capabilities = dr.capabilities;
        wcscpy_s(m_config->byovd.driverPath, dr.driverPath);
        wcscpy_s(r.errorMsg, L"BYOVD driver opened");
    } else {
        r.success = false;
        wcscpy_s(r.errorMsg, L"No BYOVD driver found or installed");
        delete det;
    }
    return r;
}

PhaseResult Orchestrator::Phase2_KernelProxyInject() {
    PhaseResult r = {true, 2, L""};
    if (!m_config->kernelProxy.enabled || !m_driver) {
        wcscpy_s(r.errorMsg, L"Kernel proxy disabled or no BYOVD available");
        return r;
    }

    KernelProxy* kp = new KernelProxy();
    if (!kp->Initialize(m_driver->deviceHandle, m_driver->capabilities)) {
        r.success = false;
        wcscpy_s(r.errorMsg, L"KernelProxy::Initialize failed");
        delete kp;
        return r;
    }

    // Deploy EPROCESS sanitizer
    EprocessSanitizerParams sp = {};
    sp.hideProcFromDbgk = true;
    sp.hideProcFromPeb = true;
    sp.hideThreads = true;
    sp.spoofCreateTime = true;
    sp.spoofParentPid = true;
    sp.spoofedParentPid = 4; // system PID
    kp->DeployEprocessSanitizer(sp);

    // Install LSTAR monitor
    LstarMonitorParams lp = {};
    kp->InstallLstarMonitor(lp);

    // Hide from driver list
    kp->HideDriverList();

    wcscpy_s(r.errorMsg, L"Kernel proxy deployed");
    return r;
}

PhaseResult Orchestrator::Phase3_SandboxSetup() {
    PhaseResult r = {true, 3, L""};
    // Stub — sandbox setup (VHDX mount, redirected paths)
    wcscpy_s(r.errorMsg, L"Sandbox setup skipped (stub)");
    return r;
}

PhaseResult Orchestrator::Phase4_PartitionCreate() {
    PhaseResult r = {true, 4, L""};
    // WHP partition creation is handled by the engine after injection
    // We pre-create the WHP partition handle and pass it
    // Stub for now
    wcscpy_s(r.errorMsg, L"Partition pre-create stub");
    return r;
}

PhaseResult Orchestrator::Phase5_RenameDlls() {
    PhaseResult r = {true, 5, L""};

    m_renamer.Init(m_seed);

    // Register all proxy DLLs
    m_renamer.RegisterDll(L"engine.dll");
    m_renamer.RegisterDll(L"ntdll_proxy.dll");
    m_renamer.RegisterDll(L"kernel32_proxy.dll");
    m_renamer.RegisterDll(L"dxvk_d3d11.dll");
    m_renamer.RegisterDll(L"dxvk_dxgi.dll");
    m_renamer.RegisterDll(L"win32u_proxy.dll");
    m_renamer.RegisterDll(L"user32_proxy.dll");
    m_renamer.RegisterDll(L"gdi32_proxy.dll");
    m_renamer.RegisterDll(L"advapi32_proxy.dll");
    m_renamer.RegisterDll(L"sechost_proxy.dll");
    m_renamer.RegisterDll(L"rpcrt4_proxy.dll");
    m_renamer.RegisterDll(L"ws2_32_proxy.dll");
    m_renamer.RegisterDll(L"iphlpapi_proxy.dll");
    m_renamer.RegisterDll(L"crypt32_proxy.dll");
    m_renamer.RegisterDll(L"bcrypt_proxy.dll");

    m_renamer.GenerateNames();

    // Build rename table into config
    m_config->proxyRenameCount = 15;
    m_renamer.BuildTable((RenameTable*)&m_config->proxyRenames);

    wcscpy_s(r.errorMsg, L"Proxy DLL names generated");
    return r;
}

PhaseResult Orchestrator::Phase6_InjectEngine() {
    PhaseResult r = {true, 6, L""};
    // Stub: engine injection via CreateRemoteThread or reflective DLL injection
    wcscpy_s(r.errorMsg, L"Injection stub");
    return r;
}

PhaseResult Orchestrator::Phase7_ResumeTarget() {
    PhaseResult r = {true, 7, L""};
    // Stub: NtResumeThread on target
    wcscpy_s(r.errorMsg, L"Resume stub");
    return r;
}

void Orchestrator::Shutdown() {
    if (m_driver) {
        if (m_driver->deviceHandle) CloseHandle(m_driver->deviceHandle);
        delete m_driver;
        m_driver = nullptr;
    }
    m_active = false;
}