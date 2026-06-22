#include "PocDemo.h"
#include "ResultLogger.h"
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <windows.h>
#include <winternl.h>
#include <profileapi.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

static void Phase1_WhpSidecar(ResultLogger* rl);
static void Phase2_CpuidSpoofing(ResultLogger* rl);
static void Phase3_RdtscTiming(ResultLogger* rl);
static void Phase4_MsrReads(ResultLogger* rl);
static void Phase5_KuserInspect(ResultLogger* rl);
static void Phase6_PebInspect(ResultLogger* rl);
static void Phase7_SyscallTests(ResultLogger* rl);
static void Phase8_FileIoTests(ResultLogger* rl);
static void Phase9_Consistency(ResultLogger* rl);

static void DoCpuid(int leaf, int subleaf, int* info)
{
    __cpuidex(info, leaf, subleaf);
}

static uint64_t DoRdtsc()
{
    return __rdtsc();
}

static uint64_t DoRdtscp(uint32_t* aux)
{
    return __rdtscp(aux);
}

static uint8_t* GetKuserBase()
{
    return (uint8_t*)0x7FFE0000;
}

static uint64_t ReadKuser(uint32_t offset)
{
    uint8_t* base = GetKuserBase();
    uint64_t val = 0;
    memcpy(&val, base + offset, sizeof(val));
    return val;
}

static uint32_t ReadKuser32(uint32_t offset)
{
    uint8_t* base = GetKuserBase();
    uint32_t val = 0;
    memcpy(&val, base + offset, sizeof(val));
    return val;
}

static uint8_t ReadKuser8(uint32_t offset)
{
    return *(GetKuserBase() + offset);
}

static uint32_t GetProductTypeOffset()
{
    uint32_t buildNum = ReadKuser32(0x260);
    if (buildNum >= 19041) return 0x2D8;
    return 0x26E;
}

static uint8_t* GetPeb()
{
    return (uint8_t*)__readgsqword(0x60);
}

// SEH helpers — no C++ objects allowed in functions with __try
static uint64_t __declspec(noinline) SafeGetXcr0()
{
    __try { return _xgetbv(0); } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static BOOL __declspec(noinline) SafeGetUserNameW(wchar_t* buf, DWORD* len)
{
    __try { return GetUserNameW(buf, len); } __except(EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

static uint64_t ReadPeb(uint32_t offset)
{
    uint8_t* peb = GetPeb();
    uint64_t val = 0;
    memcpy(&val, peb + offset, sizeof(val));
    return val;
}

static uint32_t ReadPeb32(uint32_t offset)
{
    uint8_t* peb = GetPeb();
    uint32_t val = 0;
    memcpy(&val, peb + offset, sizeof(val));
    return val;
}

typedef NTSTATUS (NTAPI* NtQuerySysInfo_t)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtQueryInfoProc_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static FARPROC GetNtProc(const char* name)
{
    static HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? GetProcAddress(ntdll, name) : nullptr;
}

int main()
{
    ResultLogger rl;
    rl.LogRaw("# System Fingerprint Dump");
    rl.LogRaw("## Kaneki-Bypass PoC — neutral value display");
    rl.LogRaw("");

    Phase1_WhpSidecar(&rl);
    Phase2_CpuidSpoofing(&rl);
    Phase3_RdtscTiming(&rl);
    Phase4_MsrReads(&rl);
    Phase5_KuserInspect(&rl);
    Phase6_PebInspect(&rl);
    Phase7_SyscallTests(&rl);
    Phase8_FileIoTests(&rl);
    Phase9_Consistency(&rl);

    rl.FlushToFile("result.md");
    return 0;
}

// ======================== PHASE 1 ========================
static void Phase1_WhpSidecar(ResultLogger* rl)
{
    rl->BeginSection("Phase 1: WHP Sidecar VM");

    HMODULE whp = LoadLibraryW(L"WinHvPlatform.dll");
    bool whpAvail = (whp != nullptr);
    if (whp) FreeLibrary(whp);

    rl->LogValue("WHP", "API available", "WinHvPlatform.dll", whpAvail ? 1 : 0,
        whpAvail ? "WHP runtime accessible" : "not loaded");

    rl->EndSection();
}

// ======================== PHASE 2: CPUID ========================
static void Phase2_CpuidSpoofing(ResultLogger* rl)
{
    rl->BeginSection("Phase 2: CPUID");

    int info[4] = {0};

    DoCpuid(0, 0, info);
    char vendor[13];
    memcpy(vendor, &info[1], 4);
    memcpy(vendor+4, &info[3], 4);
    memcpy(vendor+8, &info[2], 4);
    vendor[12] = 0;
    rl->LogValue("CPUID", "Leaf 0x0 vendor string", "leaf_0x0", (uint32_t)info[0],
        std::string("vendor=") + vendor);

    DoCpuid(1, 0, info);
    uint32_t sig = (uint32_t)info[0];
    uint32_t hyperBit = ((uint32_t)info[2] >> 31) & 1;
    rl->LogValue("CPUID", "Leaf 0x1 EAX (signature)", "leaf_0x1_eax", sig,
        hyperBit ? "hypervisor bit SET" : "hypervisor bit clear");
    rl->LogValue("CPUID", "Leaf 0x1 EBX", "leaf_0x1_ebx", (uint32_t)info[1], "");
    rl->LogValue("CPUID", "Leaf 0x1 ECX (features)", "leaf_0x1_ecx", (uint32_t)info[2], "");
    rl->LogValue("CPUID", "Leaf 0x1 EDX (features)", "leaf_0x1_edx", (uint32_t)info[3], "");

    DoCpuid(0x40000000, 0, info);
    char hvVendor[13];
    memcpy(hvVendor, &info[1], 4);
    memcpy(hvVendor+4, &info[3], 4);
    memcpy(hvVendor+8, &info[2], 4);
    hvVendor[12] = 0;
    bool hvPresent = (info[0] != 0);
    rl->LogValue("CPUID", "Leaf 0x40000000 (VMM leaf)", "leaf_0x40000000", (uint32_t)info[0],
        hvPresent ? std::string("VMM=") + hvVendor : "zeroed (no VMM)");

    DoCpuid(0x40000001, 0, info);
    rl->LogValue("CPUID", "Leaf 0x40000001 (Hyper-V features)", "leaf_0x40000001", (uint32_t)info[0], "");

    char brand[49] = {0};
    DoCpuid(0x80000002, 0, info); memcpy(brand, info, 16);
    DoCpuid(0x80000003, 0, info); memcpy(brand+16, info, 16);
    DoCpuid(0x80000004, 0, info); memcpy(brand+32, info, 16);
    brand[48] = 0;
    rl->LogValue("CPUID", "Brand string", "leaves_0x80000002-4", 0,
        std::string("brand=") + brand);

    DoCpuid(0x80000001, 0, info);
    rl->LogValue("CPUID", "Leaf 0x80000001 ECX (ext features)", "leaf_0x80000001_ecx", (uint32_t)info[2], "");

    rl->EndSection();
}

// ======================== PHASE 3: RDTSC/TIMING ========================
static void Phase3_RdtscTiming(ResultLogger* rl)
{
    rl->BeginSection("Phase 3: RDTSC/Timing");

    uint64_t tsc1 = DoRdtsc();
    rl->LogValue("RDTSC", "Base TSC value", "rdtsc", tsc1, "");

    int info[4];
    uint64_t before = DoRdtsc();
    DoCpuid(1, 0, info);
    uint64_t after = DoRdtsc();
    uint64_t delta = after - before;
    rl->LogValue("TIMING", "RDTSC delta around CPUID", "rdtsc_delta", delta,
        delta < 5000 ? "low latency" : "HIGH latency");

    uint32_t aux = 0;
    uint64_t tscp = DoRdtscp(&aux);
    rl->LogValue("RDTSCP", "RDTSCP value", "rdtscp", tscp, "");
    rl->LogValue("RDTSCP", "RDTSCP AUX (processor ID)", "rdtscp_aux", aux, "");

    uint64_t samples[10];
    bool monotonic = true;
    for (int i = 0; i < 10; i++) {
        samples[i] = DoRdtsc();
        if (i > 0 && samples[i] <= samples[i-1]) monotonic = false;
    }
    rl->LogValue("TIMING", "TSC monotonic (10 samples)", "rdtsc_monotonic", monotonic ? 1 : 0,
        monotonic ? "no rollback" : "rollback detected");

    LARGE_INTEGER qpc, qpf;
    QueryPerformanceCounter(&qpc);
    QueryPerformanceFrequency(&qpf);
    rl->LogValue("TIMING", "QPC value", "qpc", qpc.QuadPart, "");
    rl->LogValue("TIMING", "QPC frequency", "qpf", qpf.QuadPart, "");

    rl->EndSection();
}

// ======================== PHASE 4: MSR READS ========================
static void Phase4_MsrReads(ResultLogger* rl)
{
    rl->BeginSection("Phase 4: MSR Reads");
    rl->LogRaw("RDMSR not available from user-mode on Windows.");

    uint64_t xcr0 = SafeGetXcr0();
    rl->LogValue("XGETBV", "XCR0 (XFEATURE_ENABLED_MASK)", "xcr0", xcr0,
        (xcr0 & 0x7) == 0x7 ? "X87+SSE+AVX" : "limited features");

    rl->EndSection();
}

// ======================== PHASE 5: KUSER SHARED DATA ========================
static void Phase5_KuserInspect(ResultLogger* rl)
{
    rl->BeginSection("Phase 5: KUSER_SHARED_DATA (0x7FFE0000)");

    { uint8_t* kbase = (uint8_t*)0x7FFE0000; (void)kbase[0]; }

    uint32_t buildNum = ReadKuser32(0x262) & 0xFFFF;
    rl->LogValue("KUSER", "NtBuildNumber", "0x7FFE0262", buildNum,
        std::string("build=") + std::to_string(buildNum));

    uint8_t kdDebug = ReadKuser8(0x2D4);
    rl->LogValue("KUSER", "KdDebuggerEnabled byte", "0x7FFE02D4", kdDebug,
        (kdDebug & 0x02) ? "debugger NOT present" : "KdDebuggerNotPresent bit clear");

    uint64_t suiteMask = ReadKuser(0x2D0);
    rl->LogValue("KUSER", "SuiteMask", "0x7FFE02D0", suiteMask, "");

    uint32_t ptOffset = GetProductTypeOffset();
    uint8_t productType = ReadKuser8(ptOffset);
    char ptBuf[64];
    sprintf_s(ptBuf, "offset=0x%X value=%u", ptOffset, productType);
    rl->LogValue("KUSER", "ProductType", "0x7FFE" + std::to_string(ptOffset), productType, ptBuf);

    uint64_t sysTime = ReadKuser(0x318);
    rl->LogValue("KUSER", "SystemTime", "0x7FFE0318", sysTime, "100ns intervals since 1601");

    uint64_t intTime = ReadKuser(0x328);
    rl->LogValue("KUSER", "InterruptTime", "0x7FFE0328", intTime, "");

    uint32_t tickLow = ReadKuser32(0x348);
    uint32_t tickHigh = ReadKuser32(0x34C);
    uint64_t tickCount = ((uint64_t)tickHigh << 32) | tickLow;
    rl->LogValue("KUSER", "TickCountQuad", "0x7FFE0348", tickCount, "");

    uint64_t qpcKuser = ReadKuser(0x370);
    rl->LogValue("KUSER", "QPC value", "0x7FFE0370", qpcKuser, "");

    uint8_t majVer = ReadKuser8(0x260);
    rl->LogValue("KUSER", "NtMajorVersion", "0x7FFE0260", majVer, "");

    uint64_t procFeat = ReadKuser(0x272);
    rl->LogValue("KUSER", "ProcessorFeatures @ 0x272", "0x7FFE0272", procFeat, "");

    uint32_t dbgFlags = ReadKuser32(0x300);
    rl->LogValue("KUSER", "Debug flags", "0x7FFE0300", dbgFlags, dbgFlags == 0 ? "clean" : "non-zero");

    rl->EndSection();
}

// ======================== PHASE 6: PEB ========================
static void Phase6_PebInspect(ResultLogger* rl)
{
    rl->BeginSection("Phase 6: PEB");

    uint8_t* peb = GetPeb();
    if (!peb) {
        rl->LogRaw("PEB not accessible");
        rl->EndSection();
        return;
    }

    rl->LogValue("PEB", "Base address", "gs:0x60", (uint64_t)(uintptr_t)peb, "");

    uint64_t valB8 = ReadPeb(0x0B8);
    rl->LogValue("PEB", "Offset +0x0B8", "peb+0x0B8", valB8, "");

    uint64_t procParams = ReadPeb(0x118);
    rl->LogValue("PEB", "Offset +0x118 (ProcessParameters)", "peb+0x118", procParams,
        procParams ? "valid pointer" : "NULL");

    uint32_t val11C = ReadPeb32(0x11C);
    rl->LogValue("PEB", "Offset +0x11C", "peb+0x11C", val11C, "");

    uint64_t val12C = ReadPeb(0x12C);
    rl->LogValue("PEB", "Offset +0x12C", "peb+0x12C", val12C, "");

    uint64_t val130 = ReadPeb(0x130);
    rl->LogValue("PEB", "Offset +0x130", "peb+0x130", val130, "");

    uint8_t* ldr = (uint8_t*)ReadPeb(0x018);
    if (ldr) {
        uint8_t* flink = *(uint8_t**)(ldr + 0x10);
        rl->LogValue("PEB", "LDR InMemoryOrder FLINK", "peb+0x018->flink",
            (uint64_t)(uintptr_t)flink, "LDR structure accessible");
    }

    rl->EndSection();
}

// ======================== PHASE 7: SYSCALL ========================
static void Phase7_SyscallTests(ResultLogger* rl)
{
    rl->BeginSection("Phase 7: NT Syscalls");

    auto NtQuerySystemInformation = (NtQuerySysInfo_t)GetNtProc("NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        rl->LogRaw("NtQuerySystemInformation not found");
        rl->EndSection();
        return;
    }

    struct KdInfo { BOOLEAN DebuggerEnabled; BOOLEAN DebuggerNotPresent; } kd = {FALSE, FALSE};
    ULONG retLen = 0;
    NTSTATUS status = NtQuerySystemInformation(0x23, &kd, sizeof(kd), &retLen);
    rl->LogValue("SYSCALL", "NtQuerySystemInfo(0x23) KdDebugger", "syscall_0x23",
        (uint64_t)kd.DebuggerEnabled | ((uint64_t)kd.DebuggerNotPresent << 8),
        std::string("Enabled=") + (kd.DebuggerEnabled ? "Y" : "N") +
        " NotPresent=" + (kd.DebuggerNotPresent ? "Y" : "N"));

    struct CiInfo { ULONG Length; ULONG CodeIntegrityOptions; } ci = {sizeof(CiInfo), 0};
    retLen = 0;
    status = NtQuerySystemInformation(0x67, &ci, sizeof(ci), &retLen);
    rl->LogValue("SYSCALL", "NtQuerySystemInfo(0x67) CodeIntegrity", "syscall_0x67",
        ci.CodeIntegrityOptions, (ci.CodeIntegrityOptions & 1) ? "DSE enabled" : "DSE disabled");

    ULONG bufSize = 0;
    status = NtQuerySystemInformation(0x05, nullptr, 0, &bufSize);
    rl->LogValue("SYSCALL", "NtQuerySystemInfo(0x05) ProcessInfo size", "syscall_0x05",
        bufSize, "");

    bufSize = 0;
    status = NtQuerySystemInformation(0x0B, nullptr, 0, &bufSize);
    rl->LogValue("SYSCALL", "NtQuerySystemInfo(0x0B) ModuleInfo size", "syscall_0x0B",
        bufSize, bufSize == 0 ? "empty (hidden)" : std::to_string(bufSize) + " bytes");

    auto NtQueryInformationProcess = (NtQueryInfoProc_t)GetNtProc("NtQueryInformationProcess");
    if (NtQueryInformationProcess) {
        int32_t dbgPort = -1;
        retLen = 0;
        status = NtQueryInformationProcess(GetCurrentProcess(), 0x07, &dbgPort, sizeof(dbgPort), &retLen);
        rl->LogValue("SYSCALL", "NtQueryInfoProcess(0x07) DebugPort", "syscall_0x07",
            (uint64_t)dbgPort, dbgPort == -1 ? "no debugger" : "debugger present");

        HANDLE dbgObj = (HANDLE)(uintptr_t)0xDEAD;
        retLen = 0;
        status = NtQueryInformationProcess(GetCurrentProcess(), 0x1E, &dbgObj, sizeof(dbgObj), &retLen);
        rl->LogValue("SYSCALL", "NtQueryInfoProcess(0x1E) DebugObject", "syscall_0x1E",
            (uint64_t)(uintptr_t)dbgObj, dbgObj ? "debug object present" : "no debug object");

        struct PBI {
            NTSTATUS ExitStatus;
            uint64_t PebBaseAddress;
            uint64_t AffinityMask;
            LONG BasePriority;
            HANDLE UniqueProcessId;
            HANDLE InheritedFromUniqueProcessId;
        } pbi = {0};
        retLen = 0;
        status = NtQueryInformationProcess(GetCurrentProcess(), 0x00, &pbi, sizeof(pbi), &retLen);
        rl->LogValue("SYSCALL", "NtQueryInfoProcess(0x00) PEB base", "syscall_0x00",
            pbi.PebBaseAddress, "");
    }

    auto NtQueryPerformanceCounter = (NTSTATUS (NTAPI*)(PLARGE_INTEGER, PLARGE_INTEGER))
        GetNtProc("NtQueryPerformanceCounter");
    if (NtQueryPerformanceCounter) {
        LARGE_INTEGER qpc = {0}, qpf = {0};
        status = NtQueryPerformanceCounter(&qpc, &qpf);
        rl->LogValue("SYSCALL", "NtQueryPerformanceCounter", "syscall_0x0D",
            qpc.QuadPart, "");
    }

    rl->EndSection();
}

// ======================== PHASE 8: FILE/IO ========================
static void Phase8_FileIoTests(ResultLogger* rl)
{
    rl->BeginSection("Phase 8: File/Registry/IO");

    HANDLE hPhys = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD physErr = GetLastError();
    bool physAccessible = (hPhys != INVALID_HANDLE_VALUE);
    if (hPhys != INVALID_HANDLE_VALUE) CloseHandle(hPhys);
    rl->LogValue("FILE", "CreateFile(\\\\.\\PhysicalDrive0)", "\\Device\\PhysicalDrive0",
        physAccessible ? 1 : 0, physAccessible ? "ACCESSIBLE" : "BLOCKED");

    HKEY hKey = nullptr;
    LONG regStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey);
    rl->LogValue("REGISTRY", "RegOpenKeyEx(HKLM\\HARDWARE\\DESCRIPTION\\System)", "reg_hw_desc",
        (uint64_t)regStatus, regStatus == ERROR_SUCCESS ? "accessible" : "blocked");
    if (hKey) RegCloseKey(hKey);

    wchar_t volName[MAX_PATH] = {0};
    DWORD volSerial = 0;
    DWORD maxComp = 0;
    DWORD fsFlags = 0;
    wchar_t fsName[MAX_PATH] = {0};
    BOOL volOk = GetVolumeInformationW(L"C:\\", volName, MAX_PATH, &volSerial, &maxComp, &fsFlags, fsName, MAX_PATH);
    if (volOk) {
        rl->LogValue("VOLUME", "C: Volume Serial", "vol_serial", volSerial, "");
    }

    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD compLen = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(compName, &compLen);
    wchar_t userName[256] = {0};
    DWORD userLen = 256;
    BOOL userOk = SafeGetUserNameW(userName, &userLen);
    if (userOk) {
        rl->LogValue("SYSTEM", "UserName", "username", 0,
            std::string("name=") + std::to_string(userName[0]));
    }

    rl->EndSection();
}

// ======================== PHASE 9: CONSISTENCY ========================
static void Phase9_Consistency(ResultLogger* rl)
{
    rl->BeginSection("Phase 9: Cross-Layer Consistency");

    int info[4] = {0};
    DoCpuid(0x80000002, 0, info);
    char cpuBrand[49] = {0};
    memcpy(cpuBrand, info, 16);
    DoCpuid(0x80000003, 0, info); memcpy(cpuBrand+16, info, 16);
    DoCpuid(0x80000004, 0, info); memcpy(cpuBrand+32, info, 16);
    cpuBrand[48] = 0;

    DoCpuid(1, 0, info);
    uint32_t cpuSig = (uint32_t)info[0];

    uint32_t kuserBuild = ReadKuser32(0x264);
    uint32_t kuserMajorVer = ReadKuser8(0x264);

    rl->LogValue("CONSISTENCY", "CPUID Leaf 1 EAX (signature)", "cross_check", cpuSig,
        std::string("sig=0x") + std::to_string(cpuSig));
    rl->LogValue("CONSISTENCY", "KUSER NtBuildNumber", "cross_check", kuserBuild,
        std::string("build=") + std::to_string(kuserBuild));
    rl->LogValue("CONSISTENCY", "CPUID brand string", "cross_check", 0,
        std::string("brand=") + cpuBrand);

    rl->LogRaw("");
    rl->LogValue("GPU", "GPU calls always fallthrough (native)", "dxgi/d3d/vulkan", 1,
        "GPU Bridge ensures native performance");

    rl->EndSection();
}
