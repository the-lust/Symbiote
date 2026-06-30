// Symbiote Hardware Fingerprint Capture Tool
// Standalone: no injection, no VEH, no hooks. Just dumps what the PC returns.
// Output: capture.log (tab-separated, one query per line)

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <intrin.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

static FILE* g_log = nullptr;
static LARGE_INTEGER g_qpf, g_qpcStart;

static void OpenLog()
{
    g_log = fopen("capture.log", "w");
    if (!g_log) g_log = stdout;
    QueryPerformanceFrequency(&g_qpf);
    QueryPerformanceCounter(&g_qpcStart);
    fprintf(g_log, "# Symbiote Hardware Fingerprint Capture\n");
    fprintf(g_log, "# VECTOR\\ttimestamp_us\\tfields...\n");
    fflush(g_log);
}

static void Log(const char* vector, const char* fmt, ...)
{
    if (!g_log) return;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    uint64_t us = (uint64_t)((now.QuadPart - g_qpcStart.QuadPart) * 1000000 / g_qpf.QuadPart);
    fprintf(g_log, "%s\t%llu\t", vector, (unsigned long long)us);
    va_list args;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);
    fprintf(g_log, "\n");
    fflush(g_log);
}

static void CloseLog()
{
    if (g_log && g_log != stdout) fclose(g_log);
}

// ─── CPUID ──────────────────────────────────────────────────────────────────

static void CaptureCpuidAll()
{
    int info[4] = {0};
    __cpuid(info, 0);
    uint32_t maxLeaf = (uint32_t)info[0];
    char vendor[13] = {0};
    memcpy(vendor, &info[1], 4);
    memcpy(vendor + 4, &info[3], 4);
    memcpy(vendor + 8, &info[2], 4);
    Log("CPUID", "0x0\t0x%08X\t\"%s\"\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
        maxLeaf, vendor, (uint32_t)info[0], (uint32_t)info[1], (uint32_t)info[2], (uint32_t)info[3]);

    uint32_t leaves[] = {
        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA,
        0xB, 0xC, 0xD, 0xF, 0x10, 0x12, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x80000000, 0x80000001, 0x80000002,
        0x80000003, 0x80000004, 0x80000005, 0x80000006, 0x80000007,
        0x80000008, 0x80000009, 0x8000000A, 0x8000000B, 0x8000000C,
        0x8000000D, 0x8000000E, 0x8000000F, 0x80000010, 0x80000011,
        0x80000012, 0x80000013, 0x80000014, 0x80000015, 0x80000016,
        0x80000017, 0x80000018, 0x80000019, 0x8000001A, 0x8000001B,
        0x8000001C, 0x8000001D, 0x8000001E, 0x8000001F, 0x80000020,
    };
    for (auto leaf : leaves) {
        if (leaf > maxLeaf && leaf < 0x80000000) continue;
        if (leaf > 0x80000000 && leaf > (uint32_t)info[0]) {
            // For extended leaves, re-run CPUID 0x80000000 to check max
            int extInfo[4] = {0};
            __cpuid(extInfo, 0x80000000);
            if (leaf > (uint32_t)extInfo[0]) continue;
        }
        __cpuid(info, leaf);
        Log("CPUID", "0x%X\t0x%08X\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
            leaf, 0,
            (uint32_t)info[0], (uint32_t)info[1], (uint32_t)info[2], (uint32_t)info[3]);
    }

    // CPUID with subleaves (0x4, 0x7, 0xB, 0xD, 0xF, 0x10, 0x12, 0x14, etc.)
    for (uint32_t subleaf = 0; subleaf < 64; subleaf++) {
        __cpuidex(info, 4, subleaf);
        if (!info[0] && !info[1] && !info[2] && !info[3]) break;
        Log("CPUID", "0x4\t0x%X\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
            subleaf, (uint32_t)info[0], (uint32_t)info[1], (uint32_t)info[2], (uint32_t)info[3]);
    }
    for (uint32_t subleaf = 0; subleaf < 64; subleaf++) {
        __cpuidex(info, 0xB, subleaf);
        if (!info[0] && !info[1] && !info[2] && !info[3]) break;
        Log("CPUID", "0xB\t0x%X\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
            subleaf, (uint32_t)info[0], (uint32_t)info[1], (uint32_t)info[2], (uint32_t)info[3]);
    }
    // Subleaf 0 of leaf 0xD has meaningful zeros, use subleaf 1 for XSAVE
    for (uint32_t subleaf = 0; subleaf < 64; subleaf++) {
        __cpuidex(info, 0xD, subleaf);
        if (subleaf > 0 && !info[0] && !info[1] && !info[2] && !info[3]) break;
        Log("CPUID", "0xD\t0x%X\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
            subleaf, (uint32_t)info[0], (uint32_t)info[1], (uint32_t)info[2], (uint32_t)info[3]);
    }
}

// ─── MSR ─────────────────────────────────────────────────────────────────────

static void CaptureMsrAll()
{
    struct MsrEntry { uint32_t msr; const char* name; };
    MsrEntry msrs[] = {
        {0x10, "IA32_TSC"}, {0x17, "IA32_PLATFORM_ID"}, {0x1B, "IA32_APIC_BASE"},
        {0x3A, "IA32_FEATURE_CONTROL"}, {0x8B, "IA32_BIOS_SIGN_ID"},
        {0xCE, "IA32_PLATFORM_INFO"}, {0xFE, "IA32_MTRR_CAP"},
        {0x174, "IA32_SYSENTER_CS"}, {0x175, "IA32_SYSENTER_ESP"},
        {0x176, "IA32_SYSENTER_EIP"}, {0x179, "IA32_MCG_CAP"},
        {0x17A, "IA32_MCG_STATUS"}, {0x17E, "IA32_PPIN"},
        {0x17F, "IA32_PPIN_CTL"}, {0x198, "IA32_PERF_STATUS"},
        {0x199, "IA32_PERF_CTL"}, {0x19C, "IA32_THERM_STATUS"},
        {0x1A0, "IA32_MISC_ENABLE"}, {0x1A2, "IA32_TEMPERATURE_TARGET"},
        {0x1B0, "IA32_ENERGY_PERF_BIAS"}, {0x1B1, "IA32_PKG_THERM_STATUS"},
        {0x1D9, "IA32_DEBUGCTL"}, {0x2FF, "IA32_MTRR_DEF_TYPE"},
        {0x600, "IA32_DS_AREA"}, {0x770, "IA32_PM_ENABLE"},
        {0x771, "IA32_HWP_CAPABILITIES"}, {0x772, "IA32_HWP_REQUEST_PKG"},
        {0xC0000080, "IA32_EFER"}, {0xC0000081, "IA32_STAR"},
        {0xC0000082, "IA32_LSTAR"}, {0xC0000083, "IA32_CSTAR"},
        {0xC0000084, "IA32_FMASK"}, {0xC0000100, "FS_BASE"},
        {0xC0000101, "GS_BASE"}, {0xC0000102, "KERNEL_GS_BASE"},
        // IA32_VMX MSRs
        {0x480, "VMX_BASIC"}, {0x481, "VMX_PINBASED_CTLS"},
        {0x482, "VMX_PROCBASED_CTLS"}, {0x483, "VMX_EXIT_CTLS"},
        {0x484, "VMX_ENTRY_CTLS"}, {0x485, "VMX_MISC"},
        {0x486, "VMX_CR0_FIXED0"}, {0x487, "VMX_CR0_FIXED1"},
        {0x488, "VMX_CR4_FIXED0"}, {0x489, "VMX_CR4_FIXED1"},
        {0x48A, "VMX_VMCS_ENUM"}, {0x48B, "VMX_PROCBASED_CTLS2"},
        {0x48C, "VMX_EPT_VPID_CAP"}, {0x48D, "VMX_TRUE_PINBASED_CTLS"},
        {0x48E, "VMX_TRUE_PROCBASED_CTLS"}, {0x48F, "VMX_TRUE_EXIT_CTLS"},
        {0x490, "VMX_TRUE_ENTRY_CTLS"}, {0x491, "VMX_VMFUNC"},
    };
    for (auto& e : msrs) {
        __try {
            uint64_t val = __readmsr(e.msr);
            Log("MSR_READ", "0x%X\t%s\t0x%llX", e.msr, e.name, (unsigned long long)val);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("MSR_READ", "0x%X\t%s\t#GP", e.msr, e.name);
        }
    }
}

// ─── RDTSC ───────────────────────────────────────────────────────────────────

static void CaptureRdtsc()
{
    uint64_t tsc = __rdtsc();
    Log("RDTSC", "0x%llX", (unsigned long long)tsc);
    unsigned aux;
    uint64_t tscp = __rdtscp(&aux);
    Log("RDTSCP", "0x%llX\taux=0x%X", (unsigned long long)tscp, aux);
}

// ─── KUSER_SHARED_DATA ───────────────────────────────────────────────────────

static void CaptureKuser()
{
    uint8_t* kuser = (uint8_t*)0x7FFE0000;
    struct { uint32_t offset; const char* name; uint32_t size; } fields[] = {
        {0x2E0, "Version", 4}, {0x2E8, "ProductType", 1},
        {0x2D0, "SuiteMask", 4}, {0x2E4, "BuildNumber", 4},
        {0x310, "SystemTime", 8}, {0x318, "InterruptTime", 8},
        {0x320, "SystemTimeHigh", 4}, {0x370, "QpcValue", 8},
        {0x378, "QpcShift", 4}, {0x3C0, "TickCount", 8},
    };
    for (auto& f : fields) {
        uint64_t val = 0;
        memcpy(&val, kuser + f.offset, f.size > 8 ? 8 : f.size);
        Log("KUSER", "0x%X\t%s\t0x%llX", f.offset, f.name, (unsigned long long)val);
    }
}

// ─── SYSTEM INFO ──────────────────────────────────────────────────────────────

typedef NTSTATUS(NTAPI* NtQuerySysInfoFunc)(ULONG, PVOID, ULONG, PULONG);
static NtQuerySysInfoFunc g_NtQuerySystemInformation = nullptr;

static void CaptureSysInfo()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    g_NtQuerySystemInformation = (NtQuerySysInfoFunc)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!g_NtQuerySystemInformation) return;

    struct { ULONG cls; const char* name; } classes[] = {
        {0, "SystemBasicInformation"},
        {1, "SystemProcessorInformation"},
        {2, "SystemPerformanceInformation"},
        {5, "SystemProcessInformation"},
        {8, "SystemProcessorPerformanceInformation"},
        {11, "SystemModuleInformation"},
        {75, "SystemFirmwareTableInformation"},
    };
    for (auto& c : classes) {
        uint8_t buf[8192];
        ULONG retLen = 0;
        NTSTATUS s = g_NtQuerySystemInformation(c.cls, buf, sizeof(buf), &retLen);
        Log("SYSCALL", "NtQuerySystemInformation\t%u\t%s\t0x%X\t%u bytes",
            c.cls, c.name, (uint32_t)s, retLen);
    }
}

// ─── REGISTRY ─────────────────────────────────────────────────────────────────

static void CaptureRegistry()
{
    struct { const wchar_t* path; const wchar_t* value; const char* name; } keys[] = {
        {L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString", "CPU Name"},
        {L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"Identifier", "CPU ID"},
        {L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"VendorIdentifier", "CPU Vendor"},
        {L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"MHz", "CPU MHz"},
        {L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"~MHz", "CPU ~MHz"},
        {L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"Component Information", "CPU CompInfo"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer", "BIOS Manufacturer"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName", "BIOS Product"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemVersion", "BIOS Version"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardManufacturer", "Motherboard Manufacturer"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardProduct", "Motherboard Product"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor", "BIOS Vendor"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion", "BIOS Version"},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSReleaseDate", "BIOS Date"},
        {L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0", L"Component Information", "Adapter Info"},
    };

    for (auto& k : keys) {
        HKEY hKey;
        wchar_t fullPath[512];
        wcscpy_s(fullPath, k.path);
        // Try both HKLM and HKCU
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            uint8_t data[4096];
            DWORD type = 0, size = sizeof(data);
            if (RegQueryValueExW(hKey, k.value, NULL, &type, data, &size) == ERROR_SUCCESS) {
                char preview[128] = {0};
                if (type == REG_SZ || type == REG_MULTI_SZ) {
                    char* s = (char*)data;
                    int len = (size < 100) ? (int)size : 100;
                    for (int i = 0; i < len && s[i]; i++) {
                        preview[i] = (s[i] >= 32 && s[i] < 127) ? s[i] : '.';
                    }
                    preview[len] = 0;
                } else if (type == REG_DWORD) {
                    snprintf(preview, sizeof(preview), "0x%08X", *(uint32_t*)data);
                } else {
                    snprintf(preview, sizeof(preview), "(%u bytes type=%u)", size, type);
                }
                Log("REGISTRY", "HKLM\\%ls\\%ls\t%s", k.path, k.value, preview);
            }
            RegCloseKey(hKey);
        }
    }
}

// ─── GPU ──────────────────────────────────────────────────────────────────────

static void CaptureGpu()
{
    DISPLAY_DEVICEW dd;
    dd.cb = sizeof(dd);
    for (DWORD i = 0; EnumDisplayDevicesW(NULL, i, &dd, 0); i++) {
        char name[128] = {0}, desc[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, dd.DeviceName, -1, name, sizeof(name), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, dd.DeviceString, -1, desc, sizeof(desc), NULL, NULL);
        Log("GPU", "Display%u\t%s\t%s\tflags=0x%X", i, name, desc, dd.StateFlags);
        dd.cb = sizeof(dd);
    }
}

// ─── MEMORY / SYSTEM ─────────────────────────────────────────────────────────

static void CaptureMemoryAndSystem()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    Log("SYSTEM", "GetSystemInfo: pagesize=0x%X minAddr=%p maxAddr=%p cores=%u",
        si.dwPageSize, si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress,
        si.dwNumberOfProcessors);

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    Log("SYSTEM", "GlobalMemoryStatusEx: totalPhys=%llu freePhys=%llu totalPage=%llu",
        (unsigned long long)ms.ullTotalPhys, (unsigned long long)ms.ullAvailPhys,
        (unsigned long long)ms.ullTotalPageFile);
}

// ─── LOOP CAPTURE ─────────────────────────────────────────────────────────────

static void CaptureLoop()
{
    int qi[4];
    LARGE_INTEGER qpf;
    QueryPerformanceFrequency(&qpf);
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    const uint64_t RUN_US = 310 * 1000000; // ~5 min 10 sec safety margin

    for (int iter = 0; ; iter++) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        uint64_t elapsed_us = (now.QuadPart - start.QuadPart) * 1000000 / qpf.QuadPart;
        if (elapsed_us > RUN_US) break;

        Log("ITERATION", "%d\telapsed_us=%llu", iter, (unsigned long long)elapsed_us);

        // ── Fast poll: key leaves every iteration (~0.5s apart) ──
        __cpuidex(qi, 1, 0);
        Log("CPUID_POLL", "0x1\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
            (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);

        __cpuidex(qi, 7, 0);
        Log("CPUID_POLL", "0x7/0\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
            (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);

        // RDTSC + RDTSCP
        unsigned aux = 0;
        Log("RDTSC_POLL", "0x%llX", (unsigned long long)__rdtsc());
        uint64_t tscpVal = __rdtscp(&aux);
        Log("RDTSCP_POLL", "0x%llX\taux=0x%X", (unsigned long long)tscpVal, aux);

        // KUSER key fields
        uint8_t* kuser = (uint8_t*)0x7FFE0000;
        uint64_t v;
        v = 0; memcpy(&v, kuser + 0x310, 8);
        Log("KUSER_POLL", "SystemTime\t0x%llX", (unsigned long long)v);
        v = 0; memcpy(&v, kuser + 0x318, 8);
        Log("KUSER_POLL", "InterruptTime\t0x%llX", (unsigned long long)v);
        v = 0; memcpy(&v, kuser + 0x370, 8);
        Log("KUSER_POLL", "QpcValue\t0x%llX", (unsigned long long)v);
        v = 0; memcpy(&v, kuser + 0x378, 4);
        Log("KUSER_POLL", "QpcShift\t0x%llX", (unsigned long long)v);
        v = 0; memcpy(&v, kuser + 0x3C0, 8);
        Log("KUSER_POLL", "TickCount\t0x%llX", (unsigned long long)v);

        // TIMING_DELTA
        uint64_t tb = __rdtsc();
        __cpuid(qi, 0);
        uint64_t ta = __rdtsc();
        Log("TIMING_POLL", "CPUID(0) delta=%llu cycles",
            (unsigned long long)(ta - tb));

        // QPC
        LARGE_INTEGER qpcNow;
        QueryPerformanceCounter(&qpcNow);
        Log("QPC_POLL", "0x%llX", (unsigned long long)qpcNow.QuadPart);

        // ── Full poll every 30 iterations (~15s) ──
        if (iter % 30 == 0) {
            __cpuidex(qi, 2, 0);
            Log("CPUID_POLL", "0x2\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
            __cpuidex(qi, 3, 0);
            Log("CPUID_POLL", "0x3\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
            __cpuidex(qi, 4, 0);
            Log("CPUID_POLL", "0x4/0\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
            __cpuidex(qi, 5, 0);
            Log("CPUID_POLL", "0x5\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
            __cpuidex(qi, 6, 0);
            Log("CPUID_POLL", "0x6\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
            __cpuidex(qi, 0xA, 0);
            Log("CPUID_POLL", "0xA\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
            __cpuidex(qi, 0xD, 0);
            Log("CPUID_POLL", "0xD/0\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
            __cpuidex(qi, 0x80000001, 0);
            Log("CPUID_POLL", "0x80000001\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
            __cpuidex(qi, 0x80000008, 0);
            Log("CPUID_POLL", "0x80000008\t0x%08X\t0x%08X\t0x%08X\t0x%08X",
                (uint32_t)qi[0], (uint32_t)qi[1], (uint32_t)qi[2], (uint32_t)qi[3]);
        }

        // ── Sleep ~250ms ──
        LARGE_INTEGER sleepStart;
        QueryPerformanceCounter(&sleepStart);
        while (true) {
            LARGE_INTEGER nowSleep;
            QueryPerformanceCounter(&nowSleep);
            uint64_t sElapsed = (nowSleep.QuadPart - sleepStart.QuadPart) * 1000000 / qpf.QuadPart;
            if (sElapsed >= 250000) break;
            // Spin a tiny bit but don't burn CPU — small Sleep
            if (sElapsed < 200000) Sleep(50);
        }
    }
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────

int main()
{
    OpenLog();
    Log("INFO", "Starting hardware fingerprint capture (5 min loop)...");
    OSVERSIONINFOW ovi = {0}; ovi.dwOSVersionInfoSize = sizeof(ovi);
    #pragma warning(push)
    #pragma warning(disable: 4996)
    GetVersionExW(&ovi);
    #pragma warning(pop)
    Log("INFO", "OS: Windows %d.%d build %d",
        (int)ovi.dwMajorVersion, (int)ovi.dwMinorVersion, (int)ovi.dwBuildNumber);

    // Full initial dump
    Log("INFO", "=== INITIAL FULL DUMP ===");
    CaptureCpuidAll();
    CaptureMsrAll();
    CaptureRdtsc();
    CaptureKuser();
    CaptureSysInfo();
    CaptureRegistry();
    CaptureGpu();
    CaptureMemoryAndSystem();
    // CPUID Timing delta (RDTSC before and after CPUID)
    uint64_t tscBefore = __rdtsc();
    int qi[4] = {0};
    __cpuid(qi, 0);
    uint64_t tscAfter = __rdtsc();
    Log("TIMING_DELTA", "RDTSC->CPUID(0)->RDTSC delta=%llu cycles",
        (unsigned long long)(tscAfter - tscBefore));
    LARGE_INTEGER qpf;
    QueryPerformanceFrequency(&qpf);
    Log("SYSTEM", "QPC frequency: %llu Hz", (unsigned long long)qpf.QuadPart);
    Log("INFO", "ComputerName: %s", getenv("COMPUTERNAME") ? getenv("COMPUTERNAME") : "?");
    Log("INFO", "UserName: %s", getenv("USERNAME") ? getenv("USERNAME") : "?");

    // 5-minute loop
    Log("INFO", "=== STARTING 5-MINUTE POLL LOOP ===");
    CaptureLoop();

    Log("INFO", "Capture complete. %lld bytes written.",
        (long long)(g_log ? ftell(g_log) : 0));
    CloseLog();

    printf("\nCapture complete. Results written to capture.log\n");
    printf("Press Enter to exit...");
    getchar();
    return 0;
}
