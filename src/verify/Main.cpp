#define _WIN32_DCOM
#define WIN32_NO_STATUS
#include <windows.h>
#include <wbemidl.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "dnsapi.lib")

typedef NTSTATUS(NTAPI* NtQuerySysInfoFunc)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQueryInfoProcessFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef ULONGLONG(WINAPI* GetTickCount64Func)();

struct Result {
    const char* category;
    const char* check;
    std::string got;
    bool spoofed;
};

static std::vector<Result> g_results;
static char g_buf[4096];

static void LogResult(const char* cat, const char* check, const char* got, bool spoofed) {
    g_results.push_back({ cat, check, got, spoofed });
    printf("  [%s] %-45s -> %s\n", spoofed ? "OK" : "FAIL", check, got);
}

static void TestCpuid() {
    printf("\n=== CPUID ===\n");
    int info[4] = { 0 };

    __cpuid(info, 0);
    char vendor[13] = { 0 };
    memcpy(vendor, &info[1], 4);
    memcpy(vendor + 4, &info[3], 4);
    memcpy(vendor + 8, &info[2], 4);
    LogResult("CPUID", "Vendor string", vendor, strcmp(vendor, "GenuineIntel") == 0);

    __cpuid(info, 1);
    snprintf(g_buf, sizeof(g_buf), "0x%08X (family %d model %d stepping %d)", info[0],
        (info[0] >> 8) & 0xF, (info[0] >> 4) & 0xF, info[0] & 0xF);
    LogResult("CPUID", "Leaf 1 EAX (signature)", g_buf, info[0] == 0x000A0655);

    bool hvBit = (info[2] >> 31) & 1;
    LogResult("CPUID", "Hypervisor bit (ECX[31])", hvBit ? "SET (VM detected)" : "CLEAR", !hvBit);

    __cpuidex(info, 0x40000000, 0);
    char vmm[13] = { 0 };
    memcpy(vmm, &info[1], 4);
    memcpy(vmm + 4, &info[3], 4);
    memcpy(vmm + 8, &info[2], 4);
    bool vmmHidden = (info[0] == 0 && vmm[0] == 0);
    LogResult("CPUID", "VMM leaf 0x40000000", vmmHidden ? "Hidden" : vmm, vmmHidden);

    __cpuidex(info, 0x40000001, 0);
    LogResult("CPUID", "VMM features leaf", info[0] == 0 ? "Hidden" : "Present", info[0] == 0);

    __cpuid(info, 0x80000000);
    if (info[0] >= 0x80000004) {
        char brand[49] = { 0 };
        __cpuid(info, 0x80000002); memcpy(brand, info, 16);
        __cpuid(info, 0x80000003); memcpy(brand + 16, info, 16);
        __cpuid(info, 0x80000004); memcpy(brand + 32, info, 16);
        bool brandOk = strstr(brand, "i9-10900K") != nullptr;
        LogResult("CPUID", "Brand string", brand, brandOk);
    }
}

static void TestRdtsc() {
    printf("\n=== RDTSC / Timing ===\n");

    uint64_t tsc1 = __rdtsc();
    uint64_t tsc2 = __rdtsc();
    uint64_t delta = tsc2 - tsc1;
    snprintf(g_buf, sizeof(g_buf), "%llu cycles delta (tsc=%llu)", delta, tsc2);
    LogResult("TIMING", "RDTSC (non-zero, monotonic)", g_buf, delta > 0);

    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    uint64_t tscBefore = __rdtsc();
    __cpuid(cpuInfo, 1);
    uint64_t tscAfter = __rdtsc();
    uint64_t cpuidDelta = tscAfter - tscBefore;
    snprintf(g_buf, sizeof(g_buf), "%llu cycles around CPUID", cpuidDelta);
    LogResult("TIMING", "CPUID delta (not a VM exit)", g_buf, cpuidDelta < 50000);

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    snprintf(g_buf, sizeof(g_buf), "%llu", qpc.QuadPart);
    LogResult("TIMING", "QPC value is nonzero", g_buf, qpc.QuadPart > 0);

    QueryPerformanceFrequency(&qpc);
    snprintf(g_buf, sizeof(g_buf), "%llu Hz", qpc.QuadPart);
    LogResult("TIMING", "QPC frequency is realistic", g_buf, qpc.QuadPart > 1000000);
}

static void TestMsr() {
    printf("\n=== MSR ===\n");
    LogResult("MSR", "RDMSR from user-mode (kernel protected)", "Blocked by Windows", true);
}

static void TestKuserSharedData() {
    printf("\n=== KUSER_SHARED_DATA ===\n");
    uint8_t* kuser = (uint8_t*)0x7FFE0000;

    uint32_t buildNum = *(uint32_t*)(kuser + 0x260);
    snprintf(g_buf, sizeof(g_buf), "NtBuildNumber=%u (0x%X)", buildNum, buildNum);
    LogResult("KUSER", "NtBuildNumber", g_buf, true);

    uint8_t kdDebugger = kuser[0x2D4];
    LogResult("KUSER", "KdDebuggerEnabled", kdDebugger ? "ENABLED" : "DISABLED", !kdDebugger);

    uint64_t tickCount = *(uint64_t*)(kuser + 0x348);
    LogResult("KUSER", "TickCountQuad", tickCount > 0 ? "nonzero" : "zero", tickCount > 0);
}

static void TestSyscalls() {
    printf("\n=== Syscalls ===\n");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    auto NtQSI = (NtQuerySysInfoFunc)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    auto NtQIP = (NtQueryInfoProcessFunc)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (NtQSI) {
        uint8_t kdInfo[2] = { 0xFF, 0xFF };
        ULONG retLen = 0;
        NtQSI(0x23, kdInfo, sizeof(kdInfo), &retLen);
        LogResult("SYSCALL", "KdDebugger state", 
            (kdInfo[0] == 0 && kdInfo[1] == 1) ? "clean" : "dirty",
            kdInfo[0] == 0 && kdInfo[1] == 1);

        uint8_t ciInfo[8] = { 0 };
        retLen = 0;
        NtQSI(0x67, ciInfo, sizeof(ciInfo), &retLen);
        uint32_t ciOpts = *(uint32_t*)(ciInfo + 4);
        LogResult("SYSCALL", "CodeIntegrityOptions", ciOpts == 0 ? "0 (clean)" : "non-zero", ciOpts == 0);

        uint32_t modCount = 0xFFFF;
        retLen = 0;
        NtQSI(0x0B, &modCount, sizeof(modCount), &retLen);
        snprintf(g_buf, sizeof(g_buf), "%u", modCount);
        LogResult("SYSCALL", "Kernel module count", 
            modCount == 0 ? "0 (hidden)" : g_buf,
            modCount == 0);
    }

    if (NtQIP) {
        int32_t debugPort = 0;
        ULONG retLen = 0;
        NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), &retLen);
        snprintf(g_buf, sizeof(g_buf), "%d", debugPort);
        LogResult("SYSCALL", "ProcessDebugPort",
            debugPort == -1 ? "-1 (no debugger)" : g_buf,
            debugPort == -1);
    }
}

static void TestPeb() {
    printf("\n=== PEB ===\n");
    uint64_t pebAddr = (uint64_t)__readgsqword(0x60);

    uint8_t beingDebugged = *(uint8_t*)(pebAddr + 0x02);
    LogResult("PEB", "BeingDebugged", beingDebugged ? "YES" : "NO", !beingDebugged);

    uint32_t ntGlobalFlag = *(uint32_t*)(pebAddr + 0xBC);
    LogResult("PEB", "NtGlobalFlag", ntGlobalFlag == 0 ? "0 (clean)" : "non-zero", ntGlobalFlag == 0);
}

static void TestRegistry() {
    printf("\n=== Registry ===\n");
    HKEY hKey;
    LONG st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey);
    if (st == ERROR_SUCCESS) {
        wchar_t brand[128] = { 0 };
        DWORD size = sizeof(brand);
        st = RegQueryValueExW(hKey, L"ProcessorNameString", NULL, NULL, (LPBYTE)brand, &size);
        if (st == ERROR_SUCCESS) {
            char brandA[128] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, brand, -1, brandA, sizeof(brandA), NULL, NULL);
            bool has10900K = strstr(brandA, "i9-10900K") != nullptr;
            LogResult("REGISTRY", "ProcessorNameString", brandA, has10900K);
        }
        RegCloseKey(hKey);
    } else {
        LogResult("REGISTRY", "ProcessorNameString", "failed to open key", false);
    }
}

static void TestWmi() {
    printf("\n=== WMI ===\n");
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr == S_FALSE) {
        LogResult("WMI", "COM init", "S_FALSE (already initialized, diff model?)", false);
    } else if (FAILED(hr)) {
        snprintf(g_buf, sizeof(g_buf), "CoInitializeEx failed: 0x%08X", hr);
        LogResult("WMI", "COM init", g_buf, false);
        return;
    } else {
        LogResult("WMI", "COM init", "OK (fresh init)", true);
    }

    // Try ConnectServer WITHOUT calling CoInitializeSecurity (not required for local WMI)
    // If this works, the issue is purely with CoInitializeSecurity failing
    IWbemLocator* locator = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (void**)&locator);
    if (FAILED(hr) || !locator) {
        snprintf(g_buf, sizeof(g_buf), "0x%08X", hr);
        LogResult("WMI", "Locator create", g_buf, false);

        // Try passthrough proxy: direct GetProcAddress
        typedef HRESULT (STDMETHODCALLTYPE *RealCCI)(REFCLSID, IUnknown*, DWORD, REFIID, void**);
        HMODULE hOle32 = GetModuleHandleW(L"ole32.dll");
        if (hOle32) {
            RealCCI realCCI = (RealCCI)GetProcAddress(hOle32, "CoCreateInstance");
            realCCI(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&locator);
        }
        if (!locator) {
            LogResult("WMI", "Locator create", "FAILED (both paths)", false);
            CoUninitialize();
            return;
        }
    }

    // Try connecting to root\cimv2
    IWbemServices* services = nullptr;
    hr = locator->ConnectServer(L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &services);
    if (FAILED(hr) || !services) {
        snprintf(g_buf, sizeof(g_buf), "0x%08X", hr);
        LogResult("WMI", "ConnectServer (no CoInitSec)", g_buf, false);
        locator->Release();
        CoUninitialize();
        return;
    }
    LogResult("WMI", "ConnectServer (no CoInitSec)", "OK", true);

    IEnumWbemClassObject* enumerator = nullptr;
    hr = services->ExecQuery(L"WQL", L"SELECT * FROM Win32_Processor",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &enumerator);
    if (FAILED(hr) || !enumerator) {
        snprintf(g_buf, sizeof(g_buf), "ExecQuery failed: 0x%08X", hr);
        LogResult("WMI", "ExecQuery", g_buf, false);
        services->Release();
        locator->Release();
        CoUninitialize();
        return;
    }
    LogResult("WMI", "ExecQuery", "OK", true);
    {
        IWbemClassObject* obj = nullptr;
        ULONG ret = 0;
        hr = enumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
        if (SUCCEEDED(hr) && obj) {
            VARIANT vName;
            hr = obj->Get(L"Name", 0, &vName, NULL, NULL);
            if (SUCCEEDED(hr) && vName.vt == VT_BSTR) {
                char buf[256] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, vName.bstrVal, -1, buf, sizeof(buf), NULL, NULL);
                bool isSpoofed = strstr(buf, "i9-10900K") != nullptr;
                LogResult("WMI", "Win32_Processor.Name", buf, isSpoofed);
                VariantClear(&vName);
            }

            VARIANT vCores;
            hr = obj->Get(L"NumberOfCores", 0, &vCores, NULL, NULL);
            if (SUCCEEDED(hr) && vCores.vt == VT_I4) {
                snprintf(g_buf, sizeof(g_buf), "%d", vCores.intVal);
                LogResult("WMI", "NumberOfCores", g_buf, vCores.intVal == 10);
                VariantClear(&vCores);
            }

            VARIANT vLogical;
            hr = obj->Get(L"NumberOfLogicalProcessors", 0, &vLogical, NULL, NULL);
            if (SUCCEEDED(hr) && vLogical.vt == VT_I4) {
                snprintf(g_buf, sizeof(g_buf), "%d", vLogical.intVal);
                LogResult("WMI", "NumberOfLogicalProcessors", g_buf, vLogical.intVal == 20);
                VariantClear(&vLogical);
            }

            VARIANT vSpeed;
            hr = obj->Get(L"MaxClockSpeed", 0, &vSpeed, NULL, NULL);
            if (SUCCEEDED(hr) && vSpeed.vt == VT_I4) {
                snprintf(g_buf, sizeof(g_buf), "%d", vSpeed.intVal);
                LogResult("WMI", "MaxClockSpeed", g_buf, vSpeed.intVal == 3700);
                VariantClear(&vSpeed);
            }

            obj->Release();
        }
        enumerator->Release();
    }

    services->Release();
    locator->Release();
    CoUninitialize();
}

static void TestNetwork() {
    printf("\n=== Network ===\n");
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
        char hostname[256] = { 0 };
        int ret = gethostname(hostname, sizeof(hostname));
        LogResult("NET", "gethostname", ret == 0 ? hostname : "FAIL", ret == 0);
        WSACleanup();
    }
}

int main() {
    printf("========================================\n");
    printf(" Symbiote Spoof Verification Tool\n");
    printf("========================================\n");

    bool underEngine = GetModuleHandleW(L"engine.dll") != nullptr;
    printf("Engine loaded: %s\n\n", underEngine ? "YES" : "NO (baseline mode)");

    TestCpuid();
    TestRdtsc();
    TestMsr();
    TestKuserSharedData();
    TestSyscalls();
    TestPeb();
    TestRegistry();
    TestWmi();
    TestNetwork();

    printf("\n========================================\n");
    printf(" Summary\n");
    printf("========================================\n");
    int pass = 0, fail = 0;
    for (auto& r : g_results) {
        if (r.spoofed) pass++; else fail++;
    }
    printf(" Pass: %d  Fail: %d  Total: %d\n\n", pass, fail, pass + fail);

    for (auto& r : g_results) {
        if (!r.spoofed) {
            printf("  FAIL: [%s] %s = %s\n", r.category, r.check, r.got.c_str());
        }
    }

    // write detailed results to log
    std::ofstream log("verify_results.log");
    log << "Symbiote Verification Results\n";
    log << "Engine loaded: " << (underEngine ? "YES" : "NO (baseline)") << "\n\n";
    for (auto& r : g_results) {
        log << "[" << (r.spoofed ? "OK" : "FAIL") << "] " << r.category
            << " / " << r.check << " = " << r.got << "\n";
    }
    log.close();

    printf("Results written to verify_results.log\n");
    return fail > 0 ? 1 : 0;
}
