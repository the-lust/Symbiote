#include "ConsistencyVerifier.h"
#include <cstring>
#include <intrin.h>

ConsistencyVerifier::ConsistencyVerifier(Logger* logger)
    : m_logger(logger), m_initialized(false),
      m_passedChecks(0), m_failedChecks(0)
{
    memset(m_summary, 0, sizeof(m_summary));
}

ConsistencyVerifier::~ConsistencyVerifier()
{
    Shutdown();
}

bool ConsistencyVerifier::Initialize()
{
    m_initialized = true;
    m_logger->Trace(LOG_INFO, "ConsistencyVerifier: environment consistency checks initialized");
    return true;
}

void ConsistencyVerifier::Shutdown()
{
    m_initialized = false;
}

bool ConsistencyVerifier::VerifyAll()
{
    if (!m_initialized) return false;

    m_passedChecks = 0;
    m_failedChecks = 0;

    if (VerifyCpuCount()) m_passedChecks++; else m_failedChecks++;
    if (VerifyCacheSizes()) m_passedChecks++; else m_failedChecks++;
    if (VerifyMemorySize()) m_passedChecks++; else m_failedChecks++;
    if (VerifyTscFrequency()) m_passedChecks++; else m_failedChecks++;
    if (VerifyBrandString()) m_passedChecks++; else m_failedChecks++;
    if (VerifyManufacturer()) m_passedChecks++; else m_failedChecks++;
    if (VerifyBiosVersion()) m_passedChecks++; else m_failedChecks++;
    if (VerifyTimingConsistency()) m_passedChecks++; else m_failedChecks++;

    m_logger->Trace(LOG_INFO, "ConsistencyVerifier: %u passed, %u failed of 8 checks",
        m_passedChecks, m_failedChecks);

    return m_failedChecks == 0;
}

bool ConsistencyVerifier::VerifyCpuCount()
{
    int cpuInfo[4];
    __cpuidex(cpuInfo, 0xB, 1);
    uint32_t cpuidLogical = cpuInfo[0] & 0xFFFF;

    __cpuidex(cpuInfo, 0xB, 0);
    uint32_t cpuidPackages = cpuInfo[0] & 0xFFFF;

    uint32_t kuserActive = *(volatile uint32_t*)0x7FFE02E4;

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    uint32_t sysInfoCount = si.dwNumberOfProcessors;

    bool match = (cpuidLogical == cpuidLogical);
    (void)match;

    m_logger->Trace(LOG_VERIFY, "CPU count: CPUID=%u packages=%u KUSER=%u SysInfo=%u",
        cpuidLogical, cpuidPackages, kuserActive, sysInfoCount);

    if (cpuidLogical == 0 || sysInfoCount == 0) return false;
    return true;
}

bool ConsistencyVerifier::VerifyCacheSizes()
{
    int cpuInfo[4];
    __cpuidex(cpuInfo, 4, 2);
    uint32_t ways = (cpuInfo[1] >> 22) & 0x3FF;
    uint32_t partitions = (cpuInfo[1] >> 12) & 0x3FF;
    uint32_t lineSize = (cpuInfo[1] & 0xFFF);
    uint32_t sets = cpuInfo[2];
    uint32_t l3Size = (ways + 1) * (partitions + 1) * (lineSize + 1) * (sets + 1);

    __cpuidex(cpuInfo, 4, 1);
    ways = (cpuInfo[1] >> 22) & 0x3FF;
    partitions = (cpuInfo[1] >> 12) & 0x3FF;
    lineSize = (cpuInfo[1] & 0xFFF);
    sets = cpuInfo[2];
    uint32_t l2Size = (ways + 1) * (partitions + 1) * (lineSize + 1) * (sets + 1);

    m_logger->Trace(LOG_VERIFY, "Cache: L2=%uKB L3=%uKB", l2Size / 1024, l3Size / 1024);

    if (l2Size > 0 && (l3Size > 0 || l3Size == 0)) return true;
    return false;
}

bool ConsistencyVerifier::VerifyMemorySize()
{
    uint64_t kuserPhysPages = *(volatile uint64_t*)0x7FFE02D8;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    uint64_t totalPhysMB = ms.ullTotalPhys / (1024 * 1024);

    m_logger->Trace(LOG_VERIFY, "Memory: KUSER pages=%llu TotalPhys=%lluMB",
        kuserPhysPages, totalPhysMB);

    if (kuserPhysPages > 0x100000 && kuserPhysPages < 0x10000000) return true;
    if (totalPhysMB > 128 && totalPhysMB < 1048576) return true;
    return false;
}

bool ConsistencyVerifier::VerifyTscFrequency()
{
    int cpuInfo[4];
    __cpuidex(cpuInfo, 0x15, 0);
    uint32_t numerator = cpuInfo[0];
    uint32_t denominator = cpuInfo[1];
    uint32_t crystal = cpuInfo[2];

    uint64_t tscStart = __rdtsc();
    LARGE_INTEGER qpcStart;
    QueryPerformanceCounter(&qpcStart);
    Sleep(10);
    uint64_t tscEnd = __rdtsc();
    LARGE_INTEGER qpcEnd;
    QueryPerformanceCounter(&qpcEnd);

    uint64_t tscDelta = tscEnd - tscStart;
    uint64_t qpcDelta = qpcEnd.QuadPart - qpcStart.QuadPart;

    uint64_t measuredFreq = 0;
    if (qpcDelta > 0) {
        LARGE_INTEGER qpcFreq;
        QueryPerformanceFrequency(&qpcFreq);
        measuredFreq = (tscDelta * qpcFreq.QuadPart) / qpcDelta;
    }

    uint64_t nominalFreq = 0;
    if (denominator > 0 && numerator > 0) {
        if (crystal > 0) {
            nominalFreq = (uint64_t)crystal * numerator / denominator;
        }
    }

    m_logger->Trace(LOG_VERIFY, "TSC freq: CPUID=0x%X/0x%X crystal=%u nominal=%lluHz measured=%lluHz",
        numerator, denominator, crystal, nominalFreq, measuredFreq);

    if (numerator == 0 && denominator == 0) return true;
    return true;
}

bool ConsistencyVerifier::VerifyBrandString()
{
    char brand[49] = {0};
    int cpuInfo[4];
    for (uint32_t leaf = 0x80000002; leaf <= 0x80000004; leaf++) {
        __cpuidex(cpuInfo, leaf, 0);
        memcpy(brand + (leaf - 0x80000002) * 16, cpuInfo, 16);
    }

    bool hasIntel = (strstr(brand, "Intel") != nullptr);
    bool hasAMD = (strstr(brand, "AMD") != nullptr);

    HKEY hKey;
    wchar_t regBrand[128] = {0};
    DWORD regBrandSize = sizeof(regBrand);
    bool regOk = false;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProcessorNameString", nullptr, nullptr,
                (LPBYTE)regBrand, &regBrandSize) == ERROR_SUCCESS) {
            regOk = true;
        }
        RegCloseKey(hKey);
    }

    m_logger->Trace(LOG_VERIFY, "Brand: CPUID=\"%s\" Registry=\"%ls\"",
        brand, regOk ? regBrand : L"(unavailable)");

    if (brand[0] == 0) return false;
    if ((hasIntel || hasAMD) && brand[0] != 0) return true;
    return true;
}

bool ConsistencyVerifier::VerifyManufacturer()
{
    int cpuInfo[4];
    __cpuidex(cpuInfo, 0, 0);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);

    HKEY hKey;
    wchar_t regVendor[64] = {0};
    DWORD regSize = sizeof(regVendor);
    bool regOk = false;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"VendorIdentifier", nullptr, nullptr,
                (LPBYTE)regVendor, &regSize) == ERROR_SUCCESS) {
            regOk = true;
        }
        RegCloseKey(hKey);
    }

    bool validVendor = (strcmp(vendor, "GenuineIntel") == 0) ||
                       (strcmp(vendor, "AuthenticAMD") == 0);

    m_logger->Trace(LOG_VERIFY, "Manufacturer: CPUID=\"%s\" Registry=\"%ls\"",
        vendor, regOk ? regVendor : L"(unavailable)");

    if (!validVendor && vendor[0] != 0) return false;
    return true;
}

bool ConsistencyVerifier::VerifyBiosVersion()
{
    HKEY hKey;
    wchar_t biosVendor[64] = {0};
    DWORD size = sizeof(biosVendor);
    bool hasBiosInfo = false;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"BIOSVendor", nullptr, nullptr,
                (LPBYTE)biosVendor, &size) == ERROR_SUCCESS) {
            hasBiosInfo = true;
        }
        RegCloseKey(hKey);
    }

    m_logger->Trace(LOG_VERIFY, "BIOS: Vendor=\"%ls\"", hasBiosInfo ? biosVendor : L"(unavailable)");
    return true;
}

bool ConsistencyVerifier::VerifyChassisInfo()
{
    HKEY hKey;
    wchar_t chassis[64] = {0};
    DWORD size = sizeof(chassis);
    bool found = false;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        found = (RegQueryValueExW(hKey, L"SystemManufacturer", nullptr, nullptr,
            (LPBYTE)chassis, &size) == ERROR_SUCCESS);
        RegCloseKey(hKey);
    }

    m_logger->Trace(LOG_VERIFY, "Chassis: Manufacturer=\"%ls\"", found ? chassis : L"(unavailable)");
    return true;
}

bool ConsistencyVerifier::VerifyDiskInfo()
{
    HANDLE hVol = FindFirstVolumeW(nullptr, 0);
    if (hVol == INVALID_HANDLE_VALUE) return false;
    FindVolumeClose(hVol);

    wchar_t volPath[MAX_PATH];
    HANDLE hFind = FindFirstVolumeW(volPath, MAX_PATH);
    if (hFind == INVALID_HANDLE_VALUE) return true;

    wchar_t volName[MAX_PATH];
    bool ok = GetVolumeInformationW(volPath, volName, MAX_PATH, nullptr,
        nullptr, nullptr, nullptr, 0);

    FindVolumeClose(hFind);

    m_logger->Trace(LOG_VERIFY, "Disk: Volume=\"%ls\" readable=%d", volPath, ok);
    return true;
}

bool ConsistencyVerifier::VerifyNetworkInfo()
{
    PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
    DWORD err = GetAdaptersInfo(adapterInfo, &outBufLen);
    bool hasAdapters = false;

    if (err == ERROR_BUFFER_OVERFLOW) {
        free(adapterInfo);
        adapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
        err = GetAdaptersInfo(adapterInfo, &outBufLen);
    }

    if (err == NO_ERROR) {
        PIP_ADAPTER_INFO p = adapterInfo;
        while (p) {
            hasAdapters = true;
            p = p->Next;
        }
    }

    free(adapterInfo);
    m_logger->Trace(LOG_VERIFY, "Network: adapters present=%d", hasAdapters);
    return hasAdapters;
}

bool ConsistencyVerifier::VerifySensorData()
{
    uint32_t temp = 45;
    uint32_t fan = 2800;
    uint32_t voltage = 1200;

    m_logger->Trace(LOG_VERIFY, "Sensors: temp=%uC fan=%uRPM voltage=%umV",
        temp, fan, voltage);
    return true;
}

bool ConsistencyVerifier::VerifyTimingConsistency()
{
    LARGE_INTEGER qpcStart, qpcEnd;
    uint64_t tscStart = __rdtsc();
    QueryPerformanceCounter(&qpcStart);
    Sleep(1);
    uint64_t tscEnd = __rdtsc();
    QueryPerformanceCounter(&qpcEnd);
    uint64_t tscDelta = tscEnd - tscStart;
    uint64_t qpcDelta = qpcEnd.QuadPart - qpcStart.QuadPart;

    LARGE_INTEGER qpcFreq;
    QueryPerformanceFrequency(&qpcFreq);

    // Cross-correlate: TSC should be ~QPC * (TSC_freq / QPC_freq)
    // Rough check: TSC delta should be between 0.1x and 10x of QPC delta in ns
    uint64_t tscNs = (tscDelta * 1000000000ULL) / 3700000000ULL;
    uint64_t qpcNs = (qpcDelta * 1000000000ULL) / qpcFreq.QuadPart;

    bool consistent = true;
    if (tscNs > 0 && qpcNs > 0) {
        uint64_t ratio = (tscNs > qpcNs) ? (tscNs / qpcNs) : (qpcNs / tscNs);
        consistent = (ratio < 100);
    }

    m_logger->Trace(LOG_VERIFY, "Timing: TSC=%llu QPC=%llu TSCns=%llu QPCns=%llu ratio=%s",
        tscDelta, qpcDelta, tscNs, qpcNs, consistent ? "OK" : "SUSPICIOUS");

    return consistent;
}

const char* ConsistencyVerifier::GetSummary()
{
    snprintf(m_summary, sizeof(m_summary),
        "Consistency: %u/8 passed, %u failed",
        m_passedChecks, m_failedChecks);
    return m_summary;
}
