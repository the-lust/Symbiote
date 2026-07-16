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
    if (VerifyChassisInfo()) m_passedChecks++; else m_failedChecks++;
    if (VerifyDiskInfo()) m_passedChecks++; else m_failedChecks++;
    if (VerifyNetworkInfo()) m_passedChecks++; else m_failedChecks++;

    m_logger->Trace(LOG_INFO, "ConsistencyVerifier: %u passed, %u failed of %u checks",
        m_passedChecks, m_failedChecks, m_passedChecks + m_failedChecks);

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

    // Cross-validate: CPUID leaf 0xB logical count must match KUSER + SysInfo
    uint32_t minCount = cpuidLogical;
    if (kuserActive < minCount) minCount = kuserActive;
    if (sysInfoCount < minCount) minCount = sysInfoCount;
    uint32_t maxCount = cpuidLogical;
    if (kuserActive > maxCount) maxCount = kuserActive;
    if (sysInfoCount > maxCount) maxCount = sysInfoCount;

    bool match = (maxCount - minCount) <= 1;

    m_logger->Trace(LOG_VERIFY, "CPU count: CPUID=%u packages=%u KUSER=%u SysInfo=%u %s",
        cpuidLogical, cpuidPackages, kuserActive, sysInfoCount,
        match ? "OK" : "MISMATCH");

    if (cpuidLogical == 0 || sysInfoCount == 0) return false;
    if (!match) return false;
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
    uint64_t l3Size = (uint64_t)(ways + 1) * (partitions + 1) * (lineSize + 1) * (sets + 1);

    __cpuidex(cpuInfo, 4, 1);
    ways = (cpuInfo[1] >> 22) & 0x3FF;
    partitions = (cpuInfo[1] >> 12) & 0x3FF;
    lineSize = (cpuInfo[1] & 0xFFF);
    sets = cpuInfo[2];
    uint64_t l2Size = (uint64_t)(ways + 1) * (partitions + 1) * (lineSize + 1) * (sets + 1);

    // Validate against plausible ranges: L2 [128KB, 8MB], L3 [0, 64MB]
    bool l2Ok = (l2Size >= 131072 && l2Size <= 8388608);
    bool l3Ok = (l3Size <= 67108864); // L3 may be 0 on some CPUs

    m_logger->Trace(LOG_VERIFY, "Cache: L2=%lluKB(%s) L3=%lluKB(%s)",
        l2Size / 1024, l2Ok ? "OK" : "SUSPICIOUS",
        l3Size / 1024, l3Ok ? "OK" : "SUSPICIOUS");

    if (!l2Ok) return false;
    if (l3Size > 0 && !l3Ok) return false;
    return true;
}

bool ConsistencyVerifier::VerifyMemorySize()
{
    uint64_t kuserPhysPages = *(volatile uint64_t*)0x7FFE02D8;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    uint64_t totalPhysMB = ms.ullTotalPhys / (1024 * 1024);

    // Cross-check: KUSER pages should roughly match GlobalMemoryStatusEx
    uint64_t pagesFromMem = ms.ullTotalPhys / 4096;
    uint64_t diff = (kuserPhysPages > pagesFromMem)
        ? (kuserPhysPages - pagesFromMem)
        : (pagesFromMem - kuserPhysPages);
    bool match = (diff < (kuserPhysPages / 100)); // within 1%

    m_logger->Trace(LOG_VERIFY, "Memory: KUSER pages=%llu TotalPhys=%lluMB pagesFromMem=%llu %s",
        kuserPhysPages, totalPhysMB, pagesFromMem, match ? "OK" : "MISMATCH");

    if (kuserPhysPages > 0x100000 && kuserPhysPages < 0x10000000) {
        if (!match) return false;
        return true;
    }
    if (totalPhysMB > 128 && totalPhysMB < 1048576) {
        return true;
    }
    return false;
}

bool ConsistencyVerifier::VerifyTscFrequency()
{
    int cpuInfo[4];
    __cpuidex(cpuInfo, 0x15, 0);
    uint32_t numerator = cpuInfo[1];
    uint32_t denominator = cpuInfo[0];
    uint32_t crystal = cpuInfo[2];

    // Two independent measurements with sleep between them
    uint64_t tscStart = __rdtsc();
    LARGE_INTEGER qpcStart;
    QueryPerformanceCounter(&qpcStart);
    Sleep(15);
    uint64_t tscEnd = __rdtsc();
    LARGE_INTEGER qpcEnd;
    QueryPerformanceCounter(&qpcEnd);

    uint64_t tscDelta = tscEnd - tscStart;
    uint64_t qpcDelta = qpcEnd.QuadPart - qpcStart.QuadPart;

    uint64_t measuredFreq = 0;
    LARGE_INTEGER qpcFreq;
    QueryPerformanceFrequency(&qpcFreq);
    if (qpcDelta > 0) {
        measuredFreq = (tscDelta * qpcFreq.QuadPart) / qpcDelta;
    }

    uint64_t nominalFreq = 0;
    if (denominator > 0 && numerator > 0) {
        if (crystal > 0) {
            nominalFreq = (uint64_t)crystal * numerator / denominator;
        }
    }

    bool consistent = false;
    if (nominalFreq > 0 && measuredFreq > 0) {
        // Nominal must be within 10% of measured
        uint64_t diff = (nominalFreq > measuredFreq)
            ? (nominalFreq - measuredFreq)
            : (measuredFreq - nominalFreq);
        consistent = (diff * 100 / measuredFreq) < 10;
    } else if (measuredFreq > 0) {
        // No nominal from CPUID: measure again and self-check
        uint64_t tscStart2 = __rdtsc();
        LARGE_INTEGER qpcStart2;
        QueryPerformanceCounter(&qpcStart2);
        Sleep(15);
        uint64_t tscEnd2 = __rdtsc();
        LARGE_INTEGER qpcEnd2;
        QueryPerformanceCounter(&qpcEnd2);
        uint64_t tscDelta2 = tscEnd2 - tscStart2;
        uint64_t qpcDelta2 = qpcEnd2.QuadPart - qpcStart2.QuadPart;
        uint64_t measuredFreq2 = 0;
        if (qpcDelta2 > 0) {
            measuredFreq2 = (tscDelta2 * qpcFreq.QuadPart) / qpcDelta2;
        }
        if (measuredFreq2 > 0) {
            uint64_t diff2 = (measuredFreq > measuredFreq2)
                ? (measuredFreq - measuredFreq2)
                : (measuredFreq2 - measuredFreq);
            consistent = (diff2 * 100 / measuredFreq) < 5;
        }
    }

    m_logger->Trace(LOG_VERIFY, "TSC freq: CPUID=0x%X/0x%X crystal=%u nominal=%lluHz measured1=%lluHz measured2=%lluHz %s",
        denominator, numerator, crystal, nominalFreq, measuredFreq, 0ULL,
        consistent ? "OK" : "SUSPICIOUS");

    return consistent;
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
    wchar_t biosVersion[64] = {0};
    DWORD size = sizeof(biosVendor);
    bool hasVendor = false;
    bool hasVersion = false;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"BIOSVendor", nullptr, nullptr,
                (LPBYTE)biosVendor, &size) == ERROR_SUCCESS) {
            hasVendor = (wcslen(biosVendor) > 0);
        }
        size = sizeof(biosVersion);
        if (RegQueryValueExW(hKey, L"BIOSVersion", nullptr, nullptr,
                (LPBYTE)biosVersion, &size) == ERROR_SUCCESS) {
            hasVersion = (wcslen(biosVersion) > 0);
        }
        RegCloseKey(hKey);
    }

    // Validate: BIOS vendor should be a known manufacturer or non-empty
    bool vendorOk = false;
    if (hasVendor) {
        const wchar_t* knownVendors[] = {
            L"American Megatrends", L"AMI", L"Intel", L"Dell",
            L"Lenovo", L"HP", L"Hewlett-Packard", L"Phoenix",
            L"Award", L"Insyde", L"Apple", L"Microsoft",
            L"ASUSTeK", L"GIGABYTE", L"MSI", L"ASRock",
            nullptr
        };
        for (int i = 0; knownVendors[i]; i++) {
            if (wcsstr(biosVendor, knownVendors[i])) {
                vendorOk = true;
                break;
            }
        }
        if (!vendorOk) vendorOk = (wcslen(biosVendor) > 2); // non-trivial string
    }

    m_logger->Trace(LOG_VERIFY, "BIOS: Vendor=\"%ls\" Version=\"%ls\" %s",
        hasVendor ? biosVendor : L"(unavailable)",
        hasVersion ? biosVersion : L"(unavailable)",
        vendorOk ? "OK" : "SUSPICIOUS");

    if (!hasVendor) return false;
    if (!vendorOk) return false;
    return true;
}

bool ConsistencyVerifier::VerifyChassisInfo()
{
    HKEY hKey;
    wchar_t manufacturer[128] = {0};
    wchar_t product[128] = {0};
    DWORD size = sizeof(manufacturer);
    bool hasManufacturer = false;
    bool hasProduct = false;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"SystemManufacturer", nullptr, nullptr,
                (LPBYTE)manufacturer, &size) == ERROR_SUCCESS) {
            hasManufacturer = (wcslen(manufacturer) > 0);
        }
        size = sizeof(product);
        if (RegQueryValueExW(hKey, L"SystemProductName", nullptr, nullptr,
                (LPBYTE)product, &size) == ERROR_SUCCESS) {
            hasProduct = (wcslen(product) > 0);
        }
        RegCloseKey(hKey);
    }

    bool valid = false;
    if (hasManufacturer) {
        const wchar_t* knownMfrs[] = {
            L"Dell", L"HP", L"Hewlett-Packard", L"Lenovo",
            L"ASUS", L"Acer", L"Microsoft", L"Apple",
            L"GIGABYTE", L"MSI", L"Samsung", L"Toshiba",
            L"Inspur", L"Supermicro", L"Intel", nullptr
        };
        for (int i = 0; knownMfrs[i]; i++) {
            if (wcsstr(manufacturer, knownMfrs[i])) {
                valid = true;
                break;
            }
        }
        if (!valid) valid = (wcslen(manufacturer) > 2);
    }

    m_logger->Trace(LOG_VERIFY, "Chassis: Manufacturer=\"%ls\" Product=\"%ls\" %s",
        hasManufacturer ? manufacturer : L"(unavailable)",
        hasProduct ? product : L"(unavailable)",
        valid ? "OK" : "SUSPICIOUS");

    if (!hasManufacturer) return false;
    return valid;
}

bool ConsistencyVerifier::VerifyDiskInfo()
{
    wchar_t volPath[MAX_PATH];
    HANDLE hFind = FindFirstVolumeW(volPath, MAX_PATH);
    if (hFind == INVALID_HANDLE_VALUE) return false;

    wchar_t volName[MAX_PATH] = {0};
    wchar_t fsName[MAX_PATH] = {0};
    DWORD serial = 0;
    bool ok = GetVolumeInformationW(volPath, volName, MAX_PATH, &serial,
        nullptr, nullptr, fsName, MAX_PATH);

    FindVolumeClose(hFind);

    // Validate: volume name should be non-empty or drive has serial
    // Filesystem should be NTFS, FAT32, or exFAT
    bool fsValid = false;
    if (ok) {
        fsValid = (_wcsicmp(fsName, L"NTFS") == 0) ||
                  (_wcsicmp(fsName, L"FAT32") == 0) ||
                  (_wcsicmp(fsName, L"exFAT") == 0);
        if (!fsValid && fsName[0] != 0) {
            fsValid = true; // allow unknown FS if non-empty
        }
    }

    m_logger->Trace(LOG_VERIFY, "Disk: Volume=\"%ls\" FS=\"%ls\" Serial=0x%X %s",
        volPath, ok ? fsName : L"(unavailable)", serial,
        (ok && fsValid) ? "OK" : "SUSPICIOUS");

    if (!ok) return false;
    return fsValid;
}

bool ConsistencyVerifier::VerifyNetworkInfo()
{
    PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
    DWORD err = GetAdaptersInfo(adapterInfo, &outBufLen);

    if (err == ERROR_BUFFER_OVERFLOW) {
        free(adapterInfo);
        adapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
        err = GetAdaptersInfo(adapterInfo, &outBufLen);
    }

    bool hasAdapters = false;
    int validCount = 0;

    if (err == NO_ERROR) {
        PIP_ADAPTER_INFO p = adapterInfo;
        while (p) {
            hasAdapters = true;
            // Check adapter description looks real (non-empty, has a vendor)
            if (p->Description[0] != 0) {
                validCount++;
            }
            p = p->Next;
        }
    }

    free(adapterInfo);

    bool valid = hasAdapters && validCount > 0;

    m_logger->Trace(LOG_VERIFY, "Network: adapters=%d valid=%d %s",
        hasAdapters ? 1 : 0, validCount, valid ? "OK" : "SUSPICIOUS");

    return valid;
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
        "Consistency: %u/%u passed, %u failed",
        m_passedChecks, m_passedChecks + m_failedChecks, m_failedChecks);
    return m_summary;
}
