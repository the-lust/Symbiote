#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

// Known vulnerable driver signatures: { name, expectedFileSize, knownTimestamp, sysClassName, uniqueSignatureBytes }
struct VulnerableDriverEntry {
    const wchar_t* name;
    const wchar_t* className;
    const wchar_t* serviceName;
    const wchar_t* expectedFile;
    uint32_t expectedSize;
    uint32_t knownTimestamp;
    const uint8_t* signatureBytes;
    size_t signatureLen;
    uint64_t capabilities;   // bitmask: physMem|kernelRW|ssdtHook|eptHook
};

// Capability flags for BYOVD
constexpr uint64_t BYOVD_CAP_PHYSICAL_MEM   = 0x0001;
constexpr uint64_t BYOVD_CAP_KERNEL_READ    = 0x0002;
constexpr uint64_t BYOVD_CAP_KERNEL_WRITE   = 0x0004;
constexpr uint64_t BYOVD_CAP_SSDT_HOOK      = 0x0008;
constexpr uint64_t BYOVD_CAP_EPT_HOOK       = 0x0010;
constexpr uint64_t BYOVD_CAP_ALLOC_POOL     = 0x0020;
constexpr uint64_t BYOVD_CAP_VIRTUAL_MEM    = 0x0040;

struct DetectedDriver {
    VulnerableDriverEntry entry;
    wchar_t driverPath[MAX_PATH];    // actual file path discovered
    HANDLE deviceHandle;             // opened \\.\SymbLink handle
    uint64_t capabilities;           // validated at runtime
    bool isElevated;                 // if using admin PhysicalMemory fallback
};

class ByovdDetect {
public:
    ByovdDetect();
    ~ByovdDetect();

    // Scan all known vulnerable drivers, return first working one
    // Fallback to admin PhysicalMemory if no BYOVD works
    DetectedDriver DetectAndOpen();

    // Try all known drivers - return list of what's available
    std::vector<DetectedDriver> EnumerateAll();

    // Close driver handles and clean up
    void CloseAll();

    // Get currently active driver
    const DetectedDriver* ActiveDriver() const { return m_active ? &m_active.value() : nullptr; }

private:
    // Check if a specific vulnerable driver is present and loadable
    bool TryDriver(const VulnerableDriverEntry& entry, DetectedDriver& out);

    // Try admin \\.\PhysicalMemory fallback
    bool TryAdminPhysicalMemory(DetectedDriver& out);

    // Validate driver capabilities by sending test IOCTLs
    uint64_t ValidateCapabilities(HANDLE hDevice);

    // Extract driver from embedded resources or bundled directory
    bool ExtractDriver(const VulnerableDriverEntry& entry, wchar_t* outPath, size_t pathLen);

    std::vector<DetectedDriver> m_detected;
    std::optional<DetectedDriver> m_active;

    static const VulnerableDriverEntry kKnownDrivers[8];
};