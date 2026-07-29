#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

// Known vulnerable driver entry — each has a known signed .sys that
// exposes physical memory or kernel RW via IOCTL.
// The .sys file must be placed in the configured drivers directory.
struct VulnerableDriverEntry {
    const wchar_t* name;            // short name, e.g. L"rtcore64"
    const wchar_t* className;       // device symbolic link class, e.g. L"RTCore64"
    const wchar_t* serviceName;     // SCM service name, e.g. L"RTCore64"
    const wchar_t* expectedFile;    // .sys filename, e.g. L"RTCore64.sys"
    uint32_t expectedSize;          // expected file size (0 = skip size check)
    uint32_t ioctlReadPhys;         // IOCTL code for physical memory read
    uint32_t ioctlWritePhys;        // IOCTL code for physical memory write
    uint64_t capabilities;          // bitmask of BYOVD_CAP_* flags
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
    const VulnerableDriverEntry* entry;  // pointer to static entry (nullptr for admin fallback)
    wchar_t driverPath[MAX_PATH];        // on-disk path to the .sys file
    HANDLE deviceHandle;                 // opened \\.\SymbLink handle
    uint64_t capabilities;               // validated at runtime via probe IOCTL
    bool isElevated;                     // true if using admin PhysicalMemory fallback
    bool driverWasInstalled;             // true if this session installed the service
};

class ByovdDetect {
public:
    ByovdDetect();
    ~ByovdDetect();

    // Set directory where bundled driver .sys files are located.
    // Defaults to "drivers/" relative to the executable.
    void SetDriversDir(const wchar_t* dir);

    // Scan all known vulnerable drivers, return first working one.
    // For each: tries existing running → existing stopped → bundled install → next.
    // Falls back to admin \\.\PhysicalMemory if nothing works.
    DetectedDriver DetectAndOpen();

    // Try all known drivers — returns list of what's available.
    std::vector<DetectedDriver> EnumerateAll();

    // Stop and remove any driver this session installed.
    void RemoveInstalled();

    // Close all driver handles and clean up.
    void CloseAll();

    // Get currently active driver.
    const DetectedDriver* ActiveDriver() const { return m_active ? &m_active.value() : nullptr; }

private:
    // Phase 1: try opening an already-running driver service.
    bool TryOpenRunning(const VulnerableDriverEntry& entry, DetectedDriver& out);

    // Phase 2: try starting a stopped existing service.
    bool TryStartExisting(const VulnerableDriverEntry& entry, DetectedDriver& out);

    // Phase 3: install driver from bundled .sys file, start, and open.
    bool TryInstallBundle(const VulnerableDriverEntry& entry, DetectedDriver& out);

    // Core: after service is running, open the device and validate.
    bool OpenAndValidate(const VulnerableDriverEntry& entry, DetectedDriver& out);

    // Install the .sys as a kernel service and start it.
    bool InstallAndStart(const wchar_t* sysPath, const wchar_t* serviceName,
                         wchar_t* installedPath, size_t installedPathLen);

    // Validate driver capabilities by sending probe IOCTLs.
    uint64_t ValidateCapabilities(HANDLE hDevice, const VulnerableDriverEntry* entry);

    // Resolve bundled .sys path for a given entry.
    bool ResolveBundlePath(const VulnerableDriverEntry& entry, wchar_t* out, size_t outLen);

    // Try admin \\.\PhysicalMemory fallback.
    bool TryAdminPhysicalMemory(DetectedDriver& out);

    std::wstring m_driversDir;
    std::vector<DetectedDriver> m_detected;
    std::optional<DetectedDriver> m_active;

    static const VulnerableDriverEntry kKnownDrivers[8];
};