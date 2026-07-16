#pragma once
#include <windows.h>
#include <cstdint>
#include "Logger.h"

// WHP IOCTL codes (reverse engineered from WinHvPlatform.dll)
#define IOCTL_WHV_GET_PARTITION_PROPERTY  0x84000004
#define IOCTL_WHV_SET_PARTITION_PROPERTY  0x84000008
#define IOCTL_WHV_CREATE_VIRTUAL_PROCESSOR 0x84000010
#define IOCTL_WHV_RUN_VIRTUAL_PROCESSOR   0x84000014
#define IOCTL_WHV_MAP_GPA_RANGE           0x8400001C
#define IOCTL_WHV_UNMAP_GPA_RANGE         0x84000020
#define IOCTL_WHV_GET_VP_REGISTERS        0x84000028
#define IOCTL_WHV_SET_VP_REGISTERS        0x8400002C
#define IOCTL_WHV_SET_PARTITION_PROPERTY_VP_COUNT 0x84000038

// WHP partition property codes (for interception)
#define WHP_PARTITION_PROPERTY_CODE_PROCESSOR_COUNT    0x00010001
#define WHP_PARTITION_PROPERTY_CODE_CPUID_RESULT_LIST  0x00010005
#define WHP_PARTITION_PROPERTY_CODE_MSR_EXIT_BITMAP    0x0001000B
#define WHP_PARTITION_PROPERTY_CODE_EXCEPTION_EXIT_BITMAP 0x0001000D
#define WHP_PARTITION_PROPERTY_CODE_X64_IO_PORT_EXIT_BITMAP 0x0001000F

class DeviceIoEmu {
public:
    explicit DeviceIoEmu(Logger* logger);
    ~DeviceIoEmu();

    bool Initialize();
    void Shutdown();

    // NtDeviceIoControlFile hook handler
    static bool HandleDeviceIoControl(
        void* fileHandle,
        void* event,
        void* apcRoutine,
        void* apcContext,
        void* ioStatusBlock,
        uint32_t ioControlCode,
        void* inputBuffer,
        uint32_t inputBufferLength,
        void* outputBuffer,
        uint32_t outputBufferLength,
        uint64_t* result);

    // Register/unregister WHP file handle for IOCTL interception
    void RegisterWhpHandle(void* handle);
    void UnregisterWhpHandle(void* handle);
    bool IsWhpHandle(void* handle) const;

private:
    Logger* m_logger;
    void* m_whpHandle;
    bool m_initialized;

    // Inline hook for NtDeviceIoControlFile
    void* m_originalFunc;
    uint8_t m_originalBytes[12];
    bool m_hookInstalled;

    bool InstallHook();
    bool RemoveHook();
};
