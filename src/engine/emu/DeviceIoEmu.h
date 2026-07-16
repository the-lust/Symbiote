#pragma once
#include <windows.h>
#include <cstdint>
#include <unordered_map>
#include "Logger.h"

// All known WHP IOCTL codes
#define IOCTL_WHV_GET_PARTITION_PROPERTY          0x84000004
#define IOCTL_WHV_SET_PARTITION_PROPERTY          0x84000008
#define IOCTL_WHV_CREATE_VIRTUAL_PROCESSOR        0x84000010
#define IOCTL_WHV_RUN_VIRTUAL_PROCESSOR           0x84000014
#define IOCTL_WHV_TERMINATE_VIRTUAL_PROCESSOR     0x84000018
#define IOCTL_WHV_MAP_GPA_RANGE                   0x8400001C
#define IOCTL_WHV_UNMAP_GPA_RANGE                 0x84000020
#define IOCTL_WHV_GET_VP_REGISTERS                0x84000028
#define IOCTL_WHV_SET_VP_REGISTERS                0x8400002C
#define IOCTL_WHV_SET_PARTITION_PROPERTY_VP_COUNT 0x84000038
#define IOCTL_WHV_QUERY_PARTITION_PROPERTIES      0x8400003C
#define IOCTL_WHV_GET_PARTITION_COUNT             0x84000040
#define IOCTL_WHV_GET_PARTITION_ID                0x84000044

// All WHP partition property codes that Denuvo may query
#define WHP_PROP_PROCESSOR_COUNT        0x00010001
#define WHP_PROP_CPUID_RESULT_LIST      0x00010005
#define WHP_PROP_MSR_EXIT_BITMAP        0x0001000B
#define WHP_PROP_EXCEPTION_EXIT_BITMAP  0x0001000D
#define WHP_PROP_IO_PORT_EXIT_BITMAP    0x0001000F
#define WHP_PROP_EXTENDED_VMEXITS       0x00010011
#define WHP_PROP_XSAVE_ENABLED          0x00010013
#define WHP_PROP_SYSTEM_PROFILE         0x00010015
#define WHP_PROP_VP_COUNT               0x00010017
#define WHP_PROP_LOCAL_APIC_MODE        0x00010019
#define WHP_PROP_X2APIC_ENABLED         0x0001001B
#define WHP_PROP_VIRTUALIZATION_ENABLED 0x0001001D
#define WHP_PROP_TSC_FREQUENCY          0x0001001F
#define WHP_PROP_APIC_FREQUENCY         0x00010021
#define WHP_PROP_HYPERVISOR_PRESENT     0x00010023
#define WHP_PROP_GUEST_CRASH_MSRS       0x00010025
#define WHP_PROP_SYNTHETIC_PROCESSOR    0x00010027
#define WHP_PROP_VSM_CONFIGURATION      0x00010029
#define WHP_PROP_PARTITION_DEBUG        0x0001002B
#define WHP_PROP_TLB_FLUSH_TIMEOUT      0x0001002D

class DeviceIoEmu {
public:
    explicit DeviceIoEmu(Logger* logger);
    ~DeviceIoEmu();

    bool Initialize();
    void Shutdown();

    // NtDeviceIoControlFile hook handler
    static bool HandleDeviceIoControl(
        void* fileHandle, void* event, void* apcRoutine, void* apcContext,
        void* ioStatusBlock, uint32_t ioControlCode,
        void* inputBuffer, uint32_t inputBufferLength,
        void* outputBuffer, uint32_t outputBufferLength,
        uint64_t* result);

    void RegisterWhpHandle(void* handle);
    void UnregisterWhpHandle(void* handle);
    bool IsWhpHandle(void* handle) const;

    // Property spoofing configuration
    void SetSpoofedProcessorCount(uint32_t count) { m_spoofedProcCount = count; }
    void SetSpoofedTscFrequency(uint64_t freq) { m_spoofedTscFreq = freq; }

    // Hook management (needed by the C-linkage trampoline)
    bool HandleGetPartitionProperty(void* inputBuffer, uint32_t inputLength,
                                     void* outputBuffer, uint32_t outputLength,
                                     uint64_t* result);
    bool InstallHook();
    bool RemoveHook();

private:
    Logger* m_logger;
    void* m_whpHandle;
    bool m_initialized;

    void* m_originalFunc;
    uint8_t m_originalBytes[12];
    bool m_hookInstalled;

    // Spoofed property values
    uint32_t m_spoofedProcCount;
    uint64_t m_spoofedTscFreq;

    // IOCTL statistics
    uint64_t m_totalIoctlCalls;
    uint64_t m_spoofedResponses;
    std::unordered_map<uint32_t, uint64_t> m_ioctlCounters;
};
