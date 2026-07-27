#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"
#include <vector>

class CpuidHandler;
class GuestPageTable;

class Partition {
public:
    explicit Partition(Logger* logger);
    ~Partition();

    bool Create();
    bool SetupCpuCount(uint32_t count);
    bool SetupMemory(uint64_t sizeMB);
    bool SetupMsrBitmap();
    bool SetupCpuidResultList(CpuidHandler* cpuidHandler);
    bool SetupAntiDetectionCpuidResultList(CpuidHandler* cpuidHandler);
    bool SetupExceptionBitmap();
    bool SetupSelectiveExits();
    bool Init();
    void Destroy();

    WHV_PARTITION_HANDLE GetHandle() const { return m_handle; }

    // Single-page EPT operations (kept for compatibility)
    bool MapGpaRange(void* hostVa, WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes, WHV_MAP_GPA_RANGE_FLAGS flags);
    bool UnmapGpaRange(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes);

    // Coalesced EPT operations — merge contiguous GPA ranges into single WHvMap/UnmapGpaRange calls
    // to avoid ~second-long stalls from page-by-page mapping.
    bool MapGpaRangeDeferred(void* hostVa, WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes, WHV_MAP_GPA_RANGE_FLAGS flags);
    bool UnmapGpaRangeDeferred(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes);
    bool FlushDeferredMaps();
    bool FlushDeferredUnmaps();

    bool MapProcessMemory(HANDLE hProcess);
    GuestPageTable* GetPageTable() const { return m_guestPageTable; }

    void* AllocateGuestMemory(uint64_t sizeInBytes);
    void FreeGuestMemory(void* ptr);

    // Pre-mapped working set — allocate + map critical GPA ranges up front
    // to eliminate runtime EPT violation exits during game startup and gameplay.
    struct WorkingSetRegion {
        const char* name;           // descriptive label for logging
        uint64_t    sizeMB;         // size in MB (aligned to 2MB for large pages)
        uint64_t    baseGpa;        // starting GPA (in MB units, shifted left by 20)
        WHV_MAP_GPA_RANGE_FLAGS flags;
    };
    bool SetupWorkingSet(const WorkingSetRegion* regions, int regionCount);

public:
    // On-demand mapping — track GPA ranges but defer mapping until page fault
    bool MapOnDemand(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes);
    bool IsOnDemandRegion(WHV_GUEST_PHYSICAL_ADDRESS guestPa) const;
    bool MapOnDemandNow(WHV_GUEST_PHYSICAL_ADDRESS guestPa);

    // QEMU WHPX backend techniques — advanced WHP API wrappers
    bool MapGpaRange2(void* hostVa, WHV_GUEST_PHYSICAL_ADDRESS guestPa,
                      uint64_t sizeInBytes, WHV_MAP_GPA_RANGE_FLAGS flags,
                      uint32_t numaNode = 0);
    bool ReadGpaRange(WHV_GUEST_PHYSICAL_ADDRESS guestPa, void* buffer, uint32_t sizeInBytes);
    bool TranslateGva(uint32_t vcpuIndex, WHV_GUEST_VIRTUAL_ADDRESS gva,
                      WHV_TRANSLATE_GVA_FLAGS flags,
                      WHV_GUEST_PHYSICAL_ADDRESS* gpa, uint32_t* gpaAccessFlags = nullptr);
    HANDLE CreateNotificationPort(uint32_t vcpuIndex, WHV_NOTIFICATION_PORT_TYPE type);

    // Memory region tracking for snapshot/restore
    struct TrackedMemoryRegion {
        WHV_GUEST_PHYSICAL_ADDRESS gpa;
        uint64_t size;
        uint32_t flags;
    };
    const std::vector<TrackedMemoryRegion>& GetTrackedMemoryRegions() const { return m_trackedRegions; }
    uint32_t GetVcpuCount() const { return m_vcpuCount; }

private:
    Logger* m_logger;
    WHV_PARTITION_HANDLE m_handle;
    bool m_initialized;
    uint32_t m_vcpuCount;

    struct GuestMemBlock {
        void* hostVa;
        uint64_t size;
    };
    std::vector<GuestMemBlock> m_guestMemory;
    GuestPageTable* m_guestPageTable;
    std::vector<TrackedMemoryRegion> m_trackedRegions;
    std::vector<std::pair<WHV_GUEST_PHYSICAL_ADDRESS, uint64_t>> m_onDemandRegions;

    struct DeferredMap {
        WHV_MAP_GPA_RANGE_FLAGS flags;
        WHV_GUEST_PHYSICAL_ADDRESS guestPa;
        uint64_t size;
        void* hostVa;
    };
    std::vector<DeferredMap> m_deferredMaps;

    struct DeferredUnmap {
        WHV_GUEST_PHYSICAL_ADDRESS guestPa;
        uint64_t size;
    };
    std::vector<DeferredUnmap> m_deferredUnmaps;
};
