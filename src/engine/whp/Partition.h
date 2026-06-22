#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"
#include <vector>

class Partition {
public:
    explicit Partition(Logger* logger);
    ~Partition();

    bool Create();
    bool SetupCpuCount(uint32_t count);
    bool SetupMemory(uint64_t sizeMB);
    bool Init();
    void Destroy();

    WHV_PARTITION_HANDLE GetHandle() const { return m_handle; }

    bool MapGpaRange(void* hostVa, WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes, WHV_MAP_GPA_RANGE_FLAGS flags);
    bool UnmapGpaRange(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes);

    void* AllocateGuestMemory(uint64_t sizeInBytes);
    void FreeGuestMemory(void* ptr);

private:
    Logger* m_logger;
    WHV_PARTITION_HANDLE m_handle;
    bool m_initialized;

    struct GuestMemBlock {
        void* hostVa;
        uint64_t size;
    };
    std::vector<GuestMemBlock> m_guestMemory;
};
