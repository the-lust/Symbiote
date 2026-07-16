#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include "Logger.h"

struct ClonedMemoryRegion {
    uint64_t baseAddress;
    uint64_t regionSize;
    uint32_t allocationProtect;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
    std::vector<uint8_t> content;
};

class ProcessCloner {
public:
    explicit ProcessCloner(Logger* logger);
    ~ProcessCloner();

    bool SnapshotProcess(HANDLE hProcess);
    bool MapRegionsIntoGuest(void* partitionHandle);
    size_t GetRegionCount() const { return m_regions.size(); }
    uint64_t GetTotalMemorySize() const;
    bool HasRegion(uint64_t baseAddr) const;
    const ClonedMemoryRegion* FindRegion(uint64_t addr) const;
    bool CloneForBootstrap(HANDLE hProcess, uint64_t& outEntryPoint);

private:
    Logger* m_logger;
    std::vector<ClonedMemoryRegion> m_regions;
    uint64_t m_entryPoint;

    bool ShouldCloneRegion(uint32_t state, uint32_t type, uint64_t baseAddr);
    static const uint64_t MAX_CLONE_SIZE = 512ULL * 1024 * 1024;
};
