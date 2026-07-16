#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include "Logger.h"

class Partition;

struct EptPageSlot {
    uint64_t gpa;
    uint64_t hostVa;
    uint64_t mappedSize;
    bool active;
    uint64_t lastAccessTick;
    uint64_t originalHostVa;
};

class EptMemoryManager {
public:
    EptMemoryManager(Logger* logger, Partition* partition);
    ~EptMemoryManager();

    bool Initialize(uint32_t maxPages = 8192);
    bool MapOnDemand(uint64_t gpa, uint64_t size);
    bool UnmapRegion(uint64_t gpa);
    bool IsMapped(uint64_t gpa) const;
    bool HandlePageFault(uint64_t faultGpa, uint64_t& outGpa, void*& outHostVa);
    uint32_t GetActivePageCount() const { return (uint32_t)m_activePages; }
    uint32_t GetMaxPages() const { return m_maxPages; }
    uint64_t GetEvictionCount() const { return m_evictionCount; }
    void Clear();

private:
    Logger* m_logger;
    Partition* m_partition;
    uint32_t m_maxPages;
    uint32_t m_activePages;
    uint64_t m_evictionCount;
    uint64_t m_pageSize;
    std::vector<EptPageSlot> m_slots;
    std::unordered_map<uint64_t, uint32_t> m_gpaToSlot;
    std::vector<uint8_t> m_backingMemory;
    bool m_initialized;

    uint32_t AllocateSlot();
    uint32_t EvictSlot();
    bool MapSlot(uint32_t slotIndex, uint64_t gpa, uint64_t hostVa, uint64_t size);
    void UnmapSlot(uint32_t slotIndex);
};
