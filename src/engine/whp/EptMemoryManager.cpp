#include "EptMemoryManager.h"
#include "Partition.h"
#include <algorithm>

EptMemoryManager::EptMemoryManager(Logger* logger, Partition* partition)
    : m_logger(logger)
    , m_partition(partition)
    , m_maxPages(8192)
    , m_activePages(0)
    , m_evictionCount(0)
    , m_pageSize(0x1000)
    , m_initialized(false)
{
}

EptMemoryManager::~EptMemoryManager()
{
    Clear();
}

bool EptMemoryManager::Initialize(uint32_t maxPages)
{
    m_maxPages = maxPages;
    m_slots.resize(maxPages);
    for (auto& slot : m_slots) {
        slot.active = false;
        slot.gpa = 0;
        slot.hostVa = 0;
        slot.lastAccessTick = 0;
    }

    m_backingMemory.resize(maxPages * (size_t)m_pageSize);
    m_logger->Trace(LOG_INFO, "EptMemoryManager: %u slots (%llu MB backing)",
        maxPages, (uint64_t)maxPages * m_pageSize / (1024 * 1024));
    m_initialized = true;
    return true;
}

uint32_t EptMemoryManager::AllocateSlot()
{
    for (uint32_t i = 0; i < m_maxPages; i++) {
        if (!m_slots[i].active) return i;
    }
    return EvictSlot();
}

uint32_t EptMemoryManager::EvictSlot()
{
    uint32_t oldestSlot = 0;
    uint64_t oldestTick = UINT64_MAX;

    for (uint32_t i = 0; i < m_maxPages; i++) {
        if (m_slots[i].active && m_slots[i].lastAccessTick < oldestTick) {
            oldestTick = m_slots[i].lastAccessTick;
            oldestSlot = i;
        }
    }

    UnmapSlot(oldestSlot);
    m_evictionCount++;
    return oldestSlot;
}

bool EptMemoryManager::MapSlot(uint32_t slotIndex, uint64_t gpa, uint64_t hostVa, uint64_t size)
{
    if (slotIndex >= m_maxPages) return false;

    auto& slot = m_slots[slotIndex];
    slot.gpa = gpa;
    slot.hostVa = (uint64_t)m_backingMemory.data() + (uint64_t)slotIndex * m_pageSize;
    slot.originalHostVa = hostVa;
    slot.mappedSize = size;
    slot.active = true;
    slot.lastAccessTick = GetTickCount64();

    if (hostVa && size > 0) {
        memcpy((void*)slot.hostVa, (const void*)hostVa, min(size, m_pageSize));
    }

    m_gpaToSlot[gpa] = slotIndex;
    m_activePages++;
    return true;
}

void EptMemoryManager::UnmapSlot(uint32_t slotIndex)
{
    if (slotIndex >= m_maxPages || !m_slots[slotIndex].active) return;

    auto& slot = m_slots[slotIndex];
    if (slot.gpa != 0 && m_partition) {
        WHvUnmapGpaRange(m_partition->GetHandle(), slot.gpa, m_pageSize);
    }

    m_gpaToSlot.erase(slot.gpa);
    slot.active = false;
    slot.gpa = 0;
    slot.hostVa = 0;
    if (m_activePages > 0) m_activePages--;
}

bool EptMemoryManager::MapOnDemand(uint64_t gpa, uint64_t size)
{
    if (!m_initialized) return false;

    uint32_t needed = (uint32_t)((size + m_pageSize - 1) / m_pageSize);
    for (uint32_t i = 0; i < needed; i++) {
        uint64_t pageGpa = gpa + i * m_pageSize;
        if (IsMapped(pageGpa)) continue;

        uint32_t slot = AllocateSlot();
        MapSlot(slot, pageGpa, pageGpa, m_pageSize);

        if (m_partition) {
            WHvMapGpaRange(m_partition->GetHandle(),
                (void*)m_slots[slot].hostVa, pageGpa, m_pageSize,
                WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
        }
    }
    return true;
}

bool EptMemoryManager::UnmapRegion(uint64_t gpa)
{
    auto it = m_gpaToSlot.find(gpa);
    if (it == m_gpaToSlot.end()) return false;
    UnmapSlot(it->second);
    return true;
}

bool EptMemoryManager::IsMapped(uint64_t gpa) const
{
    return m_gpaToSlot.find(gpa) != m_gpaToSlot.end();
}

bool EptMemoryManager::HandlePageFault(uint64_t faultGpa, uint64_t& outGpa, void*& outHostVa)
{
    if (!m_initialized) return false;

    if (IsMapped(faultGpa)) {
        outGpa = faultGpa;
        return true;
    }

    uint32_t slot = AllocateSlot();
    if (!MapSlot(slot, faultGpa, faultGpa, m_pageSize))
        return false;

    if (m_partition) {
        WHvMapGpaRange(m_partition->GetHandle(),
            (void*)m_slots[slot].hostVa, faultGpa, m_pageSize,
            WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    }

    outGpa = faultGpa;
    outHostVa = (void*)m_slots[slot].hostVa;
    return true;
}

void EptMemoryManager::Clear()
{
    for (uint32_t i = 0; i < m_maxPages; i++) {
        if (m_slots[i].active) UnmapSlot(i);
    }
    m_gpaToSlot.clear();
    m_activePages = 0;
    m_backingMemory.clear();
    m_slots.clear();
}
