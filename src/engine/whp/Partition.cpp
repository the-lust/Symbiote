#include "Partition.h"
#include <winerror.h>

Partition::Partition(Logger* logger)
    : m_logger(logger), m_handle(nullptr), m_initialized(false)
{
}

Partition::~Partition()
{
    Destroy();
}

bool Partition::Create()
{
    HRESULT hr = WHvCreatePartition(&m_handle);
    if (FAILED(hr) || !m_handle) {
        m_logger->Trace(LOG_ERROR, "WHvCreatePartition failed: 0x%08X", hr);
        return false;
    }
    m_logger->Trace(LOG_WHP, "Partition created: handle=0x%p", m_handle);
    return true;
}

bool Partition::SetupCpuCount(uint32_t count)
{
    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeProcessorCount,
        &count, sizeof(count));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(ProcessorCount) failed: 0x%08X, count=%u", hr, count);
        return false;
    }
    m_logger->Trace(LOG_WHP, "CPU count set to %u", count);
    return true;
}

bool Partition::SetupMemory(uint64_t sizeMB)
{
    m_logger->Trace(LOG_WHP, "Memory configured: %llu MB (partition-level property not required)", sizeMB);
    return true;
}

bool Partition::Init()
{
    if (!m_handle) return false;

    HRESULT hr = WHvSetupPartition(m_handle);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetupPartition failed: 0x%08X", hr);
        return false;
    }

    m_initialized = true;
    m_logger->Trace(LOG_WHP, "Partition initialized");
    return true;
}

void Partition::Destroy()
{
    for (auto& block : m_guestMemory) {
        if (block.hostVa) {
            VirtualFree(block.hostVa, 0, MEM_RELEASE);
        }
    }
    m_guestMemory.clear();

    if (m_handle) {
        if (m_initialized) {
            WHvDeletePartition(m_handle);
        }
        m_handle = nullptr;
        m_initialized = false;
        m_logger->Trace(LOG_WHP, "Partition destroyed");
    }
}

bool Partition::MapGpaRange(void* hostVa, WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes, WHV_MAP_GPA_RANGE_FLAGS flags)
{
    if (!m_handle || !m_initialized) {
        m_logger->Trace(LOG_ERROR, "MapGpaRange: partition not ready");
        return false;
    }

    HRESULT hr = WHvMapGpaRange(m_handle, hostVa, guestPa, sizeInBytes, flags);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvMapGpaRange(guestPa=0x%llX, size=%llu) failed: 0x%08X", guestPa, sizeInBytes, hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "GPA range mapped: hostVa=%p guestPa=0x%llX size=%llu flags=0x%X", hostVa, guestPa, sizeInBytes, (uint32_t)flags);
    return true;
}

bool Partition::UnmapGpaRange(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes)
{
    if (!m_handle || !m_initialized) return false;

    HRESULT hr = WHvUnmapGpaRange(m_handle, guestPa, sizeInBytes);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvUnmapGpaRange(guestPa=0x%llX) failed: 0x%08X", guestPa, hr);
        return false;
    }
    return true;
}

void* Partition::AllocateGuestMemory(uint64_t sizeInBytes)
{
    void* ptr = VirtualAlloc(NULL, sizeInBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr) {
        m_guestMemory.push_back({ptr, sizeInBytes});
    }
    return ptr;
}

void Partition::FreeGuestMemory(void* ptr)
{
    for (size_t i = 0; i < m_guestMemory.size(); i++) {
        if (m_guestMemory[i].hostVa == ptr) {
            VirtualFree(ptr, 0, MEM_RELEASE);
            m_guestMemory.erase(m_guestMemory.begin() + i);
            return;
        }
    }
}
