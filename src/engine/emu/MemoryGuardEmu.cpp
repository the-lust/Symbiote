// Credits: PAGE_GUARD memory hiding technique adapted from MemoryGuard (https://github.com/SamuelTulach/MemoryGuard)
// Implements robust memory hiding via syscall interception rather than relying on OS page fault mechanism
#define WIN32_NO_STATUS
#include "MemoryGuardEmu.h"
#include "ConfigParser.h"
#include <algorithm>
#include <cstring>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>

MemoryGuardEmu* g_memoryGuardEmu = nullptr;

MemoryGuardEmu::MemoryGuardEmu(Logger* logger)
    : m_logger(logger)
    , m_enabled(false)
    , m_initialized(false)
    , m_selfProcessHandle(GetCurrentProcess())
{
}

MemoryGuardEmu::~MemoryGuardEmu()
{
    Shutdown();
    g_memoryGuardEmu = nullptr;
}

bool MemoryGuardEmu::Initialize()
{
    if (m_initialized) return true;
    if (!m_enabled) {
        m_initialized = true;
        return true;
    }

    m_guardedRegions.clear();
    g_memoryGuardEmu = this;
    m_initialized = true;
    m_logger->Trace(LOG_INFO, "MemoryGuardEmu: initialized, tracking PAGE_GUARD regions");
    return true;
}

void MemoryGuardEmu::Shutdown()
{
    if (!m_initialized) return;
    m_guardedRegions.clear();
    g_memoryGuardEmu = nullptr;
    m_initialized = false;
}

void MemoryGuardEmu::LoadFromConfig(ConfigParser* config)
{
    if (!config) return;
    m_enabled = config->GetBool("memory_guard", "enabled", true);
}

void MemoryGuardEmu::AddGuardedRegion(uint64_t base, uint64_t size, uint32_t protect)
{
    // Remove the raw PAGE_GUARD flag — internally we track that separately
    uint32_t trackingProtect = protect & ~PAGE_GUARD;
    if (trackingProtect == 0) trackingProtect = PAGE_READONLY;

    GuardedRegion reg;
    reg.baseAddress = base;
    reg.regionSize = size;
    reg.originalProtect = trackingProtect;
    m_guardedRegions.push_back(reg);

    m_logger->Trace(LOG_EMU, "MemoryGuardEmu: tracked guarded region 0x%llX size=0x%llX",
        base, size);
}

void MemoryGuardEmu::RemoveGuardedRegion(uint64_t base, uint64_t size)
{
    auto it = m_guardedRegions.begin();
    while (it != m_guardedRegions.end()) {
        if (it->baseAddress == base && it->regionSize == size) {
            it = m_guardedRegions.erase(it);
        } else {
            ++it;
        }
    }
}

bool MemoryGuardEmu::RangeOverlapsGuarded(uint64_t base, uint64_t size) const
{
    uint64_t rangeEnd = base + size;
    for (const auto& r : m_guardedRegions) {
        uint64_t regEnd = r.baseAddress + r.regionSize;
        // Check for overlap: ranges intersect if not (rangeEnd <= r.base || base >= regEnd)
        if (!(rangeEnd <= r.baseAddress || base >= regEnd)) {
            return true;
        }
    }
    return false;
}

bool MemoryGuardEmu::IsRegionGuarded(uint64_t base, uint64_t size) const
{
    return RangeOverlapsGuarded(base, size);
}

bool MemoryGuardEmu::HandleProtectVirtualMemory(uint64_t processHandle, uint64_t baseAddr,
                                                  uint64_t regionSize, uint32_t newProtect,
                                                  uint32_t* oldProtect, uint64_t* result)
{
    (void)oldProtect;
    (void)result;
    if (!m_enabled) return false;

    // Only track our own process
    if ((HANDLE)(uintptr_t)processHandle != m_selfProcessHandle &&
        processHandle != 0 && processHandle != (uint64_t)-1) {
        return false;
    }

    if (newProtect & PAGE_GUARD) {
        AddGuardedRegion(baseAddr, regionSize, newProtect);
    } else {
        // If removing guard, clear our tracking
        RemoveGuardedRegion(baseAddr, regionSize);
    }

    return false; // Fall through to real NtProtectVirtualMemory
}

bool MemoryGuardEmu::HandleReadVirtualMemory(uint64_t processHandle, uint64_t baseAddress,
                                               void* buffer, uint64_t numberOfBytesToRead,
                                               uint64_t* numberOfBytesRead, uint64_t* result)
{
    (void)processHandle;
    (void)buffer;
    if (!m_enabled) return false;

    // Check if reading from our own guarded regions
    if (RangeOverlapsGuarded(baseAddress, numberOfBytesToRead)) {
        if (result) *result = (uint64_t)STATUS_ACCESS_DENIED;
        if (numberOfBytesRead) *numberOfBytesRead = 0;
        m_logger->Trace(LOG_EMU, "MemoryGuardEmu: blocked NtReadVirtualMemory at 0x%llX size=0x%llX",
            baseAddress, numberOfBytesToRead);
        return true;
    }

    return false;
}

bool MemoryGuardEmu::HandleWriteVirtualMemory(uint64_t processHandle, uint64_t baseAddress,
                                                const void* buffer, uint64_t numberOfBytesToWrite,
                                                uint64_t* numberOfBytesWritten, uint64_t* result)
{
    (void)processHandle;
    (void)buffer;
    if (!m_enabled) return false;

    if (RangeOverlapsGuarded(baseAddress, numberOfBytesToWrite)) {
        if (result) *result = (uint64_t)STATUS_ACCESS_DENIED;
        if (numberOfBytesWritten) *numberOfBytesWritten = 0;
        m_logger->Trace(LOG_EMU, "MemoryGuardEmu: blocked NtWriteVirtualMemory at 0x%llX size=0x%llX",
            baseAddress, numberOfBytesToWrite);
        return true;
    }

    return false;
}

bool MemoryGuardEmu::HandleFlushInstructionCache(uint64_t processHandle, uint64_t baseAddress,
                                                   uint64_t regionSize, uint64_t* result)
{
    (void)processHandle;
    (void)baseAddress;
    (void)regionSize;
    (void)result;
    return false;
}
