// Credits: PAGE_GUARD memory hiding technique adapted from MemoryGuard (https://github.com/SamuelTulach/MemoryGuard)
// Intercepts NtProtectVirtualMemory to track PAGE_GUARD regions, filters NtReadVirtualMemory/NtWriteVirtualMemory
#pragma once
#include <cstdint>
#include <vector>
#include <windows.h>
#include "Logger.h"

class ConfigParser;

struct GuardedRegion {
    uint64_t baseAddress;
    uint64_t regionSize;
    uint32_t originalProtect;
};

class MemoryGuardEmu {
public:
    explicit MemoryGuardEmu(Logger* logger);
    ~MemoryGuardEmu();

    bool Initialize();
    void Shutdown();
    void LoadFromConfig(ConfigParser* config);

    bool IsEnabled() const { return m_enabled; }

    // NtProtectVirtualMemory hook — track PAGE_GUARD flags
    bool HandleProtectVirtualMemory(uint64_t processHandle, uint64_t baseAddr,
                                     uint64_t regionSize, uint32_t newProtect,
                                     uint32_t* oldProtect, uint64_t* result);

    // NtReadVirtualMemory — block if target region is guarded
    bool HandleReadVirtualMemory(uint64_t processHandle, uint64_t baseAddress,
                                 void* buffer, uint64_t numberOfBytesToRead,
                                 uint64_t* numberOfBytesRead, uint64_t* result);

    // NtWriteVirtualMemory — block if target region is guarded
    bool HandleWriteVirtualMemory(uint64_t processHandle, uint64_t baseAddress,
                                  const void* buffer, uint64_t numberOfBytesToWrite,
                                  uint64_t* numberOfBytesWritten, uint64_t* result);

    // NtFlushInstructionCache — forward for guarded pages
    bool HandleFlushInstructionCache(uint64_t processHandle, uint64_t baseAddress,
                                      uint64_t regionSize, uint64_t* result);

    // Check if a given address range is guarded
    bool IsRegionGuarded(uint64_t base, uint64_t size) const;

private:
    Logger* m_logger;
    bool m_enabled;
    bool m_initialized;
    HANDLE m_selfProcessHandle;

    // Tracked guarded regions
    std::vector<GuardedRegion> m_guardedRegions;

    void AddGuardedRegion(uint64_t base, uint64_t size, uint32_t protect);
    void RemoveGuardedRegion(uint64_t base, uint64_t size);
    bool RangeOverlapsGuarded(uint64_t base, uint64_t size) const;
};

extern MemoryGuardEmu* g_memoryGuardEmu;
