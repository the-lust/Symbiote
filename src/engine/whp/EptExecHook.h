#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include "Logger.h"

class Partition;

// Type of code interception hook
enum class ExecHookType {
    SINGLE_STEP = 0,     // Execute and single-step (existing)
    EPT_DISABLE_EXEC = 1, // Remove EXEC from EPT → VM exit on execute
    MEMORY_PROTECT = 2,   // Remove all access → trap read/write/execute
};

struct ExecHookEntry {
    uint64_t gpa;
    uint64_t size;
    void* hostVA;
    ExecHookType hookType;
    bool active;
    void (*callback)(uint64_t gpa, uint64_t rip);
    uint32_t hitCount;
};

class EptExecHook {
public:
    explicit EptExecHook(Logger* logger, Partition* partition);
    ~EptExecHook();

    bool Initialize();

    // EPT-based execute interception (no INT3 bytes in memory)
    bool RegisterEptExecHook(uint64_t gpa, uint64_t size, void* hostVA, void (*callback)(uint64_t, uint64_t));
    bool UnregisterEptExecHook(uint64_t gpa);

    // EPT-based memory protection (trap all access)
    bool ProtectPage(uint64_t gpa, uint64_t size);
    bool UnprotectPage(uint64_t gpa);

    // Handle memory access VM exit for EPT hooks
    bool HandleMemoryAccess(uint64_t gpa, uint64_t rip, WHV_MEMORY_ACCESS_TYPE accessType);

    // Check if a GPA has a hook
    bool HasHook(uint64_t gpa) const;

    // Snapshot serialization for save/restore
    void Serialize(std::vector<uint8_t>& buffer);
    void Deserialize(const uint8_t* data, uint32_t size);

    // Single-step completion handler (used by VcpuManager after EPT fault + step)
    bool HandleSingleStepComplete(HANDLE partitionHandle, uint32_t vcpuIndex);
    bool HandleExecFault(uint64_t gpa, uint64_t rip, HANDLE partitionHandle, uint32_t vcpuIndex);

    // Legacy single-step hook support (unchanged)
    bool RegisterPageHook(uint64_t gpa, void (*callback)(uint64_t, uint64_t));
    bool UnregisterPageHook(uint64_t gpa);

private:
    Logger* m_logger;
    Partition* m_partition;
    bool m_initialized;

    std::vector<ExecHookEntry> m_execHooks;
    std::unordered_map<uint64_t, size_t> m_gpaToExecHook;

    std::vector<ExecHookEntry> m_singleStepHooks;
    std::unordered_map<uint64_t, size_t> m_gpaToSingleStep;

    bool ApplyEptExecDisable(uint64_t gpa, uint64_t size, void* hostVA);
    bool RemoveEptExecDisable(uint64_t gpa, uint64_t size);
};
