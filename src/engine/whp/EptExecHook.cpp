#include "EptExecHook.h"
#include "Partition.h"

EptExecHook::EptExecHook(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition), m_initialized(false)
{
}

EptExecHook::~EptExecHook()
{
    // Remove all hooks on shutdown
    for (auto& hook : m_execHooks) {
        if (hook.active && m_partition) {
            WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute;
            m_partition->MapGpaRange(hook.hostVA, hook.gpa, hook.size, flags);
        }
    }
    m_execHooks.clear();
    m_gpaToExecHook.clear();
    m_singleStepHooks.clear();
    m_gpaToSingleStep.clear();
}

bool EptExecHook::Initialize()
{
    m_initialized = true;
    m_logger->Trace(LOG_EPT, "EptExecHook initialized (EPT-based code interception)");
    return true;
}

bool EptExecHook::RegisterEptExecHook(uint64_t gpa, uint64_t size, void* hostVA, void (*callback)(uint64_t, uint64_t))
{
    if (!m_initialized) return false;

    // Check if already registered
    if (m_gpaToExecHook.find(gpa) != m_gpaToExecHook.end()) {
        return true; // Already hooked
    }

    if (!ApplyEptExecDisable(gpa, size, hostVA)) {
        m_logger->Trace(LOG_ERROR, "EptExecHook: Failed to disable EXEC for GPA=0x%llX", gpa);
        return false;
    }

    ExecHookEntry entry;
    entry.gpa = gpa;
    entry.size = size;
    entry.hostVA = hostVA;
    entry.hookType = ExecHookType::EPT_DISABLE_EXEC;
    entry.active = true;
    entry.callback = callback;
    entry.hitCount = 0;

    m_gpaToExecHook[gpa] = m_execHooks.size();
    m_execHooks.push_back(entry);

    m_logger->Trace(LOG_EPT, "EPT exec hook installed: GPA=0x%llX size=%llu (no INT3 in memory)", gpa, size);
    return true;
}

bool EptExecHook::UnregisterEptExecHook(uint64_t gpa)
{
    auto it = m_gpaToExecHook.find(gpa);
    if (it == m_gpaToExecHook.end()) return false;

    ExecHookEntry& entry = m_execHooks[it->second];
    if (!RemoveEptExecDisable(entry.gpa, entry.size)) {
        m_logger->Trace(LOG_WARNING, "EptExecHook: Failed to restore EXEC for GPA=0x%llX", gpa);
    }

    entry.active = false;
    m_gpaToExecHook.erase(it);

    m_logger->Trace(LOG_EPT, "EPT exec hook removed: GPA=0x%llX", gpa);
    return true;
}

bool EptExecHook::ProtectPage(uint64_t gpa, uint64_t size)
{
    if (!m_initialized || !m_partition) return false;

    // Map as no-access (trap all read/write/execute)
    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)0;
    void* hostVA = (void*)gpa; // Identity mapping

    if (!m_partition->MapGpaRange(hostVA, gpa, size, flags)) {
        m_logger->Trace(LOG_ERROR, "EptExecHook: Failed to protect GPA=0x%llX", gpa);
        return false;
    }

    m_logger->Trace(LOG_EPT, "EPT memory protected (no access): GPA=0x%llX size=%llu", gpa, size);
    return true;
}

bool EptExecHook::UnprotectPage(uint64_t gpa)
{
    if (!m_partition) return false;

    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute;
    void* hostVA = (void*)gpa;

    if (!m_partition->MapGpaRange(hostVA, gpa, 0x1000, flags)) {
        m_logger->Trace(LOG_ERROR, "EptExecHook: Failed to unprotect GPA=0x%llX", gpa);
        return false;
    }

    m_logger->Trace(LOG_EPT, "EPT memory unprotected: GPA=0x%llX", gpa);
    return true;
}

bool EptExecHook::HandleMemoryAccess(uint64_t gpa, uint64_t rip, WHV_MEMORY_ACCESS_TYPE accessType)
{
    // Check EPT exec hooks (execute interception)
    if (accessType == WHvMemoryAccessExecute) {
        auto it = m_gpaToExecHook.find(gpa & ~0xFFFULL);
        if (it != m_gpaToExecHook.end()) {
            ExecHookEntry& entry = m_execHooks[it->second];
            entry.hitCount++;

            // Restore execute temporarily for this instruction
            RemoveEptExecDisable(entry.gpa, entry.size);

            // Call the callback
            if (entry.callback) {
                entry.callback(gpa, rip);
            }

            // Re-apply execute-disable after the instruction completes
            // The caller (VcpuManager) will re-disable after single-step
            m_logger->Trace(LOG_EPT, "EPT exec hook hit: GPA=0x%llX RIP=0x%llX hits=%u",
                gpa, rip, entry.hitCount);
            return true;
        }
    }

    // Check single-step hooks
    auto ssIt = m_gpaToSingleStep.find(gpa & ~0xFFFULL);
    if (ssIt != m_gpaToSingleStep.end()) {
        ExecHookEntry& entry = m_singleStepHooks[ssIt->second];
        entry.hitCount++;
        if (entry.callback) {
            entry.callback(gpa, rip);
        }
        return true;
    }

    return false;
}

bool EptExecHook::HasHook(uint64_t gpa) const
{
    return (m_gpaToExecHook.find(gpa) != m_gpaToExecHook.end()) ||
           (m_gpaToSingleStep.find(gpa) != m_gpaToSingleStep.end());
}

bool EptExecHook::RegisterPageHook(uint64_t gpa, void (*callback)(uint64_t, uint64_t))
{
    // Legacy single-step hook support
    if (m_gpaToSingleStep.find(gpa) != m_gpaToSingleStep.end()) return true;

    ExecHookEntry entry;
    entry.gpa = gpa;
    entry.size = 0x1000;
    entry.hostVA = (void*)gpa;
    entry.hookType = ExecHookType::SINGLE_STEP;
    entry.active = true;
    entry.callback = callback;
    entry.hitCount = 0;

    m_gpaToSingleStep[gpa] = m_singleStepHooks.size();
    m_singleStepHooks.push_back(entry);

    m_logger->Trace(LOG_EPT, "Single-step hook registered: GPA=0x%llX", gpa);
    return true;
}

void EptExecHook::Serialize(std::vector<uint8_t>& buffer)
{
    // Serialize EPT hook state: count + entries
    uint32_t count = (uint32_t)m_execHooks.size();
    size_t pos = buffer.size();
    buffer.resize(pos + sizeof(uint32_t) + count * sizeof(ExecHookEntry));
    memcpy(buffer.data() + pos, &count, sizeof(uint32_t));
    for (uint32_t i = 0; i < count; i++) {
        memcpy(buffer.data() + pos + sizeof(uint32_t) + i * sizeof(ExecHookEntry),
               &m_execHooks[i], sizeof(ExecHookEntry));
    }
}

void EptExecHook::Deserialize(const uint8_t* data, uint32_t size)
{
    if (!data || size < sizeof(uint32_t)) return;
    uint32_t count = *(const uint32_t*)data;
    if (size < sizeof(uint32_t) + count * sizeof(ExecHookEntry)) return;
    m_execHooks.clear();
    m_gpaToExecHook.clear();
    for (uint32_t i = 0; i < count; i++) {
        ExecHookEntry entry;
        memcpy(&entry, data + sizeof(uint32_t) + i * sizeof(ExecHookEntry), sizeof(ExecHookEntry));
        if (entry.active) {
            m_gpaToExecHook[entry.gpa] = m_execHooks.size();
            m_execHooks.push_back(entry);
        }
    }
}

bool EptExecHook::HandleSingleStepComplete(HANDLE partitionHandle, uint32_t vcpuIndex)
{
    (void)partitionHandle;
    (void)vcpuIndex;
    // Re-apply execute-disable for any EPT exec hooks that were temporarily lifted
    for (auto& hook : m_execHooks) {
        if (hook.active && hook.hookType == ExecHookType::EPT_DISABLE_EXEC) {
            ApplyEptExecDisable(hook.gpa, hook.size, hook.hostVA);
        }
    }
    return false;
}

bool EptExecHook::HandleExecFault(uint64_t gpa, uint64_t rip, HANDLE partitionHandle, uint32_t vcpuIndex)
{
    (void)rip;
    (void)partitionHandle;
    (void)vcpuIndex;
    // Check if this GPA has an EPT exec hook
    auto it = m_gpaToExecHook.find(gpa & ~0xFFFULL);
    if (it != m_gpaToExecHook.end()) {
        ExecHookEntry& entry = m_execHooks[it->second];
        entry.hitCount++;

        // Temporarily restore execute permission for single-step
        RemoveEptExecDisable(entry.gpa, entry.size);

        // Fire the callback
        if (entry.callback) {
            entry.callback(gpa, 0);
        }

        m_logger->Trace(LOG_EPT, "EPT exec fault: GPA=0x%llX hit=%u", gpa, entry.hitCount);
        return true;
    }
    return false;
}

bool EptExecHook::UnregisterPageHook(uint64_t gpa)
{
    auto it = m_gpaToSingleStep.find(gpa);
    if (it == m_gpaToSingleStep.end()) return false;

    m_singleStepHooks[it->second].active = false;
    m_gpaToSingleStep.erase(it);
    return true;
}

bool EptExecHook::ApplyEptExecDisable(uint64_t gpa, uint64_t size, void* hostVA)
{
    if (!m_partition) return false;

    // Remap the page WITHOUT execute permission
    // This causes a MemoryAccess VM exit when code tries to execute there
    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;

    return m_partition->MapGpaRange(hostVA, gpa, size, flags);
}

bool EptExecHook::RemoveEptExecDisable(uint64_t gpa, uint64_t size)
{
    if (!m_partition) return false;

    // Restore full access including execute
    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute;

    void* hostVA = (void*)gpa; // Identity mapping
    return m_partition->MapGpaRange(hostVA, gpa, size, flags);
}
