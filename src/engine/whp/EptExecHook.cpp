#include "EptExecHook.h"
#include "Partition.h"

#define HOOK_LOG(fmt, ...) m_logger->Trace(LOG_WHP, "EptExecHook: " fmt, ##__VA_ARGS__)
#define HOOK_ERR(fmt, ...) m_logger->Trace(LOG_ERROR, "EptExecHook: " fmt, ##__VA_ARGS__)

EptExecHook::EptExecHook(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition)
{
}

EptExecHook::~EptExecHook()
{
}

bool EptExecHook::RegisterPageHook(uint64_t gpa, HookCallback callback)
{
    auto it = m_hooks.find(gpa);
    if (it != m_hooks.end()) {
        it->second.refCount++;
        if (callback) it->second.callback = callback;
        HOOK_LOG("Page 0x%llX hook refcount -> %d", gpa, it->second.refCount);
        return true;
    }

    PageHook ph;
    ph.gpa = gpa;
    ph.refCount = 1;
    ph.callback = callback;
    m_hooks[gpa] = ph;

    // Remove EXEC from EPT mapping so instruction fetch causes a VM exit
    RemoveExecPermission(gpa);
    HOOK_LOG("Page 0x%llX hook registered, EXEC stripped", gpa);
    return true;
}

bool EptExecHook::UnregisterPageHook(uint64_t gpa)
{
    auto it = m_hooks.find(gpa);
    if (it == m_hooks.end()) return false;

    it->second.refCount--;
    if (it->second.refCount > 0) {
        HOOK_LOG("Page 0x%llX hook refcount -> %d", gpa, it->second.refCount);
        return true;
    }

    // Restore EXEC permission
    RestoreExecPermission(gpa);
    m_hooks.erase(it);
    HOOK_LOG("Page 0x%llX hook removed, EXEC restored", gpa);
    return true;
}

bool EptExecHook::HasHook(uint64_t gpa) const
{
    return m_hooks.find(gpa) != m_hooks.end();
}

bool EptExecHook::HandleExecFault(uint64_t gpa, uint64_t rip, WHV_PARTITION_HANDLE partition, uint32_t vpIndex)
{
    auto it = m_hooks.find(gpa);
    if (it == m_hooks.end()) return false;

    // Fire the registered callback
    if (it->second.callback) {
        it->second.callback(gpa, rip);
    }

    // Arm single-step: temporarily restore EXEC and set trap flag
    RestoreExecPermission(gpa);

    // Read current RFLAGS
    WHV_REGISTER_NAME rflagsName = WHvX64RegisterRflags;
    WHV_REGISTER_VALUE rflagsValue;
    HRESULT hr = WHvGetVirtualProcessorRegisters(partition, vpIndex,
        &rflagsName, 1, &rflagsValue);
    if (FAILED(hr)) {
        HOOK_ERR("Failed to read RFLAGS for single-step arm: 0x%08X", hr);
        return false;
    }

    // Save previous trap flag state
    PendingStep step;
    step.gpa = gpa;
    step.hadTrapFlag = (rflagsValue.Reg64 & 0x100) != 0;

    // Set trap flag
    rflagsValue.Reg64 |= 0x100;
    hr = WHvSetVirtualProcessorRegisters(partition, vpIndex,
        &rflagsName, 1, &rflagsValue);
    if (FAILED(hr)) {
        HOOK_ERR("Failed to set trap flag: 0x%08X", hr);
        return false;
    }

    m_pendingStep = step;
    HOOK_LOG("Single-step armed on GPA 0x%llX (previously had TF=%d)", gpa, step.hadTrapFlag);
    return true;
}

bool EptExecHook::HandleSingleStepComplete(WHV_PARTITION_HANDLE partition, uint32_t vpIndex)
{
    if (!m_pendingStep.has_value()) return false;

    uint64_t gpa = m_pendingStep->gpa;

    // Restore trap flag to previous state
    WHV_REGISTER_NAME rflagsName = WHvX64RegisterRflags;
    WHV_REGISTER_VALUE rflagsValue;
    HRESULT hr = WHvGetVirtualProcessorRegisters(partition, vpIndex,
        &rflagsName, 1, &rflagsValue);
    if (SUCCEEDED(hr)) {
        if (m_pendingStep->hadTrapFlag) {
            rflagsValue.Reg64 |= 0x100;
        } else {
            rflagsValue.Reg64 &= ~0x100;
        }
        WHvSetVirtualProcessorRegisters(partition, vpIndex,
            &rflagsName, 1, &rflagsValue);
    }

    // Re-protect the page by removing EXEC again (if still hooked)
    if (HasHook(gpa)) {
        RemoveExecPermission(gpa);
    }

    m_pendingStep.reset();
    HOOK_LOG("Single-step complete on GPA 0x%llX", gpa);
    return true;
}

void EptExecHook::RestoreExecPermission(uint64_t gpa)
{
    // Re-add EXEC to the EPT mapping for this page
    // We map with the original VA (identity-mapped: VA = GPA)
    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    WHvMapGpaRange(m_partition->GetHandle(), (void*)(uintptr_t)gpa,
        (WHV_GUEST_PHYSICAL_ADDRESS)gpa, 0x1000, flags);
}

void EptExecHook::RemoveExecPermission(uint64_t gpa)
{
    // Strip EXEC from the EPT mapping
    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    WHvMapGpaRange(m_partition->GetHandle(), (void*)(uintptr_t)gpa,
        (WHV_GUEST_PHYSICAL_ADDRESS)gpa, 0x1000, flags);
}

// ─── Snapshot serialization ───────────────────────────────────────────

size_t EptExecHook::GetSerializedSize() const
{
    // Layout: uint32_t count + count * uint64_t gpa
    return sizeof(uint32_t) + m_hooks.size() * sizeof(uint64_t);
}

bool EptExecHook::Serialize(std::vector<uint8_t>& buffer) const
{
    size_t needed = GetSerializedSize();
    size_t offset = buffer.size();
    buffer.resize(offset + needed);

    uint32_t count = (uint32_t)m_hooks.size();
    memcpy(buffer.data() + offset, &count, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    for (const auto& [gpa, hook] : m_hooks) {
        memcpy(buffer.data() + offset, &gpa, sizeof(uint64_t));
        offset += sizeof(uint64_t);
    }

    HOOK_LOG("Serialized %u hook GPAs (%zu bytes)", count, needed);
    return true;
}

bool EptExecHook::Deserialize(const uint8_t* data, size_t size)
{
    if (size < sizeof(uint32_t)) return false;

    uint32_t count;
    memcpy(&count, data, sizeof(uint32_t));
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    if (count > 0 && size < count * sizeof(uint64_t)) return false;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t gpa;
        memcpy(&gpa, data, sizeof(uint64_t));
        data += sizeof(uint64_t);
        size -= sizeof(uint64_t);

        // Re-register hook without callback (callbacks are set up by the owning code)
        RegisterPageHook(gpa, nullptr);
    }

    HOOK_LOG("Deserialized %u hook GPAs", count);
    return true;
}
