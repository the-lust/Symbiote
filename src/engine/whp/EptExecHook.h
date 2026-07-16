#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <cstdint>
#include <unordered_map>
#include <functional>
#include <optional>
#include "Logger.h"

class Partition;

class EptExecHook {
public:
    using HookCallback = std::function<void(uint64_t gpa, uint64_t rip)>;

    explicit EptExecHook(Logger* logger, Partition* partition);
    ~EptExecHook();

    // Register a page for execution hooking — strips EXEC from EPT so
    // first instruction fetch causes a VM exit. Returns false if the
    // page is already tracked (refcount incremented).
    bool RegisterPageHook(uint64_t gpa, HookCallback callback = nullptr);

    // Unregister a page hook. When refcount reaches 0, EXEC is restored.
    bool UnregisterPageHook(uint64_t gpa);

    // Returns true if the page has active execution hooks
    bool HasHook(uint64_t gpa) const;

    // Called from MemoryAccess handler when an EXEC-type EPT violation fires
    // on a hooked page. Fires callbacks, arms the single-step, returns true.
    // Returns false if the page is not hooked.
    bool HandleExecFault(uint64_t gpa, uint64_t rip, WHV_PARTITION_HANDLE partition, uint32_t vpIndex);

    // Called from #DB handler. Returns true if this was our internal
    // single-step completion (state restored). Returns false if the #DB
    // was triggered by the guest (pass through).
    bool HandleSingleStepComplete(WHV_PARTITION_HANDLE partition, uint32_t vpIndex);

    // Serialization for snapshot (saves GPA list only — callbacks are re-registered)
    bool Serialize(std::vector<uint8_t>& buffer) const;
    bool Deserialize(const uint8_t* data, size_t size);
    size_t GetSerializedSize() const;

private:
    struct PageHook {
        uint64_t gpa;
        int refCount;
        HookCallback callback;
    };

    struct PendingStep {
        uint64_t gpa;
        bool hadTrapFlag;
    };

    void RestoreExecPermission(uint64_t gpa);
    void RemoveExecPermission(uint64_t gpa);

    Logger* m_logger;
    Partition* m_partition;
    std::unordered_map<uint64_t, PageHook> m_hooks;
    std::optional<PendingStep> m_pendingStep;
};
