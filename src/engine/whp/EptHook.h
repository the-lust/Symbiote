#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <vector>
#include <unordered_map>
#include "Logger.h"
#include "ExitDispatcher.h"

class Partition;
class MsrHandler;

enum EptHookType {
    EPT_HOOK_NORMAL = 0,
    EPT_HOOK_KERNEL_PAGE = 1,
    EPT_HOOK_MSR_BITMAP = 2,
    EPT_HOOK_IDT = 3,
    EPT_HOOK_GDT = 4,
    EPT_HOOK_CR3 = 5,
};

class EptHook : public IExitHandler {
public:
    explicit EptHook(Logger* logger, Partition* partition);
    ~EptHook();

    bool HandleExit(WHV_VP_EXIT_CONTEXT* ctx, WHV_RUN_VP_EXIT_CONTEXT* exitCtx, uint64_t* rip) override;
    WHV_RUN_VP_EXIT_REASON GetExitReason() const override { return WHvRunVpExitReasonMemoryAccess; }

    bool InstallHook(uint64_t gpa, void* hostVA, uint32_t size, EptHookType type = EPT_HOOK_NORMAL);
    bool HandleEptViolation(WHV_VP_EXIT_CONTEXT* ctx, uint64_t gpa, uint64_t* rip);

    bool InstallKernelMemoryHooks();
    bool InstallMsrBitmapHook();
    bool HookPage(uint64_t gpa, void* shadowVA, uint32_t size);

private:
    Logger* m_logger;
    Partition* m_partition;

    struct EptEntry {
        uint64_t gpa;
        void* hostVA;
        uint32_t size;
        bool mapped;
        EptHookType type;
        void* originalVA;
    };
    std::vector<EptEntry> m_hooks;
    std::unordered_map<uint64_t, EptEntry*> m_gpaIndex;
};
