#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

class CpuidHandler {
public:
    explicit CpuidHandler(Logger* logger, class CpuProfile* cpuProfile);
    ~CpuidHandler();

    void LoadSpoofs();

    bool HandleCpuid(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rbx,
                     uint64_t* rcx, uint64_t* rdx, uint64_t* rip);

private:
    Logger* m_logger;
    class CpuProfile* m_cpuProfile;
};
