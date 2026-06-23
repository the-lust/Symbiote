#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

class IKernelBackend;

class CpuidHandler {
public:
    explicit CpuidHandler(Logger* logger, class IKernelBackend* backend);
    ~CpuidHandler();

    bool HandleCpuid(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rbx,
                     uint64_t* rcx, uint64_t* rdx, uint64_t* rip);

private:
    Logger* m_logger;
    class IKernelBackend* m_backend;
};
