#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

class ExceptionHandler {
public:
    explicit ExceptionHandler(Logger* logger);

    bool HandleException(WHV_VP_EXIT_CONTEXT* ctx, uint32_t exceptionCode, uint64_t** regs,
                         uint64_t* rip);

private:
    Logger* m_logger;

    bool HandleGpFault(uint64_t** regs, uint64_t* rip);
    bool HandleUdFault(uint64_t** regs, uint64_t* rip);
};
