#include "ExceptionHandler.h"

ExceptionHandler::ExceptionHandler(Logger* logger)
    : m_logger(logger)
{
}

bool ExceptionHandler::HandleException(WHV_VP_EXIT_CONTEXT* ctx, uint32_t exceptionCode,
                                        uint64_t** regs, uint64_t* rip)
{
    switch (exceptionCode) {
        case 0x0D: // #GP - General Protection Fault
            return HandleGpFault(regs, rip);
        case 0x06: // #UD - Undefined Instruction
            return HandleUdFault(regs, rip);
        default:
            m_logger->Trace(LOG_WHP, "Unhandled VM exception 0x%02X at RIP 0x%llX",
                exceptionCode, rip ? *rip : 0);
            return false;
    }
}

bool ExceptionHandler::HandleGpFault(uint64_t** regs, uint64_t* rip)
{
    if (!rip) return false;
    m_logger->Trace(LOG_WHP, "VM #GP fault at RIP 0x%llX - skipping instruction", *rip);
    // Skip the faulting instruction (assumed 2 bytes for common #GP triggers)
    *rip += 2;
    return true;
}

bool ExceptionHandler::HandleUdFault(uint64_t** regs, uint64_t* rip)
{
    if (!rip) return false;
    m_logger->Trace(LOG_WHP, "VM #UD fault at RIP 0x%llX - skipping instruction", *rip);
    // Skip the undefined instruction (assumed 2 bytes)
    *rip += 2;
    return true;
}
