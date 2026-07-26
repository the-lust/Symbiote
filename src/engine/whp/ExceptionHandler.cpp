#include "ExceptionHandler.h"
#include "../proxy/InstructionDecoder.h"
#include <windows.h>

ExceptionHandler::ExceptionHandler(Logger* logger)
    : m_logger(logger)
{
}

// Best-effort real instruction length at a guest RIP (identity-mapped, so *rip is directly
// host-readable the same way other modules in this codebase treat guest addresses — see
// e.g. HwIdEmu/FileEmu). Falls back to 2 (the prior hardcoded assumption) if the read faults
// or the decoder can't make sense of the bytes, rather than guessing a specific other length.
static int SafeInstructionLength(uint64_t rip)
{
    __try {
        int len = GetInstructionLength((const uint8_t*)(uintptr_t)rip);
        if (len <= 0 || len > 15) return 2;
        return len;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 2;
    }
}

bool ExceptionHandler::HandleException(WHV_VP_EXIT_CONTEXT*, uint32_t exceptionCode,
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

bool ExceptionHandler::HandleGpFault(uint64_t**, uint64_t* rip)
{
    if (!rip) return false;
    int len = SafeInstructionLength(*rip);
    m_logger->Trace(LOG_WHP, "VM #GP fault at RIP 0x%llX - skipping %d-byte instruction", *rip, len);
    *rip += len;
    return true;
}

bool ExceptionHandler::HandleUdFault(uint64_t**, uint64_t* rip)
{
    if (!rip) return false;
    int len = SafeInstructionLength(*rip);
    m_logger->Trace(LOG_WHP, "VM #UD fault at RIP 0x%llX - skipping %d-byte instruction", *rip, len);
    *rip += len;
    return true;
}
