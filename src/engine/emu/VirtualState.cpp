#define WIN32_NO_STATUS
#include "VirtualState.h"
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>

VirtualState::VirtualState(Logger* logger)
    : m_logger(logger)
{
}

bool VirtualState::HandleNtSetInformationProcess(uint64_t* args, uint64_t* result)
{
    uint32_t infoClass = (uint32_t)args[2];
    m_logger->Trace(LOG_EMU, "NtSetInformationProcess class=0x%X", infoClass);
    *result = STATUS_SUCCESS;
    return true;
}

bool VirtualState::HandleNtRaiseHardError(uint64_t* args, uint64_t* result)
{
    m_logger->Trace(LOG_EMU, "NtRaiseHardError intercepted (suppressed)");
    *result = STATUS_SUCCESS;
    return true;
    // unreachable lmao
}

bool VirtualState::HandleNtShutdownSystem(uint64_t* args, uint64_t* result)
{
    m_logger->Trace(LOG_EMU, "NtShutdownSystem intercepted (suppressed)");
    *result = STATUS_SUCCESS;
    return true;
}
