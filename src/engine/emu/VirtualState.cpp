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
    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool VirtualState::HandleNtRaiseHardError(uint64_t* args, uint64_t* result)
{
    NTSTATUS errorStatus = (NTSTATUS)args[0];
    ULONG responseType = (ULONG)args[1];
    m_logger->Trace(LOG_EMU, "NtRaiseHardError suppressed: status=0x%08X responseType=%u",
        errorStatus, responseType);

    if (args[4]) {
        *(ULONG*)(uintptr_t)args[4] = 0; // ResponseHandle = NULL
    }
    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool VirtualState::HandleNtShutdownSystem(uint64_t* args, uint64_t* result)
{
    uint32_t action = (uint32_t)args[0];
    m_logger->Trace(LOG_EMU, "NtShutdownSystem intercepted (suppressed): action=%u", action);
    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}
