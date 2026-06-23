#define WIN32_NO_STATUS
#include "TimingEmu.h"
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <profileapi.h>

TimingEmu::TimingEmu(Logger* logger)
    : m_logger(logger), m_qpcOffset(0x100000000ULL)
{
}

uint64_t TimingEmu::GetSpoofedQpc() const
{
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    return qpc.QuadPart + m_qpcOffset;
}

bool TimingEmu::HandleNtQueryPerformanceCounter(uint64_t* args, uint64_t* result)
{
    uint64_t qpcPtr = args[0];
    uint64_t freqPtr = args[1];

    uint64_t spoofedQpc = GetSpoofedQpc();

    if (qpcPtr) {
        *(LARGE_INTEGER*)(uintptr_t)qpcPtr = *(LARGE_INTEGER*)&spoofedQpc;
    }
    if (freqPtr) {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        *(LARGE_INTEGER*)(uintptr_t)freqPtr = freq;
    }

    *result = STATUS_SUCCESS;
    m_logger->Trace(LOG_TIMING, "NtQueryPerformanceCounter: QPC=0x%llX", spoofedQpc);
    return true;
}

bool TimingEmu::HandleNtSetTimerResolution(uint64_t* args, uint64_t* result)
{
    *result = STATUS_SUCCESS;
    return true;
}

bool TimingEmu::HandleNtQueryTimerResolution(uint64_t* args, uint64_t* result)
{
    if (args[0]) *(uint32_t*)(uintptr_t)args[0] = 0x00030D40;
    if (args[1]) *(uint32_t*)(uintptr_t)args[1] = 0x00000C4E;
    if (args[2]) *(uint32_t*)(uintptr_t)args[2] = 0x00030D40;
    *result = STATUS_SUCCESS;
    return true;
}

bool TimingEmu::HandleGetTickCount(uint64_t* args, uint64_t* result)
{
    *result = GetTickCount64();
    return true;
}

bool TimingEmu::HandleGetSystemTime(uint64_t* args, uint64_t* result)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    if (args[0]) {
        memcpy((void*)(uintptr_t)args[0], &st, sizeof(st));
    }
    *result = STATUS_SUCCESS;
    return true;
}
