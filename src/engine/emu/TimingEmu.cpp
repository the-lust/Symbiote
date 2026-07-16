#define WIN32_NO_STATUS
#include "TimingEmu.h"
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <profileapi.h>
#include <cmath>

TimingEmu::TimingEmu(Logger* logger)
    : m_logger(logger), m_syntheticTscBase(0), m_syntheticTscFreq(3700000000ULL),
      m_qpcBase(0), m_tickBase(0), m_timeBase(0), m_initialized(false)
{
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    m_qpcBase = qpc.QuadPart;
    m_tickBase = GetTickCount64();

    SYSTEMTIME st;
    GetSystemTime(&st);
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    m_timeBase = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

void TimingEmu::SetSyntheticTscSource(uint64_t* tscPtr)
{
    m_syntheticTscBase = tscPtr;
    m_logger->Trace(LOG_TIMING, "TimingEmu: linked to synthetic TSC source at 0x%p", tscPtr);
}

uint64_t TimingEmu::GetSyntheticTickCount() const
{
    if (!m_syntheticTscBase) return GetTickCount64();

    uint64_t syntheticTsc = 0;
    if (m_syntheticTscBase) {
        // Read TSC from the shared location; if zero, fall back to real TSC
        syntheticTsc = *m_syntheticTscBase;
        if (syntheticTsc == 0) syntheticTsc = __rdtsc();
    } else {
        syntheticTsc = __rdtsc();
    }

    // Convert TSC to milliseconds: TSC / freq * 1000
    uint64_t ms = (syntheticTsc * 1000ULL) / m_syntheticTscFreq;
    return m_tickBase + ms;
}

uint64_t TimingEmu::GetSyntheticQpc() const
{
    if (!m_syntheticTscBase) {
        LARGE_INTEGER qpc;
        QueryPerformanceCounter(&qpc);
        return qpc.QuadPart;
    }

    uint64_t syntheticTsc = *m_syntheticTscBase;
    if (syntheticTsc == 0) syntheticTsc = __rdtsc();

    // Convert TSC to 10MHz QPC ticks: TSC * 10,000,000 / freq
    uint64_t qpcTicks = (syntheticTsc * 10000000ULL) / m_syntheticTscFreq;
    return m_qpcBase + qpcTicks;
}

bool TimingEmu::HandleNtQueryPerformanceCounter(uint64_t* args, uint64_t* result)
{
    uint64_t qpcPtr = args[0];
    uint64_t freqPtr = args[1];

    uint64_t spoofedQpc = GetSyntheticQpc();

    if (qpcPtr) {
        *(LARGE_INTEGER*)(uintptr_t)qpcPtr = *(LARGE_INTEGER*)&spoofedQpc;
    }
    if (freqPtr) {
        LARGE_INTEGER freq;
        freq.QuadPart = 10000000; // 10 MHz consistent with TSC-derived QPC
        *(LARGE_INTEGER*)(uintptr_t)freqPtr = freq;
    }

    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool TimingEmu::HandleNtSetTimerResolution(uint64_t*, uint64_t* result)
{
    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool TimingEmu::HandleNtQueryTimerResolution(uint64_t* args, uint64_t* result)
{
    if (args[0]) *(uint32_t*)(uintptr_t)args[0] = 0x00030D40; // max
    if (args[1]) *(uint32_t*)(uintptr_t)args[1] = 0x00000C4E; // min
    if (args[2]) *(uint32_t*)(uintptr_t)args[2] = 0x00030D40; // current
    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool TimingEmu::HandleGetTickCount(uint64_t*, uint64_t* result)
{
    *result = GetSyntheticTickCount();
    return true;
}

bool TimingEmu::HandleGetSystemTime(uint64_t* args, uint64_t* result)
{
    if (!m_syntheticTscBase) {
        SYSTEMTIME st;
        GetSystemTime(&st);
        if (args[0]) memcpy((void*)(uintptr_t)args[0], &st, sizeof(st));
        *result = (uint64_t)STATUS_SUCCESS;
        return true;
    }

    // Derive system time from synthetic tick count offset
    uint64_t elapsedMs = GetSyntheticTickCount() - m_tickBase;
    uint64_t elapsed100Ns = elapsedMs * 10000;

    FILETIME ft;
    ft.dwHighDateTime = (DWORD)((m_timeBase + elapsed100Ns) >> 32);
    ft.dwLowDateTime = (DWORD)((m_timeBase + elapsed100Ns) & 0xFFFFFFFF);

    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    if (args[0]) memcpy((void*)(uintptr_t)args[0], &st, sizeof(st));
    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool TimingEmu::HandleGetSystemTimeAdjustment(uint64_t* args, uint64_t* result)
{
    if (args[0]) *(uint32_t*)(uintptr_t)args[0] = 156001;
    if (args[1]) *(uint32_t*)(uintptr_t)args[1] = 0;
    if (args[2]) args[2] = 1;
    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}
