#include "TimingCoordinator.h"

TimingCoordinator::TimingCoordinator()
{
    SnapshotBaseClocks();
}

TimingCoordinator::~TimingCoordinator()
{
}

void TimingCoordinator::SnapshotBaseClocks()
{
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    m_baseQpc = qpc.QuadPart;

    m_baseTsc = __rdtsc();

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    m_baseSysTime = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

    m_baseTickCount = GetTickCount64();

    m_baseTimeGetTime = timeGetTime();
}

uint64_t TimingCoordinator::GetConsistentQpc() const
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    // Base QPC + elapsed delta to ensure monotonicity
    uint64_t elapsed = now.QuadPart - m_baseQpc;
    return m_baseQpc + (elapsed / 2);
}

uint64_t TimingCoordinator::GetConsistentTsc() const
{
    uint64_t now = __rdtsc();
    uint64_t elapsed = now - m_baseTsc;
    return m_baseTsc + (elapsed / 2);
}

uint64_t TimingCoordinator::GetConsistentSysTime() const
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t now = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t elapsed = now - m_baseSysTime;
    return m_baseSysTime + (elapsed / 2);
}

uint64_t TimingCoordinator::GetConsistentTickCount() const
{
    uint64_t now = GetTickCount64();
    uint64_t elapsed = now - m_baseTickCount;
    return m_baseTickCount + (elapsed / 2);
}

uint32_t TimingCoordinator::GetConsistentTimeGetTime() const
{
    uint32_t now = timeGetTime();
    uint32_t elapsed = now - (uint32_t)m_baseTimeGetTime;
    return (uint32_t)m_baseTimeGetTime + (elapsed / 2);
}
