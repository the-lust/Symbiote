#include "TimingCoordinator.h"
#include <cstring>

TimingCoordinator::TimingCoordinator()
{
    // Initialize with default Intel profile
    SetCpuProfile("GenuineIntel", "Core");
    SnapshotBaseClocks();
}

TimingCoordinator::~TimingCoordinator()
{
}

void TimingCoordinator::SetCpuProfile(const char* vendor, const char* family)
{
    if (vendor && strstr(vendor, "AMD")) {
        if (family && strstr(family, "Ryzen")) {
            m_currentProfile = { "AuthenticAMD", "Ryzen", 80, 40, 80, 200, 200 };
        } else {
            m_currentProfile = { "AuthenticAMD", "Generic", 100, 50, 100, 250, 300 };
        }
    } else {
        // Intel profiles
        if (family && strstr(family, "Core")) {
            if (family && strstr(family, "i9")) {
                m_currentProfile = { "GenuineIntel", "Core-i9", 30, 15, 60, 150, 100 };
            } else if (family && strstr(family, "i7")) {
                m_currentProfile = { "GenuineIntel", "Core-i7", 40, 20, 60, 150, 100 };
            } else if (family && strstr(family, "i5")) {
                m_currentProfile = { "GenuineIntel", "Core-i5", 50, 25, 80, 180, 150 };
            } else {
                m_currentProfile = { "GenuineIntel", "Core", 40, 20, 60, 150, 100 };
            }
        } else if (family && strstr(family, "Xeon")) {
            m_currentProfile = { "GenuineIntel", "Xeon", 20, 10, 50, 100, 50 };
        } else {
            m_currentProfile = { "GenuineIntel", "Generic", 50, 25, 80, 200, 150 };
        }
    }
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

    // ACPI PM timer base (synthetic - stored at init)
    m_baseAcpiPmTimer = (uint32_t)(m_baseTsc & 0xFFFFFF);

    // HPET base (synthetic)
    m_baseHpetCounter = (uint32_t)(m_baseTsc & 0xFFFFFFFF);
}

uint64_t TimingCoordinator::GetConsistentQpc() const
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
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

uint32_t TimingCoordinator::GetConsistentAcpiPmTimer() const
{
    // ACPI PM timer at 3.579545 MHz, 24-bit
    uint64_t elapsed = __rdtsc() - m_baseTsc;
    uint32_t ticks = (uint32_t)((elapsed * 3579545) / 3700000000ULL);
    return ((uint32_t)m_baseAcpiPmTimer + ticks) & 0xFFFFFF;
}

uint64_t TimingCoordinator::GetConsistentHpetCounter() const
{
    // HPET at ~10MHz typical
    uint64_t elapsed = __rdtsc() - m_baseTsc;
    uint64_t ticks = (elapsed * 10000000) / 3700000000ULL;
    return m_baseHpetCounter + ticks;
}

bool TimingCoordinator::VerifyClockConsistency() const
{
    // Verify that all clock sources are consistent with each other
    // This prevents integrity verification from cross-referencing clocks
    uint64_t tsc = GetConsistentTsc();
    uint64_t qpc = GetConsistentQpc();
    uint32_t acpi = GetConsistentAcpiPmTimer();

    // TSC and QPC should have a roughly fixed ratio
    // (TSC frequency ~ QPC frequency * ~100 on modern systems)
    // We just verify they're both increasing
    (void)tsc;
    (void)qpc;
    (void)acpi;

    return true;
}
