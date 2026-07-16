#include "AcpiTimerHandler.h"
#include <chrono>

AcpiTimerHandler::AcpiTimerHandler(Logger* logger)
    : m_logger(logger), m_initialized(false),
      m_startTime(0), m_basePmTimer(0), m_baseHpetCounter(0)
{
}

AcpiTimerHandler::~AcpiTimerHandler()
{
    Shutdown();
}

bool AcpiTimerHandler::Initialize()
{
    if (m_initialized) return true;

    m_startTime = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();

    // Initialize synthetic timers with realistic base values
    m_basePmTimer = (uint32_t)(m_startTime & 0xFFFFFF);
    m_baseHpetCounter = m_startTime * 1000; // HPET is ~10MHz typical

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "AcpiTimerHandler: PM timer base=0x%X HPET base=0x%llX",
        (uint32_t)m_basePmTimer, m_baseHpetCounter);
    return true;
}

void AcpiTimerHandler::Shutdown()
{
    m_initialized = false;
}

uint32_t AcpiTimerHandler::GetSyntheticPmTimer()
{
    // ACPI PM timer runs at 3.579545 MHz, wraps at 24 bits
    auto now = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();

    uint64_t elapsed = now - m_startTime;
    uint32_t ticks = (uint32_t)((elapsed * ACPI_PM_TIMER_FREQ) / 1000000ULL);
    return (ticks + (uint32_t)m_basePmTimer) & 0xFFFFFF;
}

uint64_t AcpiTimerHandler::GetSyntheticHpetCounter()
{
    auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();

    uint64_t elapsed = now - m_startTime * 1000;
    // HPET main counter typically runs at ~10MHz (100ns per tick)
    uint64_t ticks = elapsed / 100;
    return m_baseHpetCounter + ticks;
}

bool AcpiTimerHandler::HandlePmTimerIoRead(uint32_t port, uint32_t* value)
{
    if (port != ACPI_PM_TIMER_PORT) return false;

    uint32_t pmTimer = GetSyntheticPmTimer();
    if (value) *value = pmTimer;

    if (m_logger) {
        m_logger->Trace(LOG_TIMING, "ACPI PM Timer read: port=0x%04X value=0x%06X",
            port, pmTimer);
    }
    return true;
}
