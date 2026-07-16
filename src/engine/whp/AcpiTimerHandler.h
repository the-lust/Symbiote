#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <cstdint>
#include "Logger.h"

// ACPI PM Timer I/O port (standard on x64)
#define ACPI_PM_TIMER_PORT      0x0608
#define ACPI_PM_TIMER_FREQ      3579545  // 3.579545 MHz
#define ACPI_PM_TIMER_BITNESS   24       // 24-bit timer

// HPET MMIO base address
#define HPET_MMIO_BASE          0xFED00000ULL
#define HPET_MMIO_SIZE          0x400

class AcpiTimerHandler {
public:
    explicit AcpiTimerHandler(Logger* logger);
    ~AcpiTimerHandler();

    bool Initialize();
    void Shutdown();

    // Generate synthetic ACPI PM timer value
    static uint32_t GetSyntheticPmTimer();

    // Generate synthetic HPET counter value
    static uint64_t GetSyntheticHpetCounter();

    // Handle ACPI PM timer read via I/O port interception
    bool HandlePmTimerIoRead(uint32_t port, uint32_t* value);

private:
    Logger* m_logger;
    bool m_initialized;
    uint64_t m_startTime;
    uint64_t m_basePmTimer;
    uint64_t m_baseHpetCounter;
};
