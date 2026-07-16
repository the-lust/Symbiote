#pragma once
#include <windows.h>
#include <cstdint>
#include <atomic>

enum JitterStrategy {
    JITTER_UNIFORM = 0,
    JITTER_CONSTANT = 1,
    JITTER_LINEAR = 2,
};

class TimingCoordinator {
public:
    TimingCoordinator();
    ~TimingCoordinator();

    // RDTSC→CPUID→RDTSC pattern detection
    uint64_t lastRdtscTime = 0;
    uint64_t lastCpuidTime = 0;
    uint32_t lastCpuidLeaf = 0;
    uint32_t rdtscCpuidRdtscCount = 0;

    // Jitter configuration
    JitterStrategy jitterStrategy = JITTER_UNIFORM;
    uint32_t jitterBaseUs = 10;

    // Monotonic TSC tracking
    uint64_t monotonicLastTsc = 0;

    // Cross-time-source correlation base
    uint64_t m_baseQpc = 0;
    uint64_t m_baseTsc = 0;
    uint64_t m_baseSysTime = 0;
    uint64_t m_baseTickCount = 0;
    uint64_t m_baseTimeGetTime = 0;

    void DetectRdtscBeforeCpuid(uint64_t rdtscTime) {
        lastRdtscTime = rdtscTime;
    }

    bool DetectCpuidAfterRdtsc(uint32_t leaf, uint64_t cpuidTime) {
        bool pattern = false;
        if (lastRdtscTime != 0 && (cpuidTime - lastRdtscTime) < 10000) {
            rdtscCpuidRdtscCount++;
            pattern = true;
        }
        lastCpuidTime = cpuidTime;
        lastCpuidLeaf = leaf;
        lastRdtscTime = 0;
        return pattern;
    }

    bool DetectRdtscAfterCpuid(uint64_t rdtscTime) {
        bool found = (lastCpuidTime != 0 && (rdtscTime - lastCpuidTime) < 10000);
        if (found) {
            rdtscCpuidRdtscCount++;
        }
        lastRdtscTime = rdtscTime;
        lastCpuidTime = 0;
        return found;
    }

    uint64_t AddJitter(uint64_t tsc, uint64_t tscFrequency) {
        uint64_t delayUs;
        switch (jitterStrategy) {
            case JITTER_CONSTANT:
                delayUs = jitterBaseUs;
                break;
            case JITTER_LINEAR: {
                uint32_t seed = (uint32_t)(tsc & 0x7FFFFFFF);
                delayUs = jitterBaseUs + ((seed * 1103515245U + 12345U) & 0x3FF);
                break;
            }
            case JITTER_UNIFORM:
            default:
                delayUs = (uint64_t)((double)rand() / RAND_MAX * 500.0);
                break;
        }
        uint64_t delta = (delayUs * tscFrequency) / 1000000;
        uint64_t result = tsc + delta;
        if (result <= monotonicLastTsc) {
            result = monotonicLastTsc + 1;
        }
        monotonicLastTsc = result;
        return result;
    }

    // Cross-time-source correlation: snap all clocks at once
    void SnapshotBaseClocks();
    // Get consistent spoofed values across all time sources
    uint64_t GetConsistentQpc() const;
    uint64_t GetConsistentTsc() const;
    uint64_t GetConsistentSysTime() const;
    uint64_t GetConsistentTickCount() const;
    uint32_t GetConsistentTimeGetTime() const;
};
