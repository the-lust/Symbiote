#pragma once
#include <windows.h>
#include <cstdint>
#include <atomic>

enum JitterStrategy {
    JITTER_UNIFORM = 0,
    JITTER_CONSTANT = 1,
    JITTER_LINEAR = 2,
    JITTER_REALISTIC = 3,  // Real-hardware modeled jitter
};

// CPU jitter profiles for realistic timing noise
struct CpuJitterProfile {
    const char* vendor;
    const char* family;
    uint32_t tscJitterMean;      // Mean TSC jitter in cycles
    uint32_t tscJitterAmplitude; // +/- jitter from mean
    uint32_t cpuidExitCostMin;   // Minimum CPUID exit cost (bare metal)
    uint32_t cpuidExitCostMax;   // Maximum CPUID exit cost (bare metal)
    uint32_t rdtscInterClusterDelta; // TSC delta between different core clusters
};

struct TimingCoordinator {
public:
    TimingCoordinator();
    ~TimingCoordinator();

    // RDTSC→CPUID→RDTSC pattern detection
    uint64_t lastRdtscTime = 0;
    uint64_t lastCpuidTime = 0;
    uint32_t lastCpuidLeaf = 0;
    uint32_t rdtscCpuidRdtscCount = 0;

    // Jitter configuration
    JitterStrategy jitterStrategy = JITTER_REALISTIC;  // Default to realistic
    uint32_t jitterBaseUs = 10;

    // Monotonic TSC tracking
    uint64_t monotonicLastTsc = 0;

    // Cross-time-source correlation base
    uint64_t m_baseQpc = 0;
    uint64_t m_baseTsc = 0;
    uint64_t m_baseSysTime = 0;
    uint64_t m_baseTickCount = 0;
    uint64_t m_baseTimeGetTime = 0;
    uint64_t m_baseAcpiPmTimer = 0;  // ACPI PM timer base
    uint64_t m_baseHpetCounter = 0;  // HPET counter base

    // CPU drift profile
    CpuJitterProfile m_currentProfile;
    void SetCpuProfile(const char* vendor, const char* family);

    // Detect RDTSC before CPUID (pattern: RDTSC → CPUID)
    void DetectRdtscBeforeCpuid(uint64_t rdtscTime) {
        lastRdtscTime = rdtscTime;
    }

    // Detect CPUID after RDTSC (pattern: RDTSC → CPUID → RDTSC)
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

    // Detect RDTSC after CPUID (completing the RDTSC→CPUID→RDTSC pattern)
    bool DetectRdtscAfterCpuid(uint64_t rdtscTime) {
        bool found = (lastCpuidTime != 0 && (rdtscTime - lastCpuidTime) < 10000);
        if (found) {
            rdtscCpuidRdtscCount++;
        }
        lastRdtscTime = rdtscTime;
        lastCpuidTime = 0;
        return found;
    }

    // Add jitter with realistic hardware profile
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
            case JITTER_REALISTIC: {
                // Real hardware model: TSC jitter follows a normal-like distribution
                // with specific amplitude per CPU model
                uint32_t seed = (uint32_t)(tsc & 0x7FFFFFFF);
                uint32_t noise = (seed * 1103515245U + 12345U) & 0x7FFF;
                
                // Scale jitter by CPU profile
                uint32_t mean = m_currentProfile.tscJitterMean;
                uint32_t amp = m_currentProfile.tscJitterAmplitude;
                delayUs = jitterBaseUs + mean + (noise % (amp * 2)) - amp;
                
                // Add occasional "spike" to mimic real hardware cache misses affecting TSC
                if ((noise & 0xFFF) == 0x123) {
                    delayUs += 200; // ~0.2ms spike (rare, like real hardware)
                }
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
    // Additional clock sources for cross-correlation
    uint32_t GetConsistentAcpiPmTimer() const;
    uint64_t GetConsistentHpetCounter() const;

    // Cross-source verification: ensure all clocks are consistent with each other
    // Returns true if all sources correlate properly (spoof passes)
    bool VerifyClockConsistency() const;
};
