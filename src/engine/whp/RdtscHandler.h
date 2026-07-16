#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <atomic>
#include <thread>
#include "Logger.h"

class IKernelBackend;
struct TimingCoordinator;
class CaptureLogger;

class RdtscHandler {
public:
    explicit RdtscHandler(Logger* logger, IKernelBackend* backend);
    ~RdtscHandler();

    void SetTimingCoordinator(TimingCoordinator* tc) { m_timingCoordinator = tc; }
    void SetCaptureLogger(CaptureLogger* cap) { m_captureLogger = cap; }

    bool HandleRdtsc(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rdx, uint64_t* rip);
    bool HandleRdtscp(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rdx, uint64_t* rcx, uint64_t* rip);

    // CounterUpdater: background thread that advances a synthetic TSC at ~3GHz
    void StartCounterUpdater();
    void StopCounterUpdater();
    static uint64_t GetCounterUpdaterTsc();
    static void CounterUpdaterThread(RdtscHandler* handler);

    uint64_t GetTscOffset() const { return m_tscOffset; }
    void SetTscOffset(uint64_t offset) { m_tscOffset = offset; }

    void SetNoiseEnabled(bool enabled) { m_noiseEnabled = enabled; }
    void SetNoiseAmplitude(uint32_t amplitude) { m_noiseAmplitude = amplitude; }
    void SetTscFrequency(uint64_t freq) { m_tscFrequency = freq; }

    void SetCurrentVpIndex(uint32_t idx) { m_vpIndex = idx; }

    // Leaf-specific TSC cycle costs for bare-metal CPUID leaves (expanded)
    static constexpr uint64_t CplLeafCost(uint32_t leaf) {
        switch (leaf) {
            case 0x00: return 80;
            case 0x01: return 120;
            case 0x02: return 600;
            case 0x03: return 80;
            case 0x04: return 350;
            case 0x05: return 100;
            case 0x06: return 100;
            case 0x07: return 150;
            case 0x09: return 80;
            case 0x0A: return 120;
            case 0x0B: return 200;
            case 0x0D: return 400;
            case 0x0F: return 100;
            case 0x10: return 80;
            case 0x12: return 80;
            case 0x14: return 80;
            case 0x15: return 80;
            case 0x16: return 80;
            case 0x17: return 80;
            case 0x18: return 80;
            case 0x19: return 80;
            case 0x1A: return 80;
            case 0x80000000: return 80;
            case 0x80000001: return 120;
            case 0x80000002: case 0x80000003: case 0x80000004: return 250;
            case 0x80000005: return 80;
            case 0x80000006: return 100;
            case 0x80000007: return 80;
            case 0x80000008: return 80;
            case 0x8000000A: return 80;
            case 0x8000001D: return 120;
            case 0x8000001E: return 120;
            case 0x8000001F: return 80;
            default: return 100;
        }
    }

    // Real hardware noise parameters per CPU model
    struct CpuNoiseParams {
        uint32_t meanJitter;      // Mean TSC jitter in cycles
        uint32_t amplitudeJitter; // +/- jitter amplitude
        uint32_t minDelta;        // Minimum observed RDTSC delta
    };

    static CpuNoiseParams GetNoiseParamsForVendor(const char* vendor);
    uint64_t AddRealisticNoise(uint64_t tsc);

private:
    Logger* m_logger;
    IKernelBackend* m_backend;
    TimingCoordinator* m_timingCoordinator;
    CaptureLogger* m_captureLogger;
    uint64_t m_tscOffset;
    uint64_t m_tscFrequency;

    std::atomic<uint64_t> m_lastTsc;
    uint64_t m_lastPreExitTsc = 0;
    bool m_noiseEnabled;
    uint32_t m_noiseAmplitude;
    uint32_t m_vpIndex = 0;

    // CounterUpdater state
    std::thread m_counterThread;
    std::atomic<bool> m_counterRunning;
    static std::atomic<uint64_t> s_counterTsc;
    static std::atomic<uint64_t> s_counterTscFrequency;

    uint32_t LcgNext(uint32_t seed);
    uint64_t AddTimingNoise(uint64_t tsc);
};
