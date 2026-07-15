#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <atomic>
#include "Logger.h"

class IKernelBackend;
struct TimingCoordinator;
class CaptureLogger;

class RdtscHandler {
public:
    explicit RdtscHandler(Logger* logger, IKernelBackend* backend);

    void SetTimingCoordinator(TimingCoordinator* tc) { m_timingCoordinator = tc; }
    void SetCaptureLogger(CaptureLogger* cap) { m_captureLogger = cap; }

    bool HandleRdtsc(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rdx, uint64_t* rip);
    bool HandleRdtscp(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rdx, uint64_t* rcx, uint64_t* rip);

    uint64_t GetTscOffset() const { return m_tscOffset; }
    void SetTscOffset(uint64_t offset) { m_tscOffset = offset; }

    void SetNoiseEnabled(bool enabled) { m_noiseEnabled = enabled; }
    void SetNoiseAmplitude(uint32_t amplitude) { m_noiseAmplitude = amplitude; }

private:
    Logger* m_logger;
    IKernelBackend* m_backend;
    TimingCoordinator* m_timingCoordinator;
    CaptureLogger* m_captureLogger;
    uint64_t m_tscOffset;

    std::atomic<uint64_t> m_lastTsc;
    uint64_t m_lastPreExitTsc = 0;
    bool m_noiseEnabled;
    uint32_t m_noiseAmplitude;

    uint32_t LcgNext(uint32_t seed);
    uint64_t AddTimingNoise(uint64_t tsc);
};
