#include "RdtscHandler.h"
#include "kernel/IKernelBackend.h"
#include "TimingCoordinator.h"
#include "capture/CaptureLogger.h"
#include <chrono>
#include <thread>
#include <cstring>

std::atomic<uint64_t> RdtscHandler::s_counterTsc{0};
std::atomic<uint64_t> RdtscHandler::s_counterTscFrequency{3700000000ULL};

static inline uint64_t ReadTSC() {
    return __rdtsc();
}

RdtscHandler::RdtscHandler(Logger* logger, IKernelBackend* backend)
    : m_logger(logger), m_backend(backend), m_timingCoordinator(nullptr),
      m_captureLogger(nullptr),
      m_tscOffset(0), m_tscFrequency(3700000000ULL), m_lastTsc(0),
      m_noiseEnabled(true), m_noiseAmplitude(100),
      m_vpIndex(0), m_counterRunning(false)
{
    if (m_backend) {
        m_tscOffset = m_backend->GetTscOffset();
    }
}

RdtscHandler::~RdtscHandler()
{
    StopCounterUpdater();
}

RdtscHandler::CpuNoiseParams RdtscHandler::GetNoiseParamsForVendor(const char* vendor)
{
    CpuNoiseParams params;
    params.meanJitter = 50;
    params.amplitudeJitter = 25;
    params.minDelta = 80;

    if (vendor) {
        if (strstr(vendor, "Intel") || strstr(vendor, "GenuineIntel")) {
            params.meanJitter = 40;
            params.amplitudeJitter = 20;
            params.minDelta = 60;
        } else if (strstr(vendor, "AMD") || strstr(vendor, "AuthenticAMD")) {
            params.meanJitter = 80;
            params.amplitudeJitter = 40;
            params.minDelta = 120;
        }
    }
    return params;
}

uint64_t RdtscHandler::AddRealisticNoise(uint64_t tsc)
{
    const char* vendor = m_backend ? "GenuineIntel" : "GenuineIntel";
    CpuNoiseParams params = GetNoiseParamsForVendor(vendor);

    uint32_t seed = (uint32_t)(tsc & 0x7FFFFFFF);
    uint32_t noise = LcgNext(seed) % (params.amplitudeJitter * 2);
    int64_t signedNoise = (int64_t)(noise) - (int64_t)params.amplitudeJitter;

    uint64_t result;
    if (signedNoise >= 0) {
        result = tsc + (uint64_t)signedNoise;
    } else {
        result = tsc - (uint64_t)(-signedNoise);
    }

    if (result <= m_lastTsc.load()) {
        result = m_lastTsc.load() + params.minDelta;
    }
    m_lastTsc.store(result);
    return result;
}

uint32_t RdtscHandler::LcgNext(uint32_t seed)
{
    return (seed * 1103515245U + 12345U) & 0x7FFFFFFFU;
}

uint64_t RdtscHandler::AddTimingNoise(uint64_t tsc)
{
    if (!m_noiseEnabled || m_noiseAmplitude == 0) {
        return tsc;
    }

    uint32_t seed = (uint32_t)(tsc & 0x7FFFFFFF);
    uint32_t noise = LcgNext(seed) % (m_noiseAmplitude * 2) - m_noiseAmplitude;

    uint64_t result = tsc + noise;
    uint64_t last = m_lastTsc.load();
    if (result <= last) {
        result = last + 1;
    }
    m_lastTsc.store(result);

    return result;
}

void RdtscHandler::StartCounterUpdater()
{
    if (m_counterRunning.load()) return;

    s_counterTscFrequency.store(m_tscFrequency);
    s_counterTsc.store(__rdtsc());
    m_counterRunning.store(true);
    m_counterThread = std::thread(CounterUpdaterThread, this);

    m_logger->Trace(LOG_TIMING, "CounterUpdater thread started (freq=%llu Hz)", m_tscFrequency);
}

void RdtscHandler::StopCounterUpdater()
{
    if (!m_counterRunning.load()) return;

    m_counterRunning.store(false);
    if (m_counterThread.joinable()) {
        m_counterThread.join();
    }
    m_logger->Trace(LOG_TIMING, "CounterUpdater thread stopped");
}

uint64_t RdtscHandler::GetCounterUpdaterTsc()
{
    return s_counterTsc.load();
}

void RdtscHandler::CounterUpdaterThread(RdtscHandler* handler)
{
    (void)handler;
    uint64_t lastReal = __rdtsc();
    uint64_t lastSynthetic = s_counterTsc.load();
    auto lastTime = std::chrono::high_resolution_clock::now();

    while (handler->m_counterRunning.load()) {
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t realTsc = __rdtsc();

        // Calculate elapsed in nanoseconds
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - lastTime).count();
        if (elapsed > 0) {
            // Advance synthetic TSC by expected cycles at configured frequency
            uint64_t freq = s_counterTscFrequency.load();
            uint64_t delta = (uint64_t)((double)freq * (double)elapsed / 1000000000.0);
            lastSynthetic += delta;
            s_counterTsc.store(lastSynthetic);
        }

        lastReal = realTsc;
        lastTime = now;

        // Sleep ~100us to keep overhead low
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

bool RdtscHandler::HandleRdtsc(WHV_VP_EXIT_CONTEXT*, uint64_t* rax, uint64_t* rdx, uint64_t*)
{
    // Use CounterUpdater TSC if available, else real TSC with offset
    uint64_t realTsc = ReadTSC();
    uint64_t counterTsc = s_counterTsc.load();
    uint64_t spoofedTsc;

    if (counterTsc > 0 && m_counterRunning.load()) {
        // Use synthetic CounterUpdater TSC + small offset for consistency
        spoofedTsc = counterTsc + m_tscOffset;
    } else {
        spoofedTsc = realTsc + m_tscOffset;
    }

    // Leaf-specific VM-exit cost compensation
    bool cpuidJustExited = false;
    uint32_t lastLeaf = 0;
    if (m_timingCoordinator) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        cpuidJustExited = m_timingCoordinator->DetectRdtscAfterCpuid((uint64_t)now.QuadPart);
        lastLeaf = m_timingCoordinator->lastCpuidLeaf;
        if (cpuidJustExited) {
            uint64_t bareMetalCost = CplLeafCost(lastLeaf);
            uint64_t lastPreExit = m_lastPreExitTsc;
            if (spoofedTsc >= lastPreExit + 100) {
                spoofedTsc = lastPreExit + bareMetalCost;
            }
            m_logger->Trace(LOG_TIMING, "RDTSC VM-exit compensation: leaf=0x%X cost=%llu cycles",
                lastLeaf, bareMetalCost);
        }
        spoofedTsc = m_timingCoordinator->AddJitter(spoofedTsc, m_tscFrequency);
    } else {
        spoofedTsc = AddRealisticNoise(spoofedTsc);
    }

    *rax = spoofedTsc & 0xFFFFFFFF;
    *rdx = (spoofedTsc >> 32) & 0xFFFFFFFF;

    if (!cpuidJustExited) {
        m_lastPreExitTsc = spoofedTsc;
    }

    if (m_captureLogger) {
        m_captureLogger->CaptureRdtsc("RDTSC", 0, realTsc);
    }

    m_logger->Trace(LOG_TIMING, "RDTSC: real=0x%llX spoofed=0x%llX (counter=%d)", realTsc, spoofedTsc, (int)m_counterRunning.load());
    return true;
}

bool RdtscHandler::HandleRdtscp(WHV_VP_EXIT_CONTEXT*, uint64_t* rax, uint64_t* rdx, uint64_t* rcx, uint64_t*)
{
    uint64_t realTsc = ReadTSC();
    uint64_t counterTsc = s_counterTsc.load();
    uint64_t spoofedTsc;

    if (counterTsc > 0 && m_counterRunning.load()) {
        spoofedTsc = counterTsc + m_tscOffset;
    } else {
        spoofedTsc = realTsc + m_tscOffset;
    }

    bool cpuidJustExited = false;
    uint32_t lastLeaf = 0;
    if (m_timingCoordinator) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        cpuidJustExited = m_timingCoordinator->DetectRdtscAfterCpuid((uint64_t)now.QuadPart);
        lastLeaf = m_timingCoordinator->lastCpuidLeaf;
        if (cpuidJustExited) {
            uint64_t bareMetalCost = CplLeafCost(lastLeaf);
            uint64_t lastPreExit = m_lastPreExitTsc;
            if (spoofedTsc >= lastPreExit + 100) {
                spoofedTsc = lastPreExit + bareMetalCost;
            }
            m_logger->Trace(LOG_TIMING, "RDTSCP VM-exit compensation: leaf=0x%X cost=%llu cycles",
                lastLeaf, bareMetalCost);
        }
        spoofedTsc = m_timingCoordinator->AddJitter(spoofedTsc, m_tscFrequency);
    } else {
        spoofedTsc = AddRealisticNoise(spoofedTsc);
    }

    if (!cpuidJustExited) {
        m_lastPreExitTsc = spoofedTsc;
    }

    *rax = spoofedTsc & 0xFFFFFFFF;
    *rdx = (spoofedTsc >> 32) & 0xFFFFFFFF;
    *rcx = m_vpIndex;

    if (m_captureLogger) {
        m_captureLogger->CaptureRdtsc("RDTSCP", 0, realTsc);
    }

    m_logger->Trace(LOG_TIMING, "RDTSCP: real=0x%llX spoofed=0x%llX vpIndex=%u (counter=%d)",
        realTsc, spoofedTsc, m_vpIndex, (int)m_counterRunning.load());
    return true;
}
