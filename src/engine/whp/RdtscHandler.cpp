#include "RdtscHandler.h"
#include "kernel/IKernelBackend.h"
#include "TimingCoordinator.h"
#include "capture/CaptureLogger.h"

static inline uint64_t ReadTSC() {
    return __rdtsc();
}

RdtscHandler::RdtscHandler(Logger* logger, IKernelBackend* backend)
    : m_logger(logger), m_backend(backend), m_timingCoordinator(nullptr),
      m_captureLogger(nullptr),
      m_tscOffset(0), m_lastTsc(0), m_noiseEnabled(true), m_noiseAmplitude(100),
      m_vpIndex(0)
{
    if (m_backend) {
        m_tscOffset = m_backend->GetTscOffset();
    }
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
    if (result <= m_lastTsc) {
        result = m_lastTsc + 1;
    }
    m_lastTsc = result;

    return result;
}

bool RdtscHandler::HandleRdtsc(WHV_VP_EXIT_CONTEXT*, uint64_t* rax, uint64_t* rdx, uint64_t*)
{
    uint64_t realTsc = ReadTSC();
    uint64_t spoofedTsc = realTsc + m_tscOffset;

    // Leaf-specific VM-exit cost compensation
    bool cpuidJustExited = false;
    uint32_t lastLeaf = 0;
    if (m_timingCoordinator) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        cpuidJustExited = m_timingCoordinator->DetectRdtscAfterCpuid((uint64_t)now.QuadPart);
        lastLeaf = m_timingCoordinator->lastCpuidLeaf;
        if (cpuidJustExited) {
            // Use leaf-specific bare-metal cost instead of fixed 80
            uint64_t bareMetalCost = CplLeafCost(lastLeaf);
            if (spoofedTsc >= m_lastPreExitTsc + 100) {
                spoofedTsc = m_lastPreExitTsc + bareMetalCost;
            }
            m_logger->Trace(LOG_TIMING, "RDTSC VM-exit compensation: leaf=0x%X cost=%llu cycles",
                lastLeaf, bareMetalCost);
        }
        spoofedTsc = m_timingCoordinator->AddJitter(spoofedTsc, 3700000000ULL);
    } else {
        spoofedTsc = AddTimingNoise(spoofedTsc);
    }

    *rax = spoofedTsc & 0xFFFFFFFF;
    *rdx = (spoofedTsc >> 32) & 0xFFFFFFFF;

    if (!cpuidJustExited) {
        m_lastPreExitTsc = spoofedTsc;
    }

    if (m_captureLogger) {
        m_captureLogger->CaptureRdtsc("RDTSC", 0, realTsc);
    }

    m_logger->Trace(LOG_TIMING, "RDTSC: real=0x%llX spoofed=0x%llX", realTsc, spoofedTsc);
    return true;
}

bool RdtscHandler::HandleRdtscp(WHV_VP_EXIT_CONTEXT*, uint64_t* rax, uint64_t* rdx, uint64_t* rcx, uint64_t*)
{
    uint64_t realTsc = ReadTSC();
    uint64_t spoofedTsc = realTsc + m_tscOffset;

    bool cpuidJustExited = false;
    uint32_t lastLeaf = 0;
    if (m_timingCoordinator) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        cpuidJustExited = m_timingCoordinator->DetectRdtscAfterCpuid((uint64_t)now.QuadPart);
        lastLeaf = m_timingCoordinator->lastCpuidLeaf;
        if (cpuidJustExited) {
            uint64_t bareMetalCost = CplLeafCost(lastLeaf);
            if (spoofedTsc >= m_lastPreExitTsc + 100) {
                spoofedTsc = m_lastPreExitTsc + bareMetalCost;
            }
            m_logger->Trace(LOG_TIMING, "RDTSCP VM-exit compensation: leaf=0x%X cost=%llu cycles",
                lastLeaf, bareMetalCost);
        }
        spoofedTsc = m_timingCoordinator->AddJitter(spoofedTsc, 3700000000ULL);
    } else {
        spoofedTsc = AddTimingNoise(spoofedTsc);
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

    m_logger->Trace(LOG_TIMING, "RDTSCP: real=0x%llX spoofed=0x%llX vpIndex=%u",
        realTsc, spoofedTsc, m_vpIndex);
    return true;
}
