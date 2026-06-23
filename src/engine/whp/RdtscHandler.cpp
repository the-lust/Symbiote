#include "RdtscHandler.h"
#include "kernel/IKernelBackend.h"

static inline uint64_t ReadTSC() {
    return __rdtsc();
}

RdtscHandler::RdtscHandler(Logger* logger, IKernelBackend* backend)
    : m_logger(logger), m_backend(backend),
      m_tscOffset(0), m_lastTsc(0), m_noiseEnabled(true), m_noiseAmplitude(100)
{
    if (m_backend) {
        m_tscOffset = m_backend->GetTscOffset();
    }
}

uint32_t RdtscHandler::LcgNext(uint32_t seed)
{
    // Linear congruential generator: ANSI C LCG
    return (seed * 1103515245U + 12345U) & 0x7FFFFFFFU;
}

uint64_t RdtscHandler::AddTimingNoise(uint64_t tsc)
{
    if (!m_noiseEnabled || m_noiseAmplitude == 0) {
        return tsc;
    }

    // Generate pseudo-random noise using TSC bits as seed
    uint32_t seed = (uint32_t)(tsc & 0x7FFFFFFF);
    uint32_t noise = LcgNext(seed) % (m_noiseAmplitude * 2) - m_noiseAmplitude;

    // Ensure TSC never goes backwards
    uint64_t result = tsc + noise;
    if (result <= m_lastTsc) {
        result = m_lastTsc + 1;
    }
    m_lastTsc = result;

    return result;
}

bool RdtscHandler::HandleRdtsc(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rdx, uint64_t* rip)
{
    uint64_t realTsc = ReadTSC();
    uint64_t spoofedTsc = realTsc + m_tscOffset;
    spoofedTsc = AddTimingNoise(spoofedTsc);

    *rax = spoofedTsc & 0xFFFFFFFF;
    *rdx = (spoofedTsc >> 32) & 0xFFFFFFFF;

    m_logger->Trace(LOG_TIMING, "RDTSC: real=0x%llX spoofed=0x%llX", realTsc, spoofedTsc);
    return true;
}

bool RdtscHandler::HandleRdtscp(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rdx, uint64_t* rcx, uint64_t* rip)
{
    uint64_t realTsc = ReadTSC();
    uint64_t spoofedTsc = realTsc + m_tscOffset;
    spoofedTsc = AddTimingNoise(spoofedTsc);

    *rax = spoofedTsc & 0xFFFFFFFF;
    *rdx = (spoofedTsc >> 32) & 0xFFFFFFFF;
    // TSC_AUX: encode logical processor number
    *rcx = 0x00000001;

    m_logger->Trace(LOG_TIMING, "RDTSCP: real=0x%llX spoofed=0x%llX", realTsc, spoofedTsc);
    return true;
}
