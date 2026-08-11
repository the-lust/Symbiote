#include "VirtualClock.h"
#include "../whp/RdtscHandler.h"

VirtualClock& VirtualClock::Get()
{
    static VirtualClock s_instance;
    return s_instance;
}

void VirtualClock::Configure(uint64_t qpcFrequency, uint64_t tscFrequency)
{
    if (qpcFrequency >= 1000 && qpcFrequency <= 1000000000ULL) {
        m_qpcFrequency = qpcFrequency;
    }
    if (tscFrequency >= 100000000ULL && tscFrequency <= 10000000000ULL) {
        m_tscFrequency = tscFrequency;
    }
    m_anchorInitialized = false; // re-anchor on next read with fresh config
}

void VirtualClock::SetTscSource(RdtscHandler* rdtsc)
{
    m_rdtsc = rdtsc;
    m_anchorInitialized = false;
}

void VirtualClock::SetSystemTimeOffset(int64_t offset100ns)
{
    m_systemTimeOffset = offset100ns;
}

void VirtualClock::SetSystemTimeAnchor(uint64_t filetime100ns)
{
    m_anchorRaw = filetime100ns;
    m_anchorVqpc = (int64_t)VirtualQpc100ns();
    m_anchorInitialized = true;
}

uint64_t VirtualClock::CurrentSpoofedTsc() const
{
    if (m_rdtsc) {
        // Same source the guest's RDTSC sees — cross-consistent by construction.
        return m_rdtsc->ReadSpoofedTsc();
    }
    // No WHP/RDTSC path (e.g. IAT-only fallback): local monotonic counter.
    return (uint64_t)GetTickCount64() * m_tscFrequency / 1000;
}

uint64_t VirtualClock::VirtualQpc100ns() const
{
    // VQPC = tsc * qpcFreq / tscFreq — exact division without 64x64 overflow.
    uint64_t tsc = CurrentSpoofedTsc();
    uint64_t q = tsc / m_tscFrequency;
    uint64_t r = tsc % m_tscFrequency;
    return q * m_qpcFrequency + r * m_qpcFrequency / m_tscFrequency;
}

uint64_t VirtualClock::InterruptTime() const
{
    // Uptime-relative: engine boot anchors at 0 — the host's boot epoch
    // (a machine-unique value) is never exposed.
    return VirtualQpc100ns();
}

uint64_t VirtualClock::SystemTime() const
{
    if (!m_anchorInitialized) {
        m_anchorInitialized = true;
        if (m_anchorRaw == 0) {
            // Absolute wall time is environment, not identity (see header note).
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            m_anchorRaw = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        }
        m_anchorVqpc = (int64_t)VirtualQpc100ns();
    }
    return m_anchorRaw + (uint64_t)((int64_t)VirtualQpc100ns() - m_anchorVqpc + m_systemTimeOffset);
}

uint64_t VirtualClock::TickCountQuad() const
{
    // 64 Hz ticks: 15.625 ms = 156250 100ns units per tick (real-validated).
    return InterruptTime() / 156250;
}

uint32_t VirtualClock::TimeUpdateLock() const
{
    return (uint32_t)TickCountQuad();
}