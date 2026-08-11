#pragma once
#include <windows.h>
#include <cstdint>

class RdtscHandler;

// ---------------------------------------------------------------------------
// VirtualClock — the engine's single time authority.
//
// Every time value the guest can observe (RDTSC via RdtscHandler, KUSER
// InterruptTime/SystemTime/TickCount, NtQuerySystemTime) is derived from ONE
// virtual TSC so all clocks advance together (monotonic, cross-consistent —
// WS-2/WS-7 requirement). The virtual TSC comes from the provider that also
// serves guest RDTSC (RdtscHandler::ReadSpoofedTsc), so a guest measuring
// TSC-vs-KUSER deltas sees consistent rates.
//
// Non-identity environment note (zero-rule): the absolute SystemTime anchor
// defaults to the host wall clock sampled ONCE at engine start. Absolute wall
// time is not a machine-unique identity vector (every legit VM passes host
// wall time through); boot-era values (uptime, interrupt time) are engine-
// relative so the host's boot epoch never leaks. An explicit config anchor
// (system_time_anchor) overrides the wall-clock default.
// ---------------------------------------------------------------------------
class VirtualClock {
public:
    static VirtualClock& Get();

    // qpcFrequency: guest QPC ticks per second (e.g. 10000000).
    // tscFrequency: guest nominal TSC frequency (TIP: 1995375200 for LUST).
    void Configure(uint64_t qpcFrequency, uint64_t tscFrequency);
    void SetTscSource(RdtscHandler* rdtsc);
    void SetSystemTimeAnchor(uint64_t filetime100ns); // 0 = host wall clock at first read
    void SetSystemTimeOffset(int64_t offset100ns);    // KUSER <-> NtQuerySystemTime skew

    uint64_t QpcFrequency() const { return m_qpcFrequency; }

    // Virtual QPC in 100ns units, monotonic within a boot.
    uint64_t VirtualQpc100ns() const;

    // Interrupt time (100 ns) — uptime-relative, anchors at engine start.
    uint64_t InterruptTime() const;

    // System time (100 ns since 1601-01-01).
    uint64_t SystemTime() const;

    // Tick count at 64 Hz (15.625 ms ticks — matches real KUSER ratio:
    // measured live uptime 365 s -> TickCount 23340 on Win11 26200).
    uint64_t TickCountQuad() const;

    // TimeUpdateLock content (same tick cadence, low part).
    uint32_t TimeUpdateLock() const;

private:
    VirtualClock() = default;

    uint64_t CurrentSpoofedTsc() const;

    uint64_t m_qpcFrequency = 10000000;
    uint64_t m_tscFrequency = 1995375200; // LUST donor default
    RdtscHandler* m_rdtsc = nullptr;

    mutable bool m_anchorInitialized = false;
    mutable uint64_t m_anchorRaw = 0;   // SystemTime anchor in 100ns
    mutable int64_t  m_anchorVqpc = 0;  // VQPC at anchor sample time
    int64_t  m_systemTimeOffset = 0;
};