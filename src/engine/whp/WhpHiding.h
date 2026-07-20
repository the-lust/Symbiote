#pragma once
#include <windows.h>
#include <cstdint>
#include "Logger.h"

class Partition;
class CpuidHandler;
class MsrHandler;
class RdtscHandler;

class WhpHiding {
public:
    explicit WhpHiding(Logger* logger);
    ~WhpHiding();

    enum HidingFeature : uint32_t {
        FEATURE_CPUID_HYPERVISOR_BIT = 0x0001,
        FEATURE_CPUID_HYPERVISOR_LEAVES = 0x0002,
        FEATURE_MSR_HYPERVISOR_RANGE = 0x0004,
        FEATURE_TSC_CONSISTENCY = 0x0008,
        FEATURE_RDTSCP_VP_INDEX = 0x0010,
        FEATURE_RED_PILL = 0x0020,
        FEATURE_ACPI_SYNTHETIC = 0x0040,
        FEATURE_TOPOLOGY = 0x0080,
        FEATURE_EPT_SCAN = 0x0100,
        FEATURE_TIMING_NATURAL = 0x0200,
        FEATURE_ALL = 0xFFFF,
    };

    bool Initialize(Partition* partition, CpuidHandler* cpuid, MsrHandler* msr, RdtscHandler* rdtsc, uint32_t features = FEATURE_ALL);
    void VerifyHiding();

    bool IsFeatureActive(HidingFeature feature) const;
    uint32_t GetActiveFeatureCount() const { return m_activeFeatures; }
    const char* GetLastVerificationResult() const { return m_lastResult; }

    bool HideRdtscpVpIndex();
    bool EnsureTscConsistency(uint64_t tscFreq);
    bool AntiRedPill();
    bool NaturalizeTiming();

    static bool IsHyperVPresent();
    static uint32_t DetectHyperVDetectors();

private:
    Logger* m_logger;
    Partition* m_partition;
    CpuidHandler* m_cpuid;
    MsrHandler* m_msr;
    RdtscHandler* m_rdtsc;
    uint32_t m_features;
    uint32_t m_activeFeatures;
    uint64_t m_hostTscFreq;
    uint64_t m_guestTscFreq;
    bool m_initialized;
    char m_lastResult[256];

    struct HyperVDetector {
        const char* name;
        uint32_t flag;
    };
    static const HyperVDetector kKnownDetectors[];
    static const uint32_t kDetectorCount;
};

extern WhpHiding* g_whpHiding;
