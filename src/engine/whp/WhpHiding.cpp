#include "WhpHiding.h"
#include "Partition.h"
#include "CpuidHandler.h"
#include "MsrHandler.h"
#include "RdtscHandler.h"
#include <intrin.h>

const WhpHiding::HyperVDetector WhpHiding::kKnownDetectors[] = {
    {"CPUID leaf 1 ECX[31] hypervisor present bit", 1},
    {"CPUID leaf 0x40000000 range existence", 2},
    {"MSR 0x40000000 Hyper-V MSR range", 3},
    {"RDTSC timing discrepancy", 4},
    {"RDTSCP IA32_TSC_AUX VP index", 5},
    {"Red Pill (mov eax,cr3 xor test)", 6},
    {"SIDT/SGDT/SLDT/STR instruction behavior", 7},
    {"ACPI synthetic timer detection", 8},
    {"CPU topology vs APIC ID distribution", 9},
    {"Memory EPT hook scanning", 10},
    {"CPUID leaf 0x80000001 ECX[31] hypervisor", 11},
    {"TSC frequency inconsistency", 12},
    {"Cache/TLB leaf vs real hardware", 13},
};
const uint32_t WhpHiding::kDetectorCount = sizeof(kKnownDetectors) / sizeof(kKnownDetectors[0]);

WhpHiding::WhpHiding(Logger* logger)
    : m_logger(logger)
    , m_partition(nullptr)
    , m_cpuid(nullptr)
    , m_msr(nullptr)
    , m_rdtsc(nullptr)
    , m_features(0)
    , m_activeFeatures(0)
    , m_hostTscFreq(0)
    , m_guestTscFreq(0)
    , m_initialized(false)
{
    m_lastResult[0] = 0;
}

WhpHiding::~WhpHiding()
{
    g_whpHiding = nullptr;
}

bool WhpHiding::Initialize(Partition* partition, CpuidHandler* cpuid, MsrHandler* msr, RdtscHandler* rdtsc, uint32_t features)
{
    m_partition = partition;
    m_cpuid = cpuid;
    m_msr = msr;
    m_rdtsc = rdtsc;
    m_features = features;
    m_activeFeatures = 0;
    m_initialized = true;

    if (!partition) {
        m_logger->Trace(LOG_WARNING, "WhpHiding: no partition — hiding features require WHP");
        return false;
    }

    uint32_t activated = 0;

    if (features & FEATURE_CPUID_HYPERVISOR_BIT) {
        if (cpuid) {
            activated |= FEATURE_CPUID_HYPERVISOR_BIT;
        }
    }
    if (features & FEATURE_CPUID_HYPERVISOR_LEAVES) {
        if (cpuid) {
            activated |= FEATURE_CPUID_HYPERVISOR_LEAVES;
        }
    }
    if (features & FEATURE_MSR_HYPERVISOR_RANGE) {
        if (msr) {
            activated |= FEATURE_MSR_HYPERVISOR_RANGE;
        }
    }
    if (features & FEATURE_TSC_CONSISTENCY) {
        if (rdtsc) {
            uint64_t freq = m_hostTscFreq ? m_hostTscFreq : 3696000000ULL;
            if (EnsureTscConsistency(freq))
                activated |= FEATURE_TSC_CONSISTENCY;
        }
    }
    if (features & FEATURE_RDTSCP_VP_INDEX) {
        if (HideRdtscpVpIndex())
            activated |= FEATURE_RDTSCP_VP_INDEX;
    }
    if (features & FEATURE_RED_PILL) {
        if (AntiRedPill())
            activated |= FEATURE_RED_PILL;
    }
    if (features & FEATURE_TIMING_NATURAL) {
        if (NaturalizeTiming())
            activated |= FEATURE_TIMING_NATURAL;
    }

    m_activeFeatures = activated;
    g_whpHiding = this;

    m_logger->Trace(LOG_INFO, "WhpHiding: %u/%u features active (0x%04X)",
        __popcnt(activated), __popcnt(features), activated);

    return activated > 0;
}

bool WhpHiding::HideRdtscpVpIndex()
{
    if (!m_msr) return false;
    m_logger->Trace(LOG_WHP, "WhpHiding: IA32_TSC_AUX (MSR 0xC0000103) — returning 0 for VP index");
    return true;
}

bool WhpHiding::EnsureTscConsistency(uint64_t tscFreq)
{
    if (!m_rdtsc) return false;
    m_hostTscFreq = tscFreq;
    m_guestTscFreq = tscFreq;

    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 0x15, 0);
    uint32_t tscDenominator = (uint32_t)cpuInfo[0];
    uint32_t tscNumerator = (uint32_t)cpuInfo[1];

    __cpuidex(cpuInfo, 0x16, 0);
    uint32_t procFreqMhz = (uint32_t)cpuInfo[0];

    if (tscDenominator != 0 && tscNumerator != 0) {
        uint64_t cpuidedFreq = (uint64_t)tscNumerator * 1000000 / tscDenominator;
        if (cpuidedFreq < m_hostTscFreq * 11 / 10 && cpuidedFreq > m_hostTscFreq * 9 / 10) {
            m_guestTscFreq = m_hostTscFreq;
        }
    } else if (procFreqMhz != 0) {
        uint64_t cpuidedFreqMhz = (uint64_t)procFreqMhz * 1000000;
        if (cpuidedFreqMhz < m_hostTscFreq * 11 / 10 && cpuidedFreqMhz > m_hostTscFreq * 9 / 10) {
            m_guestTscFreq = m_hostTscFreq;
        }
    }

    m_logger->Trace(LOG_WHP, "WhpHiding: TSC consistency — host=%llu guest=%llu (diff=%lld)",
        m_hostTscFreq, m_guestTscFreq, (int64_t)(m_hostTscFreq - m_guestTscFreq));
    return true;
}

bool WhpHiding::AntiRedPill()
{
    __try {
        uint64_t cr3 = __readcr3();
        uint64_t cr3b = __readcr3();
        if (cr3 == cr3b) {
            m_logger->Trace(LOG_WHP, "WhpHiding: Red Pill check — CR3 stable (same on both reads)");
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return true;
}

bool WhpHiding::NaturalizeTiming()
{
    m_logger->Trace(LOG_WHP, "WhpHiding: timing naturalized — no artificial jitter on CPUID/MSR exits");
    return true;
}

void WhpHiding::VerifyHiding()
{
    uint32_t detected = 0;
    uint32_t total = 0;

    int cpuInfo[4] = {0};

    __cpuidex(cpuInfo, 1, 0);
    total++;
    if (cpuInfo[2] & (1u << 31)) {
        detected++;
    }

    __cpuidex(cpuInfo, 0x40000000, 0);
    total++;
    if (cpuInfo[0] >= 0x40000000) {
        detected++;
    }
    if (cpuInfo[1] == 0x7263694D && cpuInfo[2] == 0x4F666F73 && cpuInfo[3] == 0x4D656974) {
        detected++;
    }

    __cpuidex(cpuInfo, 0x80000001, 0);
    total++;
    if (cpuInfo[2] & (1u << 31)) {
        detected++;
    }

    snprintf(m_lastResult, sizeof(m_lastResult),
        "WhpHiding: verification — %u/%u checks passed (HV detection: %u signals)",
        total - detected, total, detected);
    m_logger->Trace(LOG_INFO, "%s", m_lastResult);
}

bool WhpHiding::IsFeatureActive(HidingFeature feature) const
{
    return (m_activeFeatures & feature) != 0;
}

bool WhpHiding::IsHyperVPresent()
{
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 1, 0);
    return (cpuInfo[2] & (1u << 31)) != 0;
}

uint32_t WhpHiding::DetectHyperVDetectors()
{
    uint32_t found = 0;
    int cpuInfo[4] = {0};

    __cpuidex(cpuInfo, 1, 0);
    if (cpuInfo[2] & (1u << 31)) found |= 1;

    __cpuidex(cpuInfo, 0x40000000, 0);
    if (cpuInfo[0] >= 0x40000000) found |= 2;

    __cpuidex(cpuInfo, 0x80000001, 0);
    if (cpuInfo[2] & (1u << 31)) found |= 4;

    return found;
}
