#include "CpuidHandler.h"
#include "kernel/IKernelBackend.h"
#include "MagicCpuid.h"
#include "TimingCoordinator.h"
#include "capture/CaptureLogger.h"
#include "util/HwDetect.h"
#include <cstring>
#include <intrin.h>

#define CPUID_ECX_HYPERVISOR_BIT  (1u << 31)
#define CPUID_ECX_SMX_BIT        (1u << 6)

CpuidHandler::CpuidHandler(Logger* logger, IKernelBackend* backend)
    : m_logger(logger), m_backend(backend), m_magicCpuid(nullptr),
      m_timingCoordinator(nullptr), m_captureLogger(nullptr),
      m_hasBrandString(false), m_hasEnhancedBrand(false)
{
    m_brandString[0] = 0;
    m_enhancedBrand[0] = 0;
    m_cpuVendor[0] = 0;
    const char* vendor = DetectCpuVendor();
    strncpy_s(m_cpuVendor, sizeof(m_cpuVendor), vendor, _TRUNCATE);
}

CpuidHandler::~CpuidHandler()
{
}

void CpuidHandler::SetBrandString(const char* brand)
{
    strncpy_s(m_brandString, sizeof(m_brandString), brand, _TRUNCATE);
    m_brandString[sizeof(m_brandString) - 1] = 0;
    m_hasBrandString = (m_brandString[0] != 0);
}

void CpuidHandler::SetEnhancedBrandString(const char* brand)
{
    strncpy_s(m_enhancedBrand, sizeof(m_enhancedBrand), brand, _TRUNCATE);
    m_enhancedBrand[sizeof(m_enhancedBrand) - 1] = 0;
    m_hasEnhancedBrand = (m_enhancedBrand[0] != 0);
}

void CpuidHandler::AutoGenerateBrandString(uint64_t tscFrequency)
{
    char autoBrand[49] = {0};
    GenerateBrandString(m_cpuVendor, tscFrequency, autoBrand, sizeof(autoBrand));
    if (!m_hasBrandString && autoBrand[0]) {
        m_logger->Trace(LOG_INFO, "Auto-generated brand string: '%s' (vendor=%s freq=%llu)",
            autoBrand, m_cpuVendor, tscFrequency);
        SetBrandString(autoBrand);
    }
}

bool CpuidHandler::HandleBrandStringLeaf(uint32_t leaf, uint64_t* rax, uint64_t* rbx,
                                          uint64_t* rcx, uint64_t* rdx)
{
    if (leaf < 0x80000002 || leaf > 0x80000004)
        return false;

    const char* brand = m_brandString;
    if (m_magicCpuid && m_magicCpuid->IsEnhancedMode() && m_hasEnhancedBrand) {
        brand = m_enhancedBrand;
    }

    if (!brand || brand[0] == 0)
        return false;

    unsigned int offset = (leaf - 0x80000002) * 16;
    size_t len = strnlen_s(brand, 48);

    auto load16 = [&](unsigned int off) -> uint32_t {
        uint32_t val = 0;
        if (off < len) {
            for (int i = 0; i < 4 && (off + i) < len; i++) {
                val |= ((uint32_t)(unsigned char)brand[off + i]) << (i * 8);
            }
        }
        return val;
    };

    *rax = load16(offset);
    *rbx = load16(offset + 4);
    *rcx = load16(offset + 8);
    *rdx = load16(offset + 12);

    return true;
}

bool CpuidHandler::HandleCpuid(WHV_VP_EXIT_CONTEXT*, uint64_t* rax, uint64_t* rbx,
                                uint64_t* rcx, uint64_t* rdx, uint64_t*)
{
    uint32_t leaf = (uint32_t)(*rax);
    uint32_t subleaf = (uint32_t)(*rcx);

    // Notify timing coordinator to detect RDTSC→CPUID→RDTSC patterns
    if (m_timingCoordinator) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        m_timingCoordinator->DetectCpuidAfterRdtsc(leaf, (uint64_t)now.QuadPart);
    }

    // Per-process tracking: if a PID is registered, only override for that process.
    // NOTE: non-target processes run REAL CPUID here by design — the partition
    // hosts the whole session and the registered target (game + its spawned
    // helpers) is the spoof boundary; anything outside it is left native.
    if (m_magicCpuid && m_magicCpuid->HasTargetPid()) {
        uint64_t currentPid = (uint64_t)GetCurrentProcessId();
        if (currentPid != m_magicCpuid->GetTargetPid()) {
            int cpuInfo[4] = {0};
            __cpuidex(cpuInfo, leaf, subleaf);
            *rax = (uint32_t)cpuInfo[0];
            *rbx = (uint32_t)cpuInfo[1];
            *rcx = (uint32_t)cpuInfo[2];
            *rdx = (uint32_t)cpuInfo[3];
            m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => PASSTHROUGH (not target PID)", leaf, subleaf);
            return true;
        }
    }

    // Exit-latency telemetry (aggregated; logged every 1000 exits)
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);

    uint32_t eax, ebx, ecx, edx;
    EvaluateLeaf(leaf, subleaf, &eax, &ebx, &ecx, &edx);
    *rax = eax;
    *rbx = ebx;
    *rcx = ecx;
    *rdx = edx;

    QueryPerformanceCounter(&t1);
    if (m_backend) {
        uint64_t tscFreq = m_backend->GetTscFrequency();
        if (tscFreq) {
            LARGE_INTEGER qpf;
            QueryPerformanceFrequency(&qpf);
            uint64_t deltaCycles = (uint64_t)((t1.QuadPart - t0.QuadPart) * (int64_t)tscFreq / qpf.QuadPart);
            m_exitCount++;
            m_exitLatencyAccumCycles += deltaCycles;
            if (m_exitCount % 1000 == 0) {
                m_logger->Trace(LOG_TIMING, "CPUID exit-latency telemetry: avg=%llu cycles over last 1000 exits",
                    m_exitLatencyAccumCycles / 1000);
                m_exitLatencyAccumCycles = 0;
            }
        }
    }

    // Capture to fingerprint log
    if (m_captureLogger) {
        m_captureLogger->CaptureCpuid(leaf, subleaf, 0,
            (uint32_t)*rax, (uint32_t)*rbx, (uint32_t)*rcx, (uint32_t)*rdx);
    }

    m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => WS1: RAX=0x%08llX RBX=0x%08llX RCX=0x%08llX RDX=0x%08llX",
        leaf, subleaf, *rax, *rbx, *rcx, *rdx);

    return true;
}

void CpuidHandler::EvaluateCpuidForProcess(uint64_t pid, uint32_t leaf, uint32_t subleaf,
                                           uint32_t* eax, uint32_t* ebx,
                                           uint32_t* ecx, uint32_t* edx)
{
    if (m_magicCpuid && m_magicCpuid->HasTargetPid() && pid != m_magicCpuid->GetTargetPid()) {
        int cpuInfo[4] = {0};
        __cpuidex(cpuInfo, leaf, subleaf);
        *eax = (uint32_t)cpuInfo[0];
        *ebx = (uint32_t)cpuInfo[1];
        *ecx = (uint32_t)cpuInfo[2];
        *edx = (uint32_t)cpuInfo[3];
        return;
    }
    EvaluateLeaf(leaf, subleaf, eax, ebx, ecx, edx);
}

void CpuidHandler::EvaluateLeaf(uint32_t leaf, uint32_t subleaf,
                                uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx)
{
    // Hypervisor leaves: always zero — WHP/Hyper-V presence must be invisible
    if (leaf >= 0x40000000 && leaf <= 0x4000FFFF) {
        *eax = 0; *ebx = 0; *ecx = 0; *edx = 0;
        return;
    }

    // Brand string leaves: from the frozen brand string, else TIP, else zero
    if (leaf >= 0x80000002 && leaf <= 0x80000004) {
        uint64_t ra = 0, rb = 0, rc = 0, rd = 0;
        if (HandleBrandStringLeaf(leaf, &ra, &rb, &rc, &rd)) {
            *eax = (uint32_t)ra; *ebx = (uint32_t)rb;
            *ecx = (uint32_t)rc; *edx = (uint32_t)rd;
            return;
        }
    }

    CpuidResult result;
    if (m_backend && m_backend->HandleCpuid(leaf, subleaf, result)) {
        *eax = result.eax; *ebx = result.ebx;
        *ecx = result.ecx; *edx = result.edx;
    } else {
        // WS-1 zero-rule: leaves absent from the frozen TIP are ZEROED, never
        // answered from real hardware (that would leak the host CPU identity).
        *eax = 0; *ebx = 0; *ecx = 0; *edx = 0;
        LogZeroRuleMiss(leaf, subleaf);
    }

    uint64_t ra = *eax, rb = *ebx, rc = *ecx, rd = *edx;
    ApplyUniversalMask(leaf, subleaf, &ra, &rb, &rc, &rd);
    *eax = (uint32_t)ra; *ebx = (uint32_t)rb;
    *ecx = (uint32_t)rc; *edx = (uint32_t)rd;

    // Leaf 1: hypervisor-present bit (ECX[31]) and SMX/TXT (ECX[6]) must be
    // clear — both are direct virtualized-environment indicators.
    if (leaf == 1) {
        *ecx &= ~CPUID_ECX_HYPERVISOR_BIT;
        *ecx &= ~CPUID_ECX_SMX_BIT;
    }

    // Max-leaf clamp (defense-in-depth): never advertise a range beyond the
    // frozen profile even if a misconfigured TIP entry says otherwise.
    if (leaf == 0 && *eax > 0x0D) *eax = 0x0D;
    if (leaf == 0x80000000 && *eax > 0x80000008) *eax = 0x80000008;
}

void CpuidHandler::LogZeroRuleMiss(uint32_t leaf, uint32_t subleaf)
{
    m_zeroRuleTotal++;
    if (leaf != m_zeroRuleLastLeaf || subleaf != m_zeroRuleLastSubleaf) {
        m_zeroRuleLastLeaf = leaf;
        m_zeroRuleLastSubleaf = subleaf;
        m_zeroRuleMissCount = 0;
        m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => ZEROED (TIP miss, zero-rule)", leaf, subleaf);
    } else if (++m_zeroRuleMissCount >= 1000) {
        m_zeroRuleMissCount = 0;
        m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => ZEROED (TIP miss, zero-rule, %llu total hits)",
            leaf, subleaf, m_zeroRuleTotal);
    }
}

void CpuidHandler::ApplyUniversalMask(uint32_t leaf, uint32_t subleaf,
                                       uint64_t* rax, uint64_t* rbx,
                                       uint64_t* rcx, uint64_t* rdx)
{
    uint32_t eax = (uint32_t)*rax;
    uint32_t ebx = (uint32_t)*rbx;
    uint32_t ecx = (uint32_t)*rcx;
    uint32_t edx = (uint32_t)*rdx;
    ApplyFeatureMask(leaf, subleaf, m_cpuVendor, &eax, &ebx, &ecx, &edx);
    *rax = ((uint64_t)eax) | (*rax & 0xFFFFFFFF00000000ULL);
    *rbx = ((uint64_t)ebx) | (*rbx & 0xFFFFFFFF00000000ULL);
    *rcx = ((uint64_t)ecx) | (*rcx & 0xFFFFFFFF00000000ULL);
    *rdx = ((uint64_t)edx) | (*rdx & 0xFFFFFFFF00000000ULL);
}

void CpuidHandler::BuildCpuidResultList(WHV_X64_CPUID_RESULT* results, int* count, int maxCount,
                                        uint32_t hvHigh)
{
    int idx = 0;

    auto add = [&](uint32_t leaf, uint32_t subleaf) {
        if (idx >= maxCount) return;
        uint32_t eax, ebx, ecx, edx;
        EvaluateLeaf(leaf, subleaf, &eax, &ebx, &ecx, &edx);
        results[idx].Function = leaf;
        results[idx].Reserved[0] = 0;
        results[idx].Reserved[1] = 0;
        results[idx].Reserved[2] = 0;
        results[idx].Eax = eax;
        results[idx].Ebx = ebx;
        results[idx].Ecx = ecx;
        results[idx].Edx = edx;
        idx++;
    };

    // Standard leaves 0x0..0x1F with the profile's subleaf coverage. Every
    // value is produced by EvaluateLeaf (TIP or zero-rule) — nothing native.
    static const struct { uint32_t leaf; uint32_t subCount; } kStd[] = {
        {0x0, 1}, {0x1, 1}, {0x2, 1}, {0x3, 1}, {0x4, 5}, {0x5, 1}, {0x6, 1}, {0x7, 2},
        {0x8, 1}, {0x9, 1}, {0xA, 1}, {0xB, 2}, {0xC, 1}, {0xD, 4}, {0xE, 1}, {0xF, 1},
        {0x10, 1}, {0x11, 1}, {0x12, 1}, {0x13, 1}, {0x14, 2}, {0x15, 1}, {0x16, 1},
        {0x17, 1}, {0x18, 1}, {0x19, 1}, {0x1A, 2}, {0x1B, 1}, {0x1C, 1}, {0x1D, 1},
        {0x1E, 1}, {0x1F, 3},
    };
    for (const auto& e : kStd) {
        for (uint32_t sub = 0; sub < e.subCount; sub++) {
            add(e.leaf, sub);
        }
    }

    // Extended leaves (TIP-driven; unlisted ones fall to the zero-rule)
    for (uint32_t lf = 0x80000000; lf <= 0x80000008; lf++) {
        add(lf, 0);
    }

    // Hypervisor range — always zero, never served from the TIP
    for (uint32_t lf = 0x40000000; lf <= hvHigh; lf++) {
        add(lf, 0);
    }

    *count = idx;
    m_logger->Trace(LOG_WHP, "CpuidResultList populated: %d leaves (policy: TIP or zero-rule; no native values)", idx);
}

void CpuidHandler::GetCpuidResultList(WHV_X64_CPUID_RESULT* results, int* count, int maxCount)
{
    BuildCpuidResultList(results, count, maxCount, 0x4000000F);
}

void CpuidHandler::GetComprehensiveCpuidResultList(WHV_X64_CPUID_RESULT* results, int* count, int maxCount)
{
    BuildCpuidResultList(results, count, maxCount, 0x400000FF);
}

bool CpuidHandler::Serialize(std::vector<uint8_t>& buffer) const
{
    uint32_t brandLen = (uint32_t)strnlen_s(m_brandString, sizeof(m_brandString));
    uint32_t enhBrandLen = (uint32_t)strnlen_s(m_enhancedBrand, sizeof(m_enhancedBrand));
    auto put32 = [&](uint32_t v) {
        buffer.insert(buffer.end(), (uint8_t*)&v, (uint8_t*)&v + 4);
    };
    put32(brandLen);
    buffer.insert(buffer.end(), (uint8_t*)m_brandString, (uint8_t*)m_brandString + brandLen);
    put32(enhBrandLen);
    buffer.insert(buffer.end(), (uint8_t*)m_enhancedBrand, (uint8_t*)m_enhancedBrand + enhBrandLen);
    uint32_t flags = (m_hasBrandString ? 1u : 0) | (m_hasEnhancedBrand ? 2u : 0);
    put32(flags);
    return true;
}

bool CpuidHandler::Deserialize(const uint8_t* data, size_t size)
{
    size_t offset = 0;
    auto read32 = [&]() -> uint32_t {
        if (offset + 4 > size) return 0;
        uint32_t v;
        memcpy(&v, data + offset, 4);
        offset += 4;
        return v;
    };
    if (size < 4) return false;
    uint32_t brandLen = read32();
    if (brandLen >= sizeof(m_brandString)) return false;
    if (offset + brandLen > size) return false;
    memcpy(m_brandString, data + offset, brandLen);
    m_brandString[brandLen] = 0;
    offset += brandLen;
    uint32_t enhBrandLen = read32();
    if (enhBrandLen >= sizeof(m_enhancedBrand)) return false;
    if (offset + enhBrandLen > size) return false;
    memcpy(m_enhancedBrand, data + offset, enhBrandLen);
    m_enhancedBrand[enhBrandLen] = 0;
    offset += enhBrandLen;
    uint32_t flags = read32();
    m_hasBrandString = (flags & 1) != 0;
    m_hasEnhancedBrand = (flags & 2) != 0;
    return true;
}
