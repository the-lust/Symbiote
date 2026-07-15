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

static void JitterDelay()
{
    LARGE_INTEGER freq, start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    uint64_t delayUs = (uint64_t)((double)rand() / RAND_MAX * 500.0);
    uint64_t target = (uint64_t)start.QuadPart + (delayUs * (uint64_t)freq.QuadPart) / 1000000;
    do {
        QueryPerformanceCounter(&now);
    } while ((uint64_t)now.QuadPart < target);
}

CpuidHandler::CpuidHandler(Logger* logger, IKernelBackend* backend)
    : m_logger(logger), m_backend(backend), m_magicCpuid(nullptr),
      m_timingCoordinator(nullptr), m_captureLogger(nullptr),
      m_hasBrandString(false), m_hasEnhancedBrand(false)
{
    srand((unsigned int)GetCurrentProcessId() ^ (unsigned int)GetTickCount64());
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
    // Apply VM exit timing jitter to mask hypervisor presence
    JitterDelay();

    uint32_t leaf = (uint32_t)(*rax);
    uint32_t subleaf = (uint32_t)(*rcx);

    // Notify timing coordinator to detect RDTSC→CPUID→RDTSC patterns
    if (m_timingCoordinator) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        m_timingCoordinator->DetectCpuidAfterRdtsc(leaf, (uint64_t)now.QuadPart);
    }

    // Per-process tracking: if a target PID is registered, only spoof for that process
    if (m_magicCpuid && m_magicCpuid->HasTargetPid()) {
        uint64_t currentPid = (uint64_t)GetCurrentProcessId();
        if (currentPid != m_magicCpuid->GetTargetPid()) {
            // Not the target process - pass through without spoofing
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

    // hide hypervisor leaves
    if (leaf >= 0x40000000 && leaf <= 0x4000FFFF) {
        *rax = 0;
        *rbx = 0;
        *rcx = 0;
        *rdx = 0;
        m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => HIDDEN (hypervisor)", leaf, subleaf);
        return true;
    }

    // Brand string leaves (0x80000002-0x80000004)
    if (HandleBrandStringLeaf(leaf, rax, rbx, rcx, rdx)) {
        m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X => BRAND: RAX=0x%08llX RBX=0x%08llX RCX=0x%08llX RDX=0x%08llX",
            leaf, *rax, *rbx, *rcx, *rdx);
        return true;
    }

    bool spoofed = false;
    CpuidResult result;

    if (m_backend && m_backend->HandleCpuid(leaf, subleaf, result)) {
        *rax = result.eax;
        *rbx = result.ebx;
        *rcx = result.ecx;
        *rdx = result.edx;
        spoofed = true;
    } else {
        int cpuInfo[4] = {0};
        __cpuidex(cpuInfo, leaf, subleaf);
        *rax = (uint32_t)cpuInfo[0];
        *rbx = (uint32_t)cpuInfo[1];
        *rcx = (uint32_t)cpuInfo[2];
        *rdx = (uint32_t)cpuInfo[3];
    }

    // Apply universal feature masking to hide host-specific CPU features
    ApplyUniversalMask(leaf, subleaf, rax, rbx, rcx, rdx);

    // Clear hypervisor present bit + SMX/TXT bit in leaf 1 ECX
    // BOTH bits must be cleared: hypervisor present is the most detectable,
    // SMX/TXT is a secondary indicator of virtualized environment.
    if (leaf == 1) {
        *rcx &= ~CPUID_ECX_HYPERVISOR_BIT;
        *rcx &= ~CPUID_ECX_SMX_BIT;
    }

    // Capture to fingerprint log
    if (m_captureLogger) {
        m_captureLogger->CaptureCpuid(leaf, subleaf, 0,
            (uint32_t)*rax, (uint32_t)*rbx, (uint32_t)*rcx, (uint32_t)*rdx);
    }

    m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => %s: RAX=0x%08llX RBX=0x%08llX RCX=0x%08llX RDX=0x%08llX",
        leaf, subleaf, spoofed ? "SPOOFED" : "PASSTHROUGH", *rax, *rbx, *rcx, *rdx);

    return true;
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

void CpuidHandler::GetCpuidResultList(WHV_X64_CPUID_RESULT* results, int* count, int maxCount)
{
    int idx = 0;

    // WHP CPUID result list pre-populates known spoof values so WHP
    // doesn't need to VM-exit for these leaves (from libkrun pattern).
    auto add = [&](uint32_t leaf, uint32_t, uint32_t eax,
                   uint32_t ebx, uint32_t ecx, uint32_t edx) {
        if (idx >= maxCount) return;
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

    // Leaf 0: Vendor string + max leaf
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 0, 0);
    uint32_t maxLeaf = (uint32_t)cpuInfo[0];
    add(0, 0, maxLeaf, 0x756E6547, 0x6C65746E, 0x49656E69); // "GenuineIntel"

    // Leaf 1: Feature info — use spoofed from backend or generic Haswell-like
    CpuidResult cr;
    if (m_backend && m_backend->HandleCpuid(1, 0, cr)) {
        uint32_t ecx1 = cr.ecx & ~CPUID_ECX_HYPERVISOR_BIT;
        ApplyFeatureMask(1, 0, m_cpuVendor, &cr.eax, &cr.ebx, &ecx1, &cr.edx);
        add(1, 0, cr.eax, cr.ebx, ecx1, cr.edx);
    } else {
        __cpuidex(cpuInfo, 1, 0);
        uint32_t eax1 = (uint32_t)cpuInfo[0], ebx1 = (uint32_t)cpuInfo[1];
        uint32_t ecx1 = (uint32_t)cpuInfo[2] & ~CPUID_ECX_HYPERVISOR_BIT;
        uint32_t edx1 = (uint32_t)cpuInfo[3];
        ApplyFeatureMask(1, 0, m_cpuVendor, &eax1, &ebx1, &ecx1, &edx1);
        add(1, 0, eax1, ebx1, ecx1, edx1);
    }

    // Leaf 7 subleaf 0: Structured extended features — masked
    CpuidResult cr7;
    if (m_backend && m_backend->HandleCpuid(7, 0, cr7)) {
        ApplyFeatureMask(7, 0, m_cpuVendor, &cr7.eax, &cr7.ebx, &cr7.ecx, &cr7.edx);
        add(7, 0, cr7.eax, cr7.ebx, cr7.ecx, cr7.edx);
    } else {
        __cpuidex(cpuInfo, 7, 0);
        uint32_t eax7 = (uint32_t)cpuInfo[0];
        uint32_t ebx7 = (uint32_t)cpuInfo[1];
        uint32_t ecx7 = (uint32_t)cpuInfo[2];
        uint32_t edx7 = (uint32_t)cpuInfo[3];
        ApplyFeatureMask(7, 0, m_cpuVendor, &eax7, &ebx7, &ecx7, &edx7);
        add(7, 0, eax7, ebx7, ecx7, edx7);
    }

    // Leaf 0xA: PMU — zeroed
    add(0xA, 0, 0, 0, 0, 0);

    // Leaves 0x80000000-0x80000008 (extended): spoofed from backend or generic
    if (m_backend && m_backend->HandleCpuid(0x80000000, 0, cr)) {
        add(0x80000000, 0, cr.eax, cr.ebx, cr.ecx, cr.edx);
    } else {
        __cpuidex(cpuInfo, 0x80000000, 0);
        add(0x80000000, 0, (uint32_t)cpuInfo[0], (uint32_t)cpuInfo[1], (uint32_t)cpuInfo[2], (uint32_t)cpuInfo[3]);
    }
    if (m_backend && m_backend->HandleCpuid(0x80000001, 0, cr)) {
        uint32_t ecxEx = cr.ecx, edxEx = cr.edx;
        ApplyFeatureMask(0x80000001, 0, m_cpuVendor, &cr.eax, &cr.ebx, &ecxEx, &edxEx);
        add(0x80000001, 0, cr.eax, cr.ebx, ecxEx, edxEx);
    } else {
        __cpuidex(cpuInfo, 0x80000001, 0);
        uint32_t eaxEx = (uint32_t)cpuInfo[0], ebxEx = (uint32_t)cpuInfo[1];
        uint32_t ecxEx = (uint32_t)cpuInfo[2], edxEx = (uint32_t)cpuInfo[3];
        ApplyFeatureMask(0x80000001, 0, m_cpuVendor, &eaxEx, &ebxEx, &ecxEx, &edxEx);
        add(0x80000001, 0, eaxEx, ebxEx, ecxEx, edxEx);
    }

    // Brand string leaves — populated from our brand string or auto-generated
    if (m_hasBrandString) {
        for (uint32_t lf = 0x80000002; lf <= 0x80000004; lf++) {
            uint64_t ra, rb, rc, rd;
            HandleBrandStringLeaf(lf, &ra, &rb, &rc, &rd);
            add(lf, 0, (uint32_t)ra, (uint32_t)rb, (uint32_t)rc, (uint32_t)rd);
        }
    }

    // Hypervisor leaves 0x40000000-0x40000006: hidden (all zeros)
    for (uint32_t lf = 0x40000000; lf <= 0x40000006; lf++) {
        add(lf, 0, 0, 0, 0, 0);
    }

    *count = idx;
    m_logger->Trace(LOG_WHP, "CpuidResultList populated: %d leaves (WHP exits only for unlisted leaves)", idx);
}
