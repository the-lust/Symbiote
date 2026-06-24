#include "CpuidHandler.h"
#include "kernel/IKernelBackend.h"
#include "MagicCpuid.h"
#include "TimingCoordinator.h"
#include <cstring>
#include <intrin.h>

// Mask bits for leaf 1 ECX
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
      m_timingCoordinator(nullptr),
      m_hasBrandString(false), m_hasEnhancedBrand(false)
{
    srand((unsigned int)GetCurrentProcessId() ^ (unsigned int)GetTickCount64());
    m_brandString[0] = 0;
    m_enhancedBrand[0] = 0;
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

bool CpuidHandler::HandleBrandStringLeaf(uint32_t leaf, uint64_t* rax, uint64_t* rbx,
                                          uint64_t* rcx, uint64_t* rdx)
{
    // Leaves 0x80000002-0x80000004: 48-byte processor brand string
    if (leaf < 0x80000002 || leaf > 0x80000004)
        return false;

    // Determine active brand string (enhanced mode takes priority)
    const char* brand = m_brandString;
    if (m_magicCpuid && m_magicCpuid->IsEnhancedMode() && m_hasEnhancedBrand) {
        brand = m_enhancedBrand;
    }

    if (!brand || brand[0] == 0)
        return false;

    // Each leaf returns 16 bytes in EAX,EBX,ECX,EDX
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

    // Clear hypervisor present bit + SMX/TXT bit in leaf 1 ECX
    if (leaf == 1) {
        *rcx &= ~CPUID_ECX_HYPERVISOR_BIT;
        *rcx &= ~CPUID_ECX_SMX_BIT;
    }

    m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => %s: RAX=0x%08llX RBX=0x%08llX RCX=0x%08llX RDX=0x%08llX",
        leaf, subleaf, spoofed ? "SPOOFED" : "PASSTHROUGH", *rax, *rbx, *rcx, *rdx);

    return true;
}
