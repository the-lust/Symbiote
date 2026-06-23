#include "CpuidHandler.h"
#include "kernel/IKernelBackend.h"

CpuidHandler::CpuidHandler(Logger* logger, IKernelBackend* backend)
    : m_logger(logger), m_backend(backend)
{
}

CpuidHandler::~CpuidHandler()
{
}

bool CpuidHandler::HandleCpuid(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rbx,
                                uint64_t* rcx, uint64_t* rdx, uint64_t* rip)
{
    uint32_t leaf = (uint32_t)(*rax);
    uint32_t subleaf = (uint32_t)(*rcx);

    // hide hypervisor leaves
    if (leaf >= 0x40000000 && leaf <= 0x4000FFFF) {
        *rax = 0;
        *rbx = 0;
        *rcx = 0;
        *rdx = 0;
        m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => HIDDEN (hypervisor)", leaf, subleaf);
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

    m_logger->Trace(LOG_CPUID, "CPUID leaf=0x%X subleaf=0x%X => %s: RAX=0x%08llX RBX=0x%08llX RCX=0x%08llX RDX=0x%08llX",
        leaf, subleaf, spoofed ? "SPOOFED" : "PASSTHROUGH", *rax, *rbx, *rcx, *rdx);

    return true;
}
