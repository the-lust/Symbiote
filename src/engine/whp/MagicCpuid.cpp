#include "MagicCpuid.h"
#include <cstring>

MagicCpuid::MagicCpuid(Logger* logger)
    : m_logger(logger), m_guestGpa(0)
{
}

bool MagicCpuid::IsMagicCpuid(uint32_t leaf, uint32_t subleaf, uint64_t, uint64_t,
                               uint64_t, uint64_t) const
{
    if (leaf == MAGIC_CPUID_LEAF && subleaf == MAGIC_CPUID_SUBLEAF)
        return true;

    if (leaf >= 0x33690000 && leaf <= 0x3369FFFF)
        return true;

    if (leaf == MAGIC_QUIT)
        return true;

    // Enhanced handshake leaves
    if (leaf == MAGIC_REGISTER_PID)
        return true;
    if (leaf == MAGIC_REGISTER_SYSCALL)
        return true;
    if (leaf == MAGIC_GET_SYSCALL_HANDLER)
        return true;
    if (leaf == MAGIC_ENHANCED_MODE)
        return true;

    return false;
}

bool MagicCpuid::HandleMagicCpuid(uint32_t leaf, uint32_t subleaf, uint64_t* rax, uint64_t* rbx,
                                   uint64_t* rcx, uint64_t* rdx, uint64_t*, WHV_VP_EXIT_CONTEXT*)
{
    m_logger->Trace(LOG_WHP, "Magic CPUID leaf=0x%X subleaf=0x%X", leaf, subleaf);

    switch (leaf) {
        case MAGIC_CPUID_LEAF:
            *rax = 0x48796148;
            *rbx = 0x6C756F48;
            *rcx = 0x00000000;
            *rdx = 0x00000000;
            m_logger->Trace(LOG_INFO, "Magic CPUID ACK");
            return true;

        case MAGIC_GET_GPA:
            *rax = m_guestGpa;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            m_logger->Trace(LOG_INFO, "Magic get GPA: 0x%llX", m_guestGpa);
            return true;

        case MAGIC_SET_GPA:
            m_guestGpa = *rax;
            *rax = 0;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            m_logger->Trace(LOG_INFO, "Magic set GPA to 0x%llX", m_guestGpa);
            return true;

        case MAGIC_QUIT:
            m_logger->Trace(LOG_INFO, "Magic QUIT received - stopping VCPU");
            *rax = 0;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            m_quitRequested = true;
            return true;

        // REGISTER_PID: target announces itself with its PID in RDX
        case MAGIC_REGISTER_PID:
            m_targetPid = *rdx;
            m_logger->Trace(LOG_INFO, "Magic REGISTER_PID: target PID=%llu", m_targetPid);
            *rax = m_targetPid;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            return true;

        // REGISTER_SYSCALL: target registers its syscall handler base in RCX
        case MAGIC_REGISTER_SYSCALL:
            m_syscallHandler = *rcx;
            m_logger->Trace(LOG_INFO, "Magic REGISTER_SYSCALL: handler=0x%llX", m_syscallHandler);
            *rax = m_syscallHandler;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            return true;

        // GET_SYSCALL_HANDLER: return previously registered syscall handler address
        case MAGIC_GET_SYSCALL_HANDLER:
            *rax = m_syscallHandler;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            m_logger->Trace(LOG_INFO, "Magic GET_SYSCALL_HANDLER: 0x%llX", m_syscallHandler);
            return true;

        // ENHANCED_MODE: toggle enhanced CPUID/profile spoofing
        case MAGIC_ENHANCED_MODE:
            m_enhancedMode = (subleaf != 0);
            m_logger->Trace(LOG_INFO, "Magic ENHANCED_MODE: %s (subleaf=0x%X)",
                m_enhancedMode ? "ON" : "OFF", subleaf);
            *rax = m_enhancedMode ? 1 : 0;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            return true;

        // SET_SHM: register shared memory GPA for handshake state exchange
        case MAGIC_SET_SHM:
            m_sharedMemoryGpa = *rax;
            m_logger->Trace(LOG_INFO, "Magic SET_SHM: GPA=0x%llX", m_sharedMemoryGpa);
            *rax = 0;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            return true;

        // GET_SHM: return registered shared memory GPA
        case MAGIC_GET_SHM:
            *rax = m_sharedMemoryGpa;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            m_logger->Trace(LOG_INFO, "Magic GET_SHM: GPA=0x%llX", m_sharedMemoryGpa);
            return true;

        default:
            m_logger->Trace(LOG_WARNING, "Unknown magic leaf 0x%X", leaf);
            *rax = 0;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
            return true;
    }
}
