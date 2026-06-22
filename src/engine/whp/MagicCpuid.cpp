#include "MagicCpuid.h"
#include <cstring>

MagicCpuid::MagicCpuid(Logger* logger)
    : m_logger(logger), m_guestGpa(0)
{
}

bool MagicCpuid::IsMagicCpuid(uint32_t leaf, uint32_t subleaf, uint64_t rax, uint64_t rbx,
                               uint64_t rcx, uint64_t rdx) const
{
    if (leaf == MAGIC_CPUID_LEAF && subleaf == MAGIC_CPUID_SUBLEAF)
        return true;

    if (leaf >= 0x33690000 && leaf <= 0x3369FFFF)
        return true;

    if (leaf == MAGIC_QUIT)
        return true;

    return false;
}

bool MagicCpuid::HandleMagicCpuid(uint32_t leaf, uint32_t subleaf, uint64_t* rax, uint64_t* rbx,
                                   uint64_t* rcx, uint64_t* rdx, uint64_t* rip, WHV_VP_EXIT_CONTEXT* ctx)
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
            m_logger->Trace(LOG_INFO, "Magic QUIT received");
            *rax = 0;
            *rbx = 0;
            *rcx = 0;
            *rdx = 0;
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
