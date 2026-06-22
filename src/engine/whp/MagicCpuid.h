#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

class MagicCpuid {
public:
    explicit MagicCpuid(Logger* logger);

    bool IsMagicCpuid(uint32_t leaf, uint32_t subleaf, uint64_t rax, uint64_t rbx,
                       uint64_t rcx, uint64_t rdx) const;

    bool HandleMagicCpuid(uint32_t leaf, uint32_t subleaf, uint64_t* rax, uint64_t* rbx,
                          uint64_t* rcx, uint64_t* rdx, uint64_t* rip, WHV_VP_EXIT_CONTEXT* ctx);

    void SetGuestPhysicalAddress(uint64_t gpa) { m_guestGpa = gpa; }
    uint64_t GetGuestPhysicalAddress() const { return m_guestGpa; }

    // debug leaves (reserved)
    static const uint32_t MAGIC_CPUID_LEAF     = 0x69696969;
    static const uint32_t MAGIC_CPUID_SUBLEAF  = 0x1337;
    static const uint32_t MAGIC_GET_GPA        = 0x33690001;
    static const uint32_t MAGIC_SET_GPA        = 0x33690002;
    static const uint32_t MAGIC_QUIT           = 0x41414141;

private:
    Logger* m_logger;
    uint64_t m_guestGpa;
};
