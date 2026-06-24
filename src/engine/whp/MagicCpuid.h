#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

class MagicCpuid {
public:
    explicit     MagicCpuid(Logger* logger);

    bool IsMagicCpuid(uint32_t leaf, uint32_t subleaf, uint64_t rax, uint64_t rbx,
                       uint64_t rcx, uint64_t rdx) const;

    bool HandleMagicCpuid(uint32_t leaf, uint32_t subleaf, uint64_t* rax, uint64_t* rbx,
                          uint64_t* rcx, uint64_t* rdx, uint64_t* rip, WHV_VP_EXIT_CONTEXT* ctx);

    bool ShouldQuit() const { return m_quitRequested; }
    void ClearQuit() { m_quitRequested = false; }

    void SetGuestPhysicalAddress(uint64_t gpa) { m_guestGpa = gpa; }
    uint64_t GetGuestPhysicalAddress() const { return m_guestGpa; }

    // Per-process tracking
    uint64_t GetTargetPid() const { return m_targetPid; }
    uint64_t GetSyscallHandler() const { return m_syscallHandler; }
    bool IsEnhancedMode() const { return m_enhancedMode; }
    bool HasTargetPid() const { return m_targetPid != 0; }

    // Shared memory for handshake state
    uint64_t GetSharedMemoryGpa() const { return m_sharedMemoryGpa; }

    // debug leaves (reserved)
    static const uint32_t MAGIC_CPUID_LEAF     = 0x69696969;
    static const uint32_t MAGIC_CPUID_SUBLEAF  = 0x1337;
    static const uint32_t MAGIC_GET_GPA        = 0x33690001;
    static const uint32_t MAGIC_SET_GPA        = 0x33690002;
    static const uint32_t MAGIC_QUIT           = 0x41414141;

    // Enhanced handshake leaves
    static const uint32_t MAGIC_REGISTER_PID   = 0x00001337;
    static const uint32_t MAGIC_REGISTER_SYSCALL = 0x00336933;
    static const uint32_t MAGIC_GET_SYSCALL_HANDLER = 0x00336934;
    static const uint32_t MAGIC_ENHANCED_MODE   = 0xDEADBEEF;
    static const uint32_t MAGIC_SET_SHM         = 0x33690003;
    static const uint32_t MAGIC_GET_SHM         = 0x33690004;

private:
    Logger* m_logger;
    uint64_t m_guestGpa;
    bool m_quitRequested = false;

    // Enhanced state
    uint64_t m_targetPid = 0;
    uint64_t m_syscallHandler = 0;
    bool m_enhancedMode = false;
    uint64_t m_sharedMemoryGpa = 0;
};
