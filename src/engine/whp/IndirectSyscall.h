#pragma once
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include "Logger.h"

#pragma comment(lib, "psapi.lib")

class EptExecHook;

class IndirectSyscall {
public:
    explicit IndirectSyscall(Logger* logger);
    ~IndirectSyscall();

    bool Initialize(EptExecHook* eptHook);
    void Shutdown();

    bool IsInitialized() const { return m_initialized; }
    bool IsHookActive() const { return m_hookRegistered; }
    uint64_t GetSyscallPageGpa() const { return m_syscallPageGpa; }

    // Static callback for EPT exec hook
    static void SyscallPageCallback(uint64_t gpa, uint64_t rip);

private:
    static IndirectSyscall* s_instance;

    Logger* m_logger;
    bool m_initialized;
    EptExecHook* m_eptHook;

    uint64_t m_syscallPageGpa;
    void* m_syscallPageVa;
    bool m_hookRegistered;

    bool FindSyscallPage();
};
