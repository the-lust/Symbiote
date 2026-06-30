#pragma once
#include <windows.h>
#include <cstdint>

// Dynamic syscall number detection + spoof dispatching for WHP #BP handler.
// On each Windows build, syscall numbers change. We read them from ntdll
// at runtime to remain build-independent.

class SyscallDispatch {
public:
    SyscallDispatch();
    ~SyscallDispatch();

    // Read syscall numbers from ntdll for all functions we need
    bool Initialize();

    // Dispatch a raw syscall (called from VcpuManager #BP handler)
    // Returns true if handled (RAX already contains result), false if passthrough needed
    bool DispatchRawSyscall(uint32_t syscallNumber, uint64_t* args, uint64_t& result);

    // Get the spoofed MSR value for a raw RDMSR instruction
    bool SpoofRdmsr(uint32_t msrIndex, uint64_t& value);

    // Syscall numbers detected from ntdll
    uint32_t NtQuerySystemInformation;
    uint32_t NtQueryInformationProcess;
    uint32_t NtOpenKey;
    uint32_t NtQueryValueKey;
    uint32_t NtClose;
    uint32_t NtCreateFile;
    uint32_t NtQueryObject;

private:
    bool m_initialized = false;

    // Read a single syscall number from ntdll export
    static uint32_t GetSyscallNumber(const char* funcName);

    // Spoof handlers for specific syscalls
    bool HandleNtQuerySystemInformation(uint64_t* args, uint64_t& result);
    bool HandleNtQueryInformationProcess(uint64_t* args, uint64_t& result);
    bool HandleNtOpenKey(uint64_t* args, uint64_t& result);
    bool HandleNtQueryValueKey(uint64_t* args, uint64_t& result);
    bool HandleNtClose(uint64_t* args, uint64_t& result);
    bool HandleNtCreateFile(uint64_t* args, uint64_t& result);
};
