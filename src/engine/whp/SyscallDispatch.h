#pragma once
#include <windows.h>
#include <cstdint>
#include <unordered_map>

// Dynamic syscall number detection + spoof dispatching for WHP #BP handler.
// On each Windows build, syscall numbers change. We read them from ntdll
// at runtime to remain build-independent.

struct ForwardEntry {
    void* funcPtr;       // Address of real ntdll function
    int   argCount;      // Number of arguments (for stack arg forwarding)
};

class SyscallDispatch {
public:
    SyscallDispatch();
    ~SyscallDispatch();

    bool Initialize();

    // Dispatch a raw syscall (called from VcpuManager #BP handler)
    bool DispatchRawSyscall(uint32_t syscallNumber, uint64_t* args, uint64_t& result);

    // Forward an unhandled syscall to host ntdll
    bool ForwardSyscall(uint32_t syscallNumber, uint64_t* args, uint64_t guestRsp, uint64_t& result);

    // Get the spoofed MSR value for a raw RDMSR instruction
    bool SpoofRdmsr(uint32_t msrIndex, uint64_t& value);

    // Build the forward table from host ntdll exports
    bool BuildForwardTable();

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
    bool m_forwardBuilt = false;
    std::unordered_map<uint32_t, ForwardEntry> m_forwardTable;

    uint32_t GetSyscallNumber(const char* funcName);
    int GetArgCountForSyscall(const char* funcName);

    bool HandleNtQuerySystemInformation(uint64_t* args, uint64_t& result);
    bool HandleNtQueryInformationProcess(uint64_t* args, uint64_t& result);
    bool HandleNtOpenKey(uint64_t* args, uint64_t& result);
    bool HandleNtQueryValueKey(uint64_t* args, uint64_t& result);
    bool HandleNtClose(uint64_t* args, uint64_t& result);
    bool HandleNtCreateFile(uint64_t* args, uint64_t& result);
};
