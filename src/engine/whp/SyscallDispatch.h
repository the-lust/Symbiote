#pragma once
#include <windows.h>
#include <cstdint>
#include <unordered_map>

struct ForwardEntry {
    void* funcPtr;
    int   argCount;
};

class SyscallDispatch {
public:
    SyscallDispatch();
    ~SyscallDispatch();

    bool Initialize();

    bool DispatchRawSyscall(uint32_t syscallNumber, uint64_t* args, uint64_t& result);
    bool ForwardSyscall(uint32_t syscallNumber, uint64_t* args, uint64_t guestRsp, uint64_t& result);
    bool SpoofRdmsr(uint32_t msrIndex, uint64_t& value);
    bool BuildForwardTable();

    uint32_t NtQuerySystemInformation;
    uint32_t NtQueryInformationProcess;
    uint32_t NtOpenKey;
    uint32_t NtOpenKeyEx;
    uint32_t NtQueryValueKey;
    uint32_t NtClose;
    uint32_t NtCreateFile;
    uint32_t NtQueryObject;
    uint32_t NtCreateThread;
    uint32_t NtCreateThreadEx;
    uint32_t NtTerminateThread;
    uint32_t NtQueryVirtualMemory; // P1.8: PE header reads
    uint32_t NtDeviceIoControlFile; // P2.9: for WHP hooking
    uint32_t NtQuerySystemTime; // P1.5: time source correlation

private:
    bool m_initialized = false;
    bool m_forwardBuilt = false;
    uint64_t m_kiSystemCall64 = 0;
    std::unordered_map<uint32_t, ForwardEntry> m_forwardTable;

    uint64_t ResolveKiSystemCall64();
    uint32_t GetSyscallNumber(const char* funcName);
    int GetArgCountForSyscall(const char* funcName);

    bool HandleNtQuerySystemInformation(uint64_t* args, uint64_t& result);
    bool HandleNtQueryInformationProcess(uint64_t* args, uint64_t& result);
    bool HandleNtOpenKey(uint64_t* args, uint64_t& result);
    bool HandleNtQueryValueKey(uint64_t* args, uint64_t& result);
    bool HandleNtClose(uint64_t* args, uint64_t& result);
    bool HandleNtCreateFile(uint64_t* args, uint64_t& result);
    bool HandleNtQueryVirtualMemory(uint64_t* args, uint64_t& result); // P1.8
    bool HandleNtQuerySystemTime(uint64_t* args, uint64_t& result); // P1.5
};
