#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <vector>

enum class CpuBackendType {
    WHP,
    UNICORN,
    ICICLE,
    NONE
};

enum class CpuReg {
    RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15,
    RIP, RFLAGS,
    CS, DS, ES, FS, GS, SS,
    CR0, CR2, CR3, CR4,
    DR0, DR1, DR2, DR3, DR6, DR7,
    COUNT
};

struct BreakpointInfo {
    uint64_t address;
    bool active;
    void* userData;
};

class ICpuBackend {
public:
    virtual ~ICpuBackend() = default;
    virtual CpuBackendType GetType() const = 0;
    virtual bool Initialize() = 0;
    virtual bool Run() = 0;
    virtual bool Stop() = 0;
    virtual bool SingleStep() = 0;
    virtual uint64_t ReadRegister(CpuReg reg) = 0;
    virtual bool WriteRegister(CpuReg reg, uint64_t value) = 0;
    virtual bool ReadMemory(uint64_t addr, void* buf, size_t size) = 0;
    virtual bool WriteMemory(uint64_t addr, const void* buf, size_t size) = 0;
    virtual uint64_t GetPhysicalAddress(uint64_t virtualAddr) = 0;
    virtual bool MapGuestMemory(uint64_t gpa, void* hostVa, size_t size, bool exec = true, bool write = true) = 0;
    virtual bool UnmapGuestMemory(uint64_t gpa, size_t size) = 0;
    virtual bool SetBreakpoint(uint64_t addr) = 0;
    virtual bool RemoveBreakpoint(uint64_t addr) = 0;
    virtual bool HasBreakpoint(uint64_t addr) const = 0;
    virtual bool IsRunning() const = 0;
    virtual uint64_t GetExitCount() const = 0;
    virtual uint64_t GetSyscallCount() const = 0;
    virtual bool SaveState(std::vector<uint8_t>& buffer) = 0;
    virtual bool RestoreState(const std::vector<uint8_t>& buffer) = 0;
};
