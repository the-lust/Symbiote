#pragma once
#include "ICpuBackend.h"
#include "Logger.h"
#include <unordered_map>
#include <vector>

class UnicornBackend : public ICpuBackend {
public:
    explicit UnicornBackend(Logger* logger);
    ~UnicornBackend();

    CpuBackendType GetType() const override { return CpuBackendType::UNICORN; }
    bool Initialize() override;
    bool Run() override;
    bool Stop() override;
    bool SingleStep() override;
    uint64_t ReadRegister(CpuReg reg) override;
    bool WriteRegister(CpuReg reg, uint64_t value) override;
    bool ReadMemory(uint64_t addr, void* buf, size_t size) override;
    bool WriteMemory(uint64_t addr, const void* buf, size_t size) override;
    uint64_t GetPhysicalAddress(uint64_t virtualAddr) override;
    bool MapGuestMemory(uint64_t gpa, void* hostVa, size_t size, bool exec, bool write) override;
    bool UnmapGuestMemory(uint64_t gpa, size_t size) override;
    bool SetBreakpoint(uint64_t addr) override;
    bool RemoveBreakpoint(uint64_t addr) override;
    bool HasBreakpoint(uint64_t addr) const override;
    bool IsRunning() const override;
    uint64_t GetExitCount() const override;
    uint64_t GetSyscallCount() const override;
    bool SaveState(std::vector<uint8_t>& buffer) override;
    bool RestoreState(const std::vector<uint8_t>& buffer) override;

private:
    Logger* m_logger;
    void* m_ucEngine;
    uint64_t m_exitCount;
    uint64_t m_syscallCount;
    bool m_running;
    bool m_unicornAvailable;
    std::unordered_map<uint64_t, bool> m_breakpoints;

    static void HookCodeCallback(void* uc, uint64_t address, uint32_t size, void* userData);
    static void HookMemCallback(void* uc, uint64_t address, uint32_t size, void* userData);
};
