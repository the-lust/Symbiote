#pragma once
#include "ICpuBackend.h"
#include "Logger.h"

class Partition;
class VcpuManager;
class ExitDispatcher;
class CpuidHandler;
class RdtscHandler;
class MsrHandler;
class MagicCpuid;
class ExceptionHandler;
class EptExecHook;
class EptSplitView;
class GuestPageTable;
class KernelLock;

class WhpBackend : public ICpuBackend {
public:
    WhpBackend(Logger* logger);
    ~WhpBackend();

    CpuBackendType GetType() const override { return CpuBackendType::WHP; }
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

    Partition* GetPartition() const { return m_partition; }
    VcpuManager* GetVcpuManager() const { return m_vcpuManager; }
    void WireHandlers(CpuidHandler* cpuid, RdtscHandler* rdtsc, MsrHandler* msr,
                      MagicCpuid* magic, ExceptionHandler* exc, EptExecHook* eptExec,
                      EptSplitView* eptSplit, KernelLock* kernelLock);

private:
    Logger* m_logger;
    Partition* m_partition;
    VcpuManager* m_vcpuManager;
    ExitDispatcher* m_exitDispatcher;
    uint32_t m_vcpuIndex;
    uint64_t m_exitCount;
    uint64_t m_syscallCount;
    bool m_running;
};
