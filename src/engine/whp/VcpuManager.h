#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"
#include "CpuidHandler.h"
#include "SystemSpoofer.h"
#include "SyscallDispatch.h"
#include "EptExecHook.h"
#include "KernelLock.h"
#include <unordered_map>

class Partition;
class ExitDispatcher;
class RdtscHandler;
class MsrHandler;
class MagicCpuid;
class ExceptionHandler;
class GuestPageTable;
using SyscallHandler = bool(uint64_t syscallNumber, uint64_t* args, uint64_t* result);

struct ThreadContext {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint16_t cs, ds, es, fs, gs, ss;
};

class VcpuManager {
public:
    VcpuManager(Logger* logger, Partition* partition, ExitDispatcher* exitDispatcher,
                CpuidHandler* cpuidHandler, RdtscHandler* rdtscHandler,
                MsrHandler* msrHandler);
    ~VcpuManager();

    bool CreateVcpu(uint32_t vcpuIndex);
    bool Run(uint32_t vcpuIndex);
    void Stop(uint32_t vcpuIndex);

    // Ghost Sandbox: bootstrap VCPU from captured thread context
    bool BootstrapFromContext(uint32_t vcpuIndex, const ThreadContext& ctx, GuestPageTable* pageTable);

    void SetMagicCpuid(MagicCpuid* magic) {
        m_magicCpuid = magic;
        if (m_cpuidHandler) {
            m_cpuidHandler->SetMagicCpuid(magic);
        }
    }
    void SetSyscallHandler(SyscallHandler* handler) { m_syscallHandler = handler; }
    void SetExceptionHandler(ExceptionHandler* handler) { m_exceptionHandler = handler; }

    // Multi-VCPU child thread migration
    void SetChildThreadMigrationEnabled(bool enabled) { m_childThreadMigrationEnabled = enabled; }

    // EPT-based execution hooks (single-step mechanism)
    void SetEptExecHook(EptExecHook* hook) { m_eptExecHook = hook; }
    EptExecHook* GetEptExecHook() const { return m_eptExecHook; }

    // BEL (Big Emulator Lock) — serializes all C++ handler code
    KernelLock* GetKernelLock() { return &m_kernelLock; }

    // Singleton access for ThreadBootstrapEntry (static thread proc)
    static VcpuManager* GetInstance() { return s_instance; }

    static VcpuManager* s_instance;

private:
    bool SetupRegisters(uint32_t vcpuIndex);
    bool HandleExit(uint32_t vcpuIndex);
    bool LoadBootCode(uint32_t vcpuIndex);
    bool SetupSegmentRegisters(uint32_t vcpuIndex);
    bool SetupControlRegisters(uint32_t vcpuIndex);

    void SetContextRegisters(uint32_t vcpuIndex, const ThreadContext& ctx, GuestPageTable* pageTable);

    // LSTAR->HLT syscall interception
    bool LoadHltPage();
    bool SetupLstarMsrs(uint32_t vcpuIndex);
    bool HandleSyscallExit(uint32_t vcpuIndex);
    uint64_t m_hltPageGpa = 0;

    // Multi-VCPU: child thread management
    thread_local static uint32_t t_currentVcpuIndex;
    CRITICAL_SECTION m_vcpuAllocLock;
    std::unordered_map<HANDLE, uint32_t> m_threadHandleToVcpu;
    bool m_childThreadMigrationEnabled;

    uint32_t AllocateVcpuIndex();
    void FreeVcpuIndex(uint32_t index);
    bool SetupChildVcpuContext(uint32_t vcpuIndex, const ThreadContext& ctx);
    bool HandleCreateThreadSyscall(uint32_t vcpuIndex, uint32_t syscallNum, uint64_t* regArgs, uint64_t guestRsp, uint64_t& result);
    bool HandleTerminateThreadSyscall(uint32_t vcpuIndex, uint64_t* args, uint64_t& result);
    static DWORD WINAPI ThreadBootstrapEntry(LPVOID param);
    void EnterVcpuFromBootstrap(uint32_t vcpuIndex);

    // WHP #BP/#DB exception handling
    bool HandleVpBreakpoint(uint32_t vcpuIndex, uint64_t rip);
    bool HandleVpSingleStep(uint32_t vcpuIndex, uint64_t rip);

    bool ReadVcpuRegs(uint32_t vcpuIndex, WHV_REGISTER_NAME* names, WHV_REGISTER_VALUE* values, uint32_t count);
    bool WriteVcpuRegs(uint32_t vcpuIndex, WHV_REGISTER_NAME* names, WHV_REGISTER_VALUE* values, uint32_t count);

    struct TrampolineEntry {
        uint64_t address;
        uint8_t  originalByte;
        uint8_t  instrLen;
    };
    std::unordered_map<uint64_t, TrampolineEntry> m_trampolines;

    Logger* m_logger;
    Partition* m_partition;
    ExitDispatcher* m_exitDispatcher;
    CpuidHandler* m_cpuidHandler;
    RdtscHandler* m_rdtscHandler;
    MsrHandler* m_msrHandler;
    MagicCpuid* m_magicCpuid;
    SyscallHandler* m_syscallHandler;
    ExceptionHandler* m_exceptionHandler;
    SyscallDispatch m_syscallDispatch;
    KernelLock m_kernelLock;
    EptExecHook* m_eptExecHook = nullptr;

    // Per-VCPU GDTs — each VCPU gets its own GDT at a unique GPA so that
    // WOW64 threads on different VCPUs don't share FS-segment bases
    static constexpr uint64_t PER_VCPU_GDT_BASE = 0x200000;
    static constexpr uint32_t PER_VCPU_GDT_SIZE = 0x1000;
    bool SetupPerVcpuGdt(uint32_t vcpuIndex);

    struct VcpuContext {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;
        uint8_t* stack;
        uint8_t* allocatedStack;
        bool running;
        HANDLE hostThread;
        uint64_t lastSyncTsc;
        uint64_t timingGeneration;
    };

    static const uint32_t MAX_VCPU = 20;
    VcpuContext m_vcpus[MAX_VCPU];
    uint32_t m_vcpuCount;
    bool m_bootCodeLoaded;
};
