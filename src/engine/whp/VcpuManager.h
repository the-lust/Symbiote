#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"
#include "CpuidHandler.h"
#include "SystemSpoofer.h"
#include "SyscallDispatch.h"
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

    struct VcpuContext {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;
        uint8_t* stack;
        bool running;
    };

    static const uint32_t MAX_VCPU = 20;
    VcpuContext m_vcpus[MAX_VCPU];
    uint32_t m_vcpuCount;
    bool m_bootCodeLoaded;
};
