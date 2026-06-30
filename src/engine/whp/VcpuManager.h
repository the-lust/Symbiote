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
using SyscallHandler = bool(uint64_t syscallNumber, uint64_t* args, uint64_t* result);

class VcpuManager {
public:
    VcpuManager(Logger* logger, Partition* partition, ExitDispatcher* exitDispatcher,
                CpuidHandler* cpuidHandler, RdtscHandler* rdtscHandler,
                MsrHandler* msrHandler);
    ~VcpuManager();

    bool CreateVcpu(uint32_t vcpuIndex);
    bool Run(uint32_t vcpuIndex);
    void Stop(uint32_t vcpuIndex);

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

    // WHP #BP/#DB exception handling for guest-side syscall/RDMSR intercept
    bool HandleVpBreakpoint(uint32_t vcpuIndex, uint64_t rip);
    bool HandleVpSingleStep(uint32_t vcpuIndex, uint64_t rip);

    // Read/write VCPU registers from WHP
    bool ReadVcpuRegs(uint32_t vcpuIndex, WHV_REGISTER_NAME* names, WHV_REGISTER_VALUE* values, uint32_t count);
    bool WriteVcpuRegs(uint32_t vcpuIndex, WHV_REGISTER_NAME* names, WHV_REGISTER_VALUE* values, uint32_t count);

    // Trampoline for non-spoofed patched instructions
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
