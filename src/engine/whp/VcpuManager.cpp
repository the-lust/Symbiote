#include "VcpuManager.h"
#include "Partition.h"
#include "GuestPageTable.h"
#include "ExitDispatcher.h"
#include "CpuidHandler.h"
#include "RdtscHandler.h"
#include "MsrHandler.h"
#include "MagicCpuid.h"
#include "ExceptionHandler.h"
#include "TimingCoordinator.h"
#include <cstring>
#include <intrin.h>

#pragma comment(lib, "WinHvPlatform.lib")

VcpuManager* VcpuManager::s_instance = nullptr;
thread_local uint32_t VcpuManager::t_currentVcpuIndex = UINT32_MAX;

VcpuManager::VcpuManager(Logger* logger, Partition* partition, ExitDispatcher* exitDispatcher,
                         CpuidHandler* cpuidHandler, RdtscHandler* rdtscHandler,
                         MsrHandler* msrHandler)
    : m_logger(logger), m_partition(partition), m_exitDispatcher(exitDispatcher),
      m_cpuidHandler(cpuidHandler), m_rdtscHandler(rdtscHandler),
      m_msrHandler(msrHandler),
      m_magicCpuid(nullptr), m_syscallHandler(nullptr),
      m_exceptionHandler(nullptr),
      m_vcpuCount(0), m_bootCodeLoaded(false),
      m_childThreadMigrationEnabled(false)
{
    memset(m_vcpus, 0, sizeof(m_vcpus));
    InitializeCriticalSection(&m_vcpuAllocLock);
    s_instance = this;
}

VcpuManager::~VcpuManager()
{
    for (uint32_t i = 0; i < m_vcpuCount; i++) {
        Stop(i);
        if (m_vcpus[i].allocatedStack) {
            VirtualFree(m_vcpus[i].allocatedStack, 0, MEM_RELEASE);
        }
    }
    m_threadHandleToVcpu.clear();
    DeleteCriticalSection(&m_vcpuAllocLock);
    s_instance = nullptr;
}

bool VcpuManager::ReadVcpuRegs(uint32_t vcpuIndex, WHV_REGISTER_NAME* names, WHV_REGISTER_VALUE* values, uint32_t count)
{
    HRESULT hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex, names, count, values);
    return SUCCEEDED(hr);
}

bool VcpuManager::WriteVcpuRegs(uint32_t vcpuIndex, WHV_REGISTER_NAME* names, WHV_REGISTER_VALUE* values, uint32_t count)
{
    HRESULT hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex, names, count, values);
    return SUCCEEDED(hr);
}

void VcpuManager::Stop(uint32_t vcpuIndex)
{
    if (vcpuIndex < MAX_VCPU && m_vcpus[vcpuIndex].running) {
        m_vcpus[vcpuIndex].running = false;
        WHvCancelRunVirtualProcessor(m_partition->GetHandle(), vcpuIndex, 0);
    }
}

bool VcpuManager::CreateVcpu(uint32_t vcpuIndex)
{
    if (vcpuIndex >= MAX_VCPU) {
        m_logger->Trace(LOG_ERROR, "VCPU index %u out of range", vcpuIndex);
        return false;
    }

    HRESULT hr = WHvCreateVirtualProcessor(m_partition->GetHandle(), vcpuIndex, 0);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvCreateVirtualProcessor(%u) failed: 0x%08X", vcpuIndex, hr);
        return false;
    }

    m_vcpus[vcpuIndex].running = false;
    m_vcpus[vcpuIndex].stack = nullptr;
    m_vcpus[vcpuIndex].allocatedStack = nullptr;
    m_vcpus[vcpuIndex].hostThread = nullptr;
    m_vcpus[vcpuIndex].lastSyncTsc = 0;
    m_vcpus[vcpuIndex].timingGeneration = 0;

    if (vcpuIndex >= m_vcpuCount) m_vcpuCount = vcpuIndex + 1;

    if (vcpuIndex == 0) {
        m_syscallDispatch.Initialize();
    }

    m_logger->Trace(LOG_WHP, "VCPU %u created", vcpuIndex);
    return true;
}

bool VcpuManager::Run(uint32_t vcpuIndex)
{
    if (vcpuIndex >= m_vcpuCount) {
        m_logger->Trace(LOG_ERROR, "VCPU %u not created", vcpuIndex);
        return false;
    }

    if (!SetupRegisters(vcpuIndex)) {
        m_logger->Trace(LOG_ERROR, "Failed to setup registers for VCPU %u", vcpuIndex);
        return false;
    }

    m_vcpus[vcpuIndex].running = true;
    m_logger->Trace(LOG_INFO, "VCPU %u starting execution (boot code)", vcpuIndex);

    m_kernelLock.Lock(); // BEL: acquire on entry

    while (m_vcpus[vcpuIndex].running) {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;

        m_kernelLock.Unlock(); // BEL: release during guest execution
        HRESULT hr = WHvRunVirtualProcessor(m_partition->GetHandle(), vcpuIndex,
            &exitCtx, sizeof(exitCtx));
        m_kernelLock.Lock(); // BEL: re-acquire on VM-exit

        if (FAILED(hr)) {
            m_logger->Trace(LOG_ERROR, "WHvRunVirtualProcessor failed: 0x%08X", hr);
            break;
        }

        m_vcpus[vcpuIndex].exitCtx = exitCtx;

        if (!HandleExit(vcpuIndex)) {
            m_logger->Trace(LOG_WHP, "VCPU %u unhandled exit at reason=%d",
                vcpuIndex, exitCtx.ExitReason);
            break;
        }
    }

    m_kernelLock.Unlock(); // BEL: release on exit
    m_logger->Trace(LOG_INFO, "VCPU %u stopped", vcpuIndex);
    return true;
}

// ─── Bootstrap VCPU from captured thread context ────────────────────────

bool VcpuManager::BootstrapFromContext(uint32_t vcpuIndex, const ThreadContext& ctx, GuestPageTable* pageTable)
{
    if (vcpuIndex >= m_vcpuCount) {
        if (!CreateVcpu(vcpuIndex)) return false;
    }

    // Set up LSTAR→HLT for syscall interception (required for guest syscalls)
    if (!LoadHltPage()) {
        m_logger->Trace(LOG_ERROR, "Bootstrap: HLT page load failed");
        return false;
    }
    if (!SetupLstarMsrs(vcpuIndex)) {
        m_logger->Trace(LOG_ERROR, "Bootstrap: LSTAR MSR setup failed");
        return false;
    }

    // Set captured thread context and custom CR3
    SetContextRegisters(vcpuIndex, ctx, pageTable);

    // Set up per-VCPU GDT for this VCPU
    if (!SetupPerVcpuGdt(vcpuIndex)) {
        m_logger->Trace(LOG_ERROR, "Bootstrap: per-VCPU GDT setup failed");
        return false;
    }

    m_vcpus[vcpuIndex].running = true;
    t_currentVcpuIndex = vcpuIndex;
    m_logger->Trace(LOG_INFO, "Bootstrap: VCPU %u entered with CR3=0x%llX, RIP=0x%llX",
        vcpuIndex, pageTable ? pageTable->GetPml4Gpa() : 0, ctx.rip);

    m_kernelLock.Lock(); // BEL: acquire on entry

    // Main VCPU loop
    while (m_vcpus[vcpuIndex].running) {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;

        m_kernelLock.Unlock(); // BEL: release during guest execution
        HRESULT hr = WHvRunVirtualProcessor(m_partition->GetHandle(), vcpuIndex,
            &exitCtx, sizeof(exitCtx));
        m_kernelLock.Lock(); // BEL: re-acquire on VM-exit

        if (FAILED(hr)) {
            m_logger->Trace(LOG_ERROR, "Bootstrap: WHvRunVirtualProcessor failed: 0x%08X", hr);
            break;
        }

        m_vcpus[vcpuIndex].exitCtx = exitCtx;

        if (!HandleExit(vcpuIndex)) {
            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            if (ReadVcpuRegs(vcpuIndex, &ripName, &ripValue, 1)) {
                m_logger->Trace(LOG_WHP, "Bootstrap: unhandled exit reason=%d at RIP=0x%llX",
                    exitCtx.ExitReason, ripValue.Reg64);
            } else {
                m_logger->Trace(LOG_WHP, "Bootstrap: unhandled exit reason=%d",
                    exitCtx.ExitReason);
            }
            break;
        }
    }

    m_kernelLock.Unlock(); // BEL: release on exit
    t_currentVcpuIndex = UINT32_MAX;
    m_logger->Trace(LOG_INFO, "Bootstrap: VCPU %u stopped", vcpuIndex);
    return true;
}

void VcpuManager::SetContextRegisters(uint32_t vcpuIndex, const ThreadContext& ctx, GuestPageTable* pageTable)
{
    WHV_REGISTER_NAME names[32];
    WHV_REGISTER_VALUE values[32];
    int count = 0;

    names[count] = WHvX64RegisterRax; values[count].Reg64 = ctx.rax; count++;
    names[count] = WHvX64RegisterRbx; values[count].Reg64 = ctx.rbx; count++;
    names[count] = WHvX64RegisterRcx; values[count].Reg64 = ctx.rcx; count++;
    names[count] = WHvX64RegisterRdx; values[count].Reg64 = ctx.rdx; count++;
    names[count] = WHvX64RegisterRsi; values[count].Reg64 = ctx.rsi; count++;
    names[count] = WHvX64RegisterRdi; values[count].Reg64 = ctx.rdi; count++;
    names[count] = WHvX64RegisterRbp; values[count].Reg64 = ctx.rbp; count++;
    names[count] = WHvX64RegisterRsp; values[count].Reg64 = ctx.rsp; count++;
    names[count] = WHvX64RegisterR8;  values[count].Reg64 = ctx.r8;  count++;
    names[count] = WHvX64RegisterR9;  values[count].Reg64 = ctx.r9;  count++;
    names[count] = WHvX64RegisterR10; values[count].Reg64 = ctx.r10; count++;
    names[count] = WHvX64RegisterR11; values[count].Reg64 = ctx.r11; count++;
    names[count] = WHvX64RegisterR12; values[count].Reg64 = ctx.r12; count++;
    names[count] = WHvX64RegisterR13; values[count].Reg64 = ctx.r13; count++;
    names[count] = WHvX64RegisterR14; values[count].Reg64 = ctx.r14; count++;
    names[count] = WHvX64RegisterR15; values[count].Reg64 = ctx.r15; count++;
    names[count] = WHvX64RegisterRip; values[count].Reg64 = ctx.rip; count++;
    names[count] = WHvX64RegisterRflags; values[count].Reg64 = ctx.rflags; count++;

    WriteVcpuRegs(vcpuIndex, names, values, count);

    // Set segment registers (ring-3 code segment)
    WHV_X64_SEGMENT_REGISTER segCs;
    memset(&segCs, 0, sizeof(segCs));
    segCs.Selector = 0x33; // User-mode 64-bit code segment
    segCs.Attributes = 0x20FB; // Present, ring-3, code, 64-bit
    segCs.Base = 0;
    segCs.Limit = 0xFFFFFFFF;
    WHV_REGISTER_VALUE csValue;
    csValue.Segment = segCs;
    WHV_REGISTER_NAME csName = WHvX64RegisterCs;
    WriteVcpuRegs(vcpuIndex, &csName, &csValue, 1);

    // Data segments (ring-3)
    WHV_X64_SEGMENT_REGISTER segData;
    memset(&segData, 0, sizeof(segData));
    segData.Selector = 0x2B; // User-mode data segment
    segData.Attributes = 0x20F3; // Present, ring-3, data, writable
    segData.Base = 0;
    segData.Limit = 0xFFFFFFFF;
    WHV_REGISTER_VALUE dataValue;
    dataValue.Segment = segData;
    WHV_REGISTER_NAME dataNames[] = {WHvX64RegisterDs, WHvX64RegisterEs, WHvX64RegisterFs,
                                      WHvX64RegisterGs, WHvX64RegisterSs};
    for (int i = 0; i < 5; i++) {
        WriteVcpuRegs(vcpuIndex, &dataNames[i], &dataValue, 1);
    }

    // Set CR3 from page table
    uint64_t cr3 = pageTable ? pageTable->GetPml4Gpa() : 0;
    WHV_REGISTER_NAME crNames[4] = {WHvX64RegisterCr0, WHvX64RegisterCr3,
                                     WHvX64RegisterCr4, WHvX64RegisterCr8};
    WHV_REGISTER_VALUE crValues[4];
    crValues[0].Reg64 = 0x80000001; // PE | MP | ET
    crValues[1].Reg64 = cr3;
    crValues[2].Reg64 = 0x1706F8 & ~0x6000;   // PAE | PGE | OSFXSR | OSXMMEXCPT | OSXSAVE (VMXE+SMXE masked)
    crValues[3].Reg64 = 0;
    WriteVcpuRegs(vcpuIndex, crNames, crValues, 4);

    // EFER: LME, LMA, SCE
    WHV_REGISTER_NAME eferReg = WHvX64RegisterEfer;
    WHV_REGISTER_VALUE eferValue;
    eferValue.Reg64 = 0x801; // LME=1, LMA=1, SCE=1 (SCE is set by LSTAR MSR)
    WriteVcpuRegs(vcpuIndex, &eferReg, &eferValue, 1);

    m_logger->Trace(LOG_WHP, "Context set: RIP=0x%llX RSP=0x%llX CR3=0x%llX",
        ctx.rip, ctx.rsp, cr3);
}

// ─── Multi-VCPU: Child thread support ──────────────────────────────────

uint32_t VcpuManager::AllocateVcpuIndex()
{
    // VCPU 0 is reserved for main entry thread
    for (uint32_t i = 1; i < MAX_VCPU; i++) {
        if (!m_vcpus[i].running && m_vcpus[i].hostThread == nullptr) {
            return i;
        }
    }
    return UINT32_MAX;
}

void VcpuManager::FreeVcpuIndex(uint32_t index)
{
    if (index >= MAX_VCPU || index == 0) return;

    m_vcpus[index].running = false;

    if (m_vcpus[index].hostThread) {
        CloseHandle(m_vcpus[index].hostThread);
        m_vcpus[index].hostThread = nullptr;
    }

    if (m_vcpus[index].allocatedStack) {
        VirtualFree(m_vcpus[index].allocatedStack, 0, MEM_RELEASE);
        m_vcpus[index].allocatedStack = nullptr;
    }

    for (auto it = m_threadHandleToVcpu.begin(); it != m_threadHandleToVcpu.end(); ) {
        if (it->second == index) {
            it = m_threadHandleToVcpu.erase(it);
        } else {
            ++it;
        }
    }

    m_logger->Trace(LOG_WHP, "VCPU %u freed", index);
}

bool VcpuManager::SetupChildVcpuContext(uint32_t vcpuIndex, const ThreadContext& ctx)
{
    if (!SetupLstarMsrs(vcpuIndex)) {
        m_logger->Trace(LOG_ERROR, "ChildVCPU %u: LSTAR MSR setup failed", vcpuIndex);
        return false;
    }

    // Set up context registers with the child thread's initial state
    SetContextRegisters(vcpuIndex, ctx, m_partition->GetPageTable());
    return true;
}

DWORD WINAPI VcpuManager::ThreadBootstrapEntry(LPVOID param)
{
    uint32_t vcpuIndex = (uint32_t)(uintptr_t)param;
    VcpuManager* self = s_instance;
    if (!self || vcpuIndex >= MAX_VCPU) return 1;

    self->EnterVcpuFromBootstrap(vcpuIndex);
    return 0;
}

void VcpuManager::EnterVcpuFromBootstrap(uint32_t vcpuIndex)
{
    if (!SetupPerVcpuGdt(vcpuIndex)) {
        m_logger->Trace(LOG_ERROR, "ChildVCPU %u: per-VCPU GDT setup failed", vcpuIndex);
        return;
    }

    m_vcpus[vcpuIndex].running = true;
    t_currentVcpuIndex = vcpuIndex;

    m_logger->Trace(LOG_INFO, "ChildVCPU %u entering run loop", vcpuIndex);

    m_kernelLock.Lock(); // BEL: acquire on entry

    while (m_vcpus[vcpuIndex].running) {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;

        m_kernelLock.Unlock(); // BEL: release during guest execution
        HRESULT hr = WHvRunVirtualProcessor(m_partition->GetHandle(), vcpuIndex,
            &exitCtx, sizeof(exitCtx));
        m_kernelLock.Lock(); // BEL: re-acquire on VM-exit

        if (FAILED(hr)) {
            m_logger->Trace(LOG_ERROR, "ChildVCPU %u: WHvRunVirtualProcessor failed: 0x%08X", vcpuIndex, hr);
            break;
        }

        m_vcpus[vcpuIndex].exitCtx = exitCtx;

        if (!HandleExit(vcpuIndex)) {
            m_logger->Trace(LOG_WHP, "ChildVCPU %u: unhandled exit reason=%d", vcpuIndex, exitCtx.ExitReason);
            break;
        }
    }

    m_kernelLock.Unlock(); // BEL: release on exit
    t_currentVcpuIndex = UINT32_MAX;
    FreeVcpuIndex(vcpuIndex);
    m_logger->Trace(LOG_INFO, "ChildVCPU %u exited", vcpuIndex);
}

bool VcpuManager::HandleCreateThreadSyscall(uint32_t vcpuIndex, uint32_t syscallNum,
                                             uint64_t* regArgs, uint64_t guestRsp,
                                             uint64_t& result)
{
    (void)vcpuIndex;
    if (!m_childThreadMigrationEnabled) {
        return false; // Fall through to host ntdll forwarding
    }

    // Read all 11 args from guest stack (NtCreateThreadEx has up to 11)
    uint64_t allArgs[16] = {regArgs[0], regArgs[1], regArgs[2], regArgs[3]};
    int argCount = (syscallNum == m_syscallDispatch.NtCreateThreadEx) ? 11 : 8;
    for (int i = 4; i < argCount && i < 16; i++) {
        uint64_t* stackPtr = (uint64_t*)(guestRsp + 8 + (i - 4) * 8);
        allArgs[i] = *stackPtr;
    }

    // Extract thread entry information
    uint64_t startRip = 0, startParam = 0;
    HANDLE* threadHandleOut = nullptr;
    bool createSuspended = false;

    if (syscallNum == m_syscallDispatch.NtCreateThreadEx) {
        // NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjAttr, ProcessHandle,
        //                   StartRoutine, Argument, CreateFlags, ...)
        startRip = allArgs[4];
        startParam = allArgs[5];
        createSuspended = (allArgs[6] & 1) != 0;
        threadHandleOut = (HANDLE*)(uintptr_t)allArgs[0];
    } else {
        // NtCreateThread(ThreadHandle, DesiredAccess, ObjAttr, ProcessHandle,
        //                 ClientId, Context, InitialTeb, CreateSuspended)
        CONTEXT* guestCtx = (CONTEXT*)(uintptr_t)allArgs[5];
        if (guestCtx) {
            startRip = guestCtx->Rip;
            startParam = guestCtx->Rcx;
        }
        createSuspended = allArgs[7] != 0;
        threadHandleOut = (HANDLE*)(uintptr_t)allArgs[0];
    }

    if (!startRip) {
        m_logger->Trace(LOG_WHP, "CreateThread: no start address, forwarding to host");
        return false;
    }

    // Allocate VCPU index for child thread
    EnterCriticalSection(&m_vcpuAllocLock);
    uint32_t childVcpuIndex = AllocateVcpuIndex();
    LeaveCriticalSection(&m_vcpuAllocLock);

    if (childVcpuIndex == UINT32_MAX) {
        m_logger->Trace(LOG_WARNING, "CreateThread: no free VCPU slots (max %u)", MAX_VCPU);
        return false;
    }

    // Create VCPU on partition
    if (!CreateVcpu(childVcpuIndex)) {
        m_logger->Trace(LOG_ERROR, "CreateThread: failed to create VCPU %u", childVcpuIndex);
        return false;
    }

    // Allocate stack for child thread (1MB default)
    const uint32_t stackSize = 0x100000;
    void* stack = VirtualAlloc(nullptr, stackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stack) {
        m_logger->Trace(LOG_ERROR, "CreateThread: failed to allocate child stack");
        return false;
    }

    // Build ThreadContext for child VCPU
    ThreadContext childCtx;
    memset(&childCtx, 0, sizeof(childCtx));
    childCtx.rip = startRip;
    childCtx.rcx = startParam;
    childCtx.rsp = (uint64_t)stack + stackSize - 0x100;
    childCtx.rflags = 0x202; // IF enabled
    childCtx.cs = 0x33;
    childCtx.ds = 0x2B;
    childCtx.es = 0x2B;
    childCtx.fs = 0x2B;
    childCtx.gs = 0x2B;
    childCtx.ss = 0x2B;

    // Set up VCPU context
    if (!SetupChildVcpuContext(childVcpuIndex, childCtx)) {
        m_logger->Trace(LOG_ERROR, "CreateThread: failed to setup VCPU %u context", childVcpuIndex);
        VirtualFree(stack, 0, MEM_RELEASE);
        return false;
    }

    m_vcpus[childVcpuIndex].allocatedStack = (uint8_t*)stack;

    // Create host thread that enters VCPU N
    DWORD createFlags = createSuspended ? CREATE_SUSPENDED : 0;
    HANDLE hThread = CreateThread(nullptr, 0, ThreadBootstrapEntry,
        (LPVOID)(uintptr_t)childVcpuIndex, createFlags, nullptr);

    if (!hThread) {
        m_logger->Trace(LOG_ERROR, "CreateThread: failed to create host thread (GLE=%u)", GetLastError());
        VirtualFree(stack, 0, MEM_RELEASE);
        return false;
    }

    m_vcpus[childVcpuIndex].hostThread = hThread;

    // Output thread handle to guest
    if (threadHandleOut) {
        *threadHandleOut = hThread;
    }

    // Map handle to VCPU index
    m_threadHandleToVcpu[hThread] = childVcpuIndex;

    m_logger->Trace(LOG_INFO, "CreateThread: VCPU %u created for thread RIP=0x%llX handle=0x%p%s",
        childVcpuIndex, startRip, hThread, createSuspended ? " (suspended)" : "");

    result = 0; // STATUS_SUCCESS
    return true;
}

bool VcpuManager::HandleTerminateThreadSyscall(uint32_t vcpuIndex, uint64_t* args, uint64_t& result)
{
    (void)vcpuIndex; (void)args;
    // Only intercept for child VCPUs (not VCPU 0)
    uint32_t currentVcpu = t_currentVcpuIndex;

    if (currentVcpu != UINT32_MAX && currentVcpu > 0 && currentVcpu < MAX_VCPU
        && m_vcpus[currentVcpu].running) {
        // Child VCPU thread exiting — stop VCPU instead of killing host thread
        m_vcpus[currentVcpu].running = false;
        result = 0; // STATUS_SUCCESS
        m_logger->Trace(LOG_INFO, "TerminateThread: VCPU %u stopped (child thread exit)", currentVcpu);
        return true;
    }

    // VCPU 0 or unknown — let normal forwarding handle it
    return false;
}

// ─── Per-VCPU GDT ─────────────────────────────────────────────────────

bool VcpuManager::SetupPerVcpuGdt(uint32_t vcpuIndex)
{
    if (vcpuIndex >= MAX_VCPU) return false;

    uint64_t gdtGpa = PER_VCPU_GDT_BASE + (uint64_t)vcpuIndex * PER_VCPU_GDT_SIZE;

    // Allocate and map a page of guest memory for this VCPU's GDT
    void* gdtVa = VirtualAlloc(nullptr, PER_VCPU_GDT_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!gdtVa) {
        m_logger->Trace(LOG_ERROR, "Per-VCPU GDT %u: VirtualAlloc failed", vcpuIndex);
        return false;
    }

    // Zero-fill
    memset(gdtVa, 0, PER_VCPU_GDT_SIZE);

    // Set up minimal x64 GDT entries:
    //   Entry 0: null descriptor
    //   Entry 1: ring-0 code segment (0x10 selector)
    //   Entry 2: ring-0 data segment (0x18 selector)
    //   Entry 3: ring-3 code segment (0x23 selector) — 32-bit compatibility
    //   Entry 4: ring-3 data segment (0x2B selector)
    //   Entry 5: ring-3 code segment (0x33 selector) — 64-bit long mode
    //   Entry 6: TSS descriptor (reserved)
    uint64_t* gdt = (uint64_t*)gdtVa;
    gdt[0] = 0x0000000000000000ULL;              // null
    gdt[1] = 0x00AF9B000000FFFFULL;              // ring-0 code 64
    gdt[2] = 0x00CF93000000FFFFULL;              // ring-0 data
    gdt[3] = 0x00CFFB000000FFFFULL;              // ring-3 code 32
    gdt[4] = 0x00CFF3000000FFFFULL;              // ring-3 data
    gdt[5] = 0x00AFFB000000FFFFULL;              // ring-3 code 64

    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (!m_partition->MapGpaRange(gdtVa, gdtGpa, PER_VCPU_GDT_SIZE, flags)) {
        m_logger->Trace(LOG_ERROR, "Per-VCPU GDT %u: MapGpaRange failed at GPA 0x%llX", vcpuIndex, gdtGpa);
        VirtualFree(gdtVa, 0, MEM_RELEASE);
        return false;
    }

    // Set GDTR for this VCPU
    WHV_X64_TABLE_REGISTER gdtr;
    gdtr.Base = gdtGpa;
    gdtr.Limit = 6 * 8 - 1; // 6 entries

    WHV_REGISTER_VALUE gdtrValue;
    gdtrValue.Table = gdtr;

    WHV_REGISTER_NAME gdtrReg = WHvX64RegisterGdtr;
    HRESULT hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
        &gdtrReg, 1, &gdtrValue);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "Per-VCPU GDT %u: WHvSetVirtualProcessorRegisters failed: 0x%08X",
            vcpuIndex, hr);
        VirtualFree(gdtVa, 0, MEM_RELEASE);
        return false;
    }

    m_logger->Trace(LOG_WHP, "Per-VCPU GDT %u: GPA=0x%llX base=0x%llX limit=%u",
        vcpuIndex, gdtGpa, gdtr.Base, gdtr.Limit);
    return true;
}

// ─── Boot code setup ──────────────────────────────────────────────────

bool VcpuManager::LoadBootCode(uint32_t)
{
    if (m_bootCodeLoaded) return true;
    void* bootCode = m_partition->AllocateGuestMemory(0x10000);
    if (!bootCode) {
        m_logger->Trace(LOG_ERROR, "Failed to allocate boot code memory");
        return false;
    }

    uint8_t* code = (uint8_t*)bootCode;
    memset(code, 0, 0x10000);

    code[0x1000] = 0xB8; code[0x1001] = 0x00; code[0x1002] = 0x00;
    code[0x1003] = 0x00; code[0x1004] = 0x00;
    code[0x1005] = 0x0F; code[0x1006] = 0xA2;
    code[0x1007] = 0x0F; code[0x1008] = 0x31;
    code[0x1009] = 0x0F; code[0x100A] = 0x01; code[0x100B] = 0xF9;
    code[0x100C] = 0xF4;
    code[0x100D] = 0xEB; code[0x100E] = 0xFD;

    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (!m_partition->MapGpaRange(bootCode, 0x100000, 0x10000, flags)) {
        m_logger->Trace(LOG_ERROR, "Failed to map boot code at GPA 0x100000");
        m_partition->FreeGuestMemory(bootCode);
        return false;
    }

    uint64_t* gdt = (uint64_t*)(code + 0x800);
    gdt[0] = 0x0000000000000000ULL;
    gdt[1] = 0x00AF9B000000FFFFULL;
    gdt[2] = 0x00CF93000000FFFFULL;

    m_logger->Trace(LOG_INFO, "Boot code loaded at GPA 0x101000");
    m_bootCodeLoaded = true;
    return true;
}

bool VcpuManager::LoadHltPage()
{
    if (m_hltPageGpa) return true;
    void* hltPage = m_partition->AllocateGuestMemory(0x1000);
    if (!hltPage) {
        m_logger->Trace(LOG_ERROR, "Failed to allocate HLT page");
        return false;
    }
    uint8_t* page = (uint8_t*)hltPage;
    page[0] = 0xF4;
    page[1] = 0xEB;
    page[2] = 0xFF;

    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute);
    m_hltPageGpa = 0x12000;
    if (!m_partition->MapGpaRange(hltPage, m_hltPageGpa, 0x1000, flags)) {
        m_logger->Trace(LOG_ERROR, "Failed to map HLT page at GPA 0x%llX", m_hltPageGpa);
        m_partition->FreeGuestMemory(hltPage);
        m_hltPageGpa = 0;
        return false;
    }
    m_logger->Trace(LOG_INFO, "HLT page loaded at GPA 0x%llX (LSTAR target)", m_hltPageGpa);
    return true;
}

bool VcpuManager::SetupLstarMsrs(uint32_t vcpuIndex)
{
    if (!LoadHltPage()) return false;

    WHV_REGISTER_VALUE values[3];
    WHV_REGISTER_NAME names[3];
    int count = 0;

    names[count] = WHvX64RegisterStar;
    values[count].Reg64 = (0x18ULL << 48) | (0x10ULL << 32);
    count++;

    names[count] = WHvX64RegisterLstar;
    values[count].Reg64 = m_hltPageGpa;
    count++;

    names[count] = WHvX64RegisterSfmask;
    values[count].Reg64 = 0x4700;
    count++;

    HRESULT hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
        names, count, values);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "Failed to set LSTAR MSRs: 0x%08X", hr);
        return false;
    }
    m_logger->Trace(LOG_WHP, "LSTAR MSRs set for VCPU %u (HLT page GPA=0x%llX)", vcpuIndex, m_hltPageGpa);
    return true;
}

bool VcpuManager::HandleSyscallExit(uint32_t vcpuIndex)
{
    WHV_REGISTER_NAME names[6] = {
        WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
        WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterR11
    };
    WHV_REGISTER_VALUE values[6];
    if (!ReadVcpuRegs(vcpuIndex, names, values, 6))
        return false;

    uint32_t syscallNum = (uint32_t)values[0].Reg64;
    uint64_t returnAddr = values[1].Reg64;
    uint64_t savedRfl = values[5].Reg64;

    uint64_t args[4] = {
        0, // Will be filled from R10
        values[2].Reg64, // RDX → arg2
        values[3].Reg64, // R8  → arg3
        values[4].Reg64  // R9  → arg4
    };

    WHV_REGISTER_NAME r10Name = WHvX64RegisterR10;
    WHV_REGISTER_VALUE r10Value;
    if (!ReadVcpuRegs(vcpuIndex, &r10Name, &r10Value, 1))
        args[0] = 0;
    else
        args[0] = r10Value.Reg64;

    // Read guest RSP for stack-based args (args 5+)
    WHV_REGISTER_NAME rspName = WHvX64RegisterRsp;
    WHV_REGISTER_VALUE rspValue;
    uint64_t guestRsp = 0;
    if (ReadVcpuRegs(vcpuIndex, &rspName, &rspValue, 1)) {
        guestRsp = rspValue.Reg64;
    }

    m_logger->Trace(LOG_WHP, "VCPU %u: SYSCALL 0x%X from return-addr 0x%llX (RSP=0x%llX)",
        vcpuIndex, syscallNum, returnAddr, guestRsp);

    // Simulate a CONTEXT to pass to stack spoofer
    CONTEXT spoofCtx;
    memset(&spoofCtx, 0, sizeof(spoofCtx));
    spoofCtx.Rsp = guestRsp;
    spoofCtx.Rax = values[0].Reg64;

    // Stack spoofer: replace return address with ntdll ret sled before dispatch
    if (m_stackSpoofer) {
        m_stackSpoofer->SpoofReturnAddress(&spoofCtx);
    }

    uint64_t result = 0;
    bool handled = false;

    // Intercept thread management syscalls first
    if (syscallNum == m_syscallDispatch.NtCreateThread ||
        syscallNum == m_syscallDispatch.NtCreateThreadEx) {
        handled = HandleCreateThreadSyscall(vcpuIndex, syscallNum, args, guestRsp, result);
    }

    if (!handled && syscallNum == m_syscallDispatch.NtTerminateThread) {
        handled = HandleTerminateThreadSyscall(vcpuIndex, args, result);
    }

    if (!handled) {
        // Try DispatchRawSyscall
        handled = m_syscallDispatch.DispatchRawSyscall(syscallNum, args, result);
    }

    if (!handled) {
        // Try forwarding to host ntdll
        handled = m_syscallDispatch.ForwardSyscall(syscallNum, args, guestRsp, result);
    }

    if (!handled) {
        result = 0xC0000001;
        m_logger->Trace(LOG_WHP, "VCPU %u: unhandled syscall 0x%X", vcpuIndex, syscallNum);
    }

    // Restore return address after syscall completes
    if (m_stackSpoofer && handled) {
        m_stackSpoofer->RestoreReturnAddress(&spoofCtx, returnAddr);
    }

    WHV_REGISTER_NAME retNames[3] = {
        WHvX64RegisterRax, WHvX64RegisterRip, WHvX64RegisterRflags
    };
    WHV_REGISTER_VALUE retValues[3];
    retValues[0].Reg64 = result;
    retValues[1].Reg64 = returnAddr;
    retValues[2].Reg64 = savedRfl;
    return WriteVcpuRegs(vcpuIndex, retNames, retValues, 3);
}

bool VcpuManager::SetupRegisters(uint32_t vcpuIndex)
{
    if (!LoadBootCode(vcpuIndex)) return false;
    if (!LoadHltPage()) return false;
    if (!SetupSegmentRegisters(vcpuIndex)) return false;
    if (!SetupControlRegisters(vcpuIndex)) return false;
    if (!SetupLstarMsrs(vcpuIndex)) return false;

    WHV_REGISTER_NAME regNames[8];
    WHV_REGISTER_VALUE regValues[8];
    int regCount = 0;

    regNames[regCount] = WHvX64RegisterRip;
    regValues[regCount].Reg64 = 0x101000;
    regCount++;

    regNames[regCount] = WHvX64RegisterRsp;
    regValues[regCount].Reg64 = 0x7000;
    regCount++;

    regNames[regCount] = WHvX64RegisterRax;
    regValues[regCount].Reg64 = 0;
    regCount++;

    regNames[regCount] = WHvX64RegisterRcx;
    regValues[regCount].Reg64 = 0;
    regCount++;

    regNames[regCount] = WHvX64RegisterRdx;
    regValues[regCount].Reg64 = 0;
    regCount++;

    regNames[regCount] = WHvX64RegisterRbx;
    regValues[regCount].Reg64 = 0;
    regCount++;

    HRESULT hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
        regNames, regCount, regValues);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "Failed to set general registers: 0x%08X", hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "Registers set for VCPU %u", vcpuIndex);
    return true;
}

bool VcpuManager::SetupSegmentRegisters(uint32_t vcpuIndex)
{
    WHV_X64_SEGMENT_REGISTER seg;
    memset(&seg, 0, sizeof(seg));

    seg.Selector = 0x10;
    seg.Attributes = 0x209B;
    seg.Base = 0;
    seg.Limit = 0xFFFFFFFF;

    WHV_REGISTER_VALUE csValue;
    csValue.Segment = seg;

    WHV_REGISTER_NAME csReg = WHvX64RegisterCs;
    HRESULT hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
        &csReg, 1, &csValue);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "Failed to set CS: 0x%08X", hr);
        return false;
    }

    WHV_REGISTER_NAME segNames[] = {
        WHvX64RegisterDs, WHvX64RegisterEs, WHvX64RegisterFs,
        WHvX64RegisterGs, WHvX64RegisterSs
    };

    memset(&seg, 0, sizeof(seg));
    seg.Selector = 0x18;
    seg.Attributes = 0x2093;
    seg.Base = 0;
    seg.Limit = 0xFFFFFFFF;

    WHV_REGISTER_VALUE segValue;
    segValue.Segment = seg;

    for (int i = 0; i < 5; i++) {
        hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
            &segNames[i], 1, &segValue);
        if (FAILED(hr)) return false;
    }

    WHV_X64_TABLE_REGISTER gdtr;
    gdtr.Base = 0x100800;
    gdtr.Limit = 0x2F;

    WHV_REGISTER_VALUE gdtrValue;
    gdtrValue.Table = gdtr;

    WHV_REGISTER_NAME gdtrReg = WHvX64RegisterGdtr;
    hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
        &gdtrReg, 1, &gdtrValue);
    if (FAILED(hr)) return false;

    m_logger->Trace(LOG_WHP, "Segment registers set for VCPU %u", vcpuIndex);
    return true;
}

bool VcpuManager::SetupControlRegisters(uint32_t vcpuIndex)
{
    WHV_REGISTER_NAME crNames[4];
    WHV_REGISTER_VALUE crValues[4];
    int crCount = 0;

    crNames[crCount] = WHvX64RegisterCr0;
    crValues[crCount].Reg64 = 0x80000001;
    crCount++;

    crNames[crCount] = WHvX64RegisterCr3;
    crValues[crCount].Reg64 = 0;
    crCount++;

    crNames[crCount] = WHvX64RegisterCr4;
    crValues[crCount].Reg64 = 0x688;
    crCount++;

    crNames[crCount] = WHvX64RegisterCr8;
    crValues[crCount].Reg64 = 0;
    crCount++;

    HRESULT hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
        crNames, crCount, crValues);
    if (FAILED(hr)) return false;

    WHV_REGISTER_NAME eferReg = WHvX64RegisterEfer;
    WHV_REGISTER_VALUE eferValue;
    eferValue.Reg64 = 1;

    hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
        &eferReg, 1, &eferValue);
    if (FAILED(hr)) return false;

    m_logger->Trace(LOG_WHP, "Control registers set for VCPU %u", vcpuIndex);
    return true;
}

bool VcpuManager::HandleVpSingleStep(uint32_t vcpuIndex, uint64_t)
{
    // Check if this #DB is our internal EPT single-step completion
    if (m_eptExecHook && m_eptExecHook->HandleSingleStepComplete(
        m_partition->GetHandle(), vcpuIndex)) {
        return true;
    }

    // Not our step — let the exception handler try (or pass through)
    return false;
}

// ─── Exit handler ──────────────────────────────────────────────────────

bool VcpuManager::HandleExit(uint32_t vcpuIndex)
{
    WHV_RUN_VP_EXIT_CONTEXT& exitCtx = m_vcpus[vcpuIndex].exitCtx;
    WHV_RUN_VP_EXIT_REASON reason = exitCtx.ExitReason;
    HRESULT hr;

    if (reason == WHvRunVpExitReasonException) {
        WHV_VP_EXCEPTION_CONTEXT& exc = exitCtx.VpException;

        uint64_t rip = 0;
        WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
        WHV_REGISTER_VALUE ripValue;
        hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
            &ripName, 1, &ripValue);
        if (SUCCEEDED(hr)) rip = ripValue.Reg64;

        // Dispatch by exception vector
        switch (exc.ExceptionType) {
            case 0x01: // #DB — single step (exec hook step)
                return HandleVpSingleStep(vcpuIndex, rip);

            case 0x06: { // #UD — invalid opcode
                m_logger->Trace(LOG_WHP, "VCPU %u: #UD at RIP 0x%llX, skipping 1 byte",
                    vcpuIndex, rip);
                ripValue.Reg64 = rip + 1;
                WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                    &ripName, 1, &ripValue);
                return true;
            }

            case 0x0E: { // #PF — page fault (EPT violation fallback)
                uint64_t cr2 = 0;
                WHV_REGISTER_NAME cr2Name = WHvX64RegisterCr2;
                WHV_REGISTER_VALUE cr2Value;
                if (ReadVcpuRegs(vcpuIndex, &cr2Name, &cr2Value, 1)) {
                    cr2 = cr2Value.Reg64;
                }
                m_logger->Trace(LOG_WHP, "VCPU %u: #PF at RIP 0x%llX, fault VA 0x%llX, err=0x%X",
                    vcpuIndex, rip, cr2, (uint32_t)exc.ErrorCode);
                // Try mapping the faulting page
                if (m_partition->GetPageTable() && m_partition->GetPageTable()->MapDynamicPage(cr2, true)) {
                    m_partition->FlushDeferredMaps();
                    return true;
                }
                // Forward to exception handler as fallback
                if (m_exceptionHandler && m_exceptionHandler->HandleException(nullptr, exc.ExceptionType, nullptr, &rip)) {
                    ripValue.Reg64 = rip;
                    WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                        &ripName, 1, &ripValue);
                    return true;
                }
                return false;
            }

            case 0x10: // #MF — x87 FP error
            case 0x13: // #XM — SIMD FP error
                m_logger->Trace(LOG_WHP, "VCPU %u: FP exception type 0x%X at RIP 0x%llX (ignoring)",
                    vcpuIndex, exc.ExceptionType, rip);
                // Clear FP error state and continue
                ripValue.Reg64 = rip + 1;
                WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                    &ripName, 1, &ripValue);
                return true;

            default:
                // Try the generic exception handler
                if (m_exceptionHandler) {
                    if (m_exceptionHandler->HandleException(nullptr, exc.ExceptionType, nullptr, &rip)) {
                        ripValue.Reg64 = rip;
                        WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                            &ripName, 1, &ripValue);
                        return true;
                    }
                }
                m_logger->Trace(LOG_WHP, "VCPU %u: unhandled exception type 0x%X at RIP 0x%llX",
                    vcpuIndex, exc.ExceptionType, rip);
                return false;
        }
    }

    switch (reason) {
        case WHvRunVpExitReasonX64Cpuid: {
            WHV_X64_CPUID_ACCESS_CONTEXT& cpuid = exitCtx.CpuidAccess;
            uint64_t rax = cpuid.Rax;
            uint64_t rbx = 0;
            uint64_t rcx = cpuid.Rcx;
            uint64_t rdx = 0;

            if (m_magicCpuid && m_magicCpuid->IsMagicCpuid((uint32_t)rax, (uint32_t)rcx, rax, rbx, rcx, rdx)) {
                uint64_t rip = 0;
                m_magicCpuid->HandleMagicCpuid((uint32_t)rax, (uint32_t)rcx, &rax, &rbx, &rcx, &rdx, &rip, nullptr);
                if (m_magicCpuid->ShouldQuit()) {
                    m_magicCpuid->ClearQuit();
                    m_vcpus[vcpuIndex].running = false;
                    cpuid.DefaultResultRax = rax;
                    cpuid.DefaultResultRbx = rbx;
                    cpuid.DefaultResultRcx = rcx;
                    cpuid.DefaultResultRdx = rdx;
                    return true;
                }
            } else if (m_cpuidHandler) {
                uint64_t rip = 0;
                m_cpuidHandler->HandleCpuid(nullptr, &rax, &rbx, &rcx, &rdx, &rip);
            }

            cpuid.DefaultResultRax = rax;
            cpuid.DefaultResultRbx = rbx;
            cpuid.DefaultResultRcx = rcx;
            cpuid.DefaultResultRdx = rdx;

            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                &ripName, 1, &ripValue);
            if (SUCCEEDED(hr)) {
                ripValue.Reg64 += 2;
                WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                    &ripName, 1, &ripValue);
            }
            return true;
        }

        case WHvRunVpExitReasonX64Rdtsc: {
            uint64_t rax = 0, rdx = 0, rcx = 0;
            uint64_t rip = 0;

            if (m_rdtscHandler) {
                bool isRdtscp = exitCtx.ReadTsc.RdtscInfo.IsRdtscp != 0;
                if (isRdtscp)
                    m_rdtscHandler->HandleRdtscp(nullptr, &rax, &rdx, &rcx, &rip);
                else
                    m_rdtscHandler->HandleRdtsc(nullptr, &rax, &rdx, &rip);
            }

            WHV_REGISTER_NAME regNames[3] = {WHvX64RegisterRax, WHvX64RegisterRdx, WHvX64RegisterRcx};
            WHV_REGISTER_VALUE regValues[3];
            regValues[0].Reg64 = rax;
            regValues[1].Reg64 = rdx;
            regValues[2].Reg64 = rcx;
            WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex, regNames, 3, regValues);

            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                &ripName, 1, &ripValue);
            if (SUCCEEDED(hr)) {
                ripValue.Reg64 += 2;
                WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                    &ripName, 1, &ripValue);
            }
            return true;
        }

        case WHvRunVpExitReasonX64MsrAccess: {
            WHV_X64_MSR_ACCESS_CONTEXT& msr = exitCtx.MsrAccess;
            uint32_t msrNumber = msr.MsrNumber;
            bool isWrite = msr.AccessInfo.IsWrite;

            if (isWrite) {
                uint64_t value = msr.Rax | (msr.Rdx << 32);
                if (m_msrHandler && !m_msrHandler->HandleMsrWrite(nullptr, msrNumber, value)) {
                    m_logger->Trace(LOG_WARNING, "VCPU %u: WRMSR 0x%X unhandled, skipping", vcpuIndex, msrNumber);
                }
            } else {
                uint64_t value = 0;
                if (!m_msrHandler || !m_msrHandler->HandleMsrRead(nullptr, msrNumber, &value)) {
                    m_logger->Trace(LOG_WARNING, "VCPU %u: RDMSR 0x%X unhandled, returning 0", vcpuIndex, msrNumber);
                }
                WHV_REGISTER_NAME regNames[2] = {WHvX64RegisterRax, WHvX64RegisterRdx};
                WHV_REGISTER_VALUE regValues[2];
                regValues[0].Reg64 = value & 0xFFFFFFFF;
                regValues[1].Reg64 = (value >> 32) & 0xFFFFFFFF;
                WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex, regNames, 2, regValues);
            }

            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                &ripName, 1, &ripValue);
            if (SUCCEEDED(hr)) {
                ripValue.Reg64 += 2;
                WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                    &ripName, 1, &ripValue);
            }
            return true;
        }

        case WHvRunVpExitReasonMemoryAccess: {
            WHV_MEMORY_ACCESS_CONTEXT& mem = exitCtx.MemoryAccess;
            uint64_t faultGpa = mem.Gpa;

            // Read RIP for memory access
            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            uint64_t rip = 0;
            hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                &ripName, 1, &ripValue);
            if (SUCCEEDED(hr)) rip = ripValue.Reg64;

            // EPT-based system instruction interception (execute access)
            if (mem.AccessInfo.AccessType == 2) { // WHvMemoryAccessExecute = 2
                // First check EptExecHook (registered hooks)
                if (m_eptExecHook && m_eptExecHook->HandleExecFault(faultGpa, rip,
                    m_partition->GetHandle(), vcpuIndex)) {
                    return true;
                }

                // Try SystemSpoofer EPT handlers
                // Read instruction bytes at RIP for decoding
                uint8_t instr[16] = {0};
                if (rip) {
                    __try {
                        memcpy(instr, (void*)rip, min(sizeof(instr), 16));
                    } __except(EXCEPTION_EXECUTE_HANDLER) {
                        memset(instr, 0, sizeof(instr));
                    }
                }

                // Read guest registers for EPT handler context
                WHV_REGISTER_NAME gpNames[] = {
                    WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
                    WHvX64RegisterRbx, WHvX64RegisterRsp, WHvX64RegisterRbp,
                    WHvX64RegisterRsi, WHvX64RegisterRdi,
                    WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterR10,
                    WHvX64RegisterR11, WHvX64RegisterR12, WHvX64RegisterR13,
                    WHvX64RegisterR14, WHvX64RegisterR15
                };
                WHV_REGISTER_VALUE gpVals[16];
                bool haveGprs = false;
                if (SUCCEEDED(WHvGetVirtualProcessorRegisters(m_partition->GetHandle(),
                        vcpuIndex, gpNames, 16, gpVals))) {
                    haveGprs = true;
                }

                CONTEXT eptCtx;
                memset(&eptCtx, 0, sizeof(eptCtx));
                if (haveGprs) {
                    eptCtx.Rax = gpVals[0].Reg64;  eptCtx.Rcx = gpVals[1].Reg64;
                    eptCtx.Rdx = gpVals[2].Reg64;  eptCtx.Rbx = gpVals[3].Reg64;
                    eptCtx.Rsp = gpVals[4].Reg64;  eptCtx.Rbp = gpVals[5].Reg64;
                    eptCtx.Rsi = gpVals[6].Reg64;  eptCtx.Rdi = gpVals[7].Reg64;
                    eptCtx.R8  = gpVals[8].Reg64;  eptCtx.R9  = gpVals[9].Reg64;
                    eptCtx.R10 = gpVals[10].Reg64; eptCtx.R11 = gpVals[11].Reg64;
                    eptCtx.R12 = gpVals[12].Reg64; eptCtx.R13 = gpVals[13].Reg64;
                    eptCtx.R14 = gpVals[14].Reg64; eptCtx.R15 = gpVals[15].Reg64;
                }

                // Try syscall interception (0F 05)
                if (instr[0] == 0x0F && instr[1] == 0x05) {
                    if (m_systemSpoofer && m_systemSpoofer->HandleEptSyscallIntercept(rip, &eptCtx)) {
                        // Advance RIP past SYSCALL instruction
                        ripValue.Reg64 = rip + 2;
                        WHvSetVirtualProcessorRegisters(m_partition->GetHandle(),
                            vcpuIndex, &ripName, 1, &ripValue);
                        return true;
                    }
                }

                // Try RDMSR interception (0F 32)
                if (instr[0] == 0x0F && instr[1] == 0x32) {
                    uint32_t msrNum = (uint32_t)eptCtx.Rcx;
                    uint64_t msrValue = 0;
                    if (m_systemSpoofer && m_systemSpoofer->HandleEptRdmsrIntercept(rip, msrNum, &msrValue, &eptCtx)) {
                        eptCtx.Rax = msrValue & 0xFFFFFFFF;
                        eptCtx.Rdx = (msrValue >> 32) & 0xFFFFFFFF;
                        WHV_REGISTER_NAME msrRegs[2] = {WHvX64RegisterRax, WHvX64RegisterRdx};
                        WHV_REGISTER_VALUE msrVals[2];
                        msrVals[0].Reg64 = eptCtx.Rax;
                        msrVals[1].Reg64 = eptCtx.Rdx;
                        WHvSetVirtualProcessorRegisters(m_partition->GetHandle(),
                            vcpuIndex, msrRegs, 2, msrVals);
                        ripValue.Reg64 = rip + 2;
                        WHvSetVirtualProcessorRegisters(m_partition->GetHandle(),
                            vcpuIndex, &ripName, 1, &ripValue);
                        return true;
                    }
                }

                // Try system instruction interception (SGDT/SIDT/SLDT/STR/XGETBV)
                if (instr[0] == 0x0F && (instr[1] == 0x01 || instr[1] == 0x00)) {
                    uint32_t instrLen = (instr[1] == 0x01) ? 3 : 3;
                    if (m_systemSpoofer && m_systemSpoofer->HandleEptSysInstrIntercept(rip, instr, instrLen, &eptCtx)) {
                        // Write back modified registers
                        WHV_REGISTER_NAME sysRegs[] = {
                            WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
                            WHvX64RegisterRbx, WHvX64RegisterRsp, WHvX64RegisterRbp,
                            WHvX64RegisterRsi, WHvX64RegisterRdi,
                            WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterR10,
                            WHvX64RegisterR11, WHvX64RegisterR12, WHvX64RegisterR13,
                            WHvX64RegisterR14, WHvX64RegisterR15
                        };
                        WHV_REGISTER_VALUE sysVals[16];
                        sysVals[0].Reg64 = eptCtx.Rax;  sysVals[1].Reg64 = eptCtx.Rcx;
                        sysVals[2].Reg64 = eptCtx.Rdx;  sysVals[3].Reg64 = eptCtx.Rbx;
                        sysVals[4].Reg64 = eptCtx.Rsp;  sysVals[5].Reg64 = eptCtx.Rbp;
                        sysVals[6].Reg64 = eptCtx.Rsi;  sysVals[7].Reg64 = eptCtx.Rdi;
                        sysVals[8].Reg64 = eptCtx.R8;   sysVals[9].Reg64 = eptCtx.R9;
                        sysVals[10].Reg64 = eptCtx.R10; sysVals[11].Reg64 = eptCtx.R11;
                        sysVals[12].Reg64 = eptCtx.R12; sysVals[13].Reg64 = eptCtx.R13;
                        sysVals[14].Reg64 = eptCtx.R14; sysVals[15].Reg64 = eptCtx.R15;
                        WHvSetVirtualProcessorRegisters(m_partition->GetHandle(),
                            vcpuIndex, sysRegs, 16, sysVals);
                        ripValue.Reg64 = rip + instrLen;
                        WHvSetVirtualProcessorRegisters(m_partition->GetHandle(),
                            vcpuIndex, &ripName, 1, &ripValue);
                        return true;
                    }
                }
            }

            // Normal on-demand page mapping
            if (m_partition->GetPageTable()) {
                bool isWrite = (mem.AccessInfo.AccessType == 1); // WHvMemoryAccessWrite = 1
                if (m_partition->GetPageTable()->MapDynamicPage(faultGpa, isWrite)) {
                    m_partition->FlushDeferredMaps();
                    return true;
                }
            }

            // Fallback to exit dispatcher
            if (m_exitDispatcher) {
                bool handled = m_exitDispatcher->Dispatch(nullptr, &exitCtx, &rip);
                m_partition->FlushDeferredMaps();
                return handled;
            }
            m_partition->FlushDeferredMaps();
            return false;
        }

        case WHvRunVpExitReasonX64InterruptWindow:
            return true;

        case WHvRunVpExitReasonX64Halt: {
            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                &ripName, 1, &ripValue);
            if (FAILED(hr)) return false;

            if (m_hltPageGpa && ripValue.Reg64 == m_hltPageGpa) {
                return HandleSyscallExit(vcpuIndex);
            }

            ripValue.Reg64 += 1;
            hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                &ripName, 1, &ripValue);
            return SUCCEEDED(hr);
        }

        default:
            m_logger->Trace(LOG_WHP, "Unhandled exit reason %d", reason);
            return false;
    }
}
