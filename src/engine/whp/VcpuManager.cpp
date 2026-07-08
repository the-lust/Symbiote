#include "VcpuManager.h"
#include "Partition.h"
#include "GuestPageTable.h"
#include "ExitDispatcher.h"
#include "CpuidHandler.h"
#include "RdtscHandler.h"
#include "MsrHandler.h"
#include "MagicCpuid.h"
#include "ExceptionHandler.h"
#include <cstring>
#include <intrin.h>

#pragma comment(lib, "WinHvPlatform.lib")

VcpuManager::VcpuManager(Logger* logger, Partition* partition, ExitDispatcher* exitDispatcher,
                         CpuidHandler* cpuidHandler, RdtscHandler* rdtscHandler,
                         MsrHandler* msrHandler)
    : m_logger(logger), m_partition(partition), m_exitDispatcher(exitDispatcher),
      m_cpuidHandler(cpuidHandler), m_rdtscHandler(rdtscHandler),
      m_msrHandler(msrHandler),
      m_magicCpuid(nullptr), m_syscallHandler(nullptr),
      m_exceptionHandler(nullptr),
      m_vcpuCount(0), m_bootCodeLoaded(false)
{
    memset(m_vcpus, 0, sizeof(m_vcpus));
}

VcpuManager::~VcpuManager()
{
    for (uint32_t i = 0; i < m_vcpuCount; i++) {
        Stop(i);
    }
    for (auto& kv : m_trampolines) {
        DWORD old;
        VirtualProtect((LPVOID)kv.first, 1, PAGE_EXECUTE_READWRITE, &old);
        *(uint8_t*)kv.first = kv.second.originalByte;
        VirtualProtect((LPVOID)kv.first, 1, old, &old);
    }
    m_trampolines.clear();
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

    while (m_vcpus[vcpuIndex].running) {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;
        HRESULT hr = WHvRunVirtualProcessor(m_partition->GetHandle(), vcpuIndex,
            &exitCtx, sizeof(exitCtx));

        if (FAILED(hr)) {
            m_logger->Trace(LOG_ERROR, "WHvRunVirtualProcessor failed: 0x%08X", hr);
            break;
        }

        m_vcpus[vcpuIndex].exitCtx = exitCtx;

        if (!m_trampolines.empty()) {
            for (auto& kv : m_trampolines) {
                DWORD old;
                VirtualProtect((LPVOID)kv.first, 1, PAGE_EXECUTE_READWRITE, &old);
                *(uint8_t*)kv.first = 0xCC;
                VirtualProtect((LPVOID)kv.first, 1, old, &old);
            }
            m_trampolines.clear();
        }

        if (!HandleExit(vcpuIndex)) {
            m_logger->Trace(LOG_WHP, "VCPU %u unhandled exit at reason=%d",
                vcpuIndex, exitCtx.ExitReason);
            break;
        }
    }

    m_logger->Trace(LOG_INFO, "VCPU %u stopped", vcpuIndex);
    return true;
}

bool VcpuManager::BootstrapFromContext(uint32_t vcpuIndex, const ThreadContext& ctx, GuestPageTable* pageTable)
{
    if (vcpuIndex >= m_vcpuCount) {
        if (!CreateVcpu(vcpuIndex)) return false;
    }

    // Set up LSTAR→HLT for syscall interception (required for guest to make syscalls)
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

    m_vcpus[vcpuIndex].running = true;
    m_logger->Trace(LOG_INFO, "Bootstrap: VCPU %u entered with CR3=0x%llX, RIP=0x%llX",
        vcpuIndex, pageTable ? pageTable->GetPml4Gpa() : 0, ctx.rip);

    // Main VCPU loop
    while (m_vcpus[vcpuIndex].running) {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;
        HRESULT hr = WHvRunVirtualProcessor(m_partition->GetHandle(), vcpuIndex,
            &exitCtx, sizeof(exitCtx));

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
    crValues[2].Reg64 = 0x1706F8;   // PAE | PGE | OSFXSR | OSXMMEXCPT | VMXE | SMXE | OSXSAVE
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

    uint64_t result = 0;
    bool handled = m_syscallDispatch.DispatchRawSyscall(syscallNum, args, result);

    if (!handled) {
        // Try forwarding to host ntdll
        handled = m_syscallDispatch.ForwardSyscall(syscallNum, args, guestRsp, result);
    }

    if (!handled) {
        result = 0xC0000001;
        m_logger->Trace(LOG_WHP, "VCPU %u: unhandled syscall 0x%X", vcpuIndex, syscallNum);
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

// ─── #BP / #DB exception handling ──────────────────────────────────────

bool VcpuManager::HandleVpBreakpoint(uint32_t vcpuIndex, uint64_t rip)
{
    PatchEntryInfo patch;
    if (!SystemSpoofer::LookupPatch(rip, patch)) {
        WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
        WHV_REGISTER_VALUE ripValue;
        ripValue.Reg64 = rip + 1;
        return WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1);
    }

    switch (patch.type) {
        case PatchType::SYSCALL: {
            WHV_REGISTER_NAME names[6] = {
                WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
                WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterRip
            };
            WHV_REGISTER_VALUE values[6];
            if (!ReadVcpuRegs(vcpuIndex, names, values, 6))
                return false;

            uint32_t syscallNum = (uint32_t)values[0].Reg64;
            uint64_t args[4] = {
                values[1].Reg64,
                values[2].Reg64,
                values[3].Reg64,
                values[4].Reg64
            };
            uint64_t result = 0;

            if (m_syscallDispatch.DispatchRawSyscall(syscallNum, args, result)) {
                values[0].Reg64 = result;
                values[5].Reg64 = rip + 2;

                WHV_REGISTER_NAME rflName = WHvX64RegisterRflags;
                WHV_REGISTER_VALUE rflValue;
                if (ReadVcpuRegs(vcpuIndex, &rflName, &rflValue, 1)) {
                    rflValue.Reg64 &= ~0x100;
                    WriteVcpuRegs(vcpuIndex, &rflName, &rflValue, 1);
                }

                return WriteVcpuRegs(vcpuIndex, names, values, 6);
            }

            DWORD old;
            VirtualProtect((LPVOID)rip, 1, PAGE_EXECUTE_READWRITE, &old);
            *(uint8_t*)rip = 0x0F;
            VirtualProtect((LPVOID)rip, 1, old, &old);

            TrampolineEntry te;
            te.address = rip;
            te.originalByte = 0x0F;
            te.instrLen = 2;
            m_trampolines[rip] = te;

            values[5].Reg64 = rip;
            return WriteVcpuRegs(vcpuIndex, &names[5], &values[5], 1);
        }

        case PatchType::RDMSR: {
            WHV_REGISTER_NAME names[3] = { WHvX64RegisterRcx, WHvX64RegisterRax, WHvX64RegisterRdx };
            WHV_REGISTER_VALUE values[3];
            if (!ReadVcpuRegs(vcpuIndex, names, values, 3))
                return false;

            uint32_t msrIndex = (uint32_t)values[0].Reg64;
            uint64_t msrValue = 0;

            if (m_syscallDispatch.SpoofRdmsr(msrIndex, msrValue)) {
                values[1].Reg64 = msrValue & 0xFFFFFFFF;
                values[2].Reg64 = (msrValue >> 32) & 0xFFFFFFFF;

                WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
                WHV_REGISTER_VALUE ripValue;
                ripValue.Reg64 = rip + 2;
                if (!WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1))
                    return false;

                return WriteVcpuRegs(vcpuIndex, names, values, 3);
            }

            DWORD old;
            VirtualProtect((LPVOID)rip, 1, PAGE_EXECUTE_READWRITE, &old);
            *(uint8_t*)rip = 0x0F;
            VirtualProtect((LPVOID)rip, 1, old, &old);

            TrampolineEntry te;
            te.address = rip;
            te.originalByte = 0x0F;
            te.instrLen = 2;
            m_trampolines[rip] = te;

            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            ripValue.Reg64 = rip;
            return WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1);
        }

        case PatchType::XGETBV: {
            WHV_REGISTER_NAME names[3] = { WHvX64RegisterRcx, WHvX64RegisterRax, WHvX64RegisterRdx };
            WHV_REGISTER_VALUE values[3];
            if (!ReadVcpuRegs(vcpuIndex, names, values, 3)) return false;

            uint32_t xcr = (uint32_t)values[0].Reg64;
            if (xcr == 0) {
                values[1].Reg64 = 0x07;
                values[2].Reg64 = 0;
            } else {
                values[1].Reg64 = 0;
                values[2].Reg64 = 0;
            }
            if (!WriteVcpuRegs(vcpuIndex, names, values, 3)) return false;

            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            ripValue.Reg64 = rip + 3;
            return WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1);
        }

        default: {
            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            ripValue.Reg64 = rip + patch.instrLen;
            return WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1);
        }
    }
}

bool VcpuManager::HandleVpSingleStep(uint32_t, uint64_t)
{
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

        if (exc.ExceptionType == 0x03) {
            return HandleVpBreakpoint(vcpuIndex, rip);
        }

        if (exc.ExceptionType == 0x01) {
            return HandleVpSingleStep(vcpuIndex, rip);
        }

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
                    m_logger->Trace(LOG_WARNING, "VCPU %u: WRMSR 0x%X unhandled, skiping", vcpuIndex, msrNumber);
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
            // EPT violation — try on-demand page mapping
            WHV_MEMORY_ACCESS_CONTEXT& mem = exitCtx.MemoryAccess;
            uint64_t faultGpa = mem.Gpa;

            if (m_partition->GetPageTable()) {
                bool isWrite = mem.AccessInfo.AccessType == WHvMemoryAccessWrite;
                if (m_partition->GetPageTable()->MapDynamicPage(faultGpa, isWrite)) {
                    // Retry the instruction that caused the fault
                    return true;
                }
            }

            if (m_exitDispatcher) {
                WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
                WHV_REGISTER_VALUE ripValue;
                uint64_t rip = 0;
                hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                    &ripName, 1, &ripValue);
                if (SUCCEEDED(hr)) rip = ripValue.Reg64;
                return m_exitDispatcher->Dispatch(nullptr, &exitCtx, &rip);
            }
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
