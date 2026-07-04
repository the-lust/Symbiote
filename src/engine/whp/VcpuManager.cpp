#include "VcpuManager.h"
#include "Partition.h"
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

    // Restore any pending trampolines
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

    // Initialize syscall dispatch on first VCPU
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

    m_logger->Trace(LOG_INFO, "VCPU %u starting execution", vcpuIndex);

    while (m_vcpus[vcpuIndex].running) {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;
        HRESULT hr = WHvRunVirtualProcessor(m_partition->GetHandle(), vcpuIndex,
            &exitCtx, sizeof(exitCtx));

        if (FAILED(hr)) {
            m_logger->Trace(LOG_ERROR, "WHvRunVirtualProcessor failed: 0x%08X", hr);
            break;
        }

        m_vcpus[vcpuIndex].exitCtx = exitCtx;

        // Process any pending trampoline re-patches before each exit
        if (!m_trampolines.empty()) {
            for (auto& kv : m_trampolines) {
                DWORD old;
                VirtualProtect((LPVOID)kv.first, 1, PAGE_EXECUTE_READWRITE, &old);
                *(uint8_t*)kv.first = 0xCC;
                VirtualProtect((LPVOID)kv.first, 1, old, &old);
            }
            m_logger->Trace(LOG_WHP, "VCPU %u: re-patched %zu trampolines", vcpuIndex, m_trampolines.size());
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

void VcpuManager::Stop(uint32_t vcpuIndex)
{
    if (vcpuIndex < MAX_VCPU && m_vcpus[vcpuIndex].running) {
        m_vcpus[vcpuIndex].running = false;
        WHvCancelRunVirtualProcessor(m_partition->GetHandle(), vcpuIndex, 0);
    }
}

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
    // Map at GPA 0x100000 (above low 64K) to avoid conflict with EPT hooks at
    // GPA 0x0000 (IDT), 0x0400 (BDA), 0x1000 (GDT).
    if (!m_partition->MapGpaRange(bootCode, 0x100000, 0x10000, flags)) {
        m_logger->Trace(LOG_ERROR, "Failed to map boot code at GPA 0x100000");
        m_partition->FreeGuestMemory(bootCode);
        return false;
    }

    uint64_t* gdt = (uint64_t*)(code + 0x800);
    gdt[0] = 0x0000000000000000ULL;
    gdt[1] = 0x00AF9B000000FFFFULL;
    gdt[2] = 0x00CF93000000FFFFULL;

    m_logger->Trace(LOG_INFO, "Boot code loaded at GPA 0x101000: HLT");
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
    page[0] = 0xF4; // HLT instruction
    page[1] = 0xEB; // JMP $-1 (safety: if HLT doesn't exit, spin)
    page[2] = 0xFF;

    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute);
    m_hltPageGpa = 0x12000; // Above boot code (0x100000) + GDT (0x10800)
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

    // STAR: bits 47:32 = SYSCALL CS (0x10, ring-0 64-bit code)
    //       bits 63:48 = SYSRET CS (0x18)
    names[count] = WHvX64RegisterStar;
    values[count].Reg64 = (0x18ULL << 48) | (0x10ULL << 32);
    count++;

    // LSTAR: GPA of HLT page — every guest SYSCALL lands here, HLT causes VM exit
    names[count] = WHvX64RegisterLstar;
    values[count].Reg64 = m_hltPageGpa;
    count++;

    // SF_MASK: clear IF, DF, TF, AC, IOPL on SYSCALL
    names[count] = WHvX64RegisterSfmask;
    values[count].Reg64 = 0x4700; // IF(9)=0x200, DF(10)=0x400, TF(8)=0x100, IOPL(12-13)=0x3000, AC(18)=0x40000 → 0x47700
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
    // Read RAX (syscall number), RCX (return address), args in RDX, R8, R9
    // R11 holds saved RFLAGS from SYSCALL instruction
    WHV_REGISTER_NAME names[6] = {
        WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
        WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterR11
    };
    WHV_REGISTER_VALUE values[6];
    if (!ReadVcpuRegs(vcpuIndex, names, values, 6))
        return false;

    uint32_t syscallNum = (uint32_t)values[0].Reg64;
    uint64_t returnAddr = values[1].Reg64;  // RCX = original RIP+2
    uint64_t savedRfl = values[5].Reg64;    // R11 = saved RFLAGS

    uint64_t args[4] = {
        values[1].Reg64, // RCX → actually this is returnAddr, not arg1
        values[2].Reg64, // RDX → arg2 (arg1 on x64 calling convention)
        values[3].Reg64, // R8  → arg3 (arg2)
        values[4].Reg64  // R9  → arg4 (arg3)
    };

    // On x64 Windows SYSCALL convention:
    // RCX = return address (after SYSCALL instruction), NOT arg1
    // RDX = arg1, R8 = arg2, R9 = arg3
    // But SYSCALL saves RCX=RIP and then clobbers RCX... 
    // Wait — SYSCALL sets RCX = return address. Args passed to SYSCALL
    // are in RCX, RDX, R8, R9 (Windows x64 calling convention).
    // After SYSCALL, RCX becomes the return address, so the original RCX
    // (arg1) is lost. This is why ntdll stubs move R10 to RCX:
    //   mov r10, rcx   ; save arg1
    //   mov eax, N      ; syscall number
    //   syscall         ; RCX = return addr, RAX = result
    //   ret
    // So the REAL arg1 is in R10, not RCX.
    // But in our LSTAR->HLT approach, we catch the SYSCALL immediately,
    // so the real args at SYSCALL time are:
    //   RAX = syscall number (from mov eax, N)
    //   RCX = return address (set by SYSCALL)
    //   RDX = arg2 (saved by ntdll stub from original RCX)
    //   R8  = arg3
    //   R9  = arg4
    //   R10 = arg1 (saved by ntdll stub from original RCX)
    //   [stack] = arg5+

    WHV_REGISTER_NAME r10Name = WHvX64RegisterR10;
    WHV_REGISTER_VALUE r10Value;
    if (!ReadVcpuRegs(vcpuIndex, &r10Name, &r10Value, 1))
        args[0] = 0;
    else
        args[0] = r10Value.Reg64;  // R10 = original RCX = arg1

    // Also read stack args for args 5+ (RSP + offset for shadow space)
    // For now, only handle up to 4 args (most syscalls use ≤4)

    m_logger->Trace(LOG_WHP, "VCPU %u: SYSCALL 0x%X from RIP 0x%llX (RA=%llX)",
        vcpuIndex, syscallNum, returnAddr - 2, returnAddr);

    uint64_t result = 0;
    bool handled = m_syscallDispatch.DispatchRawSyscall(syscallNum, args, result);

    if (!handled) {
        // Not spoofed — return STATUS_NOT_IMPLEMENTED
        result = 0xC0000001; // STATUS_NOT_IMPLEMENTED
        m_logger->Trace(LOG_WHP, "VCPU %u: unhandled syscall 0x%X", vcpuIndex, syscallNum);
    }

    // Set RAX = result, RIP = return address, restore RFLAGS from R11
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
        // Not our patch — skip this #BP
        WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
        WHV_REGISTER_VALUE ripValue;
        ripValue.Reg64 = rip + 1;
        return WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1);
    }

    switch (patch.type) {
        case PatchType::SYSCALL: {
            // Read registers for syscall dispatch
            WHV_REGISTER_NAME names[6] = {
                WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
                WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterRip
            };
            WHV_REGISTER_VALUE values[6];
            if (!ReadVcpuRegs(vcpuIndex, names, values, 6))
                return false;

            uint32_t syscallNum = (uint32_t)values[0].Reg64;
            uint64_t args[4] = {
                values[1].Reg64, // RCX → arg1
                values[2].Reg64, // RDX → arg2
                values[3].Reg64, // R8  → arg3
                values[4].Reg64  // R9  → arg4
            };
            uint64_t result = 0;

            if (m_syscallDispatch.DispatchRawSyscall(syscallNum, args, result)) {
                // Spoofed — advance RIP past syscall, set result in RAX
                values[0].Reg64 = result;
                values[5].Reg64 = rip + 2; // syscall = 2 bytes

                // Clear RFLAGS.TF if somehow set
                WHV_REGISTER_NAME rflName = WHvX64RegisterRflags;
                WHV_REGISTER_VALUE rflValue;
                if (ReadVcpuRegs(vcpuIndex, &rflName, &rflValue, 1)) {
                    rflValue.Reg64 &= ~0x100; // Clear TF
                    WriteVcpuRegs(vcpuIndex, &rflName, &rflValue, 1);
                }

                return WriteVcpuRegs(vcpuIndex, names, values, 6);
            }

            // Not spoofed — passthrough: restore byte, advance RIP, re-patch on next exit
            DWORD old;
            VirtualProtect((LPVOID)rip, 1, PAGE_EXECUTE_READWRITE, &old);
            *(uint8_t*)rip = 0x0F; // Restore original first byte of syscall (0F 05)
            VirtualProtect((LPVOID)rip, 1, old, &old);

            TrampolineEntry te;
            te.address = rip;
            te.originalByte = 0x0F;
            te.instrLen = 2;
            m_trampolines[rip] = te;

            // Advance RIP to execute the real syscall
            values[5].Reg64 = rip;
            return WriteVcpuRegs(vcpuIndex, &names[5], &values[5], 1);
        }

        case PatchType::RDMSR: {
            // Read registers for RDMSR dispatch
            WHV_REGISTER_NAME names[3] = { WHvX64RegisterRcx, WHvX64RegisterRax, WHvX64RegisterRdx };
            WHV_REGISTER_VALUE values[3];
            if (!ReadVcpuRegs(vcpuIndex, names, values, 3))
                return false;

            uint32_t msrIndex = (uint32_t)values[0].Reg64;
            uint64_t msrValue = 0;

            if (m_syscallDispatch.SpoofRdmsr(msrIndex, msrValue)) {
                // Spoofed — return value in EAX:EDX
                values[1].Reg64 = msrValue & 0xFFFFFFFF;
                values[2].Reg64 = (msrValue >> 32) & 0xFFFFFFFF;

                WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
                WHV_REGISTER_VALUE ripValue;
                ripValue.Reg64 = rip + 2; // RDMSR = 2 bytes
                if (!WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1))
                    return false;

                return WriteVcpuRegs(vcpuIndex, names, values, 3);
            }

            // Not spoofed — passthrough
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
                values[1].Reg64 = 0x07; // XCR0 low = x87|SSE|AVX
                values[2].Reg64 = 0;    // XCR0 high
            } else {
                values[1].Reg64 = 0;
                values[2].Reg64 = 0;
            }
            if (!WriteVcpuRegs(vcpuIndex, names, values, 3)) return false;

            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            ripValue.Reg64 = rip + 3; // XGETBV = 3 bytes
            return WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1);
        }

        default: {
            // SGDT, SIDT, SLDT, STR — handled by host VEH, just skip on guest
            WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
            WHV_REGISTER_VALUE ripValue;
            ripValue.Reg64 = rip + patch.instrLen;
            return WriteVcpuRegs(vcpuIndex, &ripName, &ripValue, 1);
        }
    }
}

bool VcpuManager::HandleVpSingleStep(uint32_t, uint64_t)
{
    // #DB trap — currently unused since syscall clears TF.
    // Reserved for future use with instructions that don't clear TF.
    return false;
}

// ─── Exit handler ──────────────────────────────────────────────────────

bool VcpuManager::HandleExit(uint32_t vcpuIndex)
{
    WHV_RUN_VP_EXIT_CONTEXT& exitCtx = m_vcpus[vcpuIndex].exitCtx;
    WHV_RUN_VP_EXIT_REASON reason = exitCtx.ExitReason;
    HRESULT hr;

    // Handle exceptions first — #BP and #DB are handled here
    if (reason == WHvRunVpExitReasonException) {
        WHV_VP_EXCEPTION_CONTEXT& exc = exitCtx.VpException;

        uint64_t rip = 0;
        WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
        WHV_REGISTER_VALUE ripValue;
        hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
            &ripName, 1, &ripValue);
        if (SUCCEEDED(hr)) rip = ripValue.Reg64;

        // #BP (0x03) — breakpoint from patched syscall/RDMSR/SGDT/etc
        if (exc.ExceptionType == 0x03) {
            return HandleVpBreakpoint(vcpuIndex, rip);
        }

        // #DB (0x01) — single-step trampoline
        if (exc.ExceptionType == 0x01) {
            return HandleVpSingleStep(vcpuIndex, rip);
        }

        // Forward to ExceptionHandler for #GP, #UD, etc.
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
            if (m_exitDispatcher) {
                WHV_REGISTER_NAME ripName = WHvX64RegisterRip;
                WHV_REGISTER_VALUE ripValue;
                uint64_t rip = 0;
                hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(), vcpuIndex,
                    &ripName, 1, &ripValue);
                if (SUCCEEDED(hr)) {
                    rip = ripValue.Reg64;
                }
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

            // If RIP is at our HLT page GPA, this is a SYSCALL via LSTAR->HLT
            if (m_hltPageGpa && ripValue.Reg64 == m_hltPageGpa) {
                return HandleSyscallExit(vcpuIndex);
            }

            // Normal HLT — just advance past it
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
