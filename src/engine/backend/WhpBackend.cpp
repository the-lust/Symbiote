#include "WhpBackend.h"
#include "whp/Partition.h"
#include "whp/VcpuManager.h"
#include "whp/ExitDispatcher.h"
#include "whp/CpuidHandler.h"
#include "whp/RdtscHandler.h"
#include "whp/MsrHandler.h"
#include "whp/EptExecHook.h"
#include "whp/EptSplitView.h"
#include "whp/EptHook.h"
#include "whp/KernelLock.h"
#include "whp/GuestPageTable.h"
#include <WinHvPlatform.h>
#include <unordered_map>
#include <vector>
#include <algorithm>

static WHV_REGISTER_NAME CpuRegToWHP(CpuReg reg)
{
    static const WHV_REGISTER_NAME map[] = {
        WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx,
        WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterRbp, WHvX64RegisterRsp,
        WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
        WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15,
        WHvX64RegisterRip, WHvX64RegisterRflags,
        WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs, WHvX64RegisterFs,
        WHvX64RegisterGs, WHvX64RegisterSs,
        WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3, WHvX64RegisterCr4,
        WHvX64RegisterDr0, WHvX64RegisterDr1, WHvX64RegisterDr2, WHvX64RegisterDr3,
        WHvX64RegisterDr6, WHvX64RegisterDr7,
    };
    int idx = (int)reg;
    if (idx < 0 || idx >= (int)(sizeof(map)/sizeof(map[0]))) {
        return WHvX64RegisterRax;
    }
    return map[idx];
}

// Serialization format for save/restore:
//   [uint32_t magic = 0xSYMB]
//   [uint32_t regCount]
//   for each reg: [WHV_REGISTER_NAME (8 bytes)] [WHV_REGISTER_VALUE (8 bytes)]
//   [uint32_t memRegionCount]
//   for each mem: [uint64_t gpa] [uint64_t size] [uint32_t flags] [data: 'size' bytes]

static const uint32_t kSaveMagic = 0x424D5953; // "SYMB"

WhpBackend::WhpBackend(Logger* logger)
    : m_logger(logger)
    , m_partition(nullptr)
    , m_vcpuManager(nullptr)
    , m_exitDispatcher(nullptr)
    , m_vcpuIndex(0)
    , m_exitCount(0)
    , m_syscallCount(0)
    , m_running(false)
{
    memset(m_breakpoints, 0, sizeof(m_breakpoints));
    m_breakpointCount = 0;
}

WhpBackend::~WhpBackend()
{
    Stop();
    delete m_vcpuManager;
    delete m_partition;
}

void WhpBackend::WireHandlers(CpuidHandler* cpuid, RdtscHandler* rdtsc, MsrHandler* msr,
                               MagicCpuid* magic, ExceptionHandler* exc, EptExecHook* eptExec,
                               EptSplitView* eptSplit, KernelLock* kernelLock)
{
    (void)cpuid; (void)rdtsc; (void)msr; (void)magic;
    (void)exc; (void)eptExec; (void)eptSplit; (void)kernelLock;
}

bool WhpBackend::Initialize()
{
    return m_partition && m_vcpuManager;
}

bool WhpBackend::Run()
{
    if (!m_vcpuManager) return false;
    m_running = true;
    m_vcpuManager->Run(m_vcpuIndex);
    m_running = false;
    return true;
}

bool WhpBackend::Stop()
{
    if (m_vcpuManager) {
        m_vcpuManager->Stop(m_vcpuIndex);
    }
    m_running = false;
    return true;
}

bool WhpBackend::SingleStep()
{
    if (!m_vcpuManager || !m_partition) return false;

    WHV_REGISTER_NAME rflName = WHvX64RegisterRflags;
    WHV_REGISTER_VALUE rflValue;
    if (!ReadVcpuRegsInternal(&rflName, &rflValue, 1)) return false;

    rflValue.Reg64 |= 0x100;
    if (!WriteVcpuRegsInternal(&rflName, &rflValue, 1)) return false;

    m_running = true;
    WHV_RUN_VP_EXIT_CONTEXT exitCtx;
    HRESULT hr = WHvRunVirtualProcessor(m_partition->GetHandle(), m_vcpuIndex,
        &exitCtx, sizeof(exitCtx));

    rflValue.Reg64 &= ~0x100ULL;
    WriteVcpuRegsInternal(&rflName, &rflValue, 1);

    m_running = false;

    if (SUCCEEDED(hr)) {
        m_exitCount++;
        if (exitCtx.ExitReason == WHvRunVpExitReasonException &&
            exitCtx.VpException.ExceptionType == 0x01) {
            return true;
        }
    }
    return SUCCEEDED(hr);
}

uint64_t WhpBackend::ReadRegister(CpuReg reg)
{
    if (!m_partition) return 0;
    WHV_REGISTER_NAME name = CpuRegToWHP(reg);
    WHV_REGISTER_VALUE value;
    value.Reg64 = 0;
    HRESULT hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(),
        m_vcpuIndex, &name, 1, &value);
    return SUCCEEDED(hr) ? value.Reg64 : 0;
}

bool WhpBackend::WriteRegister(CpuReg reg, uint64_t value)
{
    if (!m_partition) return false;
    WHV_REGISTER_NAME name = CpuRegToWHP(reg);
    WHV_REGISTER_VALUE regValue;
    regValue.Reg64 = value;
    HRESULT hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(),
        m_vcpuIndex, &name, 1, &regValue);
    return SUCCEEDED(hr);
}

bool WhpBackend::ReadMemory(uint64_t addr, void* buf, size_t size)
{
    if (!buf || size == 0) return false;
    __try {
        memcpy(buf, (const void*)addr, size);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WhpBackend::WriteMemory(uint64_t addr, const void* buf, size_t size)
{
    if (!buf || size == 0) return false;
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)addr, size, PAGE_READWRITE, &oldProtect))
        return false;
    __try {
        memcpy((void*)addr, buf, size);
        VirtualProtect((LPVOID)addr, size, oldProtect, &oldProtect);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualProtect((LPVOID)addr, size, oldProtect, &oldProtect);
        return false;
    }
}

uint64_t WhpBackend::GetPhysicalAddress(uint64_t virtualAddr)
{
    return virtualAddr;
}

bool WhpBackend::MapGuestMemory(uint64_t gpa, void* hostVa, size_t size, bool exec, bool write)
{
    if (!m_partition) return false;
    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead;
    if (write) flags |= WHvMapGpaRangeFlagWrite;
    if (exec) flags |= WHvMapGpaRangeFlagExecute;
    return SUCCEEDED(WHvMapGpaRange(m_partition->GetHandle(), hostVa, gpa, size, flags));
}

bool WhpBackend::UnmapGuestMemory(uint64_t gpa, size_t size)
{
    if (!m_partition) return false;
    return SUCCEEDED(WHvUnmapGpaRange(m_partition->GetHandle(), gpa, size));
}

bool WhpBackend::SetBreakpoint(uint64_t addr)
{
    if (m_breakpointCount >= MAX_BREAKPOINTS || !addr) return false;

    for (uint32_t i = 0; i < m_breakpointCount; i++) {
        if (m_breakpoints[i].address == addr) return true;
    }

    m_breakpoints[m_breakpointCount].address = addr;
    m_breakpoints[m_breakpointCount].active = true;

    uint32_t slot = m_breakpointCount;
    m_breakpointCount++;

    if (slot < 4) {
        WriteRegister((CpuReg)((int)CpuReg::DR0 + slot), addr);
        uint64_t dr7 = ReadRegister(CpuReg::DR7);
        dr7 |= (1ULL << (slot * 2));
        dr7 &= ~(3ULL << (16 + slot * 4));
        WriteRegister(CpuReg::DR7, dr7);
    }

    return true;
}

bool WhpBackend::RemoveBreakpoint(uint64_t addr)
{
    for (uint32_t i = 0; i < m_breakpointCount; i++) {
        if (m_breakpoints[i].address == addr) {
            if (i < 4) {
                WriteRegister((CpuReg)((int)CpuReg::DR0 + i), 0);
                uint64_t dr7 = ReadRegister(CpuReg::DR7);
                dr7 &= ~(3ULL << (i * 2));
                WriteRegister(CpuReg::DR7, dr7);
            }
            for (uint32_t j = i; j < m_breakpointCount - 1; j++) {
                m_breakpoints[j] = m_breakpoints[j + 1];
            }
            m_breakpointCount--;
            m_breakpoints[m_breakpointCount].address = 0;
            m_breakpoints[m_breakpointCount].active = false;
            return true;
        }
    }
    return false;
}

bool WhpBackend::HasBreakpoint(uint64_t addr) const
{
    for (uint32_t i = 0; i < m_breakpointCount; i++) {
        if (m_breakpoints[i].address == addr && m_breakpoints[i].active)
            return true;
    }
    return false;
}

bool WhpBackend::IsRunning() const
{
    return m_running;
}

uint64_t WhpBackend::GetExitCount() const
{
    return m_exitCount;
}

uint64_t WhpBackend::GetSyscallCount() const
{
    return m_syscallCount;
}

bool WhpBackend::SaveState(std::vector<uint8_t>& buffer)
{
    if (!m_partition) return false;

    buffer.clear();
    auto put32 = [&](uint32_t v) {
        buffer.insert(buffer.end(), (uint8_t*)&v, (uint8_t*)&v + 4);
    };
    auto put64 = [&](uint64_t v) {
        buffer.insert(buffer.end(), (uint8_t*)&v, (uint8_t*)&v + 8);
    };

    put32(kSaveMagic);

    WHV_REGISTER_NAME allRegs[] = {
        WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx,
        WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterRbp, WHvX64RegisterRsp,
        WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
        WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15,
        WHvX64RegisterRip, WHvX64RegisterRflags,
        WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs, WHvX64RegisterFs,
        WHvX64RegisterGs, WHvX64RegisterSs,
        WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3, WHvX64RegisterCr4,
        WHvX64RegisterDr0, WHvX64RegisterDr1, WHvX64RegisterDr2, WHvX64RegisterDr3,
        WHvX64RegisterDr6, WHvX64RegisterDr7,
        WHvX64RegisterEfer, WHvX64RegisterStar, WHvX64RegisterLstar,
        WHvX64RegisterCstar, WHvX64RegisterSfmask,
    };
    uint32_t regCount = sizeof(allRegs) / sizeof(allRegs[0]);
    put32(regCount);

    WHV_REGISTER_VALUE regValues[64];
    HRESULT hr = WHvGetVirtualProcessorRegisters(m_partition->GetHandle(),
        m_vcpuIndex, allRegs, regCount, regValues);
    if (FAILED(hr)) return false;

    for (uint32_t i = 0; i < regCount; i++) {
        put64((uint64_t)allRegs[i]);
        put64(regValues[i].Reg64);
    }

    auto& trackedRegions = m_partition->GetTrackedMemoryRegions();
    put32((uint32_t)trackedRegions.size());

    for (auto& tr : trackedRegions) {
        put64(tr.gpa);
        put64(tr.size);
        put32(tr.flags);

        uint64_t offset = 0;
        while (offset < tr.size) {
            uint64_t chunkSize = min(tr.size - offset, (uint64_t)4096);
            uint8_t chunk[4096];
            WHV_GUEST_PHYSICAL_ADDRESS gpa = tr.gpa + offset;
            WHV_ACCESS_GPA_CONTROLS controls;
            controls.AsUINT64 = 0;
            controls.CacheType = WHvCacheTypeUncached;
            controls.InputVtl.AsUINT8 = 0;
            hr = WHvReadGpaRange(m_partition->GetHandle(), m_vcpuIndex,
                gpa, controls, chunk, (uint32_t)chunkSize);
            if (FAILED(hr)) memset(chunk, 0, chunkSize);
            buffer.insert(buffer.end(), chunk, chunk + chunkSize);
            offset += chunkSize;
        }
    }

    return true;
}

bool WhpBackend::RestoreState(const std::vector<uint8_t>& buffer)
{
    if (!m_partition || buffer.size() < 8) return false;

    size_t offset = 0;
    auto read32 = [&]() -> uint32_t {
        if (offset + 4 > buffer.size()) return 0;
        uint32_t v;
        memcpy(&v, buffer.data() + offset, 4);
        offset += 4;
        return v;
    };
    auto read64 = [&]() -> uint64_t {
        if (offset + 8 > buffer.size()) return 0;
        uint64_t v;
        memcpy(&v, buffer.data() + offset, 8);
        offset += 8;
        return v;
    };

    if (read32() != kSaveMagic) return false;

    uint32_t regCount = read32();
    if (regCount > 64 || offset + regCount * 16 > buffer.size()) return false;

    WHV_REGISTER_NAME names[64];
    WHV_REGISTER_VALUE values[64];
    for (uint32_t i = 0; i < regCount; i++) {
        names[i] = (WHV_REGISTER_NAME)read64();
        values[i].Reg64 = read64();
    }

    HRESULT hr = WHvSetVirtualProcessorRegisters(m_partition->GetHandle(),
        m_vcpuIndex, names, regCount, values);
    if (FAILED(hr)) return false;

    uint32_t memCount = read32();
    for (uint32_t i = 0; i < memCount; i++) {
        uint64_t gpa = read64();
        uint64_t size = read64();
        uint32_t flags = read32();
        if (offset + size > buffer.size()) return false;

        for (uint64_t chunkOffset = 0; chunkOffset < size; ) {
            uint64_t chunkSize = min(size - chunkOffset, (uint64_t)4096);
            std::vector<uint8_t> chunk(chunkSize);
            memcpy(chunk.data(), buffer.data() + offset, (size_t)chunkSize);

            void* hostVa = VirtualAlloc(NULL, (SIZE_T)chunkSize,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (hostVa) {
                memcpy(hostVa, chunk.data(), (size_t)chunkSize);
                WHV_MAP_GPA_RANGE_FLAGS f = (WHV_MAP_GPA_RANGE_FLAGS)(uint32_t)flags;
                WHvMapGpaRange(m_partition->GetHandle(), hostVa,
                    gpa + chunkOffset, chunkSize, f);
            }

            offset += (size_t)chunkSize;
            chunkOffset += chunkSize;
        }
    }

    return true;
}

bool WhpBackend::ReadVcpuRegsInternal(WHV_REGISTER_NAME* names, WHV_REGISTER_VALUE* values, uint32_t count)
{
    if (!m_partition) return false;
    return SUCCEEDED(WHvGetVirtualProcessorRegisters(
        m_partition->GetHandle(), m_vcpuIndex, names, count, values));
}

bool WhpBackend::WriteVcpuRegsInternal(WHV_REGISTER_NAME* names, WHV_REGISTER_VALUE* values, uint32_t count)
{
    if (!m_partition) return false;
    return SUCCEEDED(WHvSetVirtualProcessorRegisters(
        m_partition->GetHandle(), m_vcpuIndex, names, count, values));
}
