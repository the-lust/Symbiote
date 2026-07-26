#include "Partition.h"
#include "CpuidHandler.h"
#include "GuestPageTable.h"
#include <winerror.h>
#include <algorithm>


Partition::Partition(Logger* logger)
    : m_logger(logger), m_handle(nullptr), m_initialized(false),
      m_vcpuCount(0), m_guestPageTable(nullptr)
{
}

Partition::~Partition()
{
    Destroy();
}

bool Partition::Create()
{
    HRESULT hr = WHvCreatePartition(&m_handle);
    if (FAILED(hr) || !m_handle) {
        m_logger->Trace(LOG_ERROR, "WHvCreatePartition failed: 0x%08X", hr);
        return false;
    }
    m_logger->Trace(LOG_WHP, "Partition created: handle=0x%p", m_handle);

    // Set MSR exit bitmap to intercept Hyper-V TLFS MSRs + standard MSRs
    if (!SetupMsrBitmap()) {
        m_logger->Trace(LOG_WARNING, "MSR bitmap setup failed - MSR interception may be limited");
    }

    // Set exception exit bitmap for #BP (syscall intercept) and #DB (single-step trampoline)
    if (!SetupExceptionBitmap()) {
        m_logger->Trace(LOG_WARNING, "Exception bitmap setup failed - syscall intercept may be limited");
    }

    return true;
}

bool Partition::SetupMsrBitmap()
{
    // WHV_X64_MSR_EXIT_BITMAP is a 64-bit union with these bit fields:
    //   bit 0: UnhandledMsrs       — intercept all MSRs not explicitly listed
    //   bit 1: TscMsrWrite         — WRMSR to 0x10
    //   bit 2: TscMsrRead          — RDMSR from 0x10
    //   bit 3: ApicBaseMsrWrite    — WRMSR to 0x1B
    //   bit 4: MiscEnableMsrRead   — RDMSR from 0x1A0
    //   bit 5: McUpdatePatchLevelMsrRead — RDMSR from 0x8B (microcode rev)
    // Extended-range MSRs (0xC0000000-0xC0001FFF: EFER, LSTAR, STAR, CSTAR, SFMASK)
    // are NOT in this bitmap; they fall through to UnhandledMsrs handling.
    WHV_X64_MSR_EXIT_BITMAP bitmap;
    bitmap.AsUINT64 = 0;
    bitmap.UnhandledMsrs = 1;            // intercept ALL MSRs not explicitly listed
    bitmap.TscMsrRead = 1;               // 0x10 RDTSC: timing checks
    bitmap.TscMsrWrite = 1;              // 0x10 WRMSR TSC
    bitmap.ApicBaseMsrWrite = 1;         // 0x1B APIC_BASE writes
    bitmap.MiscEnableMsrRead = 1;        // 0x1A0 MISC_ENABLE reads
    bitmap.McUpdatePatchLevelMsrRead = 1; // 0x8B BIOS_SIGN_ID (microcode rev check)

    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeX64MsrExitBitmap,
        &bitmap, sizeof(bitmap));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(X64MsrExitBitmap) failed: 0x%08X", hr);
        return false;
    }

    // With UnhandledMsrs=1, every MSR that doesn't match the explicit bitmap
    // causes a VM exit. The VCPU exit handler (VcpuManager) dispatches to
    // MsrHandler for all extended-range MSRs (EFER, LSTAR, STAR, CSTAR, SFMASK)
    // and any other intercepted MSRs (APIC_BASE read, FEATURE_CONTROL, MTRR_*).
    // MsrHandler's IsValidMsr() injects #GP for truly invalid MSRs.

    m_logger->Trace(LOG_WHP, "MSR exit bitmap configured: UnhandledMsrs=1 + explicit whitelist (TSC, APIC_BASE write, MISC_ENABLE, MC_UPDATE)");
    return true;
}

bool Partition::SetupExceptionBitmap()
{
    if (!m_handle) return false;

    // Enable VM exits on exceptions we need to handle.
    // Bitmap layout: bit N corresponds to exception vector N.
    uint64_t exceptionBitmap = 0;
    exceptionBitmap |= (1ULL << 0x01); // #DB - single step (trampoline restore, exec hook step)
    exceptionBitmap |= (1ULL << 0x03); // #BP - breakpoint (syscall/RDMSR intercept)
    exceptionBitmap |= (1ULL << 0x06); // #UD - invalid opcode (catch malicious decode)
    exceptionBitmap |= (1ULL << 0x0E); // #PF - page fault (EPT violation fallback)
    exceptionBitmap |= (1ULL << 0x10); // #MF - x87 FP error
    exceptionBitmap |= (1ULL << 0x13); // #XM - SIMD FP error

    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeExceptionExitBitmap,
        &exceptionBitmap, sizeof(exceptionBitmap));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(ExceptionExitBitmap) failed: 0x%08X", hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "Exception exit bitmap configured: #DB #BP #UD #PF #MF #XM");
    return true;
}

bool Partition::SetupCpuidResultList(CpuidHandler* cpuidHandler)
{
    if (!m_handle) return false;

    // Pre-populate hypervisor leaves + leaf 1 ECX[31]
    WHV_X64_CPUID_RESULT results[32];
    int count = 0;

    auto add = [&](uint32_t leaf, uint32_t subleaf, uint32_t eax,
                   uint32_t ebx, uint32_t ecx, uint32_t edx) {
        (void)subleaf;
        if (count >= 32) return;
        results[count].Function = leaf;
        results[count].Reserved[0] = 0;
        results[count].Reserved[1] = 0;
        results[count].Reserved[2] = 0;
        results[count].Eax = eax;
        results[count].Ebx = ebx;
        results[count].Ecx = ecx;
        results[count].Edx = edx;
        count++;
    };

    // Leaf 1 with hypervisor present bit (ECX[31]) cleared
    // Use either configured values or real hardware (with bit cleared)
    if (cpuidHandler) {
        cpuidHandler->GetCpuidResultList(results, &count, 32);
    } else {
        // Minimal result list (no CpuidHandler available)
        int cpuInfo[4];
        __cpuidex(cpuInfo, 1, 0);
        add(1, 0, (uint32_t)cpuInfo[0], (uint32_t)cpuInfo[1],
            (uint32_t)cpuInfo[2] & ~(1u << 31), (uint32_t)cpuInfo[3]);
    }

    // Always add hypervisor leaves 0x40000000-0x4000000F as zeros
    bool hasHypervisorLeaves = false;
    for (int i = 0; i < count; i++) {
        if (results[i].Function >= 0x40000000 && results[i].Function <= 0x4000000F) {
            hasHypervisorLeaves = true;
            break;
        }
    }
    if (!hasHypervisorLeaves) {
        for (uint32_t lf = 0x40000000; lf <= 0x4000000F; lf++) {
            add(lf, 0, 0, 0, 0, 0);
        }
    }

    if (count == 0) {
        m_logger->Trace(LOG_WHP, "CpuidResultList empty — all leaves will VM-exit");
        return true;
    }

    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeCpuidResultList,
        results, (uint32_t)(count * sizeof(WHV_X64_CPUID_RESULT)));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(CpuidResultList) failed: 0x%08X", hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "CPUID result list set: %d leaves pre-populated (hypervisor range hidden)", count);
    return true;
}

bool Partition::SetupAntiDetectionCpuidResultList(CpuidHandler* cpuidHandler)
{
    if (!m_handle) return false;

    // Allocate 1024-entry array for comprehensive coverage
    WHV_X64_CPUID_RESULT results[1024];
    int count = 0;

    if (cpuidHandler) {
        cpuidHandler->GetComprehensiveCpuidResultList(results, &count, 1024);
    }

    if (count == 0) {
        m_logger->Trace(LOG_WHP, "AntiDetection CpuidResultList empty — will use standard setup");
        return SetupCpuidResultList(cpuidHandler);
    }

    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeCpuidResultList,
        results, (uint32_t)(count * sizeof(WHV_X64_CPUID_RESULT)));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(CpuidResultList/comprehensive) failed: 0x%08X", hr);
        return SetupCpuidResultList(cpuidHandler);
    }

    m_logger->Trace(LOG_WHP, "Comprehensive CPUID result list set: %d leaves (0 VM-exits for standard ranges)", count);
    return true;
}

bool Partition::SetupCpuCount(uint32_t count)
{
    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeProcessorCount,
        &count, sizeof(count));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(ProcessorCount) failed: 0x%08X, count=%u", hr, count);
        return false;
    }
    m_vcpuCount = count;
    m_logger->Trace(LOG_WHP, "CPU count set to %u", count);
    return true;
}

bool Partition::SetupMemory(uint64_t sizeMB)
{
    // Pre-map the guest working set to eliminate runtime EPT violation exits.
    // Typical game working set layout (16GB address space):
    //   [0-512MB]   Initial code + data + MMIO hole
    //   [512MB-2GB] Main image load area
    //   [2GB-8GB]   Heap + dynamic allocations
    //   [8GB-12GB]  Stack + thread stacks
    //   [12GB-16GB] GPU staging + page tables
    static const WorkingSetRegion kDefaultWorkingSet[] = {
        { "Low memory + MMIO",   512, 0,      WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute },
        { "Image region",        1536, 512,   WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute },
        { "Heap + dynamic",      6144, 2048,  WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute },
        { "Stack region",        4096, 8192,  WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute },
        { "GPU + page tables",   4096, 12288, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute },
    };

    // Use the configured size to determine how much to pre-map
    uint64_t maxRegionGpa = 0;
    for (int i = 0; i < 5; i++) {
        uint64_t endGpa = (kDefaultWorkingSet[i].baseGpa + kDefaultWorkingSet[i].sizeMB) << 20;
        if (endGpa > maxRegionGpa) maxRegionGpa = endGpa;
    }

    // Only pre-map up to our guest memory size. A prior version logged "trimming" here but
    // always passed the full, untrimmed kDefaultWorkingSet to SetupWorkingSet below regardless
    // of sizeMB — actually build a trimmed copy instead.
    WorkingSetRegion trimmed[5];
    int trimmedCount = 0;
    for (int i = 0; i < 5; i++) {
        if (kDefaultWorkingSet[i].baseGpa >= sizeMB) continue; // region starts entirely past guest size
        trimmed[trimmedCount] = kDefaultWorkingSet[i];
        uint64_t regionEndMB = kDefaultWorkingSet[i].baseGpa + kDefaultWorkingSet[i].sizeMB;
        if (regionEndMB > sizeMB) {
            trimmed[trimmedCount].sizeMB = sizeMB - kDefaultWorkingSet[i].baseGpa; // clamp partial region
        }
        trimmedCount++;
    }

    uint64_t guestSizeBytes = sizeMB << 20;
    if (maxRegionGpa > guestSizeBytes) {
        m_logger->Trace(LOG_WHP, "SetupMemory: trimming working set from %lluMB to guest size %lluMB (%d of 5 regions kept)",
            maxRegionGpa >> 20, sizeMB, trimmedCount);
    }

    if (!SetupWorkingSet(trimmed, trimmedCount)) {
        m_logger->Trace(LOG_WARNING, "SetupMemory: working set pre-map incomplete — runtime EPT violations may occur");
    }

    m_logger->Trace(LOG_WHP, "Memory configured: %llu MB (working set pre-mapped)", sizeMB);
    return true;
}

bool Partition::SetupWorkingSet(const WorkingSetRegion* regions, int regionCount)
{
    if (!m_handle) return false;

    // Enable SeLockMemoryPrivilege for large pages (2MB) if not already done
    SIZE_T largePageMin = GetLargePageMinimum();
    bool hasLargePages = false;
    if (largePageMin > 0) {
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &tp.Privileges[0].Luid)) {
                if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS) {
                    hasLargePages = true;
                }
            }
            CloseHandle(hToken);
        }
    }

    bool allOk = true;
    for (int i = 0; i < regionCount; i++) {
        const WorkingSetRegion& reg = regions[i];
        uint64_t sizeBytes = reg.sizeMB << 20;

        // Align to large page boundary if using large pages
        uint64_t allocSize = sizeBytes;
        if (hasLargePages && largePageMin > 0) {
            allocSize = ((sizeBytes + largePageMin - 1) / largePageMin) * largePageMin;
        }

        void* hostVa = NULL;
        DWORD allocType = MEM_COMMIT | MEM_RESERVE;
        if (hasLargePages && largePageMin > 0) {
            allocType |= MEM_LARGE_PAGES;
            hostVa = VirtualAlloc(NULL, (SIZE_T)allocSize, allocType, PAGE_READWRITE);
        }
        if (!hostVa) {
            allocType = MEM_COMMIT | MEM_RESERVE;
            hostVa = VirtualAlloc(NULL, (SIZE_T)sizeBytes, allocType, PAGE_READWRITE);
        }
        if (!hostVa) {
            m_logger->Trace(LOG_ERROR, "SetupWorkingSet[%s]: VirtualAlloc(%llu MB) failed", reg.name, reg.sizeMB);
            allOk = false;
            continue;
        }

        m_guestMemory.push_back({hostVa, sizeBytes});

        WHV_GUEST_PHYSICAL_ADDRESS gpa = reg.baseGpa << 20;
        HRESULT hr = WHvMapGpaRange(m_handle, hostVa, gpa, sizeBytes, reg.flags);
        if (FAILED(hr)) {
            m_logger->Trace(LOG_ERROR, "SetupWorkingSet[%s]: WHvMapGpaRange(GPA=0x%llX, size=%llu) failed: 0x%08X",
                reg.name, gpa, sizeBytes, hr);
            allOk = false;
            continue;
        }

        TrackedMemoryRegion tracked;
        tracked.gpa = gpa;
        tracked.size = sizeBytes;
        tracked.flags = (uint32_t)reg.flags;
        m_trackedRegions.push_back(tracked);

        m_logger->Trace(LOG_WHP, "SetupWorkingSet[%s]: GPA=0x%llX size=%lluMB hostVa=%p flags=0x%X",
            reg.name, gpa, reg.sizeMB, hostVa, (uint32_t)reg.flags);
    }

    m_logger->Trace(LOG_WHP, "SetupWorkingSet: %d/%d regions pre-mapped (%s)", allOk ? regionCount : 0, regionCount,
        hasLargePages ? "large pages" : "4KB pages");
    return allOk;
}

bool Partition::SetupSelectiveExits()
{
    if (!m_handle) return false;

    // WHV_EXTENDED_VM_EXITS controls which exit types WHP generates.
    // Enabling only the exit types we handle reduces processor overhead
    // since VT-x doesn't need to check for disabled exit conditions.
    //
    // We need:
    //   X64CpuidExit       — CPUID instruction (guest CPU feature reporting)
    //   X64MsrExit         — RDMSR/WRMSR (guest MSR access monitoring)
    //   ExceptionExit      — #BP syscall intercept, #DB trampoline
    //   X64RdtscExit       — RDTSC (guest timing observations)
    //   HypercallExit      — VMCALL (need to intercept or inject #UD)
    //
    // We don't need:
    //   X64ApicSmiExitTrap — SMI trapping (not emulated)
    //   X64Apic*ExitTrap   — APIC write traps (not emulated)
    //   UnknownSynicConnection — SynIC not used
    //   RetargetUnknownVpciDevice — PCI not emulated
    //   GpaAccessFaultExit — handled via EPT violations natively

    WHV_EXTENDED_VM_EXITS exits;
    exits.AsUINT64 = 0;
    exits.X64CpuidExit = 1;
    exits.X64MsrExit = 1;
    exits.ExceptionExit = 1;
    exits.X64RdtscExit = 1;
    exits.HypercallExit = 1;

    // GPA access fault exits — left as 0 by default; enable for comprehensive
    // memory access monitoring in future research work.
    exits.GpaAccessFaultExit = 0;

    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeExtendedVmExits,
        &exits, sizeof(exits));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(ExtendedVmExits) failed: 0x%08X", hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "Selective exits configured: CPUID | MSR | EXCEPTION | RDTSC | HYPERCALL");
    return true;
}

bool Partition::Init()
{
    if (!m_handle) return false;

    HRESULT hr = WHvSetupPartition(m_handle);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetupPartition failed: 0x%08X", hr);
        return false;
    }

    m_initialized = true;
    m_logger->Trace(LOG_WHP, "Partition initialized");
    return true;
}

bool Partition::MapOnDemand(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes)
{
    m_onDemandRegions.push_back({guestPa, sizeInBytes});
    m_logger->Trace(LOG_WHP, "On-demand region registered: GPA=0x%llX size=%llu", guestPa, sizeInBytes);
    return true;
}

bool Partition::IsOnDemandRegion(WHV_GUEST_PHYSICAL_ADDRESS guestPa) const
{
    for (const auto& region : m_onDemandRegions) {
        if (guestPa >= region.first && guestPa < region.first + region.second)
            return true;
    }
    return false;
}

bool Partition::MapOnDemandNow(WHV_GUEST_PHYSICAL_ADDRESS guestPa)
{
    for (const auto& region : m_onDemandRegions) {
        if (guestPa >= region.first && guestPa < region.first + region.second) {
            void* hostVa = VirtualAlloc(NULL, (SIZE_T)region.second, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!hostVa) return false;
            return MapGpaRange(hostVa, guestPa, region.second,
                WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
        }
    }
    return false;
}

bool Partition::MapProcessMemory(HANDLE hProcess)
{
    if (m_guestPageTable) {
        delete m_guestPageTable;
        m_guestPageTable = nullptr;
    }
    m_guestPageTable = new GuestPageTable(m_logger, this);
    if (!m_guestPageTable->Build(hProcess)) {
        m_logger->Trace(LOG_ERROR, "MapProcessMemory: GuestPageTable::Build failed");
        delete m_guestPageTable;
        m_guestPageTable = nullptr;
        return false;
    }
    m_logger->Trace(LOG_INFO, "MapProcessMemory: PML4 GPA=0x%llX, total=%llu pages",
        m_guestPageTable->GetPml4Gpa(), m_guestPageTable->GetTotalPages());
    return true;
}

void Partition::Destroy()
{
    delete m_guestPageTable;
    m_guestPageTable = nullptr;

    for (auto& block : m_guestMemory) {
        if (block.hostVa) {
            VirtualFree(block.hostVa, 0, MEM_RELEASE);
        }
    }
    m_guestMemory.clear();

    if (m_handle) {
        if (m_initialized) {
            WHvDeletePartition(m_handle);
        }
        m_handle = nullptr;
        m_initialized = false;
        m_logger->Trace(LOG_WHP, "Partition destroyed");
    }
}

bool Partition::MapGpaRangeDeferred(void* hostVa, WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes, WHV_MAP_GPA_RANGE_FLAGS flags)
{
    if (!m_handle || !m_initialized) return false;
    m_deferredMaps.push_back({flags, guestPa, sizeInBytes, hostVa});
    return true;
}

bool Partition::UnmapGpaRangeDeferred(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes)
{
    if (!m_handle || !m_initialized) return false;
    m_deferredUnmaps.push_back({guestPa, sizeInBytes});
    return true;
}

bool Partition::FlushDeferredMaps()
{
    if (m_deferredMaps.empty()) return true;

    // Sort by GPA ascending
    std::sort(m_deferredMaps.begin(), m_deferredMaps.end(),
        [](const DeferredMap& a, const DeferredMap& b) { return a.guestPa < b.guestPa; });

    // Merge contiguous runs with same flags
    size_t writeIdx = 0;
    for (size_t i = 1; i < m_deferredMaps.size(); i++) {
        uint64_t prevEnd = m_deferredMaps[writeIdx].guestPa + m_deferredMaps[writeIdx].size;
        if (prevEnd == m_deferredMaps[i].guestPa &&
            m_deferredMaps[writeIdx].flags == m_deferredMaps[i].flags &&
            (uint8_t*)m_deferredMaps[writeIdx].hostVa == (uint8_t*)m_deferredMaps[i].hostVa - (m_deferredMaps[i].guestPa - m_deferredMaps[writeIdx].guestPa)) {
            // Contiguous: extend current entry
            m_deferredMaps[writeIdx].size += m_deferredMaps[i].size;
        } else {
            writeIdx++;
            if (writeIdx != i) m_deferredMaps[writeIdx] = m_deferredMaps[i];
        }
    }
    m_deferredMaps.resize(writeIdx + 1);

    // Issue merged WHvMapGpaRange calls
    bool allOk = true;
    for (auto& dm : m_deferredMaps) {
        HRESULT hr = WHvMapGpaRange(m_handle, dm.hostVa, dm.guestPa, dm.size, dm.flags);
        if (FAILED(hr)) {
            m_logger->Trace(LOG_ERROR, "WHvMapGpaRange(guestPa=0x%llX, size=%llu) failed: 0x%08X",
                dm.guestPa, dm.size, hr);
            allOk = false;
        }
    }
    m_deferredMaps.clear();
    return allOk;
}

bool Partition::FlushDeferredUnmaps()
{
    if (m_deferredUnmaps.empty()) return true;

    std::sort(m_deferredUnmaps.begin(), m_deferredUnmaps.end(),
        [](const DeferredUnmap& a, const DeferredUnmap& b) { return a.guestPa < b.guestPa; });

    size_t writeIdx = 0;
    for (size_t i = 1; i < m_deferredUnmaps.size(); i++) {
        uint64_t prevEnd = m_deferredUnmaps[writeIdx].guestPa + m_deferredUnmaps[writeIdx].size;
        if (prevEnd == m_deferredUnmaps[i].guestPa) {
            m_deferredUnmaps[writeIdx].size += m_deferredUnmaps[i].size;
        } else {
            writeIdx++;
            if (writeIdx != i) m_deferredUnmaps[writeIdx] = m_deferredUnmaps[i];
        }
    }
    m_deferredUnmaps.resize(writeIdx + 1);

    bool allOk = true;
    for (auto& du : m_deferredUnmaps) {
        HRESULT hr = WHvUnmapGpaRange(m_handle, du.guestPa, du.size);
        if (FAILED(hr)) {
            m_logger->Trace(LOG_ERROR, "WHvUnmapGpaRange(guestPa=0x%llX) failed: 0x%08X", du.guestPa, hr);
            allOk = false;
        }
    }
    m_deferredUnmaps.clear();
    return allOk;
}

bool Partition::MapGpaRange(void* hostVa, WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes, WHV_MAP_GPA_RANGE_FLAGS flags)
{
    if (!m_handle || !m_initialized) {
        m_logger->Trace(LOG_ERROR, "MapGpaRange: partition not ready");
        return false;
    }

    HRESULT hr = WHvMapGpaRange(m_handle, hostVa, guestPa, sizeInBytes, flags);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvMapGpaRange(guestPa=0x%llX, size=%llu) failed: 0x%08X", guestPa, sizeInBytes, hr);
        return false;
    }

    // Track region for snapshot/restore
    TrackedMemoryRegion region;
    region.gpa = guestPa;
    region.size = sizeInBytes;
    region.flags = (uint32_t)flags;
    m_trackedRegions.push_back(region);

    m_logger->Trace(LOG_WHP, "GPA range mapped: hostVa=%p guestPa=0x%llX size=%llu flags=0x%X", hostVa, guestPa, sizeInBytes, (uint32_t)flags);
    return true;
}

bool Partition::UnmapGpaRange(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes)
{
    if (!m_handle || !m_initialized) return false;

    HRESULT hr = WHvUnmapGpaRange(m_handle, guestPa, sizeInBytes);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvUnmapGpaRange(guestPa=0x%llX) failed: 0x%08X", guestPa, hr);
        return false;
    }
    return true;
}

void* Partition::AllocateGuestMemory(uint64_t sizeInBytes)
{
    // Use large pages (2MB) when available for EPT performance.
    // Large pages reduce EPT page walk depth from 4→3 levels and cut
    // EPT violation VM exits by ~70% (Intel THP + crosvm research).
    // Falls back to 4KB pages if large pages are not supported/enabled.
    BOOL hasLargePages = FALSE;
    SIZE_T largePageMin = GetLargePageMinimum();
    if (largePageMin > 0 && sizeInBytes >= largePageMin) {
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &tp.Privileges[0].Luid)) {
                if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS) {
                    hasLargePages = TRUE;
                }
            }
            CloseHandle(hToken);
        }
    }

    void* ptr = NULL;
    if (hasLargePages && largePageMin > 0 && sizeInBytes >= largePageMin) {
        SIZE_T alignedSize = ((sizeInBytes + largePageMin - 1) / largePageMin) * largePageMin;
        ptr = VirtualAlloc(NULL, alignedSize, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);
        if (ptr) {
            m_logger->Trace(LOG_WHP, "AllocateGuestMemory: large pages (2MB) @ %p size=%llu", ptr, sizeInBytes);
        } else {
            m_logger->Trace(LOG_WARNING, "AllocateGuestMemory: large pages failed (%u), 4KB fallback", GetLastError());
        }
    }

    if (!ptr) {
        ptr = VirtualAlloc(NULL, (SIZE_T)sizeInBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (ptr) {
        m_guestMemory.push_back({ptr, sizeInBytes});
    }
    return ptr;
}

void Partition::FreeGuestMemory(void* ptr)
{
    for (size_t i = 0; i < m_guestMemory.size(); i++) {
        if (m_guestMemory[i].hostVa == ptr) {
            VirtualFree(ptr, 0, MEM_RELEASE);
            m_guestMemory.erase(m_guestMemory.begin() + i);
            return;
        }
    }
}
