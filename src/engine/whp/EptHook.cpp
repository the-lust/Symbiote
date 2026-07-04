#include "EptHook.h"
#include "Partition.h"
#include <cstring>
#include <intrin.h>

EptHook::EptHook(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition)
{
}

EptHook::~EptHook()
{
    for (auto& hook : m_hooks) {
        if (hook.mapped && m_partition) {
            m_partition->UnmapGpaRange(hook.gpa, hook.size);
        }
    }
}

bool EptHook::HandleExit(WHV_VP_EXIT_CONTEXT* ctx, WHV_RUN_VP_EXIT_CONTEXT* exitCtx, uint64_t* rip)
{
    if (exitCtx->ExitReason == WHvRunVpExitReasonMemoryAccess) {
        uint64_t gpa = exitCtx->MemoryAccess.Gpa;
        return HandleEptViolation(ctx, gpa, rip);
    }
    return false;
}

bool EptHook::InstallHook(uint64_t gpa, void* hostVA, uint32_t size, EptHookType type)
{
    EptEntry entry;
    entry.gpa = gpa;
    entry.hostVA = hostVA;
    entry.size = size;
    entry.mapped = false;
    entry.type = type;
    entry.originalVA = nullptr;

    if (m_partition) {
        WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;
        if (m_partition->MapGpaRange(hostVA, gpa, size, flags)) {
            entry.mapped = true;
        }
    }

    m_gpaIndex[gpa] = m_hooks.size();
    m_hooks.push_back(entry);
    m_logger->Trace(LOG_EPT, "EPT hook installed: GPA=0x%llX VA=%p size=%u type=%d mapped=%d",
        gpa, hostVA, size, (int)type, entry.mapped);
    return true;
}

bool EptHook::HandleEptViolation(WHV_VP_EXIT_CONTEXT*, uint64_t gpa, uint64_t*)
{
    auto it = m_gpaIndex.find(gpa);
    if (it != m_gpaIndex.end() && it->second < m_hooks.size()) {
        return MapOnViolation(m_hooks[it->second], false);
    }

    // fallback: linear search for GPA range
    for (size_t i = 0; i < m_hooks.size(); i++) {
        if (gpa >= m_hooks[i].gpa && gpa < m_hooks[i].gpa + m_hooks[i].size) {
            m_gpaIndex[gpa] = i;
            return MapOnViolation(m_hooks[i], true);
        }
    }

    m_logger->Trace(LOG_EPT, "EPT violation unhandled at GPA=0x%llX", gpa);
    return false;
}

bool EptHook::MapOnViolation(EptEntry& entry, bool fallback)
{
    if (!entry.mapped && m_partition) {
        WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;
        if (m_partition->MapGpaRange(entry.hostVA, entry.gpa, entry.size, flags)) {
            entry.mapped = true;
        }
    }

    if (entry.type == EPT_HOOK_KERNEL_PAGE || entry.type == EPT_HOOK_IDT ||
        entry.type == EPT_HOOK_GDT || entry.type == EPT_HOOK_CR3) {
        m_logger->Trace(LOG_EPT, "Kernel page EPT access at GPA=0x%llX type=%d", entry.gpa, (int)entry.type);
    }

    m_logger->Trace(LOG_EPT, "EPT violation handled at GPA=0x%llX%s", entry.gpa, fallback ? " (fallback)" : "");
    return true;
}

bool EptHook::InstallKernelMemoryHooks()
{
    // hook kernel memory regions: IDT, GDT, and critical page tables
    // these are best-effort hooks since WHP owns the actual EPT

    // IDT is typically at low memory
    uint8_t* idtShadow = (uint8_t*)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (idtShadow) {
        memset(idtShadow, 0, 0x1000);
        InstallHook(0x0000, idtShadow, 0x1000, EPT_HOOK_IDT);
    }

    // GDT shadow
    uint8_t* gdtShadow = (uint8_t*)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (gdtShadow) {
        memset(gdtShadow, 0, 0x1000);
        InstallHook(0x1000, gdtShadow, 0x1000, EPT_HOOK_GDT);
    }

    // BDA (BIOS Data Area) at GPA 0x400 is within the same 4KB page as the
    // IDT hook (GPA 0x0-0xFFF). No separate hook needed — IDT page covers it.

    m_logger->Trace(LOG_EPT, "Kernel memory hooks installed (IDT, GDT)");
    return true;
}

bool EptHook::InstallMsrBitmapHook()
{
    // WHP handles MSR exits natively via MsrHandler, no bitmap needed
    // WHP handles MSR exits natively via MsrHandler
    m_logger->Trace(LOG_EPT, "MSR bitmap hook: handled by WHP MsrHandler natively");
    return true;
}

bool EptHook::HookPage(uint64_t gpa, void* shadowVA, uint32_t size)
{
    return InstallHook(gpa, shadowVA, size, EPT_HOOK_KERNEL_PAGE);
}
