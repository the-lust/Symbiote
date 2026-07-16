#include "EptPageProtect.h"
#include "Partition.h"
#include <cstring>
#include <intrin.h>

EptPageProtect::EptPageProtect(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition), m_initialized(false)
{
}

EptPageProtect::~EptPageProtect()
{
    Shutdown();
}

bool EptPageProtect::Initialize()
{
    m_initialized = true;
    m_logger->Trace(LOG_INFO, "EptPageProtect: page protection initialized");
    return true;
}

void EptPageProtect::Shutdown()
{
    for (auto& page : m_protectedPages) {
        if (page.active && m_partition) {
            RestorePage(page.gpa, page.size, page.realVa);
            if (page.shadowVa) VirtualFree(page.shadowVa, 0, MEM_RELEASE);
        }
    }
    m_protectedPages.clear();
    m_gpaToProtect.clear();
    m_initialized = false;
}

bool EptPageProtect::HidePage(uint64_t gpa, uint64_t size)
{
    if (!m_initialized || !m_partition) return false;

    void* shadowVa = VirtualAlloc(nullptr, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shadowVa) {
        m_logger->Trace(LOG_ERROR, "EptPageProtect: shadow alloc failed for GPA=0x%llX", gpa);
        return false;
    }

    uint8_t* p = (uint8_t*)shadowVa;
    for (uint64_t i = 0; i < size; i++) {
        p[i] = (uint8_t)((i * 0x71) ^ (gpa >> (i % 8)) & 0xFF);
    }

    if (!MapHiddenPage(gpa, size, shadowVa)) {
        VirtualFree(shadowVa, 0, MEM_RELEASE);
        return false;
    }

    ProtectedPage pp;
    pp.gpa = gpa;
    pp.size = size;
    pp.shadowVa = shadowVa;
    pp.realVa = nullptr;
    pp.active = true;

    m_gpaToProtect[gpa] = m_protectedPages.size();
    m_protectedPages.push_back(pp);

    m_logger->Trace(LOG_INFO, "EptPageProtect: page hidden GPA=0x%llX size=%llu shadow=%p", gpa, size, shadowVa);
    return true;
}

bool EptPageProtect::UnhidePage(uint64_t gpa)
{
    auto it = m_gpaToProtect.find(gpa);
    if (it == m_gpaToProtect.end()) return false;

    ProtectedPage& page = m_protectedPages[it->second];
    if (!page.active) return false;

    bool result = RestorePage(page.gpa, page.size, page.realVa);
    if (page.shadowVa) {
        VirtualFree(page.shadowVa, 0, MEM_RELEASE);
        page.shadowVa = nullptr;
    }
    page.active = false;
    m_gpaToProtect.erase(it);

    return result;
}

bool EptPageProtect::HideModulePages(uint64_t moduleBase, uint64_t moduleSize)
{
    if (!m_initialized) return false;

    uint64_t alignedBase = moduleBase & ~0xFFFULL;
    uint64_t alignedSize = ((moduleSize + 0xFFF) & ~0xFFFULL);

    return HidePage(alignedBase, alignedSize);
}

bool EptPageProtect::ProtectEngineDll()
{
    HMODULE hEngine = GetModuleHandleW(L"engine.dll");
    if (!hEngine) {
        hEngine = GetModuleHandleW(NULL);
        if (!hEngine) return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(hEngine, &mbi, sizeof(mbi)) == 0) return false;

    uint64_t engineBase = (uint64_t)(uintptr_t)hEngine;
    uint64_t engineSize = (uint64_t)mbi.RegionSize;

    return HideModulePages(engineBase, engineSize);
}

bool EptPageProtect::HandleViolation(uint64_t gpa, uint64_t rip, WHV_MEMORY_ACCESS_TYPE accessType)
{
    auto it = m_gpaToProtect.find(gpa & ~0xFFFULL);
    if (it == m_gpaToProtect.end()) return false;

    m_logger->Trace(LOG_INFO, "EptPageProtect: violation GPA=0x%llX RIP=0x%llX type=%d",
        gpa, rip, (int)accessType);

    return true;
}

bool EptPageProtect::GetShadowContent(uint64_t gpa, void* buffer, uint32_t size)
{
    auto it = m_gpaToProtect.find(gpa & ~0xFFFULL);
    if (it == m_gpaToProtect.end()) return false;

    ProtectedPage& page = m_protectedPages[it->second];
    if (!page.shadowVa || !buffer) return false;

    uint64_t offset = gpa - page.gpa;
    if (offset + size > page.size) return false;

    memcpy(buffer, (uint8_t*)page.shadowVa + offset, size);
    return true;
}

bool EptPageProtect::MapHiddenPage(uint64_t gpa, uint64_t size, void* shadowVa)
{
    if (!m_partition) return false;

    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;
    return m_partition->MapGpaRange(shadowVa, gpa, size, flags);
}

bool EptPageProtect::RestorePage(uint64_t gpa, uint64_t size, void* realVa)
{
    if (!m_partition || !realVa) return false;

    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute;
    return m_partition->MapGpaRange(realVa, gpa, size, flags);
}
