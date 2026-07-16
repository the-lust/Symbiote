#include "GuestPageTable.h"
#include "Partition.h"
#include <cstring>

#define GPT_LOG(fmt, ...) m_logger->Trace(LOG_WHP, "GuestPT: " fmt, ##__VA_ARGS__)
#define GPT_ERR(fmt, ...) m_logger->Trace(LOG_ERROR, "GuestPT: " fmt, ##__VA_ARGS__)

GuestPageTable::GuestPageTable(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition),
      m_pml4Gpa(0), m_totalPages(0), m_nextTableGpa(PAGE_TABLE_GPA_BASE)
{
}

GuestPageTable::~GuestPageTable()
{
    for (auto& p : m_ptPages) { if (p.hostVa) VirtualFree(p.hostVa, 0, MEM_RELEASE); }
    for (auto& p : m_pdPages) { if (p.hostVa) VirtualFree(p.hostVa, 0, MEM_RELEASE); }
    for (auto& p : m_pdptPages) { if (p.hostVa) VirtualFree(p.hostVa, 0, MEM_RELEASE); }
    for (auto& p : m_pml4Pages) { if (p.hostVa) VirtualFree(p.hostVa, 0, MEM_RELEASE); }
    m_pml4Pages.clear();
    m_pdptPages.clear();
    m_pdPages.clear();
    m_ptPages.clear();
}

WHV_GUEST_PHYSICAL_ADDRESS GuestPageTable::AllocTablePage(void*& hostVa)
{
    hostVa = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!hostVa) return 0;
    memset(hostVa, 0, 0x1000);

    WHV_GUEST_PHYSICAL_ADDRESS gpa = m_nextTableGpa;
    m_nextTableGpa += 0x1000;

    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (!m_partition->MapGpaRange(hostVa, gpa, 0x1000, flags)) {
        VirtualFree(hostVa, 0, MEM_RELEASE);
        return 0;
    }

    return gpa;
}

void GuestPageTable::SetPte(uint64_t* entry, WHV_GUEST_PHYSICAL_ADDRESS gpa, bool user, bool writable, bool executable)
{
    uint64_t pte = (gpa & 0x0000FFFFFFFFFF000ULL); // page frame (bits 47:12)
    pte |= 0x001; // Present
    if (user)    pte |= 0x004; // User (ring-3)
    if (writable) pte |= 0x002; // R/W
    if (!executable) pte |= (1ULL << 63); // NX
    *entry = pte;
}

uint64_t* GuestPageTable::GetPml4Entry(uint64_t va)
{
    int idx = (int)((va >> 39) & 0x1FF);
    if (m_pml4Pages.empty()) return nullptr;
    return &((uint64_t*)m_pml4Pages[0].hostVa)[idx];
}

uint64_t* GuestPageTable::GetPdptEntry(uint64_t va, uint64_t* pml4e)
{
    int idx = (int)((va >> 30) & 0x1FF);
    if (!(*pml4e & 1)) {
        void* hostVa = nullptr;
        WHV_GUEST_PHYSICAL_ADDRESS gpa = AllocTablePage(hostVa);
        if (!gpa) return nullptr;
        m_pdptPages.push_back({hostVa, gpa, true});
        SetPte(pml4e, gpa, true, true, true);
        GPT_LOG("Allocated PDPT page: VA=%p GPA=0x%llX for PML4[%d]", hostVa, gpa, idx);
    }
    // Find the PDPT page from pml4e GPA
    WHV_GUEST_PHYSICAL_ADDRESS pdptGpa = (*pml4e) & 0x0000FFFFFFFFFF000ULL;
    for (auto& p : m_pdptPages) {
        if (p.gpa == pdptGpa) {
            return &((uint64_t*)p.hostVa)[idx];
        }
    }
    return nullptr;
}

uint64_t* GuestPageTable::GetPdEntry(uint64_t va, uint64_t* pdpte)
{
    int idx = (int)((va >> 21) & 0x1FF);
    if (!(*pdpte & 1)) {
        void* hostVa = nullptr;
        WHV_GUEST_PHYSICAL_ADDRESS gpa = AllocTablePage(hostVa);
        if (!gpa) return nullptr;
        m_pdPages.push_back({hostVa, gpa, true});
        SetPte(pdpte, gpa, true, true, true);
        GPT_LOG("Allocated PD page: VA=%p GPA=0x%llX", hostVa, gpa);
    }
    WHV_GUEST_PHYSICAL_ADDRESS pdGpa = (*pdpte) & 0x0000FFFFFFFFFF000ULL;
    for (auto& p : m_pdPages) {
        if (p.gpa == pdGpa) {
            return &((uint64_t*)p.hostVa)[idx];
        }
    }
    return nullptr;
}

uint64_t* GuestPageTable::GetPtEntry(uint64_t va, uint64_t* pde)
{
    int idx = (int)((va >> 12) & 0x1FF);
    if (!(*pde & 1)) {
        void* hostVa = nullptr;
        WHV_GUEST_PHYSICAL_ADDRESS gpa = AllocTablePage(hostVa);
        if (!gpa) return nullptr;
        m_ptPages.push_back({hostVa, gpa, true});
        SetPte(pde, gpa, true, true, true);
        GPT_LOG("Allocated PT page: VA=%p GPA=0x%llX", hostVa, gpa);
    }
    WHV_GUEST_PHYSICAL_ADDRESS ptGpa = (*pde) & 0x0000FFFFFFFFFF000ULL;
    for (auto& p : m_ptPages) {
        if (p.gpa == ptGpa) {
            return &((uint64_t*)p.hostVa)[idx];
        }
    }
    return nullptr;
}

bool GuestPageTable::Build(HANDLE hProcess)
{
    if (m_pml4Gpa) return true;

    // Allocate PML4 page
    void* pml4Va = nullptr;
    WHV_GUEST_PHYSICAL_ADDRESS pml4Gpa = AllocTablePage(pml4Va);
    if (!pml4Gpa) {
        GPT_ERR("Failed to allocate PML4 page");
        return false;
    }
    m_pml4Pages.push_back({pml4Va, pml4Gpa, true});
    m_pml4Gpa = pml4Gpa;
    GPT_LOG("PML4 allocated: VA=%p GPA=0x%llX", pml4Va, pml4Gpa);

    // Enumerate all committed pages in the process
    uint8_t* addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t totalMapped = 0;
    int regionCount = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0) {
            if (!MapProcessRegion(hProcess, (uint64_t)mbi.BaseAddress, mbi.RegionSize)) {
                GPT_ERR("Failed to map region at 0x%llX size=%llu",
                    (uint64_t)mbi.BaseAddress, mbi.RegionSize);
                return false;
            }
            totalMapped += mbi.RegionSize;
            regionCount++;
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if ((uint64_t)addr >= 0x7FFFFFFFFFFFFFFFULL) break;
    }

    m_totalPages = totalMapped / 0x1000;
    GPT_LOG("Build complete: %u regions, %llu pages (%llu MB), CR3=0x%llX",
        regionCount, m_totalPages, totalMapped / (1024 * 1024), m_pml4Gpa);
    return true;
}

bool GuestPageTable::MapProcessRegion(HANDLE hProcess, uint64_t baseAddr, uint64_t regionSize)
{
    // Query protection for this region
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (LPCVOID)baseAddr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }

    DWORD prot = mbi.Protect;
    // Guard pages and no-access pages should not be present in guest page tables
    if (prot & PAGE_GUARD || prot == PAGE_NOACCESS) return true;

    bool writable = (prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) != 0;
    bool executable = (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

    // Map each 4KB page in this region
    for (uint64_t offset = 0; offset < regionSize; offset += 0x1000) {
        uint64_t va = baseAddr + offset;

        uint64_t* pml4e = GetPml4Entry(va);
        if (!pml4e) { GPT_ERR("No PML4 entry for VA 0x%llX", va); return false; }

        uint64_t* pdpte = GetPdptEntry(va, pml4e);
        if (!pdpte) { GPT_ERR("No PDPT entry for VA 0x%llX", va); return false; }

        uint64_t* pde = GetPdEntry(va, pdpte);
        if (!pde) { GPT_ERR("No PD entry for VA 0x%llX", va); return false; }

        uint64_t* pte = GetPtEntry(va, pde);
        if (!pte) { GPT_ERR("No PT entry for VA 0x%llX", va); return false; }

        // Identity map: GPA = VA
        SetPte(pte, (WHV_GUEST_PHYSICAL_ADDRESS)va, true, writable, executable);
    }

    // Map the entire region to the partition (EPT)
    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead;
    if (writable) flags = (WHV_MAP_GPA_RANGE_FLAGS)(flags | WHvMapGpaRangeFlagWrite);
    if (executable) flags = (WHV_MAP_GPA_RANGE_FLAGS)(flags | WHvMapGpaRangeFlagExecute);

    if (!m_partition->MapGpaRange((void*)baseAddr, (WHV_GUEST_PHYSICAL_ADDRESS)baseAddr, regionSize, flags)) {
        GPT_ERR("Failed to EPT-map region at 0x%llX size=%llu", baseAddr, regionSize);
        return false;
    }

    return true;
}

bool GuestPageTable::MapDynamicPage(uint64_t va, bool)
{
    // Handle EPT violations by mapping a single page on demand
    uint64_t pageBase = va & ~0xFFFULL;

    // Check if this page is already mapped in the partition
    // (We can't easily check EPT, so just re-map — WHP handles duplicates)

    // Query the page to determine protection
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)pageBase, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        GPT_ERR("MapDynamicPage: VirtualQuery failed at VA 0x%llX", pageBase);
        return false;
    }

    if (mbi.State != MEM_COMMIT) {
        GPT_ERR("MapDynamicPage: page at VA 0x%llX not committed", pageBase);
        return false;
    }

    DWORD prot = mbi.Protect;
    bool writable = (prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) != 0;
    bool executable = (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

    // Build PTEs if they don't exist
    uint64_t* pml4e = GetPml4Entry(pageBase);
    if (!pml4e || !(*pml4e & 1)) {
        // Page table hierarchy doesn't exist for this page; allocate it
        uint64_t* pdePt = GetPdEntry(pageBase, GetPdptEntry(pageBase, GetPml4Entry(pageBase)));
        if (!pdePt) return false;
    }

    uint64_t* pte = GetPtEntry(pageBase, GetPdEntry(pageBase, GetPdptEntry(pageBase, GetPml4Entry(pageBase))));
    if (!pte) return false;

    if (!(*pte & 1)) {
        SetPte(pte, (WHV_GUEST_PHYSICAL_ADDRESS)pageBase, true, writable, executable);
    }

    // Map in EPT via deferred coalescing wrapper
    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead;
    if (writable) flags = (WHV_MAP_GPA_RANGE_FLAGS)(flags | WHvMapGpaRangeFlagWrite);
    if (executable) flags = (WHV_MAP_GPA_RANGE_FLAGS)(flags | WHvMapGpaRangeFlagExecute);

    if (!m_partition->MapGpaRangeDeferred((void*)pageBase, (WHV_GUEST_PHYSICAL_ADDRESS)pageBase, 0x1000, flags)) {
        GPT_ERR("MapDynamicPage: failed to defer EPT-map VA 0x%llX", pageBase);
        return false;
    }

    GPT_LOG("Dynamic page mapped: VA=0x%llX prot=0x%X write=%d exec=%d", pageBase, prot, writable, executable);
    m_totalPages++;
    return true;
}
