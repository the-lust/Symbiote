#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"
#include <vector>
#include <cstdint>

class Partition;

class GuestPageTable {
public:
    explicit GuestPageTable(Logger* logger, Partition* partition);
    ~GuestPageTable();

    bool Build(HANDLE hProcess);
    WHV_GUEST_PHYSICAL_ADDRESS GetPml4Gpa() const { return m_pml4Gpa; }
    uint64_t GetTotalPages() const { return m_totalPages; }
    bool MapDynamicPage(uint64_t va, bool isWrite);

    static constexpr uint64_t PAGE_TABLE_GPA_BASE = 0x1000000000000ULL;

private:
    struct PageTablePage {
        void* hostVa;
        WHV_GUEST_PHYSICAL_ADDRESS gpa;
        bool valid;
    };

    Logger* m_logger;
    Partition* m_partition;
    WHV_GUEST_PHYSICAL_ADDRESS m_pml4Gpa;
    uint64_t m_totalPages;
    uint64_t m_nextTableGpa;

    std::vector<PageTablePage> m_pml4Pages;
    std::vector<PageTablePage> m_pdptPages;
    std::vector<PageTablePage> m_pdPages;
    std::vector<PageTablePage> m_ptPages;

    WHV_GUEST_PHYSICAL_ADDRESS AllocTablePage(void*& hostVa);
    bool MapProcessRegion(HANDLE hProcess, uint64_t baseAddr, uint64_t regionSize);
    uint64_t* GetPml4Entry(uint64_t va);
    uint64_t* GetPdptEntry(uint64_t va, uint64_t* pml4e);
    uint64_t* GetPdEntry(uint64_t va, uint64_t* pdpte);
    uint64_t* GetPtEntry(uint64_t va, uint64_t* pde);

    static void SetPte(uint64_t* entry, WHV_GUEST_PHYSICAL_ADDRESS gpa, bool user, bool writable, bool executable);
};
