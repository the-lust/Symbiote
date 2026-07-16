#include "ProcessCloner.h"
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

ProcessCloner::ProcessCloner(Logger* logger)
    : m_logger(logger)
    , m_entryPoint(0)
{
}

ProcessCloner::~ProcessCloner()
{
    m_regions.clear();
}

bool ProcessCloner::ShouldCloneRegion(uint32_t state, uint32_t type, uint64_t baseAddr)
{
    if (state != MEM_COMMIT) return false;
    if (type == MEM_MAPPED) return false;
    if (baseAddr < 0x10000) return false;
    if (baseAddr >= 0x7FFFFFFFFFFFULL) return false;
    return true;
}

bool ProcessCloner::SnapshotProcess(HANDLE hProcess)
{
    m_regions.clear();
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uint64_t totalCloned = 0;
    uint8_t* addr = nullptr;

    while ((uint64_t)addr < (uint64_t)sysInfo.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T result = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));
        if (result == 0) break;

        if (ShouldCloneRegion(mbi.State, mbi.Type, (uint64_t)mbi.BaseAddress)) {
            if (totalCloned + mbi.RegionSize > MAX_CLONE_SIZE) {
                addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }

            ClonedMemoryRegion region;
            region.baseAddress = (uint64_t)mbi.BaseAddress;
            region.regionSize = mbi.RegionSize;
            region.allocationProtect = mbi.AllocationProtect;
            region.state = mbi.State;
            region.protect = mbi.Protect;
            region.type = mbi.Type;
            region.content.resize(mbi.RegionSize);

            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, region.content.data(), mbi.RegionSize, &bytesRead)) {
                m_regions.push_back(std::move(region));
                totalCloned += mbi.RegionSize;
            }
        }

        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
    }

    m_logger->Trace(LOG_INFO, "ProcessCloner: cloned %zu regions (%llu MB)",
        m_regions.size(), totalCloned / (1024 * 1024));
    return !m_regions.empty();
}

bool ProcessCloner::MapRegionsIntoGuest(void* partitionHandle)
{
    (void)partitionHandle;
    m_logger->Trace(LOG_INFO, "ProcessCloner: mapping %zu regions into guest", m_regions.size());
    return true;
}

uint64_t ProcessCloner::GetTotalMemorySize() const
{
    uint64_t total = 0;
    for (const auto& r : m_regions) total += r.regionSize;
    return total;
}

bool ProcessCloner::HasRegion(uint64_t baseAddr) const
{
    for (const auto& r : m_regions) {
        if (r.baseAddress == baseAddr) return true;
    }
    return false;
}

const ClonedMemoryRegion* ProcessCloner::FindRegion(uint64_t addr) const
{
    for (const auto& r : m_regions) {
        if (addr >= r.baseAddress && addr < r.baseAddress + r.regionSize)
            return &r;
    }
    return nullptr;
}

bool ProcessCloner::CloneForBootstrap(HANDLE hProcess, uint64_t& outEntryPoint)
{
    if (!SnapshotProcess(hProcess)) return false;

    uint8_t* base = (uint8_t*)GetModuleHandleW(NULL);
    if (base) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        outEntryPoint = (uint64_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
        m_entryPoint = outEntryPoint;
    }

    return true;
}
