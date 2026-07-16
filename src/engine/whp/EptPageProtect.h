#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include "Logger.h"

class Partition;

// EPT-based page protection for hiding critical memory from Denuvo scans
class EptPageProtect {
public:
    explicit EptPageProtect(Logger* logger, Partition* partition);
    ~EptPageProtect();

    bool Initialize();
    void Shutdown();

    // Protect a page at GPA: Denuvo reads get garbage, writes fail
    bool HidePage(uint64_t gpa, uint64_t size);

    // Unprotect a previously hidden page
    bool UnhidePage(uint64_t gpa);

    // Hide all pages belonging to a module (by base address)
    bool HideModulePages(uint64_t moduleBase, uint64_t moduleSize);

    // Set up engine DLL self-protection
    bool ProtectEngineDll();

    // Handle EPT violation for protected pages
    bool HandleViolation(uint64_t gpa, uint64_t rip, WHV_MEMORY_ACCESS_TYPE accessType);

    // Get shadow page content for a GPA (returns fake data for hidden pages)
    bool GetShadowContent(uint64_t gpa, void* buffer, uint32_t size);

private:
    Logger* m_logger;
    Partition* m_partition;
    bool m_initialized;

    struct ProtectedPage {
        uint64_t gpa;
        uint64_t size;
        void* shadowVa;     // Shadow memory with fake/spoofed content
        void* realVa;       // Real host VA (original content)
        bool active;
    };

    std::vector<ProtectedPage> m_protectedPages;
    std::unordered_map<uint64_t, size_t> m_gpaToProtect;

    bool MapHiddenPage(uint64_t gpa, uint64_t size, void* shadowVa);
    bool RestorePage(uint64_t gpa, uint64_t size, void* realVa);
};
