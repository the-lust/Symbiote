#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "Logger.h"

class Partition;

struct SplitViewPage {
    uint64_t gpa;
    uint64_t size;
    void* visibleVa;     // VA mapped when page IS visible
    void* hiddenVa;      // VA mapped when page is NOT visible
    bool defaultVisible; // Default visibility state
};

class EptSplitView {
public:
    EptSplitView(Logger* logger, Partition* partition);
    ~EptSplitView();

    bool Initialize();

    // Register a page range to be split-view managed
    bool RegisterHiddenRange(uint64_t gpa, uint64_t size, void* hiddenVa, void* visibleVa);

    // Set visibility for a specific VCPU
    bool SetPageVisibility(uint32_t vpIndex, uint64_t gpa, bool visible);

    // Apply current view state on VCPU switch (called from ThreadScheduler)
    bool ApplyViewForVcpu(uint32_t vpIndex);

    const std::vector<SplitViewPage>& GetManagedPages() const { return m_pages; }

private:
    Logger* m_logger;
    Partition* m_partition;
    bool m_initialized;

    std::vector<SplitViewPage> m_pages;

    struct VcpuViewState {
        std::unordered_map<uint64_t, bool> pageVisibility;
    };
    std::unordered_map<uint32_t, VcpuViewState> m_vcpuViews;
};
