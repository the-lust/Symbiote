#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include "Logger.h"

class Partition;

struct SplitViewPage {
    uint64_t gpa;
    uint64_t size;
    void* hiddenVa;
    void* visibleVa;
    bool defaultVisible;
    // Pre-mapped handles to avoid remap on every switch
    void* cachedHiddenVa;
    void* cachedVisibleVa;
};

struct VcpuViewState {
    std::unordered_map<uint64_t, bool> pageVisibility;
    // Track currently mapped view to avoid redundant WHvMapGpaRange calls
    uint64_t lastViewGeneration;
};

class EptSplitView {
public:
    explicit EptSplitView(Logger* logger, Partition* partition);
    ~EptSplitView();

    bool Initialize();

    bool RegisterHiddenRange(uint64_t gpa, uint64_t size, void* hiddenVa, void* visibleVa);
    bool SetPageVisibility(uint32_t vpIndex, uint64_t gpa, bool visible);

    // Optimized view application: skip redundant maps, batch contiguous ranges
    bool ApplyViewForVcpu(uint32_t vpIndex);

    // Direct memory access (passthrough view) for reading hidden pages without switching
    bool ReadHiddenMemory(uint64_t gpa, void* buffer, uint64_t size);
    bool WriteHiddenMemory(uint64_t gpa, const void* buffer, uint64_t size);

    // Hide specific memory regions from integrity verification scanning (EPT-based memory protection)
    bool ProtectMemoryRange(uint64_t gpa, uint64_t size);

    // Check if a GPA is currently managed by split-view
    bool IsManagedGpa(uint64_t gpa) const;

private:
    Logger* m_logger;
    Partition* m_partition;
    bool m_initialized;
    uint64_t m_currentGeneration;

    std::vector<SplitViewPage> m_pages;
    std::unordered_map<uint32_t, VcpuViewState> m_vcpuViews;

    // Cache for fast GPA lookup
    std::unordered_map<uint64_t, SplitViewPage*> m_gpaToPage;

    bool MapView(uint64_t gpa, uint64_t size, void* va);
    bool UnmapView(uint64_t gpa, uint64_t size);

    // 2MB/4KB page size selection
    static constexpr uint64_t PAGE_SIZE_4K = 0x1000;
    static constexpr uint64_t PAGE_SIZE_2M = 0x200000;
    static uint64_t GetOptimalPageSize(uint64_t size);
};
