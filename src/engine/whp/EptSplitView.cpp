#include "EptSplitView.h"
#include "Partition.h"
#include <algorithm>

EptSplitView::EptSplitView(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition), m_initialized(false), m_currentGeneration(0)
{
}

EptSplitView::~EptSplitView()
{
    m_pages.clear();
    m_vcpuViews.clear();
    m_gpaToPage.clear();
    m_initialized = false;
}

bool EptSplitView::Initialize()
{
    m_initialized = true;
    m_logger->Trace(LOG_WHP, "EptSplitView initialized (optimized with page caching)");
    return true;
}

uint64_t EptSplitView::GetOptimalPageSize(uint64_t size)
{
    // Use 2MB large pages for regions >= 2MB contiguous
    if (size >= PAGE_SIZE_2M && (size % PAGE_SIZE_2M) == 0) {
        return PAGE_SIZE_2M;
    }
    return PAGE_SIZE_4K;
}

bool EptSplitView::RegisterHiddenRange(uint64_t gpa, uint64_t size, void* hiddenVa, void* visibleVa)
{
    if (!m_initialized) return false;

    SplitViewPage page;
    page.gpa = gpa;
    page.size = size;
    page.hiddenVa = hiddenVa;
    page.visibleVa = visibleVa;
    page.defaultVisible = false;
    page.cachedHiddenVa = hiddenVa;
    page.cachedVisibleVa = visibleVa;

    m_pages.push_back(page);
    m_gpaToPage[gpa] = &m_pages.back();

    m_logger->Trace(LOG_WHP, "SplitView registered: GPA=0x%llX size=%llu (%s) hidden=%p visible=%p",
        gpa, size,
        GetOptimalPageSize(size) == PAGE_SIZE_2M ? "2MB" : "4KB",
        hiddenVa, visibleVa);

    return true;
}

bool EptSplitView::SetPageVisibility(uint32_t vpIndex, uint64_t gpa, bool visible)
{
    if (!m_initialized) return false;

    VcpuViewState& state = m_vcpuViews[vpIndex];
    state.pageVisibility[gpa] = visible;

    return true;
}

bool EptSplitView::MapView(uint64_t gpa, uint64_t size, void* va)
{
    if (!m_partition) return false;

    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;

    // Map with optimal page size
    return m_partition->MapGpaRange(va, gpa, size, flags);
}

bool EptSplitView::UnmapView(uint64_t gpa, uint64_t size)
{
    if (!m_partition) return false;
    return m_partition->UnmapGpaRange(gpa, size);
}

bool EptSplitView::ApplyViewForVcpu(uint32_t vpIndex)
{
    if (!m_initialized || !m_partition) return false;

    auto viewIt = m_vcpuViews.find(vpIndex);
    bool hasView = (viewIt != m_vcpuViews.end());

    // Skip if view already applied at current generation
    uint64_t gen = hasView ? viewIt->second.lastViewGeneration : 0;
    if (gen == m_currentGeneration) {
        return true;
    }

    // Collect all pages that need remapping with their target visibility
    struct Range {
        uint64_t gpa;
        uint64_t size;
        void* targetVa;
        bool visible;
    };
    std::vector<Range> ranges;

    for (const auto& page : m_pages) {
        if (page.size == 0 || page.visibleVa == nullptr || page.hiddenVa == nullptr) {
            continue;
        }

        bool visible = page.defaultVisible;
        if (hasView) {
            auto overrideIt = viewIt->second.pageVisibility.find(page.gpa);
            if (overrideIt != viewIt->second.pageVisibility.end()) {
                visible = overrideIt->second;
            }
        }

        void* targetVa = visible ? page.visibleVa : page.hiddenVa;
        ranges.push_back({page.gpa, page.size, targetVa, visible});
    }

    if (ranges.empty()) return true;

    // Sort by GPA to identify contiguous ranges
    std::sort(ranges.begin(), ranges.end(),
        [](const Range& a, const Range& b) { return a.gpa < b.gpa; });

    // Merge contiguous ranges with same visibility into larger blocks
    std::vector<Range> merged;
    merged.reserve(ranges.size());
    Range current = ranges[0];

    for (size_t i = 1; i < ranges.size(); i++) {
        const Range& next = ranges[i];
        uint64_t currentEnd = current.gpa + current.size;
        bool contiguous = (next.gpa == currentEnd);
        bool sameVisibility = (next.visible == current.visible);

        if (contiguous && sameVisibility) {
            // Extend current range
            current.size += next.size;
        } else {
            merged.push_back(current);
            current = next;
        }
    }
    merged.push_back(current);

    // Apply each merged range with optimal page size (2MB for large blocks)
    int appliedCount = 0;
    for (const auto& range : merged) {
        uint64_t rangeGpa = range.gpa;
        uint64_t rangeSize = range.size;
        uint8_t* rangeVa = (uint8_t*)range.targetVa;

        // Unmap existing mapping
        if (!m_partition->UnmapGpaRange(rangeGpa, rangeSize)) {
            m_logger->Trace(LOG_ERROR, "SplitView unmap failed: VCPU=%u GPA=0x%llX size=%llu",
                vpIndex, rangeGpa, rangeSize);
            return false;
        }

        // Map with read/write access (WHP handles large pages internally)
        WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;

        if (!m_partition->MapGpaRange(rangeVa, rangeGpa, rangeSize, flags)) {
            m_logger->Trace(LOG_ERROR, "SplitView map failed: VCPU=%u GPA=0x%llX size=%llu flags=0x%X",
                vpIndex, rangeGpa, rangeSize, (uint32_t)flags);
            return false;
        }

        m_logger->Trace(LOG_WHP, "SplitView applied: VCPU=%u GPA=0x%llX size=%llu -> %s (VA=%p)",
            vpIndex, rangeGpa, rangeSize,
            range.visible ? "visible" : "hidden", rangeVa);
        appliedCount++;
    }

    m_logger->Trace(LOG_DEBUG, "SplitView: VCPU=%u %d pages merged into %d range(s)",
        vpIndex, (int)ranges.size(), appliedCount);

    // Update generation to avoid redundant remaps
    if (hasView) {
        viewIt->second.lastViewGeneration = ++m_currentGeneration;
    }

    return true;
}

bool EptSplitView::ReadHiddenMemory(uint64_t gpa, void* buffer, uint64_t size)
{
    // Direct read from hidden page without switching view
    auto it = m_gpaToPage.find(gpa);
    if (it == m_gpaToPage.end()) {
        return false;
    }

    SplitViewPage* page = it->second;
    if (!page->hiddenVa || !buffer) return false;

    uint64_t offset = gpa - page->gpa;
    if (offset + size > page->size) return false;

    memcpy(buffer, (uint8_t*)page->hiddenVa + offset, size);
    return true;
}

bool EptSplitView::WriteHiddenMemory(uint64_t gpa, const void* buffer, uint64_t size)
{
    auto it = m_gpaToPage.find(gpa);
    if (it == m_gpaToPage.end()) return false;

    SplitViewPage* page = it->second;
    if (!page->hiddenVa || !buffer) return false;

    uint64_t offset = gpa - page->gpa;
    if (offset + size > page->size) return false;

    memcpy((uint8_t*)page->hiddenVa + offset, buffer, size);
    return true;
}

bool EptSplitView::ProtectMemoryRange(uint64_t gpa, uint64_t size)
{
    if (!m_initialized || !m_partition) return false;

    // Protect a memory range by mapping it as read-only (no write)
    // Denuvo's memory integrity checks write to pages to verify them;
    // blocking writes prevents the check from completing
    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute;

    void* hostVa = nullptr;
    auto it = m_gpaToPage.find(gpa);
    if (it != m_gpaToPage.end() && it->second->visibleVa) {
        hostVa = it->second->visibleVa;
    } else {
        // Find the host VA by reverse lookup from GPA
        // For non-tracked pages, we need to get the mapping from partition
        hostVa = (void*)gpa; // Identity mapping fallback
    }

    bool result = m_partition->MapGpaRange(hostVa, gpa, size, flags);
    if (result) {
        m_logger->Trace(LOG_WHP, "Memory protected (RX only): GPA=0x%llX size=%llu", gpa, size);
    }
    return result;
}

bool EptSplitView::IsManagedGpa(uint64_t gpa) const
{
    return m_gpaToPage.find(gpa) != m_gpaToPage.end();
}
