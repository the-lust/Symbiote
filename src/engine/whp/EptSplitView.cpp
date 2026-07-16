#include "EptSplitView.h"
#include "Partition.h"

EptSplitView::EptSplitView(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition), m_initialized(false)
{
}

EptSplitView::~EptSplitView()
{
    m_pages.clear();
    m_vcpuViews.clear();
    m_initialized = false;
}

bool EptSplitView::Initialize()
{
    m_initialized = true;
    m_logger->Trace(LOG_WHP, "EptSplitView initialized");
    return true;
}

bool EptSplitView::RegisterHiddenRange(uint64_t gpa, uint64_t size, void* hiddenVa, void* visibleVa)
{
    if (!m_initialized) {
        return false;
    }

    SplitViewPage page;
    page.gpa = gpa;
    page.size = size;
    page.hiddenVa = hiddenVa;
    page.visibleVa = visibleVa;
    page.defaultVisible = false;

    m_pages.push_back(page);

    m_logger->Trace(LOG_WHP, "SplitView registered: GPA=0x%llX size=%llu hidden=%p visible=%p",
        gpa, size, hiddenVa, visibleVa);

    return true;
}

bool EptSplitView::SetPageVisibility(uint32_t vpIndex, uint64_t gpa, bool visible)
{
    if (!m_initialized) {
        return false;
    }

    m_vcpuViews[vpIndex].pageVisibility[gpa] = visible;

    m_logger->Trace(LOG_WHP, "SplitView visibility: VCPU=%u GPA=0x%llX -> %s",
        vpIndex, gpa, visible ? "visible" : "hidden");

    return true;
}

bool EptSplitView::ApplyViewForVcpu(uint32_t vpIndex)
{
    if (!m_initialized || !m_partition) {
        return false;
    }

    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;

    auto viewIt = m_vcpuViews.find(vpIndex);
    bool hasView = (viewIt != m_vcpuViews.end());

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

        m_partition->UnmapGpaRange(page.gpa, page.size);
        if (!m_partition->MapGpaRange(targetVa, page.gpa, page.size, flags)) {
            m_logger->Trace(LOG_ERROR, "SplitView map failed: VCPU=%u GPA=0x%llX %s",
                vpIndex, page.gpa, visible ? "visible" : "hidden");
            return false;
        }

        m_logger->Trace(LOG_WHP, "SplitView applied: VCPU=%u GPA=0x%llX -> %s (VA=%p)",
            vpIndex, page.gpa, visible ? "visible" : "hidden", targetVa);
    }

    return true;
}
