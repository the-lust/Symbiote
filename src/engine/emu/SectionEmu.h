#pragma once
#include <windows.h>
#include <vector>
#include "Logger.h"

class SectionEmu {
public:
    explicit SectionEmu(Logger* logger);
    ~SectionEmu();

    bool HandleNtCreateSection(uint64_t* args, uint64_t* result);
    bool HandleNtOpenSection(uint64_t* args, uint64_t* result);
    bool HandleNtMapViewOfSection(uint64_t* args, uint64_t* result);
    bool HandleNtUnmapViewOfSection(uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;

    struct SectionInfo {
        HANDLE handle;
        uint64_t size;
        uint32_t protect;
    };
    std::vector<SectionInfo> m_sections;
    uint64_t m_nextHandle;
};