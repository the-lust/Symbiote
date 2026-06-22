#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"

class PeLoader {
public:
    explicit PeLoader(Logger* logger);
    ~PeLoader();

    bool LoadImage(const std::wstring& path, uint8_t** outImage, size_t* outSize);
    bool ResolveImports(uint8_t* image, size_t size);
    bool ApplyRelocations(uint8_t* image, size_t size, uint64_t baseAddr);
    uint64_t GetEntryPoint(uint8_t* image, size_t size);

    struct ImportedFunction {
        std::string dllName;
        std::string funcName;
        uintptr_t address;
    };

    std::vector<ImportedFunction> GetImports(uint8_t* image, size_t size);

private:
    Logger* m_logger;

    bool IsPeImage(const uint8_t* data, size_t size);
    PIMAGE_NT_HEADERS GetNtHeaders(const uint8_t* data, size_t size);
};