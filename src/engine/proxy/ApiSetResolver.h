#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <windows.h>
#include "Logger.h"

class ApiSetResolver {
public:
    explicit ApiSetResolver(Logger* logger);
    ~ApiSetResolver();

    bool Initialize();
    std::wstring Resolve(const std::wstring& apiSetName) const;
    const std::unordered_map<std::wstring, std::wstring>& GetMappings() const;
    bool IsInitialized() const { return m_initialized; }
    void LogCoverage() const;

private:
    Logger* m_logger;
    std::unordered_map<std::wstring, std::wstring> m_mappings;
    bool m_initialized;

    bool ParseV6();
    uintptr_t FindApiSetMap();
};
