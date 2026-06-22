#pragma once
#include <cstdint>
#include <vector>
#include <windows.h>
#include "Logger.h"

class RegistryEmu {
public:
    explicit RegistryEmu(Logger* logger);

    bool HandleNtOpenKey(uint64_t* args, uint64_t* result);
    bool HandleNtQueryValueKey(uint64_t* args, uint64_t* result);
    bool HandleNtEnumerateKey(uint64_t* args, uint64_t* result);
    bool HandleNtEnumerateValueKey(uint64_t* args, uint64_t* result);
    bool HandleNtCreateKey(uint64_t* args, uint64_t* result);
    bool HandleNtDeleteKey(uint64_t* args, uint64_t* result);
    bool HandleNtClose(uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;

    struct VirtualKey {
        std::wstring path;
        uint64_t handle;
    };
    std::vector<VirtualKey> m_virtualKeys;
    uint64_t m_nextHandle;

    bool IsSensitiveKey(const std::wstring& path) const;
    uint64_t AllocHandle();
};
