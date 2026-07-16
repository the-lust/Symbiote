#pragma once
#include <windows.h>
#include "Logger.h"

// Fallthrough: tail-call the real system function for non-sensitive API calls

class Fallthrough {
public:
    explicit Fallthrough(Logger* logger);
    ~Fallthrough();

    void* GetRealProc(const char* dllName, const char* procName);

private:
    Logger* m_logger;

    struct DllCache {
        char name[64];
        HMODULE handle;
    };
    DllCache m_cache[16];
    int m_cacheCount;

    HMODULE GetRealDll(const char* dllName);
};
