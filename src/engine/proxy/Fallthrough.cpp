#include "Fallthrough.h"
#include <cstring>

Fallthrough::Fallthrough(Logger* logger)
    : m_logger(logger), m_cacheCount(0)
{
    memset(m_cache, 0, sizeof(m_cache));
}

Fallthrough::~Fallthrough()
{
}

HMODULE Fallthrough::GetRealDll(const char* dllName)
{
    for (int i = 0; i < m_cacheCount; i++) {
        if (_stricmp(m_cache[i].name, dllName) == 0) {
            return m_cache[i].handle;
        }
    }

    wchar_t wideName[64];
    size_t converted = 0;
    mbstowcs_s(&converted, wideName, dllName, 63);

    wchar_t systemDir[MAX_PATH];
    GetSystemDirectoryW(systemDir, MAX_PATH);
    wchar_t fullPath[MAX_PATH];
    swprintf_s(fullPath, L"%s\\%s", systemDir, wideName);

    HMODULE hMod = LoadLibraryW(fullPath);
    if (!hMod && m_cacheCount < 16) {
        hMod = LoadLibraryA(dllName);
    }

    if (hMod && m_cacheCount < 16) {
        strncpy_s(m_cache[m_cacheCount].name, dllName, 63);
        m_cache[m_cacheCount].handle = hMod;
        m_cacheCount++;
    }

    return hMod;
}

void* Fallthrough::GetRealProc(const char* dllName, const char* procName)
{
    HMODULE hMod = GetRealDll(dllName);
    if (!hMod) {
        m_logger->Trace(LOG_ERROR, "Fallthrough: cannot load %s", dllName);
        return nullptr;
    }

    void* proc = (void*)GetProcAddress(hMod, procName);
    if (!proc) {
        m_logger->Trace(LOG_ERROR, "Fallthrough: cannot find %s!%s", dllName, procName);
    }
    return proc;
}
