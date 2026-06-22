#pragma once
#include <windows.h>
#include <string>
#include "Logger.h"

class ModuleCloak;

class ProxyBase {
public:
    ProxyBase(const std::wstring& realDllPath, Logger* logger);
    ~ProxyBase();

    bool Initialize();
    void* GetRealProc(const char* procName);
    bool HookSensitiveFunctions();

    void SetSpoofHandler(bool (*handler)(const char* dllName, const char* funcName,
                                          void* origFunc, uint64_t* args, uint64_t* result));

    static ProxyBase* GetInstance() { return s_instance; }
    Logger* GetLogger() { return m_logger; }

    typedef bool (*SpoofHandler)(const char* dllName, const char* funcName,
                                  void* origFunc, uint64_t* args, uint64_t* result);

private:
    static ProxyBase* s_instance;
    std::wstring m_realDllPath;
    HMODULE m_realDll;
    Logger* m_logger;
    ModuleCloak* m_moduleCloak;
    SpoofHandler m_spoofHandler;
};
