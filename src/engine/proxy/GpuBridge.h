#pragma once
#include <windows.h>
#include <string>
#include "Logger.h"

class GpuBridge {
public:
    explicit GpuBridge(Logger* logger);
    ~GpuBridge();

    bool Initialize();

    void* GetRealProc(const char* dllName, const char* procName);

    bool IsGpuDll(const char* dllName) const;

    bool IsGpuFunction(const char* dllName, const char* funcName) const;

    static const int MAX_GPU_DLLS = 8;
    static const int MAX_GPU_EXPORTS = 64;

private:
    struct GpuDllInfo {
        char name[64];
        HMODULE handle;
        struct {
            char name[128];
            void* addr;
        } exports[MAX_GPU_EXPORTS];
        int exportCount;
    };

    GpuDllInfo m_gpuDlls[MAX_GPU_DLLS];
    int m_gpuDllCount;

    Logger* m_logger;

    void AddGpuDll(const char* name);
    bool LoadGpuDll(int index);
};

extern GpuBridge* g_gpuBridge;