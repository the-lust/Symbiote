#pragma once
#include <windows.h>
#include "Logger.h"

class IatPatch {
public:
    explicit IatPatch(Logger* logger);
    ~IatPatch();

    bool PatchIAT(const char* dllName, const char* funcName, void* newFunc);
    bool PatchEAT(const char* dllName, const char* funcName, void* newFunc);
    bool RestoreAll();

private:
    Logger* m_logger;

    struct PatchEntry {
        void* address;
        void* original;
        bool isIAT;
    };
    PatchEntry m_patches[64];
    int m_patchCount;
};
