#include "IatPatch.h"
#include <cstring>

IatPatch::IatPatch(Logger* logger)
    : m_logger(logger), m_patchCount(0)
{
    memset(m_patches, 0, sizeof(m_patches));
}

IatPatch::~IatPatch()
{
    RestoreAll();
}

bool IatPatch::PatchIAT(const char* dllName, const char* funcName, void* newFunc)
{
    HMODULE hMod = GetModuleHandleW(NULL);
    if (!hMod) return false;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)hMod + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0) return false;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)hMod + importDir.VirtualAddress);

    while (importDesc->Name) {
        const char* importedDll = (const char*)((uintptr_t)hMod + importDesc->Name);
        if (_stricmp(importedDll, dllName) != 0) {
            importDesc++;
            continue;
        }

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uintptr_t)hMod + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((uintptr_t)hMod + importDesc->OriginalFirstThunk);

        while (thunk->u1.Function) {
            if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)hMod + origThunk->u1.AddressOfData);
                if (strcmp(importByName->Name, funcName) == 0) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);

                    if (m_patchCount < 64) {
                        m_patches[m_patchCount].address = &thunk->u1.Function;
                        m_patches[m_patchCount].original = (void*)thunk->u1.Function;
                        m_patches[m_patchCount].isIAT = true;
                        m_patchCount++;
                    }

                    thunk->u1.Function = (uintptr_t)newFunc;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);

                    m_logger->Trace(LOG_PROXY, "IAT patched: %s!%s -> %p", dllName, funcName, newFunc);
                    return true;
                }
            }
            thunk++;
            origThunk++;
        }
        importDesc++;
    }

    return false;
}

bool IatPatch::PatchEAT(const char* dllName, const char* funcName, void* newFunc)
{
    HMODULE hMod = GetModuleHandleA(dllName);
    if (!hMod) {
        m_logger->Trace(LOG_ERROR, "PatchEAT: cannot find module %s", dllName);
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)hMod + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0) return false;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)hMod + exportDir.VirtualAddress);

    DWORD* names = (DWORD*)((uintptr_t)hMod + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((uintptr_t)hMod + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((uintptr_t)hMod + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((uintptr_t)hMod + names[i]);
        if (strcmp(name, funcName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD* funcAddr = &functions[ordinal];

            DWORD oldProtect;
            VirtualProtect(funcAddr, sizeof(DWORD), PAGE_READWRITE, &oldProtect);

            if (m_patchCount < 64) {
                m_patches[m_patchCount].address = funcAddr;
                m_patches[m_patchCount].original = (void*)(uintptr_t)*funcAddr;
                m_patches[m_patchCount].isIAT = false;
                m_patchCount++;
            }

            *funcAddr = (DWORD)(uintptr_t)newFunc;
            VirtualProtect(funcAddr, sizeof(DWORD), oldProtect, &oldProtect);

            m_logger->Trace(LOG_PROXY, "EAT patched: %s!%s -> %p", dllName, funcName, newFunc);
            return true;
        }
    }

    return false;
}

bool IatPatch::RestoreAll()
{
    for (int i = 0; i < m_patchCount; i++) {
        DWORD oldProtect;
        VirtualProtect(m_patches[i].address, sizeof(void*), PAGE_READWRITE, &oldProtect);
        *(void**)m_patches[i].address = m_patches[i].original;
        VirtualProtect(m_patches[i].address, sizeof(void*), oldProtect, &oldProtect);
    }
    m_patchCount = 0;
    return true;
}
