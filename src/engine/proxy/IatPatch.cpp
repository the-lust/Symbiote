#include "IatPatch.h"
#include <cstring>
#include <cctype>

IatPatch::IatPatch(Logger* logger)
    : m_logger(logger), m_patchCount(0)
{
    memset(m_patches, 0, sizeof(m_patches));
}

IatPatch::~IatPatch()
{
    RestoreAll();
}

static bool IsSystemModule(const char* dllName)
{
    static const char* kSystemDlls[] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll",
        "advapi32.dll", "user32.dll", "gdi32.dll",
        "ws2_32.dll", "winhttp.dll", "dnsapi.dll",
        "iphlpapi.dll", "secur32.dll", "crypt32.dll",
        "wtsapi32.dll", "wbem.dll", "ole32.dll",
        "oleaut32.dll", "combase.dll", "rpcrt4.dll",
        "shlwapi.dll", "shell32.dll", "bcrypt.dll",
        "cfgmgr32.dll", "devobj.dll", "powrprof.dll",
        "setupapi.dll", "mpr.dll", "imm32.dll",
        "version.dll", "winmm.dll", "psapi.dll",
        "dbghelp.dll", "imagehlp.dll", nullptr,
    };
    const char* lower = dllName;
    char buf[64];
    if (strlen(dllName) < sizeof(buf)) {
        for (int i = 0; dllName[i]; i++) buf[i] = (char)tolower(dllName[i]);
        buf[strlen(dllName)] = 0;
        lower = buf;
    }
    for (int i = 0; kSystemDlls[i]; i++) {
        if (strcmp(lower, kSystemDlls[i]) == 0) return true;
    }
    return false;
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
            // Check if the import is via ApiSet — compare normalized names
            if (!IsSystemModule(dllName)) {
                importDesc++;
                continue;
            }
            // Handle ApiSet contract names — strip "api-" prefix and match suffix
            if (strncmp(importedDll, "api-", 4) == 0 && strncmp(dllName, "api-", 4) == 0) {
                if (_stricmp(importedDll, dllName) != 0) {
                    importDesc++;
                    continue;
                }
            } else if (strncmp(importedDll, "api-", 4) == 0) {
                // Skip ApiSet contracts when matching against real DLL names
                importDesc++;
                continue;
            } else {
                importDesc++;
                continue;
            }
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

    // Check bound imports as fallback
    IMAGE_DATA_DIRECTORY boundDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    if (boundDir.Size > 0) {
        PIMAGE_BOUND_IMPORT_DESCRIPTOR boundDesc = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((uintptr_t)hMod + boundDir.VirtualAddress);
        while (boundDesc->OffsetModuleName) {
            const char* boundName = (const char*)((uintptr_t)hMod + boundDesc->OffsetModuleName);
            if (_stricmp(boundName, dllName) == 0) {
                m_logger->Trace(LOG_PROXY, "bound import found for %s:%s - resolving via LoadLibrary", dllName, funcName);
                // Bound imports are pre-resolved at link time; we can't intercept them
                // via the IAT. The caller should use an EAT patch instead.
                return false;
            }
            boundDesc++;
        }
    }

    // Check delay-load imports as fallback
    IMAGE_DATA_DIRECTORY delayDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delayDir.Size > 0) {
        PIMAGE_DELAYLOAD_DESCRIPTOR delayDesc = (PIMAGE_DELAYLOAD_DESCRIPTOR)((uintptr_t)hMod + delayDir.VirtualAddress);
        while (delayDesc->DllNameRVA) {
            const char* delayName = (const char*)((uintptr_t)hMod + delayDesc->DllNameRVA);
            if (_stricmp(delayName, dllName) == 0) {
                m_logger->Trace(LOG_PROXY, "delay-load import found for %s:%s", dllName, funcName);
                // Walk the delay-load import table
                PIMAGE_THUNK_DATA delayIAT = (PIMAGE_THUNK_DATA)((uintptr_t)hMod + delayDesc->ImportAddressTableRVA);
                PIMAGE_THUNK_DATA delayINT = (PIMAGE_THUNK_DATA)((uintptr_t)hMod + delayDesc->ImportNameTableRVA);

                // Check if the delay-load has been triggered (IAT populated)
                if (delayIAT->u1.Function) {
                    for (int i = 0; delayIAT[i].u1.Function; i++) {
                        if (!(delayINT[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                            PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)hMod + delayINT[i].u1.AddressOfData);
                            if (strcmp(ibn->Name, funcName) == 0) {
                                DWORD oldProtect;
                                VirtualProtect(&delayIAT[i].u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                                if (m_patchCount < 64) {
                                    m_patches[m_patchCount].address = &delayIAT[i].u1.Function;
                                    m_patches[m_patchCount].original = (void*)delayIAT[i].u1.Function;
                                    m_patches[m_patchCount].isIAT = true;
                                    m_patchCount++;
                                }
                                delayIAT[i].u1.Function = (uintptr_t)newFunc;
                                VirtualProtect(&delayIAT[i].u1.Function, sizeof(void*), oldProtect, &oldProtect);
                                m_logger->Trace(LOG_PROXY, "delay-load IAT patched: %s!%s -> %p", dllName, funcName, newFunc);
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
            delayDesc++;
        }
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

            // Check if it's a forwarded export (points to another module)
            if (*funcAddr >= exportDir.VirtualAddress &&
                *funcAddr < exportDir.VirtualAddress + exportDir.Size) {
                const char* forwardStr = (const char*)((uintptr_t)hMod + *funcAddr);
                m_logger->Trace(LOG_PROXY, "forwarded export %s!%s -> %s, skipping EAT patch", dllName, funcName, forwardStr);
                return false;
            }

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
