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
            // A prior version had an "ApiSet contract name" branch here that looked like it
            // resolved api-ms-win-*.dll import names against a target dllName via ApiSetResolver,
            // but every path through it ended in `continue` (including the "both start with
            // api-" case, which re-checked the same _stricmp already known to be nonzero) — it
            // was dead code that never actually did ApiSet resolution, just an exact-name match
            // dressed up to look smarter. ApiSetResolver (see ApiSetResolver.h) exists and could
            // wire real resolution in here, but isn't hooked up — for now this is honestly just
            // an exact (case-insensitive) name match.
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
            // ordinal indexes into AddressOfFunctions (NumberOfFunctions entries) — a prior
            // version never checked this against a malformed/unusual export table, which is an
            // out-of-bounds read *and* (since the code below writes through funcAddr) write.
            if (ordinal >= exports->NumberOfFunctions) {
                m_logger->Trace(LOG_ERROR, "PatchEAT: ordinal %u out of range (max %u) for %s!%s",
                    ordinal, exports->NumberOfFunctions, dllName, funcName);
                return false;
            }
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
        // EAT patches store a DWORD* into the tightly-packed 4-byte AddressOfFunctions RVA
        // array (see PatchEAT), not a full pointer slot like IAT entries. A prior version
        // always did an 8-byte pointer-sized write here regardless of isIAT, which for EAT
        // entries correctly restored the patched export's low 4 bytes but zeroed the RVA of
        // the *next* export in the table.
        size_t writeSize = m_patches[i].isIAT ? sizeof(void*) : sizeof(DWORD);
        DWORD oldProtect;
        VirtualProtect(m_patches[i].address, writeSize, PAGE_READWRITE, &oldProtect);
        if (m_patches[i].isIAT) {
            *(void**)m_patches[i].address = m_patches[i].original;
        } else {
            *(DWORD*)m_patches[i].address = (DWORD)(uintptr_t)m_patches[i].original;
        }
        VirtualProtect(m_patches[i].address, writeSize, oldProtect, &oldProtect);
    }
    m_patchCount = 0;
    return true;
}
