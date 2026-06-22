#include "ModuleCloak.h"
#include <winternl.h>
#include <cstring>
#include <algorithm>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // more fields but we only need up to BaseDllName
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

ModuleCloak::ModuleCloak(Logger* logger)
    : m_logger(logger), m_cloaked(false)
{
}

ModuleCloak::~ModuleCloak()
{
}

bool ModuleCloak::CloakModule()
{
    if (m_cloaked) return true;

    bool pebHidden = HideFromPEB();
    bool ldrHidden = HideFromLdr();

    m_cloaked = pebHidden || ldrHidden;
    return m_cloaked;
}

bool ModuleCloak::HideFromPEB()
{
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb) {
        m_logger->Trace(LOG_ERROR, "Cannot read PEB");
        return false;
    }

    PMY_PEB_LDR_DATA ldr = (PMY_PEB_LDR_DATA)peb->Ldr;
    if (!ldr) {
        m_logger->Trace(LOG_ERROR, "Cannot read LDR");
        return false;
    }

    HMODULE hMod;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)_ReturnAddress(), &hMod)) {
        m_logger->Trace(LOG_ERROR, "Cannot get own module handle");
        return false;
    }

    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        PMY_LDR_DATA_TABLE_ENTRY ldrEntry = (PMY_LDR_DATA_TABLE_ENTRY)
            CONTAINING_RECORD(entry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (ldrEntry->DllBase == hMod) {
            entry->Blink->Flink = entry->Flink;
            entry->Flink->Blink = entry->Blink;

            m_logger->Trace(LOG_PROXY, "Module unlinked from PEB InMemoryOrderModuleList");
            return true;
        }
        entry = entry->Flink;
    }

    m_logger->Trace(LOG_WARNING, "Module not found in PEB module list");
    return false;
}

bool ModuleCloak::HideFromLdr()
{
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return false;

    PMY_PEB_LDR_DATA ldr = (PMY_PEB_LDR_DATA)peb->Ldr;

    HMODULE hMod;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)_ReturnAddress(), &hMod)) {
        return false;
    }

    LIST_ENTRY* head = &ldr->InInitializationOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        PMY_LDR_DATA_TABLE_ENTRY ldrEntry = (PMY_LDR_DATA_TABLE_ENTRY)
            CONTAINING_RECORD(entry, MY_LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

        if (ldrEntry->DllBase == hMod) {
            entry->Blink->Flink = entry->Flink;
            entry->Flink->Blink = entry->Blink;

            m_logger->Trace(LOG_PROXY, "Module unlinked from InInitializationOrderModuleList");
            return true;
        }
        entry = entry->Flink;
    }

    return false;
}
