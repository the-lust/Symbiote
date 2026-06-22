#define WIN32_NO_STATUS
#include "RegistryEmu.h"
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <algorithm>
#include <cstring>

#ifndef _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
#define _UNICODE_STRING_DEFINED
#endif

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

RegistryEmu::RegistryEmu(Logger* logger)
    : m_logger(logger), m_nextHandle(0x1000)
{
}

uint64_t RegistryEmu::AllocHandle()
{
    return m_nextHandle++;
}

bool RegistryEmu::IsSensitiveKey(const std::wstring& path) const
{
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    if (lower.find(L"\\security") != std::wstring::npos) return true;
    if (lower.find(L"vmware") != std::wstring::npos) return true;
    if (lower.find(L"vbox") != std::wstring::npos) return true;
    if (lower.find(L"xen") != std::wstring::npos) return true;
    if (lower.find(L"virtualbox") != std::wstring::npos) return true;
    if (lower.find(L"\\device\\") != std::wstring::npos) return true;

    return false;
}

static std::wstring ReadUnicodeString(uint64_t usPtr)
{
    if (!usPtr) return L"";
    UNICODE_STRING us;
    memcpy(&us, (void*)(uintptr_t)usPtr, sizeof(us));
    if (!us.Buffer || us.Length == 0) return L"";
    std::wstring result(us.Length / sizeof(wchar_t), L'\0');
    memcpy(&result[0], us.Buffer, us.Length);
    return result;
}

static std::wstring GetKeyPathFromAttributes(uint64_t attrPtr)
{
    if (!attrPtr) return L"(null)";
    OBJECT_ATTRIBUTES oa;
    memcpy(&oa, (void*)(uintptr_t)attrPtr, sizeof(oa));
    if (oa.ObjectName) {
        return ReadUnicodeString((uint64_t)(uintptr_t)oa.ObjectName);
    }
    return L"(no name)";
}

bool RegistryEmu::HandleNtOpenKey(uint64_t* args, uint64_t* result)
{
    uint64_t keyHandlePtr = args[0];
    uint32_t access = (uint32_t)args[2];
    uint64_t attrPtr = args[3];

    std::wstring path = GetKeyPathFromAttributes(attrPtr);
    bool sensitive = IsSensitiveKey(path);

    if (sensitive) {
        *result = STATUS_OBJECT_NAME_NOT_FOUND;
        m_logger->Trace(LOG_SOGEN, "NtOpenKey BLOCKED: %s", path.c_str());
        return true;
    }

    // non-sensitive, fall through
    m_logger->Trace(LOG_SOGEN, "NtOpenKey fall through: %s", path.c_str());
    return false;
}

bool RegistryEmu::HandleNtQueryValueKey(uint64_t* args, uint64_t* result)
{
    // fall through
    return false;
}

bool RegistryEmu::HandleNtEnumerateKey(uint64_t* args, uint64_t* result)
{
    *result = STATUS_NO_MORE_ENTRIES;
    return true;
}

bool RegistryEmu::HandleNtEnumerateValueKey(uint64_t* args, uint64_t* result)
{
    *result = STATUS_NO_MORE_ENTRIES;
    return true;
}

bool RegistryEmu::HandleNtCreateKey(uint64_t* args, uint64_t* result)
{
    uint64_t keyHandlePtr = args[0];
    uint64_t handle = AllocHandle();
    m_virtualKeys.push_back({L"(created)", handle});

    if (keyHandlePtr) {
        *(HANDLE*)(uintptr_t)keyHandlePtr = (HANDLE)(ULONG_PTR)handle;
    }

    *result = STATUS_SUCCESS;
    return true;
}

bool RegistryEmu::HandleNtDeleteKey(uint64_t* args, uint64_t* result)
{
    *result = STATUS_SUCCESS;
    return true;
}

bool RegistryEmu::HandleNtClose(uint64_t* args, uint64_t* result)
{
    uint64_t handle = args[0];
    auto it = std::remove_if(m_virtualKeys.begin(), m_virtualKeys.end(),
        [handle](const VirtualKey& k) { return k.handle == handle; });
    m_virtualKeys.erase(it, m_virtualKeys.end());

    *result = STATUS_SUCCESS;
    return true;
}
