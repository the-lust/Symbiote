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

    // VM software detection
    if (lower.find(L"vmware") != std::wstring::npos) return true;
    if (lower.find(L"vbox") != std::wstring::npos) return true;
    if (lower.find(L"virtualbox") != std::wstring::npos) return true;
    if (lower.find(L"xen") != std::wstring::npos) return true;
    if (lower.find(L"qemu") != std::wstring::npos) return true;
    if (lower.find(L"virtual") != std::wstring::npos) return true;

    // Hyper-V specific artifacts
    if (lower.find(L"hyper-v") != std::wstring::npos) return true;
    if (lower.find(L"hyperv") != std::wstring::npos) return true;
    if (lower.find(L"vmbus") != std::wstring::npos) return true;
    if (lower.find(L"vmics") != std::wstring::npos) return true;
    if (lower.find(L"vmide") != std::wstring::npos) return true;
    if (lower.find(L"vms3") != std::wstring::npos) return true;
    if (lower.find(L"msvm") != std::wstring::npos) return true;
    if (lower.find(L"vmwp") != std::wstring::npos) return true;
    if (lower.find(L"vmgencounter") != std::wstring::npos) return true;

    // Registry paths that expose VM in real hardware vs virtualized
    if (lower.find(L"\\security\\") != std::wstring::npos) return true;
    if (lower.find(L"\\device\\") != std::wstring::npos) return true;

    // Block direct BIOS registry queries that reveal Hyper-V
    if (lower.find(L"hardware\\description\\system\\bios") != std::wstring::npos) return true;
    if (lower.find(L"hardware\\devicemap\\scsi") != std::wstring::npos) return true;

    // Block VM-related service entries
    if (lower.find(L"services\\vmbus") != std::wstring::npos) return true;
    if (lower.find(L"services\\hyperv") != std::wstring::npos) return true;

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
    uint64_t attrPtr = args[3];

    std::wstring path = GetKeyPathFromAttributes(attrPtr);
    bool sensitive = IsSensitiveKey(path);

    if (sensitive) {
        *result = (uint64_t)STATUS_OBJECT_NAME_NOT_FOUND;
        m_logger->Trace(LOG_EMU, "NtOpenKey BLOCKED: %s", path.c_str());
        return true;
    }

    // non-sensitive, fall through
    m_logger->Trace(LOG_EMU, "NtOpenKey fall through: %s", path.c_str());
    return false;
}

bool RegistryEmu::HandleNtQueryValueKey(uint64_t* args, uint64_t* result)
{
    std::wstring path = GetKeyPathFromAttributes(args[2]);
    m_logger->Trace(LOG_EMU, "NtQueryValueKey: %ls", path.c_str());

    // Pass through to real NtQueryValueKey for tracked keys
    typedef NTSTATUS (NTAPI* RealNtQueryValueKey_t)(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
    static RealNtQueryValueKey_t realFunc = (RealNtQueryValueKey_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryValueKey");

    if (realFunc) {
        NTSTATUS status = realFunc((HANDLE)(ULONG_PTR)args[0],
            (PUNICODE_STRING)(uintptr_t)args[1],
            (ULONG)args[3],
            (PVOID)(uintptr_t)args[4],
            (ULONG)args[5],
            (PULONG)(uintptr_t)args[6]);
        *result = (uint64_t)status;
        return true;
    }
    return false;
}

bool RegistryEmu::HandleNtEnumerateKey(uint64_t* args, uint64_t* result)
{
    HANDLE keyHandle = (HANDLE)(ULONG_PTR)args[0];
    ULONG index = (ULONG)args[1];

    // Check virtual keys first
    for (size_t i = 0; i < m_virtualKeys.size(); i++) {
        if ((HANDLE)(ULONG_PTR)m_virtualKeys[i].handle == keyHandle) {
            if (index == 0 && args[4]) {
                // Return virtual key name
                UNICODE_STRING* outName = (UNICODE_STRING*)(uintptr_t)args[4];
                std::wstring name = m_virtualKeys[i].path;
                size_t bytes = (name.size() + 1) * sizeof(wchar_t);
                if (outName->MaximumLength >= bytes) {
                    memcpy(outName->Buffer, name.c_str(), bytes);
                    outName->Length = (USHORT)bytes;
                }
                *result = (uint64_t)STATUS_SUCCESS;
                return true;
            }
        }
    }

    // Pass through to real NtEnumerateKey
    typedef NTSTATUS (NTAPI* RealNtEnumerateKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
    static RealNtEnumerateKey_t realFunc = (RealNtEnumerateKey_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtEnumerateKey");

    if (realFunc) {
        NTSTATUS status = realFunc(keyHandle, index, (ULONG)args[2],
            (PVOID)(uintptr_t)args[3], (ULONG)args[4], (PULONG)(uintptr_t)args[5]);
        *result = (uint64_t)status;
        return true;
    }
    return false;
}

bool RegistryEmu::HandleNtEnumerateValueKey(uint64_t* args, uint64_t* result)
{
    // Pass through to real NtEnumerateValueKey
    typedef NTSTATUS (NTAPI* RealNtEnumerateValueKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
    static RealNtEnumerateValueKey_t realFunc = (RealNtEnumerateValueKey_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtEnumerateValueKey");

    if (realFunc) {
        NTSTATUS status = realFunc((HANDLE)(ULONG_PTR)args[0], (ULONG)args[1],
            (ULONG)args[2], (PVOID)(uintptr_t)args[3], (ULONG)args[4], (PULONG)(uintptr_t)args[5]);
        *result = (uint64_t)status;
        return true;
    }
    return false;
}

bool RegistryEmu::HandleNtCreateKey(uint64_t* args, uint64_t* result)
{
    uint64_t keyHandlePtr = args[0];
    uint64_t handle = AllocHandle();
    m_virtualKeys.push_back({L"(created)", handle});

    if (keyHandlePtr) {
        *(HANDLE*)(uintptr_t)keyHandlePtr = (HANDLE)(ULONG_PTR)handle;
    }

    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool RegistryEmu::HandleNtDeleteKey(uint64_t*, uint64_t* result)
{
    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool RegistryEmu::HandleNtClose(uint64_t* args, uint64_t* result)
{
    uint64_t handle = args[0];
    auto it = std::remove_if(m_virtualKeys.begin(), m_virtualKeys.end(),
        [handle](const VirtualKey& k) { return k.handle == handle; });
    m_virtualKeys.erase(it, m_virtualKeys.end());

    *result = (uint64_t)STATUS_SUCCESS;
    return true;
}
