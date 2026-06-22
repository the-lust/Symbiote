#define WIN32_NO_STATUS
#include "FileEmu.h"
#include <winternl.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winioctl.h>
#include <algorithm>
#include <cstring>
#include <sstream>

// UNICODE_STRING and OBJECT_ATTRIBUTES come from winternl.h

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

static std::wstring GetFilePathFromAttributes(uint64_t attrPtr)
{
    if (!attrPtr) return L"(null)";
    OBJECT_ATTRIBUTES oa;
    memcpy(&oa, (void*)(uintptr_t)attrPtr, sizeof(oa));
    if (oa.ObjectName) {
        return ReadUnicodeString((uint64_t)(uintptr_t)oa.ObjectName);
    }
    return L"(no name)";
}

static std::wstring GetFileNameFromCreateArgs(uint64_t* args)
{
    // NtCreateFile parameters:
    // args[0] = FileHandle
    // args[1] = DesiredAccess
    // args[2] = ObjectAttributes (pointr)
    // args[3] = IoStatusBlock
    // args[4] = AllocationSize
    // args[5] = FileAttributes
    // args[6] = ShareAccess
    // args[7] = CreateDisposition
    // args[8] = CreateOptions
    return GetFilePathFromAttributes(args[2]);
}

FileEmu::FileEmu(Logger* logger)
    : m_logger(logger)
{
}

bool FileEmu::IsSensitiveFile(const std::wstring& path) const
{
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    if (lower.find(L"\\device\\physicaldrive") != std::wstring::npos) return true;
    if (lower.find(L"\\device\\harddisk") != std::wstring::npos) return true;
    if (lower.find(L"vmware") != std::wstring::npos) return true;
    if (lower.find(L"vbox") != std::wstring::npos) return true;
    if (lower.find(L"xen") != std::wstring::npos) return true;

    return false;
}

bool FileEmu::HandleNtCreateFile(uint64_t* args, uint64_t* result)
{
    std::wstring path = GetFileNameFromCreateArgs(args);
    m_logger->Trace(LOG_SOGEN, "NtCreateFile: %ls", path.c_str());

    if (IsSensitiveFile(path)) {
        *result = STATUS_OBJECT_NAME_NOT_FOUND;
        return true;
    }

    // not sensitive, fall through
    return false;
}

bool FileEmu::HandleNtReadFile(uint64_t* args, uint64_t* result)
{
    // fall through
    return false;
}

bool FileEmu::HandleNtWriteFile(uint64_t* args, uint64_t* result)
{
    // fall through
    return false;
}

bool FileEmu::HandleNtQueryInformationFile(uint64_t* args, uint64_t* result)
{
    // fall through
    return false;
}

bool FileEmu::HandleNtQueryVolumeInformationFile(uint64_t* args, uint64_t* result)
{
    auto infoClass = (uint32_t)args[4];
    uint64_t buffer = args[2];
    uint32_t length = (uint32_t)args[3];

    switch (infoClass) {
        case 5: { // FileFsSizeInformation
            if (length < 24) { *result = STATUS_INFO_LENGTH_MISMATCH; return true; }
            typedef struct _FILE_FS_SIZE_INFO {
                LARGE_INTEGER TotalAllocationUnits;
                LARGE_INTEGER AvailableAllocationUnits;
                ULONG SectorsPerAllocationUnit;
                ULONG BytesPerSector;
            } FILE_FS_SIZE_INFO;
            FILE_FS_SIZE_INFO info;
            info.TotalAllocationUnits.QuadPart = 0x1000000;
            info.AvailableAllocationUnits.QuadPart = 0x800000;
            info.SectorsPerAllocationUnit = 8;
            info.BytesPerSector = 512;
            memcpy((void*)(uintptr_t)buffer, &info, sizeof(info));
            *result = STATUS_SUCCESS;
            return true;
        }
        default:
            *result = STATUS_SUCCESS;
            return true;
    }
}

bool FileEmu::HandleNtDeviceIoControlFile(uint64_t* args, uint64_t* result)
{
    uint32_t ioControlCode = (uint32_t)args[5];

    m_logger->Trace(LOG_SOGEN, "NtDeviceIoControlFile code=0x%X", ioControlCode);

    switch (ioControlCode) {
        case IOCTL_STORAGE_QUERY_PROPERTY: {
            uint64_t outputBuffer = args[7];
            uint32_t outputLength = (uint32_t)args[8];

            if (outputLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                *result = STATUS_BUFFER_TOO_SMALL;
                return true;
            }

            STORAGE_DEVICE_DESCRIPTOR desc;
            memset(&desc, 0, sizeof(desc));
            desc.Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
            desc.Size = sizeof(STORAGE_DEVICE_DESCRIPTOR);
            desc.DeviceType = FILE_DEVICE_DISK;
            desc.DeviceTypeModifier = 0;
            desc.CommandQueueing = TRUE;
            desc.VendorIdOffset = 0;
            desc.ProductIdOffset = 0;
            desc.ProductRevisionOffset = 0;
            desc.SerialNumberOffset = 0;
            desc.BusType = BusTypeSata;

            memcpy((void*)(uintptr_t)outputBuffer, &desc, sizeof(desc));

            if (outputLength > sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                memset((void*)((uintptr_t)outputBuffer + sizeof(STORAGE_DEVICE_DESCRIPTOR)), 0,
                       outputLength - sizeof(STORAGE_DEVICE_DESCRIPTOR));
            }
            *result = STATUS_SUCCESS;
            return true;
        }
        default:
            // GPU IOCTLs and other non-storage DeviceIoControl: fall through to real system
            return false;
    }
}

bool FileEmu::HandleNtQueryAttributesFile(uint64_t* args, uint64_t* result)
{
    // pass through to real NtQueryAttributesFile
    typedef NTSTATUS (WINAPI* NtQueryAttributesFileFunc)(POBJECT_ATTRIBUTES, PVOID);
    static NtQueryAttributesFileFunc realFunc = (NtQueryAttributesFileFunc)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryAttributesFile");

    if (realFunc) {
        NTSTATUS status = realFunc((POBJECT_ATTRIBUTES)args[0], (PVOID)args[1]);
        if (result) *result = (uint64_t)status;
        return true;
    }

    return false;
}

bool FileEmu::HandleNtOpenFile(uint64_t* args, uint64_t* result)
{
    // pass through to real NtOpenFile
    typedef NTSTATUS (WINAPI* NtOpenFileFunc)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID, ULONG, ULONG);
    static NtOpenFileFunc realFunc = (NtOpenFileFunc)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");

    if (realFunc) {
        NTSTATUS status = realFunc((PHANDLE)args[0], (ACCESS_MASK)args[1],
            (POBJECT_ATTRIBUTES)args[2], (PVOID)args[3], (ULONG)args[4], (ULONG)args[5]);
        if (result) *result = (uint64_t)status;
        return true;
    }

    return false;
}

bool FileEmu::HandleNtDeleteFile(uint64_t* args, uint64_t* result)
{
    typedef NTSTATUS (WINAPI* NtDeleteFileFunc)(POBJECT_ATTRIBUTES);
    static NtDeleteFileFunc realFunc = (NtDeleteFileFunc)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDeleteFile");

    if (realFunc) {
        NTSTATUS status = realFunc((POBJECT_ATTRIBUTES)args[0]);
        if (result) *result = (uint64_t)status;
        return true;
    }

    return false;
}

bool FileEmu::HandleNtQueryDirectoryFile(uint64_t* args, uint64_t* result)
{
    typedef NTSTATUS (WINAPI* NtQueryDirectoryFileFunc)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, ULONG, ULONG, BOOLEAN, PUNICODE_STRING, BOOLEAN);
    static NtQueryDirectoryFileFunc realFunc = (NtQueryDirectoryFileFunc)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryDirectoryFile");

    if (realFunc) {
        NTSTATUS status = realFunc((HANDLE)args[0], (HANDLE)args[1], (PVOID)args[2],
            (PVOID)args[3], (PVOID)args[4], (PVOID)args[5], (ULONG)args[6],
            (ULONG)args[7], (BOOLEAN)args[8], (PUNICODE_STRING)args[9], (BOOLEAN)args[10]);
        if (result) *result = (uint64_t)status;
        return true;
    }

    return false;
}

bool FileEmu::HandleNtNotifyChangeDirectoryFile(uint64_t* args, uint64_t* result)
{
    typedef NTSTATUS (WINAPI* NtNotifyChangeDirectoryFileFunc)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, ULONG, ULONG, BOOLEAN);
    static NtNotifyChangeDirectoryFileFunc realFunc = (NtNotifyChangeDirectoryFileFunc)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtNotifyChangeDirectoryFile");

    if (realFunc) {
        NTSTATUS status = realFunc((HANDLE)args[0], (HANDLE)args[1], (PVOID)args[2],
            (PVOID)args[3], (PVOID)args[4], (PVOID)args[5], (ULONG)args[6],
            (ULONG)args[7], (BOOLEAN)args[8]);
        if (result) *result = (uint64_t)status;
        return true;
    }

    return false;
}
