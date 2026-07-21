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
#include "whp/SandboxFallthrough.h"

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
    m_logger->Trace(LOG_EMU, "NtCreateFile: %ls", path.c_str());

    if (IsSensitiveFile(path)) {
        *result = (uint64_t)STATUS_OBJECT_NAME_NOT_FOUND;
        return true;
    }

    // Sandbox path redirection
    if (g_sandboxFallthrough && g_sandboxFallthrough->IsInitialized()) {
        ULONG createDisposition = (ULONG)args[7];
        bool isWrite = (createDisposition != FILE_OPEN && createDisposition != FILE_OPEN_IF);
        FileRedirection::FileInfo info;
        if (g_sandboxFallthrough->HandleFileOperation(path.c_str(), isWrite, info)) {
            if (info.isRedirected) {
                std::wstring targetPath;
                if (isWrite) {
                    g_sandboxFallthrough->EnsureFileWriteCopy(info.truePath.c_str());
                    targetPath = info.boxPath;
                } else {
                    targetPath = info.boxPath;
                    if (GetFileAttributesW(targetPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                        targetPath = info.truePath;
                    }
                }
                // Create a modified OBJECT_ATTRIBUTES pointing to the target path
                UNICODE_STRING targetUs;
                targetUs.Buffer = &targetPath[0];
                targetUs.Length = (USHORT)(targetPath.size() * sizeof(wchar_t));
                targetUs.MaximumLength = targetUs.Length;
                OBJECT_ATTRIBUTES targetOa;
                memcpy(&targetOa, (void*)(uintptr_t)args[2], sizeof(targetOa));
                targetOa.RootDirectory = NULL;
                targetOa.ObjectName = &targetUs;
                // Call real NtCreateFile with redirected path
                typedef NTSTATUS (NTAPI* RealNtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
                static RealNtCreateFile_t realFunc = (RealNtCreateFile_t)
                    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
                if (realFunc) {
                    HANDLE hFile = NULL;
                    IO_STATUS_BLOCK iosb;
                    NTSTATUS status = realFunc(&hFile, (ACCESS_MASK)args[1], &targetOa, &iosb,
                        (PLARGE_INTEGER)args[4], (ULONG)args[5], (ULONG)args[6],
                        (ULONG)args[7], (ULONG)args[8], (PVOID)args[9], (ULONG)args[10]);
                    if (args[0]) *(HANDLE*)(uintptr_t)args[0] = hFile;
                    if (args[3]) memcpy((void*)(uintptr_t)args[3], &iosb, sizeof(iosb));
                    *result = (uint64_t)status;
                    return true;
                }
            }
        }
    }

    // not sensitive, fall through
    return false;
}

bool FileEmu::HandleNtReadFile(uint64_t* args, uint64_t* result)
{
    HANDLE hFile = (HANDLE)(ULONG_PTR)args[0];
    PVOID buffer = (PVOID)(uintptr_t)args[1];
    ULONG length = (ULONG)args[2];
    PULONG bytesRead = (PULONG)(uintptr_t)args[3];
    PLARGE_INTEGER offset = (PLARGE_INTEGER)(uintptr_t)args[4];

    typedef NTSTATUS (NTAPI* RealNtReadFile_t)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, ULONG, PULONG, PLARGE_INTEGER);
    static RealNtReadFile_t realFunc = (RealNtReadFile_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadFile");

    if (!realFunc) return false;
    NTSTATUS status = realFunc(hFile, nullptr, nullptr, nullptr, (PIO_STATUS_BLOCK)buffer, buffer, length, bytesRead, offset);
    *result = (uint64_t)status;
    return true;
}

bool FileEmu::HandleNtWriteFile(uint64_t* args, uint64_t* result)
{
    HANDLE hFile = (HANDLE)(ULONG_PTR)args[0];
    PVOID buffer = (PVOID)(uintptr_t)args[1];
    ULONG length = (ULONG)args[2];
    PULONG bytesWritten = (PULONG)(uintptr_t)args[3];
    PLARGE_INTEGER offset = (PLARGE_INTEGER)(uintptr_t)args[4];

    typedef NTSTATUS (NTAPI* RealNtWriteFile_t)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, ULONG, PULONG, PLARGE_INTEGER);
    static RealNtWriteFile_t realFunc = (RealNtWriteFile_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteFile");

    if (!realFunc) return false;
    NTSTATUS status = realFunc(hFile, nullptr, nullptr, nullptr, (PIO_STATUS_BLOCK)buffer, buffer, length, bytesWritten, offset);
    *result = (uint64_t)status;
    return true;
}

bool FileEmu::HandleNtQueryInformationFile(uint64_t* args, uint64_t* result)
{
    HANDLE hFile = (HANDLE)(ULONG_PTR)args[0];
    PVOID info = (PVOID)(uintptr_t)args[1];
    ULONG length = (ULONG)args[2];
    auto infoClass = (FILE_INFORMATION_CLASS)args[3];

    typedef NTSTATUS (NTAPI* RealNtQueryInformationFile_t)(HANDLE, PVOID, PVOID, ULONG, FILE_INFORMATION_CLASS);
    static RealNtQueryInformationFile_t realFunc = (RealNtQueryInformationFile_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationFile");

    if (!realFunc) return false;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = realFunc(hFile, &iosb, info, length, infoClass);
    *result = (uint64_t)status;
    return true;
}

bool FileEmu::HandleNtQueryVolumeInformationFile(uint64_t* args, uint64_t* result)
{
    auto infoClass = (uint32_t)args[4];
    uint64_t buffer = args[2];
    uint32_t length = (uint32_t)args[3];

    switch (infoClass) {
        case 5: { // FileFsSizeInformation
            if (length < 24) { *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH; return true; }
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
            *result = (uint64_t)STATUS_SUCCESS;
            return true;
        }
        default:
            *result = (uint64_t)STATUS_SUCCESS;
            return true;
    }
}

bool FileEmu::HandleNtDeviceIoControlFile(uint64_t* args, uint64_t* result)
{
    uint32_t ioControlCode = (uint32_t)args[5];

    m_logger->Trace(LOG_EMU, "NtDeviceIoControlFile code=0x%X", ioControlCode);

    switch (ioControlCode) {
        case IOCTL_STORAGE_QUERY_PROPERTY: {
            uint64_t outputBuffer = args[7];
            uint32_t outputLength = (uint32_t)args[8];

            if (outputLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
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
            *result = (uint64_t)STATUS_SUCCESS;
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
    // Sandbox path redirection for reads
    if (g_sandboxFallthrough && g_sandboxFallthrough->IsInitialized()) {
        std::wstring path = GetFilePathFromAttributes(args[2]);
        if (!path.empty()) {
            FileRedirection::FileInfo info;
            if (g_sandboxFallthrough->HandleFileOperation(path.c_str(), false, info)) {
                if (info.isRedirected) {
                    std::wstring targetPath = info.boxPath;
                    if (GetFileAttributesW(targetPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                        targetPath = info.truePath;
                    }
                    UNICODE_STRING targetUs;
                    targetUs.Buffer = &targetPath[0];
                    targetUs.Length = (USHORT)(targetPath.size() * sizeof(wchar_t));
                    targetUs.MaximumLength = targetUs.Length;
                    OBJECT_ATTRIBUTES targetOa;
                    memcpy(&targetOa, (void*)(uintptr_t)args[2], sizeof(targetOa));
                    targetOa.RootDirectory = NULL;
                    targetOa.ObjectName = &targetUs;
                    typedef NTSTATUS (WINAPI* RealNtOpenFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID, ULONG, ULONG);
                    static RealNtOpenFile_t realFunc = (RealNtOpenFile_t)
                        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
                    if (realFunc) {
                        NTSTATUS status = realFunc((PHANDLE)args[0], (ACCESS_MASK)args[1],
                            &targetOa, (PVOID)args[3], (ULONG)args[4], (ULONG)args[5]);
                        if (result) *result = (uint64_t)status;
                        return true;
                    }
                }
            }
        }
    }

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
    // Sandbox: redirect delete to box path
    if (g_sandboxFallthrough && g_sandboxFallthrough->IsInitialized()) {
        std::wstring path = GetFilePathFromAttributes(args[0]);
        if (!path.empty()) {
            FileRedirection::FileInfo info;
            if (g_sandboxFallthrough->HandleFileOperation(path.c_str(), true, info)) {
                if (info.isRedirected) {
                    g_sandboxFallthrough->EnsureFileWriteCopy(info.truePath.c_str());
                    UNICODE_STRING targetUs;
                    targetUs.Buffer = &info.boxPath[0];
                    targetUs.Length = (USHORT)(info.boxPath.size() * sizeof(wchar_t));
                    targetUs.MaximumLength = targetUs.Length;
                    OBJECT_ATTRIBUTES targetOa;
                    memcpy(&targetOa, (void*)(uintptr_t)args[0], sizeof(targetOa));
                    targetOa.RootDirectory = NULL;
                    targetOa.ObjectName = &targetUs;
                    typedef NTSTATUS (WINAPI* RealNtDeleteFile_t)(POBJECT_ATTRIBUTES);
                    static RealNtDeleteFile_t realFunc = (RealNtDeleteFile_t)
                        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDeleteFile");
                    if (realFunc) {
                        NTSTATUS status = realFunc(&targetOa);
                        if (result) *result = (uint64_t)status;
                        return true;
                    }
                }
            }
        }
    }

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
