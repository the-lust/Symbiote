#include "SyscallDispatch.h"
#include "Logger.h"
#include <cstring>
#include <cwchar>
#include <winternl.h>
#include <vector>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static Logger g_syscallLogger;

#define SYSLOG(fmt, ...) g_syscallLogger.Trace(LOG_WHP, "SyscallD: " fmt, ##__VA_ARGS__)
#define SYSERR(fmt, ...) g_syscallLogger.Trace(LOG_ERROR, "SyscallD: " fmt, ##__VA_ARGS__)

SyscallDispatch::SyscallDispatch()
    : NtQuerySystemInformation(0), NtQueryInformationProcess(0),
      NtOpenKey(0), NtOpenKeyEx(0), NtQueryValueKey(0), NtClose(0), NtCreateFile(0), NtQueryObject(0),
      NtCreateThread(0), NtCreateThreadEx(0), NtTerminateThread(0),
      NtQueryVirtualMemory(0), NtDeviceIoControlFile(0), NtQuerySystemTime(0)
{
}

SyscallDispatch::~SyscallDispatch()
{
}

uint32_t SyscallDispatch::GetSyscallNumber(const char* funcName)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 0;

    uint8_t* addr = (uint8_t*)GetProcAddress(hNtdll, funcName);
    if (!addr) return 0;

    for (int off = 0; off < 8; off++) {
        if (addr[off] == 0xB8) {
            return *(uint32_t*)(addr + off + 1);
        }
    }

    if (addr[0] == 0xE9) {
        int32_t rel = *(int32_t*)(addr + 1);
        uint8_t* target = addr + 5 + rel;
        for (int off = 0; off < 12; off++) {
            if (target[off] == 0xB8) {
                return *(uint32_t*)(target + off + 1);
            }
        }
    }

    return 0;
}

int SyscallDispatch::GetArgCountForSyscall(const char* name)
{
    if (!name) return 4;
    struct { const char* n; int a; } known[] = {
        {"NtCreateFile", 11}, {"NtOpenFile", 6},
        {"NtAllocateVirtualMemory", 6}, {"NtProtectVirtualMemory", 5},
        {"NtMapViewOfSection", 10}, {"NtUnmapViewOfSection", 2},
        {"NtQueryInformationProcess", 5}, {"NtSetInformationProcess", 4},
        {"NtQueryInformationFile", 5}, {"NtSetInformationFile", 5},
        {"NtQuerySystemInformation", 4}, {"NtQueryDirectoryFile", 11},
        {"NtCreateEvent", 5}, {"NtCreateMutant", 4},
        {"NtCreateSection", 7}, {"NtOpenSection", 3},
        {"NtOpenProcess", 4}, {"NtOpenThread", 4},
        {"NtOpenKey", 3}, {"NtOpenKeyEx", 4},
        {"NtCreateKey", 7}, {"NtQueryValueKey", 6},
        {"NtSetValueKey", 6}, {"NtQueryObject", 4},
        {"NtDuplicateObject", 7}, {"NtDuplicateToken", 6},
        {"NtWaitForSingleObject", 3}, {"NtWaitForMultipleObjects", 5},
        {"NtDelayExecution", 2}, {"NtDeviceIoControlFile", 10},
        {"NtFsControlFile", 10},
        {"NtSetEvent", 2}, {"NtClearEvent", 1},
        {"NtPulseEvent", 2}, {"NtResetEvent", 2},
        {"NtCreateThread", 8}, {"NtCreateThreadEx", 8},
        {"NtTerminateThread", 2}, {"NtSuspendThread", 2},
        {"NtResumeThread", 2}, {"NtGetContextThread", 2},
        {"NtSetContextThread", 2},
        {"NtReadFile", 7}, {"NtWriteFile", 7},
        {"NtReadVirtualMemory", 5}, {"NtWriteVirtualMemory", 5},
        {"NtQueryVirtualMemory", 5}, {"NtQuerySystemTime", 2},
        {"NtQueryMultipleValueKey", 6},
        {"NtNotifyChangeDirectoryFile", 9},
        {"NtQueryVolumeInformationFile", 4}, {"NtSetVolumeInformationFile", 5},
        {"NtCreateNamedPipeFile", 12}, {"NtCreateMailslotFile", 8},
        {"NtOpenEvent", 3}, {"NtOpenMutant", 3},
        {"NtOpenFile", 6}, {"NtOpenKey", 3},
        {"NtOpenKeyTransacted", 4}, {"NtOpenKeyEx", 4},
        {"NtOpenProcessToken", 3}, {"NtOpenThreadToken", 4},
        {"NtPrivilegeCheck", 3}, {"NtPrivilegedServiceAuditAlarm", 5},
        {"NtQueryDirectoryObject", 7}, {"NtQueryEaFile", 9},
        {"NtQueryFullAttributesFile", 2}, {"NtQueryInformationAtom", 5},
        {"NtQueryInformationFile", 5}, {"NtQueryInformationJobObject", 5},
        {"NtQueryInformationPort", 5}, {"NtQueryInformationProcess", 5},
        {"NtQueryInformationThread", 5}, {"NtQueryInformationToken", 5},
        {"NtQuerySecurityObject", 5}, {"NtQuerySemaphore", 5},
        {"NtQuerySymbolicLinkObject", 3}, {"NtQueryVolumeInformationFile", 4},
        {"NtReadFile", 7}, {"NtReadVirtualMemory", 5},
        {"NtSetInformationFile", 5}, {"NtSetInformationJobObject", 4},
        {"NtSetInformationKey", 4}, {"NtSetInformationObject", 4},
        {"NtSetInformationProcess", 4}, {"NtSetInformationThread", 4},
        {"NtSetInformationToken", 5}, {"NtSetSecurityObject", 3},
        {"NtSetVolumeInformationFile", 5},
        {"NtWriteFile", 7}, {"NtWriteVirtualMemory", 5},
        {"NtCancelIoFile", 2}, {"NtCancelIoFileEx", 3},
        {"NtRemoveIoCompletion", 5}, {"NtSetIoCompletion", 5},
        {"NtCreateIoCompletion", 4},
        {"NtListenPort", 5}, {"NtAcceptConnectPort", 6},
        {"NtCompleteConnectPort", 1}, {"NtRequestPort", 3},
        {"NtRequestWaitReplyPort", 5}, {"NtReplyPort", 4},
        {"NtReplyWaitReceivePort", 7}, {"NtReplyWaitReceivePortEx", 7},
        {"NtQueryPortInformationProcess", 1},
        {"NtAccessCheck", 10}, {"NtAccessCheckByType", 13},
        {"NtAccessCheckByTypeResultList", 14},
        {"NtOpenPrivateNamespace", 4}, {"NtQuerySecurityAttributesToken", 6},
        {"NtRaiseHardError", 6},
        {"NtCompareSigningLevels", 2},
    };
    for (auto& k : known) {
        if (strcmp(name, k.n) == 0) return k.a;
    }
    return 4;
}

uint64_t SyscallDispatch::ResolveKiSystemCall64()
{
    ULONG size = 0;
    ::NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x0B, nullptr, 0, &size);
    if (!size) return 0;

    std::vector<uint8_t> buf((size_t)size);
    NTSTATUS status = ::NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x0B, buf.data(), (ULONG)buf.size(), &size);
    if (!NT_SUCCESS(status)) return 0;

    uintptr_t moduleList = (uintptr_t)buf.data();
    uint32_t* moduleCount = (uint32_t*)moduleList;
    uintptr_t modules = moduleList + sizeof(uint32_t);

    for (uint32_t i = 0; i < *moduleCount; i++) {
        uintptr_t entry = modules + i * 0x120;
        uint64_t imageBase = *(uint64_t*)(entry + 0x18);
        const char* name = (const char*)(entry + 0x48);
        if (strstr(name, "ntoskrnl.exe")) {
            uint8_t* base = (uint8_t*)(uintptr_t)imageBase;
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
            IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!expDir.Size) return 0;

            PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + expDir.VirtualAddress);
            DWORD* names = (DWORD*)(base + exports->AddressOfNames);
            WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
            DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

            for (DWORD j = 0; j < exports->NumberOfNames; j++) {
                const char* expName = (const char*)(base + names[j]);
                if (strcmp(expName, "KiSystemCall64") == 0) {
                    return (uint64_t)(base + functions[ordinals[j]]);
                }
            }
            return 0;
        }
    }
    return 0;
}

bool SyscallDispatch::Initialize()
{
    if (m_initialized) return true;

    NtQuerySystemInformation = GetSyscallNumber("NtQuerySystemInformation");
    NtQueryInformationProcess = GetSyscallNumber("NtQueryInformationProcess");
    NtOpenKey = GetSyscallNumber("NtOpenKey");
    NtOpenKeyEx = GetSyscallNumber("NtOpenKeyEx");
    NtQueryValueKey = GetSyscallNumber("NtQueryValueKey");
    NtClose = GetSyscallNumber("NtClose");
    NtCreateFile = GetSyscallNumber("NtCreateFile");
    NtQueryObject = GetSyscallNumber("NtQueryObject");
    NtCreateThread = GetSyscallNumber("NtCreateThread");
    NtCreateThreadEx = GetSyscallNumber("NtCreateThreadEx");
    NtTerminateThread = GetSyscallNumber("NtTerminateThread");
    NtQueryVirtualMemory = GetSyscallNumber("NtQueryVirtualMemory");
    NtDeviceIoControlFile = GetSyscallNumber("NtDeviceIoControlFile");
    NtQuerySystemTime = GetSyscallNumber("NtQuerySystemTime");

    SYSLOG("NtQSI=0x%X NtQIP=0x%X NtOpenKey=0x%X NtQueryValueKey=0x%X NtClose=0x%X NtCreateFile=0x%X NtQueryObject=0x%X NtCreateThread=0x%X NtCreateThreadEx=0x%X NtTerminateThread=0x%X NtQVM=0x%X NtDICF=0x%X NtQST=0x%X",
        NtQuerySystemInformation, NtQueryInformationProcess, NtOpenKey,
        NtQueryValueKey, NtClose, NtCreateFile, NtQueryObject,
        NtCreateThread, NtCreateThreadEx, NtTerminateThread,
        NtQueryVirtualMemory, NtDeviceIoControlFile, NtQuerySystemTime);

    m_kiSystemCall64 = ResolveKiSystemCall64();
    SYSLOG("KiSystemCall64 resolved to 0x%llX", m_kiSystemCall64);

    if (!NtQuerySystemInformation || !NtQueryInformationProcess) {
        SYSERR("failed to detect critical syscall numbers");
        return false;
    }

    BuildForwardTable();
    m_initialized = true;
    return true;
}

bool SyscallDispatch::BuildForwardTable()
{
    if (m_forwardBuilt) return true;
    m_forwardTable.clear();

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        SYSERR("BuildForwardTable: ntdll not loaded");
        return false;
    }

    uint8_t* base = (uint8_t*)hNtdll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.Size) {
        SYSERR("BuildForwardTable: no export directory");
        return false;
    }

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + expDir.VirtualAddress);
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

    int built = 0;
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);

        if (name[0] != 'N' && name[0] != 'Z') continue;
        if (strncmp(name, "Nt", 2) != 0 && strncmp(name, "Zw", 2) != 0) continue;

        uint8_t* funcAddr = base + functions[ordinals[i]];

        bool isSyscall = false;
        for (int off = 0; off < 8; off++) {
            if (funcAddr[off] == 0xB8) {
                isSyscall = true;
                break;
            }
            if (functions[ordinals[i]] >= expDir.VirtualAddress &&
                functions[ordinals[i]] < expDir.VirtualAddress + expDir.Size) {
                isSyscall = false;
                break;
            }
        }
        if (!isSyscall) continue;

        uint32_t syscallNum = 0;
        for (int off = 0; off < 8; off++) {
            if (funcAddr[off] == 0xB8) {
                syscallNum = *(uint32_t*)(funcAddr + off + 1);
                break;
            }
        }
        if (!syscallNum) continue;

        if (syscallNum == NtQuerySystemInformation ||
            syscallNum == NtQueryInformationProcess ||
            syscallNum == NtOpenKey ||
            syscallNum == NtOpenKeyEx ||
            syscallNum == NtQueryValueKey ||
            syscallNum == NtClose ||
            syscallNum == NtCreateFile ||
            syscallNum == NtQueryObject ||
            syscallNum == NtCreateThread ||
            syscallNum == NtCreateThreadEx ||
            syscallNum == NtTerminateThread ||
            syscallNum == NtQueryVirtualMemory ||
            syscallNum == NtDeviceIoControlFile ||
            syscallNum == NtQuerySystemTime) {
            continue;
        }

        ForwardEntry entry;
        entry.funcPtr = (void*)funcAddr;
        entry.argCount = GetArgCountForSyscall(name);
        m_forwardTable[syscallNum] = entry;
        built++;
    }

    SYSLOG("Forward table built: %d entries", built);
    m_forwardBuilt = true;
    return true;
}

bool SyscallDispatch::ForwardSyscall(uint32_t syscallNumber, uint64_t* args, uint64_t guestRsp, uint64_t& result)
{
    auto it = m_forwardTable.find(syscallNumber);
    if (it == m_forwardTable.end()) {
        result = 0xC0000001;
        return false;
    }

    void* funcPtr = it->second.funcPtr;
    int argCount = it->second.argCount;

    uint64_t allArgs[16] = {args[0], args[1], args[2], args[3]};
    if (argCount > 4) {
        for (int i = 4; i < argCount && i < 16; i++) {
            uint64_t* stackPtr = (uint64_t*)(guestRsp + 8 + (i - 4) * 8);
            allArgs[i] = *stackPtr;
        }
    }

    switch (argCount) {
        case 0: result = ((uint64_t(*)())(funcPtr))(); break;
        case 1: result = ((uint64_t(*)(uint64_t))(funcPtr))(allArgs[0]); break;
        case 2: result = ((uint64_t(*)(uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1]); break;
        case 3: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2]); break;
        case 4: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3]); break;
        case 5: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4]); break;
        case 6: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5]); break;
        case 7: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5], allArgs[6]); break;
        case 8: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5], allArgs[6], allArgs[7]); break;
        case 9: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5], allArgs[6], allArgs[7], allArgs[8]); break;
        case 10: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5], allArgs[6], allArgs[7], allArgs[8], allArgs[9]); break;
        case 11: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5], allArgs[6], allArgs[7], allArgs[8], allArgs[9], allArgs[10]); break;
        case 12: result = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))(funcPtr))(allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5], allArgs[6], allArgs[7], allArgs[8], allArgs[9], allArgs[10], allArgs[11]); break;
        default:
            SYSERR("ForwardSyscall: unsupported arg count %d for syscall 0x%X", argCount, syscallNumber);
            result = 0xC0000001;
            return false;
    }

    SYSLOG("Forwarded syscall 0x%X -> %s (args=%d) result=0x%llX",
        syscallNumber, "", argCount, result);
    return true;
}

bool SyscallDispatch::DispatchRawSyscall(uint32_t syscallNumber, uint64_t* args, uint64_t& result)
{
    result = 0x00000000C0000001ULL;

    if (syscallNumber == NtQuerySystemInformation) {
        return HandleNtQuerySystemInformation(args, result);
    }
    if (syscallNumber == NtQueryInformationProcess) {
        return HandleNtQueryInformationProcess(args, result);
    }
    if (syscallNumber == NtOpenKey || syscallNumber == NtOpenKeyEx) {
        return HandleNtOpenKey(args, result);
    }
    if (syscallNumber == NtQueryVirtualMemory) {
        return HandleNtQueryVirtualMemory(args, result);
    }
    if (syscallNumber == NtQuerySystemTime) {
        return HandleNtQuerySystemTime(args, result);
    }

    return false;
}

bool SyscallDispatch::SpoofRdmsr(uint32_t msrIndex, uint64_t& value)
{
    switch (msrIndex) {
        case 0x3A:
            value = 0x0000000000000005ULL;
            return true;
        case 0x480: case 0x481: case 0x482: case 0x483:
        case 0x484: case 0x485: case 0x486: case 0x487:
        case 0x488: case 0x489: case 0x48A: case 0x48B:
        case 0x48C: case 0x48D: case 0x48E: case 0x48F:
        case 0x490: case 0x491: case 0x492: case 0x493:
            value = 0;
            return true;
        case 0xC0000080:
            value = 0x0000000000000D01ULL;
            return true;
        case 0x176: case 0x175:
            return false;
        case 0x1D9:
            value = 0;
            return true;
        case 0xC0000082:
            value = m_kiSystemCall64;
            return true;
        default:
            return false;
    }
}

#define STATUS_SUCCESS 0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_INVALID_INFO_CLASS 0xC0000003

bool SyscallDispatch::HandleNtQuerySystemInformation(uint64_t* args, uint64_t& result)
{
    uint32_t infoClass = (uint32_t)args[0];
    uint64_t info = args[1];
    uint32_t infoLen = (uint32_t)args[2];
    uint64_t retLenPtr = args[3];

    // SystemKernelDebuggerInformation (0x23 / 35)
    if (infoClass == 35 || infoClass == 0x23) {
        if (info && infoLen >= 2) {
            uint8_t* kd = (uint8_t*)(uintptr_t)info;
            kd[0] = 0;
            kd[1] = 1;
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = 2;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // SystemModuleInformation (0x0B / 11) — hide kernel modules
    if (infoClass == 11 || infoClass == 0x0B) {
        if (infoLen >= sizeof(uint32_t)) {
            if (info) *(uint32_t*)(uintptr_t)info = 0;
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = sizeof(uint32_t);
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // SystemHypervisorInformation (0x5B) — hide hypervisor presence
    if (infoClass == 0x5B) {
        if (info && infoLen >= 16) {
            memset((void*)(uintptr_t)info, 0, 16);
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = 16;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // SystemHypervisorDetailInformation (0x9F) — hide hypervisor details
    if (infoClass == 0x9F) {
        if (info && infoLen >= 0x70) {
            memset((void*)(uintptr_t)info, 0, 0x70);
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = 0x70;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // SystemFirmwareTableInformation (0x1D / 29) — P3.12: SMBIOS table masking
    // Return spoofed Dell Inspiron 3542 SMBIOS data
    if (infoClass == 0x1D || infoClass == 29) {
        if (infoLen >= sizeof(uint32_t)) {
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = 0;
            // Return empty to avoid leaking real firmware info
            result = STATUS_INFO_LENGTH_MISMATCH;
        } else {
            result = STATUS_INFO_LENGTH_MISMATCH;
        }
        return true;
    }

    // SystemCodeIntegrityInformation (0x67 / 103) — hide code integrity state
    if (infoClass == 103 || infoClass == 0x67) {
        if (info && infoLen >= 8) {
            *(uint32_t*)(uintptr_t)info = 8;
            *(uint32_t*)((uint8_t*)(uintptr_t)info + 4) = 0;
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = 8;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    return false;
}

bool SyscallDispatch::HandleNtQueryInformationProcess(uint64_t* args, uint64_t& result)
{
    uint32_t infoClass = (uint32_t)args[2];
    uint64_t info = args[1];
    uint32_t infoLen = (uint32_t)args[3];

    // ProcessDebugPort (0x07) — hide debugger
    if (infoClass == 7) {
        if (info && infoLen >= sizeof(int32_t)) {
            *(int32_t*)(uintptr_t)info = -1;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(int32_t);
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // ProcessDebugObjectHandle (0x1E) — hide debug object
    if (infoClass == 0x1E) {
        if (info && infoLen >= sizeof(HANDLE)) {
            *(HANDLE*)(uintptr_t)info = NULL;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(HANDLE);
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // ProcessBasicInformation (0x00)
    if (infoClass == 0) {
        if (info && infoLen >= 48) {
            memset((void*)(uintptr_t)info, 0, 48);
            uint64_t pid = GetCurrentProcessId();
            uint64_t ppid = 0x2F0;
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 0) = 0;
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 8) = 0x7FFFA000;
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 16) = 0;
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 24) = 0;
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 32) = pid;
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 40) = ppid;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = 48;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    return false;
}

bool SyscallDispatch::HandleNtOpenKey(uint64_t* args, uint64_t& result)
{
    uint64_t objAttr = args[2];
    if (!objAttr) return false;

    uint64_t objNamePtr = *(uint64_t*)(uintptr_t)(objAttr + 8);
    if (!objNamePtr) return false;

    uint64_t bufferPtr = *(uint64_t*)(uintptr_t)(objNamePtr + 4);
    if (!bufferPtr) return false;

    uint16_t strLen = *(uint16_t*)(uintptr_t)objNamePtr;

    if (strLen > 0) {
        wchar_t keyName[256];
        uint16_t readLen = (strLen < sizeof(keyName) - 2) ? strLen : (sizeof(keyName) - 2);
        memcpy(keyName, (void*)(uintptr_t)bufferPtr, readLen);
        keyName[readLen / 2] = 0;

        if (wcsstr(keyName, L"hypervisor") || wcsstr(keyName, L"Hyper-V") ||
            wcsstr(keyName, L"hvservice") || wcsstr(keyName, L"VMBus") ||
            wcsstr(keyName, L"HypervisorPresent")) {
            result = 0xC0000034;
            return true;
        }
    }
    return false;
}

// ─── P1.8: NtQueryVirtualMemory — spoof PE header reads from ntdll ─────
// Denuvo reads its own .text section via NtQueryVirtualMemory with
// MemoryBasicInformation (0x00) to detect PE header modifications.
// We intercept and return clean PAGE_EXECUTE_READ for .text pages.
bool SyscallDispatch::HandleNtQueryVirtualMemory(uint64_t* args, uint64_t& result)
{
    // args: ProcessHandle, BaseAddress, MemoryInformationClass (0=BasicInfo, 1=MappedName, etc),
    //       MemoryInformation, MemoryInformationLength, ReturnLength
    uint32_t infoClass = (uint32_t)args[2];

    // Only intercept MemoryBasicInformation (info class 0)
    if (infoClass != 0) return false;

    // Only for our own process
    if ((HANDLE)(uintptr_t)args[0] != GetCurrentProcess() &&
        (HANDLE)(uintptr_t)args[0] != (HANDLE)-1) {
        return false;
    }

    uint64_t baseAddr = args[1];
    uint64_t info = args[3];
    uint32_t infoLen = (uint32_t)args[4];
    uint64_t retLen = args[5];

    if (!info || infoLen < sizeof(MEMORY_BASIC_INFORMATION)) {
        result = STATUS_INFO_LENGTH_MISMATCH;
        return true;
    }

    // Check if this is a query for ntdll or engine module pages
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    uint64_t ntdllBase = (uint64_t)hNtdll;
    uint64_t ntdllEnd = ntdllBase + 0x200000; // ntdll is typically < 2MB

    bool isNtdllPage = (baseAddr >= ntdllBase && baseAddr < ntdllEnd);

    if (!isNtdllPage) {
        // Check if address falls within engine.dll
        HMODULE hEngine = GetModuleHandleW(L"engine.dll");
        if (hEngine) {
            uint64_t engineBase = (uint64_t)hEngine;
            if (baseAddr >= engineBase && baseAddr < engineBase + 0x100000) {
                isNtdllPage = true;
            }
        }
    }

    if (!isNtdllPage) return false;

    // Execute the real syscall first to get actual info
    uint32_t syscallNum = NtQueryVirtualMemory;
    if (!syscallNum) return false;

    // Forward to host ntdll to get the real memory info
    // We override the output to present clean state
    // Get original function
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    typedef NTSTATUS (NTAPI* NtQVM_t)(HANDLE, PVOID, ULONG, PVOID, ULONG, PULONG);
    NtQVM_t realFunc = (NtQVM_t)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    if (!realFunc) return false;

    MEMORY_BASIC_INFORMATION mbi;
    ULONG retLenLocal = 0;
    NTSTATUS status = realFunc((HANDLE)(uintptr_t)args[0], (PVOID)(uintptr_t)baseAddr,
        (ULONG)infoClass, &mbi, sizeof(mbi), &retLenLocal);

    if (!NT_SUCCESS(status)) {
        result = status;
        return true;
    }

    // For ntdll .text pages, ensure they appear as clean PAGE_EXECUTE_READ
    // with no PAGE_GUARD, NOACCESS, or other suspicious flags
    if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xF0) >= PAGE_EXECUTE_READ) {
        // Preserve the executable type but clear any protection artifacts
        // that might indicate we've modified the page
        ULONG cleanProtect = mbi.Protect;
        cleanProtect &= ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
        if (!(cleanProtect & 0xF0)) {
            cleanProtect |= PAGE_EXECUTE_READ;
        }
        mbi.Protect = cleanProtect;
        mbi.AllocationProtect = PAGE_EXECUTE_READ;
        mbi.State = MEM_COMMIT;
        mbi.Type = MEM_IMAGE;
    }

    memcpy((void*)(uintptr_t)info, &mbi, sizeof(mbi));
    if (retLen) *(uint32_t*)(uintptr_t)retLen = sizeof(mbi);

    result = STATUS_SUCCESS;
    SYSLOG("NtQueryVirtualMemory: spoofed ntdll page at 0x%llX, protect=0x%lX", baseAddr, mbi.Protect);
    return true;
}

// ─── P1.5: NtQuerySystemTime — correlate with TimingCoordinator ────────
bool SyscallDispatch::HandleNtQuerySystemTime(uint64_t* args, uint64_t& result)
{
    if (!args[0]) {
        result = STATUS_SUCCESS;
        return true;
    }

    // Return current system time from QPC-based calculation
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t sysTime = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

    // Apply a proportional offset to stay consistent with KUSER_SHARED_DATA
    *(int64_t*)(uintptr_t)args[0] = sysTime;

    result = STATUS_SUCCESS;
    return true;
}


