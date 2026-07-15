#include "SyscallDispatch.h"
#include "Logger.h"
#include <cstring>

static Logger g_syscallLogger;

#define SYSLOG(fmt, ...) g_syscallLogger.Trace(LOG_WHP, "SyscallD: " fmt, ##__VA_ARGS__)
#define SYSERR(fmt, ...) g_syscallLogger.Trace(LOG_ERROR, "SyscallD: " fmt, ##__VA_ARGS__)

SyscallDispatch::SyscallDispatch()
    : NtQuerySystemInformation(0), NtQueryInformationProcess(0),
      NtOpenKey(0), NtQueryValueKey(0), NtClose(0), NtCreateFile(0), NtQueryObject(0)
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
    // Syscalls with >4 args; default 4 for unknown
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

bool SyscallDispatch::Initialize()
{
    if (m_initialized) return true;

    NtQuerySystemInformation = GetSyscallNumber("NtQuerySystemInformation");
    NtQueryInformationProcess = GetSyscallNumber("NtQueryInformationProcess");
    NtOpenKey = GetSyscallNumber("NtOpenKey");
    NtQueryValueKey = GetSyscallNumber("NtQueryValueKey");
    NtClose = GetSyscallNumber("NtClose");
    NtCreateFile = GetSyscallNumber("NtCreateFile");
    NtQueryObject = GetSyscallNumber("NtQueryObject");
    NtCreateThread = GetSyscallNumber("NtCreateThread");
    NtCreateThreadEx = GetSyscallNumber("NtCreateThreadEx");
    NtTerminateThread = GetSyscallNumber("NtTerminateThread");

    SYSLOG("NtQSI=0x%X NtQIP=0x%X NtOpenKey=0x%X NtQueryValueKey=0x%X NtClose=0x%X NtCreateFile=0x%X NtQueryObject=0x%X NtCreateThread=0x%X NtCreateThreadEx=0x%X NtTerminateThread=0x%X",
        NtQuerySystemInformation, NtQueryInformationProcess, NtOpenKey,
        NtQueryValueKey, NtClose, NtCreateFile, NtQueryObject,
        NtCreateThread, NtCreateThreadEx, NtTerminateThread);

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

        // Only process Nt* and Zw* syscalls
        if (name[0] != 'N' && name[0] != 'Z') continue;
        if (strncmp(name, "Nt", 2) != 0 && strncmp(name, "Zw", 2) != 0) continue;

        uint8_t* funcAddr = base + functions[ordinals[i]];

        // Check if this is a syscall stub (must have a mov eax, imm32)
        bool isSyscall = false;
        for (int off = 0; off < 8; off++) {
            if (funcAddr[off] == 0xB8) {
                isSyscall = true;
                break;
            }
            // Handle forwarded exports
            if (functions[ordinals[i]] >= expDir.VirtualAddress &&
                functions[ordinals[i]] < expDir.VirtualAddress + expDir.Size) {
                // This is a forwarded export (e.g., NtYieldExecution → NtDelayExecution)
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

        // Skip syscalls already detected
        if (syscallNum == NtQuerySystemInformation ||
            syscallNum == NtQueryInformationProcess ||
            syscallNum == NtOpenKey ||
            syscallNum == NtQueryValueKey ||
            syscallNum == NtClose ||
            syscallNum == NtCreateFile ||
            syscallNum == NtQueryObject ||
            syscallNum == NtCreateThread ||
            syscallNum == NtCreateThreadEx ||
            syscallNum == NtTerminateThread) {
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
        result = 0xC0000001; // STATUS_NOT_IMPLEMENTED
        return false;
    }

    void* funcPtr = it->second.funcPtr;
    int argCount = it->second.argCount;

    // Build full arg array: args[0..3] are from registers, args[4+] from guest stack
    uint64_t allArgs[16] = {args[0], args[1], args[2], args[3]};
    if (argCount > 4) {
        // Guest stack layout at SYSCALL time:
        // [RSP+0] = return address (pushed by CALL to ntdll stub)
        // [RSP+8] = arg5, [RSP+0x10] = arg6, etc.
        for (int i = 4; i < argCount && i < 16; i++) {
            // Read from identity-mapped guest stack
            uint64_t* stackPtr = (uint64_t*)(guestRsp + 8 + (i - 4) * 8);
            allArgs[i] = *stackPtr;
        }
    }

    // Dispatch based on arg count (C++ function pointer cast handles register/stack args)
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
            value = 0;
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

    if (infoClass == 103 || infoClass == 0x67) {
        if (info && infoLen >= 8) {
            *(uint32_t*)(uintptr_t)info = 8;
            *(uint32_t*)((uint8_t*)(uintptr_t)info + 4) = 0;
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = 8;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    if (infoClass == 11 || infoClass == 0x0B) {
        if (infoLen >= sizeof(uint32_t)) {
            if (info) *(uint32_t*)(uintptr_t)info = 0;
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = sizeof(uint32_t);
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

    if (infoClass == 7) {
        if (info && infoLen >= sizeof(int32_t)) {
            *(int32_t*)(uintptr_t)info = -1;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(int32_t);
        }
        result = STATUS_SUCCESS;
        return true;
    }

    if (infoClass == 0x1E) {
        if (info && infoLen >= sizeof(HANDLE)) {
            *(HANDLE*)(uintptr_t)info = NULL;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(HANDLE);
        }
        result = STATUS_SUCCESS;
        return true;
    }

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

bool SyscallDispatch::HandleNtOpenKey(uint64_t*, uint64_t& result) { result = STATUS_SUCCESS; return false; }
bool SyscallDispatch::HandleNtQueryValueKey(uint64_t*, uint64_t& result) { result = STATUS_SUCCESS; return false; }
bool SyscallDispatch::HandleNtClose(uint64_t*, uint64_t& result) { result = STATUS_SUCCESS; return false; }
bool SyscallDispatch::HandleNtCreateFile(uint64_t*, uint64_t& result) { result = STATUS_SUCCESS; return false; }
