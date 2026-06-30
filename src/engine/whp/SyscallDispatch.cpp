#include "SyscallDispatch.h"
#include "Logger.h"
#include <cstring>

static Logger g_syscallLogger;

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

    // Windows 10 x64 pattern:
    //   0: 4C 8B D1          mov r10, rcx
    //   3: B8 XX XX XX XX    mov eax, syscall_number
    //   8: 0F 05             syscall
    //   A: C3                ret
    // Also handle:
    //   0: B8 XX XX XX XX    mov eax, syscall_number (older pattern)
    //   5: 4C 8B D1          mov r10, rcx
    //   8: 0F 05             syscall
    //   A: C3                ret

    // Pattern 1: B8 XX XX XX XX (mov eax, imm32) at any offset
    for (int off = 0; off < 8; off++) {
        if (addr[off] == 0xB8) {
            return *(uint32_t*)(addr + off + 1);
        }
    }

    // Pattern 2: on some Windows builds, there might be a jmp to a shared stub
    // E9 XX XX XX XX (jmp rel32)
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

    g_syscallLogger.Trace(LOG_WHP,
        "SyscallDispatch: NtQSI=0x%X NtQIP=0x%X NtOpenKey=0x%X NtQueryValueKey=0x%X NtClose=0x%X NtCreateFile=0x%X NtQueryObject=0x%X",
        NtQuerySystemInformation, NtQueryInformationProcess, NtOpenKey,
        NtQueryValueKey, NtClose, NtCreateFile, NtQueryObject);

    if (!NtQuerySystemInformation || !NtQueryInformationProcess) {
        g_syscallLogger.Trace(LOG_ERROR, "SyscallDispatch: failed to detect critical syscall numbers");
        return false;
    }

    m_initialized = true;
    return true;
}

bool SyscallDispatch::DispatchRawSyscall(uint32_t syscallNumber, uint64_t* args, uint64_t& result)
{
    result = 0x00000000C0000001ULL; // STATUS_NOT_IMPLEMENTED

    // Map raw syscall numbers to our handlers
    if (syscallNumber == NtQuerySystemInformation) {
        return HandleNtQuerySystemInformation(args, result);
    }
    if (syscallNumber == NtQueryInformationProcess) {
        return HandleNtQueryInformationProcess(args, result);
    }

    return false; // Not handled — needs passthrough
}

bool SyscallDispatch::SpoofRdmsr(uint32_t msrIndex, uint64_t& value)
{
    // MSRs that Denuvo checks for VM detection
    switch (msrIndex) {
        case 0x3A:   // IA32_FEATURE_CONTROL — VMX lock bit
            value = 0x0000000000000005ULL; // Locked, VMXON enabled (typical real HW)
            return true;

        case 0x480:  // IA32_VMX_BASIC — zeroed = no VMX support
        case 0x481:  // IA32_VMX_PINBASED_CTLS
        case 0x482:  // IA32_VMX_PROCBASED_CTLS
        case 0x483:  // IA32_VMX_EXIT_CTLS
        case 0x484:  // IA32_VMX_ENTRY_CTLS
        case 0x485:  // IA32_VMX_MISC
        case 0x486:  // IA32_VMX_CR0_FIXED0
        case 0x487:  // IA32_VMX_CR0_FIXED1
        case 0x488:  // IA32_VMX_CR4_FIXED0
        case 0x489:  // IA32_VMX_CR4_FIXED1
        case 0x48A:  // IA32_VMX_VMCS_ENUM
        case 0x48B:  // IA32_VMX_PROCBASED_CTLS2
        case 0x48C:  // IA32_VMX_EPT_VPID_CAP
        case 0x48D:  // IA32_VMX_TRUE_PINBASED_CTLS
        case 0x48E:  // IA32_VMX_TRUE_PROCBASED_CTLS
        case 0x48F:  // IA32_VMX_TRUE_EXIT_CTLS
        case 0x490:  // IA32_VMX_TRUE_ENTRY_CTLS
        case 0x491:  // IA32_VMX_TRUE_MISC
        case 0x492:  // IA32_VMX_CR0_FIXED0 (true)
        case 0x493:  // IA32_VMX_CR0_FIXED1 (true)
            value = 0; // = no VMX support
            return true;

        case 0xC0000080: // EFER — SVME bit (AMD SVM enable)
            value = 0x0000000000000D01ULL; // Typical: SCE=1, LME=1, LMA=1, NXE=1 (no SVME)
            return true;

        case 0x176:  // MSR_SYSENTER_EIP (Intel) / MSR_SYSENTER_EIP_IST (AMD)
        case 0x175:  // MSR_SYSENTER_ESP
            // Pass through — these are legitimately used by Windows
            return false;

        case 0x1D9:  // IA32_DEBUGCTL — BTF bit
            value = 0; // No debugging enabled
            return true;

        case 0xC0000082: // MSR_LSTAR — syscall target
            value = 0; // Hidden from guest
            return true;

        default:
            return false;
    }
}

// ─── Spoof handlers ────────────────────────────────────────────────────

#define STATUS_SUCCESS 0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_INVALID_INFO_CLASS 0xC0000003

bool SyscallDispatch::HandleNtQuerySystemInformation(uint64_t* args, uint64_t& result)
{
    uint32_t infoClass = (uint32_t)args[0];
    uint64_t info = args[1];
    uint32_t infoLen = (uint32_t)args[2];
    uint64_t retLenPtr = args[3];

    // SystemKernelDebuggerInformation (35 / 0x23)
    if (infoClass == 35 || infoClass == 0x23) {
        if (info && infoLen >= 2) {
            uint8_t* kd = (uint8_t*)(uintptr_t)info;
            kd[0] = 0; // KernelDebuggerEnabled = FALSE
            kd[1] = 1; // KernelDebuggerNotPresent = TRUE
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = 2;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // SystemCodeIntegrityInformation (103 / 0x67)
    if (infoClass == 103 || infoClass == 0x67) {
        if (info && infoLen >= 8) {
            *(uint32_t*)(uintptr_t)info = 8;
            *(uint32_t*)((uint8_t*)(uintptr_t)info + 4) = 0; // CI options = clean
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = 8;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // SystemModuleInformation (11 / 0x0B)
    if (infoClass == 11 || infoClass == 0x0B) {
        if (infoLen >= sizeof(uint32_t)) {
            if (info) *(uint32_t*)(uintptr_t)info = 0;
            if (retLenPtr) *(uint32_t*)(uintptr_t)retLenPtr = sizeof(uint32_t);
        }
        result = STATUS_SUCCESS;
        return true;
    }

    return false; // Not spoofed — needs passthrough
}

bool SyscallDispatch::HandleNtQueryInformationProcess(uint64_t* args, uint64_t& result)
{
    uint32_t infoClass = (uint32_t)args[2];
    uint64_t info = args[1];
    uint32_t infoLen = (uint32_t)args[3];

    // ProcessDebugPort (class 7) — return -1 = no debugger
    if (infoClass == 7) {
        if (info && infoLen >= sizeof(int32_t)) {
            *(int32_t*)(uintptr_t)info = -1;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(int32_t);
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // ProcessDebugObjectHandle (class 30 / 0x1E) — return NULL
    if (infoClass == 0x1E) {
        if (info && infoLen >= sizeof(HANDLE)) {
            *(HANDLE*)(uintptr_t)info = NULL;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(HANDLE);
        }
        result = STATUS_SUCCESS;
        return true;
    }

    // ProcessBasicInformation (class 0) — return clean PBI
    if (infoClass == 0) {
        if (info && infoLen >= 48) {
            memset((void*)(uintptr_t)info, 0, 48);
            uint64_t pid = GetCurrentProcessId();
            uint64_t ppid = 0x2F0;
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 0) = 0;                     // ExitStatus
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 8) = 0x7FFFA000;            // PebBaseAddress
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 16) = 0;                    // AffinityMask
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 24) = 0;                    // BasePriority
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 32) = pid;                  // UniqueProcessId
            *(uintptr_t*)((uint8_t*)(uintptr_t)info + 40) = ppid;                 // InheritedFromUniqueProcessId
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = 48;
        }
        result = STATUS_SUCCESS;
        return true;
    }

    return false;
}

// Unused handlers — placeholders for future expansion
bool SyscallDispatch::HandleNtOpenKey(uint64_t*, uint64_t& result) { result = STATUS_SUCCESS; return false; }
bool SyscallDispatch::HandleNtQueryValueKey(uint64_t*, uint64_t& result) { result = STATUS_SUCCESS; return false; }
bool SyscallDispatch::HandleNtClose(uint64_t*, uint64_t& result) { result = STATUS_SUCCESS; return false; }
bool SyscallDispatch::HandleNtCreateFile(uint64_t*, uint64_t& result) { result = STATUS_SUCCESS; return false; }
