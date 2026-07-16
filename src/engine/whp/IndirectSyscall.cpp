#include "IndirectSyscall.h"
#include "EptExecHook.h"
#include <cstring>

IndirectSyscall* IndirectSyscall::s_instance = nullptr;

IndirectSyscall::IndirectSyscall(Logger* logger)
    : m_logger(logger), m_initialized(false), m_eptHook(nullptr),
      m_syscallPageGpa(0), m_syscallPageVa(nullptr), m_hookRegistered(false)
{
}

IndirectSyscall::~IndirectSyscall()
{
    Shutdown();
}

bool IndirectSyscall::Initialize(EptExecHook* eptHook)
{
    if (m_initialized) return true;

    m_eptHook = eptHook;
    if (!m_eptHook) {
        m_logger->Trace(LOG_WARNING, "IndirectSyscall: EptExecHook not available");
        return false;
    }

    // Find ntdll syscall page
    if (!FindSyscallPage()) {
        m_logger->Trace(LOG_WARNING, "IndirectSyscall: no syscall page found in ntdll");
        m_initialized = true; // Still initialize (just won't hook)
        return true;
    }

    // Register the syscall page for EPT execute-disable interception
    if (!m_eptHook->RegisterEptExecHook(m_syscallPageGpa, 0x1000, m_syscallPageVa,
            IndirectSyscall::SyscallPageCallback)) {
        m_logger->Trace(LOG_ERROR, "IndirectSyscall: failed to register EPT hook");
        return false;
    }

    m_hookRegistered = true;
    m_initialized = true;
    s_instance = this;

    m_logger->Trace(LOG_INFO,
        "IndirectSyscall: EPT hook installed on ntdll syscall page GPA=0x%llX VA=%p",
        m_syscallPageGpa, m_syscallPageVa);
    return true;
}

void IndirectSyscall::Shutdown()
{
    if (m_hookRegistered && m_eptHook && m_syscallPageGpa) {
        m_eptHook->UnregisterEptExecHook(m_syscallPageGpa);
        m_hookRegistered = false;
    }
    m_initialized = false;
}

bool IndirectSyscall::FindSyscallPage()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hNtdll, &modInfo, sizeof(modInfo)))
        return false;

    uint8_t* base = (uint8_t*)modInfo.lpBaseOfDll;
    SIZE_T size = modInfo.SizeOfImage;

    // Look for the syscall; ret pattern (0F 05 C3)
    for (SIZE_T i = 0; i + 2 < size; i++) {
        if (base[i] == 0x0F && base[i + 1] == 0x05 && base[i + 2] == 0xC3) {
            // Found it! Get page alignment
            uint8_t* pageBase = (uint8_t*)((uint64_t)(uintptr_t)(base + i) & ~0xFFFULL);
            m_syscallPageVa = (void*)pageBase;

            // Convert VA to GPA for WHP (identity-mapped in our partition)
            m_syscallPageGpa = (uint64_t)(uintptr_t)pageBase;

            m_logger->Trace(LOG_INFO,
                "IndirectSyscall: found syscall pattern at ntdll+0x%llX, page at %p",
                (uint64_t)(uintptr_t)(base + i) - (uint64_t)(uintptr_t)base, pageBase);
            return true;
        }
    }

    // Fallback: try just 0F 05 (syscall without immediate ret)
    for (SIZE_T i = 0; i + 1 < size; i++) {
        if (base[i] == 0x0F && base[i + 1] == 0x05) {
            uint8_t* pageBase = (uint8_t*)((uint64_t)(uintptr_t)(base + i) & ~0xFFFULL);
            m_syscallPageVa = (void*)pageBase;
            m_syscallPageGpa = (uint64_t)(uintptr_t)pageBase;

            m_logger->Trace(LOG_INFO,
                "IndirectSyscall: found syscall (no ret) at ntdll+0x%llX, page at %p",
                (uint64_t)(uintptr_t)(base + i) - (uint64_t)(uintptr_t)base, pageBase);
            return true;
        }
    }

    return false;
}

void IndirectSyscall::SyscallPageCallback(uint64_t gpa, uint64_t rip)
{
    // This callback is invoked when the EPT exec-disable page is hit
    // The actual syscall dispatch happens in VcpuManager's handle flow
    // This callback logs the event and can be used for statistics

    if (!s_instance) return;
    s_instance->m_logger->Trace(LOG_EPT,
        "IndirectSyscall: syscall page hit GPA=0x%llX RIP=0x%llX",
        gpa, rip);
}
