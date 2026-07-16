#include "StackSpoofer.h"
#include <cstring>

StackSpoofer::StackSpoofer(Logger* logger)
    : m_logger(logger), m_initialized(false), m_retSledAddr(0), m_retSledSize(0)
{
}

StackSpoofer::~StackSpoofer()
{
    Shutdown();
}

bool StackSpoofer::Initialize()
{
    if (m_initialized) return true;

    // Find a ret sled in a module
    if (!FindRetSled()) {
        m_logger->Trace(LOG_WARNING, "StackSpoofer: no ret sled found, using ntdll fallback");
    }

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "StackSpoofer: initialized (retSled=0x%llX size=%u)",
        m_retSledAddr, m_retSledSize);
    return true;
}

void StackSpoofer::Shutdown()
{
    m_initialized = false;
}

bool StackSpoofer::FindRetSled()
{
    // Search ntdll for a sequence of RET instructions (C3)
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hNtdll, &modInfo, sizeof(modInfo)))
        return false;

    uint8_t* base = (uint8_t*)modInfo.lpBaseOfDll;
    SIZE_T size = modInfo.SizeOfImage;

    // Look for KiFastSystemCallRet pattern (C3 or C2 XX XX)
    for (SIZE_T i = 0; i + 1 < size; i++) {
        if (base[i] == 0xC3) {
            // Found a standalone RET - check surrounding bytes for usability
            if (i >= 5 && base[i-5] == 0x0F && base[i-4] == 0x05) {
                // syscall; ret pattern - use the ret
                m_retSledAddr = (uint64_t)(uintptr_t)(base + i);
                m_retSledSize = 1;
                m_logger->Trace(LOG_INFO, "StackSpoofer: found syscall ret sled at ntdll+0x%llX",
                    (uint64_t)(uintptr_t)(base + i) - (uint64_t)(uintptr_t)base);
                return true;
            }
        }
    }

    // Fallback: just find any ret in the DLL
    for (SIZE_T i = 0; i < size; i++) {
        if (base[i] == 0xC3 && (i == 0 || base[i-1] != 0xCD)) {
            m_retSledAddr = (uint64_t)(uintptr_t)(base + i);
            m_retSledSize = 1;
            m_logger->Trace(LOG_INFO, "StackSpoofer: fallback ret sled at ntdll+0x%llX",
                (uint64_t)(uintptr_t)(base + i) - (uint64_t)(uintptr_t)base);
            return true;
        }
    }

    return false;
}

void StackSpoofer::SpoofReturnAddress(void* context)
{
    if (!m_retSledAddr || !context) return;

    CONTEXT* ctx = (CONTEXT*)context;
    uint64_t rsp = ctx->Rsp;

    // Read the current return address from the stack
    uint64_t currentRet = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)rsp, &currentRet, sizeof(currentRet), nullptr))
        return;

    // Save the original return address
    m_savedRetAddr[rsp % MAX_SAVED_FRAMES] = currentRet;

    // Replace with ret sled address
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)rsp, &m_retSledAddr, sizeof(m_retSledAddr), nullptr);

    m_logger->Trace(LOG_SPOOF, "StackSpoofer: replaced ret 0x%llX -> 0x%llX at RSP 0x%llX",
        currentRet, m_retSledAddr, rsp);
}

bool StackSpoofer::RestoreReturnAddress(void* context, uint64_t)
{
    if (!context) return false;

    CONTEXT* ctx = (CONTEXT*)context;
    uint64_t rsp = ctx->Rsp;
    uint64_t savedRet = m_savedRetAddr[rsp % MAX_SAVED_FRAMES];

    if (savedRet == 0) return false;

    // Restore the original return address
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)rsp, &savedRet, sizeof(savedRet), nullptr);

    m_logger->Trace(LOG_SPOOF, "StackSpoofer: restored ret 0x%llX at RSP 0x%llX", savedRet, rsp);
    return true;
}

uint64_t StackSpoofer::GetReturnAddress(uint64_t rsp)
{
    uint64_t retAddr = 0;
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)rsp, &retAddr, sizeof(retAddr), nullptr);
    return retAddr;
}
