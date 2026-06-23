#include "MsrPatcher.h"
#include "kernel/IKernelBackend.h"
#include <tlhelp32.h>
#include <string>

#pragma comment(lib, "psapi.lib")

MsrPatcher* MsrPatcher::s_instance = nullptr;

MsrPatcher::MsrPatcher(Logger* logger, IKernelBackend* backend)
    : m_logger(logger), m_backend(backend),
      m_vehHandle(nullptr), m_initialized(false)
{
    InitializeCriticalSection(&m_cs);
}

MsrPatcher::~MsrPatcher()
{
    Shutdown();
    DeleteCriticalSection(&m_cs);
}

bool MsrPatcher::Initialize()
{
    if (m_initialized) return true;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        m_logger->Trace(LOG_WARNING, "MsrPatcher: CreateToolhelp32Snapshot failed (%u)", GetLastError());
        return false;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int scannedCount = 0;
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (scannedCount > 0) break;

            ScanModule(me.szModule, (uint8_t*)me.modBaseAddr, me.modBaseSize);
            m_logger->Trace(LOG_INFO, "MsrPatcher: scanned module '%ls' (%zu patches found so far)",
                me.szModule, m_patches.size());
            scannedCount++;
        } while (Module32NextW(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);

    if (m_patches.empty()) {
        m_logger->Trace(LOG_INFO, "MsrPatcher: no RDMSR/WRMSR instructions found in main module");
        m_initialized = true;
        return true;
    }

    s_instance = this;
    m_vehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!m_vehHandle) {
        m_logger->Trace(LOG_ERROR, "MsrPatcher: AddVectoredExceptionHandler failed (%u)", GetLastError());
        m_patches.clear();
        return false;
    }

    DWORD oldProtect;
    for (auto& entry : m_patches) {
        void* addr = entry.first;
        PatchEntry& pe = entry.second;
        if (VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            pe.originalByte = *(uint8_t*)addr;
            *(uint8_t*)addr = 0xCC;
            VirtualProtect(addr, 1, oldProtect, &oldProtect);
        }
    }

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "MsrPatcher: initialized with %zu patches", m_patches.size());
    for (auto& entry : m_patches) {
        m_logger->Trace(LOG_INFO, "MsrPatcher: patched %s(MSR=0x%X) at %p",
            entry.second.isWrite ? "WRMSR" : "RDMSR",
            entry.second.msrIndex, entry.first);
    }
    return true;
}

void MsrPatcher::Shutdown()
{
    if (!m_initialized) return;

    EnterCriticalSection(&m_cs);

    if (m_vehHandle) {
        RemoveVectoredExceptionHandler(m_vehHandle);
        m_vehHandle = nullptr;
    }

    DWORD oldProtect;
    for (auto& entry : m_patches) {
        void* addr = entry.first;
        uint8_t orig = entry.second.originalByte;
        if (VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *(uint8_t*)addr = orig;
            VirtualProtect(addr, 1, oldProtect, &oldProtect);
        }
    }
    m_patches.clear();

    s_instance = nullptr;
    m_initialized = false;

    LeaveCriticalSection(&m_cs);
    m_logger->Trace(LOG_INFO, "MsrPatcher: shutdown, all patches restored");
}

bool MsrPatcher::ScanModule(const wchar_t* moduleName, uint8_t* baseAddr, SIZE_T moduleSize)
{
    if (!baseAddr || moduleSize < 0x1000) return false;

    if (moduleName && (wcsstr(moduleName, L"engine.dll") || wcsstr(moduleName, L"ENGINE.DLL"))) {
        return false;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)baseAddr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(baseAddr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD sectionCount = nt->FileHeader.NumberOfSections;

    static const size_t MAX_PATCHES = 200;
    static const uint32_t MAX_SECTION_SIZE = 50 * 1024 * 1024;

    for (WORD i = 0; i < sectionCount; i++) {
        IMAGE_SECTION_HEADER* section = &sections[i];
        bool isExecutable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (!isExecutable) continue;

        uint32_t sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
        if (sectionSize == 0 || sectionSize > MAX_SECTION_SIZE) continue;

        uint8_t* sectionStart = baseAddr + section->VirtualAddress;
        ScanSection(sectionStart, sectionSize);
        if (m_patches.size() >= MAX_PATCHES) break;
    }
    return true;
}

bool MsrPatcher::ScanSection(uint8_t* sectionStart, SIZE_T sectionSize)
{
    if (!sectionStart || sectionSize < 2) return false;

    static const size_t MAX_PATCHES = 200;

    for (SIZE_T i = 0; i < sectionSize - 2; i++) {
        if (m_patches.size() >= MAX_PATCHES) break;

        void* addr = sectionStart + i;

        if (sectionStart[i] == 0x0F && sectionStart[i + 1] == 0x32) {
            EnterCriticalSection(&m_cs);
            if (m_patches.find(addr) == m_patches.end()) {
                PatchEntry pe;
                pe.originalByte = 0x0F;
                pe.instrLength = 2;
                pe.msrIndex = 0;
                pe.isWrite = false;
                m_patches[addr] = pe;
            }
            LeaveCriticalSection(&m_cs);
            i += 1;
            continue;
        }

        if (sectionStart[i] == 0x0F && sectionStart[i + 1] == 0x30) {
            EnterCriticalSection(&m_cs);
            if (m_patches.find(addr) == m_patches.end()) {
                PatchEntry pe;
                pe.originalByte = 0x0F;
                pe.instrLength = 2;
                pe.msrIndex = 0;
                pe.isWrite = true;
                m_patches[addr] = pe;
            }
            LeaveCriticalSection(&m_cs);
            i += 1;
            continue;
        }
    }
    return true;
}

uint64_t MsrPatcher::HandleMsrRead(uint32_t msr)
{
    uint64_t result = 0;

    switch (msr) {
        case 0x10: // MSR_IA32_TSC
            result = __rdtsc() + m_backend->GetTscOffset();
            break;

        case 0x17: // MSR_IA32_APIC_BASE
            result = 0xFEE00000ULL | (1ULL << 11);
            break;

        case 0x1B: // MSR_IA32_APIC_INTERRUPT_TARGET
            result = 0;
            break;

        case 0x8B: // MSR_IA32_PLATFORM_ID
            result = 0x4000000000000ULL;
            break;

        case 0xE2: // MSR_PKG_CST_CONFIG_CONTROL
            result = 0x00000000;
            break;

        case 0xCE: // MSR_IA32_PERF_STATUS
            if (m_backend && m_backend->GetTscFrequency() > 0) {
                uint64_t freqMHz = m_backend->GetTscFrequency() / 1000000;
                result = (freqMHz & 0xFF) << 8;
            } else {
                result = 0x2800;
            }
            break;

        case 0x198: // MSR_IA32_PERF_CTL
            result = 0x2800;
            break;

        case 0x199: // MSR_IA32_PERF_STATUS (Core)
            result = 0x2800;
            break;

        case 0x1A0: // MSR_IA32_MISC_ENABLE
            result = 0x850089ULL;
            break;

        case 0x1AA: // MSR_IA32_MCG_CAP
            result = 0x000000000000000EULL;
            break;

        case 0xFE: // MSR_IA32_MTRRCAP
            result = 0x0000000000000506ULL;
            break;

        case 0x2FF: // MSR_IA32_MTRR_DEF_TYPE
            result = 0x0000000000000C00ULL;
            break;

        case 0xC0000080: // MSR_IA32_EFER
            result = 0x0000000000000D01ULL;
            break;

        case 0x1AC: // MSR_TURBO_RATIO_LIMIT1
            result = 0x0000000000000035ULL;
            break;

        case 0x1AD: // MSR_TURBO_RATIO_LIMIT
            result = 0x3131323233333535ULL;
            break;

        case 0x1AE: // MSR_TURBO_RATIO_LIMIT_CORES
            result = 0x0030003000000000ULL;
            break;

        case 0x1FC: // MSR_POWER_CTL
            result = 0x0000000000000040ULL;
            break;

        case 0x606: // MSR_RAPL_POWER_UNIT
            result = 0x0000000A0E001003ULL;
            break;

        case 0x610: // MSR_PKG_POWER_LIMIT
            result = 0x0000B3CA001500C0ULL;
            break;

        case 0x611: // MSR_PKG_ENERGY_STATUS
            result = 0x0000000000000000ULL;
            break;

        case 0x614: // MSR_PKG_POWER_INFO
            result = 0x00000000000000C8ULL;
            break;

        case 0x648: // MSR_CONFIG_TDP_NOMINAL
            result = 0x0000000000000037ULL;
            break;

        case 0x649: // MSR_CONFIG_TDP_LEVEL1
            result = 0x0000000000000000ULL;
            break;

        case 0x64A: // MSR_CONFIG_TDP_LEVEL2
            result = 0x0000000000000000ULL;
            break;

        case 0x64B: // MSR_CONFIG_TDP_CONTROL
            result = 0x0000000000000000ULL;
            break;

        case 0x19C: // MSR_IA32_THERM_STATUS
            result = 0x0000000000000000ULL;
            break;

        case 0x1A2: // MSR_IA32_TEMPERATURE_TARGET
            result = 0x0000000000640000ULL;
            break;

        case 0x19B: // MSR_IA32_THERM_INTERRUPT
            result = 0x0000000000000000ULL;
            break;

        case 0x1B1: // MSR_IA32_PACKAGE_THERM_STATUS
            result = 0x0000000000000000ULL;
            break;

        case 0x1B2: // MSR_IA32_PACKAGE_THERM_INTERRUPT
            result = 0x0000000000000000ULL;
            break;

        case 0x19A: // MSR_IA32_CLOCK_MODULATION
            result = 0x0000000000000000ULL;
            break;

        case 0x1B0: // MSR_IA32_ENERGY_PERF_BIAS
            result = 0x0000000000000006ULL;
            break;

        default:
            m_logger->Trace(LOG_WARNING, "MsrPatcher: unhandled RDMSR(0x%X), reading real value", msr);
            result = 0;
            break;
    }

    m_logger->Trace(LOG_INFO, "MsrPatcher: RDMSR(0x%X) => 0x%llX", msr, result);
    return result;
}

LONG CALLBACK MsrPatcher::VectoredHandler(EXCEPTION_POINTERS* ep)
{
    if (!s_instance) return EXCEPTION_CONTINUE_SEARCH;
    return s_instance->OnException(ep);
}

LONG MsrPatcher::OnException(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void* exceptionAddr = ep->ExceptionRecord->ExceptionAddress;
    CONTEXT* ctx = ep->ContextRecord;

    EnterCriticalSection(&m_cs);
    auto it = m_patches.find(exceptionAddr);
    if (it == m_patches.end()) {
        LeaveCriticalSection(&m_cs);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    PatchEntry pe = it->second;
    LeaveCriticalSection(&m_cs);

    if (pe.isWrite) {
        uint32_t msr = (uint32_t)ctx->Rcx;
        uint64_t value = (ctx->Rdx << 32) | (ctx->Rax & 0xFFFFFFFF);
        m_logger->Trace(LOG_INFO, "MsrPatcher: WRMSR(0x%X) = 0x%llX (blocked)", msr, value);
        ctx->Rip += pe.instrLength;
    } else {
        uint32_t msr = (uint32_t)ctx->Rcx;
        uint64_t value = HandleMsrRead(msr);
        ctx->Rax = value & 0xFFFFFFFF;
        ctx->Rdx = (value >> 32) & 0xFFFFFFFF;
        ctx->Rip += pe.instrLength;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}
