#include "CodePatcher.h"
#include "profile/CpuProfile.h"
#include "profile/TimingProfile.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <string>

#pragma comment(lib, "psapi.lib")

static const size_t CODE_PATCHER_MAX_PATCHES = 200;

CodePatcher* CodePatcher::s_instance = nullptr;

CodePatcher::CodePatcher(Logger* logger, CpuProfile* cpuProfile, TimingProfile* timingProfile)
    : m_logger(logger), m_cpuProfile(cpuProfile), m_timingProfile(timingProfile),
      m_vehHandle(nullptr), m_initialized(false),
      m_lastSpoofedTsc(0), m_cpuidTimingBase(0), m_cpuidTimingPending(false)
{
    InitializeCriticalSection(&m_cs);
}

CodePatcher::~CodePatcher()
{
    Shutdown();
    DeleteCriticalSection(&m_cs);
}

bool CodePatcher::Initialize()
{
    if (m_initialized) return true;

    // enum all loaded modules
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        m_logger->Trace(LOG_WARNING, "CodePatcher: CreateToolhelp32Snapshot failed (%u) lmao", GetLastError());
        return false;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int scannedCount = 0;
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (scannedCount > 20) break; // safety limit

            // skip system DLLs (they have many CPUID calls that would exhaust patch budget)
            bool isSystem = (me.szModule &&
                (wcsstr(me.szModule, L"ntdll.dll") ||
                 wcsstr(me.szModule, L"kernel32.dll") ||
                 wcsstr(me.szModule, L"kernelbase.dll") ||
                 wcsstr(me.szModule, L"ucrtbase.dll") ||
                 wcsstr(me.szModule, L"msvcrt.dll") ||
                 wcsstr(me.szModule, L"combase.dll") ||
                 wcsstr(me.szModule, L"ole32.dll") ||
                 wcsstr(me.szModule, L"shell32.dll") ||
                 wcsstr(me.szModule, L"shlwapi.dll") ||
                 wcsstr(me.szModule, L"advapi32.dll")));
            if (isSystem) {
                scannedCount++;
                continue;
            }

            ScanModule(me.szModule, (uint8_t*)me.modBaseAddr, me.modBaseSize);
            m_logger->Trace(LOG_INFO, "CodePatcher: scanned module '%ls' (%zu patches found so far)",
                me.szModule, m_patches.size());
            scannedCount++;
            if (m_patches.size() >= CODE_PATCHER_MAX_PATCHES) break;
        } while (Module32NextW(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);

    m_logger->Trace(LOG_INFO, "CodePatcher: found %zu patchable instructions", m_patches.size());

    if (m_patches.empty()) {
        m_initialized = true;
        return true;
    }

    // register VEH first so we dont miss early exceptions
    s_instance = this;
    m_vehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!m_vehHandle) {
        m_logger->Trace(LOG_ERROR, "CodePatcher: AddVectoredExceptionHandler failed (%u)", GetLastError());
        m_patches.clear();
        return false;
    }

    DWORD oldProtect;
    for (auto& entry : m_patches) {
        void* addr = entry.first;
        PatchEntry& pe = entry.second;
        if (VirtualProtect(addr, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            pe.originalByte = *(uint8_t*)addr;
            // Write UD2 (0F 0B) - guaranteed to raise #UD
            // This replaces the first 2 bytes of CPUID (0F A2), RDTSC (0F 31), or RDTSCP (0F 01)
            *(uint16_t*)addr = 0x0B0F; // UD2 in little-endian
            VirtualProtect(addr, 2, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), addr, 2);
        } else {
            m_logger->Trace(LOG_ERROR, "CodePatcher: VirtualProtect(%p) failed (%u)", addr, GetLastError());
        }
    }

    m_initialized = true;
    const char* typeNames[] = { "CPUID", "RDTSC", "RDTSCP" };
    for (auto& entry : m_patches) {
        m_logger->Trace(LOG_INFO, "CodePatcher: patched %s at %p", typeNames[entry.second.type], entry.first);
    }
    m_logger->Trace(LOG_INFO, "CodePatcher: initialized with %zu patches", m_patches.size());
    return true;
}

void CodePatcher::Shutdown()
{
    if (!m_initialized) return;

    EnterCriticalSection(&m_cs);

    if (m_vehHandle) {
        RemoveVectoredExceptionHandler(m_vehHandle);
        m_vehHandle = nullptr;
    }

    // Restore origional bytes
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
    m_logger->Trace(LOG_INFO, "CodePatcher: shutdown, all patches restored");
}

bool CodePatcher::ScanModule(const wchar_t* moduleName, uint8_t* baseAddr, SIZE_T moduleSize)
{
    if (!baseAddr || moduleSize < 0x1000) return false;

    // skip ourselves + proxy DLLs
    if (moduleName && (
        wcsstr(moduleName, L"engine.dll") ||
        wcsstr(moduleName, L"_proxy.dll") ||
        wcsstr(moduleName, L"engine_dll")
    )) {
        return false;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)baseAddr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(baseAddr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD sectionCount = nt->FileHeader.NumberOfSections;

    static const uint32_t MAX_SECTION_SIZE = 50 * 1024 * 1024; // 50 MB

    for (WORD i = 0; i < sectionCount; i++) {
        IMAGE_SECTION_HEADER* section = &sections[i];

        // only care about executable sections
        bool isExecutable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (!isExecutable) continue;

        uint32_t sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
        if (sectionSize == 0 || sectionSize > MAX_SECTION_SIZE) continue;

        uint8_t* sectionStart = baseAddr + section->VirtualAddress;
        ScanSection(sectionStart, sectionSize);
        if (m_patches.size() >= CODE_PATCHER_MAX_PATCHES) break;
    }
    return true;
}

bool CodePatcher::ScanSection(uint8_t* sectionStart, SIZE_T sectionSize)
{
    if (!sectionStart || sectionSize < 4) return false;

    static const size_t MAX_TIMING_PATCHES = 64;

    auto tryAddPatch = [&](void* addr, int instrLength, int type) -> bool {
        if (m_patches.size() >= CODE_PATCHER_MAX_PATCHES) return false;
        EnterCriticalSection(&m_cs);
        if (m_patches.find(addr) == m_patches.end()) {
            PatchEntry pe;
            pe.originalByte = 0x0F;
            pe.instrLength = instrLength;
            pe.type = type;
            m_patches[addr] = pe;
        }
        LeaveCriticalSection(&m_cs);
        return true;
    };

    // Pass 1: RDTSC/RDTSCP first — Denuvo timing checks depend on these being hooked
    size_t timingPatches = 0;
    for (SIZE_T i = 0; i < sectionSize - 4; i++) {
        if (m_patches.size() >= CODE_PATCHER_MAX_PATCHES || timingPatches >= MAX_TIMING_PATCHES) break;

        void* addr = sectionStart + i;

        if (sectionStart[i] == 0x0F && sectionStart[i + 1] == 0x31) {
            if (tryAddPatch(addr, 2, 1)) {
                timingPatches++;
            }
            i += 1;
            continue;
        }

        if (i < sectionSize - 3 &&
            sectionStart[i] == 0x0F && sectionStart[i + 1] == 0x01 && sectionStart[i + 2] == 0xF9) {
            if (tryAddPatch(addr, 3, 2)) {
                timingPatches++;
            }
            i += 2;
        }
    }

    // Pass 2: CPUID (lower priority — large CRT/init blocks can exhaust patch budget)
    for (SIZE_T i = 0; i < sectionSize - 4; i++) {
        if (m_patches.size() >= CODE_PATCHER_MAX_PATCHES) break;

        if (sectionStart[i] == 0x0F && sectionStart[i + 1] == 0xA2) {
            tryAddPatch(sectionStart + i, 2, 0);
            i += 1;
        }
    }

    return true;
}

LONG CALLBACK CodePatcher::VectoredHandler(EXCEPTION_POINTERS* ep)
{
    if (!s_instance) return EXCEPTION_CONTINUE_SEARCH;
    return s_instance->OnException(ep);
}

LONG CodePatcher::OnException(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode != STATUS_ILLEGAL_INSTRUCTION) {
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

    switch (pe.type) {
        case 0: { // CPUID
            uint32_t leaf = (uint32_t)ctx->Rax;
            uint32_t subleaf = (uint32_t)ctx->Rcx;

            m_cpuidTimingBase = (m_lastSpoofedTsc != 0) ? m_lastSpoofedTsc : __rdtsc();
            m_cpuidTimingPending = true;

            if (leaf >= 0x40000000 && leaf <= 0x4000FFFF) {
                ctx->Rax = 0; ctx->Rbx = 0; ctx->Rcx = 0; ctx->Rdx = 0;
                m_logger->Trace(LOG_CPUID, "CodePatcher CPUID hypervisor leaf 0x%X => HIDDEN", leaf);
            } else {
                uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
                if (m_cpuProfile && m_cpuProfile->GetSpoof(leaf, subleaf, &eax, &ebx, &ecx, &edx)) {
                    ctx->Rax = eax; ctx->Rbx = ebx; ctx->Rcx = ecx; ctx->Rdx = edx;
                } else {
                    int info[4] = {0};
                    __try { __cpuidex(info, leaf, subleaf); } __except(EXCEPTION_EXECUTE_HANDLER) { info[0]=info[1]=info[2]=info[3]=0; }
                    ctx->Rax = (uint32_t)info[0];
                    ctx->Rbx = (uint32_t)info[1];
                    ctx->Rcx = (uint32_t)info[2];
                    ctx->Rdx = (uint32_t)info[3];
                }
                if (leaf == 1) {
                    ctx->Rcx &= ~(1u << 31);
                    ctx->Rcx &= ~(1u << 2);
                }
                m_logger->Trace(LOG_CPUID, "CodePatcher CPUID leaf=0x%X subleaf=0x%X => RAX=0x%08llX RBX=0x%08llX RCX=0x%08llX RDX=0x%08llX",
                    leaf, subleaf, ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx);
            }
            ctx->Rip += pe.instrLength;
            break;
        }
        case 1: { // RDTSC
            uint64_t spoofedTsc = 0;
            if (m_cpuidTimingPending) {
                uint32_t seed = (uint32_t)(m_cpuidTimingBase & 0x7FFFFFFF);
                uint32_t jitter = ((seed * 1103515245U + 12345U) & 0x7FFFFFFFU) % 400;
                spoofedTsc = m_cpuidTimingBase + 1800 + jitter;
                m_cpuidTimingPending = false;
            } else {
                uint64_t realTsc = __rdtsc();
                spoofedTsc = realTsc;
                if (m_timingProfile) {
                    spoofedTsc += m_timingProfile->GetTscOffset();
                }

                if (m_timingProfile && m_timingProfile->GetTscFrequency() > 0) {
                    uint32_t seed = (uint32_t)(spoofedTsc & 0x7FFFFFFF);
                    uint32_t noise = ((seed * 1103515245U + 12345U) & 0x7FFFFFFFU) % 200 - 100;
                    spoofedTsc += noise;
                }

                if (spoofedTsc <= m_lastSpoofedTsc) {
                    spoofedTsc = m_lastSpoofedTsc + 1;
                }
                m_cpuidTimingBase = spoofedTsc;
            }

            if (spoofedTsc <= m_lastSpoofedTsc) {
                spoofedTsc = m_lastSpoofedTsc + 1;
            }
            m_lastSpoofedTsc = spoofedTsc;

            ctx->Rax = spoofedTsc & 0xFFFFFFFF;
            ctx->Rdx = (spoofedTsc >> 32) & 0xFFFFFFFF;
            ctx->Rip += pe.instrLength;

            m_logger->Trace(LOG_TIMING, "CodePatcher RDTSC => 0x%llX (offset=0x%llX)", spoofedTsc, m_timingProfile ? m_timingProfile->GetTscOffset() : 0);
            break;
        }
        case 2: { // RDTSCP
            uint64_t spoofedTsc = 0;
            if (m_cpuidTimingPending) {
                uint32_t seed = (uint32_t)(m_cpuidTimingBase & 0x7FFFFFFF);
                uint32_t jitter = ((seed * 1103515245U + 12345U) & 0x7FFFFFFFU) % 400;
                spoofedTsc = m_cpuidTimingBase + 1800 + jitter;
                m_cpuidTimingPending = false;
            } else {
                uint64_t realTsc = __rdtsc();
                spoofedTsc = realTsc;
                if (m_timingProfile) {
                    spoofedTsc += m_timingProfile->GetTscOffset();
                }

                uint32_t seed = (uint32_t)(spoofedTsc & 0x7FFFFFFF);
                uint32_t noise = ((seed * 1103515245U + 12345U) & 0x7FFFFFFFU) % 200 - 100;
                spoofedTsc += noise;

                if (spoofedTsc <= m_lastSpoofedTsc) {
                    spoofedTsc = m_lastSpoofedTsc + 1;
                }
                m_cpuidTimingBase = spoofedTsc;
            }

            if (spoofedTsc <= m_lastSpoofedTsc) {
                spoofedTsc = m_lastSpoofedTsc + 1;
            }
            m_lastSpoofedTsc = spoofedTsc;

            ctx->Rax = spoofedTsc & 0xFFFFFFFF;
            ctx->Rdx = (spoofedTsc >> 32) & 0xFFFFFFFF;
            ctx->Rcx = 0x00000001;
            ctx->Rip += pe.instrLength;

            m_logger->Trace(LOG_TIMING, "CodePatcher RDTSCP => 0x%llX", spoofedTsc);
            break;
        }
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}
