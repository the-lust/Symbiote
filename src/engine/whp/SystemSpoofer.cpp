#include "SystemSpoofer.h"
#include "Logger.h"
#include <vector>
#include <unordered_map>
#include <algorithm>

SystemSpoofer* SystemSpoofer::s_instance = nullptr;

struct PatchEntry {
    PatchType type;
    uint8_t   origByte;
    uint8_t   modrm;
    uint8_t   instrLen;
};

static std::unordered_map<uint64_t, PatchEntry> g_patches;
static std::vector<uint64_t> g_patchAddrs;

// EPT-hidden patches tracker for anti-memory-scanning
struct HiddenPatch {
    uint64_t addr;
    uint8_t camouflageBytes[12]; // Random bytes that replace INT3 when hidden
    uint8_t realBytes[12];       // Original instruction bytes
    bool eptHidden;
};
static std::vector<HiddenPatch> g_hiddenPatches;
static bool g_antiScanEnabled = false;

struct PendingPatch {
    uint64_t addr;
    PatchType type;
    uint8_t   origByte;
    uint8_t   modrm;
    uint8_t   instrLen;
};
static std::vector<PendingPatch> g_pending;

static int ComputeModRmLen(uint8_t modrm)
{
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm  = modrm & 7;
    int len = 1;
    if (mod != 3 && rm == 4)
        len += 1;
    if (mod == 1)
        len += 1;
    else if (mod == 2)
        len += 4;
    else if (mod == 0 && rm == 5)
        len += 4;
    return len;
}

static uint64_t ComputeEffAddr(const CONTEXT* ctx, uint8_t modrm, uint8_t* code, uint64_t rip)
{
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm  = modrm & 7;
    if (mod == 3)
        return 0;
    uint64_t regs[8];
    regs[0] = ctx->Rax; regs[1] = ctx->Rcx; regs[2] = ctx->Rdx; regs[3] = ctx->Rbx;
    regs[4] = ctx->Rsp; regs[5] = ctx->Rbp; regs[6] = ctx->Rsi; regs[7] = ctx->Rdi;
    int offset = 3;
    if (mod == 0 && rm == 5) {
        int32_t disp = *(int32_t*)(code + offset);
        return rip + 7 + disp;
    }
    uint64_t base = regs[rm];
    if (rm == 4) {
        uint8_t sib = code[offset++];
        uint8_t sibBase = sib & 7;
        uint8_t sibIndex = (sib >> 3) & 7;
        uint8_t sibScale = (sib >> 6) & 3;
        if (sibIndex != 4)
            base = regs[sibIndex] * (1ULL << sibScale) + (sibBase == 5 && mod == 0 ? 0 : regs[sibBase]);
        else
            base = (sibBase == 5 && mod == 0) ? 0 : regs[sibBase];
    }
    if (mod == 1) {
        int8_t disp = *(int8_t*)(code + offset);
        return base + disp;
    }
    if (mod == 2) {
        int32_t disp = *(int32_t*)(code + offset);
        return base + disp;
    }
    return base;
}

static void WriteMemory(uint64_t addr, const void* data, size_t size)
{
    DWORD old;
    VirtualProtect((LPVOID)addr, size, PAGE_READWRITE, &old);
    memcpy((LPVOID)addr, data, size);
    VirtualProtect((LPVOID)addr, size, old, &old);
}

bool SystemSpoofer::LookupPatch(uint64_t addr, PatchEntryInfo& out)
{
    auto it = g_patches.find(addr);
    if (it == g_patches.end())
        return false;
    out.type = it->second.type;
    out.modrm = it->second.modrm;
    out.instrLen = it->second.instrLen;
    return true;
}

SystemSpoofer::SystemSpoofer(Logger* logger)
    : m_logger(logger)
{
}

SystemSpoofer::~SystemSpoofer()
{
    if (m_vehHandle) {
        RemoveVectoredExceptionHandler(m_vehHandle);
        m_vehHandle = nullptr;
    }
    for (auto& kv : g_patches) {
        DWORD old;
        VirtualProtect((LPVOID)kv.first, 1, PAGE_EXECUTE_READWRITE, &old);
        *(uint8_t*)kv.first = kv.second.origByte;
        VirtualProtect((LPVOID)kv.first, 1, old, &old);
    }
    g_patches.clear();
    g_patchAddrs.clear();
    g_pending.clear();
    s_instance = nullptr;
}

bool SystemSpoofer::Initialize()
{
    if (m_initialized) return true;
    s_instance = this;

    ScanAndPatch();

    m_vehHandle = AddVectoredExceptionHandler(1, VectoredHandler);

    ApplyPatches();

    m_initialized = true;

    if (m_logger) {
        m_logger->Trace(LOG_INFO,
            "SystemSpoofer: patched %zu (SGDT=%d SIDT=%d SLDT=%d STR=%d XGETBV=%d SYSCALL=%d RDMSR=%d)",
            g_patches.size(),
            m_stats.sgdtCount, m_stats.sidtCount, m_stats.sldtCount,
            m_stats.strCount, m_stats.xgetbvCount,
            m_stats.syscallCount, m_stats.rdmsrCount);
    }
    return true;
}

void SystemSpoofer::ApplyPatches()
{
    if (g_pending.empty()) return;

    // During scan we already excluded engine.dll region.
    // Now only patch non-image regions (skip all loaded DLLs).
    // Most false-positive matches are in system DLL code, and
    // patching them corrupts actively-executing code.
    size_t patchIdx = 0;
    uint8_t* addr = (uint8_t*)0x10000;
    uint8_t* end  = (uint8_t*)0x7FFFFFFF0000ULL;

    while ((uintptr_t)addr < (uintptr_t)end && patchIdx < g_pending.size()) {
        MEMORY_BASIC_INFORMATION mbi;
        ZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
            addr += 0x10000;
            if ((uintptr_t)addr < 0x10000) break;
            continue;
        }

        uint64_t regionEndAddr = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & 0xF0) >= PAGE_EXECUTE_READ &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOCACHE) &&
            mbi.Type != MEM_IMAGE) {

            if (patchIdx < g_pending.size() &&
                g_pending[patchIdx].addr < regionEndAddr &&
                g_pending[patchIdx].addr >= (uint64_t)(uintptr_t)mbi.BaseAddress) {

                DWORD oldProtect;
                VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                    PAGE_EXECUTE_READWRITE, &oldProtect);

                while (patchIdx < g_pending.size() &&
                       g_pending[patchIdx].addr < regionEndAddr) {
                    auto& pp = g_pending[patchIdx];
                    *(uint8_t*)(uintptr_t)pp.addr = 0xCC;
                    PatchEntry pe;
                    pe.type = pp.type;
                    pe.origByte = pp.origByte;
                    pe.modrm = pp.modrm;
                    pe.instrLen = pp.instrLen;
                    g_patches[pp.addr] = pe;
                    g_patchAddrs.push_back(pp.addr);
                    patchIdx++;
                }

                VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
                FlushInstructionCache(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize);
            }
        }

        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if ((uintptr_t)addr <= (uintptr_t)mbi.BaseAddress) break;
    }

    g_pending.clear();
    g_pending.shrink_to_fit();
}

void SystemSpoofer::ScanAndPatch()
{
    uint8_t* addr = (uint8_t*)0x10000;
    uint8_t* end  = (uint8_t*)0x7FFFFFFF0000ULL;
    int regionCount = 0;

    while ((uintptr_t)addr < (uintptr_t)end) {
        MEMORY_BASIC_INFORMATION mbi;
        ZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
            addr += 0x10000;
            if ((uintptr_t)addr < 0x10000) break;
            continue;
        }

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & 0xF0) >= PAGE_EXECUTE_READ &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOCACHE)) {
            regionCount++;
            ScanRegion((uint8_t*)mbi.BaseAddress, mbi.RegionSize);
        }

        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if ((uintptr_t)addr <= (uintptr_t)mbi.BaseAddress) break;
    }
}

void SystemSpoofer::ScanRegion(uint8_t* start, SIZE_T size)
{
    for (SIZE_T i = 0; i + 3 < size; i++) {
        if (start[i] != 0x0F) continue;

        uint8_t op2 = start[i + 1];

        // RDMSR: 0F 32 (2 bytes)
        if (op2 == 0x32) {
            PatchInstruction((uint64_t)(uintptr_t)(start + i), PatchType::RDMSR, start[i], 0, 2);
            i += 1;
            continue;
        }

        // SLDT (0F 00 /0), STR (0F 00 /1)
        if (op2 == 0x00 && i + 3 <= size) {
            uint8_t modrm = start[i + 2];
            uint8_t reg = (modrm >> 3) & 7;

            if (reg == 0) {
                int extra = ComputeModRmLen(modrm);
                int total = 2 + extra;
                if ((int)i + total <= (int)size) {
                    PatchInstruction((uint64_t)(uintptr_t)(start + i), PatchType::SLDT, start[i], modrm, total);
                }
                i += 2;
                continue;
            }
            if (reg == 1) {
                int extra = ComputeModRmLen(modrm);
                int total = 2 + extra;
                if ((int)i + total <= (int)size) {
                    PatchInstruction((uint64_t)(uintptr_t)(start + i), PatchType::STR, start[i], modrm, total);
                }
                i += 2;
                continue;
            }
            continue;
        }

        // SGDT (0F 01 /0), SIDT (0F 01 /1), XGETBV (0F 01 D0)
        if (op2 == 0x01 && i + 3 <= size) {
            uint8_t modrm = start[i + 2];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t reg = (modrm >> 3) & 7;

            if (mod == 3 && reg == 2 && (modrm & 7) == 0) {
                PatchInstruction((uint64_t)(uintptr_t)(start + i), PatchType::XGETBV, start[i], 0, 3);
                i += 2;
                continue;
            }

            if (mod == 3) continue;
            if (reg == 0) {
                int extra = ComputeModRmLen(modrm);
                int total = 2 + extra;
                if ((int)i + total <= (int)size) {
                    PatchInstruction((uint64_t)(uintptr_t)(start + i), PatchType::SGDT, start[i], modrm, total);
                }
                i += 2;
                continue;
            }
            if (reg == 1) {
                int extra = ComputeModRmLen(modrm);
                int total = 2 + extra;
                if ((int)i + total <= (int)size) {
                    PatchInstruction((uint64_t)(uintptr_t)(start + i), PatchType::SIDT, start[i], modrm, total);
                }
                i += 2;
                continue;
            }
            i += 2;
        }
    }
}

void SystemSpoofer::PatchInstruction(uint64_t addr, PatchType type, uint8_t origByte, uint8_t modrm, int len)
{
    PendingPatch pp;
    pp.addr = addr;
    pp.type = type;
    pp.origByte = origByte;
    pp.modrm = modrm;
    pp.instrLen = (uint8_t)len;
    g_pending.push_back(pp);

    switch (type) {
        case PatchType::SGDT:    m_stats.sgdtCount++; break;
        case PatchType::SIDT:    m_stats.sidtCount++; break;
        case PatchType::SLDT:    m_stats.sldtCount++; break;
        case PatchType::STR:     m_stats.strCount++;  break;
        case PatchType::XGETBV:  m_stats.xgetbvCount++; break;
        case PatchType::SYSCALL: m_stats.syscallCount++; break;
        case PatchType::RDMSR:   m_stats.rdmsrCount++; break;
    }
}

static void SetRegisterByRm(CONTEXT* ctx, uint8_t rm, uint64_t value)
{
    switch (rm) {
        case 0: ctx->Rax = value; break;
        case 1: ctx->Rcx = value; break;
        case 2: ctx->Rdx = value; break;
        case 3: ctx->Rbx = value; break;
        case 4: ctx->Rsp = value; break;
        case 5: ctx->Rbp = value; break;
        case 6: ctx->Rsi = value; break;
        case 7: ctx->Rdi = value; break;
    }
}

LONG CALLBACK SystemSpoofer::VectoredHandler(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    if (!s_instance) return EXCEPTION_CONTINUE_SEARCH;

    uint64_t rip = (uint64_t)ep->ExceptionRecord->ExceptionAddress;

    auto it = g_patches.find(rip);
    if (it == g_patches.end())
        return EXCEPTION_CONTINUE_SEARCH;

    const PatchEntry& pe = it->second;
    uint64_t newRip = rip + pe.instrLen;
    CONTEXT* ctx = ep->ContextRecord;

    // Stack-spoiling defense: integrity check stores critical values in high unused
    // stack space before CPUID/SYSCALL/RDMSR operations, then causes an
    // exception. Windows writes EXCEPTION_RECORD + CONTEXT to the thread
    // stack, overwriting those values. Save and restore the top of stack
    // around our handler to preserve integrity check data.
    uint64_t savedStackBackup[64];
    uint64_t rsp = ctx->Rsp;
    memcpy(savedStackBackup, (void*)rsp, sizeof(savedStackBackup));

    switch (pe.type) {
        case PatchType::SGDT:
        case PatchType::SIDT: {
            uint8_t modrm = pe.modrm;
            uint64_t dest = ComputeEffAddr(ctx, modrm, (uint8_t*)rip, rip);
            if (dest) {
                uint16_t limit = (uint16_t)(pe.type == PatchType::SGDT ? s_instance->m_gdtLimit : s_instance->m_idtLimit);
                uint64_t base = (pe.type == PatchType::SGDT ? s_instance->m_gdtBase : s_instance->m_idtBase);
                uint8_t data[10];
                memcpy(data, &limit, 2);
                memcpy(data + 2, &base, 8);
                WriteMemory(dest, data, 10);
            }
            break;
        }
        case PatchType::SLDT: {
            uint8_t modrm = pe.modrm;
            uint8_t mod = (modrm >> 6) & 3;
            if (mod == 3) {
                SetRegisterByRm(ctx, modrm & 7, 0);
            } else {
                uint64_t dest = ComputeEffAddr(ctx, modrm, (uint8_t*)rip, rip);
                if (dest) {
                    uint16_t zero = 0;
                    WriteMemory(dest, &zero, 2);
                }
            }
            break;
        }
        case PatchType::STR: {
            uint8_t modrm = pe.modrm;
            uint8_t mod = (modrm >> 6) & 3;
            if (mod == 3) {
                SetRegisterByRm(ctx, modrm & 7, 0x40);
            } else {
                uint64_t dest = ComputeEffAddr(ctx, modrm, (uint8_t*)rip, rip);
                if (dest) {
                    uint16_t trVal = 0x40;
                    WriteMemory(dest, &trVal, 2);
                }
            }
            break;
        }
        case PatchType::XGETBV: {
            uint32_t xcr = (uint32_t)ctx->Rcx;
            if (xcr == 0) {
                ctx->Rax = (uint64_t)(uint32_t)(s_instance->m_xgetbvResult & 0xFFFFFFFF);
                ctx->Rdx = (uint64_t)(uint32_t)(s_instance->m_xgetbvResult >> 32);
            } else {
                ctx->Rax = 0;
                ctx->Rdx = 0;
            }
            break;
        }
        case PatchType::SYSCALL:
        case PatchType::RDMSR:
            break;
    }

    // Restore stack top to prevent stack-spoiling detection
    memcpy((void*)rsp, savedStackBackup, sizeof(savedStackBackup));

    ctx->Rip = newRip;
    return EXCEPTION_CONTINUE_EXECUTION;
}

void SystemSpoofer::EnableAntiScan(bool enable)
{
    g_antiScanEnabled = enable;
    if (enable) {
        m_logger->Trace(LOG_INFO, "Anti-scan: EPT camouflage enabled");
    }
}

bool SystemSpoofer::ApplyCamouflage()
{
    if (!g_antiScanEnabled) return false;

    for (auto& kv : g_patches) {
        uint64_t addr = kv.first;
        
        // Check if already hidden
        bool alreadyHidden = false;
        for (auto& hp : g_hiddenPatches) {
            if (hp.addr == addr) {
                alreadyHidden = true;
                break;
            }
        }
        if (alreadyHidden) continue;

        HiddenPatch hp;
        hp.addr = addr;
        hp.eptHidden = false;
        
        // Save original INT3 bytes
        memcpy(hp.realBytes, (void*)addr, 12);
        
        // Generate camouflage bytes (NOP-like instructions that won't crash)
        GenerateCamouflage(hp.camouflageBytes, 12);
        
        // Write camouflage over INT3
        DWORD old;
        VirtualProtect((LPVOID)addr, 12, PAGE_EXECUTE_READWRITE, &old);
        memcpy((void*)addr, hp.camouflageBytes, 12);
        VirtualProtect((LPVOID)addr, 12, old, &old);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)addr, 12);
        
        g_hiddenPatches.push_back(hp);

        m_logger->Trace(LOG_INFO, "Anti-scan: camouflaged patch at 0x%llX", addr);
    }
    return true;
}

bool SystemSpoofer::RestorePatches()
{
    if (g_hiddenPatches.empty()) return true;

    for (auto& hp : g_hiddenPatches) {
        DWORD old;
        VirtualProtect((LPVOID)hp.addr, 12, PAGE_EXECUTE_READWRITE, &old);
        memcpy((void*)hp.addr, hp.realBytes, 12);
        VirtualProtect((LPVOID)hp.addr, 12, old, &old);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)hp.addr, 12);

        m_logger->Trace(LOG_INFO, "Anti-scan: restored patch at 0x%llX", hp.addr);
    }
    g_hiddenPatches.clear();
    return true;
}

void SystemSpoofer::GenerateCamouflage(uint8_t* buffer, int len)
{
    // Generate realistic-looking instruction bytes that won't execute
    // Use a mix of 2-byte NOP (66 90), MOV, and other safe opcodes
    static const uint8_t nops[] = { 0x90, 0x66, 0x90, 0x0F, 0x1F, 0x00, 0x0F, 0x1F, 0x40, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    
    for (int i = 0; i < len; i++) {
        buffer[i] = nops[rand() % (sizeof(nops) / sizeof(nops[0]))];
    }
}

// ── EPT-based instruction interception handlers ────────────────────

bool SystemSpoofer::HandleEptSyscallIntercept(uint64_t rip, void* context)
{
    if (!s_instance) return false;

    uint64_t syscallNum = 0;
    if (context) {
        CONTEXT* ctx = (CONTEXT*)context;
        syscallNum = ctx->Rax;
    }

    // Dispatch syscall via existing handler path
    s_instance->m_logger->Trace(LOG_EPT,
        "EPT syscall intercept: RIP=0x%llX syscall=0x%llX",
        rip, syscallNum);

    // The VcpuManager will handle RAX-based syscall dispatch;
    // this hook notifies that a raw SYSCALL instruction was executed
    // from an EPT-no-exec page (detecting direct syscall passthrough)
    return true;
}

bool SystemSpoofer::HandleEptRdmsrIntercept(uint64_t rip, uint32_t msr, uint64_t* value, void*)
{
    if (!s_instance || !value) return false;

    s_instance->m_logger->Trace(LOG_EPT,
        "EPT RDMSR intercept: RIP=0x%llX MSR=0x%X", rip, msr);

    // Return spoofed values consistent with the hypervisor environment
    switch (msr) {
        case 0x10: // IA32_TIME_STAMP_COUNTER
            if (s_instance->m_syntheticTsc) {
                *value = *s_instance->m_syntheticTsc;
                return true;
            }
            *value = __rdtsc();
            return true;

        case 0x8B: // IA32_BIOS_SIGN_ID (microcode revision)
            *value = 0x00000000;
            return true;

        case 0x17: // IA32_PLATFORM_ID
            *value = 0;
            return true;

        case 0x3A: // IA32_FEATURE_CONTROL
            *value = 0x0000000000000005ULL;
            return true;

        case 0x1B: // IA32_APIC_BASE
            *value = 0xFEE00000 | (1ULL << 11);
            return true;

        case 0xE1: // IA32_MC0_STATUS
        case 0xE3: // IA32_MC1_STATUS
        case 0xE5: // IA32_MC2_STATUS
        case 0xE7: // IA32_MC3_STATUS
            *value = 0;
            return true;

        case 0xC0010114: // HWCR (AMD)
        case 0xC0010010: // TSeg (AMD)
        case 0xC0011020: // IBS (AMD)
            *value = 0;
            return true;

        default:
            // Return safe default
            *value = 0;
            return true;
    }
}

bool SystemSpoofer::HandleEptSysInstrIntercept(uint64_t rip, uint8_t* instruction, uint32_t length, void* context)
{
    if (!s_instance || !instruction) return false;

    CONTEXT* ctx = (CONTEXT*)context;
    if (!ctx) return false;

    if (length >= 2 && instruction[0] == 0x0F) {
        switch (instruction[1]) {
            case 0x01: {
                if (length >= 3) {
                    uint8_t modrm = instruction[2];
                    uint8_t reg = (modrm >> 3) & 7;
                    uint8_t mod = (modrm >> 6) & 3;

                    if (reg == 2 && mod == 3 && (modrm & 7) == 0) {
                        // XGETBV (0F 01 D0)
                        uint32_t xcr = (uint32_t)ctx->Rcx;
                        if (xcr == 0) {
                            ctx->Rax = (uint64_t)(uint32_t)(s_instance->m_xgetbvResult & 0xFFFFFFFF);
                            ctx->Rdx = (uint64_t)(uint32_t)(s_instance->m_xgetbvResult >> 32);
                        } else {
                            ctx->Rax = 0;
                            ctx->Rdx = 0;
                        }
                        s_instance->m_logger->Trace(LOG_EPT,
                            "EPT XGETBV intercept: XCR0=0x%llX", s_instance->m_xgetbvResult);
                        return true;
                    }

                    if (reg == 0) { // SGDT (0F 01 /0)
                        uint64_t dest = ComputeEffAddr(ctx, modrm, instruction, rip);
                        if (dest) {
                            uint16_t limit = s_instance->m_gdtLimit;
                            uint64_t base = s_instance->m_gdtBase;
                            uint8_t data[10];
                            memcpy(data, &limit, 2);
                            memcpy(data + 2, &base, 8);
                            WriteMemory(dest, data, 10);
                        }
                        s_instance->m_logger->Trace(LOG_EPT,
                            "EPT SGDT: base=0x%llX limit=0x%X", s_instance->m_gdtBase, s_instance->m_gdtLimit);
                        return true;
                    }

                    if (reg == 1) { // SIDT (0F 01 /1)
                        uint64_t dest = ComputeEffAddr(ctx, modrm, instruction, rip);
                        if (dest) {
                            uint16_t limit = s_instance->m_idtLimit;
                            uint64_t base = s_instance->m_idtBase;
                            uint8_t data[10];
                            memcpy(data, &limit, 2);
                            memcpy(data + 2, &base, 8);
                            WriteMemory(dest, data, 10);
                        }
                        s_instance->m_logger->Trace(LOG_EPT,
                            "EPT SIDT: base=0x%llX limit=0x%X", s_instance->m_idtBase, s_instance->m_idtLimit);
                        return true;
                    }
                }
                break;
            }

            case 0x00: {
                if (length >= 3) {
                    uint8_t modrm = instruction[2];
                    uint8_t reg = (modrm >> 3) & 7;
                    uint8_t mod = (modrm >> 6) & 3;

                    if (reg == 0) { // SLDT (0F 00 /0)
                        if (mod == 3) {
                            SetRegisterByRm(ctx, modrm & 7, 0);
                        } else {
                            uint64_t dest = ComputeEffAddr(ctx, modrm, instruction, rip);
                            if (dest) {
                                uint16_t zero = 0;
                                WriteMemory(dest, &zero, 2);
                            }
                        }
                        s_instance->m_logger->Trace(LOG_EPT, "EPT SLDT intercept at RIP=0x%llX", rip);
                        return true;
                    }

                    if (reg == 1) { // STR (0F 00 /1)
                        if (mod == 3) {
                            SetRegisterByRm(ctx, modrm & 7, 0x40);
                        } else {
                            uint64_t dest = ComputeEffAddr(ctx, modrm, instruction, rip);
                            if (dest) {
                                uint16_t trVal = 0x40;
                                WriteMemory(dest, &trVal, 2);
                            }
                        }
                        s_instance->m_logger->Trace(LOG_EPT, "EPT STR intercept at RIP=0x%llX", rip);
                        return true;
                    }
                }
                break;
            }

            case 0x05: { // SYSCALL (0F 05)
                s_instance->m_logger->Trace(LOG_EPT,
                    "EPT SYSCALL intercept via sys instr handler at RIP=0x%llX", rip);
                return true;
            }

            case 0x32: { // RDMSR (0F 32)
                uint32_t msr = (uint32_t)ctx->Rcx;
                uint64_t value = 0;
                SystemSpoofer::HandleEptRdmsrIntercept(rip, msr, &value, context);
                ctx->Rax = value & 0xFFFFFFFF;
                ctx->Rdx = (value >> 32) & 0xFFFFFFFF;
                s_instance->m_logger->Trace(LOG_EPT,
                    "EPT RDMSR intercept via sys instr handler: MSR=0x%X value=0x%llX", msr, value);
                return true;
            }
        }
    }

    s_instance->m_logger->Trace(LOG_WARNING,
        "EPT sys instr intercept: unknown instr at RIP=0x%llX (len=%u first=0x%02X)",
        rip, length, instruction[0]);
    return true;
}
