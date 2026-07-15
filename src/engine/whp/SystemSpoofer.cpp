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

    // Stack-spoiling defense: Denuvo stores critical values in high unused
    // stack space before CPUID/SYSCALL/RDMSR operations, then causes an
    // exception. Windows writes EXCEPTION_RECORD + CONTEXT to the thread
    // stack, overwriting those values. Save and restore the top of stack
    // around our handler to preserve Denuvo's data.
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

    // Restore stack top to prevent Denuvo's stack-spoiling detection
    memcpy((void*)rsp, savedStackBackup, sizeof(savedStackBackup));

    ctx->Rip = newRip;
    return EXCEPTION_CONTINUE_EXECUTION;
}
