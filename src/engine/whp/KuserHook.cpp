#include "KuserHook.h"
#include "../kernel/VirtualClock.h"
#include <cstring>

KuserHook* KuserHook::s_instance = nullptr;

KuserHook::KuserHook(Logger* logger)
    : m_logger(logger), m_spoofedKuser(nullptr), m_sharedView(nullptr),
      m_sharedMap(nullptr), m_vehHandle(nullptr),
      m_syncThread(nullptr), m_stopEvent(nullptr), m_active(false), m_running(false)
{
}

KuserHook::~KuserHook()
{
    Shutdown();
}

bool KuserHook::TryProtectKuserPage()
{
    // KUSER page is kernel-managed; it cannot be made writable from user mode
    // (writes raise STATUS_GUARD_PAGE_VIOLATION and crash the process). Reads
    // in non-WHP mode are served by the VEH overlay from the spoofed buffer.
    m_logger->Trace(LOG_WARNING, "KuserHook: can't modify KUSER page (kernel owns it) — VEH overlay only");
    return false;
}

void KuserHook::BuildSpoofedPage()
{
    if (!m_spoofedKuser) return;

    // Zero-rule base — never copy anything from the real KUSER page.
    memset(m_spoofedKuser, 0, KUSER_PAGE_SIZE);

    KUSER_SHARED_DATA_X64* k = (KUSER_SHARED_DATA_X64*)m_spoofedKuser;

    // Donor (LUST) defaults; KuserSync is the config-driven primary path.
    k->NtBuildNumber = 19045;
    k->NtMajorVersion = 10;
    k->NtMinorVersion = 0;
    k->NtProductType = 1;
    k->ProductTypeIsValid = 1;
    k->NativeProcessorArchitecture = 9;
    k->SuiteMask = 0x0110;
    k->NumberOfPhysicalPages = 0x1FA054;
    k->FullNumberOfPhysicalPages = 0x1FA054;
    k->ActiveProcessorCount = 4;
    k->ActiveGroupCount = 1;
    k->UnparkedProcessorCount = 4;
    k->MitigationPolicies = 0x0A;
    k->CyclesPerYield = 9;
    k->ImageNumberLow = 0x8664;
    k->ImageNumberHigh = 0x8664;
    k->LargePageMinimum = 0x200000;
    k->QpcFrequency = 10000000;
    k->TickCountMultiplier = 262144000;
    k->QpcSystemTimeIncrement = 0x8000000000000000ULL;
    k->QpcInterruptTimeIncrement = 0x8000000000000000ULL;
    k->QpcSystemTimeIncrementShift = 1;
    k->QpcInterruptTimeIncrementShift = 1;
    k->KdDebuggerEnabled = 0;
    k->SystemCall = 0;
    k->SafeBootMode = 0;
    k->VirtualizationFlags = 0;

    SyncTimeFields();

    m_logger->Trace(LOG_EPT, "KuserHook: spoofed KUSER page built (zero-rule base, layout-typed)");
}

void KuserHook::SyncTimeFields()
{
    if (!m_spoofedKuser) return;

    KUSER_SHARED_DATA_X64* k = (KUSER_SHARED_DATA_X64*)m_spoofedKuser;
    VirtualClock& clock = VirtualClock::Get();

    uint64_t vqpc = clock.VirtualQpc100ns();
    uint64_t sysTime = clock.SystemTime();
    uint64_t intTime = vqpc;
    uint64_t tickCount = clock.TickCountQuad();

    auto setKst = [](KSYSTEM_TIME_X64* dst, uint64_t value) {
        dst->LowPart = (uint32_t)(value & 0xFFFFFFFF);
        dst->High1Time = (int32_t)(value >> 32);
        dst->High2Time = dst->High1Time;
    };
    setKst(&k->SystemTime, sysTime);
    setKst(&k->InterruptTime, intTime);

    k->TickCountQuad = tickCount;
    k->TickCountHigh2Time = (int32_t)(tickCount >> 32);
    k->TimeUpdateLock = clock.TimeUpdateLock();
    k->BaselineSystemTimeQpc = vqpc;
    k->BaselineInterruptTimeQpc = vqpc;

    if (m_sharedView) {
        memcpy(m_sharedView, m_spoofedKuser, KUSER_PAGE_SIZE);
    }
}

bool KuserHook::Initialize()
{
    m_spoofedKuser = VirtualAlloc(NULL, KUSER_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m_spoofedKuser) {
        m_logger->Trace(LOG_ERROR, "KuserHook: failed to allocate spoofed KUSER buffer");
        return false;
    }

    BuildSpoofedPage();

    // Attempt to protect the real KUSER page — expected to fail (kernel-owned)
    bool pageProtected = TryProtectKuserPage();

    // Named shared memory with the spoofed KUSER for external tools / PoC
    m_sharedMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, KUSER_PAGE_SIZE, L"Symbiote_KuserSpoof");
    m_sharedView = nullptr;
    if (m_sharedMap) {
        m_sharedView = MapViewOfFile(m_sharedMap, FILE_MAP_WRITE, 0, 0, KUSER_PAGE_SIZE);
        if (m_sharedView) {
            memcpy(m_sharedView, m_spoofedKuser, KUSER_PAGE_SIZE);
        } else {
            m_logger->Trace(LOG_EPT, "KuserHook: MapViewOfFile failed (%u)", GetLastError());
        }
    } else {
        m_logger->Trace(LOG_EPT, "KuserHook: CreateFileMappingW failed (%u)", GetLastError());
    }

    // VEH handler for page fault interception
    s_instance = this;
    m_vehHandle = AddVectoredExceptionHandler(0, VectoredHandler);
    if (!m_vehHandle) {
        m_logger->Trace(LOG_ERROR, "KuserHook: AddVectoredExceptionHandler failed (%u)", GetLastError());
        VirtualFree(m_spoofedKuser, 0, MEM_RELEASE);
        m_spoofedKuser = nullptr;
        return false;
    }

    // Sync thread keeps time fields live
    m_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (m_stopEvent) {
        m_syncThread = CreateThread(NULL, 0, SyncThreadProc, this, 0, NULL);
        if (m_syncThread) {
            m_running = true;
        }
    }

    m_active = pageProtected;
    m_logger->Trace(LOG_EPT, "KuserHook: initialized (pageProtected=%d, spoofedVA=%p)", pageProtected, m_spoofedKuser);
    return true;
}

void KuserHook::Shutdown()
{
    if (m_running && m_stopEvent) {
        SetEvent(m_stopEvent);
        if (m_syncThread) {
            WaitForSingleObject(m_syncThread, 1000);
            CloseHandle(m_syncThread);
        }
        CloseHandle(m_stopEvent);
        m_running = false;
    }

    if (m_vehHandle) {
        RemoveVectoredExceptionHandler(m_vehHandle);
        m_vehHandle = nullptr;
    }

    if (m_spoofedKuser) {
        VirtualFree(m_spoofedKuser, 0, MEM_RELEASE);
        m_spoofedKuser = nullptr;
    }

    if (m_sharedView) {
        UnmapViewOfFile(m_sharedView);
        m_sharedView = nullptr;
    }
    if (m_sharedMap) {
        CloseHandle(m_sharedMap);
        m_sharedMap = nullptr;
    }

    s_instance = nullptr;
    m_active = false;
    m_logger->Trace(LOG_EPT, "KuserHook: shutdown complete");
}

LONG CALLBACK KuserHook::VectoredHandler(EXCEPTION_POINTERS* ep)
{
    if (!s_instance) return EXCEPTION_CONTINUE_SEARCH;
    return s_instance->OnException(ep);
}

LONG KuserHook::OnException(EXCEPTION_POINTERS* ep)
{
    // Only handle access violations and guard page violations
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        ep->ExceptionRecord->ExceptionCode != EXCEPTION_GUARD_PAGE) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // check if fault addr is inside KUSER
    uint64_t faultAddr = ep->ExceptionRecord->ExceptionInformation[1];
    if (faultAddr < KUSER_VA || faultAddr >= KUSER_VA + KUSER_PAGE_SIZE) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (!m_spoofedKuser) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    CONTEXT* ctx = ep->ContextRecord;
    uint64_t offset = faultAddr - KUSER_VA;

    // read or write?
    bool isWrite = (ep->ExceptionRecord->ExceptionInformation[0] == 1);

    if (isWrite) {
        // Writes to KUSER are kernel-only in reality; treat as passthrough to
        // the spoofed buffer if the instruction decodes, else propagate.
        uint8_t* code = (uint8_t*)ctx->Rip;
        if ((code[0] & 0xFD) == 0x48 && code[1] == 0x89 && (code[2] & 0xC7) == 0x05) {
            int r = (code[2] >> 3) & 7;
            uint64_t val = ctx->Rax;
            switch (r) { case 1: val = ctx->Rcx; break; case 2: val = ctx->Rdx; break;
                case 3: val = ctx->Rbx; break; case 4: val = ctx->Rsp; break;
                case 5: val = ctx->Rbp; break; case 6: val = ctx->Rsi; break;
                case 7: val = ctx->Rdi; break; }
            *(volatile uint64_t*)((uint8_t*)m_spoofedKuser + offset) = val;
            ctx->Rip += 7;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        m_logger->Trace(LOG_EPT, "KuserHook: write access to KUSER+0x%llX at RIP=0x%llX (passthrough)", offset, ctx->Rip);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Read accesses: redirect to the spoofed buffer by emulating the access.
    uint8_t* code = (uint8_t*)ctx->Rip;
    int instrLen = 0;

    auto read64 = [&](uint64_t off) -> uint64_t {
        return *(volatile uint64_t*)((uint8_t*)m_spoofedKuser + off);
    };
    auto read32 = [&](uint64_t off) -> uint32_t {
        return *(volatile uint32_t*)((uint8_t*)m_spoofedKuser + off);
    };
    auto read16 = [&](uint64_t off) -> uint16_t {
        return *(volatile uint16_t*)((uint8_t*)m_spoofedKuser + off);
    };
    auto read8 = [&](uint64_t off) -> uint8_t {
        return *(volatile uint8_t*)((uint8_t*)m_spoofedKuser + off);
    };

    auto setReg = [&](int reg, uint64_t val) {
        switch (reg & 7) {
            case 0: ctx->Rax = val; break;
            case 1: ctx->Rcx = val; break;
            case 2: ctx->Rdx = val; break;
            case 3: ctx->Rbx = val; break;
            case 4: ctx->Rsp = val; break;
            case 5: ctx->Rbp = val; break;
            case 6: ctx->Rsi = val; break;
            case 7: ctx->Rdi = val; break;
        }
    };

    auto getReg = [&](int reg) -> uint64_t {
        switch (reg & 7) {
            case 0: return ctx->Rax;
            case 1: return ctx->Rcx;
            case 2: return ctx->Rdx;
            case 3: return ctx->Rbx;
            case 4: return ctx->Rsp;
            case 5: return ctx->Rbp;
            case 6: return ctx->Rsi;
            case 7: return ctx->Rdi;
            default: return 0;
        }
    };

    auto parity = [](uint8_t v) -> int {
        v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
        return (~v) & 1;
    };

    auto setFlagsArith = [&](uint64_t dest, uint64_t src, uint64_t result, bool isSub) {
        uint32_t efl = ctx->EFlags;
        efl &= ~0x8D5;
        if (result == 0) efl |= 0x40;
        if (result & 0x8000000000000000ULL) efl |= 0x80;
        if (parity((uint8_t)result)) efl |= 0x04;
        uint64_t xorD = dest ^ result;
        uint64_t xorS = src ^ result;
        if (isSub) {
            if (dest < src) efl |= 0x01;
            if ((xorD & xorS) & 0x8000000000000000ULL) efl |= 0x800;
        } else {
            if (result < dest) efl |= 0x01;
            if ((xorD & xorS & 0x8000000000000000ULL)) efl |= 0x800;
        }
        ctx->EFlags = efl;
    };

    auto setFlagsLogic = [&](uint64_t result) {
        uint32_t efl = ctx->EFlags;
        efl &= ~0x8D5;
        if (result == 0) efl |= 0x40;
        if (result & 0x8000000000000000ULL) efl |= 0x80;
        if (parity((uint8_t)result)) efl |= 0x04;
        efl &= ~0x801;
        ctx->EFlags = efl;
    };

    // === COMMON KUSER ACCESS PATTERNS (RIP-relative) ===
    if ((code[0] & 0xFD) == 0x48 && code[1] == 0x8B && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        setReg(code[2] >> 3, read64(offset));
    }
    else if (code[0] == 0x8B && (code[1] & 0xC7) == 0x05) {
        instrLen = 6;
        setReg(code[1] >> 3, (uint64_t)read32(offset));
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x8D && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        setReg(code[2] >> 3, (uint64_t)(uint8_t*)m_spoofedKuser + offset);
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x3B && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        int r = (code[2] >> 3) & 7;
        uint64_t d = getReg(r), s = read64(offset);
        setFlagsArith(d, s, d - s, true);
    }
    else if (code[0] == 0x3B && (code[1] & 0xC7) == 0x05) {
        instrLen = 6;
        int r = (code[1] >> 3) & 7;
        uint64_t d = getReg(r) & 0xFFFFFFFF, s = read32(offset);
        setFlagsArith(d, s, d - s, true);
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x85 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        int r = (code[2] >> 3) & 7;
        setFlagsLogic(getReg(r) & read64(offset));
    }
    else if (code[0] == 0x85 && (code[1] & 0xC7) == 0x05) {
        instrLen = 6;
        int r = (code[1] >> 3) & 7;
        setFlagsLogic((getReg(r) & 0xFFFFFFFF) & read32(offset));
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x03 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2] >> 3) & 7;
        uint64_t d = getReg(r), s = read64(offset), res = d + s;
        setReg(r, res); setFlagsArith(d, s, res, false);
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x33 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2] >> 3) & 7;
        uint64_t d = getReg(r), s = read64(offset), res = d ^ s;
        setReg(r, res); setFlagsLogic(res);
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x2B && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2] >> 3) & 7;
        uint64_t d = getReg(r), s = read64(offset), res = d - s;
        setReg(r, res); setFlagsArith(d, s, res, true);
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x23 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2] >> 3) & 7;
        uint64_t d = getReg(r), s = read64(offset), res = d & s;
        setReg(r, res); setFlagsLogic(res);
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x0B && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2] >> 3) & 7;
        uint64_t d = getReg(r), s = read64(offset), res = d | s;
        setReg(r, res); setFlagsLogic(res);
    }
    else if (code[0] == 0x0F && code[1] == 0xB6 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        setReg(code[2] >> 3, (uint64_t)read8(offset));
    }
    else if (code[0] == 0x0F && code[1] == 0xB7 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        setReg(code[2] >> 3, (uint64_t)read16(offset));
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x0F && code[2] == 0xBE && (code[3] & 0xC7) == 0x05) {
        instrLen = 8;
        setReg(code[3] >> 3, (int64_t)(int8_t)read8(offset));
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x0F && code[2] == 0xBF && (code[3] & 0xC7) == 0x05) {
        instrLen = 8;
        setReg(code[3] >> 3, (int64_t)(int16_t)read16(offset));
    }
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x89 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        int r = (code[2] >> 3) & 7;
        *(volatile uint64_t*)((uint8_t*)m_spoofedKuser + offset) = getReg(r);
    }
    else if (code[0] == 0x89 && (code[1] & 0xC7) == 0x05) {
        instrLen = 6;
        int r = (code[1] >> 3) & 7;
        *(volatile uint32_t*)((uint8_t*)m_spoofedKuser + offset) = (uint32_t)getReg(r);
    }
    else if (code[0] == 0xA8) {
        instrLen = 2;
        setFlagsLogic(read8(offset) & code[1]);
    }
    else if (code[0] == 0x3C) {
        instrLen = 2;
        uint8_t imm = code[1];
        uint64_t v = read8(offset);
        setFlagsArith(v, imm, v - imm, true);
    }
    else {
        m_logger->Trace(LOG_EPT, "KuserHook: unhandled instr RIP=0x%llX %02X %02X %02X %02X", ctx->Rip, code[0], code[1], code[2], code[3]);
        instrLen = 2;
    }

    if (instrLen > 0) {
        ctx->Rip += instrLen;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI KuserHook::SyncThreadProc(LPVOID lpParam)
{
    KuserHook* self = (KuserHook*)lpParam;

    while (true) {
        DWORD waitResult = WaitForSingleObject(self->m_stopEvent, 1);
        if (waitResult == WAIT_OBJECT_0) break;
        self->SyncTimeFields();
    }

    return 0;
}