#include "KuserHook.h"
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
    // KUSER page is kernel-managed, can't be made writable from user mode.
    // writing to it causes STATUS_GUARD_PAGE_VIOLATION and crashes the process.
    // the target reads from our shared memory "Symbiote_KuserSpoof" instead.
    m_logger->Trace(LOG_WARNING, "KuserHook: cant modify KUSER page (kernel owns it)");
    return false;
}

void KuserHook::CopyStaticSpoofs()
{
    if (!m_spoofedKuser) return;

    // just copy real KUSER data
    memcpy(m_spoofedKuser, (void*)KUSER_VA, KUSER_PAGE_SIZE);

    uint8_t* kuser = (uint8_t*)m_spoofedKuser;

    // override some fields to match i9-10900K reference profile

    // NtMajorVersion=10, NtMinorVersion=0, NtBuildNumber=9000 (0x2328)
    kuser[0x260] = 0x0A; // MajorVersion = 10 (Win 10)
    kuser[0x261] = 0x00; // MinorVersion = 0
    *(uint16_t*)(kuser + 0x262) = 0x2328; // BuildNumber = 9000

    // CSD Version (0x264)
    kuser[0x264] = 0x00;
    kuser[0x265] = 0x00;

    // SuiteMask, ProductType (0x268-0x26E) - i9-10900K workstation layout
    *(uint16_t*)(kuser + 0x268) = 0x0001; // SuiteMask low
    *(uint16_t*)(kuser + 0x26A) = 0x0009; // SuiteMask high
    *(uint16_t*)(kuser + 0x26C) = 0x000A; // ProductType + flags

    // ProcessorFeatures — match i9-10900K per-byte pattern (0x270-0x2C0)
    *(uint64_t*)(kuser + 0x272) = 0x0001000100000000ULL;
    *(uint64_t*)(kuser + 0x273) = 0x0101000100010000ULL;
    *(uint64_t*)(kuser + 0x281) = 0x0100000100010101ULL;
    *(uint64_t*)(kuser + 0x282) = 0x0101000000010001ULL;
    *(uint64_t*)(kuser + 0x283) = 0x0101000100010000ULL;
    *(uint32_t*)(kuser + 0x288) = 0x01000101;
    *(uint32_t*)(kuser + 0x290) = 0x01000101;
    *(uint64_t*)(kuser + 0x294) = 0x0101010101010001ULL;
    *(uint64_t*)(kuser + 0x29C) = 0x0101010100010101ULL;
    *(uint64_t*)(kuser + 0x2A4) = 0x0000010101000001ULL;
    *(uint32_t*)(kuser + 0x2AC) = 0x00010101;

    // SuiteMask @ 0x2D0 is ULONG (4 bytes) — do not write uint64 here (overlaps 0x2D4)
    *(uint32_t*)(kuser + 0x2D0) = 0x00000110;

    // ProductType: Workstation (0x01) — set at all known offsets for cross-build compatibility
    kuser[0x26E] = 0x01;   // pre-19041 layout
    kuser[0x2D8] = 0x01;   // 19041+ layout
    kuser[0x2E8] = 0x01;   // fallback offset for cross-build compatibility

    ApplyStableSpoofs();

    // Debug flags — no debugger present
    *(uint32_t*)(kuser + 0x300) = 0x00000000;
    *(uint32_t*)(kuser + 0x304) = 0x00000000;
    *(uint32_t*)(kuser + 0x308) = 0x00000000;
    *(uint32_t*)(kuser + 0x30C) = 0x00000000;
    *(uint32_t*)(kuser + 0x310) = 0x00000000;
    *(uint32_t*)(kuser + 0x314) = 0x00000000;

    m_logger->Trace(LOG_EPT, "KuserHook: static spoofs applied");
}

void KuserHook::ApplyStableSpoofs()
{
    if (!m_spoofedKuser) return;

    uint8_t* kuser = (uint8_t*)m_spoofedKuser;
    // KdDebuggerEnabled @ 0x2D4 — bit 1 = KdDebuggerNotPresent
    kuser[0x2D4] = 0x02;
    kuser[0x2D5] = 0x01;
}

void KuserHook::SyncTimeFields()
{
    if (!m_spoofedKuser) return;

    uint8_t* spoofed = (uint8_t*)m_spoofedKuser;

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);

    uint64_t tickCount = qpc.QuadPart / 10000;
    uint64_t interruptTime = qpc.QuadPart;
    uint64_t sysTime;
    GetSystemTimeAsFileTime((LPFILETIME)&sysTime);

    // SystemTime (0x318, 0x320)
    *(volatile uint64_t*)(spoofed + 0x318) = sysTime;
    *(volatile uint64_t*)(spoofed + 0x320) = sysTime >> 32;

    // InterruptTime (0x328, 0x330)
    *(volatile uint64_t*)(spoofed + 0x328) = interruptTime;
    *(volatile uint64_t*)(spoofed + 0x330) = interruptTime >> 32;

    // InterruptTime bias (0x338, 0x340)
    *(volatile uint64_t*)(spoofed + 0x338) = interruptTime;
    *(volatile uint64_t*)(spoofed + 0x340) = interruptTime >> 32;

    // TickCount (0x348, 0x34C, 0x350)
    *(volatile uint32_t*)(spoofed + 0x348) = (uint32_t)(tickCount & 0xFFFFFFFF);
    *(volatile uint32_t*)(spoofed + 0x34C) = (uint32_t)(tickCount >> 32);
    *(volatile uint32_t*)(spoofed + 0x350) = (uint32_t)(tickCount >> 32);

    // QPC value (0x370)
    *(volatile uint64_t*)(spoofed + 0x370) = qpc.QuadPart;

    ApplyStableSpoofs();

    // Sync to shared memory
    if (m_sharedView) {
        memcpy(m_sharedView, m_spoofedKuser, KUSER_PAGE_SIZE);
    }
}

bool KuserHook::Initialize()
{
    // Allocate the spoofed KUSER buffer
    m_spoofedKuser = VirtualAlloc(NULL, KUSER_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m_spoofedKuser) {
        m_logger->Trace(LOG_ERROR, "KuserHook: failed to allocate spoofed KUSER buffer");
        return false;
    }

    // Copy static spoofs into the buffer
    CopyStaticSpoofs();
    SyncTimeFields();

    // Attempt to protect the real KUSER page
    bool pageProtected = TryProtectKuserPage();

    // Create a named shared memory with spoofed KUSER for external tools / PoC
    m_sharedMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, KUSER_PAGE_SIZE, L"Symbiote_KuserSpoof");
    m_sharedView = nullptr;
    if (m_sharedMap) {
        m_sharedView = MapViewOfFile(m_sharedMap, FILE_MAP_WRITE, 0, 0, KUSER_PAGE_SIZE);
        if (m_sharedView) {
            memcpy(m_sharedView, m_spoofedKuser, KUSER_PAGE_SIZE);
            m_logger->Trace(LOG_EPT, "KuserHook: shared spoofed KUSER created at %p", m_sharedView);
        } else {
            m_logger->Trace(LOG_EPT, "KuserHook: MapViewOfFile failed (%u)", GetLastError());
        }
    } else {
        m_logger->Trace(LOG_EPT, "KuserHook: CreateFileMappingW failed (%u)", GetLastError());
    }

    // Register VEH Handler for page fault interception
    s_instance = this;
    m_vehHandle = AddVectoredExceptionHandler(0, VectoredHandler);
    if (!m_vehHandle) {
        m_logger->Trace(LOG_ERROR, "KuserHook: AddVectoredExceptionHandler failed (%u)", GetLastError());
        VirtualFree(m_spoofedKuser, 0, MEM_RELEASE);
        m_spoofedKuser = nullptr;
        return false;
    }

    // Start sync thread even if page protection failed ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â emulator handlers still use the buffer
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

    // Restore KUSER page protection (if we changed it)
    if (m_active) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)KUSER_VA, KUSER_PAGE_SIZE, PAGE_READONLY, &oldProtect);
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
        // For write accesses, we'd need to know the write value, which is complex.
        // Log and ignore ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â let the exception propagate.
        m_logger->Trace(LOG_EPT, "KuserHook: write access to KUSER+0x%llX at RIP=0x%llX (passthrough)", offset, ctx->Rip);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // For read accesses: redirect to spoofed buffer
    // We need to find the instruction that caused the fault and emulate it.
    // The faulting instruction reads from [faultAddr].
    // Simple cases: MOV reg, [KUSER+offset], LEA reg, [KUSER+offset]

    // For simplicity in this research phase, we advance RIP past the instruction
    // and rely on the register state having been populated.
    // Full instruction emulation is complex ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â we log the hit for analysis.
    m_logger->Trace(LOG_EPT, "KuserHook: read access to KUSER+0x%llX (offset=0x%llX) at RIP=0x%llX", faultAddr, offset, ctx->Rip);

    // Try to decode instruction and redirect the read/write
    uint8_t* code = (uint8_t*)ctx->Rip;
    int instrLen = 0;

    // helper: read value from spoofed kuser at offset
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

    // helper: set register by modRM.reg field
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

    // helper: get register value by index
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

    // helper: compute parity of low byte
    auto parity = [](uint8_t v) -> int {
        v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
        return (~v) & 1;
    };

    // helper: set EFLAGS for arithmetic result
    auto setFlagsArith = [&](uint64_t dest, uint64_t src, uint64_t result, bool isSub) {
        uint32_t efl = ctx->EFlags;
        efl &= ~0x8D5; // CF, PF, AF, ZF, SF, OF
        if (result == 0) efl |= 0x40; // ZF
        if (result & 0x8000000000000000ULL) efl |= 0x80; // SF
        if (parity((uint8_t)result)) efl |= 0x04; // PF
        uint64_t xorD = dest ^ result;
        uint64_t xorS = src ^ result;
        if (isSub) {
            if (dest < src) efl |= 0x01; // CF
            if ((xorD & xorS) & 0x8000000000000000ULL) efl |= 0x800; // OF
        } else {
            if (result < dest) efl |= 0x01; // CF
            if ((xorD & xorS & 0x8000000000000000ULL)) efl |= 0x800; // OF
        }
        ctx->EFlags = efl;
    };

    // helper: set EFLAGS for logical result (TEST/AND/OR/XOR)
    auto setFlagsLogic = [&](uint64_t result) {
        uint32_t efl = ctx->EFlags;
        efl &= ~0x8D5;
        if (result == 0) efl |= 0x40;
        if (result & 0x8000000000000000ULL) efl |= 0x80;
        if (parity((uint8_t)result)) efl |= 0x04;
        efl &= ~0x801; // clear CF, OF
        ctx->EFlags = efl;
    };

    // === COMMON KUSER ACCESS PATTERNS ===
    // RIP-relative: ModRM.mod=00, RM=101 (disp32 follows)

    // MOV r64, [RIP+disp32]  REX.W 8B /r
    if ((code[0] & 0xFD) == 0x48 && code[1] == 0x8B && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        setReg(code[2] >> 3, read64(offset));
        m_logger->Trace(LOG_EPT, "KuserHook: MOV R%d [K+0x%llX] = 0x%llX", (code[2]>>3)&7, offset, read64(offset));
    }
    // MOV r32, [RIP+disp32]  8B /r
    else if (code[0] == 0x8B && (code[1] & 0xC7) == 0x05) {
        instrLen = 6;
        setReg(code[1] >> 3, (uint64_t)read32(offset));
        m_logger->Trace(LOG_EPT, "KuserHook: MOV R%d [K+0x%llX] (32b)", (code[1]>>3)&7, offset);
    }
    // LEA r64, [RIP+disp32]  REX.W 8D /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x8D && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        setReg(code[2] >> 3, (uint64_t)(uint8_t*)m_spoofedKuser + offset);
        m_logger->Trace(LOG_EPT, "KuserHook: LEA R%d [K+0x%llX]", (code[2]>>3)&7, offset);
    }
    // CMP r64, [RIP+disp32]  REX.W 3B /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x3B && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        int r = (code[2] >> 3) & 7;
        uint64_t d = getReg(r), s = read64(offset);
        setFlagsArith(d, s, d - s, true);
        m_logger->Trace(LOG_EPT, "KuserHook: CMP R%d [K+0x%llX]=0x%llX", r, offset, s);
    }
    // CMP r32, [RIP+disp32]  3B /r
    else if (code[0] == 0x3B && (code[1] & 0xC7) == 0x05) {
        instrLen = 6;
        int r = (code[1] >> 3) & 7;
        uint64_t d = getReg(r) & 0xFFFFFFFF, s = read32(offset);
        setFlagsArith(d, s, d - s, true);
        m_logger->Trace(LOG_EPT, "KuserHook: CMP R%d [K+0x%llX] (32b)", r, offset);
    }
    // TEST r64, [RIP+disp32]  REX.W 85 /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x85 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        int r = (code[2] >> 3) & 7;
        setFlagsLogic(getReg(r) & read64(offset));
        m_logger->Trace(LOG_EPT, "KuserHook: TEST R%d [K+0x%llX]", r, offset);
    }
    // TEST r32, [RIP+disp32]  85 /r
    else if (code[0] == 0x85 && (code[1] & 0xC7) == 0x05) {
        instrLen = 6;
        int r = (code[1] >> 3) & 7;
        setFlagsLogic((getReg(r) & 0xFFFFFFFF) & read32(offset));
    }
    // ADD r64, [RIP+disp32]  REX.W 03 /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x03 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2]>>3)&7;
        uint64_t d = getReg(r), s = read64(offset), res = d + s;
        setReg(r, res); setFlagsArith(d, s, res, false);
    }
    // XOR r64, [RIP+disp32]  REX.W 33 /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x33 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2]>>3)&7;
        uint64_t d = getReg(r), s = read64(offset), res = d ^ s;
        setReg(r, res); setFlagsLogic(res);
    }
    // SUB r64, [RIP+disp32]  REX.W 2B /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x2B && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2]>>3)&7;
        uint64_t d = getReg(r), s = read64(offset), res = d - s;
        setReg(r, res); setFlagsArith(d, s, res, true);
    }
    // AND r64, [RIP+disp32]  REX.W 23 /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x23 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2]>>3)&7;
        uint64_t d = getReg(r), s = read64(offset), res = d & s;
        setReg(r, res); setFlagsLogic(res);
    }
    // OR r64, [RIP+disp32]  REX.W 0B /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x0B && (code[2] & 0xC7) == 0x05) {
        instrLen = 7; int r = (code[2]>>3)&7;
        uint64_t d = getReg(r), s = read64(offset), res = d | s;
        setReg(r, res); setFlagsLogic(res);
    }
    // MOVZX r64, byte [RIP+disp32]  0F B6 /r
    else if (code[0] == 0x0F && code[1] == 0xB6 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        setReg(code[2] >> 3, (uint64_t)read8(offset));
    }
    // MOVZX r64, word [RIP+disp32]  0F B7 /r
    else if (code[0] == 0x0F && code[1] == 0xB7 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        setReg(code[2] >> 3, (uint64_t)read16(offset));
    }
    // MOVSX r64, byte [RIP+disp32]  REX.W 0F BE /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x0F && code[2] == 0xBE && (code[3] & 0xC7) == 0x05) {
        instrLen = 8;
        setReg(code[3] >> 3, (int64_t)(int8_t)read8(offset));
    }
    // MOVSX r64, word [RIP+disp32]  REX.W 0F BF /r
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x0F && code[2] == 0xBF && (code[3] & 0xC7) == 0x05) {
        instrLen = 8;
        setReg(code[3] >> 3, (int64_t)(int16_t)read16(offset));
    }
    // MOV [RIP+disp32], r64  REX.W 89 /r (WRITE)
    else if ((code[0] & 0xFD) == 0x48 && code[1] == 0x89 && (code[2] & 0xC7) == 0x05) {
        instrLen = 7;
        int r = (code[2] >> 3) & 7;
        uint64_t val = getReg(r);
        *(volatile uint64_t*)((uint8_t*)m_spoofedKuser + offset) = val;
        m_logger->Trace(LOG_EPT, "KuserHook: MOV [K+0x%llX], R%d = 0x%llX (WRITE)", offset, r, val);
    }
    // MOV [RIP+disp32], r32  89 /r (WRITE)
    else if (code[0] == 0x89 && (code[1] & 0xC7) == 0x05) {
        instrLen = 6;
        int r = (code[1] >> 3) & 7;
        *(volatile uint32_t*)((uint8_t*)m_spoofedKuser + offset) = (uint32_t)getReg(r);
    }
    // TEST AL, imm8  A8 ib
    else if (code[0] == 0xA8) {
        instrLen = 2;
        setFlagsLogic(read8(offset) & code[1]);
        m_logger->Trace(LOG_EPT, "KuserHook: TEST AL,0x%02X [K+0x%llX]=0x%02X", code[1], offset, (uint32_t)read8(offset));
    }
    // CMP AL, imm8  3C ib
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
