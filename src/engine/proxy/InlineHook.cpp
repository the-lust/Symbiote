#include "InlineHook.h"
#include "InstructionDecoder.h"
#include <cstring>

InlineHook::InlineHook()
    : m_actualBytes(0), m_target(nullptr), m_detour(nullptr),
      m_trampoline(nullptr), m_installed(false)
{
    ZeroMemory(m_originalBytes, MAX_PRE_READ);
}

InlineHook::~InlineHook()
{
    Remove();
}

bool InlineHook::Install(void* target, void* detour)
{
    if (!target || !detour || m_installed) return false;
    m_target = target;
    m_detour = detour;

    if (!ReadAndDecode()) return false;

    m_trampoline = VirtualAlloc(nullptr, TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!m_trampoline) return false;

    if (!CreateTrampoline()) { Remove(); return false; }
    if (!WriteHookBytes()) { Remove(); return false; }

    m_installed = true;
    return true;
}

void InlineHook::Remove()
{
    if (!m_installed || !m_target) return;

    DWORD old;
    if (VirtualProtect(m_target, HOOK_JMP_SIZE,
        PAGE_EXECUTE_READWRITE, &old))
    {
        memcpy(m_target, m_originalBytes, HOOK_JMP_SIZE);
        VirtualProtect(m_target, HOOK_JMP_SIZE, old, &old);
        FlushInstructionCache(GetCurrentProcess(), m_target, HOOK_JMP_SIZE);
    }

    if (m_trampoline) {
        VirtualFree(m_trampoline, 0, MEM_RELEASE);
        m_trampoline = nullptr;
    }

    m_installed = false;
}

// The trampoline (CreateTrampoline) copies the target's overwritten prologue bytes verbatim
// and executes them from a VirtualAlloc'd address elsewhere in the address space. It never
// scans for or relocates RIP-relative memory operands (very common in x64 code for
// global/import references) or relative call/jmp/jcc instructions — copied verbatim, either
// computes a wildly wrong effective address (RIP-relative) or jumps to garbage (relative
// branch) when executed from the trampoline. Full relocation is nontrivial to get right for
// every encoding; until it's implemented, detect these cases and refuse to install the hook
// rather than silently corrupt the target's execution.
static bool PrologueHasUnrelocatableInstruction(const uint8_t* code, int len)
{
    int pos = 0;
    while (pos < len) {
        uint8_t rex = 0;
        int start = pos;
        while (pos < len && ((code[pos] & 0xF0) == 0x40)) { rex = code[pos]; pos++; }
        if (pos >= len) return true; // truncated, be conservative

        uint8_t op = code[pos];

        // Relative branches: jmp/call rel32, jmp rel8, jcc rel8/rel32
        if (op == 0xE8 || op == 0xE9 || op == 0xEB) return true;
        if (op >= 0x70 && op <= 0x7F) return true;
        if (op == 0x0F && pos + 1 < len && code[pos + 1] >= 0x80 && code[pos + 1] <= 0x8F) return true;

        // RIP-relative memory operand: in 64-bit mode, ModRM with mod==00 and rm==101 means
        // [RIP+disp32], not [EBP]/no-base as in 32-bit mode.
        int modrmPos = (op == 0x0F) ? pos + 2 : pos + 1;
        if (modrmPos < len) {
            uint8_t modrm = code[modrmPos];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;
            if (mod == 0 && rm == 5) return true;
        }

        int instrLen = GetInstructionLength(code + start);
        if (instrLen <= 0) return true; // decoder couldn't make sense of it, be conservative
        pos = start + instrLen;
    }
    return false;
}

bool InlineHook::ReadAndDecode()
{
    SIZE_T bytesRead;
    if (!ReadProcessMemory(GetCurrentProcess(), m_target, m_originalBytes,
        MAX_PRE_READ, &bytesRead) || (int)bytesRead < HOOK_JMP_SIZE)
    {
        return false;
    }

    int boundary = FindInstructionBoundary(
        m_originalBytes, HOOK_JMP_SIZE, MAX_PRE_READ);
    if (boundary <= 0 || boundary > MAX_PRE_READ)
        return false;

    if (PrologueHasUnrelocatableInstruction(m_originalBytes, boundary)) {
        return false;
    }

    m_actualBytes = boundary;
    return true;
}

bool InlineHook::CreateTrampoline()
{
    uint8_t* p = (uint8_t*)m_trampoline;

    // Copy complete instructions
    memcpy(p, m_originalBytes, m_actualBytes);
    p += m_actualBytes;

    // Absolute jmp back to original flow: target + m_actualBytes
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t*)&p[2] = (uint64_t)((uint8_t*)m_target + m_actualBytes);
    p[10] = 0xFF; p[11] = 0xE0;

    DWORD old;
    if (!VirtualProtect(m_trampoline, TRAMPOLINE_SIZE,
        PAGE_EXECUTE_READWRITE, &old))
        return false;
    VirtualProtect(m_trampoline, TRAMPOLINE_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), m_trampoline, TRAMPOLINE_SIZE);
    return true;
}

bool InlineHook::WriteHookBytes()
{
    uint8_t jmpBytes[HOOK_JMP_SIZE];
    jmpBytes[0] = 0x48; jmpBytes[1] = 0xB8;
    *(uint64_t*)&jmpBytes[2] = (uint64_t)(uintptr_t)m_detour;
    jmpBytes[10] = 0xFF; jmpBytes[11] = 0xE0;

    DWORD old;
    if (!VirtualProtect(m_target, HOOK_JMP_SIZE,
        PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(m_target, jmpBytes, HOOK_JMP_SIZE);
    VirtualProtect(m_target, HOOK_JMP_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), m_target, HOOK_JMP_SIZE);
    return true;
}
