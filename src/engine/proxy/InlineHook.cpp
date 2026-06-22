#include "InlineHook.h"
#include <cstring>

InlineHook::InlineHook()
    : m_target(nullptr), m_detour(nullptr), m_trampoline(nullptr), m_installed(false)
{
    ZeroMemory(m_originalBytes, HOOK_SIZE);
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

    // save orig bytes
    if (!ReadProcessMemory(GetCurrentProcess(), target, m_originalBytes, HOOK_SIZE, nullptr))
        return false;

    // allocate trampoline page
    m_trampoline = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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
    if (VirtualProtect(m_target, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(m_target, m_originalBytes, HOOK_SIZE);
        VirtualProtect(m_target, HOOK_SIZE, old, &old);
        FlushInstructionCache(GetCurrentProcess(), m_target, HOOK_SIZE);
    }

    if (m_trampoline) {
        VirtualFree(m_trampoline, 0, MEM_RELEASE);
        m_trampoline = nullptr;
    }

    m_installed = false;
}

bool InlineHook::WriteHookBytes()
{
    // mov rax, detour  (48 B8 <8 byte addr>)
    // jmp rax          (FF E0)
    uint8_t jmpBytes[HOOK_SIZE];
    ZeroMemory(jmpBytes, HOOK_SIZE);
    jmpBytes[0] = 0x48; jmpBytes[1] = 0xB8; // mov rax, imm64
    *(uint64_t*)&jmpBytes[2] = (uint64_t)(uintptr_t)m_detour;
    jmpBytes[10] = 0xFF; jmpBytes[11] = 0xE0; // jmp rax

    DWORD old;
    if (!VirtualProtect(m_target, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(m_target, jmpBytes, HOOK_SIZE);
    VirtualProtect(m_target, HOOK_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), m_target, HOOK_SIZE);
    return true;
}

bool InlineHook::CreateTrampoline()
{
    // trampoline: copy orig bytes + absolute jmp back to original flow
    uint8_t* p = (uint8_t*)m_trampoline;

    // copy orig bytes
    memcpy(p, m_originalBytes, HOOK_SIZE);
    p += HOOK_SIZE;

    // absolute jmp: mov rax, target+HOOK_SIZE; jmp rax
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t*)&p[2] = (uint64_t)((uint8_t*)m_target + HOOK_SIZE);
    p[10] = 0xFF; p[11] = 0xE0;

    DWORD old;
    if (!VirtualProtect(m_trampoline, 64, PAGE_EXECUTE_READWRITE, &old))
        return false;
    VirtualProtect(m_trampoline, 64, old, &old);
    FlushInstructionCache(GetCurrentProcess(), m_trampoline, 64);
    return true;
}
