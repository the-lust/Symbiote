#pragma once
#include <cstdint>
#include <windows.h>

// Inline hook for x64:
// Overwrites the first 12+ bytes of a target function with
// a JMP to our detour. Provides a trampoline for passthrough.
class InlineHook {
public:
    InlineHook();
    ~InlineHook();

    bool Install(void* target, void* detour);
    void Remove();
    bool IsInstalled() const { return m_installed; }
    void* GetTrampoline() const { return m_trampoline; }

private:
    static const int HOOK_SIZE = 16;

    uint8_t m_originalBytes[HOOK_SIZE];
    void* m_target;
    void* m_detour;
    void* m_trampoline;
    bool m_installed;

    bool WriteHookBytes();
    bool CreateTrampoline();
};
