#pragma once
#include <cstdint>
#include <windows.h>

class InlineHook {
public:
    InlineHook();
    ~InlineHook();

    bool Install(void* target, void* detour);
    void Remove();
    bool IsInstalled() const { return m_installed; }
    void* GetTrampoline() const { return m_trampoline; }

private:
    // The JMP hook written at the target is always 12 bytes:
    //   mov rax, imm64  (48 B8 <8 addr bytes>)  = 10 bytes
    //   jmp rax        (FF E0)                    = 2 bytes
    static const int HOOK_JMP_SIZE = 12;
    // Max bytes to pre-read from target for instruction boundary decoding
    static const int MAX_PRE_READ = 32;
    static const int TRAMPOLINE_SIZE = 64;

    uint8_t m_originalBytes[MAX_PRE_READ];
    int m_actualBytes;  // number of complete instruction bytes covering >= HOOK_JMP_SIZE
    void* m_target;
    void* m_detour;
    void* m_trampoline;
    bool m_installed;

    bool ReadAndDecode();
    bool CreateTrampoline();
    bool WriteHookBytes();
};
