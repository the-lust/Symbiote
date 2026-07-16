#pragma once
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include "Logger.h"

#pragma comment(lib, "psapi.lib")

class StackSpoofer {
public:
    explicit StackSpoofer(Logger* logger);
    ~StackSpoofer();

    bool Initialize();
    void Shutdown();

    // Replace the return address on the stack with a ret sled address
    void SpoofReturnAddress(void* context);

    // Restore the original return address after the syscall returns
    bool RestoreReturnAddress(void* context, uint64_t currentRip);

    // Read the current return address from the stack
    uint64_t GetReturnAddress(uint64_t rsp);

private:
    Logger* m_logger;
    bool m_initialized;
    uint64_t m_retSledAddr;
    uint32_t m_retSledSize;

    static const uint32_t MAX_SAVED_FRAMES = 64;
    uint64_t m_savedRetAddr[MAX_SAVED_FRAMES];

    bool FindRetSled();
};
