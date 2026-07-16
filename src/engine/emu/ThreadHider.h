#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include "Logger.h"

class ThreadHider {
public:
    explicit ThreadHider(Logger* logger);
    ~ThreadHider();

    bool Initialize();
    void Shutdown();

    // Register a thread to hide from enumeration
    void HideThread(uint32_t threadId);
    void UnhideThread(uint32_t threadId);

    // Called from syscall handler for NtQuerySystemInformation
    bool HandleSystemProcessInformation(uint64_t infoBuffer, uint32_t infoLength, uint64_t* returnLength, uint64_t* result);

    // Hook for CreateToolhelp32Snapshot / Thread32First / Thread32Next
    static bool WINAPI HookCreateToolhelp32Snapshot(uint32_t dwFlags, uint32_t th32ProcessID, uint64_t* result);
    static bool WINAPI HookThread32First(void* hSnapshot, void* lpte, uint64_t* result);
    static bool WINAPI HookThread32Next(void* hSnapshot, void* lpte, uint64_t* result);

private:
    Logger* m_logger;
    bool m_initialized;
    std::vector<uint32_t> m_hiddenThreads;
    std::vector<uint32_t> m_hiddenProcesses;

    bool IsThreadHidden(uint32_t threadId) const;
    bool IsProcessHidden(uint32_t processId) const;

    // Inline hooks
    void* m_originalCreateToolhelp32Snapshot;
    void* m_originalThread32First;
    void* m_originalThread32Next;
    uint8_t m_origBytesSnapshot[12];
    uint8_t m_origBytesFirst[12];
    uint8_t m_origBytesNext[12];
    bool m_hooksInstalled;

    bool InstallHooks();
    bool RemoveHooks();
};
