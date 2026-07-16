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

    void HideThread(uint32_t threadId);
    void UnhideThread(uint32_t threadId);
    void HideProcess(uint32_t processId);
    void UnhideProcess(uint32_t processId);

    bool HandleSystemProcessInformation(uint64_t infoBuffer, uint32_t infoLength, uint32_t* returnLength, uint64_t* result);

    bool IsThreadHidden(uint32_t threadId) const;
    bool IsProcessHidden(uint32_t processId) const;

    void* m_originalCreateToolhelp32Snapshot;
    void* m_originalThread32First;
    void* m_originalThread32Next;

private:
    Logger* m_logger;
    bool m_initialized;
    std::vector<uint32_t> m_hiddenThreads;
    std::vector<uint32_t> m_hiddenProcesses;

    uint8_t m_origBytesSnapshot[12];
    uint8_t m_origBytesFirst[12];
    uint8_t m_origBytesNext[12];
    void* m_trampolineSnapshot;
    void* m_trampolineFirst;
    void* m_trampolineNext;
    bool m_hooksInstalled;

    bool InstallHooks();
    bool RemoveHooks();
};
