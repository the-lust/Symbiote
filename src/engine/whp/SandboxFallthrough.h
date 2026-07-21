#pragma once
#include <windows.h>
#include "Logger.h"
#include "FileRedirection.h"
#include "RegistryRedirection.h"

class VirtualDisk;
class IpcFilter;

class SandboxFallthrough {
public:
    explicit SandboxFallthrough(Logger* logger);
    ~SandboxFallthrough();

    struct SandboxConfig {
        wchar_t boxName[64];
        wchar_t vhdxPath[MAX_PATH];
        uint64_t vhdxSizeMb;
        bool     enableFileRedirection;
        bool     enableRegistryRedirection;
        bool     enableIpcFiltering;
        bool     enableVirtualDisk;
        wchar_t  mountPoint[MAX_PATH];
    };

    bool Initialize(const SandboxConfig& cfg);
    void Shutdown();

    // File fallthrough: when a file syscall can't be emulated
    bool HandleFileOperation(const wchar_t* path, bool isWrite,
                             FileRedirection::FileInfo& info);

    // Registry fallthrough: when a registry syscall can't be emulated
    bool HandleRegistryOperation(const wchar_t* path, bool isWrite,
                                 RegistryRedirection::KeyInfo& info);

    // IPC check: should this ALPC/pipe connection be blocked?
    bool ShouldBlockIpc(const wchar_t* portName, bool isAlpc);

    // Ensure write copy for a file before modification
    bool EnsureFileWriteCopy(const wchar_t* path);

    // Ensure write copy for a registry key before modification
    bool EnsureRegWriteCopy(const wchar_t* path);

    // Mount/unmount virtual disk
    bool MountDisk();
    bool UnmountDisk();

    bool IsInitialized() const { return m_initialized; }
    const SandboxConfig& GetConfig() const { return m_cfg; }

private:
    Logger* m_logger;
    bool m_initialized;
    SandboxConfig m_cfg;
};

extern SandboxFallthrough* g_sandboxFallthrough;
