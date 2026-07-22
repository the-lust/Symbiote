// Credits: Unified sandbox coordinator pattern adapted from Sandboxie (https://github.com/sandboxie-plus/Sandboxie)
#include "SandboxFallthrough.h"
#include "VirtualDisk.h"
#include "FileRedirection.h"
#include "RegistryRedirection.h"
#include "IpcFilter.h"

SandboxFallthrough* g_sandboxFallthrough = nullptr;

SandboxFallthrough::SandboxFallthrough(Logger* logger)
    : m_logger(logger)
    , m_initialized(false)
{
    memset(&m_cfg, 0, sizeof(m_cfg));
    wcscpy_s(m_cfg.boxName, L"DefaultBox");
    m_cfg.enableFileRedirection = true;
    m_cfg.enableRegistryRedirection = true;
    m_cfg.enableIpcFiltering = true;
    m_cfg.enableVirtualDisk = false;
    m_cfg.vhdxSizeMb = 4096;
}

SandboxFallthrough::~SandboxFallthrough()
{
    Shutdown();
    g_sandboxFallthrough = nullptr;
}

bool SandboxFallthrough::Initialize(const SandboxConfig& cfg)
{
    m_cfg = cfg;

    if (m_cfg.enableFileRedirection) {
        if (!g_fileRedirection) {
            g_fileRedirection = new FileRedirection(m_logger);
            g_fileRedirection->Initialize(m_cfg.boxName);
        }
        m_logger->Trace(LOG_INFO, "SandboxFallthrough: file redirection enabled for '%ls'", m_cfg.boxName);
    }

    if (m_cfg.enableRegistryRedirection) {
        if (!g_registryRedirection) {
            g_registryRedirection = new RegistryRedirection(m_logger);
            g_registryRedirection->Initialize(m_cfg.boxName);
        }
        m_logger->Trace(LOG_INFO, "SandboxFallthrough: registry redirection enabled for '%ls'", m_cfg.boxName);
    }

    if (m_cfg.enableIpcFiltering) {
        if (!g_ipcFilter) {
            g_ipcFilter = new IpcFilter(m_logger);
            g_ipcFilter->Initialize();
        }
        m_logger->Trace(LOG_INFO, "SandboxFallthrough: IPC filtering enabled");
    }

    if (m_cfg.enableVirtualDisk && m_cfg.vhdxPath[0]) {
        MountDisk();
    }

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "SandboxFallthrough: initialized (file=%d reg=%d ipc=%d vdisk=%d)",
        m_cfg.enableFileRedirection, m_cfg.enableRegistryRedirection,
        m_cfg.enableIpcFiltering, m_cfg.enableVirtualDisk);
    return true;
}

void SandboxFallthrough::Shutdown()
{
    if (m_cfg.enableVirtualDisk) {
        UnmountDisk();
    }

    delete g_ipcFilter; g_ipcFilter = nullptr;
    delete g_registryRedirection; g_registryRedirection = nullptr;
    delete g_fileRedirection; g_fileRedirection = nullptr;
    delete g_virtualDisk; g_virtualDisk = nullptr;

    m_initialized = false;
    m_logger->Trace(LOG_INFO, "SandboxFallthrough: shut down");
}

bool SandboxFallthrough::HandleFileOperation(const wchar_t* path, bool isWrite,
                                              FileRedirection::FileInfo& info)
{
    if (!m_initialized || !g_fileRedirection) return false;
    return g_fileRedirection->Resolve(path, isWrite, info);
}

bool SandboxFallthrough::HandleRegistryOperation(const wchar_t* path, bool isWrite,
                                                  RegistryRedirection::KeyInfo& info)
{
    if (!m_initialized || !g_registryRedirection) return false;
    return g_registryRedirection->Resolve(path, isWrite, info);
}

bool SandboxFallthrough::ShouldBlockIpc(const wchar_t* portName, bool isAlpc)
{
    if (!m_initialized || !g_ipcFilter) return false;
    if (isAlpc) {
        return g_ipcFilter->ShouldBlockAlpc(portName);
    }
    return g_ipcFilter->ShouldBlockPipe(portName);
}

bool SandboxFallthrough::EnsureFileWriteCopy(const wchar_t* path)
{
    if (!m_initialized || !g_fileRedirection) return false;
    return g_fileRedirection->EnsureWriteCopy(path);
}

bool SandboxFallthrough::EnsureRegWriteCopy(const wchar_t* path)
{
    if (!m_initialized || !g_registryRedirection) return false;
    return g_registryRedirection->EnsureWriteCopy(path);
}

bool SandboxFallthrough::MountDisk()
{
    if (!m_cfg.vhdxPath[0] || m_cfg.vhdxSizeMb == 0) return false;

    if (!g_virtualDisk) {
        g_virtualDisk = new VirtualDisk(m_logger);
    }

    VirtualDisk::DiskConfig diskCfg;
    memset(&diskCfg, 0, sizeof(diskCfg));
    wcscpy_s(diskCfg.path, m_cfg.vhdxPath);
    diskCfg.sizeMb = m_cfg.vhdxSizeMb;
    diskCfg.type = VirtualDisk::DISK_VHDX;
    diskCfg.blockSizeBytes = 0x200000;
    diskCfg.fixedSize = false;

    if (!g_virtualDisk->Create(diskCfg)) {
        m_logger->Trace(LOG_ERROR, "SandboxFallthrough: virtual disk creation failed");
        return false;
    }

    uint32_t diskNumber = 0;
    if (!g_virtualDisk->Attach(&diskNumber)) {
        m_logger->Trace(LOG_ERROR, "SandboxFallthrough: virtual disk attach failed");
        return false;
    }

    if (m_cfg.mountPoint[0]) {
        g_virtualDisk->MountVolume(0, m_cfg.mountPoint);
    }

    m_logger->Trace(LOG_INFO, "SandboxFallthrough: VHDX mounted at %ls (%llu MB)",
        m_cfg.vhdxPath, m_cfg.vhdxSizeMb);
    return true;
}

bool SandboxFallthrough::UnmountDisk()
{
    if (!g_virtualDisk) return false;
    g_virtualDisk->Detach();
    g_virtualDisk->Destroy();
    return true;
}
