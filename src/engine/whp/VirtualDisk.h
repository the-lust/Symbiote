#pragma once
#include <windows.h>
#include <cstdint>

class Logger;

class VirtualDisk {
public:
    explicit VirtualDisk(Logger* logger);
    ~VirtualDisk();

    enum DiskType : uint32_t {
        DISK_VHDX = 0,
        DISK_VHD  = 1,
    };

    struct DiskConfig {
        uint64_t  sizeMb;
        DiskType  type;
        uint32_t  blockSizeBytes;
        bool      fixedSize;
        wchar_t   path[MAX_PATH];
    };

    bool Create(const DiskConfig& cfg);
    bool Attach(uint32_t* outDiskNumber);
    bool Detach();
    bool Destroy();
    bool IsAttached() const { return m_attached; }

    bool MountVolume(wchar_t driveLetter, const wchar_t* mountPoint);
    bool UnmountVolume(wchar_t driveLetter);

    uint64_t GetSizeMb() const { return m_cfg.sizeMb; }
    const wchar_t* GetPath() const { return m_cfg.path; }
    uint32_t GetDiskNumber() const { return m_diskNumber; }

    static bool IsVhdSupported();

private:
    Logger* m_logger;
    DiskConfig m_cfg;
    bool m_attached;
    uint32_t m_diskNumber;
    HANDLE m_handle;

    bool SyncAttach();
};

extern VirtualDisk* g_virtualDisk;
