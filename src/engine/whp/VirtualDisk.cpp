// Credits: Virtual disk (VHDX/VHD) sandbox storage pattern adapted from Sandboxie (https://github.com/sandboxie-plus/Sandboxie)
#include "VirtualDisk.h"
#include "Logger.h"
#include <virtdisk.h>

#pragma comment(lib, "virtdisk.lib")

VirtualDisk* g_virtualDisk = nullptr;

static const GUID VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT_LOCAL =
    { 0xec984aec, 0xa0f9, 0x47e9, { 0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b } };


VirtualDisk::VirtualDisk(Logger* logger)
    : m_logger(logger)
    , m_attached(false)
    , m_diskNumber(0)
    , m_handle(INVALID_HANDLE_VALUE)
{
    memset(&m_cfg, 0, sizeof(m_cfg));
}

VirtualDisk::~VirtualDisk()
{
    Detach();
    Destroy();
    g_virtualDisk = nullptr;
}

bool VirtualDisk::Create(const DiskConfig& cfg)
{
    if (m_handle != INVALID_HANDLE_VALUE) {
        m_logger->Trace(LOG_ERROR, "VirtualDisk: already created");
        return false;
    }

    m_cfg = cfg;

    VIRTUAL_STORAGE_TYPE storageType;
    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
    storageType.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT_LOCAL;
    if (cfg.type == DISK_VHD) {
        storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
    }

    CREATE_VIRTUAL_DISK_PARAMETERS params;
    memset(&params, 0, sizeof(params));
    params.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    params.Version2.MaximumSize = cfg.sizeMb * 1024ULL * 1024ULL;
    params.Version2.BlockSizeInBytes = cfg.blockSizeBytes ? cfg.blockSizeBytes : 0x200000;
    params.Version2.SectorSizeInBytes = 512;
    params.Version2.PhysicalSectorSizeInBytes = 4096;

    HRESULT hr = CreateVirtualDisk(
        &storageType,
        cfg.path,
        VIRTUAL_DISK_ACCESS_NONE,
        NULL,
        cfg.fixedSize ? CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION
                      : CREATE_VIRTUAL_DISK_FLAG_NONE,
        0,
        &params,
        NULL,
        &m_handle);

    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "VirtualDisk: CreateVirtualDisk failed: 0x%08X", hr);
        m_handle = INVALID_HANDLE_VALUE;
        return false;
    }

    m_logger->Trace(LOG_INFO, "VirtualDisk: created %s at %ls (%llu MB %s)",
        cfg.type == DISK_VHDX ? L"VHDX" : L"VHD",
        cfg.path, cfg.sizeMb,
        cfg.fixedSize ? L"fixed" : L"dynamic");

    return true;
}

bool VirtualDisk::Attach(uint32_t* outDiskNumber)
{
    if (m_handle == INVALID_HANDLE_VALUE) {
        m_logger->Trace(LOG_ERROR, "VirtualDisk: no disk created");
        return false;
    }

    ATTACH_VIRTUAL_DISK_PARAMETERS params;
    memset(&params, 0, sizeof(params));
    params.Version = ATTACH_VIRTUAL_DISK_VERSION_1;

    HRESULT hr = AttachVirtualDisk(
        m_handle,
        NULL,
        ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME,
        0,
        &params,
        NULL);

    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "VirtualDisk: AttachVirtualDisk failed: 0x%08X", hr);
        return false;
    }

    m_attached = true;

    if (outDiskNumber) {
        if (!SyncAttach()) return false;
    *outDiskNumber = m_diskNumber;
    }

    m_logger->Trace(LOG_INFO, "VirtualDisk: attached as \\\\.\\PhysicalDrive%u", m_diskNumber);
    return true;
}

bool VirtualDisk::Detach()
{
    if (!m_attached || m_handle == INVALID_HANDLE_VALUE) return true;

    HRESULT hr = DetachVirtualDisk(m_handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_WARNING, "VirtualDisk: DetachVirtualDisk failed: 0x%08X", hr);
    }

    m_attached = false;
    m_diskNumber = 0;
    m_logger->Trace(LOG_INFO, "VirtualDisk: detached");
    return SUCCEEDED(hr);
}

bool VirtualDisk::Destroy()
{
    if (m_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
    return true;
}

bool VirtualDisk::MountVolume(wchar_t driveLetter, const wchar_t* mountPoint)
{
    if (!m_attached) {
        m_logger->Trace(LOG_ERROR, "VirtualDisk: not attached, cannot mount");
        return false;
    }

        wchar_t volumePath[] = L"\\\\.\\PhysicalDrive0";
        volumePath[17] = L'0' + (wchar_t)m_diskNumber;

    HANDLE hVol = CreateFileW(volumePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        m_logger->Trace(LOG_ERROR, "VirtualDisk: cannot open physical drive %u", m_diskNumber);
        return false;
    }

    DWORD bytesReturned = 0;
    STORAGE_DEVICE_NUMBER sdn;
    if (!DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER,
        NULL, 0, &sdn, sizeof(sdn), &bytesReturned, NULL)) {
        CloseHandle(hVol);
        return false;
    }
    CloseHandle(hVol);

    wchar_t mountTarget[64];
    if (mountPoint && mountPoint[0]) {
        wcscpy_s(mountTarget, mountPoint);
    } else {
        wsprintfW(mountTarget, L"%c:\\", driveLetter);
    }

    m_logger->Trace(LOG_INFO, "VirtualDisk: volume ready at %ls", mountTarget);
    return true;
}

bool VirtualDisk::UnmountVolume(wchar_t driveLetter)
{
    (void)driveLetter;
    return true;
}

bool VirtualDisk::SyncAttach()
{
    for (uint32_t i = 0; i < 32; i++) {
        wchar_t path[] = L"\\\\.\\PhysicalDrive0";
        path[17] = L'0' + (wchar_t)i;

        HANDLE h = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;

        DWORD bytesReturned = 0;
        STORAGE_DEVICE_NUMBER sdn;
        BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
            NULL, 0, &sdn, sizeof(sdn), &bytesReturned, NULL);
        CloseHandle(h);

        if (ok && sdn.DeviceType == FILE_DEVICE_VIRTUAL_DISK) {
            m_diskNumber = sdn.DeviceNumber;
            return true;
        }
    }
    return false;
}

bool VirtualDisk::IsVhdSupported()
{
    HINSTANCE h = LoadLibraryW(L"virtdisk.dll");
    if (!h) return false;
    FreeLibrary(h);
    return true;
}
