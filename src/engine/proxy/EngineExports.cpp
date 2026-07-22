#include "EngineExports.h"
#include "emu/HwIdEmu.h"
#include "whp/IpcFilter.h"

// ── HwIdEmu exports ──────────────────────────────────────────────────────

#pragma comment(linker, "/EXPORT:HwIdEmu_GetDiskCount=HwIdEmu_GetDiskCount")
uint32_t __stdcall HwIdEmu_GetDiskCount()
{
    if (!g_hwIdEmu || !g_hwIdEmu->IsEnabled()) return 0;
    return g_hwIdEmu->GetDiskCount();
}

#pragma comment(linker, "/EXPORT:HwIdEmu_GetDisk=HwIdEmu_GetDisk")
BOOL __stdcall HwIdEmu_GetDisk(uint32_t index, wchar_t* modelOut, uint32_t* modelLen,
                                wchar_t* serialOut, uint32_t* serialLen, uint64_t* sizeBytes)
{
    if (!g_hwIdEmu || !g_hwIdEmu->IsEnabled()) return FALSE;
    const DiskSpoofInfo* disk = g_hwIdEmu->GetDisk(index);
    if (!disk) return FALSE;

    if (modelOut && modelLen) {
        uint32_t copyLen = (uint32_t)disk->model.length();
        if (copyLen > *modelLen - 1) copyLen = *modelLen - 1;
        wcsncpy_s(modelOut, *modelLen, disk->model.c_str(), copyLen);
        modelOut[copyLen] = L'\0';
        *modelLen = copyLen;
    }
    if (serialOut && serialLen) {
        uint32_t copyLen = (uint32_t)disk->serial.length();
        if (copyLen > *serialLen - 1) copyLen = *serialLen - 1;
        wcsncpy_s(serialOut, *serialLen, disk->serial.c_str(), copyLen);
        serialOut[copyLen] = L'\0';
        *serialLen = copyLen;
    }
    if (sizeBytes) *sizeBytes = disk->sizeBytes;
    return TRUE;
}

#pragma comment(linker, "/EXPORT:HwIdEmu_GetSystemInfo=HwIdEmu_GetSystemInfo")
BOOL __stdcall HwIdEmu_GetSystemInfo(uint32_t infoType, wchar_t* buffer, uint32_t* bufferLen)
{
    if (!g_hwIdEmu || !g_hwIdEmu->IsEnabled()) return FALSE;
    if (!buffer || !bufferLen || *bufferLen < 2) return FALSE;

    const std::wstring* src = nullptr;
    switch (infoType) {
        case HWID_SYSTEM_MANUFACTURER: src = &g_hwIdEmu->GetSystemManufacturer(); break;
        case HWID_SYSTEM_PRODUCT:      src = &g_hwIdEmu->GetSystemProduct();      break;
        case HWID_SYSTEM_SERIAL:       src = &g_hwIdEmu->GetSystemSerial();       break;
        case HWID_BIOS_VENDOR:         src = &g_hwIdEmu->GetBiosVendor();         break;
        default:                   return FALSE;
    }

    uint32_t copyLen = (uint32_t)src->length();
    if (copyLen > *bufferLen - 1) copyLen = *bufferLen - 1;
    wcsncpy_s(buffer, *bufferLen, src->c_str(), copyLen);
    buffer[copyLen] = L'\0';
    *bufferLen = copyLen;
    return TRUE;
}

#pragma comment(linker, "/EXPORT:HwIdEmu_GetVolumeSerial=HwIdEmu_GetVolumeSerial")
BOOL __stdcall HwIdEmu_GetVolumeSerial(uint32_t* serialNumber)
{
    (void)serialNumber;
    // Volume serial is handled inline in FileEmu; this is a placeholder for WMI
    return FALSE;
}

// ── IpcFilter exports ────────────────────────────────────────────────────

#pragma comment(linker, "/EXPORT:IpcFilter_ShouldBlockAlpc=IpcFilter_ShouldBlockAlpc")
BOOL __stdcall IpcFilter_ShouldBlockAlpc(const wchar_t* portName)
{
    if (!g_ipcFilter || !g_ipcFilter->IsInitialized()) return FALSE;
    return g_ipcFilter->ShouldBlockAlpc(portName) ? TRUE : FALSE;
}

#pragma comment(linker, "/EXPORT:IpcFilter_ShouldBlockPipe=IpcFilter_ShouldBlockPipe")
BOOL __stdcall IpcFilter_ShouldBlockPipe(const wchar_t* pipeName)
{
    if (!g_ipcFilter || !g_ipcFilter->IsInitialized()) return FALSE;
    return g_ipcFilter->ShouldBlockPipe(pipeName) ? TRUE : FALSE;
}
