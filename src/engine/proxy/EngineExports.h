#pragma once
#include <windows.h>
#include <cstdint>

// HwIdEmu exports — called by wbem_proxy to get configurable HWID values
extern "C" {
    uint32_t __stdcall HwIdEmu_GetDiskCount();
    BOOL     __stdcall HwIdEmu_GetDisk(uint32_t index, wchar_t* modelOut, uint32_t* modelLen,
                                       wchar_t* serialOut, uint32_t* serialLen, uint64_t* sizeBytes);
    BOOL     __stdcall HwIdEmu_GetSystemInfo(uint32_t infoType, wchar_t* buffer, uint32_t* bufferLen);
    BOOL     __stdcall HwIdEmu_GetVolumeSerial(uint32_t* serialNumber);
}

// IpcFilter exports — called by ntdll_proxy
extern "C" {
    BOOL __stdcall IpcFilter_ShouldBlockAlpc(const wchar_t* portName);
    BOOL __stdcall IpcFilter_ShouldBlockPipe(const wchar_t* pipeName);
}

// System info types for HwIdEmu_GetSystemInfo
#define HWID_SYSTEM_MANUFACTURER  1
#define HWID_SYSTEM_PRODUCT       2
#define HWID_SYSTEM_SERIAL        3
#define HWID_BIOS_VENDOR          4
#define HWID_BIOS_VERSION         5
#define HWID_BASEBOARD_SERIAL     6
#define HWID_CHASSIS_SERIAL       7
