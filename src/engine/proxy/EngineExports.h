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

// FirmwareTableSpoofer exports — SMBIOS/ACPI table sanitization
extern "C" {
    BOOL __stdcall FwTable_GetSmbios(uint32_t* bufferSize, uint8_t* buffer);
    BOOL __stdcall FwTable_GetAcpi(const char* tableSignature, uint32_t* bufferSize, uint8_t* buffer);
    BOOL __stdcall FwTable_GetFirmware(uint32_t* bufferSize, uint8_t* buffer);
    BOOL __stdcall FwTable_SanitizeSmbios(uint8_t* smbiosData, uint32_t dataSize);
    BOOL __stdcall FwTable_SanitizeAcpi(uint8_t* acpiData, uint32_t dataSize);
}

// RegistryRedirection exports — called by ntdll_proxy for registry COW
extern "C" {
    BOOL __stdcall RegRedir_ShouldRedirect(const wchar_t* keyPath);
    BOOL __stdcall RegRedir_GetRedirectedValue(const wchar_t* keyPath, const wchar_t* valueName,
                                                uint8_t* data, uint32_t* dataSize, uint32_t* type);
}

// FileRedirection exports — called by ntdll_proxy for file COW
extern "C" {
    BOOL __stdcall FileRedir_ShouldRedirect(const wchar_t* path);
    BOOL __stdcall FileRedir_GetRedirectedPath(const wchar_t* path, wchar_t* outPath, uint32_t* pathLen, BOOL isWrite);
}

// ByovdDriver exports — kernel memory R/W via vulnerable signed driver
extern "C" {
    BOOL __stdcall Byovd_IsAvailable();
    BOOL __stdcall Byovd_ReadPhysicalMemory(uint64_t physicalAddr, uint8_t* buffer, uint32_t size);
    BOOL __stdcall Byovd_WritePhysicalMemory(uint64_t physicalAddr, const uint8_t* buffer, uint32_t size);
    BOOL __stdcall Byovd_ReadKernelMemory(uint64_t kernelAddr, uint8_t* buffer, uint32_t size);
    BOOL __stdcall Byovd_WriteKernelMemory(uint64_t kernelAddr, const uint8_t* buffer, uint32_t size);
}

// System info types for HwIdEmu_GetSystemInfo
#define HWID_SYSTEM_MANUFACTURER  1
#define HWID_SYSTEM_PRODUCT       2
#define HWID_SYSTEM_SERIAL        3
#define HWID_BIOS_VENDOR          4
#define HWID_BIOS_VERSION         5
#define HWID_BASEBOARD_SERIAL     6
#define HWID_CHASSIS_SERIAL       7

// Function address table API (replaces named exports)
extern "C" {
    // Build the export table at the given shared memory address (called at engine init)
    void Engine_BuildExportTable(void* sharedMemAddr);
    // Look up a function by its ID (used by proxy DLLs)
    void* Engine_GetExport(uint32_t funcId);
}
