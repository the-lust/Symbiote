#include "EngineExports.h"
#include "emu/HwIdEmu.h"
#include "whp/IpcFilter.h"
#include "whp/RegistryRedirection.h"
#include "whp/FileRedirection.h"
#include "whp/ByovdDriver.h"
#include <cstring>
#include <string>

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

    if (modelOut && modelLen && *modelLen >= 1) {
        uint32_t copyLen = (uint32_t)disk->model.length();
        if (copyLen > *modelLen - 1) copyLen = *modelLen - 1;
        wcsncpy_s(modelOut, *modelLen, disk->model.c_str(), copyLen);
        modelOut[copyLen] = L'\0';
        *modelLen = copyLen;
    }
    if (serialOut && serialLen && *serialLen >= 1) {
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
        case HWID_BIOS_VERSION:        src = &g_hwIdEmu->GetBiosVersion();        break;
        case HWID_BASEBOARD_SERIAL:    src = &g_hwIdEmu->GetBaseboardSerial();    break;
        case HWID_CHASSIS_SERIAL:      src = &g_hwIdEmu->GetChassisSerial();      break;
        default:                       return FALSE;
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
    return FALSE;
}

// ── FirmwareTableSpoofer exports ─────────────────────────────────────────

#pragma comment(linker, "/EXPORT:FwTable_GetSmbios=FwTable_GetSmbios")
BOOL __stdcall FwTable_GetSmbios(uint32_t* bufferSize, uint8_t* buffer)
{
    if (!bufferSize) return FALSE;

    DWORD realSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (realSize == 0) {
        *bufferSize = 0;
        return FALSE;
    }

    if (!buffer) {
        *bufferSize = realSize;
        return TRUE;
    }

    if (*bufferSize < realSize) return FALSE;

    DWORD readSize = GetSystemFirmwareTable('RSMB', 0, buffer, *bufferSize);
    if (readSize == 0) return FALSE;

    *bufferSize = readSize;
    return TRUE;
}

#pragma comment(linker, "/EXPORT:FwTable_GetAcpi=FwTable_GetAcpi")
BOOL __stdcall FwTable_GetAcpi(const char* tableSignature, uint32_t* bufferSize, uint8_t* buffer)
{
    if (!tableSignature || !bufferSize) return FALSE;

    DWORD sig = 0;
    memcpy(&sig, tableSignature, 4);

    DWORD realSize = GetSystemFirmwareTable('ACPI', sig, NULL, 0);
    if (realSize == 0) {
        *bufferSize = 0;
        return FALSE;
    }

    if (!buffer) {
        *bufferSize = realSize;
        return TRUE;
    }

    if (*bufferSize < realSize) return FALSE;

    DWORD readSize = GetSystemFirmwareTable('ACPI', sig, buffer, *bufferSize);
    if (readSize == 0) return FALSE;

    *bufferSize = readSize;
    return TRUE;
}

#pragma comment(linker, "/EXPORT:FwTable_GetFirmware=FwTable_GetFirmware")
BOOL __stdcall FwTable_GetFirmware(uint32_t* bufferSize, uint8_t* buffer)
{
    if (!bufferSize) return FALSE;

    DWORD realSize = GetSystemFirmwareTable('FIRM', 0, NULL, 0);
    if (realSize == 0) {
        *bufferSize = 0;
        return FALSE;
    }

    if (!buffer) {
        *bufferSize = realSize;
        return TRUE;
    }

    if (*bufferSize < realSize) return FALSE;

    DWORD readSize = GetSystemFirmwareTable('FIRM', 0, buffer, *bufferSize);
    if (readSize == 0) return FALSE;

    *bufferSize = readSize;
    return TRUE;
}

#pragma comment(linker, "/EXPORT:FwTable_SanitizeSmbios=FwTable_SanitizeSmbios")
BOOL __stdcall FwTable_SanitizeSmbios(uint8_t* smbiosData, uint32_t dataSize)
{
    if (!smbiosData || dataSize < 32) return FALSE;

    if (memcmp(smbiosData, "_SM_", 4) != 0 && memcmp(smbiosData, "_SM3_", 5) != 0) {
        return FALSE;
    }

    static const char* kVmStrings[] = {
        "VMware", "VMWARE", "VirtualBox", "VBOX", "vbox",
        "QEMU", "Bochs", "bochs", "Oracle", "Innotek",
        "Parallels", "prl_", "KVM", "kvm",
        nullptr
    };

    uint32_t sanitized = 0;
    for (uint32_t i = 0; i + 4 < dataSize; i++) {
        for (int s = 0; kVmStrings[s]; s++) {
            size_t slen = strlen(kVmStrings[s]);
            if (i + slen <= dataSize) {
                if (memcmp(&smbiosData[i], kVmStrings[s], slen) == 0) {
                    memset(&smbiosData[i], 0, slen);
                    sanitized++;
                    i += (uint32_t)slen - 1;
                    break;
                }
            }
        }
    }

    return sanitized > 0 || TRUE;
}

#pragma comment(linker, "/EXPORT:FwTable_SanitizeAcpi=FwTable_SanitizeAcpi")
BOOL __stdcall FwTable_SanitizeAcpi(uint8_t* acpiData, uint32_t dataSize)
{
    if (!acpiData || dataSize < sizeof(uint64_t)) return FALSE;

    static const char* kVmOemIds[] = {
        "VBOX__", "VMW__", "BXPC", "BOCHS", "QEMU",
        nullptr
    };

    for (int s = 0; kVmOemIds[s]; s++) {
        size_t slen = strlen(kVmOemIds[s]);
        if (dataSize >= 10 + slen) {
            if (memcmp(acpiData + 10, kVmOemIds[s], slen) == 0) {
                memset(acpiData + 10, ' ', slen);
            }
        }
        if (dataSize >= 16 + slen) {
            if (memcmp(acpiData + 16, kVmOemIds[s], slen) == 0) {
                memset(acpiData + 16, ' ', slen);
            }
        }
    }

    return TRUE;
}

// ── RegistryRedirection exports ───────────────────────────────────────────

#pragma comment(linker, "/EXPORT:RegRedir_ShouldRedirect=RegRedir_ShouldRedirect")
BOOL __stdcall RegRedir_ShouldRedirect(const wchar_t* keyPath)
{
    if (!g_registryRedirection || !g_registryRedirection->IsInitialized()) return FALSE;
    return g_registryRedirection->ShouldRedirect(keyPath) ? TRUE : FALSE;
}

#pragma comment(linker, "/EXPORT:RegRedir_GetRedirectedValue=RegRedir_GetRedirectedValue")
BOOL __stdcall RegRedir_GetRedirectedValue(const wchar_t* keyPath, const wchar_t* valueName,
                                            uint8_t* data, uint32_t* dataSize, uint32_t* type)
{
    if (!g_registryRedirection || !g_registryRedirection->IsInitialized()) return FALSE;
    if (!keyPath || !valueName) return FALSE;

    RegistryRedirection::RedirectedValue value;
    if (!g_registryRedirection->GetRedirectedValue(keyPath, valueName, value)) {
        return FALSE;
    }

    if (data && dataSize) {
        uint32_t copySize = (uint32_t)value.data.size();
        if (copySize > *dataSize) copySize = *dataSize;
        memcpy(data, value.data.data(), copySize);
        *dataSize = copySize;
    }

    if (type) *type = value.type;
    return TRUE;
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

// ── FileRedirection exports ───────────────────────────────────────────────

#pragma comment(linker, "/EXPORT:FileRedir_ShouldRedirect=FileRedir_ShouldRedirect")
BOOL __stdcall FileRedir_ShouldRedirect(const wchar_t* path)
{
    if (!g_fileRedirection || !g_fileRedirection->IsInitialized()) return FALSE;
    FileRedirection::FileInfo info;
    if (g_fileRedirection->Resolve(path, false, info)) {
        return info.isRedirected ? TRUE : FALSE;
    }
    return FALSE;
}

#pragma comment(linker, "/EXPORT:FileRedir_GetRedirectedPath=FileRedir_GetRedirectedPath")
BOOL __stdcall FileRedir_GetRedirectedPath(const wchar_t* path, wchar_t* outPath, uint32_t* pathLen, BOOL isWrite)
{
    if (!g_fileRedirection || !g_fileRedirection->IsInitialized()) return FALSE;
    if (!path || !outPath || !pathLen || *pathLen < 1) return FALSE;

    std::wstring boxPath;
    if (g_fileRedirection->GetRedirectedPath(path, boxPath, isWrite != FALSE)) {
        uint32_t copyLen = (uint32_t)boxPath.length();
        if (copyLen > *pathLen - 1) copyLen = *pathLen - 1;
        wcsncpy_s(outPath, *pathLen, boxPath.c_str(), copyLen);
        outPath[copyLen] = L'\0';
        *pathLen = copyLen;
        return TRUE;
    }
    return FALSE;
}

// ── ByovdDriver exports ───────────────────────────────────────────────────

#pragma comment(linker, "/EXPORT:Byovd_IsAvailable=Byovd_IsAvailable")
BOOL __stdcall Byovd_IsAvailable()
{
    return (g_byovdDriver && g_byovdDriver->IsAvailable()) ? TRUE : FALSE;
}

#pragma comment(linker, "/EXPORT:Byovd_ReadPhysicalMemory=Byovd_ReadPhysicalMemory")
BOOL __stdcall Byovd_ReadPhysicalMemory(uint64_t physicalAddr, uint8_t* buffer, uint32_t size)
{
    if (!g_byovdDriver || !g_byovdDriver->IsAvailable()) return FALSE;
    return g_byovdDriver->ReadPhysicalMemory(physicalAddr, buffer, size) ? TRUE : FALSE;
}

#pragma comment(linker, "/EXPORT:Byovd_WritePhysicalMemory=Byovd_WritePhysicalMemory")
BOOL __stdcall Byovd_WritePhysicalMemory(uint64_t physicalAddr, const uint8_t* buffer, uint32_t size)
{
    if (!g_byovdDriver || !g_byovdDriver->IsAvailable()) return FALSE;
    return g_byovdDriver->WritePhysicalMemory(physicalAddr, buffer, size) ? TRUE : FALSE;
}

#pragma comment(linker, "/EXPORT:Byovd_ReadKernelMemory=Byovd_ReadKernelMemory")
BOOL __stdcall Byovd_ReadKernelMemory(uint64_t kernelAddr, uint8_t* buffer, uint32_t size)
{
    if (!g_byovdDriver || !g_byovdDriver->IsAvailable()) return FALSE;
    return g_byovdDriver->ReadKernelMemory(kernelAddr, buffer, size) ? TRUE : FALSE;
}

#pragma comment(linker, "/EXPORT:Byovd_WriteKernelMemory=Byovd_WriteKernelMemory")
BOOL __stdcall Byovd_WriteKernelMemory(uint64_t kernelAddr, const uint8_t* buffer, uint32_t size)
{
    if (!g_byovdDriver || !g_byovdDriver->IsAvailable()) return FALSE;
    return g_byovdDriver->WriteKernelMemory(kernelAddr, buffer, size) ? TRUE : FALSE;
}
