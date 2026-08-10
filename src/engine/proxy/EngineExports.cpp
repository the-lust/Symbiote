#include "EngineExports.h"
#include "emu/HwIdEmu.h"
#include "whp/IpcFilter.h"
#include "whp/RegistryRedirection.h"
#include "whp/FileRedirection.h"
#include "whp/ByovdDriver.h"
#include "proxy/SyscallBridge.h"
#include <cstring>
#include <string>

// ── Function Address Table ────────────────────────────────────────────────
// Sole named export: Engine_GetExport(uint32_t funcId) -> void*
// All other exports are resolved through this function by ID.
// No GetProcAddress-by-name works for the 22+ implementation functions.

constexpr uint32_t kExportTableVersion = 1;

struct ExportEntry {
    uint32_t funcId;
    void*    funcPtr;
};

// Function IDs — must match ProxyExportTable.h's ProxyFuncId enum
enum ExportFuncId : uint32_t {
    EXPORT_HWID_GET_DISK_COUNT        = 1,
    EXPORT_HWID_GET_DISK              = 2,
    EXPORT_HWID_GET_SYSTEM_INFO       = 3,
    EXPORT_HWID_GET_VOLUME_SERIAL     = 4,
    EXPORT_FW_GET_SMBIOS              = 5,
    EXPORT_FW_GET_ACPI                = 6,
    EXPORT_FW_GET_FIRMWARE            = 7,
    EXPORT_FW_SANITIZE_SMBIOS         = 8,
    EXPORT_FW_SANITIZE_ACPI           = 9,
    EXPORT_REG_REDIR_SHOULD_REDIRECT  = 10,
    EXPORT_REG_REDIR_GET_REDIRECTED   = 11,
    EXPORT_IPC_FILTER_BLOCK_ALPC      = 12,
    EXPORT_IPC_FILTER_BLOCK_PIPE      = 13,
    EXPORT_FILE_REDIR_SHOULD_REDIRECT = 14,
    EXPORT_FILE_REDIR_GET_PATH        = 15,
    EXPORT_BYOVD_IS_AVAILABLE         = 16,
    EXPORT_BYOVD_READ_PHYSICAL        = 17,
    EXPORT_BYOVD_WRITE_PHYSICAL       = 18,
    EXPORT_BYOVD_READ_KERNEL          = 19,
    EXPORT_BYOVD_WRITE_KERNEL         = 20,
    EXPORT_ROUTE_SYSCALL              = 21,
    EXPORT_GET_SPOOFED_IDENTITY       = 22,
    EXPORT_COUNT
};

// ── Implementation stubs ──────────────────────────────────────────────────

// HwIdEmu exports
static uint32_t __stdcall _HwIdEmu_GetDiskCount()
{
    if (!g_hwIdEmu || !g_hwIdEmu->IsEnabled()) return 0;
    return g_hwIdEmu->GetDiskCount();
}

static BOOL __stdcall _HwIdEmu_GetDisk(uint32_t index, wchar_t* modelOut, uint32_t* modelLen,
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

static BOOL __stdcall _HwIdEmu_GetSystemInfo(uint32_t infoType, wchar_t* buffer, uint32_t* bufferLen)
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

static BOOL __stdcall _HwIdEmu_GetVolumeSerial(uint32_t* serialNumber)
{
    (void)serialNumber;
    return FALSE;
}

// Firmware table exports
static BOOL __stdcall _FwTable_GetSmbios(uint32_t* bufferSize, uint8_t* buffer)
{
    if (!bufferSize) return FALSE;

    DWORD realSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (realSize == 0) { *bufferSize = 0; return FALSE; }

    if (!buffer) { *bufferSize = realSize; return TRUE; }
    if (*bufferSize < realSize) return FALSE;

    DWORD readSize = GetSystemFirmwareTable('RSMB', 0, buffer, *bufferSize);
    if (readSize == 0) return FALSE;
    *bufferSize = readSize;
    return TRUE;
}

static BOOL __stdcall _FwTable_GetAcpi(const char* tableSignature, uint32_t* bufferSize, uint8_t* buffer)
{
    if (!tableSignature || !bufferSize) return FALSE;
    DWORD sig = 0;
    memcpy(&sig, tableSignature, 4);

    DWORD realSize = GetSystemFirmwareTable('ACPI', sig, NULL, 0);
    if (realSize == 0) { *bufferSize = 0; return FALSE; }

    if (!buffer) { *bufferSize = realSize; return TRUE; }
    if (*bufferSize < realSize) return FALSE;

    DWORD readSize = GetSystemFirmwareTable('ACPI', sig, buffer, *bufferSize);
    if (readSize == 0) return FALSE;
    *bufferSize = readSize;
    return TRUE;
}

static BOOL __stdcall _FwTable_GetFirmware(uint32_t* bufferSize, uint8_t* buffer)
{
    if (!bufferSize) return FALSE;
    DWORD realSize = GetSystemFirmwareTable('FIRM', 0, NULL, 0);
    if (realSize == 0) { *bufferSize = 0; return FALSE; }

    if (!buffer) { *bufferSize = realSize; return TRUE; }
    if (*bufferSize < realSize) return FALSE;

    DWORD readSize = GetSystemFirmwareTable('FIRM', 0, buffer, *bufferSize);
    if (readSize == 0) return FALSE;
    *bufferSize = readSize;
    return TRUE;
}

static BOOL __stdcall _FwTable_SanitizeSmbios(uint8_t* smbiosData, uint32_t dataSize)
{
    if (!smbiosData || dataSize < 32) return FALSE;
    if (memcmp(smbiosData, "_SM_", 4) != 0 && memcmp(smbiosData, "_SM3_", 5) != 0) return FALSE;

    static const char* kVmStrings[] = {
        "VMware", "VMWARE", "VirtualBox", "VBOX", "vbox",
        "QEMU", "Bochs", "bochs", "Oracle", "Innotek",
        "Parallels", "prl_", "KVM", "kvm", nullptr
    };

    uint32_t sanitized = 0;
    for (uint32_t i = 0; i + 4 < dataSize; i++) {
        for (int s = 0; kVmStrings[s]; s++) {
            size_t slen = strlen(kVmStrings[s]);
            if (i + slen <= dataSize && memcmp(&smbiosData[i], kVmStrings[s], slen) == 0) {
                memset(&smbiosData[i], 0, slen);
                sanitized++;
                i += (uint32_t)slen - 1;
                break;
            }
        }
    }
    return sanitized > 0 || TRUE;
}

static BOOL __stdcall _FwTable_SanitizeAcpi(uint8_t* acpiData, uint32_t dataSize)
{
    if (!acpiData || dataSize < sizeof(uint64_t)) return FALSE;
    static const char* kVmOemIds[] = { "VBOX__", "VMW__", "BXPC", "BOCHS", "QEMU", nullptr };
    for (int s = 0; kVmOemIds[s]; s++) {
        size_t slen = strlen(kVmOemIds[s]);
        if (dataSize >= 10 + slen && memcmp(acpiData + 10, kVmOemIds[s], slen) == 0)
            memset(acpiData + 10, ' ', slen);
        if (dataSize >= 16 + slen && memcmp(acpiData + 16, kVmOemIds[s], slen) == 0)
            memset(acpiData + 16, ' ', slen);
    }
    return TRUE;
}

// RegistryRedirection exports
static BOOL __stdcall _RegRedir_ShouldRedirect(const wchar_t* keyPath)
{
    if (!g_registryRedirection || !g_registryRedirection->IsInitialized()) return FALSE;
    return g_registryRedirection->ShouldRedirect(keyPath) ? TRUE : FALSE;
}

static BOOL __stdcall _RegRedir_GetRedirectedValue(const wchar_t* keyPath, const wchar_t* valueName,
                                                     uint8_t* data, uint32_t* dataSize, uint32_t* type)
{
    if (!g_registryRedirection || !g_registryRedirection->IsInitialized()) return FALSE;
    RegistryRedirection::RedirectedValue value;
    if (!g_registryRedirection->GetRedirectedValue(keyPath, valueName, value))
        return FALSE;
    if (data && dataSize) {
        uint32_t copySize = (uint32_t)value.data.size();
        if (copySize > *dataSize) copySize = *dataSize;
        memcpy(data, value.data.data(), copySize);
        *dataSize = copySize;
    }
    if (type) *type = value.type;
    return TRUE;
}

// IpcFilter exports
static BOOL __stdcall _IpcFilter_ShouldBlockAlpc(const wchar_t* portName)
{
    if (!g_ipcFilter || !g_ipcFilter->IsInitialized()) return FALSE;
    return g_ipcFilter->ShouldBlockAlpc(portName) ? TRUE : FALSE;
}

static BOOL __stdcall _IpcFilter_ShouldBlockPipe(const wchar_t* pipeName)
{
    if (!g_ipcFilter || !g_ipcFilter->IsInitialized()) return FALSE;
    return g_ipcFilter->ShouldBlockPipe(pipeName) ? TRUE : FALSE;
}

// FileRedirection exports
static BOOL __stdcall _FileRedir_ShouldRedirect(const wchar_t* path)
{
    if (!g_fileRedirection || !g_fileRedirection->IsInitialized()) return FALSE;
    FileRedirection::FileInfo info;
    if (g_fileRedirection->Resolve(path, false, info))
        return info.isRedirected ? TRUE : FALSE;
    return FALSE;
}

static BOOL __stdcall _FileRedir_GetRedirectedPath(const wchar_t* path, wchar_t* outPath,
                                                     uint32_t* pathLen, BOOL isWrite)
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

// ByovdDriver exports
static BOOL __stdcall _Byovd_IsAvailable()
{
    return (g_byovdDriver && g_byovdDriver->IsAvailable()) ? TRUE : FALSE;
}

static BOOL __stdcall _Byovd_ReadPhysicalMemory(uint64_t physicalAddr, uint8_t* buffer, uint32_t size)
{
    if (!g_byovdDriver || !g_byovdDriver->IsAvailable()) return FALSE;
    return g_byovdDriver->ReadPhysicalMemory(physicalAddr, buffer, size) ? TRUE : FALSE;
}

static BOOL __stdcall _Byovd_WritePhysicalMemory(uint64_t physicalAddr, const uint8_t* buffer, uint32_t size)
{
    if (!g_byovdDriver || !g_byovdDriver->IsAvailable()) return FALSE;
    return g_byovdDriver->WritePhysicalMemory(physicalAddr, buffer, size) ? TRUE : FALSE;
}

static BOOL __stdcall _Byovd_ReadKernelMemory(uint64_t kernelAddr, uint8_t* buffer, uint32_t size)
{
    if (!g_byovdDriver || !g_byovdDriver->IsAvailable()) return FALSE;
    return g_byovdDriver->ReadKernelMemory(kernelAddr, buffer, size) ? TRUE : FALSE;
}

static BOOL __stdcall _Byovd_WriteKernelMemory(uint64_t kernelAddr, const uint8_t* buffer, uint32_t size)
{
    if (!g_byovdDriver || !g_byovdDriver->IsAvailable()) return FALSE;
    return g_byovdDriver->WriteKernelMemory(kernelAddr, buffer, size) ? TRUE : FALSE;
}

// ── Export table builder ──────────────────────────────────────────────────
// Called at engine init: builds the function address table and stores it
// at the address the launcher expects (from shared memory).

static ExportEntry g_exportTable[EXPORT_COUNT + 1] = {
    {0, nullptr}, // reserved
    {EXPORT_HWID_GET_DISK_COUNT,            (void*)_HwIdEmu_GetDiskCount},
    {EXPORT_HWID_GET_DISK,                  (void*)_HwIdEmu_GetDisk},
    {EXPORT_HWID_GET_SYSTEM_INFO,           (void*)_HwIdEmu_GetSystemInfo},
    {EXPORT_HWID_GET_VOLUME_SERIAL,         (void*)_HwIdEmu_GetVolumeSerial},
    {EXPORT_FW_GET_SMBIOS,                  (void*)_FwTable_GetSmbios},
    {EXPORT_FW_GET_ACPI,                    (void*)_FwTable_GetAcpi},
    {EXPORT_FW_GET_FIRMWARE,                (void*)_FwTable_GetFirmware},
    {EXPORT_FW_SANITIZE_SMBIOS,             (void*)_FwTable_SanitizeSmbios},
    {EXPORT_FW_SANITIZE_ACPI,               (void*)_FwTable_SanitizeAcpi},
    {EXPORT_REG_REDIR_SHOULD_REDIRECT,      (void*)_RegRedir_ShouldRedirect},
    {EXPORT_REG_REDIR_GET_REDIRECTED,       (void*)_RegRedir_GetRedirectedValue},
    {EXPORT_IPC_FILTER_BLOCK_ALPC,          (void*)_IpcFilter_ShouldBlockAlpc},
    {EXPORT_IPC_FILTER_BLOCK_PIPE,          (void*)_IpcFilter_ShouldBlockPipe},
    {EXPORT_FILE_REDIR_SHOULD_REDIRECT,     (void*)_FileRedir_ShouldRedirect},
    {EXPORT_FILE_REDIR_GET_PATH,            (void*)_FileRedir_GetRedirectedPath},
    {EXPORT_BYOVD_IS_AVAILABLE,             (void*)_Byovd_IsAvailable},
    {EXPORT_BYOVD_READ_PHYSICAL,            (void*)_Byovd_ReadPhysicalMemory},
    {EXPORT_BYOVD_WRITE_PHYSICAL,           (void*)_Byovd_WritePhysicalMemory},
    {EXPORT_BYOVD_READ_KERNEL,              (void*)_Byovd_ReadKernelMemory},
    {EXPORT_BYOVD_WRITE_KERNEL,             (void*)_Byovd_WriteKernelMemory},
    {EXPORT_ROUTE_SYSCALL,                  (void*)RouteSyscall},
    {EXPORT_GET_SPOOFED_IDENTITY,           nullptr},  // placeholder
};

// Export table header: version + count + function table address
// Written to a known shared memory region for the consumer
struct ExportTableHeader {
    uint32_t    version;
    uint32_t    entryCount;
    ExportEntry entries[EXPORT_COUNT + 1];
};

static ExportTableHeader g_exportHeader;

// Called by engine init — fills the export table at shared memory address
void Engine_BuildExportTable(void* sharedMemAddr)
{
    g_exportHeader.version = kExportTableVersion;
    g_exportHeader.entryCount = EXPORT_COUNT + 1;
    memcpy(g_exportHeader.entries, g_exportTable, sizeof(g_exportTable));

    if (sharedMemAddr) {
        memcpy(sharedMemAddr, &g_exportHeader, sizeof(ExportTableHeader));
    }
}

// ── Sole named export: Engine_GetExport ──────────────────────────────────
// All other functions are resolved through this by ID.
#pragma comment(linker, "/EXPORT:Engine_GetExport=Engine_GetExport")

// Lookup a function by ID (used by proxy DLLs)
void* Engine_GetExport(uint32_t funcId)
{
    for (uint32_t i = 0; i <= EXPORT_COUNT; i++) {
        if (g_exportTable[i].funcId == funcId)
            return g_exportTable[i].funcPtr;
    }
    return nullptr;
}