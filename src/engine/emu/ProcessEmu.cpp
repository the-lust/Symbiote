#define WIN32_NO_STATUS
#include "ProcessEmu.h"
#include "ConfigParser.h"
#include <windows.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <iomanip>

#ifndef _UNICODE_STRING_DEFINED
struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
};
typedef struct _UNICODE_STRING UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
#define _UNICODE_STRING_DEFINED
#endif

typedef struct _PEB* PPEB;
typedef LONG KPRIORITY;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    DWORD PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemKernelDebuggerInformation = 35,
    SystemFirmwareTableInformation = 75,
    SystemCodeIntegrityInformation = 103,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

ProcessEmu::ProcessEmu(Logger* logger, ModuleCloak* cloak)
    : m_logger(logger), m_moduleCloak(cloak),
      m_processorCount(8), m_affinityMask(0xFF),
      m_physicalPageCount(0x400000), m_timerResolution(0x00030D40),
      m_biosVendor("American Megatrends Inc."),
      m_biosVersion("F20"), m_biosDate("04/15/2020"),
      m_manufacturer("Gigabyte Technology Co., Ltd."),
      m_productName("Z490 AORUS PRO AX"),
      m_productVersion("1.0"), m_serialNumber("SN0123456789"),
      m_chassisSerial("CH0123456789"), m_baseboardSerial("MB0123456789"),
      m_sku("Default_String"), m_family("Z490")
{
}

void ProcessEmu::LoadFromConfig(ConfigParser* config)
{
    if (!config) return;

    m_processorCount = (uint32_t)config->GetUint64("system", "processor_count", m_processorCount);
    m_affinityMask = config->GetUint64("system", "processor_affinity_mask", m_affinityMask);
    m_physicalPageCount = (uint32_t)config->GetUint64("system", "physical_page_count", m_physicalPageCount);
    m_timerResolution = (uint32_t)config->GetUint64("system", "timer_resolution", m_timerResolution);

    m_manufacturer = config->GetString("hardware", "manufacturer", m_manufacturer);
    m_productName = config->GetString("hardware", "product", m_productName);
    m_productVersion = config->GetString("hardware", "version", m_productVersion);
    m_serialNumber = config->GetString("hardware", "serial", m_serialNumber);
    m_biosVendor = config->GetString("hardware", "bios_vendor", m_biosVendor);
    m_biosVersion = config->GetString("hardware", "bios_version", m_biosVersion);
    m_biosDate = config->GetString("hardware", "bios_date", m_biosDate);
    m_chassisSerial = config->GetString("hardware", "chassis_serial", m_chassisSerial);
    m_baseboardSerial = config->GetString("hardware", "baseboard_serial", m_baseboardSerial);
}

void ProcessEmu::BuildVirtualProcessList()
{
    m_virtualProcessList.clear();

    auto addProc = [&](uint64_t pid, uint64_t ppid, const wchar_t* name,
                        uint32_t session, uint32_t handles, uint32_t threads) {
        VirtualProcessInfo info;
        info.uniqueProcessId = pid;
        info.parentProcessId = ppid;
        info.imageName = name;
        info.sessionId = session;
        info.handleCount = handles;
        info.threadCount = threads;
        m_virtualProcessList.push_back(info);
    };

    addProc(0, 0, L"System Idle Process", 0, 0, 4);
    addProc(4, 0, L"System", 0, 1200, 180);
    addProc(0x1E4, 4, L"smss.exe", 0, 45, 6);
    addProc(0x2A0, 0x1E4, L"csrss.exe", 0, 420, 11);
    addProc(0x2C0, 0x1E4, L"csrss.exe", 1, 340, 10);
    addProc(0x2D4, 4, L"wininit.exe", 0, 120, 4);
    addProc(0x2E4, 4, L"winlogon.exe", 1, 180, 5);
    addProc(0x2F0, 0x2D4, L"services.exe", 0, 480, 8);
    addProc(0x2FC, 0x2D4, L"lsass.exe", 0, 920, 14);
    addProc(0x308, 0x2D4, L"svchost.exe", 0, 180, 5);
    addProc(0x31C, 0x2F0, L"svchost.exe", 0, 340, 12);
    addProc(0x338, 0x2F0, L"svchost.exe", 0, 290, 8);
    addProc(0x34C, 0x2F0, L"svchost.exe", 0, 620, 22);
    addProc(0x360, 0x2F0, L"svchost.exe", 0, 410, 16);
    addProc(0x374, 0x2F0, L"svchost.exe", 0, 300, 10);
    addProc(0x388, 0x2F0, L"svchost.exe", 0, 250, 7);
    addProc(0x39C, 0x2F0, L"svchost.exe", 0, 390, 14);
    addProc(0x3B0, 0x2F0, L"svchost.exe", 0, 210, 6);
    addProc(0x3C4, 0x2F0, L"svchost.exe", 0, 280, 9);
    addProc(0x3D8, 0x2F0, L"spoolsv.exe", 0, 170, 6);
    addProc(0x3EC, 0x2F0, L"svchost.exe", 0, 190, 5);
    addProc(0x3FC, 0x2F0, L"svchost.exe", 0, 160, 5);
    addProc(0x410, 0x2F0, L"svchost.exe", 0, 230, 7);
    addProc(0x424, 0x2F0, L"svchost.exe", 0, 200, 6);

    wchar_t gamePath[MAX_PATH];
    GetModuleFileNameW(NULL, gamePath, MAX_PATH);
    std::wstring gameName = gamePath;
    size_t pos = gameName.find_last_of(L"\\/");
    if (pos != std::wstring::npos) gameName = gameName.substr(pos + 1);

    addProc(GetCurrentProcessId(), 0x2F0, gameName.c_str(), 1, 80, 8);

    m_logger->Trace(LOG_EMU, "Built virtual process list with %zu entries",
        m_virtualProcessList.size());
}

uint64_t ProcessEmu::GetSpoofedPebField(uint32_t offset)
{
    // PEB fields read for fingerprinting
    switch (offset) {
        case 0x0B8: return 0; // TlsExpansionCounter
        case 0x118: return (uint64_t)(uintptr_t)GetProcessHeap(); // ProcessParameters
        case 0x11C: return 0;
        case 0x12C: return 0;
        case 0x130: return 0;
        default: return 0;
    }
}

bool ProcessEmu::HandleNtQuerySystemInformation(uint64_t* args, uint64_t* result)
{
    uint32_t infoClass = static_cast<uint32_t>(args[0]);
    uint64_t infoBuffer = args[1];
    uint32_t infoLength = static_cast<uint32_t>(args[2]);
    uint64_t returnLengthPtr = args[3];

    m_logger->Trace(LOG_EMU, "NtQuerySystemInformation class=0x%X length=0x%X",
        infoClass, infoLength);

    switch (infoClass) {
        case SystemBasicInformation: {
            if (infoLength < sizeof(SYSTEM_BASIC_INFORMATION)) {
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                if (returnLengthPtr) *(uint32_t*)returnLengthPtr = sizeof(SYSTEM_BASIC_INFORMATION);
                return true;
            }
            SYSTEM_BASIC_INFORMATION basic;
            memset(&basic, 0, sizeof(basic));
            basic.PageSize = 0x1000;
            basic.AllocationGranularity = 0x10000;
            basic.MinimumUserModeAddress = 0x10000;
            basic.MaximumUserModeAddress = 0x7FFFFFFEFFFF;
            basic.NumberOfProcessors = (CCHAR)m_processorCount;
            basic.ActiveProcessorsAffinityMask = m_affinityMask;
            basic.TimerResolution = m_timerResolution;
            basic.NumberOfPhysicalPages = m_physicalPageCount;
            basic.LowestPhysicalPageNumber = 0x00000001;
            basic.HighestPhysicalPageNumber = 0x000F4000;
            memcpy((void*)infoBuffer, &basic, sizeof(basic));
            if (returnLengthPtr) *(uint32_t*)returnLengthPtr = sizeof(SYSTEM_BASIC_INFORMATION);
                *result = (uint64_t)STATUS_SUCCESS;
            return true;
        }

        case SystemProcessInformation: {
            std::vector<uint8_t> buffer;
            for (const auto& proc : m_virtualProcessList) {
                SYSTEM_PROCESS_INFORMATION spi;
                memset(&spi, 0, sizeof(spi));
                spi.NumberOfThreads = proc.threadCount;
                spi.UniqueProcessId = (HANDLE)(ULONG_PTR)proc.uniqueProcessId;
                spi.InheritedFromUniqueProcessId = (HANDLE)(ULONG_PTR)proc.parentProcessId;
                spi.HandleCount = proc.handleCount;
                spi.SessionId = proc.sessionId;
                spi.BasePriority = 8;

                std::wstring imgName = proc.imageName;
                if (!imgName.empty()) {
                    spi.ImageName.Length = (USHORT)(imgName.size() * sizeof(wchar_t));
                    spi.ImageName.MaximumLength = spi.ImageName.Length + sizeof(wchar_t);
                }

                size_t offset = buffer.size();
                buffer.resize(offset + sizeof(SYSTEM_PROCESS_INFORMATION));

                size_t nameBufferOffset = buffer.size();
                if (!imgName.empty()) {
                    buffer.resize(nameBufferOffset + imgName.size() * sizeof(wchar_t) + sizeof(wchar_t));
                    memcpy(buffer.data() + nameBufferOffset, imgName.c_str(),
                           imgName.size() * sizeof(wchar_t));
                    ((wchar_t*)(buffer.data() + nameBufferOffset))[imgName.size()] = 0;
                }

                if (!imgName.empty()) {
                    spi.ImageName.Buffer = (PWCH)((uintptr_t)infoBuffer + nameBufferOffset);
                }

                memcpy(buffer.data() + offset, &spi, sizeof(SYSTEM_PROCESS_INFORMATION));
            }

            uint32_t totalSize = (uint32_t)buffer.size();
            if (totalSize > infoLength) {
                if (returnLengthPtr) *(uint32_t*)returnLengthPtr = totalSize;
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }

            if (buffer.size() >= sizeof(SYSTEM_PROCESS_INFORMATION)) {
                PSYSTEM_PROCESS_INFORMATION lastEntry = (PSYSTEM_PROCESS_INFORMATION)
                    (buffer.data() + buffer.size() - sizeof(SYSTEM_PROCESS_INFORMATION));
                lastEntry->NextEntryOffset = 0;
            }

            memcpy((void*)infoBuffer, buffer.data(), buffer.size());
            if (returnLengthPtr) *(uint32_t*)returnLengthPtr = totalSize;
                *result = (uint64_t)STATUS_SUCCESS;
            return true;
        }

        case SystemKernelDebuggerInformation: {
            if (infoLength < 2) {
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }
            uint8_t kdBytes[2] = { 0, 1 }; // enabled=FALSE, notPresent=TRUE
            memcpy((void*)infoBuffer, kdBytes, min(infoLength, 2u));
            if (returnLengthPtr) *(uint32_t*)returnLengthPtr = 2;
                *result = (uint64_t)STATUS_SUCCESS;
            m_logger->Trace(LOG_INFO, "Spoofed KdDebuggerNotPresent=TRUE");
            return true;
        }

        case SystemCodeIntegrityInformation: {
            if (infoLength < sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)) {
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }
            SYSTEM_CODEINTEGRITY_INFORMATION ciInfo;
            ciInfo.Length = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
            ciInfo.CodeIntegrityOptions = 0;
            memcpy((void*)infoBuffer, &ciInfo, sizeof(ciInfo));
            if (returnLengthPtr) *(uint32_t*)returnLengthPtr = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
                *result = (uint64_t)STATUS_SUCCESS;
            return true;
        }

        case 0x0B: { // SystemModuleInformation
            // Some implementations enumerate kernel modules to detect unsigned drivers
            // Return empty module list
            uint32_t neededSize = sizeof(uint32_t); // just entry count = 0
            if (infoLength < neededSize) {
                if (returnLengthPtr) *(uint32_t*)returnLengthPtr = neededSize;
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }
            *(uint32_t*)infoBuffer = 0; // zero modules
            if (returnLengthPtr) *(uint32_t*)returnLengthPtr = neededSize;
                *result = (uint64_t)STATUS_SUCCESS;
            m_logger->Trace(LOG_EMU, "SystemModuleInformation: returned empty list (0 modules)");
            return true;
        }

        case SystemFirmwareTableInformation: {
            typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
                ULONG ProviderSignature;
                BOOLEAN ProviderSpecific;
                BOOLEAN ACPIBufferTooSmall;
                UCHAR Reserved[2];
                ULONG FirmwareTableID;
                PVOID FirmwareTableBuffer;
                ULONG FirmwareTableBufferLength;
            } SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

            PSYSTEM_FIRMWARE_TABLE_INFORMATION fti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)(uintptr_t)infoBuffer;

            if (infoLength < sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION)) {
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }

            uint32_t providerSig = fti->ProviderSignature;
            void* tableBuffer = fti->FirmwareTableBuffer;
            uint32_t tableBufLen = fti->FirmwareTableBufferLength;

            // Handle ACPI provider — spoof MADT to show 20 processors
            if (providerSig == 0x49435041) {
                // Call real NtQuerySystemInformation to get ACPI data
                HMODULE nt = GetModuleHandleA("ntdll.dll");
                if (!nt) { *result = (uint64_t)(ULONG)STATUS_NOT_IMPLEMENTED; return true; }
                typedef NTSTATUS (NTAPI* NtQsiFunc)(ULONG, PVOID, ULONG, PULONG);
                auto realNtQsi = (NtQsiFunc)GetProcAddress(nt, "NtQuerySystemInformation");
                if (!realNtQsi) { *result = (uint64_t)(ULONG)STATUS_NOT_IMPLEMENTED; return true; }

                // If this is a size query (buffer is null / too small), let real syscall handle it
                if (fti->ACPIBufferTooSmall || !tableBuffer) {
                    NTSTATUS status = realNtQsi(infoClass, (PVOID)infoBuffer, infoLength, (PULONG)returnLengthPtr);
                    *result = (uint64_t)(ULONG)status;
                    return true;
                }

                // Get real ACPI data into a temporary buffer
                ULONG realLen = 0;
                NTSTATUS status = realNtQsi(infoClass, (PVOID)infoBuffer, infoLength, &realLen);
                if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
                    *result = (uint64_t)status;
                    return true;
                }

                // Allocate temp buffer for real data
                ULONG bufSize = max(tableBufLen, realLen);
                uint8_t* tempBuf = (uint8_t*)malloc(bufSize);
                if (!tempBuf) { *result = (uint64_t)(ULONG)STATUS_NO_MEMORY; return true; }

                fti->FirmwareTableBuffer = tempBuf;
                fti->FirmwareTableBufferLength = bufSize;
                status = realNtQsi(infoClass, (PVOID)infoBuffer, infoLength, &realLen);
                fti->FirmwareTableBuffer = tableBuffer;
                fti->FirmwareTableBufferLength = bufSize;

                if (!NT_SUCCESS(status)) {
                    free(tempBuf);
                    *result = (uint64_t)(ULONG)status;
                    return true;
                }

                // Spoof MADT (APIC) if this is the right table
                void* acpiData = tempBuf;
                ULONG acpiLen = bufSize;
                if (fti->FirmwareTableID == 0x43495041 && acpiData && acpiLen >= 44) {
                    // Count existing processor entries (Type 0) and save non-processor entries
                    struct SavedEntry { uint8_t data[256]; uint8_t type; uint8_t length; };
                    SavedEntry saved[32]; int savedCount = 0; int origProcCount = 0;

                    uint8_t* pos = (uint8_t*)acpiData + 44;
                    uint8_t* end = (uint8_t*)acpiData + acpiLen;
                    while (pos + 2 <= end) {
                        uint8_t type = pos[0];
                        uint8_t len = pos[1];
                        if (len < 2 || pos + len > end) break;
                        if (type == 0) origProcCount++;
                        else if (savedCount < 32) { memcpy(saved[savedCount].data, pos, len); saved[savedCount].type = type; saved[savedCount].length = len; savedCount++; }
                        pos += len;
                    }

                    // Build new MADT with 20 processor entries
                    const int targetCount = 20;
                    uint8_t newTable[4096];
                    memcpy(newTable, acpiData, 44);
                    uint8_t* wp = newTable + 44;
                    for (int i = 0; i < targetCount; i++) {
                        wp[0] = 0; wp[1] = 8;
                        wp[2] = (uint8_t)i; wp[3] = (uint8_t)i;
                        *(uint32_t*)(wp + 4) = 1;
                        wp += 8;
                    }
                    for (int i = 0; i < savedCount; i++) {
                        memcpy(wp, saved[i].data, saved[i].length);
                        wp += saved[i].length;
                    }

                    ULONG newLen = (ULONG)(wp - newTable);
                    *(ULONG*)(newTable + 4) = newLen;

                    uint8_t sum = 0;
                    for (ULONG i = 0; i < newLen; i++) sum += newTable[i];
                    newTable[9] = (uint8_t)((uint8_t)newTable[9] - sum);

                    if (tableBufLen >= newLen) {
                        memcpy(tableBuffer, newTable, newLen);
                        fti->FirmwareTableBufferLength = newLen;
                    } else {
                        fti->FirmwareTableBufferLength = newLen;
                        free(tempBuf);
                        *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
                        return true;
                    }
                    m_logger->Trace(LOG_EMU, "ACPI MADT spoofed: %d -> %d processors", origProcCount, targetCount);
                } else {
                    // Not MADT — copy original data
                    if (tableBuffer && tableBufLen >= acpiLen) {
                        memcpy(tableBuffer, acpiData, acpiLen);
                        fti->FirmwareTableBufferLength = acpiLen;
                    }
                }
                free(tempBuf);
                if (returnLengthPtr) *(uint32_t*)returnLengthPtr = fti->FirmwareTableBufferLength;
                *result = (uint64_t)STATUS_SUCCESS;
                return true;
            }

            // Only handle SMBIOS provider ('RSMB' = 0x52534D42)
            if (providerSig != 0x52534D42) {
                *result = (uint64_t)STATUS_NOT_SUPPORTED;
                return false;
            }

            // Build complete SMBIOS 3.2.0 data with proper EPS + Type 0/1/2/3/4/127
            uint8_t smbiosBuf[0x1000];
            memset(smbiosBuf, 0, sizeof(smbiosBuf));
            uint32_t pos = 0;

            // helper: add null-terminated string
            auto addStr = [&](const char* s) {
                uint32_t n = (uint32_t)strlen(s) + 1;
                memcpy(smbiosBuf + pos, s, n);
                pos += n;
            };

            // ---- SMBIOS 3.2.0 Entry Point Structure (24 bytes) ----
            // Signature "_SM3_"
            smbiosBuf[pos++] = '_'; smbiosBuf[pos++] = 'S';
            smbiosBuf[pos++] = 'M'; smbiosBuf[pos++] = '3';
            smbiosBuf[pos++] = '_';
            pos++; // checksum placeholder — filled below
            smbiosBuf[pos++] = 3;  // major
            smbiosBuf[pos++] = 2;  // minor
            smbiosBuf[pos++] = 0;  // docrev
            smbiosBuf[pos++] = 0;  // revision
            smbiosBuf[pos++] = 0;  // reserved
            // maxStructureSize (4 bytes) — filled at end
            uint32_t maxSizeOff = pos;
            pos += 4;
            // tableAddress (8 bytes) — leave 0
            pos += 8;
            // entryPointLength
            smbiosBuf[pos++] = 24;
            // Note: EPS total = 24 bytes

            // ---- SMBIOS Structure Table ----

            // SMBIOS Type 0 — BIOS Information (24 bytes + strings)
            smbiosBuf[pos++] = 0;  smbiosBuf[pos++] = 24; // type, length
            smbiosBuf[pos++] = 0;  smbiosBuf[pos++] = 0;  // handle
            smbiosBuf[pos++] = 1;  smbiosBuf[pos++] = 2;  // vendor, version
            smbiosBuf[pos++] = 3;  smbiosBuf[pos++] = 0;  // date, reserved
            memset(smbiosBuf + pos, 0, 12); pos += 12;    // bios characteristics
            smbiosBuf[pos++] = 0xFF; smbiosBuf[pos++] = 0x00; // extension bytes
            smbiosBuf[pos++] = 0xFF; smbiosBuf[pos++] = 0xFF; // rom size
            addStr(m_biosVendor.c_str());
            addStr(m_biosVersion.c_str());
            addStr(m_biosDate.c_str());
            smbiosBuf[pos++] = 0; // end of strings

            // SMBIOS Type 1 — System Information (27 bytes + strings)
            smbiosBuf[pos++] = 1;  smbiosBuf[pos++] = 27; // type, length
            smbiosBuf[pos++] = 1;  smbiosBuf[pos++] = 0;  // handle
            smbiosBuf[pos++] = 1;  smbiosBuf[pos++] = 2;  // mfr, product
            smbiosBuf[pos++] = 3;  smbiosBuf[pos++] = 4;  // version, serial
            memset(smbiosBuf + pos, 0, 16); pos += 16;    // uuid
            smbiosBuf[pos++] = 6;  smbiosBuf[pos++] = 5;  // wakeup, sku
            smbiosBuf[pos++] = 6;                          // family
            addStr(m_manufacturer.c_str());
            addStr(m_productName.c_str());
            addStr(m_productVersion.c_str());
            addStr(m_serialNumber.c_str());
            addStr(m_sku.c_str());
            addStr(m_family.c_str());
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 2 — Baseboard (15 bytes + strings)
            smbiosBuf[pos++] = 2;  smbiosBuf[pos++] = 15; // type, length
            smbiosBuf[pos++] = 2;  smbiosBuf[pos++] = 0;  // handle
            smbiosBuf[pos++] = 1;  smbiosBuf[pos++] = 2;  // mfr, product
            smbiosBuf[pos++] = 3;  smbiosBuf[pos++] = 4;  // version, serial
            smbiosBuf[pos++] = 5;  smbiosBuf[pos++] = 0x03; // asset, type
            smbiosBuf[pos++] = 0;  smbiosBuf[pos++] = 0;  // reserved
            smbiosBuf[pos++] = 0;  smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0;
            addStr(m_manufacturer.c_str());
            addStr(m_productName.c_str());
            addStr(m_productVersion.c_str());
            addStr(m_baseboardSerial.c_str());
            addStr("Default_Asset_Tag");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 3 — Chassis (22 bytes + strings)
            smbiosBuf[pos++] = 3;  smbiosBuf[pos++] = 22; // type, length
            smbiosBuf[pos++] = 3;  smbiosBuf[pos++] = 0;  // handle
            smbiosBuf[pos++] = 1;  smbiosBuf[pos++] = 3;  // mfr, type=desktop
            smbiosBuf[pos++] = 2;  smbiosBuf[pos++] = 3;  // version, serial
            smbiosBuf[pos++] = 4;  smbiosBuf[pos++] = 0;  // asset, bootup
            smbiosBuf[pos++] = 0;  smbiosBuf[pos++] = 0;  // power supply
            smbiosBuf[pos++] = 0;  memset(smbiosBuf + pos, 0, 4); pos += 4;
            smbiosBuf[pos++] = 3;  smbiosBuf[pos++] = 1;  // OEM defined, height
            smbiosBuf[pos++] = 0;                          // number of power cords
            addStr(m_manufacturer.c_str());
            addStr(m_productVersion.c_str());
            addStr(m_chassisSerial.c_str());
            addStr("Default_Asset_Tag");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 4 — Processor Information (42 bytes + strings)
            smbiosBuf[pos++] = 4;  smbiosBuf[pos++] = 42; // type, length
            smbiosBuf[pos++] = 4;  smbiosBuf[pos++] = 0;  // handle
            smbiosBuf[pos++] = 1;                          // socket = "LGA1200"
            smbiosBuf[pos++] = 3;                          // processor type = central
            smbiosBuf[pos++] = 0xBE;                       // processor family = Intel Core i9 (0xBE)
            smbiosBuf[pos++] = 2;                          // manufacturer = "Intel"
            // Processor ID (8 bytes) = CPUID leaf 1 EAX + EDX
            *(uint32_t*)(smbiosBuf + pos) = 0x000A0655; pos += 4; // EAX = stepping/model/family
            *(uint32_t*)(smbiosBuf + pos) = 0xBFEBFBFF; pos += 4; // EDX = standard features
            smbiosBuf[pos++] = 3;                          // version = "Intel(R) Core(TM) i9-10900K"
            smbiosBuf[pos++] = 0;                          // voltage
            smbiosBuf[pos++] = 0;                          // external clock
            *(uint16_t*)(smbiosBuf + pos) = 3700; pos += 2; // max speed = 3700 MHz
            *(uint16_t*)(smbiosBuf + pos) = 3700; pos += 2; // current speed = 3700 MHz
            smbiosBuf[pos++] = 0x41;                       // status = CPU enabled + populated
            smbiosBuf[pos++] = 0x06;                       // processor upgrade = LGA 1200
            *(uint16_t*)(smbiosBuf + pos) = 0xFFFF; pos += 2; // L1 cache handle = none
            *(uint16_t*)(smbiosBuf + pos) = 0xFFFF; pos += 2; // L2 cache handle = none
            *(uint16_t*)(smbiosBuf + pos) = 0xFFFF; pos += 2; // L3 cache handle = none
            smbiosBuf[pos++] = 0;                          // serial (string 4)
            smbiosBuf[pos++] = 0;                          // asset tag (string 5)
            smbiosBuf[pos++] = 0;                          // part number (string 6)
            smbiosBuf[pos++] = 10;                         // core count = 10
            smbiosBuf[pos++] = 10;                         // enabled core count = 10
            smbiosBuf[pos++] = 0;                          // thread count
            smbiosBuf[pos++] = 20;                         // thread count = 20
            smbiosBuf[pos++] = 0;                          // processor characteristics
            smbiosBuf[pos++] = 0;
            // Strings
            addStr("LGA1200");
            addStr("Intel");
            addStr("Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz");
            smbiosBuf[pos++] = 0; // end of strings

            // SMBIOS Type 7 — Cache Information (19 bytes + strings)
            smbiosBuf[pos++] = 7;  smbiosBuf[pos++] = 19; // type, length
            smbiosBuf[pos++] = 5;  smbiosBuf[pos++] = 0;  // handle = 5
            smbiosBuf[pos++] = 1;                          // socket designation = "L1-Cache"
            smbiosBuf[pos++] = 0x03;                       // cache configuration
            smbiosBuf[pos++] = 0x00;
            smbiosBuf[pos++] = 0x40;                       // max cache size = 64 KB
            smbiosBuf[pos++] = 0x40;                       // installed size = 64 KB
            smbiosBuf[pos++] = 0;                          // supported SRAM type
            smbiosBuf[pos++] = 0;                          // current SRAM type
            smbiosBuf[pos++] = 0;                          // cache speed = 0 (unknown)
            smbiosBuf[pos++] = 0x01;                       // error correction = parity
            smbiosBuf[pos++] = 0x02;                       // system cache type = data
            smbiosBuf[pos++] = 0x02;                       // associativity = 8-way
            smbiosBuf[pos] = 0; pos++;                     // reserved
            smbiosBuf[pos] = 0; pos++;                     // reserved
            addStr("L1-Cache");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 7 — L2 Cache (19 bytes + strings)
            smbiosBuf[pos++] = 7;  smbiosBuf[pos++] = 19; // type, length
            smbiosBuf[pos++] = 6;  smbiosBuf[pos++] = 0;  // handle = 6
            smbiosBuf[pos++] = 1;                          // socket = "L2-Cache"
            smbiosBuf[pos++] = 0x03; smbiosBuf[pos++] = 0x00;
            smbiosBuf[pos++] = 0x01;                       // max = 256 KB (code for 256K)
            smbiosBuf[pos++] = 0x01;                       // installed = 256K
            smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0x01;                       // ecc = parity
            smbiosBuf[pos++] = 0x02;                       // type = unified
            smbiosBuf[pos++] = 0x03;                       // associativity = 12-way
            smbiosBuf[pos] = 0; pos++;
            smbiosBuf[pos] = 0; pos++;
            addStr("L2-Cache");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 7 — L3 Cache (19 bytes + strings)
            smbiosBuf[pos++] = 7;  smbiosBuf[pos++] = 19;
            smbiosBuf[pos++] = 7;  smbiosBuf[pos++] = 0;  // handle = 7
            smbiosBuf[pos++] = 1;                          // socket = "L3-Cache"
            smbiosBuf[pos++] = 0x03; smbiosBuf[pos++] = 0x00;
            smbiosBuf[pos++] = 0x0A;                       // max = 20 MB
            smbiosBuf[pos++] = 0x0A;                       // installed = 20 MB
            smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0x01;                       // ecc = parity
            smbiosBuf[pos++] = 0x03;                       // type = unified
            smbiosBuf[pos++] = 0x04;                       // associativity = 20-way
            smbiosBuf[pos] = 0; pos++;
            smbiosBuf[pos] = 0; pos++;
            addStr("L3-Cache");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 17 — Memory Device (40 bytes + strings)
            smbiosBuf[pos++] = 17; smbiosBuf[pos++] = 40;  // type, length
            smbiosBuf[pos++] = 8;  smbiosBuf[pos++] = 0;   // handle = 8
            smbiosBuf[pos++] = 9;                           // physical memory array handle
            smbiosBuf[pos++] = 0;                           // memory error handle = none
            smbiosBuf[pos++] = 0xFF;                        // total width = unknown
            smbiosBuf[pos++] = 0xFF;
            smbiosBuf[pos++] = 0xFF;                        // data width = unknown
            smbiosBuf[pos++] = 0xFF;
            smbiosBuf[pos++] = 0x80; pos++;               // size = 16 GB (0x8000 = 16GB, bit 15 = extended)
            smbiosBuf[pos++] = 0x0A;                        // form factor = SODIMM
            smbiosBuf[pos++] = 0;                           // device set = 0
            smbiosBuf[pos++] = 1;                           // device locator = "DIMM0"
            smbiosBuf[pos++] = 2;                           // bank locator = "BANK 0"
            smbiosBuf[pos++] = 26;                          // memory type = DDR4
            smbiosBuf[pos++] = 0;                           // type detail
            smbiosBuf[pos++] = 0;
            // speed in MHz
            *(uint16_t*)(smbiosBuf + pos) = 2666; pos += 2;
            smbiosBuf[pos++] = 3;                           // manufacturer = "Kingston"
            smbiosBuf[pos++] = 0;                           // serial number (string 4)
            smbiosBuf[pos++] = 4;                           // asset tag (string 5)
            smbiosBuf[pos++] = 5;                           // part number (string 6)
            smbiosBuf[pos++] = 0;                           // attributes
            *(uint32_t*)(smbiosBuf + pos) = 0; pos += 4;   // extended size = 0
            *(uint16_t*)(smbiosBuf + pos) = 2666; pos += 2;// configured clock speed
            // minimum voltage, maximum voltage, configured voltage
            *(uint16_t*)(smbiosBuf + pos) = 0; pos += 2;
            *(uint16_t*)(smbiosBuf + pos) = 0; pos += 2;
            *(uint16_t*)(smbiosBuf + pos) = 1200; pos += 2; // 1.2V
            addStr("DIMM0");
            addStr("BANK 0");
            addStr("Kingston");
            addStr("00000000");
            addStr("Default_String");
            addStr("KVR26N19D8/16");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 19 — Memory Array Mapped Address (16 bytes)
            smbiosBuf[pos++] = 19; smbiosBuf[pos++] = 16;
            smbiosBuf[pos++] = 11; smbiosBuf[pos++] = 0;   // handle = 11
            *(uint32_t*)(smbiosBuf + pos) = 0; pos += 4;   // starting address = 0
            *(uint32_t*)(smbiosBuf + pos) = 0x03FF; pos += 4; // ending address = 16GB
            smbiosBuf[pos++] = 9;                           // memory array handle
            smbiosBuf[pos++] = 0;                           // partition width = 0
            // Extended starting address
            *(uint64_t*)(smbiosBuf + pos) = 0; pos += 8;
            // Extended ending address
            *(uint64_t*)(smbiosBuf + pos) = 0x400000000ULL; pos += 8; // 16GB in bytes

            // SMBIOS Type 21 — Built-in Pointing Device (7 bytes)
            smbiosBuf[pos++] = 21; smbiosBuf[pos++] = 7;
            smbiosBuf[pos++] = 12; smbiosBuf[pos++] = 0;   // handle = 12
            smbiosBuf[pos++] = 2;                           // type = trackpoint
            smbiosBuf[pos++] = 3;                           // interface = PS/2
            smbiosBuf[pos++] = 2;                           // buttons = 2

            // SMBIOS Type 22 — Portable Battery (26 bytes + strings)
            smbiosBuf[pos++] = 22; smbiosBuf[pos++] = 26;
            smbiosBuf[pos++] = 13; smbiosBuf[pos++] = 0;   // handle = 13
            smbiosBuf[pos++] = 1;                           // location = "System"
            smbiosBuf[pos++] = 2;                           // manufacturer = "Dell Inc."
            smbiosBuf[pos++] = 0x19;                        // manufacture date
            smbiosBuf[pos++] = 3;                           // serial number
            smbiosBuf[pos++] = 4;                           // device name
            smbiosBuf[pos++] = 0x03;                        // device chemistry = Li-Ion
            smbiosBuf[pos++] = 0x42;                        // design capacity = 66 mWh (0x42 * 100)
            smbiosBuf[pos++] = 0;                           // design voltage (0 = unknown)
            smbiosBuf[pos++] = 0;                           // SBDS version number
            smbiosBuf[pos++] = 0;                           // maximum error in battery
            smbiosBuf[pos++] = 0;                           // sbds serial number
            smbiosBuf[pos++] = 0;                           // sbds manufacture date
            smbiosBuf[pos++] = 0;                           // sbds device chemistry
            smbiosBuf[pos++] = 0;                           // design capacity multiplier
            smbiosBuf[pos+1] = 0; pos += 2;                // OEM specific
            smbiosBuf[pos++] = 0;                           // battery type
            addStr("System");
            addStr("Dell Inc.");
            addStr("2024/01/15");
            addStr("DELL_BAT_001");
            addStr("Li-Ion 66WH");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 11 — OEM Strings
            smbiosBuf[pos++] = 11; smbiosBuf[pos++] = 5;
            smbiosBuf[pos++] = 14; smbiosBuf[pos++] = 0;   // handle = 14
            smbiosBuf[pos++] = 1;                           // count = 1 string
            addStr("Dell System");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 13 — BIOS Language
            smbiosBuf[pos++] = 13; smbiosBuf[pos++] = 22;
            smbiosBuf[pos++] = 15; smbiosBuf[pos++] = 0;   // handle = 15
            smbiosBuf[pos++] = 1;                           // installable languages = 1
            smbiosBuf[pos++] = 0;                           // flags
            // reserved
            smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0; smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 1;                           // current language = string 1
            addStr("en|US|iso8859-1");
            smbiosBuf[pos++] = 0;

            // SMBIOS Type 127 — End of Table
            smbiosBuf[pos++] = 127;
            smbiosBuf[pos++] = 4;
            smbiosBuf[pos++] = 0;
            smbiosBuf[pos++] = 0;

            // ---- Fix up EPS fields ----
            uint32_t structTableLen = pos - 24; // SMBIOS structure table length (after EPS)
            // maxStructureSize
            *(uint32_t*)(smbiosBuf + maxSizeOff) = structTableLen;

            // EPS checksum = -(sum of all 24 EPS bytes)
            uint8_t sum = 0;
            for (int i = 0; i < 24; i++) sum += smbiosBuf[i];
            smbiosBuf[5] = (uint8_t)(0x100 - sum); // checksum byte

            if (tableBufLen < pos) {
                fti->FirmwareTableBufferLength = pos;
                *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
                return true;
            }
            if (tableBuffer) memcpy(tableBuffer, smbiosBuf, pos);
            fti->FirmwareTableBuffer = tableBuffer;
            fti->FirmwareTableBufferLength = pos;
                *result = (uint64_t)STATUS_SUCCESS;
            m_logger->Trace(LOG_EMU, "SMBIOS 3.2 spoofed: %u bytes, Type4 handle=4", pos);
            return true;
        }

        case SystemHandleInformation:
        default: {
            // Unknown/unhandled class - fall through to real OS
            *result = (uint64_t)STATUS_NOT_SUPPORTED;
            return false;
        }
    }
}

bool ProcessEmu::HandleNtOpenProcess(uint64_t* args, uint64_t* result)
{
    // args: [0]=&handle, [1]=desiredAccess, [2]=objectAttr, [3]=clientId
    HANDLE processHandle = nullptr;
    ACCESS_MASK access = (ACCESS_MASK)args[1];
    uint32_t pid = (uint32_t)args[3];

    m_logger->Trace(LOG_EMU, "NtOpenProcess: access=0x%X pid=%u", access, pid);

    HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (!nt) { *result = (uint64_t)STATUS_ACCESS_DENIED; return true; }

    typedef NTSTATUS (WINAPI* NtOpenProcessFunc)(HANDLE*, ACCESS_MASK, void*, uint32_t);
    auto realNtOpenProcess = (NtOpenProcessFunc)GetProcAddress(nt, "NtOpenProcess");
    if (!realNtOpenProcess) { *result = (uint64_t)STATUS_ACCESS_DENIED; return true; }

    // pack client id into uint32: low 16 bits = pid, high 16 bits = tid
    NTSTATUS status = realNtOpenProcess(&processHandle, access, (void*)args[2], pid);
    if (NT_SUCCESS(status) && args[0]) {
        *(HANDLE*)(uintptr_t)args[0] = processHandle;
    }

    if (result) *result = (uint64_t)status;
    return true;
}

bool ProcessEmu::HandleNtQueryInformationProcess(uint64_t* args, uint64_t* result)
{
    uint32_t infoClass = static_cast<uint32_t>(args[2]);

    m_logger->Trace(LOG_EMU, "NtQueryInformationProcess class=0x%X", infoClass);

    switch (infoClass) {
        case 0x07: {
            if (args[1] == 0 || args[3] < sizeof(uint32_t)) {
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }
            *(uint32_t*)(uintptr_t)args[1] = 0xFFFFFFFF;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(uint32_t);
                *result = (uint64_t)STATUS_SUCCESS;
            m_logger->Trace(LOG_INFO, "Spoofed ProcessDebugPort=0xFFFFFFFF (no debugger)");
            return true;
        }

        case 0x1E: {
            if (args[1] == 0 || args[3] < sizeof(HANDLE)) {
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }
            *(HANDLE*)(uintptr_t)args[1] = NULL;
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(HANDLE);
                *result = (uint64_t)STATUS_SUCCESS;
            m_logger->Trace(LOG_INFO, "Spoofed ProcessDebugObjectHandle=NULL");
            return true;
        }

        case 0x00: {
            typedef struct _PROCESS_BASIC_INFORMATION {
                NTSTATUS ExitStatus;
                PPEB PebBaseAddress;
                ULONG_PTR AffinityMask;
                KPRIORITY BasePriority;
                HANDLE UniqueProcessId;
                HANDLE InheritedFromUniqueProcessId;
            } PROCESS_BASIC_INFORMATION;

            if (args[1] == 0 || args[3] < sizeof(PROCESS_BASIC_INFORMATION)) {
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }
            PROCESS_BASIC_INFORMATION pbi;
            memset(&pbi, 0, sizeof(pbi));
            pbi.ExitStatus = STATUS_SUCCESS;
            pbi.PebBaseAddress = (PPEB)0x7FFFA000;
            pbi.AffinityMask = 0xFF;
            pbi.BasePriority = 8;
            pbi.UniqueProcessId = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
            pbi.InheritedFromUniqueProcessId = (HANDLE)0x2F0;
            memcpy((void*)(uintptr_t)args[1], &pbi, sizeof(pbi));
            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = sizeof(PROCESS_BASIC_INFORMATION);
                *result = (uint64_t)STATUS_SUCCESS;
            return true;
        }

        case 0x1B: {
            wchar_t gamePath[MAX_PATH];
            GetModuleFileNameW(NULL, gamePath, MAX_PATH);

            uint32_t nameLen = (uint32_t)(wcslen(gamePath) * sizeof(wchar_t));
            uint32_t requiredSize = sizeof(UNICODE_STRING) + nameLen + sizeof(wchar_t);

            if (args[3] < requiredSize) {
                if (args[4]) *(uint32_t*)(uintptr_t)args[4] = requiredSize;
                *result = (uint64_t)STATUS_INFO_LENGTH_MISMATCH;
                return true;
            }

            UNICODE_STRING* outStr = (UNICODE_STRING*)(uintptr_t)args[1];
            outStr->Length = (USHORT)nameLen;
            outStr->MaximumLength = (USHORT)(nameLen + sizeof(wchar_t));
            outStr->Buffer = (PWCH)(uintptr_t)(args[1] + sizeof(UNICODE_STRING));
            memcpy(outStr->Buffer, gamePath, nameLen + sizeof(wchar_t));

            if (args[4]) *(uint32_t*)(uintptr_t)args[4] = requiredSize;
                *result = (uint64_t)STATUS_SUCCESS;
            return true;
        }

        default: {
            *result = (uint64_t)STATUS_INVALID_INFO_CLASS;
            return true;
        }
    }
}
