#include <windows.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <cstdint>
#include <string.h>

// Test the HwIdEmu storage IOCTL path and volume info spoofing
// Run this inside a Symbiote-sandboxed process to verify HWID spoofing

int main()
{
    printf("=== VirtualDisk / Storage IOCTL Smoke Test ===\n\n");

    // Test 1: Query volume information via GetVolumeInformationW
    printf("[1] GetVolumeInformationW:\n");
    {
        wchar_t volName[MAX_PATH] = {0};
        wchar_t fsName[MAX_PATH] = {0};
        DWORD volSerial = 0;
        DWORD maxComponent = 0;
        DWORD flags = 0;
        BOOL ok = GetVolumeInformationW(
            L"C:\\", volName, MAX_PATH, &volSerial, &maxComponent, &flags, fsName, MAX_PATH);
        if (ok) {
            printf("  Volume: %ls (serial=0x%08X)\n", volName, volSerial);
            printf("  Filesystem: %ls\n", fsName);
        } else {
            printf("  FAILED (GLE=%lu) — may not be running under Symbiote\n", GetLastError());
        }
    }

    // Test 2: CreateFile and DeviceIoControl on \\.\PhysicalDrive0
    printf("\n[2] PhysicalDrive0 IOCTL_STORAGE_QUERY_PROPERTY:\n");
    {
        HANDLE hDrive = CreateFileW(
            L"\\\\.\\PhysicalDrive0",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
        if (hDrive == INVALID_HANDLE_VALUE) {
            printf("  FAILED to open PhysicalDrive0 (GLE=%lu)\n", GetLastError());
        } else {
            // STORAGE_DEVICE_DESCRIPTOR query
            STORAGE_PROPERTY_QUERY query;
            memset(&query, 0, sizeof(query));
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;

            uint8_t buf[4096];
            DWORD bytesReturned = 0;
            BOOL ok = DeviceIoControl(
                hDrive,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query, sizeof(query),
                buf, sizeof(buf),
                &bytesReturned,
                NULL);
            if (ok && bytesReturned >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)buf;
                const char* vendor = desc->VendorIdOffset ? (const char*)buf + desc->VendorIdOffset : "";
                const char* product = desc->ProductIdOffset ? (const char*)buf + desc->ProductIdOffset : "";
                const char* serial = desc->SerialNumberOffset ? (const char*)buf + desc->SerialNumberOffset : "";
                printf("  Vendor:  %s\n", vendor);
                printf("  Product: %s\n", product);
                printf("  Serial:  %s\n", serial);
                printf("  Version: %u, Size: %u\n", desc->Version, desc->Size);
                if (desc->SerialNumberOffset > 0) {
                    printf("  => HwIdEmu spoofing ACTIVE (serial present)\n");
                } else {
                    printf("  => HwIdEmu spoofing INACTIVE or not loaded\n");
                }
            } else {
                printf("  IOCTL FAILED (GLE=%lu) bytes=%lu\n", GetLastError(), bytesReturned);
                printf("  => Blocked by ntdll_proxy NtCreateFile hook (physical drive access denied)\n");
            }
            CloseHandle(hDrive);
        }
    }

    // Test 3: ATA pass-through query
    printf("\n[3] ATA IDENTIFY device (via IOCTL_ATA_PASS_THROUGH):\n");
    {
        HANDLE hDrive = CreateFileW(
            L"\\\\.\\PhysicalDrive0",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hDrive != INVALID_HANDLE_VALUE) {
            // ATA IDENTIFY command
            struct {
                ATA_PASS_THROUGH_EX apt;
                uint8_t data[512];
            } pt;
            memset(&pt, 0, sizeof(pt));
            pt.apt.Length = sizeof(ATA_PASS_THROUGH_EX);
            pt.apt.AtaFlags = ATA_FLAGS_DATA_IN;
            pt.apt.DataTransferLength = 512;
            pt.apt.TimeOutValue = 10;
            pt.apt.DataBufferOffset = FIELD_OFFSET(decltype(pt), data);
            pt.apt.CurrentTaskFile[6] = 0xEC; // ATA IDENTIFY

            DWORD bytesReturned = 0;
            BOOL ok = DeviceIoControl(
                hDrive,
                IOCTL_ATA_PASS_THROUGH,
                &pt, sizeof(pt),
                &pt, sizeof(pt),
                &bytesReturned,
                NULL);

            if (ok && bytesReturned > sizeof(ATA_PASS_THROUGH_EX)) {
                // Serial number is at bytes 10-19 (20 chars, ASCII)
                char serial[21] = {0};
                for (int i = 0; i < 20; i += 2) {
                    serial[i] = pt.data[10 + i + 1];
                    serial[i + 1] = pt.data[10 + i];
                }
                char model[41] = {0};
                for (int i = 0; i < 40; i += 2) {
                    model[i] = pt.data[27 + i + 1];
                    model[i + 1] = pt.data[27 + i];
                }
                printf("  ATA IDENTIFY:\n");
                printf("  Serial: \"%s\"\n", serial);
                printf("  Model:  \"%s\"\n", model);
                printf("  => HwIdEmu ATA spoofing %s\n",
                    strstr(serial, "SYMBIOTE") ? "ACTIVE" : "INACTIVE (real device data)");
            } else {
                printf("  ATA PASS-THROUGH FAILED (GLE=%lu)\n", GetLastError());
            }
            CloseHandle(hDrive);
        }
    }

    printf("\n=== Test Complete ===\n");
    printf("Check emu.log for detailed HwIdEmu dispatch trace.\n");
    return 0;
}
