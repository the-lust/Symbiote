#pragma once
#include <windows.h>

extern "C" {
    NTSTATUS K_VolmgrInitialize(PVOID context);
    void K_VolmgrSpoofDiskSerial(const wchar_t* serial);
    void K_VolmgrSpoofDiskGeometry();
    void K_VolmgrHideVolume(wchar_t driveLetter);
}