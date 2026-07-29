#pragma once
#include <windows.h>

extern "C" {
    NTSTATUS K_DxgkrnlInitialize(PVOID context);
    void K_DxgkrnlSpoofAdapterInfo(ULONG adapterIndex);
    void K_DxgkrnlSpoofDriverModel();
    NTSTATUS K_DxgkrnlFilterEscapes();
}