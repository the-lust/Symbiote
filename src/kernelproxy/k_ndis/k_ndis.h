#pragma once
#include <windows.h>

extern "C" {
    NTSTATUS K_NdisInitialize(PVOID context);
    void K_NdisSpoofMacAddress();
    void K_NdisSpoofAdapterName();
    void K_NdisFilterPacket(void* packet);
}