#pragma once
#include <windows.h>

// Stub entry point for kernel proxy injection.
// Called by KernelProxy via BYOVD physical memory injection.
// Runs in kernel context.

extern "C" {
    // Main entry — called from kernel thread after injection
    NTSTATUS K_NtoskrnlInitialize(PVOID context);

    // Spoof SSDT entries to return fake data
    NTSTATUS K_NtoskrnlHookSsdt();

    // Restore original SSDT entries
    void K_NtoskrnlRestore();

    // EPROCESS debug flag sanitizer
    NTSTATUS K_NtoskrnlSanitizeEprocess(HANDLE targetPid);

    // Filter NtQuerySystemInformation output
    NTSTATUS K_NtoskrnlFilterSystemInfo(ULONG infoClass, PVOID info, ULONG size);

    // Communication with user-mode engine
    NTSTATUS K_NtoskrnlPing();
}