#pragma once
#include <windows.h>

extern "C" {
    NTSTATUS K_Win32kInitialize(PVOID context);
    void K_Win32kSpoofDesktopInfo();
    void K_Win32kHideWindow(HWND target);
    void K_Win32kSpoofSessionInfo();
}