#include "WhpDetection.h"
#include <windows.h>
#include <shellapi.h>
#include <WinHvPlatform.h>
#include <string>

bool IsWHPDetected()
{
    HMODULE hWinHv = LoadLibraryW(L"WinHvPlatform.dll");
    if (!hWinHv) return false;

    WHV_PARTITION_HANDLE hPartition = nullptr;
    HRESULT hr = WHvCreatePartition(&hPartition);
    if (FAILED(hr)) {
        FreeLibrary(hWinHv);
        return false;
    }
    WHvDeletePartition(hPartition);
    FreeLibrary(hWinHv);
    return true;
}

bool IsWHPEnabledInWindows()
{
    // check if WinHvPlatform.dll exists
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring dllPath = std::wstring(sysDir) + L"\\WinHvPlatform.dll";
    DWORD attr = GetFileAttributesW(dllPath.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

static bool RunElevatedDism(const wchar_t* args, const wchar_t*)
{
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring dismPath = std::wstring(sysDir) + L"\\dism.exe";

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd = nullptr;
    sei.lpVerb = L"runas";
    sei.lpFile = dismPath.c_str();
    sei.lpParameters = args;
    sei.lpDirectory = nullptr;
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) return false;
        return false;
    }

    WaitForSingleObject(sei.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);

    return exitCode == 0;
}

int InstallWHP()
{
    // try dism elevated first
    bool ok = RunElevatedDism(
        L"/Online /Enable-Feature /FeatureName:HypervisorPlatform /All /Quiet /NoRestart",
        L"Installing WHP");

    if (!ok) {
        // second try: Hyper-V platform
        ok = RunElevatedDism(
            L"/Online /Enable-Feature /FeatureName:Microsoft-Hyper-V /All /Quiet /NoRestart",
            L"Installing Hyper-V Platform");
    }

    return ok ? 0 : -1;
}

int PromptForWHPInstall()
{
    int msgboxID = MessageBoxW(nullptr,
        L"Windows Hypervisor Platform (WHP) is required.\n\n"
        L"This tool needs WHP to create a hardware-virtualized environment.\n\n"
        L"Click Yes to install WHP now (requires admin privileges).\n"
        L"A reboot may be required after installation.\n"
        L"Click No to exit.",
        L"WHP Required",
        MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1);

    if (msgboxID == IDYES) {
        int ret = InstallWHP();
        if (ret == 0) {
            int reboot = MessageBoxW(nullptr,
                L"WHP installed successfully.\n\n"
                L"A reboot is recommended for WHP to take effect.\n"
                L"Would you like to reboot now?",
                L"Install Complete",
                MB_ICONINFORMATION | MB_YESNO | MB_DEFBUTTON2);
            if (reboot == IDYES) {
                HANDLE hToken;
                TOKEN_PRIVILEGES tkp;
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                    LookupPrivilegeValueW(nullptr, L"SeShutdownPrivilege", &tkp.Privileges[0].Luid);
                    tkp.PrivilegeCount = 1;
                    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, nullptr);
                    CloseHandle(hToken);
                }
                ExitWindowsEx(EWX_REBOOT | EWX_FORCEIFHUNG, SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
                    SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED);
            }
        } else {
            MessageBoxW(nullptr,
                L"Failed to install WHP.\n\n"
                L"Please enable it manually:\n"
                L"  Settings > Apps > Optional Features >\n"
                L"  Windows Hypervisor Platform\n\n"
                L"Or run as Administrator:\n"
                L"  dism /online /Enable-Feature /FeatureName:HypervisorPlatform",
                L"Install Failed",
                MB_ICONERROR | MB_OK);
        }
        return ret;
    }
    return -1;
}