#include "ProcessUtils.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>

std::wstring GetEngineDllPath()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring exePath = path;
    size_t pos = exePath.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        exePath = exePath.substr(0, pos);
    }
    return exePath + L"\\engine.dll";
}

bool CreateSuspendedProcess(const std::wstring& targetPath, const std::wstring& targetArgs, STARTUPINFOW& si, PROCESS_INFORMATION& pi)
{
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::wstring cmdLine = L"\"" + targetPath + L"\"";
    if (!targetArgs.empty()) {
        cmdLine += L" " + targetArgs;
    }

    BOOL result = CreateProcessW(
        targetPath.c_str(),
        &cmdLine[0],
        NULL,
        NULL,
        TRUE,   // inherit handles for STARTF_USESTDHANDLES
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    return result != FALSE;
}

bool CallRemoteFunction(HANDLE hProcess, const std::wstring& dllPath, const char* funcName)
{
    // Extract just the filename from the path for module lookup
    std::wstring dllName = dllPath;
    size_t pos = dllName.find_last_of(L"\\/");
    if (pos != std::wstring::npos) dllName = dllName.substr(pos + 1);

    HMODULE hLocal = GetModuleHandleW(dllName.c_str());
    if (!hLocal) {
        hLocal = LoadLibraryW(dllPath.c_str());
        if (!hLocal) return false;
    }

    void* localAddr = GetProcAddress(hLocal, funcName);
    if (!localAddr) return false;

    uintptr_t localBase = (uintptr_t)hLocal;
    uintptr_t offset = (uintptr_t)localAddr - localBase;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    uintptr_t targetBase = 0;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (_wcsicmp(me.szModule, dllName.c_str()) == 0) {
                targetBase = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);

    if (!targetBase) return false;

    void* targetAddr = (void*)(targetBase + offset);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)targetAddr, NULL, 0, NULL);
    if (!hThread) return false;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return true;
}

bool InjectDll(HANDLE hProcess, const std::wstring& dllPath)
{
    size_t pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) return false;

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), pathSize, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    LPTHREAD_START_ROUTINE loadLibAddr = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibAddr) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibAddr, remoteMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    return true;
}

bool ResumeAndWait(HANDLE hProcess, HANDLE hThread, DWORD* exitCode)
{
    ResumeThread(hThread);
    WaitForSingleObject(hProcess, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(hProcess, &code);
    if (exitCode) *exitCode = code;

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
