#pragma once
#include <windows.h>
#include <string>

bool CreateSuspendedProcess(const std::wstring& targetPath, const std::wstring& targetArgs, STARTUPINFOW& si, PROCESS_INFORMATION& pi);
bool InjectDll(HANDLE hProcess, const std::wstring& dllPath);
bool CallRemoteFunction(HANDLE hProcess, const std::wstring& dllPath, const char* funcName);
// Same as CallRemoteFunction, but also retrieves the remote thread's exit code into *outResult.
// Only meaningful for exported functions that actually return a value (e.g. BOOL Engine_Init()) —
// exit codes for void-returning exports are undefined and must not be relied on.
bool CallRemoteFunctionWithResult(HANDLE hProcess, const std::wstring& dllPath, const char* funcName, DWORD* outResult);
bool ResumeAndWait(HANDLE hProcess, HANDLE hThread, DWORD* exitCode = nullptr);
std::wstring GetEngineDllPath();
