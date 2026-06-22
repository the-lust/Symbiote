#pragma once
#include <windows.h>
#include <string>

bool CreateSuspendedProcess(const std::wstring& targetPath, const std::wstring& targetArgs, STARTUPINFOW& si, PROCESS_INFORMATION& pi);
bool InjectDll(HANDLE hProcess, const std::wstring& dllPath);
bool CallRemoteFunction(HANDLE hProcess, const std::wstring& dllPath, const char* funcName);
bool ResumeAndWait(HANDLE hProcess, HANDLE hThread, DWORD* exitCode = nullptr);
std::wstring GetEngineDllPath();
