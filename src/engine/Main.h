#pragma once
#include <windows.h>

#define ENGINE_DLL_EXPORT __declspec(dllexport)

extern "C" {
ENGINE_DLL_EXPORT BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
ENGINE_DLL_EXPORT void Engine_SetDebug();
ENGINE_DLL_EXPORT void Engine_Init();
}

BOOL InstallHooks();
BOOL RemoveHooks();
