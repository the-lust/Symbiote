#pragma once
#include <cstdint>

void SetSoGenBridge(class SoGenEmulator* emu);

extern "C" bool __stdcall SoGenRouteSyscall(uint64_t syscallNumber, uint64_t* args, uint64_t* result);
