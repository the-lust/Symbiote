#include "SoGenBridge.h"
#include "sogen/SoGenEmulator.h"

// Set by engine Main.cpp after SoGen emulator is created
static SoGenEmulator* g_bridgeSoGen = nullptr;

void SetSoGenBridge(SoGenEmulator* emu)
{
    g_bridgeSoGen = emu;
}

#pragma comment(linker, "/EXPORT:SoGenRouteSyscall=SoGenRouteSyscall")

bool __stdcall SoGenRouteSyscall(uint64_t syscallNumber, uint64_t* args, uint64_t* result)
{
    if (!g_bridgeSoGen) return false;
    return g_bridgeSoGen->EmulateSyscall(syscallNumber, args, result);
}
