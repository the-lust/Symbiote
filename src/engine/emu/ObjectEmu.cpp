#include "ObjectEmu.h"
#include <windows.h>
#include <winternl.h>

ObjectEmu::ObjectEmu(Logger* logger)
    : m_logger(logger)
{
}

ObjectEmu::~ObjectEmu()
{
}

bool ObjectEmu::HandleNtQueryObject(uint64_t* args, uint64_t* result)
{
    HANDLE handle = (HANDLE)(uintptr_t)args[0];
    uint32_t infoClass = (uint32_t)args[1];
    void* infoBuf = (void*)(uintptr_t)args[2];
    uint32_t infoLen = (uint32_t)args[3];
    uint32_t* retLen = (uint32_t*)(uintptr_t)args[4];

    m_logger->Trace(LOG_EMU, "NtQueryObject: handle=%p class=%u len=%u", handle, infoClass, infoLen);

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) { if (result) *result = 0xC0000002; return true; }

    typedef NTSTATUS (WINAPI* NtQueryObjectFunc)(HANDLE, uint32_t, void*, uint32_t, uint32_t*);
    auto realNtQueryObject = (NtQueryObjectFunc)GetProcAddress(nt, "NtQueryObject");
    if (!realNtQueryObject) { if (result) *result = 0xC0000002; return true; }

    NTSTATUS status = realNtQueryObject(handle, infoClass, infoBuf, infoLen, retLen);
    if (result) *result = (uint64_t)status;
    return true;
}