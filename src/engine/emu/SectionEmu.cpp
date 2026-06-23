#define WIN32_NO_STATUS
#include "SectionEmu.h"
#include <windows.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// SECTION_INHERIT might not be defined in older SDKs
#ifndef ViewShare
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
#endif

SectionEmu::SectionEmu(Logger* logger)
    : m_logger(logger), m_nextHandle(0x1000)
{
}

SectionEmu::~SectionEmu()
{
    for (auto& sec : m_sections) {
        if (sec.handle) CloseHandle(sec.handle);
    }
}

// declare NT func ptrs since not always in headers
typedef NTSTATUS (WINAPI* NtCreateSectionFunc)(PHANDLE, ACCESS_MASK, void*, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (WINAPI* NtOpenSectionFunc)(PHANDLE, ACCESS_MASK, void*);
typedef NTSTATUS (WINAPI* NtMapViewOfSectionFunc)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS (WINAPI* NtUnmapViewOfSectionFunc)(HANDLE, PVOID);

static NtCreateSectionFunc g_realNtCreateSection = nullptr;
static NtOpenSectionFunc g_realNtOpenSection = nullptr;
static NtMapViewOfSectionFunc g_realNtMapViewOfSection = nullptr;
static NtUnmapViewOfSectionFunc g_realNtUnmapViewOfSection = nullptr;

static bool EnsureFuncs()
{
    if (!g_realNtCreateSection) {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (!nt) return false;
        g_realNtCreateSection = (NtCreateSectionFunc)GetProcAddress(nt, "NtCreateSection");
        g_realNtOpenSection = (NtOpenSectionFunc)GetProcAddress(nt, "NtOpenSection");
        g_realNtMapViewOfSection = (NtMapViewOfSectionFunc)GetProcAddress(nt, "NtMapViewOfSection");
        g_realNtUnmapViewOfSection = (NtUnmapViewOfSectionFunc)GetProcAddress(nt, "NtUnmapViewOfSection");
    }
    return g_realNtCreateSection != nullptr;
}

bool SectionEmu::HandleNtCreateSection(uint64_t* args, uint64_t* result)
{
    if (!EnsureFuncs()) return false;

    uint64_t maxSize = args[3];
    uint32_t protect = (uint32_t)args[4];
    uint32_t allocAttr = (uint32_t)args[5];
    HANDLE fileHandle = (HANDLE)args[6];

    HANDLE sectionHandle = nullptr;
    NTSTATUS status = g_realNtCreateSection(&sectionHandle, (ACCESS_MASK)args[1],
        nullptr, (PLARGE_INTEGER)&maxSize, protect, allocAttr, fileHandle);

    if (NT_SUCCESS(status)) {
        SectionInfo info;
        info.handle = sectionHandle;
        info.size = maxSize;
        info.protect = protect;
        m_sections.push_back(info);

        *(HANDLE*)(uintptr_t)args[0] = sectionHandle;
        m_logger->Trace(LOG_EMU, "NtCreateSection: handle=%p size=%llu", sectionHandle, maxSize);
    }

    if (result) *result = (uint64_t)status;
    return true;
}

bool SectionEmu::HandleNtOpenSection(uint64_t* args, uint64_t* result)
{
    if (!EnsureFuncs()) return false;

    HANDLE sectionHandle = nullptr;
    NTSTATUS status = g_realNtOpenSection(&sectionHandle, (ACCESS_MASK)args[1],
        (void*)args[2]);

    if (NT_SUCCESS(status)) {
        *(HANDLE*)(uintptr_t)args[0] = sectionHandle;
    }

    if (result) *result = (uint64_t)status;
    return true;
}

bool SectionEmu::HandleNtMapViewOfSection(uint64_t* args, uint64_t* result)
{
    if (!EnsureFuncs()) return false;

    HANDLE sectionHandle = (HANDLE)args[0];
    HANDLE processHandle = (HANDLE)args[1];
    PVOID* baseAddr = (PVOID*)(uintptr_t)args[2];
    ULONG_PTR zeroBits = (ULONG_PTR)args[3];
    SIZE_T commitSize = (SIZE_T)args[4];
    PLARGE_INTEGER sectionOffset = (PLARGE_INTEGER)args[5];
    PSIZE_T viewSize = (PSIZE_T)args[6];
    SECTION_INHERIT inherit = (SECTION_INHERIT)args[7];
    ULONG allocType = (ULONG)args[8];
    ULONG protect = (ULONG)args[9];

    NTSTATUS status = g_realNtMapViewOfSection(sectionHandle, processHandle, baseAddr,
        zeroBits, commitSize, sectionOffset, viewSize, inherit, allocType, protect);

    if (result) *result = (uint64_t)status;
    return true;
}

bool SectionEmu::HandleNtUnmapViewOfSection(uint64_t* args, uint64_t* result)
{
    if (!EnsureFuncs()) return false;

    HANDLE processHandle = (HANDLE)args[0];
    PVOID baseAddr = (PVOID)args[1];

    NTSTATUS status = g_realNtUnmapViewOfSection(processHandle, baseAddr);

    if (result) *result = (uint64_t)status;
    return true;
}