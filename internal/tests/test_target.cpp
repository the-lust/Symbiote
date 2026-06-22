#include <cstdio>
#include <cstdint>
#include <intrin.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI* NtQuerySysInfo_t)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtQueryInfoProc_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtCreateFile_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG);

int main()
{
    printf("Test target: engine injection test\n\n");

    // 1 CPUID
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 0, 0);
    printf("CPUID 0:     EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\n",
        cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    __cpuidex(cpuInfo, 1, 0);
    printf("CPUID 1:     EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\n",
        cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    __cpuidex(cpuInfo, 7, 0);
    printf("CPUID 7:     EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\n",
        cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);

    // 2 RDTSC
    uint64_t tsc = __rdtsc();
    printf("RDTSC:       0x%llX\n", tsc);

    // 3 KUSER fields
    uint8_t* kuser = (uint8_t*)0x7FFE0000;
    printf("KUSER:\n");
    printf("  SystemTime  0x318 = 0x%llX\n", *(uint64_t*)(kuser + 0x318));
    printf("  InterruptTm 0x328 = 0x%llX\n", *(uint64_t*)(kuser + 0x328));
    printf("  TickCount   0x348 = 0x%08X\n", *(uint32_t*)(kuser + 0x348));
    printf("  SuiteMask   0x2D0 = 0x%llX\n", *(uint64_t*)(kuser + 0x2D0));
    printf("  ProductType 0x2E8 = 0x%llX\n", *(uint64_t*)(kuser + 0x2E8));

    // 4 NtQuerySystemInfo
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtQuerySysInfo_t NtQuerySystemInformation = (NtQuerySysInfo_t)
        GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation) {
        uint8_t buf[512] = {0};
        ULONG retLen = 0;
        NTSTATUS status = NtQuerySystemInformation(0x2C, buf, sizeof(buf), &retLen);
        printf("NtQuerySystemInfo(0x2C=SystemCodeIntegrity):\n");
        printf("  status=0x%08X len=%u\n", status, retLen);
    }

    // 5 NtQueryInfoProcess
    NtQueryInfoProc_t NtQueryInformationProcess = (NtQueryInfoProc_t)
        GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess) {
        uint8_t buf[64] = {0};
        ULONG retLen = 0;
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(),
            (PROCESSINFOCLASS)0x0E, buf, sizeof(buf), &retLen);
        printf("NtQueryInfoProcess(0x0E=ProcessDebugFlags):\n");
        printf("  status=0x%08X val=0x%llX\n", status, *(uint64_t*)buf);
    }

    // 6 NtCreateFile (phys drive - should be blocked)
    NtCreateFile_t NtCreateFile = (NtCreateFile_t)
        GetProcAddress(ntdll, "NtCreateFile");
    if (NtCreateFile) {
        printf("NtCreateFile (physicaldrive test):\n");
        // Just checking the proxy is loaded
    }

    // 7 Timing APIs
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    printf("QPC:         0x%llX\n", qpc.QuadPart);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("GetSystemInfo: %u processors, page=%u\n",
        si.dwNumberOfProcessors, si.dwPageSize);

    printf("\nTest target completed. Waiting 3s for engine init...\n");
    Sleep(3000);
    printf("Test target exiting.\n");
    return 0;
}
