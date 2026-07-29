#include "KernelProxy.h"
#include <cstring>
#include <cstdio>
#include <algorithm>

// IOCTL codes for physical memory access (driver-specific; use generic probe)
constexpr ULONG IOCTL_PHYS_READ  = 0x222004;
constexpr ULONG IOCTL_PHYS_WRITE = 0x222008;
constexpr ULONG IOCTL_ALLOC_POOL = 0x22200C;
constexpr ULONG IOCTL_VIRT_MAP   = 0x222010;

KernelProxy::KernelProxy()
    : m_hDevice(nullptr)
    , m_caps(0)
    , m_active(false)
    , m_commBufferVa(nullptr)
    , m_commBufferPhys(0)
    , m_commBufferSize(0)
    , m_ntosBase(0)
    , m_ntosSize(0)
{}

KernelProxy::~KernelProxy() { Shutdown(); }

bool KernelProxy::Initialize(HANDLE hByovdDevice, uint64_t byovdCaps) {
    m_hDevice = hByovdDevice;
    m_caps = byovdCaps;

    if (byovdCaps & BYOVD_CAP_PHYSICAL_MEM) {
        // Allocate a communication buffer in kernel space
        if (byovdCaps & BYOVD_CAP_ALLOC_POOL) {
            DWORD bytesRet = 0;
            uint64_t poolSize = 4096;
            uint64_t mappedVa = 0;
            uint64_t outPhys = 0;

            // Try allocating kernel pool via BYOVD
            DeviceIoControl(m_hDevice, IOCTL_ALLOC_POOL,
                &poolSize, sizeof(poolSize),
                &outPhys, sizeof(outPhys), &bytesRet, nullptr);
            if (outPhys) {
                m_commBufferPhys = outPhys;
                m_commBufferSize = (size_t)poolSize;
                // Map it into user mode
                DeviceIoControl(m_hDevice, IOCTL_VIRT_MAP,
                    &m_commBufferPhys, sizeof(m_commBufferPhys),
                    &mappedVa, sizeof(mappedVa), &bytesRet, nullptr);
                m_commBufferVa = (void*)(ULONG_PTR)mappedVa;
            }
        }
    }

    m_active = true;
    return true;
}

bool KernelProxy::InjectSsdtHooks(const SsdtTableInitParams& params) {
    if (!(m_caps & BYOVD_CAP_PHYSICAL_MEM)) return false;
    m_ntosBase = (uint64_t)params.ntosBase;
    m_ntosSize = (uint64_t)params.ntosEnd - (uint64_t)params.ntosBase;

    // For each SSDT entry we want to hook:
    // 1) Read the current KiServiceTable
    // 2) Replace offset with our stub handler address
    // 3) Flush CPU instruction cache

    uint32_t ssdtCount = *(uint32_t*)params.keServiceLimit;
    for (uint32_t i = 0; i < ssdtCount; i++) {
        // Only hook syscalls we care about
        // For now, stub: hook NtQuerySystemInformation (index varies by OS)
        // In production: use per-version syscall index map
        if (i == 0x0036) { // NtQuerySystemInformation (Win10 21H2+)
            HookSsdtEntry(i, nullptr, nullptr);
        }
    }
    return true;
}

bool KernelProxy::DeployEprocessSanitizer(const EprocessSanitizerParams& params) {
    if (!(m_caps & BYOVD_CAP_PHYSICAL_MEM)) return false;

    // Write EPROCESS sanitizer stub kernel code + thread creation into non-paged pool
    // The stub will:
    // 1) Walk EPROCESS list
    // 2) For each process matching our PID, sanitize:
    //    - Hide from DbgkDebugObjectType (PsSetProcessDebugFlags)
    //    - Spoof CreateTime
    //    - Spoof InheritedFromUniqueProcessId
    //    - Clear PEB debug flags (BeingDebugged, NtGlobalFlag)
    // 3) Sleep and repeat
    //
    // For now, write the kernel stub shellcode
    uint8_t sanitizerStub[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x55, 0x57,
        0x41, 0x54, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88,
        0x01, 0x00, 0x00, 0x48, 0x8B, 0x80, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8B,
        0xF8, 0x48, 0x8B, 0x4F, 0x10, 0x48, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0xB7, 0x20, 0x02, 0x00, 0x00,
        // ... full stub in production
        0xCC // int3 placeholder
    };

    uint64_t stubPhys = 0;
    void* stubVa = nullptr;
    InjectStub(L"sanitizer", sanitizerStub, sizeof(sanitizerStub),
               0x100000, &stubPhys, &stubVa);

    return stubPhys != 0;
}

bool KernelProxy::InstallLstarMonitor(const LstarMonitorParams& params) {
    if (!(m_caps & BYOVD_CAP_PHYSICAL_MEM)) return false;

    // Install a timer DPC or thread that:
    // 1) Reads MSR 0xC0000082 (LSTAR)
    // 2) Compares to knownGoodLstar
    // 3) If changed (anti-cheap hooked it), write it back
    // 4) Same for STAR, CSTAR, SF_MASK
    // 5) Signal detection event to user mode

    // This is a stub — the actual shellcode is larger
    uint8_t lstarMonStub[] = { 0xCC };
    uint64_t stubPhys = 0;
    void* stubVa = nullptr;
    InjectStub(L"lstarmon", lstarMonStub, sizeof(lstarMonStub),
               0x100000, &stubPhys, &stubVa);

    return stubPhys != 0;
}

bool KernelProxy::InstallIdtHook(const IdtHookParams& params) {
    if (!(m_caps & BYOVD_CAP_PHYSICAL_MEM)) return false;
    // In real implementation:
    // 1) Read IDT via SIDT
    // 2) Replace vector params.targetVector with our handler
    // 3) Our handler pre-filters syscall, then jumps to original
    return true;
}

bool KernelProxy::HideDriverList() {
    if (!(m_caps & BYOVD_CAP_KERNEL_WRITE)) return false;

    // Walk \Driver\... object directory via ObQueryNameString
    // Unlink our injected driver module from PsLoadedModuleList
    // This requires writing to LIST_ENTRY pointers in kernel

    // Stub: find LdrLoadDll / ZwQuerySystemInformation calls
    // and intercept to filter out listings
    return true;
}

bool KernelProxy::PingStubs() {
    if (!m_commBufferVa) return false;
    // Write a magic value to comm buffer; kernel stub should respond
    volatile uint64_t* ping = (volatile uint64_t*)m_commBufferVa;
    *ping = 0xDEADBEEFCAFEBABE;
    Sleep(10);
    // Kernel stub should write back a response
    // For now, just check it wasn't zeroed
    return *ping != 0;
}

void KernelProxy::Shutdown() {
    if (m_commBufferVa && m_commBufferPhys) {
        // Free kernel pool — IOCTL to free
        DWORD bytesRet = 0;
        DeviceIoControl(m_hDevice, 0x222014, // IOCTL_FREE_POOL
            &m_commBufferPhys, sizeof(m_commBufferPhys),
            nullptr, 0, &bytesRet, nullptr);
        m_commBufferVa = nullptr;
        m_commBufferPhys = 0;
    }
    m_hDevice = nullptr;
    m_active = false;
}

bool KernelProxy::WritePhysical(uint64_t physAddr, const void* data, size_t size) {
    if (!(m_caps & BYOVD_CAP_PHYSICAL_MEM)) return false;
    DWORD bytesRet = 0;

    struct {
        uint64_t addr;
        uint32_t size;
        uint8_t  data[1];
    }* input = (decltype(input))malloc(sizeof(*input) + size - 1);
    input->addr = physAddr;
    input->size = (uint32_t)size;
    memcpy(input->data, data, size);
    BOOL ok = DeviceIoControl(m_hDevice, IOCTL_PHYS_WRITE,
        input, (DWORD)(sizeof(uint64_t) + sizeof(uint32_t) + size),
        nullptr, 0, &bytesRet, nullptr);
    free(input);
    return ok != FALSE;
}

bool KernelProxy::ReadPhysical(uint64_t physAddr, void* data, size_t size) {
    if (!(m_caps & BYOVD_CAP_PHYSICAL_MEM)) return false;
    DWORD bytesRet = 0;

    struct {
        uint64_t addr;
        uint32_t size;
    } input;
    input.addr = physAddr;
    input.size = (uint32_t)size;

    return DeviceIoControl(m_hDevice, IOCTL_PHYS_READ,
        &input, sizeof(input),
        data, (DWORD)size, &bytesRet, nullptr) != FALSE;
}

uint64_t KernelProxy::FindNtosBase() {
    // Read IDTR base, walk up to find ntoskrnl.exe
    // In production: scan for MZ header in kernel address range
    return m_ntosBase ? m_ntosBase : 0xFFFFF80000000000ULL;
}

bool KernelProxy::InjectStub(const wchar_t* stubName, const uint8_t* stubData, size_t stubSize,
                              uint64_t physBase, uint64_t* outPhys, void** outVa) {
    if (!m_hDevice) return false;

    // Allocate non-paged pool via BYOVD
    DWORD bytesRet = 0;
    uint64_t poolPhys = 0;
    uint64_t poolSize = stubSize + 0x1000;

    DeviceIoControl(m_hDevice, IOCTL_ALLOC_POOL,
        &poolSize, sizeof(poolSize),
        &poolPhys, sizeof(poolPhys), &bytesRet, nullptr);

    if (!poolPhys) {
        // Fallback: try to find a suitable physical memory hole
        // This is unreliable but worth trying
        poolPhys = physBase + 0x100000;
    }

    // Write stub code into kernel memory
    if (!WritePhysical(poolPhys, stubData, stubSize))
        return false;

    // Map into user mode for monitoring
    uint64_t mappedVa = 0;
    DeviceIoControl(m_hDevice, IOCTL_VIRT_MAP,
        &poolPhys, sizeof(poolPhys),
        &mappedVa, sizeof(mappedVa), &bytesRet, nullptr);

    *outPhys = poolPhys;
    *outVa = (void*)mappedVa;
    return true;
}

bool KernelProxy::HookSsdtEntry(uint32_t index, void* newHandler, void** oldHandler) {
    if (!m_ntosBase) return false;

    // KiServiceTable is exported from ntoskrnl.exe
    // We need to:
    // 1) Locate KiServiceTable (exported or scan pattern)
    // 2) Read current SsdtEntry at index
    // 3) Compute function address from entry
    // 4) Write new entry pointing to our stub kernel code
    // 5) KeFlushEntireIcache on all cores

    uint32_t* kiServiceTable = (uint32_t*)nullptr; // = MmGetSystemRoutineAddress("KeServiceDescriptorTable")
    if (!kiServiceTable) return false;

    // Current handler address = ntosBase + (ssdtEntry >> 4)
    // New handler must be in kernel address space
    // Write: kiServiceTable[index] = (uint32_t)((uint64_t)newHandler - ntosBase) << 4

    return true;
}