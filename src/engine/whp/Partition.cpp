#include "Partition.h"
#include "CpuidHandler.h"
#include "GuestPageTable.h"
#include <winerror.h>

Partition::Partition(Logger* logger)
    : m_logger(logger), m_handle(nullptr), m_initialized(false), m_guestPageTable(nullptr)
{
}

Partition::~Partition()
{
    Destroy();
}

bool Partition::Create()
{
    HRESULT hr = WHvCreatePartition(&m_handle);
    if (FAILED(hr) || !m_handle) {
        m_logger->Trace(LOG_ERROR, "WHvCreatePartition failed: 0x%08X", hr);
        return false;
    }
    m_logger->Trace(LOG_WHP, "Partition created: handle=0x%p", m_handle);

    // Set MSR exit bitmap to intercept Hyper-V TLFS MSRs + standard MSRs
    if (!SetupMsrBitmap()) {
        m_logger->Trace(LOG_WARNING, "MSR bitmap setup failed - MSR interception may be limited");
    }

    // Set exception exit bitmap for #BP (syscall intercept) and #DB (single-step trampoline)
    if (!SetupExceptionBitmap()) {
        m_logger->Trace(LOG_WARNING, "Exception bitmap setup failed - syscall intercept may be limited");
    }

    return true;
}

bool Partition::SetupMsrBitmap()
{
    // Use WHV X64 MSR exit bitmap to intercept all unhandled MSRs
    // (including Hyper-V TLFS MSRs) plus specific standard MSRs
    WHV_X64_MSR_EXIT_BITMAP bitmap;
    bitmap.AsUINT64 = 0;
    bitmap.UnhandledMsrs = 1;        // All MSRs not natively handled by WHP (incl. Hyper-V TLFS)
    bitmap.TscMsrRead = 1;           // Intercept RDTSC/RDTSCP
    bitmap.TscMsrWrite = 1;          // Intercept WRMSR TSC
    bitmap.ApicBaseMsrWrite = 1;     // Intercept APIC_BASE writes
    bitmap.MiscEnableMsrRead = 1;    // Intercept MISC_ENABLE reads
    bitmap.McUpdatePatchLevelMsrRead = 1; // Intercept BIOS_SIGN_ID reads

    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeX64MsrExitBitmap,
        &bitmap, sizeof(bitmap));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(X64MsrExitBitmap) failed: 0x%08X", hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "MSR exit bitmap configured: UnhandledMsrs=1 Tsc=1 ApicBase=1 MiscEnable=1");
    return true;
}

bool Partition::SetupExceptionBitmap()
{
    if (!m_handle) return false;

    // Enable VM exits on #BP (0x03 = INT3) for raw syscall interception
    // and #DB (0x01 = single-step) for trampoline restore
    // Bitmap layout: bit N corresponds to exception vector N, where the
    // WHP-defined enum values map to exception vectors directly
    uint64_t exceptionBitmap = 0;
    exceptionBitmap |= (1ULL << 0x01); // #DB - single step (trampoline restore)
    exceptionBitmap |= (1ULL << 0x03); // #BP - breakpoint (syscall/RDMSR intercept)

    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeExceptionExitBitmap,
        &exceptionBitmap, sizeof(exceptionBitmap));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(ExceptionExitBitmap) failed: 0x%08X", hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "Exception exit bitmap configured: #BP=1 #DB=1");
    return true;
}

bool Partition::SetupCpuidResultList(CpuidHandler* cpuidHandler)
{
    if (!m_handle || !cpuidHandler) return false;

    // Pre-populate known CPUID leaves so WHP doesn't VM-exit for them
    // (from libkrun pattern — reduces overhead and detection surface)
    WHV_X64_CPUID_RESULT results[32];
    int count = 0;
    cpuidHandler->GetCpuidResultList(results, &count, 32);

    if (count == 0) {
        m_logger->Trace(LOG_WHP, "CpuidResultList empty — all leaves will VM-exit");
        return true;
    }

    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeCpuidResultList,
        results, (uint32_t)(count * sizeof(WHV_X64_CPUID_RESULT)));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(CpuidResultList) failed: 0x%08X", hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "CPUID result list set: %d leaves pre-populated", count);
    return true;
}

bool Partition::SetupCpuCount(uint32_t count)
{
    HRESULT hr = WHvSetPartitionProperty(m_handle,
        WHvPartitionPropertyCodeProcessorCount,
        &count, sizeof(count));
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetPartitionProperty(ProcessorCount) failed: 0x%08X, count=%u", hr, count);
        return false;
    }
    m_logger->Trace(LOG_WHP, "CPU count set to %u", count);
    return true;
}

bool Partition::SetupMemory(uint64_t sizeMB)
{
    m_logger->Trace(LOG_WHP, "Memory configured: %llu MB (partition-level property not required)", sizeMB);
    return true;
}

bool Partition::Init()
{
    if (!m_handle) return false;

    HRESULT hr = WHvSetupPartition(m_handle);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvSetupPartition failed: 0x%08X", hr);
        return false;
    }

    m_initialized = true;
    m_logger->Trace(LOG_WHP, "Partition initialized");
    return true;
}

bool Partition::MapProcessMemory(HANDLE hProcess)
{
    if (m_guestPageTable) {
        delete m_guestPageTable;
        m_guestPageTable = nullptr;
    }
    m_guestPageTable = new GuestPageTable(m_logger, this);
    if (!m_guestPageTable->Build(hProcess)) {
        m_logger->Trace(LOG_ERROR, "MapProcessMemory: GuestPageTable::Build failed");
        delete m_guestPageTable;
        m_guestPageTable = nullptr;
        return false;
    }
    m_logger->Trace(LOG_INFO, "MapProcessMemory: PML4 GPA=0x%llX, total=%llu pages",
        m_guestPageTable->GetPml4Gpa(), m_guestPageTable->GetTotalPages());
    return true;
}

void Partition::Destroy()
{
    delete m_guestPageTable;
    m_guestPageTable = nullptr;

    for (auto& block : m_guestMemory) {
        if (block.hostVa) {
            VirtualFree(block.hostVa, 0, MEM_RELEASE);
        }
    }
    m_guestMemory.clear();

    if (m_handle) {
        if (m_initialized) {
            WHvDeletePartition(m_handle);
        }
        m_handle = nullptr;
        m_initialized = false;
        m_logger->Trace(LOG_WHP, "Partition destroyed");
    }
}

bool Partition::MapGpaRange(void* hostVa, WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes, WHV_MAP_GPA_RANGE_FLAGS flags)
{
    if (!m_handle || !m_initialized) {
        m_logger->Trace(LOG_ERROR, "MapGpaRange: partition not ready");
        return false;
    }

    HRESULT hr = WHvMapGpaRange(m_handle, hostVa, guestPa, sizeInBytes, flags);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvMapGpaRange(guestPa=0x%llX, size=%llu) failed: 0x%08X", guestPa, sizeInBytes, hr);
        return false;
    }

    m_logger->Trace(LOG_WHP, "GPA range mapped: hostVa=%p guestPa=0x%llX size=%llu flags=0x%X", hostVa, guestPa, sizeInBytes, (uint32_t)flags);
    return true;
}

bool Partition::UnmapGpaRange(WHV_GUEST_PHYSICAL_ADDRESS guestPa, uint64_t sizeInBytes)
{
    if (!m_handle || !m_initialized) return false;

    HRESULT hr = WHvUnmapGpaRange(m_handle, guestPa, sizeInBytes);
    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "WHvUnmapGpaRange(guestPa=0x%llX) failed: 0x%08X", guestPa, hr);
        return false;
    }
    return true;
}

void* Partition::AllocateGuestMemory(uint64_t sizeInBytes)
{
    void* ptr = VirtualAlloc(NULL, sizeInBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr) {
        m_guestMemory.push_back({ptr, sizeInBytes});
    }
    return ptr;
}

void Partition::FreeGuestMemory(void* ptr)
{
    for (size_t i = 0; i < m_guestMemory.size(); i++) {
        if (m_guestMemory[i].hostVa == ptr) {
            VirtualFree(ptr, 0, MEM_RELEASE);
            m_guestMemory.erase(m_guestMemory.begin() + i);
            return;
        }
    }
}
