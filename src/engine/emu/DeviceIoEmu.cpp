#include "DeviceIoEmu.h"
#include <cstring>

typedef long (NTAPI* NtDeviceIoControlFile_t)(
    void* FileHandle, void* Event, void* ApcRoutine, void* ApcContext,
    void* IoStatusBlock, uint32_t IoControlCode,
    void* InputBuffer, uint32_t InputBufferLength,
    void* OutputBuffer, uint32_t OutputBufferLength);

static NtDeviceIoControlFile_t Real_NtDeviceIoControlFile = nullptr;
static DeviceIoEmu* g_deviceIoInstance = nullptr;

// Hook trampoline — receives control from the 12-byte patch at NtDeviceIoControlFile.
// The calling convention matches the original NtDeviceIoControlFile signature,
// so all arguments arrive in correct registers/stack.
extern "C" long NTAPI NtDeviceIoControlFile_Hook(
    void* fileHandle, void* event, void* apcRoutine, void* apcContext,
    void* ioStatusBlock, uint32_t ioControlCode,
    void* inputBuffer, uint32_t inputBufferLength,
    void* outputBuffer, uint32_t outputBufferLength)
{
    DeviceIoEmu* inst = g_deviceIoInstance;
    if (inst && Real_NtDeviceIoControlFile) {
        uint64_t result = 0;
        if (inst->HandleDeviceIoControl(
                fileHandle, event, apcRoutine, apcContext,
                ioStatusBlock, ioControlCode,
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &result)) {
            return (long)result;
        }
        // Unhandled: temporarily restore original bytes, call real function, re-hook
        inst->RemoveHook();
        long status = Real_NtDeviceIoControlFile(
            fileHandle, event, apcRoutine, apcContext,
            ioStatusBlock, ioControlCode,
            inputBuffer, inputBufferLength,
            outputBuffer, outputBufferLength);
        inst->InstallHook();
        return status;
    }
    if (Real_NtDeviceIoControlFile) {
        return Real_NtDeviceIoControlFile(
            fileHandle, event, apcRoutine, apcContext,
            ioStatusBlock, ioControlCode,
            inputBuffer, inputBufferLength,
            outputBuffer, outputBufferLength);
    }
    return 0xC0000001; // STATUS_UNSUCCESSFUL
}

DeviceIoEmu::DeviceIoEmu(Logger* logger)
    : m_logger(logger), m_whpHandle(nullptr), m_initialized(false),
      m_originalFunc(nullptr), m_hookInstalled(false),
      m_spoofedProcCount(2), m_spoofedTscFreq(3700000000ULL),
      m_totalIoctlCalls(0), m_spoofedResponses(0)
{
    memset(m_originalBytes, 0, sizeof(m_originalBytes));
}

DeviceIoEmu::~DeviceIoEmu()
{
    Shutdown();
}

bool DeviceIoEmu::Initialize()
{
    if (m_initialized) return true;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        m_logger->Trace(LOG_ERROR, "DeviceIoEmu: cannot find ntdll.dll");
        return false;
    }

    Real_NtDeviceIoControlFile = (NtDeviceIoControlFile_t)
        GetProcAddress(hNtdll, "NtDeviceIoControlFile");
    if (!Real_NtDeviceIoControlFile) {
        m_logger->Trace(LOG_ERROR, "DeviceIoEmu: cannot find NtDeviceIoControlFile");
        return false;
    }

    m_originalFunc = (void*)Real_NtDeviceIoControlFile;
    g_deviceIoInstance = this;

    memcpy(m_originalBytes, m_originalFunc, 12);

    if (!InstallHook()) {
        m_logger->Trace(LOG_ERROR, "DeviceIoEmu: hook installation failed");
        return false;
    }

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "DeviceIoEmu: NtDeviceIoControlFile hook installed (all WHP IOCTLs intercepted)");
    return true;
}

void DeviceIoEmu::Shutdown()
{
    if (!m_initialized) return;
    RemoveHook();
    Real_NtDeviceIoControlFile = nullptr;
    g_deviceIoInstance = nullptr;
    m_initialized = false;
    m_logger->Trace(LOG_INFO, "DeviceIoEmu: shutdown (total IOCTLs=%llu spoofed=%llu)",
        m_totalIoctlCalls, m_spoofedResponses);
}

bool DeviceIoEmu::InstallHook()
{
    DWORD oldProtect;
    if (!VirtualProtect(m_originalFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    uint8_t* p = (uint8_t*)m_originalFunc;
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t*)&p[2] = (uint64_t)(uintptr_t)NtDeviceIoControlFile_Hook;
    p[10] = 0xFF; p[11] = 0xE0;

    VirtualProtect(m_originalFunc, 12, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), m_originalFunc, 12);
    m_hookInstalled = true;
    return true;
}

bool DeviceIoEmu::RemoveHook()
{
    if (!m_hookInstalled || !m_originalFunc) return false;
    DWORD oldProtect;
    VirtualProtect(m_originalFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(m_originalFunc, m_originalBytes, 12);
    VirtualProtect(m_originalFunc, 12, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), m_originalFunc, 12);
    m_hookInstalled = false;
    return true;
}

void DeviceIoEmu::RegisterWhpHandle(void* handle)
{
    m_whpHandle = handle;
    m_logger->Trace(LOG_INFO, "DeviceIoEmu: WHP handle registered: %p", handle);
}

void DeviceIoEmu::UnregisterWhpHandle(void* handle)
{
    if (m_whpHandle == handle) m_whpHandle = nullptr;
}

bool DeviceIoEmu::IsWhpHandle(void* handle) const
{
    return (handle == m_whpHandle);
}

bool DeviceIoEmu::HandleDeviceIoControl(
    void* fileHandle, void* event, void* apcRoutine, void* apcContext,
    void* ioStatusBlock, uint32_t ioControlCode,
    void* inputBuffer, uint32_t inputBufferLength,
    void* outputBuffer, uint32_t outputBufferLength,
    uint64_t* result)
{
    (void)fileHandle;
    (void)event;
    (void)apcRoutine;
    (void)apcContext;
    (void)ioStatusBlock;
    DeviceIoEmu* inst = g_deviceIoInstance;
    if (!inst || !Real_NtDeviceIoControlFile) return false;

    // Check if this is a WHP IOCTL
    bool isWhpIoctl = false;
    switch (ioControlCode) {
        case IOCTL_WHV_GET_PARTITION_PROPERTY:
        case IOCTL_WHV_SET_PARTITION_PROPERTY:
        case IOCTL_WHV_CREATE_VIRTUAL_PROCESSOR:
        case IOCTL_WHV_RUN_VIRTUAL_PROCESSOR:
        case IOCTL_WHV_TERMINATE_VIRTUAL_PROCESSOR:
        case IOCTL_WHV_MAP_GPA_RANGE:
        case IOCTL_WHV_UNMAP_GPA_RANGE:
        case IOCTL_WHV_GET_VP_REGISTERS:
        case IOCTL_WHV_SET_VP_REGISTERS:
        case IOCTL_WHV_SET_PARTITION_PROPERTY_VP_COUNT:
        case IOCTL_WHV_QUERY_PARTITION_PROPERTIES:
        case IOCTL_WHV_GET_PARTITION_COUNT:
        case IOCTL_WHV_GET_PARTITION_ID:
            isWhpIoctl = true;
            break;
    }

    if (!isWhpIoctl) return false;

    inst->m_totalIoctlCalls++;
    inst->m_ioctlCounters[ioControlCode]++;

    // Handle WHvGetPartitionProperty - return configured values
    if (ioControlCode == IOCTL_WHV_GET_PARTITION_PROPERTY) {
        if (inst->HandleGetPartitionProperty(inputBuffer, inputBufferLength,
                                              outputBuffer, outputBufferLength, result)) {
            inst->m_spoofedResponses++;
            return true;
        }
        // Fall through to real implementation
    }

    // Log the IOCTL at high frequency for analysis
    if (inst->m_totalIoctlCalls % 100 == 1) {
        inst->m_logger->Trace(LOG_EMU,
            "WHP IOCTL #%llu: code=0x%08X inLen=%u outLen=%u",
            inst->m_totalIoctlCalls, ioControlCode, inputBufferLength, outputBufferLength);
    }

    return false; // Fall through to real NtDeviceIoControlFile
}

bool DeviceIoEmu::HandleGetPartitionProperty(
    void* inputBuffer, uint32_t inputLength,
    void* outputBuffer, uint32_t outputLength,
    uint64_t* result)
{
    if (!inputBuffer || inputLength < sizeof(uint32_t)) return false;
    if (!outputBuffer || outputLength < sizeof(uint32_t)) return false;

    uint32_t propertyCode = *(uint32_t*)inputBuffer;
    bool spoofed = false;
    uint64_t spoofedValue = 0;

    switch (propertyCode) {
        case WHP_PROP_PROCESSOR_COUNT:
            spoofed = true;
            spoofedValue = m_spoofedProcCount;
            m_logger->Trace(LOG_INFO, "WHP property spoofed: ProcessorCount -> %u", m_spoofedProcCount);
            break;

        case WHP_PROP_VP_COUNT:
            spoofed = true;
            spoofedValue = m_spoofedProcCount;
            m_logger->Trace(LOG_INFO, "WHP property spoofed: VpCount -> %u", m_spoofedProcCount);
            break;

        case WHP_PROP_TSC_FREQUENCY:
            spoofed = true;
            spoofedValue = m_spoofedTscFreq;
            m_logger->Trace(LOG_INFO, "WHP property spoofed: TscFrequency -> %llu", m_spoofedTscFreq);
            break;

        case WHP_PROP_HYPERVISOR_PRESENT:
            spoofed = true;
            spoofedValue = 0; // FALSE - no hypervisor present
            m_logger->Trace(LOG_INFO, "WHP property spoofed: HypervisorPresent -> FALSE");
            break;

        case WHP_PROP_XSAVE_ENABLED:
            spoofed = true;
            spoofedValue = 1; // TRUE - XSAVE is enabled on modern CPUs
            break;

        case WHP_PROP_LOCAL_APIC_MODE:
            spoofed = true;
            spoofedValue = 1; // xAPIC mode
            break;

        case WHP_PROP_X2APIC_ENABLED:
            spoofed = true;
            spoofedValue = 1; // TRUE - x2APIC enabled on modern CPUs
            break;

        case WHP_PROP_VIRTUALIZATION_ENABLED:
            spoofed = true;
            spoofedValue = 0; // FALSE - no virtualization extensions visible
            break;

        case WHP_PROP_SYSTEM_PROFILE:
            spoofed = true;
            spoofedValue = 0; // Default profile
            break;

        case WHP_PROP_EXTENDED_VMEXITS:
            spoofed = true;
            spoofedValue = 0; // No extended VM exits
            break;

        case WHP_PROP_PARTITION_DEBUG:
            spoofed = true;
            spoofedValue = 0; // Debug disabled
            break;

        case WHP_PROP_GUEST_CRASH_MSRS:
            spoofed = true;
            spoofedValue = 0; // No crash MSRs enabled
            break;

        default:
            // Unknown property - let through
            m_logger->Trace(LOG_EMU, "WHP property query (passthrough): code=0x%08X", propertyCode);
            return false;
    }

    if (spoofed && outputBuffer && outputLength >= sizeof(uint64_t)) {
        memset(outputBuffer, 0, outputLength);
        // Property values are returned differently depending on property:
        // For most properties, the value is written directly to output buffer
        if (outputLength >= 8) {
            *(uint64_t*)outputBuffer = spoofedValue;
        } else if (outputLength >= 4) {
            *(uint32_t*)outputBuffer = (uint32_t)spoofedValue;
        }

        // Set IO status block if passed via the hook
        if (result) *result = 0; // STATUS_SUCCESS

        return true;
    }

    return false;
}
