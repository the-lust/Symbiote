#include "DeviceIoEmu.h"
#include <cstring>
#include <intrin.h>

// Type definition for NtDeviceIoControlFile
typedef long (NTAPI* NtDeviceIoControlFile_t)(
    void* FileHandle,
    void* Event,
    void* ApcRoutine,
    void* ApcContext,
    void* IoStatusBlock,
    uint32_t IoControlCode,
    void* InputBuffer,
    uint32_t InputBufferLength,
    void* OutputBuffer,
    uint32_t OutputBufferLength);

static NtDeviceIoControlFile_t Real_NtDeviceIoControlFile = nullptr;
static DeviceIoEmu* g_deviceIoInstance = nullptr;

// Inline hook trampoline
#pragma code_seg(".text")
__declspec(naked) void NtDeviceIoControlFile_Hook()
{
    __asm {
        // Save registers
        push rdi
        push rsi
        push rbx
        sub rsp, 0x28

        // Call our handler with all 10 arguments
        mov rcx, [rsp + 0x48]  // FileHandle
        mov rdx, [rsp + 0x50]  // Event
        mov r8,  [rsp + 0x58]  // ApcRoutine
        mov r9,  [rsp + 0x60]  // ApcContext
        // Stack args
        mov rax, [rsp + 0x68]
        mov [rsp + 0x20], rax  // IoStatusBlock
        mov rax, [rsp + 0x70]
        mov [rsp + 0x28], rax  // IoControlCode
        // Call the C++ handler
        call DeviceIoEmu::HandleDeviceIoControl

        // Restore stack and cleanup
        add rsp, 0x28
        pop rbx
        pop rsi
        pop rdi
        ret
    }
}
#pragma code_seg()

DeviceIoEmu::DeviceIoEmu(Logger* logger)
    : m_logger(logger), m_whpHandle(nullptr), m_initialized(false),
      m_originalFunc(nullptr), m_hookInstalled(false)
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

    // Get real NtDeviceIoControlFile address
    Real_NtDeviceIoControlFile = (NtDeviceIoControlFile_t)
        GetProcAddress(hNtdll, "NtDeviceIoControlFile");
    if (!Real_NtDeviceIoControlFile) {
        m_logger->Trace(LOG_ERROR, "DeviceIoEmu: cannot find NtDeviceIoControlFile");
        return false;
    }

    m_originalFunc = (void*)Real_NtDeviceIoControlFile;
    g_deviceIoInstance = this;

    // Save original bytes for trampoline
    memcpy(m_originalBytes, m_originalFunc, 12);

    // Install the hook
    if (!InstallHook()) {
        m_logger->Trace(LOG_ERROR, "DeviceIoEmu: hook installation failed");
        return false;
    }

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "DeviceIoEmu: NtDeviceIoControlFile hook installed");
    return true;
}

void DeviceIoEmu::Shutdown()
{
    if (!m_initialized) return;

    RemoveHook();
    Real_NtDeviceIoControlFile = nullptr;
    g_deviceIoInstance = nullptr;
    m_initialized = false;

    m_logger->Trace(LOG_INFO, "DeviceIoEmu: shutdown");
}

bool DeviceIoEmu::InstallHook()
{
    DWORD oldProtect;
    if (!VirtualProtect(m_originalFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    // Write 12-byte jmp: mov rax, address; jmp rax
    uint8_t* p = (uint8_t*)m_originalFunc;
    p[0] = 0x48; p[1] = 0xB8;  // mov rax, imm64
    *(uint64_t*)&p[2] = (uint64_t)(uintptr_t)NtDeviceIoControlFile_Hook;
    p[10] = 0xFF; p[11] = 0xE0;  // jmp rax

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
    if (m_whpHandle == handle) {
        m_whpHandle = nullptr;
    }
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
    DeviceIoEmu* instance = g_deviceIoInstance;
    if (!instance || !Real_NtDeviceIoControlFile) {
        return false; // Fall through to real implementation
    }

    // Only intercept WHP-related IOCTLs
    bool isWhpIoctl = false;
    switch (ioControlCode) {
        case IOCTL_WHV_GET_PARTITION_PROPERTY:
        case IOCTL_WHV_SET_PARTITION_PROPERTY:
        case IOCTL_WHV_CREATE_VIRTUAL_PROCESSOR:
        case IOCTL_WHV_RUN_VIRTUAL_PROCESSOR:
        case IOCTL_WHV_MAP_GPA_RANGE:
        case IOCTL_WHV_UNMAP_GPA_RANGE:
        case IOCTL_WHV_GET_VP_REGISTERS:
        case IOCTL_WHV_SET_VP_REGISTERS:
            isWhpIoctl = true;
            break;
    }

    if (!isWhpIoctl) {
        return false; // Non-WHP IOCTL, fall through
    }

    // Log the WHP IOCTL call for analysis
    instance->m_logger->Trace(LOG_EMU,
        "WHP IOCTL intercepted: code=0x%08X inLen=%u outLen=%u handle=%p",
        ioControlCode, inputBufferLength, outputBufferLength, fileHandle);

    // For WHvGetPartitionProperty, we can optionally spoof properties
    if (ioControlCode == IOCTL_WHV_GET_PARTITION_PROPERTY && outputBuffer && outputBufferLength >= 8) {
        // Read the property code from input buffer
        if (inputBuffer && inputBufferLength >= 4) {
            uint32_t propertyCode = *(uint32_t*)inputBuffer;
            instance->m_logger->Trace(LOG_EMU,
                "WHP GET_PARTITION_PROPERTY: code=0x%08X", propertyCode);

            // Intercept specific property queries
            // Return spoofed values for anti-detection
            if (propertyCode == WHP_PARTITION_PROPERTY_CODE_PROCESSOR_COUNT && outputBufferLength >= 4) {
                *(uint32_t*)outputBuffer = 2; // Spoof to 2 processors
                if (result) *result = 0; // STATUS_SUCCESS
                instance->m_logger->Trace(LOG_INFO,
                    "WHP partition property spoofed: ProcessorCount -> 2");
                return true;
            }
        }
    }

    // For WHvRunVirtualProcessor, we can monitor timing
    if (ioControlCode == IOCTL_WHV_RUN_VIRTUAL_PROCESSOR) {
        instance->m_logger->Trace(LOG_EMU,
            "WHP RUN_VIRTUAL_PROCESSOR: inLen=%u", inputBufferLength);
    }

    // WHvCreateVirtualProcessor - log and pass through
    if (ioControlCode == IOCTL_WHV_CREATE_VIRTUAL_PROCESSOR) {
        instance->m_logger->Trace(LOG_INFO,
            "WHP CREATE_VIRTUAL_PROCESSOR detected");
    }

    // Pass through to real implementation
    return false;
}
