// ProxyExportTable.h — shared helper for proxy DLLs to resolve engine exports
// via Engine_GetExport (the sole named export of engine.dll).
//
// Usage: call Engine_GetExport(FUNC_ID) to get any engine function pointer.
// The funcId constants below must match EngineExports.cpp's ExportFuncId enum.
#pragma once
#include <windows.h>
#include <cstdint>

// Function IDs — shared between EngineExports.cpp and all proxy DLLs
enum ProxyFuncId : uint32_t {
    // HwIdEmu
    FUNC_HWID_GET_DISK_COUNT        = 1,
    FUNC_HWID_GET_DISK              = 2,
    FUNC_HWID_GET_SYSTEM_INFO       = 3,
    FUNC_HWID_GET_VOLUME_SERIAL     = 4,
    // Firmware tables
    FUNC_FW_GET_SMBIOS              = 5,
    FUNC_FW_GET_ACPI                = 6,
    FUNC_FW_GET_FIRMWARE            = 7,
    FUNC_FW_SANITIZE_SMBIOS         = 8,
    FUNC_FW_SANITIZE_ACPI           = 9,
    // Registry redirection
    FUNC_REG_REDIR_SHOULD_REDIRECT  = 10,
    FUNC_REG_REDIR_GET_REDIRECTED   = 11,
    // IPC filtering
    FUNC_IPC_FILTER_BLOCK_ALPC       = 12,
    FUNC_IPC_FILTER_BLOCK_PIPE       = 13,
    // File redirection
    FUNC_FILE_REDIR_SHOULD_REDIRECT = 14,
    FUNC_FILE_REDIR_GET_PATH        = 15,
    // BYOVD
    FUNC_BYOVD_IS_AVAILABLE         = 16,
    FUNC_BYOVD_READ_PHYS            = 17,
    FUNC_BYOVD_WRITE_PHYS           = 18,
    FUNC_BYOVD_READ_KERNEL          = 19,
    FUNC_BYOVD_WRITE_KERNEL         = 20,
    // RouteSyscall (ntdll_proxy)
    FUNC_ROUTE_SYSCALL              = 21,
    FUNC_GET_SPOOFED_IDENTITY       = 22,
};

// Single named export from engine.dll — all proxy DLLs use this
// to resolve any engine function by ID.
// Returns nullptr if funcId is unknown.
typedef void* (__stdcall* EngineGetExport_t)(uint32_t funcId);

// Helper: lazily resolve Engine_GetExport from engine.dll and cache it.
// Called by every proxy DLL function that needs an engine export.
inline EngineGetExport_t GetEngineExportResolver() {
    static EngineGetExport_t resolver = nullptr;
    static bool init = false;
    if (!init) {
        init = true;
        HMODULE hEngine = GetModuleHandleW(L"engine.dll");
        if (hEngine) {
            resolver = (EngineGetExport_t)GetProcAddress(hEngine, "Engine_GetExport");
        }
    }
    return resolver;
}

// Convenience: resolve a single function by ID. Returns nullptr if engine not ready.
inline void* ResolveEngineExport(uint32_t funcId) {
    EngineGetExport_t exportFn = GetEngineExportResolver();
    return exportFn ? exportFn(funcId) : nullptr;
}