#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_set>

class Logger;

class DxvkIntegration {
public:
    explicit DxvkIntegration(Logger* logger);
    ~DxvkIntegration();

    // Detect if DXVK DLLs exist alongside the target executable
    static bool DetectDxvkDlls(const std::wstring& targetExePath);

    // Get list of DXVK DLL paths that should use passthrough proxy interception
    static std::vector<std::wstring> GetDxvkDllPaths(const std::wstring& targetExePath);

    // Install DXVK DLLs into the target directory (if not present)
    bool InstallDxvkDlls(const std::wstring& targetExePath, const std::wstring& dxvkSourceDir);

    // Ensure our proxy system doesn't hook DXVK DLLs
    bool ProtectDxvkDlls(const std::vector<std::wstring>& dxvkDlls);

    // Check if a given DLL module is a DXVK DLL (should skip proxy interception)
    static bool IsDxvkModule(const std::wstring& moduleName);

    // Detect Vulkan layer paths for forwarding
    static std::vector<std::wstring> DetectVulkanLayers();
    static bool IsVulkanLayer(const std::wstring& moduleName);

    // DXVK DLL names
    static const wchar_t* kDxvkDlls[];

private:
    Logger* m_logger;
    std::unordered_set<std::wstring> m_knownLayers;

    static const std::wstring kD3d9;
    static const std::wstring kD3d10Core;
    static const std::wstring kD3d10;
    static const std::wstring kD3d10_1;
    static const std::wstring kD3d11;
    static const std::wstring kDxgi;
};

// Global DXVK passthrough flag — set after DXVK DLLs are loaded so proxy hooks skip them
extern bool g_dxvkPassthroughActive;
