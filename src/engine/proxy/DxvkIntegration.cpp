#include "DxvkIntegration.h"
#include "Logger.h"
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

bool g_dxvkPassthroughActive = false;

const wchar_t* DxvkIntegration::kDxvkDlls[] = {
    L"d3d9.dll",
    L"d3d10.dll",
    L"d3d10_1.dll",
    L"d3d10core.dll",
    L"d3d11.dll",
    L"dxgi.dll",
    nullptr
};

const std::wstring DxvkIntegration::kD3d9 = L"d3d9.dll";
const std::wstring DxvkIntegration::kD3d10Core = L"d3d10core.dll";
const std::wstring DxvkIntegration::kD3d10 = L"d3d10.dll";
const std::wstring DxvkIntegration::kD3d10_1 = L"d3d10_1.dll";
const std::wstring DxvkIntegration::kD3d11 = L"d3d11.dll";
const std::wstring DxvkIntegration::kDxgi = L"dxgi.dll";

DxvkIntegration::DxvkIntegration(Logger* logger)
    : m_logger(logger)
{
}

DxvkIntegration::~DxvkIntegration()
{
}

bool DxvkIntegration::DetectDxvkDlls(const std::wstring& targetExePath)
{
    fs::path exeDir = fs::path(targetExePath).parent_path();
    if (exeDir.empty()) return false;

    for (const wchar_t** dll = kDxvkDlls; *dll; dll++) {
        fs::path dllPath = exeDir / *dll;
        if (fs::exists(dllPath)) {
            return true;
        }
    }

    return false;
}

std::vector<std::wstring> DxvkIntegration::GetDxvkDllPaths(const std::wstring& targetExePath)
{
    std::vector<std::wstring> paths;
    fs::path exeDir = fs::path(targetExePath).parent_path();
    if (exeDir.empty()) return paths;

    for (const wchar_t** dll = kDxvkDlls; *dll; dll++) {
        fs::path dllPath = exeDir / *dll;
        if (fs::exists(dllPath)) {
            paths.push_back(dllPath.wstring());
        }
    }

    return paths;
}

bool DxvkIntegration::InstallDxvkDlls(const std::wstring& targetExePath, const std::wstring& dxvkSourceDir)
{
    fs::path exeDir = fs::path(targetExePath).parent_path();
    if (exeDir.empty() || dxvkSourceDir.empty()) return false;

    int installed = 0;
    int total = 0;

    for (const wchar_t** dll = kDxvkDlls; *dll; dll++) {
        total++;
        fs::path srcPath = fs::path(dxvkSourceDir) / *dll;
        fs::path dstPath = exeDir / *dll;

        if (!fs::exists(srcPath)) {
            m_logger->Trace(LOG_WARNING, "DXVK: source DLL not found: %s",
                srcPath.string().c_str());
            continue;
        }

        if (fs::exists(dstPath)) {
            m_logger->Trace(LOG_INFO, "DXVK: already installed: %s",
                dstPath.string().c_str());
            installed++;
            continue;
        }

        try {
            fs::copy_file(srcPath, dstPath, fs::copy_options::overwrite_existing);
            m_logger->Trace(LOG_INFO, "DXVK: installed %s -> %s",
                srcPath.string().c_str(), dstPath.string().c_str());
            installed++;
        } catch (const fs::filesystem_error& e) {
            m_logger->Trace(LOG_ERROR, "DXVK: failed to install %s: %s",
                srcPath.string().c_str(), e.what());
        }
    }

    return installed == total;
}

bool DxvkIntegration::ProtectDxvkDlls(const std::vector<std::wstring>& dxvkDlls)
{
    if (dxvkDlls.empty()) return true;

    g_dxvkPassthroughActive = true;

    for (const auto& dllPath : dxvkDlls) {
        HMODULE hMod = LoadLibraryW(dllPath.c_str());
        if (hMod) {
            m_logger->Trace(LOG_INFO, "DXVK: pre-loaded %s (module=0x%p)",
                fs::path(dllPath).filename().string().c_str(), (void*)hMod);
        } else {
            m_logger->Trace(LOG_WARNING, "DXVK: failed to pre-load %s (GLE=%u)",
                fs::path(dllPath).filename().string().c_str(), GetLastError());
        }
    }

    m_logger->Trace(LOG_INFO, "DXVK: passthrough active for %zu DLLs", dxvkDlls.size());
    return true;
}

bool DxvkIntegration::IsDxvkModule(const std::wstring& moduleName)
{
    if (!g_dxvkPassthroughActive) return false;

    std::wstring lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    for (const wchar_t** dll = kDxvkDlls; *dll; dll++) {
        if (lower == *dll) return true;
    }
    return false;
}

std::vector<std::wstring> DxvkIntegration::DetectVulkanLayers()
{
    std::vector<std::wstring> layers;
    std::wstring searchPaths[] = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64",
    };

    for (const auto& dir : searchPaths) {
        if (!fs::exists(dir)) continue;
        for (const auto& entry : fs::directory_iterator(dir)) {
            std::wstring name = entry.path().filename().wstring();
            std::wstring lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (lower.find(L"vk") != std::wstring::npos && lower.find(L".dll") != std::wstring::npos) {
                layers.push_back(entry.path().wstring());
            }
        }
    }
    return layers;
}

bool DxvkIntegration::IsVulkanLayer(const std::wstring& moduleName)
{
    std::wstring lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return lower.find(L"vk") != std::wstring::npos && lower.find(L".dll") != std::wstring::npos;
}

std::wstring DxvkIntegration::GetHostVulkanIcdPath()
{
    // Find the real host Vulkan ICD JSON file that DXVK needs to find the GPU.
    // Vulkan ICDs register via JSON files in:
    //   HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\Vulkan\Drivers
    // Each JSON file path points to a manifest that contains the actual driver DLL path.
    //
    // We look for the first available real ICD (nvidia, amd, intel) and return its path.

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Khronos\\Vulkan\\Drivers",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t valueName[256];
        DWORD valueNameLen = 256;
        DWORD valueType = 0;
        BYTE data[1024];
        DWORD dataLen = sizeof(data);

        for (DWORD i = 0; RegEnumValueW(hKey, i, valueName, &valueNameLen,
                NULL, &valueType, data, &dataLen) == ERROR_SUCCESS; i++) {
            if (valueType == REG_SZ && dataLen > 4) {
                std::wstring jsonPath((wchar_t*)data, dataLen / sizeof(wchar_t) - 1);

                // Check if it's a real GPU driver (not a software/null driver)
                std::wstring lower = jsonPath;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                if (lower.find(L"nvidia") != std::wstring::npos ||
                    lower.find(L"amd") != std::wstring::npos ||
                    lower.find(L"amd64") != std::wstring::npos ||
                    lower.find(L"intel") != std::wstring::npos ||
                    lower.find(L"igfx") != std::wstring::npos) {
                    RegCloseKey(hKey);
                    return jsonPath;
                }
            }
            valueNameLen = 256;
            dataLen = sizeof(data);
        }
        RegCloseKey(hKey);
    }

    // Fallback: common locations for ICD JSON files
    static const wchar_t* kCommonIcdPaths[] = {
        L"C:\\Windows\\System32\\nv-vk64.json",
        L"C:\\Windows\\System32\\amd-vulkan64.json",
        L"C:\\Windows\\System32\\igfx_icd.json",
        L"C:\\Windows\\SysWOW64\\nv-vk32.json",
        L"C:\\Windows\\SysWOW64\\amd-vulkan32.json",
        nullptr
    };

    for (int i = 0; kCommonIcdPaths[i]; i++) {
        if (GetFileAttributesW(kCommonIcdPaths[i]) != INVALID_FILE_ATTRIBUTES) {
            return kCommonIcdPaths[i];
        }
    }

    return L"";
}

bool DxvkIntegration::SetVulkanIcdEnvironment(const std::wstring& targetExePath)
{
    (void)targetExePath;
    std::wstring icdPath = GetHostVulkanIcdPath();
    if (icdPath.empty()) {
        return false;
    }

    if (!SetEnvironmentVariableW(L"VK_ICD_FILENAMES", icdPath.c_str())) {
        return false;
    }

    return true;
}
