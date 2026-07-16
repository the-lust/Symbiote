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

    // Check if any DXVK DLLs exist in the target directory
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

    // Set the passthrough flag so proxy hooks skip interception for DXVK modules
    g_dxvkPassthroughActive = true;

    // Ensure all DXVK DLLs are loaded into the process (so they're initialized
    // before the target starts hooking them). We do this by forcing a LoadLibrary
    // for each DXVK DLL path.
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
