#include "GpuBridge.h"
#include <cstring>
#include <filesystem>

namespace fs = std::filesystem;

GpuBridge* g_gpuBridge = nullptr;

GpuBridge::GpuBridge(Logger* logger)
    : m_logger(logger), m_gpuDllCount(0), m_vulkanLoader(nullptr)
{
    memset(m_gpuDlls, 0, sizeof(m_gpuDlls));
    m_icdJsonPath[0] = 0;
}

GpuBridge::~GpuBridge()
{
    for (int i = 0; i < m_gpuDllCount; i++) {
        if (m_gpuDlls[i].handle) {
            FreeLibrary(m_gpuDlls[i].handle);
        }
    }
    g_gpuBridge = nullptr;
}

void GpuBridge::AddGpuDll(const char* name)
{
    if (m_gpuDllCount >= MAX_GPU_DLLS) return;
    strncpy_s(m_gpuDlls[m_gpuDllCount].name, name, sizeof(m_gpuDlls[m_gpuDllCount].name) - 1);
    m_gpuDlls[m_gpuDllCount].handle = nullptr;
    m_gpuDlls[m_gpuDllCount].exportCount = 0;
    m_gpuDllCount++;
    m_logger->Trace(LOG_INFO, "GpuBridge: registered %s", name);
}

bool GpuBridge::LoadGpuDll(int index)
{
    if (index < 0 || index >= m_gpuDllCount) return false;
    if (m_gpuDlls[index].handle) return true;

    char fullName[128];
    strcpy_s(fullName, m_gpuDlls[index].name);

    m_gpuDlls[index].handle = LoadLibraryA(fullName);
    if (!m_gpuDlls[index].handle) {
        m_logger->Trace(LOG_WARNING, "GpuBridge: failed to load %s", fullName);
        return false;
    }

    m_logger->Trace(LOG_INFO, "GpuBridge: loaded %s (handle=%p)", fullName, m_gpuDlls[index].handle);
    return true;
}

bool GpuBridge::DetectVulkanIcd()
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Khronos\\Vulkan\\Drivers", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char valueName[256];
        DWORD valueNameLen = sizeof(valueName);
        DWORD type = 0;
        DWORD data = 0;
        DWORD dataLen = sizeof(data);
        int index = 0;

        while (RegEnumValueA(hKey, index, valueName, &valueNameLen, NULL, &type, (LPBYTE)&data, &dataLen) == ERROR_SUCCESS) {
            if (type == REG_DWORD && data == 0) {
                fs::path icdPath(valueName);
                if (fs::exists(icdPath)) {
                    strncpy_s(m_icdJsonPath, icdPath.string().c_str(), _TRUNCATE);
                    m_logger->Trace(LOG_INFO, "GpuBridge: detected Vulkan ICD: %s", m_icdJsonPath);
                    RegCloseKey(hKey);
                    return true;
                }
            }
            valueNameLen = sizeof(valueName);
            dataLen = sizeof(data);
            index++;
        }
        RegCloseKey(hKey);
    }

    fs::path nvIcd = "C:\\Windows\\System32\\nv-vk64.json";
    if (fs::exists(nvIcd)) {
        strncpy_s(m_icdJsonPath, nvIcd.string().c_str(), _TRUNCATE);
        return true;
    }
    fs::path amdIcd = "C:\\Windows\\System32\\amd-vulkan64.json";
    if (fs::exists(amdIcd)) {
        strncpy_s(m_icdJsonPath, amdIcd.string().c_str(), _TRUNCATE);
        return true;
    }
    fs::path intelIcd = "C:\\Windows\\System32\\intel-vulkan64.json";
    if (fs::exists(intelIcd)) {
        strncpy_s(m_icdJsonPath, intelIcd.string().c_str(), _TRUNCATE);
        return true;
    }

    return false;
}

bool GpuBridge::Initialize()
{
    AddGpuDll("dxgi.dll");
    AddGpuDll("d3d11.dll");
    AddGpuDll("d3d12.dll");
    AddGpuDll("vulkan-1.dll");
    AddGpuDll("d2d1.dll");
    AddGpuDll("dwrite.dll");
    AddGpuDll("d3dcompiler_47.dll");

    for (int i = 0; i < m_gpuDllCount; i++) {
        LoadGpuDll(i);
    }

    m_vulkanLoader = GetModuleHandleA("vulkan-1.dll");
    if (!m_vulkanLoader) {
        m_vulkanLoader = LoadLibraryA("vulkan-1.dll");
    }
    if (m_vulkanLoader) {
        DetectVulkanIcd();
        ForwardVulkanIcd();
    }

    g_gpuBridge = this;

    m_logger->Trace(LOG_INFO, "GpuBridge initialized with %d GPU DLLs", m_gpuDllCount);
    return true;
}

bool GpuBridge::ForwardVulkanIcd()
{
    if (!m_icdJsonPath[0]) return false;

    SetEnvironmentVariableA("VK_ICD_FILENAMES", m_icdJsonPath);
    m_logger->Trace(LOG_INFO, "GpuBridge: forwarded Vulkan ICD via VK_ICD_FILENAMES=%s", m_icdJsonPath);

    char system32[MAX_PATH];
    GetSystemDirectoryA(system32, sizeof(system32));
    std::string vkDllPath = std::string(system32) + "\\vulkan-1.dll";

    HMODULE hVulkan = LoadLibraryA(vkDllPath.c_str());
    if (hVulkan) {
        m_logger->Trace(LOG_INFO, "GpuBridge: loaded system vulkan-1.dll for forwarding");
    }

    return true;
}

void* GpuBridge::GetRealProc(const char* dllName, const char* procName)
{
    for (int i = 0; i < m_gpuDllCount; i++) {
        if (_stricmp(m_gpuDlls[i].name, dllName) == 0) {
            if (m_gpuDlls[i].handle) {
                return (void*)GetProcAddress(m_gpuDlls[i].handle, procName);
            }
            return nullptr;
        }
    }
    return nullptr;
}

bool GpuBridge::IsGpuDll(const char* dllName) const
{
    for (int i = 0; i < m_gpuDllCount; i++) {
        if (_stricmp(m_gpuDlls[i].name, dllName) == 0) {
            return true;
        }
    }
    return false;
}

bool GpuBridge::IsGpuFunction(const char* dllName, const char* funcName) const
{
    if (!IsGpuDll(dllName)) return false;

    const char* gpuFuncs[] = {
        "CreateDXGIFactory", "CreateDXGIFactory1", "CreateDXGIFactory2",
        "D3D11CreateDevice", "D3D11CreateDeviceAndSwapChain",
        "D3D12CreateDevice", "D3D12CreateRootSignatureDeserializer",
        "vkCreateInstance", "vkDestroyInstance", "vkEnumeratePhysicalDevices",
        "vkEnumeratePhysicalDeviceGroups", "vkGetPhysicalDeviceProperties",
        "vkGetPhysicalDeviceProperties2", "vkGetPhysicalDeviceFeatures",
        "vkGetPhysicalDeviceFeatures2", "vkGetPhysicalDeviceQueueFamilyProperties",
        "vkCreateDevice", "vkDestroyDevice",
        "D2D1CreateFactory", "DWriteCreateFactory",
        nullptr
    };

    for (int i = 0; gpuFuncs[i] != nullptr; i++) {
        if (strcmp(funcName, gpuFuncs[i]) == 0) return true;
    }

    return false;
}
