#include "GpuBridge.h"
#include <cstring>

GpuBridge* g_gpuBridge = nullptr;

GpuBridge::GpuBridge(Logger* logger)
    : m_logger(logger), m_gpuDllCount(0)
{
    memset(m_gpuDlls, 0, sizeof(m_gpuDlls));
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

    g_gpuBridge = this;

    m_logger->Trace(LOG_INFO, "GpuBridge initialized with %d GPU DLLs", m_gpuDllCount);
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
        "D2D1CreateFactory", "DWriteCreateFactory",
        nullptr
    };

    for (int i = 0; gpuFuncs[i] != nullptr; i++) {
        if (strcmp(funcName, gpuFuncs[i]) == 0) return true;
    }

    return false;
}