#include <windows.h>
#include <string>
#include <unordered_map>
#include "Logger.h"
#include "ProxyExport.h"

static Logger g_logger;
static HMODULE g_realXgameruntime = nullptr;
static std::unordered_map<std::string, FARPROC> g_forwardTable;

static const wchar_t* kRealDllNames[] = {
    L"xgameruntime.dll",
    L"Microsoft.Gaming.XboxGameRuntime.dll",
    L"gameplatform.dll",
    nullptr
};

static HMODULE LoadRealDll()
{
    for (int i = 0; kRealDllNames[i]; i++) {
        wchar_t sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring path = std::wstring(sysDir) + L"\\" + kRealDllNames[i];
        HMODULE hMod = LoadLibraryW(path.c_str());
        if (hMod) {
            g_logger.Trace(LOG_PROXY, "xgameruntime: loaded real DLL from %ls", path.c_str());
            return hMod;
        }
        path = std::wstring(L"C:\\Windows\\System32\\") + kRealDllNames[i];
        hMod = LoadLibraryW(path.c_str());
        if (hMod) {
            g_logger.Trace(LOG_PROXY, "xgameruntime: loaded real DLL from %ls", path.c_str());
            return hMod;
        }
    }
    g_logger.Trace(LOG_WARNING, "xgameruntime: no real DLL found, some functions will return defaults");
    return nullptr;
}

static FARPROC GetRealProc(const char* name)
{
    if (!g_realXgameruntime) return nullptr;
    auto it = g_forwardTable.find(name);
    if (it != g_forwardTable.end()) return it->second;
    FARPROC proc = GetProcAddress(g_realXgameruntime, name);
    g_forwardTable[name] = proc;
    return proc;
}

// ─── XGameRuntimeInitialize hook ────────────────────────────────────────
typedef HRESULT (__stdcall* RealXGameRuntimeInitialize_t)();
static RealXGameRuntimeInitialize_t g_realXGameRuntimeInitialize = nullptr;

extern "C" HRESULT __stdcall Proxy_XGameRuntimeInitialize()
{
    if (!g_realXgameruntime) {
        g_realXgameruntime = LoadRealDll();
    }
    if (!g_realXGameRuntimeInitialize) {
        if (g_realXgameruntime) {
            g_realXGameRuntimeInitialize = (RealXGameRuntimeInitialize_t)
                GetProcAddress(g_realXgameruntime, "XGameRuntimeInitialize");
        }
    }
    HRESULT hr = g_realXGameRuntimeInitialize ? g_realXGameRuntimeInitialize() : E_FAIL;
    if (SUCCEEDED(hr)) {
        g_logger.Trace(LOG_PROXY, "XGameRuntimeInitialize succeeded");
    }
    return hr;
}

// ─── XUserGetGamertag hook ──────────────────────────────────────────────
typedef HRESULT (__stdcall* RealXUserGetGamertag_t)(HANDLE user, size_t size, char* gamertag);
static RealXUserGetGamertag_t g_realXUserGetGamertag = nullptr;

static const char* SPOOFED_GAMERTAG = "Player";
static const wchar_t* SPOOFED_GAMERTAG_W = L"Player";

extern "C" HRESULT __stdcall Proxy_XUserGetGamertag(HANDLE user, size_t size, char* gamertag)
{
    if (!g_realXUserGetGamertag && g_realXgameruntime) {
        g_realXUserGetGamertag = (RealXUserGetGamertag_t)
            GetProcAddress(g_realXgameruntime, "XUserGetGamertag");
    }
    if (gamertag && size > 0) {
        strcpy_s(gamertag, size, SPOOFED_GAMERTAG);
        g_logger.Trace(LOG_PROXY, "XUserGetGamertag -> spoofed: %s", SPOOFED_GAMERTAG);
        return S_OK;
    }
    return g_realXUserGetGamertag ? g_realXUserGetGamertag(user, size, gamertag) : E_FAIL;
}

extern "C" HRESULT __stdcall Proxy_XUserGetGamertagUtf16(HANDLE user, size_t size, wchar_t* gamertag)
{
    (void)user;
    if (gamertag && size > 0) {
        wcscpy_s(gamertag, size, SPOOFED_GAMERTAG_W);
        g_logger.Trace(LOG_PROXY, "XUserGetGamertagUtf16 -> spoofed");
        return S_OK;
    }
    return E_FAIL;
}

// ─── XUserGetTokenAndSignature hook ─────────────────────────────────────
typedef HRESULT (__stdcall* RealXUserGetTokenAndSignature_t)(
    HANDLE user, const void* httpMethod, const void* uri,
    const void* headers, size_t headerCount,
    const void* body, size_t bodySize,
    void* result, void* allocator);
static RealXUserGetTokenAndSignature_t g_realXUserGetTokenAndSignature = nullptr;

extern "C" HRESULT __stdcall Proxy_XUserGetTokenAndSignature(
    HANDLE user, const void* httpMethod, const void* uri,
    const void* headers, size_t headerCount,
    const void* body, size_t bodySize,
    void* result, void* allocator)
{
    (void)user;
    (void)httpMethod; (void)uri; (void)headers; (void)headerCount;
    (void)body; (void)bodySize; (void)result; (void)allocator;

    if (!g_realXUserGetTokenAndSignature && g_realXgameruntime) {
        g_realXUserGetTokenAndSignature = (RealXUserGetTokenAndSignature_t)
            GetProcAddress(g_realXgameruntime, "XUserGetTokenAndSignature");
    }
    if (g_realXUserGetTokenAndSignature) {
        return g_realXUserGetTokenAndSignature(user, httpMethod, uri,
            headers, headerCount, body, bodySize, result, allocator);
    }
    return E_NOTIMPL;
}

// ─── XSystemGetAnalyticsInfo hook ───────────────────────────────────────
typedef HRESULT (__stdcall* RealXSystemGetAnalyticsInfo_t)(void* info);
static RealXSystemGetAnalyticsInfo_t g_realXSystemGetAnalyticsInfo = nullptr;

extern "C" HRESULT __stdcall Proxy_XSystemGetAnalyticsInfo(void* info)
{
    (void)info;
    if (!g_realXSystemGetAnalyticsInfo && g_realXgameruntime) {
        g_realXSystemGetAnalyticsInfo = (RealXSystemGetAnalyticsInfo_t)
            GetProcAddress(g_realXgameruntime, "XSystemGetAnalyticsInfo");
    }
    g_logger.Trace(LOG_PROXY, "XSystemGetAnalyticsInfo -> spoofed");
    return S_OK;
}

// ─── XSystemGetXboxLiveSandboxId hook ───────────────────────────────────
typedef HRESULT (__stdcall* RealXSystemGetXboxLiveSandboxId_t)(char* sandboxId, size_t size);
static RealXSystemGetXboxLiveSandboxId_t g_realXSystemGetXboxLiveSandboxId = nullptr;

static const char* SPOOFED_SANDBOX_ID = "RETAIL";

extern "C" HRESULT __stdcall Proxy_XSystemGetXboxLiveSandboxId(char* sandboxId, size_t size)
{
    if (sandboxId && size > 0) {
        strcpy_s(sandboxId, size, SPOOFED_SANDBOX_ID);
        g_logger.Trace(LOG_PROXY, "XSystemGetXboxLiveSandboxId -> spoofed: %s", SPOOFED_SANDBOX_ID);
        return S_OK;
    }
    if (!g_realXSystemGetXboxLiveSandboxId && g_realXgameruntime) {
        g_realXSystemGetXboxLiveSandboxId = (RealXSystemGetXboxLiveSandboxId_t)
            GetProcAddress(g_realXgameruntime, "XSystemGetXboxLiveSandboxId");
    }
    return g_realXSystemGetXboxLiveSandboxId ? g_realXSystemGetXboxLiveSandboxId(sandboxId, size) : E_FAIL;
}

// ─── XSystemGetConsoleId hook ───────────────────────────────────────────
typedef HRESULT (__stdcall* RealXSystemGetConsoleId_t)(char* consoleId, size_t size);
static RealXSystemGetConsoleId_t g_realXSystemGetConsoleId = nullptr;

static const char* SPOOFED_CONSOLE_ID = "XBOXPC-000000000000000";

extern "C" HRESULT __stdcall Proxy_XSystemGetConsoleId(char* consoleId, size_t size)
{
    if (consoleId && size > 0) {
        strcpy_s(consoleId, size, SPOOFED_CONSOLE_ID);
        g_logger.Trace(LOG_PROXY, "XSystemGetConsoleId -> spoofed: %s", SPOOFED_CONSOLE_ID);
        return S_OK;
    }
    if (!g_realXSystemGetConsoleId && g_realXgameruntime) {
        g_realXSystemGetConsoleId = (RealXSystemGetConsoleId_t)
            GetProcAddress(g_realXgameruntime, "XSystemGetConsoleId");
    }
    return g_realXSystemGetConsoleId ? g_realXSystemGetConsoleId(consoleId, size) : E_FAIL;
}

// ─── XStoreQueryProductsAsync hook ──────────────────────────────────────
typedef void* (__stdcall* RealXStoreQueryProductsAsync_t)(void* context, void* filter);
static RealXStoreQueryProductsAsync_t g_realXStoreQueryProductsAsync = nullptr;

extern "C" void* __stdcall Proxy_XStoreQueryProductsAsync(void* context, void* filter)
{
    (void)context; (void)filter;
    if (!g_realXStoreQueryProductsAsync && g_realXgameruntime) {
        g_realXStoreQueryProductsAsync = (RealXStoreQueryProductsAsync_t)
            GetProcAddress(g_realXgameruntime, "XStoreQueryProductsAsync");
    }
    if (g_realXStoreQueryProductsAsync) {
        return g_realXStoreQueryProductsAsync(context, filter);
    }
    return nullptr;
}

// ─── XStoreCanAcquireLicenseForProductAsync hook ────────────────────────
extern "C" void* __stdcall Proxy_XStoreCanAcquireLicenseForProductAsync(void* store, const char* productSkuId, void* context)
{
    (void)store; (void)productSkuId; (void)context;
    g_logger.Trace(LOG_PROXY, "XStoreCanAcquireLicenseForProductAsync -> spoofed (licensed=true)");
    return nullptr;
}

// ─── Generic forwarder ──────────────────────────────────────────────────
extern "C" FARPROC __stdcall Proxy_ForwardStub(const char* funcName)
{
    return GetRealProc(funcName);
}

// ─── Exports table ──────────────────────────────────────────────────────
// Forwarded to real xgameruntime.dll (or return spoofed values for key funcs)
PROXY_EXPORT(XGameRuntimeInitialize, Proxy_XGameRuntimeInitialize, 0)
PROXY_EXPORT(XUserGetGamertag, Proxy_XUserGetGamertag, 12)
PROXY_EXPORT(XUserGetGamertagUtf16, Proxy_XUserGetGamertagUtf16, 12)
PROXY_EXPORT(XUserGetTokenAndSignature, Proxy_XUserGetTokenAndSignature, 36)
PROXY_EXPORT(XSystemGetAnalyticsInfo, Proxy_XSystemGetAnalyticsInfo, 4)
PROXY_EXPORT(XSystemGetXboxLiveSandboxId, Proxy_XSystemGetXboxLiveSandboxId, 8)
PROXY_EXPORT(XSystemGetConsoleId, Proxy_XSystemGetConsoleId, 8)
PROXY_EXPORT(XStoreQueryProductsAsync, Proxy_XStoreQueryProductsAsync, 8)
PROXY_EXPORT(XStoreCanAcquireLicenseForProductAsync, Proxy_XStoreCanAcquireLicenseForProductAsync, 12)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            g_logger.Init();
            g_logger.Trace(LOG_PROXY, "xgameruntime proxy loaded");
            DisableThreadLibraryCalls(hModule);
            LoadRealDll();
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
