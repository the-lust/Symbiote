#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>
#include "Logger.h"
#include "ProxyExport.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wbemuuid.lib")

static LONG g_refCount = 0;

class CSpoofWbemClassObject;
class CSpoofEnumWbemClassObject;
class CSpoofWbemServices;
class CSpoofWbemLocator;

// ============================================================================
// Spoofed Win32_Processor props (i9-10900K)
// ============================================================================
struct SpoofedProcessor {
    static const wchar_t* Name() { return L"Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz"; }
    static const wchar_t* Manufacturer() { return L"GenuineIntel"; }
    static const wchar_t* ProcessorId() { return L"BFEBFBFF000A0655"; }
    static const wchar_t* Caption() { return L"Intel64 Family 6 Model 165 Stepping 5"; }
    static const wchar_t* Description() { return L"Intel64 Family 6 Model 165 Stepping 5"; }
    static DWORD NumberOfCores() { return 10; }
    static DWORD NumberOfLogicalProcessors() { return 20; }
    static DWORD MaxClockSpeed() { return 3700; }
    static DWORD CurrentClockSpeed() { return 3700; }
    static DWORD ExtClock() { return 100; }
    static DWORD L2CacheSize() { return 256; }
    static DWORD L3CacheSize() { return 20; }
};

// ============================================================================
// CSpoofWbemClassObject - wraps IWbemClassObject, spoofs Get() for CPU props
// ============================================================================
class CSpoofWbemClassObject : public IWbemClassObject {
private:
    LONG m_ref;
    IWbemClassObject* m_real;

public:
    CSpoofWbemClassObject(IWbemClassObject* real) : m_ref(1), m_real(real) {
        if (m_real) m_real->AddRef();
        InterlockedIncrement(&g_refCount);
    }
    ~CSpoofWbemClassObject() {
        if (m_real) m_real->Release();
        InterlockedDecrement(&g_refCount);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IWbemClassObject) {
            *ppv = this; AddRef(); return S_OK;
        }
        return m_real ? m_real->QueryInterface(riid, ppv) : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_ref); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return r;
    }

    HRESULT STDMETHODCALLTYPE GetQualifierSet(IWbemQualifierSet** ppQualSet) override {
        return m_real ? m_real->GetQualifierSet(ppQualSet) : E_FAIL;
    }

    HRESULT STDMETHODCALLTYPE Get(LPCWSTR wszName, long lFlags, VARIANT* pVal, CIMTYPE* pType, long* plFlavor) override {
        if (!wszName || !pVal) return m_real ? m_real->Get(wszName, lFlags, pVal, pType, plFlavor) : E_FAIL;
        bool spoofed = true;
        VariantInit(pVal);
        pVal->vt = VT_BSTR;
        if (wcscmp(wszName, L"Name") == 0) pVal->bstrVal = SysAllocString(SpoofedProcessor::Name());
        else if (wcscmp(wszName, L"Manufacturer") == 0) pVal->bstrVal = SysAllocString(SpoofedProcessor::Manufacturer());
        else if (wcscmp(wszName, L"ProcessorId") == 0) pVal->bstrVal = SysAllocString(SpoofedProcessor::ProcessorId());
        else if (wcscmp(wszName, L"Caption") == 0) pVal->bstrVal = SysAllocString(SpoofedProcessor::Caption());
        else if (wcscmp(wszName, L"Description") == 0) pVal->bstrVal = SysAllocString(SpoofedProcessor::Description());
        else if (wcscmp(wszName, L"NumberOfCores") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedProcessor::NumberOfCores(); }
        else if (wcscmp(wszName, L"NumberOfLogicalProcessors") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedProcessor::NumberOfLogicalProcessors(); }
        else if (wcscmp(wszName, L"MaxClockSpeed") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedProcessor::MaxClockSpeed(); }
        else if (wcscmp(wszName, L"CurrentClockSpeed") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedProcessor::CurrentClockSpeed(); }
        else if (wcscmp(wszName, L"ExtClock") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedProcessor::ExtClock(); }
        else if (wcscmp(wszName, L"L2CacheSize") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedProcessor::L2CacheSize(); }
        else if (wcscmp(wszName, L"L3CacheSize") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedProcessor::L3CacheSize(); }
        else spoofed = false;
        if (pType) *pType = CIM_STRING;
        if (plFlavor) *plFlavor = 0;
        if (spoofed) return S_OK;
        return m_real ? m_real->Get(wszName, lFlags, pVal, pType, plFlavor) : E_FAIL;
    }

    HRESULT STDMETHODCALLTYPE Put(LPCWSTR wszName, long lFlags, VARIANT* pVal, CIMTYPE Type) override {
        return m_real ? m_real->Put(wszName, lFlags, pVal, Type) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE Delete(LPCWSTR wszName) override { return m_real ? m_real->Delete(wszName) : E_FAIL; }
    HRESULT STDMETHODCALLTYPE GetNames(LPCWSTR wszQualifierName, long lFlags, VARIANT* pQualifierVal, SAFEARRAY** pNames) override {
        return m_real ? m_real->GetNames(wszQualifierName, lFlags, pQualifierVal, pNames) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE BeginEnumeration(long lFlags) override { return m_real ? m_real->BeginEnumeration(lFlags) : E_FAIL; }
    HRESULT STDMETHODCALLTYPE Next(long lFlags, BSTR* strName, VARIANT* pVal, CIMTYPE* pType, long* plFlavor) override {
        return m_real ? m_real->Next(lFlags, strName, pVal, pType, plFlavor) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE EndEnumeration() override { return m_real ? m_real->EndEnumeration() : E_FAIL; }
    HRESULT STDMETHODCALLTYPE GetPropertyQualifierSet(LPCWSTR wszProperty, IWbemQualifierSet** ppQualSet) override {
        return m_real ? m_real->GetPropertyQualifierSet(wszProperty, ppQualSet) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE Clone(IWbemClassObject** ppCopy) override {
        return m_real ? m_real->Clone(ppCopy) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE GetObjectText(long lFlags, BSTR* pstrObjectText) override {
        return m_real ? m_real->GetObjectText(lFlags, pstrObjectText) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE SpawnDerivedClass(long lFlags, IWbemClassObject** ppNewClass) override {
        return m_real ? m_real->SpawnDerivedClass(lFlags, ppNewClass) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE SpawnInstance(long lFlags, IWbemClassObject** ppNewInstance) override {
        return m_real ? m_real->SpawnInstance(lFlags, ppNewInstance) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE CompareTo(long lFlags, IWbemClassObject* pCompareTo) override {
        return m_real ? m_real->CompareTo(lFlags, pCompareTo) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE GetPropertyOrigin(LPCWSTR wszName, BSTR* pstrClassName) override {
        return m_real ? m_real->GetPropertyOrigin(wszName, pstrClassName) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE InheritsFrom(LPCWSTR strAncestor) override {
        return m_real ? m_real->InheritsFrom(strAncestor) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE GetMethod(LPCWSTR wszName, long lFlags, IWbemClassObject** ppInSignature, IWbemClassObject** ppOutSignature) override {
        return m_real ? m_real->GetMethod(wszName, lFlags, ppInSignature, ppOutSignature) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE PutMethod(LPCWSTR wszName, long lFlags, IWbemClassObject* pInSignature, IWbemClassObject* pOutSignature) override {
        return m_real ? m_real->PutMethod(wszName, lFlags, pInSignature, pOutSignature) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE DeleteMethod(LPCWSTR wszName) override { return m_real ? m_real->DeleteMethod(wszName) : E_FAIL; }
    HRESULT STDMETHODCALLTYPE BeginMethodEnumeration(long lFlags) override { return m_real ? m_real->BeginMethodEnumeration(lFlags) : E_FAIL; }
    HRESULT STDMETHODCALLTYPE NextMethod(long lFlags, BSTR* pstrName, IWbemClassObject** ppInSignature, IWbemClassObject** ppOutSignature) override {
        return m_real ? m_real->NextMethod(lFlags, pstrName, ppInSignature, ppOutSignature) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE EndMethodEnumeration() override { return m_real ? m_real->EndMethodEnumeration() : E_FAIL; }
    HRESULT STDMETHODCALLTYPE GetMethodQualifierSet(LPCWSTR wszMethod, IWbemQualifierSet** ppQualSet) override {
        return m_real ? m_real->GetMethodQualifierSet(wszMethod, ppQualSet) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE GetMethodOrigin(LPCWSTR wszMethodName, BSTR* pstrClassName) override {
        return m_real ? m_real->GetMethodOrigin(wszMethodName, pstrClassName) : E_FAIL;
    }
};

// ============================================================================
// CSpoofEnumWbemClassObject - wraps IEnumWbemClassObject, spoofs Next()
// ============================================================================
class CSpoofEnumWbemClassObject : public IEnumWbemClassObject {
private:
    LONG m_ref;
    IEnumWbemClassObject* m_real;

public:
    CSpoofEnumWbemClassObject(IEnumWbemClassObject* real) : m_ref(1), m_real(real) {
        if (m_real) m_real->AddRef();
        InterlockedIncrement(&g_refCount);
    }
    ~CSpoofEnumWbemClassObject() {
        if (m_real) m_real->Release();
        InterlockedDecrement(&g_refCount);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IEnumWbemClassObject) {
            *ppv = this; AddRef(); return S_OK;
        }
        return m_real ? m_real->QueryInterface(riid, ppv) : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_ref); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return r;
    }

    HRESULT STDMETHODCALLTYPE Reset() override { return m_real ? m_real->Reset() : E_FAIL; }

    HRESULT STDMETHODCALLTYPE Next(long lTimeout, ULONG uCount, IWbemClassObject** apObjects, ULONG* puReturned) override {
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->Next(lTimeout, uCount, apObjects, puReturned);
        if (SUCCEEDED(hr) && apObjects && puReturned && *puReturned > 0) {
            for (ULONG i = 0; i < *puReturned; i++) {
                if (apObjects[i]) {
                    apObjects[i] = new CSpoofWbemClassObject(apObjects[i]);
                }
            }
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE NextAsync(ULONG uCount, IWbemObjectSink* pSink) override {
        return m_real ? m_real->NextAsync(uCount, pSink) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE Clone(IEnumWbemClassObject** ppEnum) override {
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->Clone(ppEnum);
        if (SUCCEEDED(hr) && ppEnum && *ppEnum) {
            *ppEnum = new CSpoofEnumWbemClassObject(*ppEnum);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE Skip(long lTimeout, ULONG nCount) override {
        return m_real ? m_real->Skip(lTimeout, nCount) : E_FAIL;
    }
};

// ============================================================================
// CSpoofWbemServices - wraps IWbemServices, intercepts ExecQuery
// ============================================================================
class CSpoofWbemServices : public IWbemServices {
private:
    LONG m_ref;
    IWbemServices* m_real;

    bool IsWin32ProcessorQuery(const wchar_t* str) {
        if (!str) return false;
        return (wcsstr(str, L"Win32_Processor") != NULL);
    }

public:
    CSpoofWbemServices(IWbemServices* real) : m_ref(1), m_real(real) {
        if (m_real) m_real->AddRef();
        InterlockedIncrement(&g_refCount);
    }
    ~CSpoofWbemServices() {
        if (m_real) m_real->Release();
        InterlockedDecrement(&g_refCount);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IWbemServices) {
            *ppv = this; AddRef(); return S_OK;
        }
        return m_real ? m_real->QueryInterface(riid, ppv) : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_ref); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return r;
    }

    HRESULT STDMETHODCALLTYPE OpenNamespace(BSTR strNamespace, long lFlags, IWbemContext* pCtx, IWbemServices** ppNewNamespace, IWbemCallResult** ppCallResult) override {
        return m_real ? m_real->OpenNamespace(strNamespace, lFlags, pCtx, ppNewNamespace, ppCallResult) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE CancelAsyncCall(IWbemObjectSink* pSink) override { return m_real ? m_real->CancelAsyncCall(pSink) : E_FAIL; }
    HRESULT STDMETHODCALLTYPE QueryObjectSink(long lFlags, IWbemObjectSink** ppSink) override { return m_real ? m_real->QueryObjectSink(lFlags, ppSink) : E_FAIL; }
    HRESULT STDMETHODCALLTYPE GetObject(BSTR strObjectPath, long lFlags, IWbemContext* pCtx, IWbemClassObject** ppObject, IWbemCallResult** ppCallResult) override {
        return m_real ? m_real->GetObject(strObjectPath, lFlags, pCtx, ppObject, ppCallResult) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE GetObjectAsync(BSTR strObjectPath, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->GetObjectAsync(strObjectPath, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE PutClass(IWbemClassObject* pObject, long lFlags, IWbemContext* pCtx, IWbemCallResult** ppCallResult) override {
        return m_real ? m_real->PutClass(pObject, lFlags, pCtx, ppCallResult) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE PutClassAsync(IWbemClassObject* pObject, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->PutClassAsync(pObject, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE DeleteClass(BSTR strClass, long lFlags, IWbemContext* pCtx, IWbemCallResult** ppCallResult) override {
        return m_real ? m_real->DeleteClass(strClass, lFlags, pCtx, ppCallResult) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE DeleteClassAsync(BSTR strClass, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->DeleteClassAsync(strClass, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE CreateClassEnum(BSTR strSuperclass, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) override {
        return m_real ? m_real->CreateClassEnum(strSuperclass, lFlags, pCtx, ppEnum) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE CreateClassEnumAsync(BSTR strSuperclass, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->CreateClassEnumAsync(strSuperclass, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE PutInstance(IWbemClassObject* pInst, long lFlags, IWbemContext* pCtx, IWbemCallResult** ppCallResult) override {
        return m_real ? m_real->PutInstance(pInst, lFlags, pCtx, ppCallResult) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE PutInstanceAsync(IWbemClassObject* pInst, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->PutInstanceAsync(pInst, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE DeleteInstance(BSTR strObjectPath, long lFlags, IWbemContext* pCtx, IWbemCallResult** ppCallResult) override {
        return m_real ? m_real->DeleteInstance(strObjectPath, lFlags, pCtx, ppCallResult) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE DeleteInstanceAsync(BSTR strObjectPath, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->DeleteInstanceAsync(strObjectPath, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }

    HRESULT STDMETHODCALLTYPE CreateInstanceEnum(BSTR strClass, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) override {
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->CreateInstanceEnum(strClass, lFlags, pCtx, ppEnum);
        if (SUCCEEDED(hr) && ppEnum && *ppEnum && IsWin32ProcessorQuery(strClass)) {
            *ppEnum = new CSpoofEnumWbemClassObject(*ppEnum);
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE CreateInstanceEnumAsync(BSTR strClass, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->CreateInstanceEnumAsync(strClass, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }

    HRESULT STDMETHODCALLTYPE ExecQuery(BSTR strQueryLanguage, BSTR strQuery, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) override {
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->ExecQuery(strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
        if (SUCCEEDED(hr) && ppEnum && *ppEnum && IsWin32ProcessorQuery(strQuery)) {
            *ppEnum = new CSpoofEnumWbemClassObject(*ppEnum);
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE ExecQueryAsync(BSTR strQueryLanguage, BSTR strQuery, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->ExecQueryAsync(strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE ExecNotificationQuery(BSTR strQueryLanguage, BSTR strQuery, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) override {
        return m_real ? m_real->ExecNotificationQuery(strQueryLanguage, strQuery, lFlags, pCtx, ppEnum) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE ExecNotificationQueryAsync(BSTR strQueryLanguage, BSTR strQuery, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->ExecNotificationQueryAsync(strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE ExecMethod(BSTR strObjectPath, BSTR strMethodName, long lFlags, IWbemContext* pCtx, IWbemClassObject* pInParams, IWbemClassObject** ppOutParams, IWbemCallResult** ppCallResult) override {
        return m_real ? m_real->ExecMethod(strObjectPath, strMethodName, lFlags, pCtx, pInParams, ppOutParams, ppCallResult) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE ExecMethodAsync(BSTR strObjectPath, BSTR strMethodName, long lFlags, IWbemContext* pCtx, IWbemClassObject* pInParams, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->ExecMethodAsync(strObjectPath, strMethodName, lFlags, pCtx, pInParams, pResponseHandler) : E_FAIL;
    }
};

// ============================================================================
// CSpoofWbemLocator - wraps IWbemLocator
// ============================================================================
class CSpoofWbemLocator : public IWbemLocator {
private:
    LONG m_ref;
    IWbemLocator* m_real;

public:
    CSpoofWbemLocator(IWbemLocator* real) : m_ref(1), m_real(real) {
        if (m_real) m_real->AddRef();
        InterlockedIncrement(&g_refCount);
    }
    ~CSpoofWbemLocator() {
        if (m_real) m_real->Release();
        InterlockedDecrement(&g_refCount);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IWbemLocator) {
            *ppv = this; AddRef(); return S_OK;
        }
        return m_real ? m_real->QueryInterface(riid, ppv) : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_ref); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return r;
    }

    HRESULT STDMETHODCALLTYPE ConnectServer(BSTR strNetworkResource, BSTR strUser, BSTR strPassword, BSTR strLocale, long lSecurityFlags, BSTR strAuthority, IWbemContext* pCtx, IWbemServices** ppNamespace) override {
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->ConnectServer(strNetworkResource, strUser, strPassword, strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace);
        if (SUCCEEDED(hr) && ppNamespace && *ppNamespace) {
            *ppNamespace = new CSpoofWbemServices(*ppNamespace);
        }
        return hr;
    }
};

// ============================================================================
// Hooked CoCreateInstance
// ============================================================================
typedef HRESULT (STDMETHODCALLTYPE* RealCoCreateInstance_t)(REFCLSID rclsid, IUnknown* pUnkOuter, DWORD dwClsContext, REFIID riid, void** ppv);
static RealCoCreateInstance_t RealCoCreateInstance = NULL;

extern "C" HRESULT STDMETHODCALLTYPE Proxy_CoCreateInstance(REFCLSID rclsid, IUnknown* pUnkOuter, DWORD dwClsContext, REFIID riid, void** ppv)
{
    if (!RealCoCreateInstance) {
        HMODULE hOle32 = GetModuleHandleW(L"ole32.dll");
        if (hOle32) RealCoCreateInstance = (RealCoCreateInstance_t)GetProcAddress(hOle32, "CoCreateInstance");
        if (!RealCoCreateInstance) return E_FAIL;
    }

    HRESULT hr = RealCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
    if (SUCCEEDED(hr) && ppv && *ppv) {
        CLSID clsidWbemLocator;
        CLSIDFromString(L"{4590F811-1D3A-11D0-891F-00AA004B2E24}", &clsidWbemLocator);
        if (IsEqualCLSID(rclsid, clsidWbemLocator)) {
            IWbemLocator* locator = (IWbemLocator*)*ppv;
            *ppv = new CSpoofWbemLocator(locator);
        }
    }
    return hr;
}

// CoCreateInstance: 5 params (REFCLSID, IUnknown*, DWORD, REFIID, void**). STDMETHODCALLTYPE == __stdcall on x86.
PROXY_EXPORT(CoCreateInstance, Proxy_CoCreateInstance, 20)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{    DisableThreadLibraryCalls(hModule);
    return TRUE;
}
