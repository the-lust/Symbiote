#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>
#include "Logger.h"
#include "ProxyExport.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wbemuuid.lib")

static LONG g_refCount = 0;
static Logger g_logger;

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
// Spoofed Win32_ComputerSystem props (hide hypervisor)
// ============================================================================
struct SpoofedComputerSystem {
    static const wchar_t* Manufacturer() { return L"Dell Inc."; }
    static const wchar_t* Model() { return L"Inspiron 3542"; }
    static const wchar_t* SystemType() { return L"x64-based PC"; }
    static const wchar_t* Domain() { return L"WORKGROUP"; }
    static const wchar_t* UserName() { return L"DESKTOP-I3542\\User"; }
    static const wchar_t* PrimaryOwnerName() { return L"User"; }
    static bool HypervisorPresent() { return false; }
    static DWORD NumberOfProcessors() { return 1; }
    static DWORD NumberOfLogicalProcessors() { return 4; }
    static uint64_t TotalPhysicalMemory() { return 8589934592ULL; } // 8 GB
};

// ============================================================================
// Spoofed Win32_BaseBoard props (Dell Inspiron 3542)
// ============================================================================
struct SpoofedBaseBoard {
    static const wchar_t* Manufacturer() { return L"Dell Inc."; }
    static const wchar_t* Product() { return L"0WW73H"; }
    static const wchar_t* Version() { return L"A03"; }
    static const wchar_t* SerialNumber() { return L".5RSJB12.CN3MF00A3L00D3."; }
};

// ============================================================================
// Spoofed Win32_BIOS props (Dell A03)
// ============================================================================
struct SpoofedBIOS {
    static const wchar_t* Manufacturer() { return L"Dell Inc."; }
    static const wchar_t* Name() { return L"A03"; }
    static const wchar_t* Version() { return L"DELL   - 20140527"; }
    static const wchar_t* SerialNumber() { return L"5RSJB12"; }
    static const wchar_t* SMBIOSBIOSVersion() { return L"A03"; }
    static const wchar_t* ReleaseDate() { return L"20140527000000.000000+000"; }
};

// ============================================================================
// Spoofed Win32_DiskDrive props
// ============================================================================
struct SpoofedDiskDrive {
    static const wchar_t* Model() { return L"CT500BX500SSD1"; }
    static const wchar_t* SerialNumber() { return L"2324E6E428AC"; }
    static const wchar_t* InterfaceType() { return L"Serial ATA"; }
    static const wchar_t* MediaType() { return L"Fixed hard disk media"; }
    static uint64_t Size() { return 500105249280ULL; }
    static DWORD BytesPerSector() { return 512; }
    static DWORD SectorsPerTrack() { return 63; }
    static DWORD TotalHeads() { return 255; }
    static DWORD TotalCylinders() { return 60821; }
    static DWORD Partitions() { return 4; }
};

// ============================================================================
// CSpoofWbemClassObject - wraps IWbemClassObject, spoofs Get() for WMI props
// ============================================================================
enum WmiClassType {
    WMI_CLASS_UNKNOWN = 0,
    WMI_CLASS_PROCESSOR,
    WMI_CLASS_COMPUTER_SYSTEM,
    WMI_CLASS_BASEBOARD,
    WMI_CLASS_BIOS,
    WMI_CLASS_DISK_DRIVE,
};

class CSpoofWbemClassObject : public IWbemClassObject {
private:
    LONG m_ref;
    IWbemClassObject* m_real;
    WmiClassType m_classType;

public:
    CSpoofWbemClassObject(IWbemClassObject* real, WmiClassType classType = WMI_CLASS_UNKNOWN)
        : m_ref(1), m_real(real), m_classType(classType) {
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

        // --- Win32_Processor ---
        if (wcscmp(wszName, L"Name") == 0 && m_classType == WMI_CLASS_PROCESSOR) pVal->bstrVal = SysAllocString(SpoofedProcessor::Name());
        else if (wcscmp(wszName, L"Manufacturer") == 0) {
            if (m_classType == WMI_CLASS_COMPUTER_SYSTEM)
                pVal->bstrVal = SysAllocString(SpoofedComputerSystem::Manufacturer());
            else if (m_classType == WMI_CLASS_BASEBOARD)
                pVal->bstrVal = SysAllocString(SpoofedBaseBoard::Manufacturer());
            else
                pVal->bstrVal = SysAllocString(SpoofedProcessor::Manufacturer());
        }
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

        // --- Win32_ComputerSystem ---
        else if (wcscmp(wszName, L"HypervisorPresent") == 0) { pVal->vt = VT_BOOL; pVal->boolVal = SpoofedComputerSystem::HypervisorPresent() ? VARIANT_TRUE : VARIANT_FALSE; }
        else if (wcscmp(wszName, L"Model") == 0) pVal->bstrVal = SysAllocString(SpoofedComputerSystem::Model());
        else if (wcscmp(wszName, L"SystemType") == 0) pVal->bstrVal = SysAllocString(SpoofedComputerSystem::SystemType());
        else if (wcscmp(wszName, L"Domain") == 0) pVal->bstrVal = SysAllocString(SpoofedComputerSystem::Domain());
        else if (wcscmp(wszName, L"PrimaryOwnerName") == 0) pVal->bstrVal = SysAllocString(SpoofedComputerSystem::PrimaryOwnerName());
        else if (wcscmp(wszName, L"TotalPhysicalMemory") == 0) { pVal->vt = VT_UI8; pVal->ullVal = SpoofedComputerSystem::TotalPhysicalMemory(); }
        else if (wcscmp(wszName, L"NumberOfProcessors") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedComputerSystem::NumberOfProcessors(); }

        // --- Win32_BaseBoard ---
        else if (wcscmp(wszName, L"Product") == 0 && m_classType == WMI_CLASS_BASEBOARD) pVal->bstrVal = SysAllocString(SpoofedBaseBoard::Product());
        else if (wcscmp(wszName, L"Version") == 0 && m_classType == WMI_CLASS_BASEBOARD) pVal->bstrVal = SysAllocString(SpoofedBaseBoard::Version());
        else if (wcscmp(wszName, L"SerialNumber") == 0) {
            if (m_classType == WMI_CLASS_BASEBOARD)
                pVal->bstrVal = SysAllocString(SpoofedBaseBoard::SerialNumber());
            else if (m_classType == WMI_CLASS_BIOS)
                pVal->bstrVal = SysAllocString(SpoofedBIOS::SerialNumber());
            else if (m_classType == WMI_CLASS_DISK_DRIVE)
                pVal->bstrVal = SysAllocString(SpoofedDiskDrive::SerialNumber());
            else
                spoofed = false;
        }

        // --- Win32_BIOS ---
        else if (wcscmp(wszName, L"SMBIOSBIOSVersion") == 0) pVal->bstrVal = SysAllocString(SpoofedBIOS::SMBIOSBIOSVersion());
        else if (wcscmp(wszName, L"ReleaseDate") == 0) pVal->bstrVal = SysAllocString(SpoofedBIOS::ReleaseDate());

        // --- Win32_DiskDrive ---
        else if (wcscmp(wszName, L"InterfaceType") == 0) pVal->bstrVal = SysAllocString(SpoofedDiskDrive::InterfaceType());
        else if (wcscmp(wszName, L"MediaType") == 0) pVal->bstrVal = SysAllocString(SpoofedDiskDrive::MediaType());
        else if (wcscmp(wszName, L"Size") == 0) { pVal->vt = VT_UI8; pVal->ullVal = SpoofedDiskDrive::Size(); }
        else if (wcscmp(wszName, L"BytesPerSector") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedDiskDrive::BytesPerSector(); }
        else if (wcscmp(wszName, L"SectorsPerTrack") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedDiskDrive::SectorsPerTrack(); }
        else if (wcscmp(wszName, L"TotalHeads") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedDiskDrive::TotalHeads(); }
        else if (wcscmp(wszName, L"TotalCylinders") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedDiskDrive::TotalCylinders(); }
        else if (wcscmp(wszName, L"Partitions") == 0) { pVal->vt = VT_I4; pVal->lVal = (LONG)SpoofedDiskDrive::Partitions(); }

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
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->Clone(ppCopy);
        if (SUCCEEDED(hr) && ppCopy && *ppCopy) {
            *ppCopy = new CSpoofWbemClassObject(*ppCopy, m_classType);
        }
        return hr;
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
    WmiClassType m_classType;

public:
    CSpoofEnumWbemClassObject(IEnumWbemClassObject* real, WmiClassType classType = WMI_CLASS_UNKNOWN)
        : m_ref(1), m_real(real), m_classType(classType) {
        if (m_real) m_real->AddRef();
        InterlockedIncrement(&g_refCount);
    }
    ~CSpoofEnumWbemClassObject() {
        if (m_real) m_real->Release();
        InterlockedDecrement(&g_refCount);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppV) override {
        if (riid == IID_IUnknown || riid == IID_IEnumWbemClassObject) {
            *ppV = this; AddRef(); return S_OK;
        }
        return m_real ? m_real->QueryInterface(riid, ppV) : E_NOINTERFACE;
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
                    apObjects[i] = new CSpoofWbemClassObject(apObjects[i], m_classType);
                }
            }
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE Skip(long lTimeout, ULONG nCount) override {
        return m_real ? m_real->Skip(lTimeout, nCount) : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE Clone(IEnumWbemClassObject** ppEnum) override {
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->Clone(ppEnum);
        if (SUCCEEDED(hr) && ppEnum && *ppEnum) {
            *ppEnum = new CSpoofEnumWbemClassObject(*ppEnum, m_classType);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE NextAsync(ULONG uCount, IWbemObjectSink* pSink) override {
        return m_real ? m_real->NextAsync(uCount, pSink) : E_FAIL;
    }
};

// ============================================================================
// CSpoofWbemServices - wraps IWbemServices, intercepts ExecQuery
// ============================================================================
class CSpoofWbemServices : public IWbemServices {
private:
    LONG m_ref;
    IWbemServices* m_real;

    bool IsSpoofedWmiQuery(const wchar_t* str) {
        if (!str) return false;
        return (wcsstr(str, L"Win32_Processor") != NULL) ||
               (wcsstr(str, L"Win32_ComputerSystem") != NULL) ||
               (wcsstr(str, L"Win32_BaseBoard") != NULL) ||
               (wcsstr(str, L"Win32_BIOS") != NULL) ||
               (wcsstr(str, L"Win32_DiskDrive") != NULL);
    }

    WmiClassType DetectClassType(const wchar_t* str) {
        if (!str) return WMI_CLASS_UNKNOWN;
        if (wcsstr(str, L"Win32_Processor")) return WMI_CLASS_PROCESSOR;
        if (wcsstr(str, L"Win32_ComputerSystem")) return WMI_CLASS_COMPUTER_SYSTEM;
        if (wcsstr(str, L"Win32_BaseBoard")) return WMI_CLASS_BASEBOARD;
        if (wcsstr(str, L"Win32_BIOS")) return WMI_CLASS_BIOS;
        if (wcsstr(str, L"Win32_DiskDrive")) return WMI_CLASS_DISK_DRIVE;
        return WMI_CLASS_UNKNOWN;
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
        if (SUCCEEDED(hr) && ppEnum && *ppEnum && IsSpoofedWmiQuery(strClass)) {
            *ppEnum = new CSpoofEnumWbemClassObject(*ppEnum, DetectClassType(strClass));
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE CreateInstanceEnumAsync(BSTR strClass, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
        return m_real ? m_real->CreateInstanceEnumAsync(strClass, lFlags, pCtx, pResponseHandler) : E_FAIL;
    }

    HRESULT STDMETHODCALLTYPE ExecQuery(BSTR strQueryLanguage, BSTR strQuery, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) override {
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->ExecQuery(strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
        if (SUCCEEDED(hr) && ppEnum && *ppEnum && IsSpoofedWmiQuery(strQuery)) {
            *ppEnum = new CSpoofEnumWbemClassObject(*ppEnum, DetectClassType(strQuery));
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
    HRESULT STDMETHODCALLTYPE ExecMethodAsync(BSTR strObjectPath, BSTR strMethodName, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override {
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
        g_logger.Trace(LOG_PROXY, "ConnectServer: hr=0x%08X", hr);
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
        if (!hOle32) hOle32 = LoadLibraryW(L"ole32.dll");
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

PROXY_EXPORT(CoCreateInstance, Proxy_CoCreateInstance, 20)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_logger.Init();
        g_logger.Trace(LOG_PROXY, "wbem_proxy loaded");
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}
