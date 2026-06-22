#include <windows.h>
#include <wincrypt.h>
#include "Logger.h"
#include "ProxyExport.h"

// argbytes = paramCount * 4
PROXY_EXPORT(CertOpenSystemStoreW,             proxy_CertOpenSystemStoreW,              8)  // 2
PROXY_EXPORT(CertCloseStore,                   proxy_CertCloseStore,                    8)  // 2
PROXY_EXPORT(CertEnumCertificatesInStore,      proxy_CertEnumCertificatesInStore,       8)  // 2
PROXY_EXPORT(CertDuplicateCertificateContext,  proxy_CertDuplicateCertificateContext,   4)  // 1
PROXY_EXPORT(CertFreeCertificateContext,       proxy_CertFreeCertificateContext,        4)  // 1
PROXY_EXPORT(CertGetNameStringW,               proxy_CertGetNameStringW,               24)  // 6
PROXY_EXPORT(CryptStringToBinaryA,             proxy_CryptStringToBinaryA,             28)  // 7
PROXY_EXPORT(CryptBinaryToStringA,             proxy_CryptBinaryToStringA,             20)  // 5
PROXY_EXPORT(CryptDecodeObjectEx,              proxy_CryptDecodeObjectEx,              32)  // 8
PROXY_EXPORT(CryptEncodeObjectEx,              proxy_CryptEncodeObjectEx,              28)  // 7
PROXY_EXPORT(CryptAcquireContextW,             proxy_CryptAcquireContextW,             20)  // 5
PROXY_EXPORT(CryptReleaseContext,              proxy_CryptReleaseContext,               8)  // 2
PROXY_EXPORT(CryptGenKey,                      proxy_CryptGenKey,                      16)  // 4
PROXY_EXPORT(CryptDestroyKey,                  proxy_CryptDestroyKey,                   4)  // 1
PROXY_EXPORT(CryptDecrypt,                     proxy_CryptDecrypt,                     24)  // 6
PROXY_EXPORT(CryptEncrypt,                     proxy_CryptEncrypt,                     28)  // 7
PROXY_EXPORT(CryptHashData,                    proxy_CryptHashData,                    16)  // 4
PROXY_EXPORT(CryptGetHashParam,                proxy_CryptGetHashParam,                20)  // 5
PROXY_EXPORT(CryptCreateHash,                  proxy_CryptCreateHash,                  20)  // 5
PROXY_EXPORT(CryptDestroyHash,                 proxy_CryptDestroyHash,                  4)  // 1
PROXY_EXPORT(CertCreateCertificateContext,     proxy_CertCreateCertificateContext,     12)  // 3
PROXY_EXPORT(CertGetCertificateContextProperty,proxy_CertGetCertificateContextProperty,16) // 4

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"crypt32.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" HCERTSTORE WINAPI proxy_CertOpenSystemStoreW(HCRYPTPROV_LEGACY hProv, LPCWSTR szSubsystemProtocol) {
    typedef HCERTSTORE (WINAPI* Real_t)(HCRYPTPROV_LEGACY, LPCWSTR);
    static Real_t real = (Real_t)GetRealProc("CertOpenSystemStoreW");
    return real ? real(hProv, szSubsystemProtocol) : NULL;
}
extern "C" BOOL WINAPI proxy_CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags) {
    typedef BOOL (WINAPI* Real_t)(HCERTSTORE, DWORD);
    static Real_t real = (Real_t)GetRealProc("CertCloseStore");
    return real ? real(hCertStore, dwFlags) : FALSE;
}
extern "C" PCCERT_CONTEXT WINAPI proxy_CertEnumCertificatesInStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext) {
    typedef PCCERT_CONTEXT (WINAPI* Real_t)(HCERTSTORE, PCCERT_CONTEXT);
    static Real_t real = (Real_t)GetRealProc("CertEnumCertificatesInStore");
    return real ? real(hCertStore, pPrevCertContext) : NULL;
}
extern "C" PCCERT_CONTEXT WINAPI proxy_CertDuplicateCertificateContext(PCCERT_CONTEXT pCertContext) {
    typedef PCCERT_CONTEXT (WINAPI* Real_t)(PCCERT_CONTEXT);
    static Real_t real = (Real_t)GetRealProc("CertDuplicateCertificateContext");
    return real ? real(pCertContext) : NULL;
}
extern "C" BOOL WINAPI proxy_CertFreeCertificateContext(PCCERT_CONTEXT pCertContext) {
    typedef BOOL (WINAPI* Real_t)(PCCERT_CONTEXT);
    static Real_t real = (Real_t)GetRealProc("CertFreeCertificateContext");
    return real ? real(pCertContext) : FALSE;
}
extern "C" DWORD WINAPI proxy_CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void* pvTypePara, LPWSTR pszNameString, DWORD cchNameString) {
    typedef DWORD (WINAPI* Real_t)(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);
    static Real_t real = (Real_t)GetRealProc("CertGetNameStringW");
    return real ? real(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString) : 0;
}
extern "C" BOOL WINAPI proxy_CryptStringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags) {
    typedef BOOL (WINAPI* Real_t)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
    static Real_t real = (Real_t)GetRealProc("CryptStringToBinaryA");
    return real ? real(pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptBinaryToStringA(const BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD* pcchString) {
    typedef BOOL (WINAPI* Real_t)(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
    static Real_t real = (Real_t)GetRealProc("CryptBinaryToStringA");
    return real ? real(pbBinary, cbBinary, dwFlags, pszString, pcchString) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptDecodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, void* pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo) {
    typedef BOOL (WINAPI* Real_t)(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, void*, void*, DWORD*);
    static Real_t real = (Real_t)GetRealProc("CryptDecodeObjectEx");
    return real ? real(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pDecodePara, pvStructInfo, pcbStructInfo) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptEncodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const void* pvStructInfo, DWORD dwFlags, void* pEncodePara, BYTE* pbEncoded, DWORD* pcbEncoded) {
    typedef BOOL (WINAPI* Real_t)(DWORD, LPCSTR, const void*, DWORD, void*, BYTE*, DWORD*);
    static Real_t real = (Real_t)GetRealProc("CryptEncodeObjectEx");
    return real ? real(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pbEncoded, pcbEncoded) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptAcquireContextW(HCRYPTPROV* phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
    static Real_t real = (Real_t)GetRealProc("CryptAcquireContextW");
    return real ? real(phProv, pszContainer, pszProvider, dwProvType, dwFlags) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTPROV, DWORD);
    static Real_t real = (Real_t)GetRealProc("CryptReleaseContext");
    return real ? real(hProv, dwFlags) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*);
    static Real_t real = (Real_t)GetRealProc("CryptGenKey");
    return real ? real(hProv, Algid, dwFlags, phKey) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptDestroyKey(HCRYPTKEY hKey) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTKEY);
    static Real_t real = (Real_t)GetRealProc("CryptDestroyKey");
    return real ? real(hKey) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
    static Real_t real = (Real_t)GetRealProc("CryptDecrypt");
    return real ? real(hKey, hHash, Final, dwFlags, pbData, pdwDataLen) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
    static Real_t real = (Real_t)GetRealProc("CryptEncrypt");
    return real ? real(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptHashData(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
    static Real_t real = (Real_t)GetRealProc("CryptHashData");
    return real ? real(hHash, pbData, dwDataLen, dwFlags) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
    static Real_t real = (Real_t)GetRealProc("CryptGetHashParam");
    return real ? real(hHash, dwParam, pbData, pdwDataLen, dwFlags) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
    static Real_t real = (Real_t)GetRealProc("CryptCreateHash");
    return real ? real(hProv, Algid, hKey, dwFlags, phHash) : FALSE;
}
extern "C" BOOL WINAPI proxy_CryptDestroyHash(HCRYPTHASH hHash) {
    typedef BOOL (WINAPI* Real_t)(HCRYPTHASH);
    static Real_t real = (Real_t)GetRealProc("CryptDestroyHash");
    return real ? real(hHash) : FALSE;
}
extern "C" PCCERT_CONTEXT WINAPI proxy_CertCreateCertificateContext(DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded) {
    typedef PCCERT_CONTEXT (WINAPI* Real_t)(DWORD, const BYTE*, DWORD);
    static Real_t real = (Real_t)GetRealProc("CertCreateCertificateContext");
    return real ? real(dwCertEncodingType, pbCertEncoded, cbCertEncoded) : NULL;
}
extern "C" BOOL WINAPI proxy_CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData) {
    typedef BOOL (WINAPI* Real_t)(PCCERT_CONTEXT, DWORD, void*, DWORD*);
    static Real_t real = (Real_t)GetRealProc("CertGetCertificateContextProperty");
    return real ? real(pCertContext, dwPropId, pvData, pcbData) : FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD, LPVOID) { DisableThreadLibraryCalls(hModule); return TRUE; }
