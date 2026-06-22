#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include "Logger.h"
#include "ProxyExport.h"

#pragma comment(lib, "secur32.lib")

// SEC_ENTRY == __stdcall on x86. argbytes = paramCount * 4.
PROXY_EXPORT(InitializeSecurityContextW, proxy_InitializeSecurityContextW, 48) // 12 params
PROXY_EXPORT(AcceptSecurityContext,      proxy_AcceptSecurityContext,      36) // 9
PROXY_EXPORT(AcquireCredentialsHandleW,  proxy_AcquireCredentialsHandleW,  36) // 9
PROXY_EXPORT(FreeCredentialsHandle,      proxy_FreeCredentialsHandle,       4) // 1
PROXY_EXPORT(FreeContextBuffer,          proxy_FreeContextBuffer,           4) // 1
PROXY_EXPORT(ImpersonateSecurityContext, proxy_ImpersonateSecurityContext,  4) // 1
PROXY_EXPORT(RevertSecurityContext,      proxy_RevertSecurityContext,       4) // 1
PROXY_EXPORT(QueryContextAttributesW,    proxy_QueryContextAttributesW,    12) // 3
PROXY_EXPORT(EncryptMessage,             proxy_EncryptMessage,             16) // 4
PROXY_EXPORT(DecryptMessage,             proxy_DecryptMessage,             16) // 4
PROXY_EXPORT(MakeSignature,              proxy_MakeSignature,              16) // 4
PROXY_EXPORT(VerifySignature,            proxy_VerifySignature,            16) // 4
PROXY_EXPORT(GetUserNameExW,             proxy_GetUserNameExW,             12) // 3

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"secur32.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_InitializeSecurityContextW(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR* pszTargetName,
    ULONG fCredentialUse, ULONG dwReserved, ULONG dwContextReq,
    PSecBufferDesc pInput, ULONG dwReserved2, PCtxtHandle phNewContext,
    PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry)
{
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
    static Real_t real = (Real_t)GetRealProc("InitializeSecurityContextW");
    return real ? real(phCredential, phContext, pszTargetName, fCredentialUse, dwReserved, dwContextReq, pInput, dwReserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_AcceptSecurityContext(
    PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput,
    ULONG fContextReq, ULONG dwReserved, PCtxtHandle phNewContext,
    PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsTimeStamp)
{
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCredHandle, PCtxtHandle, PSecBufferDesc, ULONG, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
    static Real_t real = (Real_t)GetRealProc("AcceptSecurityContext");
    return real ? real(phCredential, phContext, pInput, fContextReq, dwReserved, phNewContext, pOutput, pfContextAttr, ptsTimeStamp) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_AcquireCredentialsHandleW(
    SEC_WCHAR* pszPrincipal, SEC_WCHAR* pszPackage, ULONG fCredentialUse,
    PVOID pvLogonId, PVOID pAuthData, SEC_GET_KEY_FN pGetKeyFn,
    PVOID pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(SEC_WCHAR*, SEC_WCHAR*, ULONG, PVOID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
    static Real_t real = (Real_t)GetRealProc("AcquireCredentialsHandleW");
    return real ? real(pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_FreeCredentialsHandle(PCredHandle phCredential) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCredHandle);
    static Real_t real = (Real_t)GetRealProc("FreeCredentialsHandle");
    return real ? real(phCredential) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_FreeContextBuffer(PVOID pvContextBuffer) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PVOID);
    static Real_t real = (Real_t)GetRealProc("FreeContextBuffer");
    return real ? real(pvContextBuffer) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_ImpersonateSecurityContext(PCtxtHandle phContext) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCtxtHandle);
    static Real_t real = (Real_t)GetRealProc("ImpersonateSecurityContext");
    return real ? real(phContext) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_RevertSecurityContext(PCtxtHandle phContext) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCtxtHandle);
    static Real_t real = (Real_t)GetRealProc("RevertSecurityContext");
    return real ? real(phContext) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_QueryContextAttributesW(PCtxtHandle phContext, ULONG ulAttribute, PVOID pBuffer) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCtxtHandle, ULONG, PVOID);
    static Real_t real = (Real_t)GetRealProc("QueryContextAttributesW");
    return real ? real(phContext, ulAttribute, pBuffer) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_EncryptMessage(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
    static Real_t real = (Real_t)GetRealProc("EncryptMessage");
    return real ? real(phContext, fQOP, pMessage, MessageSeqNo) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
    static Real_t real = (Real_t)GetRealProc("DecryptMessage");
    return real ? real(phContext, pMessage, MessageSeqNo, pfQOP) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_MakeSignature(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
    static Real_t real = (Real_t)GetRealProc("MakeSignature");
    return real ? real(phContext, fQOP, pMessage, MessageSeqNo) : SEC_E_INTERNAL_ERROR;
}

extern "C" SECURITY_STATUS SEC_ENTRY proxy_VerifySignature(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP) {
    typedef SECURITY_STATUS (SEC_ENTRY* Real_t)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
    static Real_t real = (Real_t)GetRealProc("VerifySignature");
    return real ? real(phContext, pMessage, MessageSeqNo, pfQOP) : SEC_E_INTERNAL_ERROR;
}

extern "C" BOOLEAN WINAPI proxy_GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize) {
    typedef BOOLEAN (WINAPI* Real_t)(EXTENDED_NAME_FORMAT, LPWSTR, PULONG);
    static Real_t real = (Real_t)GetRealProc("GetUserNameExW");
    return real ? real(NameFormat, lpNameBuffer, nSize) : FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD, LPVOID) { DisableThreadLibraryCalls(hModule); return TRUE; }
