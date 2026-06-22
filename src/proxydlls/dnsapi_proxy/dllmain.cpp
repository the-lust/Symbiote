#include <windows.h>
#include <windns.h>
#include "Logger.h"
#include "ProxyExport.h"

// argbytes = paramCount * 4
PROXY_EXPORT(DnsQuery_W,                 proxy_DnsQuery_W,                 24) // 6
PROXY_EXPORT(DnsQuery_A,                 proxy_DnsQuery_A,                 24) // 6
PROXY_EXPORT(DnsRecordListFree,          proxy_DnsRecordListFree,           8) // 2
PROXY_EXPORT(DnsNameCompare_W,           proxy_DnsNameCompare_W,            8) // 2
PROXY_EXPORT(DnsWriteQuestionToBuffer_W, proxy_DnsWriteQuestionToBuffer_W, 20) // 5

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"dnsapi.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" DNS_STATUS WINAPI proxy_DnsQuery_W(LPCWSTR pszName, WORD wType, DWORD Options, PIP4_ARRAY aipServers, PDNS_RECORDW* ppQueryResults, PVOID* pReserved) {
    typedef DNS_STATUS (WINAPI* Real_t)(LPCWSTR, WORD, DWORD, PIP4_ARRAY, PDNS_RECORDW*, PVOID*);
    static Real_t real = (Real_t)GetRealProc("DnsQuery_W");
    return real ? real(pszName, wType, Options, aipServers, ppQueryResults, pReserved) : ERROR_FILE_NOT_FOUND;
}
extern "C" DNS_STATUS WINAPI proxy_DnsQuery_A(LPCSTR pszName, WORD wType, DWORD Options, PIP4_ARRAY aipServers, PDNS_RECORDA* ppQueryResults, PVOID* pReserved) {
    typedef DNS_STATUS (WINAPI* Real_t)(LPCSTR, WORD, DWORD, PIP4_ARRAY, PDNS_RECORDA*, PVOID*);
    static Real_t real = (Real_t)GetRealProc("DnsQuery_A");
    return real ? real(pszName, wType, Options, aipServers, ppQueryResults, pReserved) : ERROR_FILE_NOT_FOUND;
}
extern "C" void WINAPI proxy_DnsRecordListFree(PDNS_RECORDW pRecordList, DNS_FREE_TYPE FreeType) {
    typedef void (WINAPI* Real_t)(PDNS_RECORDW, DNS_FREE_TYPE);
    static Real_t real = (Real_t)GetRealProc("DnsRecordListFree");
    if (real) real(pRecordList, FreeType);
}
extern "C" BOOL WINAPI proxy_DnsNameCompare_W(LPCWSTR pName1, LPCWSTR pName2) {
    typedef BOOL (WINAPI* Real_t)(LPCWSTR, LPCWSTR);
    static Real_t real = (Real_t)GetRealProc("DnsNameCompare_W");
    return real ? real(pName1, pName2) : FALSE;
}
extern "C" BOOL WINAPI proxy_DnsWriteQuestionToBuffer_W(PDNS_MESSAGE_BUFFER pBuffer, LPCWSTR pszName, WORD wType, WORD wQclass, BOOL fCharSet) {
    typedef BOOL (WINAPI* Real_t)(PDNS_MESSAGE_BUFFER, LPCWSTR, WORD, WORD, BOOL);
    static Real_t real = (Real_t)GetRealProc("DnsWriteQuestionToBuffer_W");
    return real ? real(pBuffer, pszName, wType, wQclass, fCharSet) : FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD, LPVOID) { DisableThreadLibraryCalls(hModule); return TRUE; }
