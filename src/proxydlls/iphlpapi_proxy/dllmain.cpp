#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include "Logger.h"
#include "ProxyExport.h"

// argbytes = paramCount * 4
PROXY_EXPORT(GetAdaptersInfo,      proxy_GetAdaptersInfo,       8)  // 2
PROXY_EXPORT(GetAdaptersAddresses, proxy_GetAdaptersAddresses, 20)  // 5
PROXY_EXPORT(GetNetworkParams,     proxy_GetNetworkParams,      8)  // 2
PROXY_EXPORT(GetExtendedTcpTable,  proxy_GetExtendedTcpTable,  24)  // 6
PROXY_EXPORT(GetExtendedUdpTable,  proxy_GetExtendedUdpTable,  24)  // 6
PROXY_EXPORT(NotifyAddrChange,     proxy_NotifyAddrChange,      8)  // 2
PROXY_EXPORT(GetBestInterfaceEx,   proxy_GetBestInterfaceEx,    8)  // 2

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"iphlpapi.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" ULONG WINAPI proxy_GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) {
    typedef ULONG (WINAPI* Real_t)(PIP_ADAPTER_INFO, PULONG);
    static Real_t real = (Real_t)GetRealProc("GetAdaptersInfo");
    return real ? real(pAdapterInfo, pOutBufLen) : ERROR_NO_DATA;
}
extern "C" ULONG WINAPI proxy_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES pAdapterAddresses, PULONG pSizePointer) {
    typedef ULONG (WINAPI* Real_t)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
    static Real_t real = (Real_t)GetRealProc("GetAdaptersAddresses");
    return real ? real(Family, Flags, Reserved, pAdapterAddresses, pSizePointer) : ERROR_NO_DATA;
}
extern "C" DWORD WINAPI proxy_GetNetworkParams(PFIXED_INFO pFixedInfo, PULONG pOutBufLen) {
    typedef DWORD (WINAPI* Real_t)(PFIXED_INFO, PULONG);
    static Real_t real = (Real_t)GetRealProc("GetNetworkParams");
    return real ? real(pFixedInfo, pOutBufLen) : ERROR_NO_DATA;
}
extern "C" DWORD WINAPI proxy_GetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved) {
    typedef DWORD (WINAPI* Real_t)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
    static Real_t real = (Real_t)GetRealProc("GetExtendedTcpTable");
    return real ? real(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved) : ERROR_INVALID_PARAMETER;
}
extern "C" DWORD WINAPI proxy_GetExtendedUdpTable(PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved) {
    typedef DWORD (WINAPI* Real_t)(PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG);
    static Real_t real = (Real_t)GetRealProc("GetExtendedUdpTable");
    return real ? real(pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved) : ERROR_INVALID_PARAMETER;
}
extern "C" DWORD WINAPI proxy_NotifyAddrChange(PHANDLE Handle, LPOVERLAPPED Overlapped) {
    typedef DWORD (WINAPI* Real_t)(PHANDLE, LPOVERLAPPED);
    static Real_t real = (Real_t)GetRealProc("NotifyAddrChange");
    return real ? real(Handle, Overlapped) : ERROR_INVALID_PARAMETER;
}
extern "C" ULONG WINAPI proxy_GetBestInterfaceEx(struct sockaddr* pDestAddr, PDWORD pdwBestIfIndex) {
    typedef ULONG (WINAPI* Real_t)(struct sockaddr*, PDWORD);
    static Real_t real = (Real_t)GetRealProc("GetBestInterfaceEx");
    return real ? real(pDestAddr, pdwBestIfIndex) : ERROR_NO_DATA;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD, LPVOID) { DisableThreadLibraryCalls(hModule); return TRUE; }
