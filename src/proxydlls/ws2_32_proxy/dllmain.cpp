#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "Logger.h"
#include "ProxyExport.h"

// argbytes = paramCount * 4. SOCKET is u64 on x64 but pushed as 4 bytes on x86.
// On x86 every param below is 4 bytes; counts are read from the signatures above.
PROXY_EXPORT(WSAGetLastError,         proxy_WSAGetLastError,          0)  // 0
PROXY_EXPORT(WSAStartup,              proxy_WSAStartup,               8)  // 2
PROXY_EXPORT(WSACleanup,              proxy_WSACleanup,               0)  // 0
PROXY_EXPORT(socket,                  proxy_socket,                  12)  // 3
PROXY_EXPORT(bind,                    proxy_bind,                    12)  // 3
PROXY_EXPORT(listen,                  proxy_listen,                   8)  // 2
PROXY_EXPORT(accept,                  proxy_accept,                  12)  // 3
PROXY_EXPORT(connect,                 proxy_connect,                 12)  // 3
PROXY_EXPORT(send,                    proxy_send,                    16)  // 4
PROXY_EXPORT(recv,                    proxy_recv,                    16)  // 4
PROXY_EXPORT(closesocket,             proxy_closesocket,              4)  // 1
PROXY_EXPORT(select,                  proxy_select,                  20)  // 5
PROXY_EXPORT(ioctlsocket,             proxy_ioctlsocket,             12)  // 3
PROXY_EXPORT(setsockopt,              proxy_setsockopt,              20)  // 5
PROXY_EXPORT(getsockopt,              proxy_getsockopt,              20)  // 5
PROXY_EXPORT(getsockname,             proxy_getsockname,             12)  // 3
PROXY_EXPORT(getpeername,             proxy_getpeername,             12)  // 3
PROXY_EXPORT(gethostbyname,           proxy_gethostbyname,            4)  // 1
PROXY_EXPORT(gethostbyaddr,           proxy_gethostbyaddr,           12)  // 3
PROXY_EXPORT(getaddrinfo,             proxy_getaddrinfo,             16)  // 4
PROXY_EXPORT(freeaddrinfo,            proxy_freeaddrinfo,             4)  // 1
PROXY_EXPORT(inet_ntop,               proxy_inet_ntop,               16)  // 4
PROXY_EXPORT(inet_pton,               proxy_inet_pton,               12)  // 3
PROXY_EXPORT(WSAIoctl,                proxy_WSAIoctl,                36)  // 9
PROXY_EXPORT(WSASocketW,              proxy_WSASocketW,              24)  // 6
PROXY_EXPORT(WSAAccept,               proxy_WSAAccept,               20)  // 5
PROXY_EXPORT(WSASend,                 proxy_WSASend,                 28)  // 7
PROXY_EXPORT(WSARecv,                 proxy_WSARecv,                 28)  // 7
PROXY_EXPORT(WSAPoll,                 proxy_WSAPoll,                 12)  // 3
PROXY_EXPORT(WSAGetOverlappedResult,  proxy_WSAGetOverlappedResult,  20)  // 5

static FARPROC GetRealProc(const char* name)
{
    static HMODULE hReal = LoadLibraryW(L"ws2_32.dll");
    return hReal ? GetProcAddress(hReal, name) : nullptr;
}

extern "C" int WINAPI proxy_WSAGetLastError() {
    typedef int (WINAPI* Real_t)();
    static Real_t real = (Real_t)GetRealProc("WSAGetLastError");
    return real ? real() : 0;
}
extern "C" int WINAPI proxy_WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData) {
    typedef int (WINAPI* Real_t)(WORD, LPWSADATA);
    static Real_t real = (Real_t)GetRealProc("WSAStartup");
    return real ? real(wVersionRequested, lpWSAData) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_WSACleanup() {
    typedef int (WINAPI* Real_t)();
    static Real_t real = (Real_t)GetRealProc("WSACleanup");
    return real ? real() : SOCKET_ERROR;
}
extern "C" SOCKET WINAPI proxy_socket(int af, int type, int protocol) {
    typedef SOCKET (WINAPI* Real_t)(int, int, int);
    static Real_t real = (Real_t)GetRealProc("socket");
    return real ? real(af, type, protocol) : INVALID_SOCKET;
}
extern "C" int WINAPI proxy_bind(SOCKET s, const struct sockaddr* addr, int namelen) {
    typedef int (WINAPI* Real_t)(SOCKET, const struct sockaddr*, int);
    static Real_t real = (Real_t)GetRealProc("bind");
    return real ? real(s, addr, namelen) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_listen(SOCKET s, int backlog) {
    typedef int (WINAPI* Real_t)(SOCKET, int);
    static Real_t real = (Real_t)GetRealProc("listen");
    return real ? real(s, backlog) : SOCKET_ERROR;
}
extern "C" SOCKET WINAPI proxy_accept(SOCKET s, struct sockaddr* addr, int* addrlen) {
    typedef SOCKET (WINAPI* Real_t)(SOCKET, struct sockaddr*, int*);
    static Real_t real = (Real_t)GetRealProc("accept");
    return real ? real(s, addr, addrlen) : INVALID_SOCKET;
}
extern "C" int WINAPI proxy_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    typedef int (WINAPI* Real_t)(SOCKET, const struct sockaddr*, int);
    static Real_t real = (Real_t)GetRealProc("connect");
    return real ? real(s, name, namelen) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_send(SOCKET s, const char* buf, int len, int flags) {
    typedef int (WINAPI* Real_t)(SOCKET, const char*, int, int);
    static Real_t real = (Real_t)GetRealProc("send");
    return real ? real(s, buf, len, flags) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_recv(SOCKET s, char* buf, int len, int flags) {
    typedef int (WINAPI* Real_t)(SOCKET, char*, int, int);
    static Real_t real = (Real_t)GetRealProc("recv");
    return real ? real(s, buf, len, flags) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_closesocket(SOCKET s) {
    typedef int (WINAPI* Real_t)(SOCKET);
    static Real_t real = (Real_t)GetRealProc("closesocket");
    return real ? real(s) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout) {
    typedef int (WINAPI* Real_t)(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
    static Real_t real = (Real_t)GetRealProc("select");
    return real ? real(nfds, readfds, writefds, exceptfds, timeout) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_ioctlsocket(SOCKET s, long cmd, u_long* argp) {
    typedef int (WINAPI* Real_t)(SOCKET, long, u_long*);
    static Real_t real = (Real_t)GetRealProc("ioctlsocket");
    return real ? real(s, cmd, argp) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen) {
    typedef int (WINAPI* Real_t)(SOCKET, int, int, const char*, int);
    static Real_t real = (Real_t)GetRealProc("setsockopt");
    return real ? real(s, level, optname, optval, optlen) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen) {
    typedef int (WINAPI* Real_t)(SOCKET, int, int, char*, int*);
    static Real_t real = (Real_t)GetRealProc("getsockopt");
    return real ? real(s, level, optname, optval, optlen) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_getsockname(SOCKET s, struct sockaddr* name, int* namelen) {
    typedef int (WINAPI* Real_t)(SOCKET, struct sockaddr*, int*);
    static Real_t real = (Real_t)GetRealProc("getsockname");
    return real ? real(s, name, namelen) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_getpeername(SOCKET s, struct sockaddr* name, int* namelen) {
    typedef int (WINAPI* Real_t)(SOCKET, struct sockaddr*, int*);
    static Real_t real = (Real_t)GetRealProc("getpeername");
    return real ? real(s, name, namelen) : SOCKET_ERROR;
}
extern "C" struct hostent* WINAPI proxy_gethostbyname(const char* name) {
    typedef struct hostent* (WINAPI* Real_t)(const char*);
    static Real_t real = (Real_t)GetRealProc("gethostbyname");
    return real ? real(name) : NULL;
}
extern "C" struct hostent* WINAPI proxy_gethostbyaddr(const char* addr, int len, int type) {
    typedef struct hostent* (WINAPI* Real_t)(const char*, int, int);
    static Real_t real = (Real_t)GetRealProc("gethostbyaddr");
    return real ? real(addr, len, type) : NULL;
}
extern "C" int WINAPI proxy_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
    typedef int (WINAPI* Real_t)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
    static Real_t real = (Real_t)GetRealProc("getaddrinfo");
    return real ? real(node, service, hints, res) : SOCKET_ERROR;
}
extern "C" void WINAPI proxy_freeaddrinfo(struct addrinfo* res) {
    typedef void (WINAPI* Real_t)(struct addrinfo*);
    static Real_t real = (Real_t)GetRealProc("freeaddrinfo");
    if (real) real(res);
}
extern "C" const char* WINAPI proxy_inet_ntop(int af, const void* src, char* dst, socklen_t size) {
    typedef const char* (WINAPI* Real_t)(int, const void*, char*, socklen_t);
    static Real_t real = (Real_t)GetRealProc("inet_ntop");
    return real ? real(af, src, dst, size) : NULL;
}
extern "C" int WINAPI proxy_inet_pton(int af, const char* src, void* dst) {
    typedef int (WINAPI* Real_t)(int, const char*, void*);
    static Real_t real = (Real_t)GetRealProc("inet_pton");
    return real ? real(af, src, dst) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    typedef int (WINAPI* Real_t)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    static Real_t real = (Real_t)GetRealProc("WSAIoctl");
    return real ? real(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine) : SOCKET_ERROR;
}
extern "C" SOCKET WINAPI proxy_WSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags) {
    typedef SOCKET (WINAPI* Real_t)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
    static Real_t real = (Real_t)GetRealProc("WSASocketW");
    return real ? real(af, type, protocol, lpProtocolInfo, g, dwFlags) : INVALID_SOCKET;
}
extern "C" SOCKET WINAPI proxy_WSAAccept(SOCKET s, struct sockaddr* addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD_PTR dwCallbackData) {
    typedef SOCKET (WINAPI* Real_t)(SOCKET, struct sockaddr*, LPINT, LPCONDITIONPROC, DWORD_PTR);
    static Real_t real = (Real_t)GetRealProc("WSAAccept");
    return real ? real(s, addr, addrlen, lpfnCondition, dwCallbackData) : INVALID_SOCKET;
}
extern "C" int WINAPI proxy_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    typedef int (WINAPI* Real_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    static Real_t real = (Real_t)GetRealProc("WSASend");
    return real ? real(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    typedef int (WINAPI* Real_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    static Real_t real = (Real_t)GetRealProc("WSARecv");
    return real ? real(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine) : SOCKET_ERROR;
}
extern "C" int WINAPI proxy_WSAPoll(LPWSAPOLLFD fdArray, ULONG fds, INT timeout) {
    typedef int (WINAPI* Real_t)(LPWSAPOLLFD, ULONG, INT);
    static Real_t real = (Real_t)GetRealProc("WSAPoll");
    return real ? real(fdArray, fds, timeout) : SOCKET_ERROR;
}
extern "C" BOOL WINAPI proxy_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED lpOverlapped, LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags) {
    typedef BOOL (WINAPI* Real_t)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
    static Real_t real = (Real_t)GetRealProc("WSAGetOverlappedResult");
    return real ? real(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags) : FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD, LPVOID) { DisableThreadLibraryCalls(hModule); return TRUE; }
