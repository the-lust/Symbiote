// ProxyExport.h — Architecture-aware export macro for proxy DLLs.
//
// Problem: proxy DLLs export WINAPI/__stdcall (NTAPI/SEC_ENTRY/STDMETHODCALLTYPE)
// functions via `#pragma comment(linker, "/EXPORT:Pub=Impl")`. On x64 this resolves
// fine (one calling convention, undecorated symbols). On x86 the compiler decorates
// the __stdcall symbol as `_Impl@<argbytes>`, so `/EXPORT:Pub=Impl` cannot find `Impl`
// and the linker reports LNK2001.
//
// Fix: PROXY_EXPORT(pub, impl, argbytes) emits the correct pragma per arch.
//   - x64 / non-Win32 : `/EXPORT:pub=impl`            (unchanged, undecorated)
//   - x86 (_M_IX86)   : `/EXPORT:pub=_impl@argbytes`  (matches decorated symbol)
//
// argbytes = (number of scalar/pointer parameters) * 4. All proxy exports here use
// only 4-byte scalars, pointers, or references (which decay to pointers), so this
// is a straight param-count * 4. A wrong count self-flags as a lingering LNK2001 on
// that exact symbol, so miscounts are trivially caught.
//
// Usage (replace the bare pragmas in each proxy dllmain.cpp):
//     PROXY_EXPORT(RegOpenKeyExW, Proxy_RegOpenKeyExW, 20)   // 5 params * 4
//
#pragma once

#if defined(_M_IX86) || (defined(_WIN32) && !defined(_M_X64) && !defined(_M_ARM64))
    // x86: __stdcall symbols are decorated by the compiler as _name@bytes.
    // The linker's /EXPORT directive must reference the exact decorated symbol,
    // so we emit the leading underscore and @bytes suffix explicitly.
    #define PROXY_EXPORT(pub, impl, argbytes) \
        __pragma(comment(linker, "/EXPORT:" #pub "=_" #impl "@" #argbytes))
#else
    // x64 / ARM64 / non-Win32: single calling convention, undecorated
    #define PROXY_EXPORT(pub, impl, argbytes) \
        __pragma(comment(linker, "/EXPORT:" #pub "=" #impl))
#endif
