cmake_minimum_required(VERSION 3.20)
project(symbiote LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(MSVC)
    add_compile_options(/W4 /WX)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Werror)
endif()

option(SYMBIOTE_DEBUG "Enable debug logging in engine and launcher" OFF)
option(SYMBIOTE_MINGW "Build with MinGW compatibility (disable WHP-dependent features)" OFF)

if(SYMBIOTE_DEBUG)
    add_compile_definitions(SYMBIOTE_DEBUG=1)
endif()

# WHP requires x64 host — disable on x86 and MinGW builds
if(SYMBIOTE_MINGW OR CMAKE_SIZEOF_VOID_P LESS 8)
    set(SYMBIOTE_NO_WHP ON)
    add_compile_definitions(SYMBIOTE_NO_WHP=1)
endif()

# Find WHP SDK (only for MSVC x64 builds)
if(NOT SYMBIOTE_NO_WHP)
    find_path(WHP_INCLUDE_DIR WinHvPlatform.h)
    find_library(WHP_LIBRARY WinHvPlatform)
    if(NOT WHP_LIBRARY)
        set(WHP_LIBRARY "WinHvPlatform")
    endif()
else()
    set(WHP_INCLUDE_DIR "")
    set(WHP_LIBRARY "")
endif()

# ─── Logger (static lib, shared across all targets) ───────────────────
add_library(logger STATIC
    src/engine/log/Logger.cpp
)
target_include_directories(logger PUBLIC src/engine/log)

# ─── Launcher ─────────────────────────────────────────────────────────
set(LAUNCHER_SOURCES
    src/launcher/Main.cpp
    src/launcher/ConfigParser.cpp
    src/launcher/ProcessUtils.cpp
    src/launcher/app.manifest
)
if(NOT SYMBIOTE_NO_WHP)
    list(APPEND LAUNCHER_SOURCES src/launcher/WhpDetection.cpp)
endif()
add_executable(launcher WIN32 ${LAUNCHER_SOURCES})
target_include_directories(launcher PRIVATE src/launcher src/engine/log)
target_link_libraries(launcher PRIVATE logger)
if(NOT SYMBIOTE_NO_WHP)
    target_link_libraries(launcher PRIVATE ${WHP_LIBRARY})
endif()

# ─── Engine DLL ───────────────────────────────────────────────────────
set(ENGINE_SOURCES
    src/launcher/ConfigParser.cpp
    src/engine/Main.cpp
    src/engine/whp/AllocTracker.cpp
    src/engine/whp/SystemSpoofer.cpp
    src/engine/whp/SyscallDispatch.cpp
    src/engine/whp/KuserHook.cpp
    src/engine/whp/Canary.cpp
    # Syscall emulator
    src/engine/emu/CryptoEmu.cpp
    src/engine/emu/FileEmu.cpp
    src/engine/emu/MemoryEmu.cpp
    src/engine/emu/ObjectEmu.cpp
    src/engine/emu/PeLoader.cpp
    src/engine/emu/ProcessEmu.cpp
    src/engine/emu/RegistryEmu.cpp
    src/engine/emu/SectionEmu.cpp

    src/engine/emu/SyscallNames.cpp
    src/engine/emu/ThreadManager.cpp
    src/engine/emu/TimingEmu.cpp
    src/engine/emu/VirtualState.cpp
    # Kernel abstraction
    src/engine/kernel/MinimalKernel.cpp
    src/engine/kernel/SystemProfile.cpp
    src/engine/kernel/KernelBackend.cpp
    # Profiles
    src/engine/profile/GpuProfile.cpp
    src/engine/profile/StorageProfile.cpp
    # Capture logger
    src/engine/capture/CaptureLogger.cpp
    # Proxy/IAT support
    src/engine/proxy/Fallthrough.cpp
    src/engine/proxy/GpuBridge.cpp
    src/engine/proxy/IatPatch.cpp
    src/engine/proxy/InlineHook.cpp
    src/engine/proxy/InstructionDecoder.cpp
    src/engine/proxy/ModuleCloak.cpp
    src/engine/proxy/ProxyBase.cpp
    src/engine/proxy/SyscallBridge.cpp
)
if(NOT SYMBIOTE_NO_WHP)
    list(APPEND ENGINE_SOURCES
        # WHP-dependent components (x64 only)
        src/engine/whp/CpuidHandler.cpp
        src/engine/whp/ExceptionHandler.cpp
        src/engine/whp/ExitDispatcher.cpp
        src/engine/whp/EptHook.cpp
        src/engine/whp/KuserSync.cpp
        src/engine/whp/MagicCpuid.cpp
        src/engine/whp/MsrHandler.cpp
        src/engine/whp/Partition.cpp
        src/engine/whp/RdtscHandler.cpp
        src/engine/whp/ThreadScheduler.cpp
        src/engine/whp/GuestPageTable.cpp
        src/engine/whp/VcpuManager.cpp
    )
endif()
add_library(engine SHARED ${ENGINE_SOURCES})
target_include_directories(engine PRIVATE src/engine src/engine/log src/launcher)
target_link_libraries(engine PRIVATE logger)
if(NOT SYMBIOTE_NO_WHP)
    target_link_libraries(engine PRIVATE ${WHP_LIBRARY})
endif()
if(WIN32)
    target_link_libraries(engine PRIVATE dbghelp)
endif()

# ─── Proxy DLL helper ────────────────────────────────────────────────
function(add_proxy_dll name source)
    string(REPLACE "_proxy" "" output_name "${name}")
    add_library("${name}" SHARED "${source}")
    target_include_directories("${name}" PRIVATE src/proxydlls/shared src/engine/log)
    target_link_libraries("${name}" PRIVATE logger)
    set_target_properties("${name}" PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
        OUTPUT_NAME "${output_name}"
    )
endfunction()

# Existing proxy DLLs
add_proxy_dll(ntdll_proxy      src/proxydlls/ntdll_proxy/dllmain.cpp)
add_proxy_dll(kernel32_proxy   src/proxydlls/kernel32_proxy/dllmain.cpp)
add_proxy_dll(kernelbase_proxy src/proxydlls/kernelbase_proxy/dllmain.cpp)
add_proxy_dll(advapi32_proxy   src/proxydlls/advapi32_proxy/dllmain.cpp)
add_proxy_dll(user32_proxy     src/proxydlls/user32_proxy/dllmain.cpp)
add_proxy_dll(wbem_proxy       src/proxydlls/wbem_proxy/dllmain.cpp)

# New proxy DLL stubs
add_proxy_dll(wtsapi32_proxy   src/proxydlls/wtsapi32_proxy/dllmain.cpp)
add_proxy_dll(secur32_proxy    src/proxydlls/secur32_proxy/dllmain.cpp)
add_proxy_dll(crypt32_proxy    src/proxydlls/crypt32_proxy/dllmain.cpp)
add_proxy_dll(winhttp_proxy    src/proxydlls/winhttp_proxy/dllmain.cpp)
add_proxy_dll(dnsapi_proxy     src/proxydlls/dnsapi_proxy/dllmain.cpp)
add_proxy_dll(iphlpapi_proxy   src/proxydlls/iphlpapi_proxy/dllmain.cpp)
add_proxy_dll(ws2_32_proxy     src/proxydlls/ws2_32_proxy/dllmain.cpp)

# ─── Verify Tool ──────────────────────────────────────────────────────
add_executable(verify src/verify/Main.cpp)
target_include_directories(verify PRIVATE src/engine/log)
target_link_libraries(verify PRIVATE logger)

# ─── Handshake Test Tool ──────────────────────────────────────────────
add_executable(handshake_test tools/handshake_test/Main.cpp)

# ─── Capture Tool ──────────────────────────────────────────────────────
add_executable(capture_tool tools/capture/Main.cpp)

# ─── MSR Reader Tool (requires semav6msr64 driver) ─────────────────────
add_executable(msr_reader tools/msr_reader/Main.cpp)


