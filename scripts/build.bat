@echo off
setlocal enabledelayedexpansion

set ROOT=%~dp0..
set BUILD=%ROOT%\build
set PRESET=msvc-x64

if not "%1"=="" (
    if /i "%1"=="debug" set PRESET=msvc-x64-debug
    if /i "%1"=="x86" set PRESET=msvc-x86
    if /i "%1"=="x86-debug" set PRESET=msvc-x86-debug
    if /i "%1"=="mingw" set PRESET=mingw-x64
    if /i "%1"=="mingw-x86" set PRESET=mingw-x86
)

echo === Genjutsu Build System ===
echo Preset: %PRESET%
echo Root: %ROOT%
echo.

:: Clean
echo [1/4] Cleaning...
rd /s /q "%ROOT%\.vs" 2>nul
if exist "%TEMP%\MSBuild*" del /s /q "%TEMP%\MSBuild*" 2>nul
echo Done.
echo.

:: CMake Configure
echo [2/4] Configuring CMake...
cmake --preset %PRESET% 2>&1
if %ERRORLEVEL% neq 0 (
    echo CMake configure FAILED!
    exit /b 1
)
echo Done.
echo.

:: Build
echo [3/4] Building...
cmake --build --preset %PRESET% 2>&1
if %ERRORLEVEL% neq 0 (
    echo Build FAILED!
    exit /b 1
)
echo Done.
echo.

:: Output
echo [4/4] Build complete.
echo.
echo Output:
set "BIN=%BUILD%\%PRESET:\=/%/bin"
if "%PRESET:debug=%"=="%PRESET%" (
    set CFG_DIR=Release
) else (
    set CFG_DIR=Debug
)
echo   %BIN%\%CFG_DIR%\launcher.exe
echo   %BIN%\%CFG_DIR%\engine.dll
echo   %BIN%\%CFG_DIR%\*_proxy.dll (13 proxy DLLs)
echo.
echo ===== BUILD COMPLETE =====
