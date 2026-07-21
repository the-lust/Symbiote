#Requires -Version 5.1

<#
.SYNOPSIS
    Symbiote developer environment setup script.
    Inspired by RedSand's OnHost provisioning pattern.

.DESCRIPTION
    Validates prerequisites, installs missing tooling, and configures the
    build environment. Run once after cloning the repo.

    Checks:
      - Visual Studio 2022+ with C++ workload
      - CMake 3.20+
      - Windows SDK
      - WHP availability

    Optional:
      - Install additional proxy DLL build dependencies
      - Create build directory junction
#>

$ErrorActionPreference = 'Stop'
$logFile = Join-Path $PSScriptRoot 'setup-dev.log'

function Write-Log {
    param([string]$Message)
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Message" | Add-Content -Path $logFile
    Write-Host $Message
}

try {
    Write-Log "=== Symbiote dev setup start ==="

    # ── Check VS 2022+ ──
    $vsPath = & {
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vswhere) {
            return & $vswhere -latest -property installationPath
        }
        $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vswhere) {
            return & $vswhere -latest -property installationPath
        }
        return $null
    }
    if ($vsPath) {
        Write-Log "Visual Studio found: $vsPath"
    } else {
        Write-Log "WARNING: Visual Studio not found via vswhere. Install VS 2022+ with C++ workload."
    }

    # ── Check CMake ──
    $cmake = Get-Command cmake -ErrorAction SilentlyContinue
    if ($cmake) {
        $cmakeVer = & cmake --version | Select-Object -First 1
        Write-Log "CMake found: $cmakeVer"
    } else {
        Write-Log "WARNING: CMake not found. Install CMake 3.20+ and add to PATH."
    }

    # ── Check Windows SDK ──
    $sdkPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Include\10.0.*\um\WinHvPlatform.h"
    $sdkFiles = Get-ChildItem $sdkPath -ErrorAction SilentlyContinue
    if ($sdkFiles) {
        Write-Log "Windows SDK found (WHP header present)"
    } else {
        Write-Log "WARNING: WinHvPlatform.h not found. Install latest Windows SDK."
    }

    # ── Check WHP availability ──
    $whpAvailable = $false
    try {
        $whp = Get-CimInstance -Namespace root\wmi -ClassName Msvm_VirtualSystemManagementService -ErrorAction Stop
        $whpAvailable = $true
    } catch {
        # Also check via feature state
        $sandbox = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction SilentlyContinue
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V" -ErrorAction SilentlyContinue
        if ($sandbox -and $sandbox.State -eq 'Enabled') {
            $whpAvailable = $true
        } elseif ($hyperv -and $hyperv.State -eq 'Enabled') {
            $whpAvailable = $true
        } else {
            Write-Log "WARNING: WHP not detected. Enable Windows Sandbox or Hyper-V for full functionality."
            Write-Log "  Run as Admin: Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All"
        }
    }
    if ($whpAvailable) {
        Write-Log "WHP available - full virtualization mode supported"
    }

    # ── Check git hooks ──
    $hooksDir = Join-Path $PSScriptRoot '.git\hooks'
    if (Test-Path $hooksDir) {
        Write-Log "Git hooks directory present"
    }

    # ── Create build directory placeholder ──
    $buildDir = Join-Path $PSScriptRoot 'build'
    if (-not (Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
        Write-Log "Created build directory: $buildDir"
    }

    Write-Log "=== Symbiote dev setup complete ==="
    Write-Log "Next step: cmake --preset msvc-x64 && cmake --build --preset msvc-x64"

} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log "ERROR at: $($_.ScriptStackTrace)"
    exit 1
}
