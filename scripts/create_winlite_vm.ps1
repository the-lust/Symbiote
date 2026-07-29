<#
.SYNOPSIS
    Creates a Hyper-V Gen-2 VM booting from a Windows Lite VHDX.
    This is QEMU Tier A — full Windows guest with WHPX acceleration.
    
    The VM has NO:
    - Network adapter (isolated)
    - Audio adapter
    - GPU passthru (uses basic framebuffer)
    - Clipboard/integration services
    
    It has ONLY:
    - 2 vCPUs with WHPX
    - 2-4GB RAM
    - Boot from WinLite VHDX
.NOTES
    Requires: Hyper-V enabled, Admin privileges
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$VHDXPath = "D:\emu\winlite\winlite.vhdx",
    
    [Parameter(Mandatory=$false)]
    [string]$VMName = "Genjutsu-WinLite",
    
    [Parameter(Mandatory=$false)]
    [int]$CpuCount = 2,
    
    [Parameter(Mandatory=$false)]
    [int]$RamMB = 2048,
    
    [Parameter(Mandatory=$false)]
    [switch]$DestroyExisting
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command "New-VM" -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Hyper-V PowerShell module not available." -ForegroundColor Red
    Write-Host "Install: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell"
    exit 1
}

if (-not (Test-Path $VHDXPath)) {
    Write-Host "ERROR: VHDX not found at $VHDXPath" -ForegroundColor Red
    Write-Host "Run build_minimal_win.ps1 first, or provide -VHDXPath"
    exit 1
}

if ($DestroyExisting) {
    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($vm) {
        $vm | Stop-VM -TurnOff -Force -ErrorAction SilentlyContinue
        $vm | Remove-VM -Force
        Write-Host "Existing VM '$VMName' removed." -ForegroundColor Yellow
    }
}

Write-Host "Creating VM '$VMName'..." -ForegroundColor Cyan

# Create Gen-2 VM with minimal features
$vmParams = @{
    Name = $VMName
    MemoryStartupBytes = $RamMB * 1MB
    Generation = 2
    BootDevice = "VHD"
    VHDPath = $VHDXPath
    SwitchName = $null  # No network
    NoVHD = $false
}
New-VM @vmParams

# Configure
$vm = Get-VM -Name $VMName
$vm | Set-VMProcessor -Count $CpuCount -ExposeVirtualizationExtensions $true
$vm | Set-VMMemory -DynamicMemoryEnabled $false

# Remove all unnecessary devices
$vm | Get-VMNetworkAdapter | Remove-VMNetworkAdapter -Force -ErrorAction SilentlyContinue
$vm | Get-VMDvdDrive | Remove-VMDvdDrive -Force -ErrorAction SilentlyContinue
$vm | Get-VMFloppyDiskDrive | Remove-VMFloppyDiskDrive -Force -ErrorAction SilentlyContinue

# Disable integration services (keep only Heartbeat)
$vm | Disable-VMIntegrationService -Name "Shutdown" -ErrorAction SilentlyContinue
$vm | Disable-VMIntegrationService -Name "Time Synchronization" -ErrorAction SilentlyContinue
$vm | Disable-VMIntegrationService -Name "Data Exchange" -ErrorAction SilentlyContinue
$vm | Disable-VMIntegrationService -Name "Guest Service Interface" -ErrorAction SilentlyContinue
$vm | Disable-VMIntegrationService -Name "Key Pair" -ErrorAction SilentlyContinue

# Set automatic stop action
$vm | Set-VM -AutomaticStopAction TurnOff -AutomaticStartAction Nothing

Write-Host @"

    VM '$VMName' created.
    
    To start:     Start-VM -Name $VMName
    To connect:   vmconnect localhost $VMName
    To stop:      Stop-VM -Name $VMName -TurnOff

    WARNING: No network, no audio, no integration services.
    This is an isolated sandbox VM.

"@ -ForegroundColor Green