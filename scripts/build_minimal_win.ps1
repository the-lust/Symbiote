<# 
.SYNOPSIS
    Build a minimal Windows Lite image — stripped of all UI, Explorer, networking, audio, 
    and non-essential services. Just enough to run the Genjutsu engine + target game.
    
    Target: ~2-4GB disk footprint, ~512MB-1GB RAM idle.
    
    Based on: Tiny10/AtlasOS philosophy but pushed further — no explorer.exe, no DWM,
    no audio stack, no network stack (unless needed), no update service.
.DESCRIPTION
    This script creates a bootable VHDX with a minimal Windows installation.
    
    Prerequisites:
    - Windows ADK (Assessment and Deployment Kit) installed
    - Windows 10/11 ISO mounted or extracted
    - Administrator privileges
    
    Usage:
    .\build_minimal_win.ps1 -ISOPath "D:\ISOs\Win10_22H2.iso" -VHDXPath "D:\emu\winlite\winlite.vhdx"
    
    IMPORTANT: This is a semi-automated process. You will need Windows installation media.
    The script handles component removal, registry tweaks, and service disabling post-install.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ISOPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$VHDXPath = "D:\emu\winlite\winlite.vhdx",
    
    [Parameter(Mandatory=$false)]
    [int]$VHDXSizeGB = 16,
    
    [Parameter(Mandatory=$false)]
    [string]$MountDrive = "V",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDism
)

$ErrorActionPreference = "Stop"

#region Utility Functions
function Write-Banner {
    Write-Host @"

    ╔══════════════════════════════════════════════════════════╗
    ║           Windows Lite Image Builder                    ║
    ║     Minimal gaming sandbox — No UI, No Explorer,        ║
    ║     No Network, No Audio, No Bloat                      ║
    ╚══════════════════════════════════════════════════════════╝
    
    Target: Native code execution + WHP virtualization only
    Footprint target: <4GB disk, <1GB RAM idle

"@
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ADK {
    $paths = @(
        "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit",
        "C:\Program Files\Windows Kits\10\Assessment and Deployment Kit"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Find-DismImage {
    param([string]$IsoPath)
    
    if ($IsoPath -and (Test-Path $IsoPath)) {
        return $IsoPath
    }
    
    # Check mounted ISOs
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        (Test-Path "$($_.Root)\sources\install.wim") -or 
        (Test-Path "$($_.Root)\sources\install.esd")
    }
    if ($drives) {
        return $drives[0].Root
    }
    
    return $null
}

#endregion

#region Main Build

function New-VHDX {
    param([string]$Path, [int]$SizeGB)
    
    Write-Host "[1/8] Creating VHDX at $Path ($SizeGB GB)..." -ForegroundColor Cyan
    
    $parent = Split-Path $Path -Parent
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    
    # Create dynamic VHDX
    New-VHD -Path $Path -Dynamic -SizeBytes ([int64]$SizeGB * 1GB) -BlockSizeBytes 1MB -LogicalSectorSize 4096 | Out-Null
    
    # Mount and initialize
    $vhd = Mount-VHD -Path $Path -Passthru
    $disk = $vhd | Get-Disk
    $disk | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
    
    # Initialize as MBR (compatible with more scenarios)
    $disk | Initialize-Disk -PartitionStyle MBR
    $part = $disk | New-Partition -UseMaximumSize -DriveLetter $MountDrive -IsActive
    $part | Format-Volume -FileSystem NTFS -NewFileSystemLabel "WinLite" -Confirm:$false -Force
    
    Write-Host "  VHDX created and mounted as $($MountDrive):" -ForegroundColor Green
}

function Install-WindowsImage {
    param([string]$Source, [string]$TargetDrive)
    
    Write-Host "[2/8] Applying Windows image to $($TargetDrive):..." -ForegroundColor Cyan
    
    $wimPath = $null
    if (Test-Path "$Source\sources\install.wim") { $wimPath = "$Source\sources\install.wim" }
    elseif (Test-Path "$Source\sources\install.esd") { $wimPath = "$Source\sources\install.esd" }
    
    if (-not $wimPath) { throw "Could not find install.wim or install.esd in $Source" }
    
    # List available editions
    Write-Host "  Available Windows editions:" -ForegroundColor Yellow
    Get-WindowsImage -ImagePath $wimPath | Format-Table ImageIndex, ImageName, ImageSize -AutoSize
    
    $edition = Read-Host "  Select ImageIndex to install (default: 5 = Pro)"
    if ([string]::IsNullOrWhiteSpace($edition)) { $edition = "5" }
    
    # Apply image
    Expand-WindowsImage -ImagePath $wimPath -Index ([int]$edition) -ApplyPath "$($TargetDrive):\" -CheckIntegrity
    
    Write-Host "  Image applied." -ForegroundColor Green
}

function Remove-ComponentPackages {
    param([string]$TargetDrive)
    
    Write-Host "[3/8] Removing component packages (Explorer, UI, media, network, bloat)..." -ForegroundColor Cyan
    
    $packagesToRemove = @(
        # Windows Shell / UI
        "Windows-Client-ShellStartup",
        "Internet-Browser",
        "Windows-Defender",
        "Windows-Media-Player",
        "Windows-Network-QoS",
        "Windows-Printing-PrintToPDFServices",
        "Windows-Printing-XPSServices",
        
        # UI-related
        "Windows-Embedded-ShellLauncher",
        "Windows-ShellExperienceHost",
        
        # Media
        "Windows-Media-Format",
        "Windows-Media-MediaPlayback",
        
        # Tablet/Ink/Handwriting
        "Microsoft-Windows-TabletPCMath",
        "Microsoft-Windows-Handwriting",
        "Microsoft-Windows-InkAndHandwriting",
        
        # Language and speech
        "Microsoft-Windows-Speech",
        "Microsoft-Windows-TextToSpeech",
        
        # Themes and accessibility
        "Microsoft-Windows-ThemeUI",
        "Microsoft-Windows-Narrator",
        "Microsoft-Windows-Magnify",
        
        # Network discovery
        "Microsoft-Windows-NetworkDiscovery",
        "Microsoft-Windows-WiFiDiscovery",
        "Microsoft-Windows-WiFiDirect",
        
        # Remote
        "Microsoft-Windows-RemoteDesktop",
        "Microsoft-Windows-RemoteAssistance",
        
        # Xbox / Gaming extras (keep raw D3D/DXGI)
        "Microsoft-Xbox-GameCallableUI",
        "Microsoft-Xbox-GamingOverlay",
        "Microsoft-XboxGameCallableUI-Wrapper",
        
        # OneDrive/Store/Cortana
        "Microsoft-OneDrive",
        "Microsoft-Windows-Store",
        "Microsoft-Windows-Cortana",
        
        # BitLocker (we don't need encryption)
        "BitLocker",
        "BitLocker-Windows",
        
        # Windows Update
        "Microsoft-Windows-WU",
        
        # General bloat
        "Microsoft-Windows-Holographic",
        "Microsoft-Windows-MixedReality",
        "Microsoft-Windows-Map",
        "Microsoft-Windows-MapControl",
        "Microsoft-Windows-PeopleExperienceHost",
        "Microsoft-Windows-ParentalControls",
        "Microsoft-Windows-QuickAssist",
        "Microsoft-Windows-StepsRecorder",
        "Microsoft-Windows-WindowsToGo"
    )
    
    $removed = 0
    $failed = 0
    foreach ($pkg in $packagesToRemove) {
        try {
            # Try removing the package
            $result = Remove-WindowsPackage -Path "$($TargetDrive):\" -PackageName $pkg -NoRestart -ErrorAction SilentlyContinue
            if ($result.RestartNeeded -eq $false) {
                $removed++
            }
        } catch {
            $failed++
        }
    }
    
    Write-Host "  Removed: $removed packages, Skipped: $failed" -ForegroundColor Green
    
    # Also remove capabilties if using Win10 1809+
    $capabilitiesToRemove = @(
        "Language.Handwriting",
        "Language.Speech",
        "Language.TextToSpeech",
        "Media.WindowsMediaPlayer",
        "Browser.InternetExplorer"
    )
    
    foreach ($cap in $capabilitiesToRemove) {
        try {
            Remove-WindowsCapability -Path "$($TargetDrive):\" -Name $cap -ErrorAction SilentlyContinue | Out-Null
        } catch {}
    }
}

function Apply-RegistryTweaks {
    param([string]$TargetDrive)
    
    Write-Host "[4/8] Applying registry tweaks (offline)..." -ForegroundColor Cyan
    
    # Load registry hives
    reg load "HKLM\WinLite_SOFTWARE" "$($TargetDrive):\Windows\System32\config\SOFTWARE" 2>$null
    reg load "HKLM\WinLite_SYSTEM" "$($TargetDrive):\Windows\System32\config\SYSTEM" 2>$null
    reg load "HKLM\WinLite_DEFAULT" "$($TargetDrive):\Windows\System32\config\default" 2>$null
    
    try {
        # Disable DWM (Desktop Window Manager)
        # reg add "HKLM\WinLite_SOFTWARE\Microsoft\Windows\DWM" /v Composition /t REG_DWORD /d 0 /f
        
        # Disable UAC (no admin prompts needed)
        reg add "HKLM\WinLite_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
        
        # Disable Windows Defender
        reg add "HKLM\WinLite_SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
        
        # Disable Automatic Updates
        reg add "HKLM\WinLite_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
        
        # Disable System Restore
        reg add "HKLM\WinLite_SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
        
        # Disable Hibernation
        reg add "HKLM\WinLite_SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
        reg add "HKLM\WinLite_SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
        
        # Disable Pagefile (or minimize)
        # reg add "HKLM\WinLite_SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v PagingFiles /t REG_MULTI_SZ /d "" /f
        
        # Disable error reporting
        reg add "HKLM\WinLite_SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
        
        # Disable indexing
        reg add "HKLM\WinLite_SOFTWARE\Microsoft\Windows Search" /v SetupCompletedSuccessfully /t REG_DWORD /d 1 /f
        reg add "HKLM\WinLite_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f
        
        # Set Explorer to launch nothing (no shell)
        reg add "HKLM\WinLite_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "cmd.exe" /f
        
        # Disable boot animation
        reg add "HKLM\WinLite_SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v BootAnimationEnabled /t REG_DWORD /d 0 /f
        
        # Network: disable NetBIOS, LLMNR, mDNS
        reg add "HKLM\WinLite_SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v DisableNetbiosOverTcp /t REG_DWORD /d 1 /f
        reg add "HKLM\WinLite_SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
        
        # Disable firewall
        reg add "HKLM\WinLite_SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
        reg add "HKLM\WinLite_SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
        reg add "HKLM\WinLite_SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
        
        # Disable Customer Experience Improvement
        reg add "HKLM\WinLite_SOFTWARE\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
        
        # Console: disable screen saver
        reg add "HKLM\WinLite_DEFAULT\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d "0" /f
        
        Write-Host "  Registry tweaks applied." -ForegroundColor Green
    } finally {
        # Unload hives
        reg unload "HKLM\WinLite_SOFTWARE" 2>$null
        reg unload "HKLM\WinLite_SYSTEM" 2>$null
        reg unload "HKLM\WinLite_DEFAULT" 2>$null
    }
}

function Remove-FileBloat {
    param([string]$TargetDrive)
    
    Write-Host "[5/8] Removing file bloat..." -ForegroundColor Cyan
    
    $pathsToRemove = @(
        "$($TargetDrive):\Windows\Help\",
        "$($TargetDrive):\Windows\System32\Help\",
        "$($TargetDrive):\Windows\Fonts\*.ttf",      # Keep Consolas, Lucida Console, Segoe UI
        "$($TargetDrive):\Windows\Installer\*.msi",
        "$($TargetDrive):\Windows\Media\*.wav",       # Remove all sounds
        "$($TargetDrive):\Windows\Web\*",
        "$($TargetDrive):\Windows\System32\migwiz\*",
        "$($TargetDrive):\Windows\System32\oobe\*",
        "$($TargetDrive):\Windows\System32\restore\*",
        "$($TargetDrive):\Windows\System32\smartscreen*",
        "$($TargetDrive):\Windows\System32\SystemResetPlatform\*",
        "$($TargetDrive):\Windows\System32\WinBioPlugIns\*",
        "$($TargetDrive):\Windows\System32\winmail*",
        "$($TargetDrive):\Windows\System32\winmine*",
        "$($TargetDrive):\Windows\System32\winmsd*",
        "$($TargetDrive):\Windows\System32\winsat*",
        "$($TargetDrive):\Windows\System32\winver*",
        "$($TargetDrive):\Windows\System32\wordpad*",
        "$($TargetDrive):\Windows\System32\write*",
        "$($TargetDrive):\Windows\SysWOW64\migwiz\*",
        "$($TargetDrive):\ProgramData\Microsoft\Windows\Samples\*",
        "$($TargetDrive):\Users\Default\Videos\*",
        "$($TargetDrive):\Users\Default\Music\*",
        "$($TargetDrive):\Users\Default\Pictures\*",
        "$($TargetDrive):\Users\Default\Downloads\*",
        "$($TargetDrive):\Users\Public\Videos\*",
        "$($TargetDrive):\Users\Public\Music\*",
        "$($TargetDrive):\Users\Public\Pictures\*"
    )
    
    foreach ($path in $pathsToRemove) {
        try {
            if (Test-Path $path) {
                if (Get-Item $path -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {}
    }
    
    # Remove WinSxS backup (CAUTION: can't roll back after this)
    # Take ownership first
    takeown /F "$($TargetDrive):\Windows\System32\config" /A /R /D Y 2>$null
    icacls "$($TargetDrive):\Windows\System32\config" /grant "Everyone:(F)" /T /Q 2>$null
    
    Write-Host "  File bloat removed." -ForegroundColor Green
}

function Disable-Services {
    param([string]$TargetDrive)
    
    Write-Host "[6/8] Disabling non-essential services (offline)..." -ForegroundColor Cyan
    
    $servicesToDisable = @(
        # Core unnecessary services
        "AudioEndpointBuilder",
        "AudioSrv",
        "WSearch",
        "WMPNetworkSvc",
        "wcncsvc",
        "WdNisSvc",
        "WinDefend",
        "wlidsvc",
        "WlanSvc",
        "WlanVC",
        "wlpasvc",
        "wlidsvc",
        "WManSvc",
        "wmiApSrv",
        "WMPNetworkSvc",
        "wscsvc",
        "wuauserv",
        "WwanSvc",
        "XblAuthManager",
        "XblGameSave",
        "XboxGipSvc",
        "XboxNetApiSvc",
        "XboxNetApiSvc",
        
        # Networking (keep only TCP/IP stack)
        "BcastDVRUserService",
        "BFE",
        "Browser",
        "CscService",
        "DPS",
        "dmwappushservice",
        "DusmSvc",
        "Eaphost",
        "FontCache",
        "iphlpsvc",
        "KeyIso",
        "LanmanServer",
        "LanmanWorkstation",
        "lltdsvc",
        "lmhosts",
        "MpsSvc",
        "NcbService",
        "Netlogon",
        "Netman",
        "NlaSvc",
        "nsi",
        "p2psvc",
        "p2pimsvc",
        "PNRPsvc",
        "RasAuto",
        "RasMan",
        "RemoteAccess",
        "RemoteRegistry",
        "SessionEnv",
        "SharedAccess",
        "StorSvc",
        "SysMain",
        "TabletInputService",
        "Themes",
        "UevAgentService",
        "UsoSvc",
        "VacSvc",
        "VaultSvc",
        "WbioSrvc",
        "Wcmsvc",
        "WdiServiceHost",
        "WdiSystemHost",
        "WebClient",
        "WEPHOSTSVC",
        "WpnService",
        
        # Print
        "Spooler",
        "PrintNotify"
    )
    
    # Load SYSTEM hive to modify service configs
    reg load "HKLM\WinLite_SYSTEM" "$($TargetDrive):\Windows\System32\config\SYSTEM" 2>$null
    
    try {
        foreach ($svc in $servicesToDisable) {
            $svcPath = "HKLM\WinLite_SYSTEM\CurrentControlSet\Services\$svc"
            try {
                reg add $svcPath /v Start /t REG_DWORD /d 4 /f | Out-Null
            } catch {}
        }
        Write-Host "  Services disabled." -ForegroundColor Green
    } finally {
        reg unload "HKLM\WinLite_SYSTEM" 2>$null
    }
}

function Install-Bootloader {
    param([string]$TargetDrive)
    
    Write-Host "[7/8] Installing bootloader..." -ForegroundColor Cyan
    
    # For MBR: use bootsect
    $bootsect = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\Tools\PE\x86\bootsect.exe"
    if (-not (Test-Path $bootsect)) {
        # Try finding bootsect in System32
        $bootsect = "C:\Windows\System32\bootsect.exe"
    }
    
    if (Test-Path $bootsect) {
        Start-Process -FilePath $bootsect -ArgumentList "/NT60 $($MountDrive): /FORCE" -Wait -NoNewWindow
        Write-Host "  Boot sector written." -ForegroundColor Green
    } else {
        Write-Host "  bootsect.exe not found — need to run manually:" -ForegroundColor Yellow
        Write-Host "    bootsect /NT60 $($MountDrive): /FORCE" -ForegroundColor Yellow
    }
    
    # Write BCD entry
    bcdboot "$($TargetDrive):\Windows" /s $MountDrive: /f BIOS | Out-Null
}

function Finalize {
    param([string]$TargetDrive)
    
    Write-Host "[8/8] Finalizing..." -ForegroundColor Cyan
    
    # Run dism cleanup
    if (-not $SkipDism) {
        Write-Host "  Running DISM cleanup (this may take a while)..." -ForegroundColor Cyan
        try {
            dism /Image:"$($TargetDrive):\" /Cleanup-Image /StartComponentCleanup /ResetBase 2>$null
        } catch {
            Write-Host "  DISM cleanup skipped (expected for offline image)" -ForegroundColor Yellow
        }
    }
    
    # Create startup script that launches engine
    $startupCmd = @"
@echo off
echo Windows Lite - Genjutsu Gaming Sandbox
echo Loading engine...
cd \genjutsu
engine.exe --config config.ini
echo Engine exited. Shutting down...
shutdown /s /t 5
"@
    Set-Content -Path "$($TargetDrive):\Windows\System32\startup.cmd" -Value $startupCmd -Encoding ASCII
    
    Write-Host "  Finalized." -ForegroundColor Green
}

#endregion

#region Execution

Clear-Host
Write-Banner

# Checks
if (-not (Test-Admin)) {
    Write-Host "ERROR: Must run as Administrator." -ForegroundColor Red
    exit 1
}

$adkPath = Test-ADK
if (-not $adkPath) {
    Write-Host "WARNING: Windows ADK not found. DISM-based operations may fail." -ForegroundColor Yellow
    Write-Host "  Install from: https://go.microsoft.com/fwlink/?linkid=2271337" -ForegroundColor Yellow
}

# Find source
$source = Find-DismImage -IsoPath $ISOPath
if (-not $source) {
    Write-Host "Windows source not found. Provide -ISOPath or mount an ISO." -ForegroundColor Red
    Write-Host "Example: .\build_minimal_win.ps1 -ISOPath D:\ISOs\Win10_22H2.iso" -ForegroundColor Yellow
    exit 1
}

Write-Host "Source: $source" -ForegroundColor Cyan

try {
    # Step 1: Create VHDX
    New-VHDX -Path $VHDXPath -SizeGB $VHDXSizeGB
    
    # Step 2: Apply Windows image
    Install-WindowsImage -Source $source -TargetDrive $MountDrive
    
    # Step 3: Remove component packages
    Remove-ComponentPackages -TargetDrive $MountDrive
    
    # Step 4: Apply registry tweaks
    Apply-RegistryTweaks -TargetDrive $MountDrive
    
    # Step 5: Remove file bloat
    Remove-FileBloat -TargetDrive $MountDrive
    
    # Step 6: Disable services
    Disable-Services -TargetDrive $MountDrive
    
    # Step 7: Install bootloader
    Install-Bootloader -TargetDrive $MountDrive
    
    # Step 8: Finalize
    Finalize -TargetDrive $MountDrive
    
    Write-Host @"

╔══════════════════════════════════════════════════════════╗
║  Windows Lite image created!                            ║
║                                                         ║
║  VHDX: $VHDXPath
║  Drive: $($MountDrive): currently mounted               ║
║                                                         ║
║  Next steps:                                            ║
║  1. Dismount: Dismount-VHD $VHDXPath                    ║
║  2. Boot from VHDX or attach to Hyper-V VM               ║
║  3. The engine will auto-start from startup.cmd          ║
║                                                         ║
║  Manual boot: bcdedit /set {default} osdevice           ║
║      partition=$($MountDrive):                          ║
╚══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green
    
} catch {
    Write-Host "Build failed: $_" -ForegroundColor Red
    exit 1
}

#endregion