param(
    [string]$Target = "C:\TargetApp\target.exe",
    [string]$Launcher = "D:\emu\genjutsu\build\msvc\x64\bin\Release\launcher.exe",
    [string]$ConfigPath = "D:\emu\genjutsu\config\config.ini",
    [string]$LogPath = "D:\emu\genjutsu\build\msvc\x64\bin\Release\emu.log",
    [int]$Timeout = 40
)

# Backup original config
$origConfig = Get-Content $ConfigPath -Raw

# Generate "all disabled" config — all features off, passthrough
$allOff = @"
; ALL SPOOFERS DISABLED — passthrough test
[cpuid]
status = 0
[cpuid.basic]
status = 1
vendor = GenuineIntel
max_leaf = 0xD
max_ext_leaf = 0x80000008
family = 6
model = 69
stepping = 1
signature = 0x00040651
leaf_0x0_eax = 0x0000000D
leaf_0x0_ebx = 0x756E6547
leaf_0x0_ecx = 0x6C65746E
leaf_0x0_edx = 0x49656E69
leaf_0x1_eax = 0x00040651
leaf_0x1_ebx = 0x00100800
leaf_0x1_ecx = 0x7FDAFBBF
leaf_0x1_edx = 0xBFEBFBFF
brand_string = Intel(R) Core(TM) i7-4510U CPU @ 2.00GHz
[rdtsc]
status = 0
[msr]
status = 0
[kuser]
status = 0
[gpu]
status = 0
[timing]
status = 0
tsc_frequency = 1995375200
tsc_offset = 0x0
apic_frequency = 100000000
tsc_noise = 100
qpc_frequency = 10000000
[process]
status = 0
[registry]
status = 0
[file]
status = 0
[thread]
status = 0
[module_cloak]
status = 0
[token]
status = 0
[hardware]
manufacturer = Dell Inc.
product = Inspiron 3542
version = Not Specified
bios_vendor = Dell Inc.
bios_version = A03
bios_date = 05/27/2014
bios_major = 0
bios_minor = 3
baseboard_manufacturer = Dell Inc.
baseboard_product = 0WW73H
baseboard_version = A03
chassis_serial = 5RSJB12
system_uuid = {4C4C4544-0052-5310-804A-B5C04F423132}
[storage]
disk0_model = CT500BX500SSD1
disk0_serial = 2324E6E428AC
disk0_size = 500105249280
disk1_model = ST1000LM024 HN-M101MBB
disk1_serial = S314J90F795108
disk1_size = 1000202273280
[network]
adapter0_mac = B8:2A:72:C9:38:7E
adapter1_mac = 00:15:5D:73:9A:FA
[vm]
memory_size_mb = 512
cpu_count = 2
[target]
path = C:\TargetApp\target.exe
arguments =
wait_for_debugger = false
"@

# Sections to test (each solo, rest disabled)
$sections = @(
    "cpuid",
    "rdtsc",
    "msr",
    "kuser",
    "gpu",
    "timing",
    "process",
    "registry",
    "file",
    "thread",
    "module_cloak",
    "token"
)

function Set-ConfigSection {
    param([string]$ConfigBase, [string]$Section, [string]$ToggleValue)
    $lines = $ConfigBase -split "`r`n|`n"
    $inSection = $false
    $result = @()
    $sectionHeader = "[$Section]"
    foreach ($line in $lines) {
        if ($line.Trim() -eq $sectionHeader) { $inSection = $true }
        elseif ($inSection -and $line.Trim().StartsWith("[")) { $inSection = $false }
        if ($inSection -and $line.Trim().StartsWith("status")) {
            $result += "status = $ToggleValue"
        } else {
            $result += $line
        }
    }
    return $result -join "`r`n"
}

Write-Host "============================================"
Write-Host "SECTION-BY-SECTION BISECT TEST"
Write-Host "Each test: ONE section enabled, ALL others off"
Write-Host "============================================"

# Test 1: All disabled (baseline)
Write-Host ""
Write-Host "--- Test: ALL OFF (baseline) ---"
$allOff | Out-File -FilePath $ConfigPath -Encoding ascii
Start-Sleep -Seconds 1
if (Test-Path $LogPath) { Remove-Item $LogPath -Force }
$proc = Start-Process -FilePath $Launcher -ArgumentList "--target `"$Target`"" -NoNewWindow -PassThru
$elapsed = 0
while ($elapsed -lt $Timeout -and !$proc.HasExited) {
    Start-Sleep -Seconds 1
    $elapsed++
}
if (!$proc.HasExited) { $proc.Kill(); $elapsed = "KILLED" } else { $elapsed = "EXITED($($proc.ExitCode))" }
$log = Get-Content $LogPath -Tail 3
$hasCrash = ($log | Select-String "CRASH|Engine unloaded" | Select-Object -First 1)
Write-Host "  Duration: $elapsed — $($log[-1])"

# Test each section solo
$results = @()
foreach ($section in $sections) {
    # Generate config with only this section on
    $cfg = $allOff
    $cfg = Set-ConfigSection $cfg $section "1"
    # For cpuid, also enable sub-sections
    if ($section -eq "cpuid") {
        $cfg = Set-ConfigSection $cfg "cpuid.basic" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.leaf_2" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.leaf_4" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.leaf_5" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.leaf_6" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.leaf_7" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.leaf_A" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.leaf_B" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.leaf_D" "1"
        $cfg = Set-ConfigSection $cfg "cpuid.ext" "1"
    }
    
    Write-Host "--- Test: $section ONLY ---"
    $cfg | Out-File -FilePath $ConfigPath -Encoding ascii
    Start-Sleep -Seconds 1
    if (Test-Path $LogPath) { Remove-Item $LogPath -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    $proc = Start-Process -FilePath $Launcher -ArgumentList "--target `"$Target`"" -NoNewWindow -PassThru
    $elapsed = 0
    while ($elapsed -lt $Timeout -and !$proc.HasExited) {
        Start-Sleep -Seconds 1
        $elapsed++
    }
    if (!$proc.HasExited) { $proc.Kill(); $duration = "KILLED" } else { $duration = "EXITED($($proc.ExitCode))" }
    
    # Check log
    $logContent = Get-Content $LogPath -ErrorAction SilentlyContinue
    $lastLine = $logContent | Select-Object -Last 1
    $unloaded = $logContent | Select-String "Engine unloaded" | Select-Object -First 1
    $crash = $logContent | Select-String "CRASH" | Select-Object -First 1
    
    if ($crash) {
        $verdict = "CRASH"
    } elseif ($unloaded -and $elapsed -lt ($Timeout - 2)) {
        $verdict = "EARLY_EXIT (${elapsed}s)"
    } elseif ($unloaded) {
        $verdict = "EXIT_OK (${elapsed}s)"
    } else {
        $verdict = "SURVIVED (${elapsed}s)"
    }
    
    Write-Host "  $verdict — last: $lastLine"
    $results += [PSCustomObject]@{ Section = $section; Verdict = $verdict; Duration = $duration }
}

# Restore original config
$origConfig | Out-File -FilePath $ConfigPath -Encoding ascii

Write-Host ""
Write-Host "============================================"
Write-Host "RESULTS SUMMARY"
Write-Host "============================================"
$results | Format-Table Section, Verdict, Duration -AutoSize
Write-Host "============================================"
