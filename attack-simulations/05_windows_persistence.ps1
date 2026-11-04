<#
.SYNOPSIS
    Red Team Simulation: Windows Autostart Persistence & Startup Folder Dropper
    Simulates adversary establishing persistence on a Windows endpoint via:
    1. Registry Run key modification (HKCU / HKLM)
    2. Startup folder script placement
    Corresponds to Wazuh Rule 100017 (MITRE ATT&CK T1547.001).
#>

param(
    [switch]$Cleanup
)

$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$ValueName = "WazuhSimulatedBackdoor"
$BackdoorCommand = "powershell.exe -NoProfile -WindowStyle Hidden -Command Write-Host 'Simulated C2 beacon'"

$StartupDir = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup")
$StartupBatch = Join-Path $StartupDir "updater_task.bat"

if ($Cleanup) {
    Write-Host "[*] Cleaning up simulated persistence artifacts..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if (Test-Path $StartupBatch) { Remove-Item -Path $StartupBatch -Force }
    Write-Host "[+] Cleanup completed." -ForegroundColor Green
    exit 0
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " RED TEAM SIMULATION: WINDOWS PERSISTENCE INJECTION" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Registry Persistence via Run Key
Write-Host "[*] Injecting registry persistence into: $RegPath" -ForegroundColor Yellow
try {
    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $BackdoorCommand -Force
    Write-Host "[+] Registry Run key created: $ValueName -> $BackdoorCommand" -ForegroundColor Green
    Write-Host "    Expected Alert: Rule 100017 (Windows Registry Persistence - Level 11)" -ForegroundColor DarkGray
} catch {
    Write-Host "[-] Failed to write registry key: $_" -ForegroundColor Red
}

# 2. Startup Folder Payload Placement
Write-Host "`n[*] Dropping simulated startup persistence batch file..." -ForegroundColor Yellow
try {
    if (-not (Test-Path $StartupDir)) {
        New-Item -ItemType Directory -Path $StartupDir -Force | Out-Null
    }
    "@echo off`r`necho Simulated Persistence Execution" | Out-File -FilePath $StartupBatch -Encoding ascii
    Write-Host "[+] Startup script dropped: $StartupBatch" -ForegroundColor Green
    Write-Host "    Expected FIM Alert: FILE_CREATED in Startup folder" -ForegroundColor DarkGray
} catch {
    Write-Host "[-] Failed to drop startup file: $_" -ForegroundColor Red
}

Write-Host "`n[+] Simulation finished. Run with -Cleanup to remove artifacts." -ForegroundColor Cyan
