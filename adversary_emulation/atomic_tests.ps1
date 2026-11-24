<#
.SYNOPSIS
    Controlled Adversary Emulation Harness (Atomic Red Team Tests)
.DESCRIPTION
    Executes controlled adversary techniques in an isolated test environment:
    - T1059.001: PowerShell Execution Policy Bypass & Base64 Command Execution
    - T1003.001: LSASS Memory Dumping simulation via comsvcs.dll
    - T1082: System Discovery
    - T1547.001: Persistence via Registry Run Key
.NOTES
    Author: Bassma Alaoui Sossey
    Lab: Windows 11 ARM on UTM
#>

[CmdletBinding()]
param (
    [string]$LogOutputDir = "$PSScriptRoot\..\triage_collector\emulated_logs"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Windows DFIR Lab: Controlled Adversary Emulation" -ForegroundColor Cyan
Write-Host "   Author: Bassma Alaoui Sossey | UEMF Engineering" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not (Test-Path $LogOutputDir)) {
    New-Item -ItemType Directory -Path $LogOutputDir -Force | Out-Null
}

$LogFile = Join-Path $LogOutputDir "adversary_activity_log.json"
$Events = [System.Collections.Generic.List[PSObject]]::new()

function Log-Action {
    param([string]$TechniqueId, [string]$TechniqueName, [string]$CommandExecuted)
    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("o")
        TechniqueId = $TechniqueId
        TechniqueName = $TechniqueName
        Command = $CommandExecuted
        User = $env:USERNAME
        Hostname = $env:COMPUTERNAME
    }
    $Events.Add($entry)
    Write-Host "[+] Executed $TechniqueId ($TechniqueName): $CommandExecuted" -ForegroundColor Yellow
}

# --- Technique 1: T1059.001 - PowerShell Encoded Command ---
Write-Host "`n[*] Simulating T1059.001: PowerShell Base64 Encoded Command..." -ForegroundColor Green
$cmd = 'Write-Host "Atomic Red Team Test - Benign Payload Execution"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
$fullCmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -enc $encoded"
Log-Action -TechniqueId "T1059.001" -TechniqueName "PowerShell Encoded Execution" -CommandExecuted $fullCmd

# --- Technique 2: T1082 - System Information Discovery ---
Write-Host "`n[*] Simulating T1082: System Information Discovery..." -ForegroundColor Green
$discoveryCmd = "systeminfo /fo csv"
Log-Action -TechniqueId "T1082" -TechniqueName "System Information Discovery" -CommandExecuted $discoveryCmd

# --- Technique 3: T1003.001 - LSASS Memory Dumping via Comsvcs.dll ---
Write-Host "`n[*] Simulating T1003.001: LSASS Process Dump (Comsvcs)..." -ForegroundColor Green
# Simulated benign target dump syntax for detection verification
$lsassCmd = "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 656 C:\Temp\lsass.dmp full"
Log-Action -TechniqueId "T1003.001" -TechniqueName "LSASS Memory Dump via comsvcs" -CommandExecuted $lsassCmd

# --- Technique 4: T1547.001 - Persistence via Registry Run Key ---
Write-Host "`n[*] Simulating T1547.001: Persistence via Registry Run Key..." -ForegroundColor Green
$regCmd = 'reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdateMock" /t REG_SZ /d "C:\Users\Public\payload.exe" /f'
Log-Action -TechniqueId "T1547.001" -TechniqueName "Registry Run Key Persistence" -CommandExecuted $regCmd

# Export recorded actions to JSON for detection testing
$Events | ConvertTo-Json -Depth 3 | Set-Content -Path $LogFile -Encoding UTF8
Write-Host "`n[✓] Adversary emulation complete. Logged telemetry saved to: $LogFile" -ForegroundColor Cyan
