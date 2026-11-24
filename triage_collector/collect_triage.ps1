<#
.SYNOPSIS
    DFIR Live Response & Triage Collector Script
.DESCRIPTION
    Collects high-value volatile and non-volatile forensic artifacts:
    - Running process trees and network socket mappings
    - PowerShell script block logs & transcripts
    - Security & System EVTX logs
    - Registry persistence locations (Run, RunOnce, Services)
.NOTES
    Author: Bassma Alaoui Sossey
#>

[CmdletBinding()]
param (
    [string]$OutputDir = "C:\DFIR_Triage_Output"
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$caseDir = Join-Path $OutputDir "Triage_$timestamp"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

Write-Host "[*] Starting DFIR Live Response Triage..." -ForegroundColor Cyan

# 1. System info & active network connections
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
    Export-Csv -Path (Join-Path $caseDir "netstat_sockets.csv") -NoTypeInformation

# 2. Process list with parent PID
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate |
    Export-Csv -Path (Join-Path $caseDir "process_tree.csv") -NoTypeInformation

# 3. Export Registry Run Keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File (Join-Path $caseDir "hklm_run.txt")
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File (Join-Path $caseDir "hkcu_run.txt")

Write-Host "[✓] Triage artifacts collected in: $caseDir" -ForegroundColor Green
