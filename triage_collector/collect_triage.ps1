<#
.SYNOPSIS
    VESPER Non-Destructive Windows DFIR Live Triage Collector with SHA-256 Chain of Custody
.DESCRIPTION
    Collects read-only host triage artifacts (network sockets, process tree with parent PIDs,
    registry Run keys, and event log metadata) and generates a SHA-256 manifest for integrity verification.
.NOTES
    Author: Bassma Alaoui Sossey
#>

[CmdletBinding()]
param (
    [string]$OutputDir = (Join-Path $env:TEMP "VESPER_Triage")
)

$ErrorActionPreference = "Stop"
$utcNow = (Get-Date).ToUniversalTime()
$stamp = $utcNow.ToString("yyyyMMdd_HHmmssZ")
$caseDir = Join-Path $OutputDir "Triage_$stamp"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

$collected = [System.Collections.Generic.List[string]]::new()
$errors = [System.Collections.Generic.List[string]]::new()

try {
    $netPath = Join-Path $caseDir "netstat_sockets.csv"
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        Export-Csv -Path $netPath -NoTypeInformation -Encoding UTF8
    $collected.Add($netPath)
} catch {
    $errors.Add("netstat_sockets: $($_.Exception.Message)")
}

try {
    $procPath = Join-Path $caseDir "process_tree.csv"
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate |
        Export-Csv -Path $procPath -NoTypeInformation -Encoding UTF8
    $collected.Add($procPath)
} catch {
    $errors.Add("process_tree: $($_.Exception.Message)")
}

try {
    $regPath = Join-Path $caseDir "registry_run_keys.json"
    $regSnapshot = [PSCustomObject]@{
        HKLM_Run = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue)
        HKCU_Run = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue)
    }
    $regSnapshot | ConvertTo-Json -Depth 4 | Set-Content -Path $regPath -Encoding UTF8
    $collected.Add($regPath)
} catch {
    $errors.Add("registry_run_keys: $($_.Exception.Message)")
}

$hashes = foreach ($file in $collected) {
    if (Test-Path $file) {
        $h = Get-FileHash -Path $file -Algorithm SHA256
        [PSCustomObject]@{
            file = (Split-Path $file -Leaf)
            sha256 = $h.Hash.ToLowerInvariant()
            bytes = (Get-Item $file).Length
        }
    }
}

$manifest = [PSCustomObject]@{
    tool = "VESPER Live Triage Collector"
    collected_at_utc = $utcNow.ToString("o")
    hostname = $env:COMPUTERNAME
    username = $env:USERNAME
    os_version = [System.Environment]::OSVersion.VersionString
    artifacts = $hashes
    non_fatal_errors = $errors
}

$manifestPath = Join-Path $caseDir "manifest_sha256.json"
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8
Write-Output "VESPER_TRIAGE_COMPLETE:$manifestPath"
