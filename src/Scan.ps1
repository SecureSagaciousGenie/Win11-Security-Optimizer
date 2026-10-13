<#
    Scan.ps1  --  headless, read-only scan
    --------------------------------------
    Author: Ahmad Shaukat

    Runs the read-only engines without the GUI and writes the results as JSON.
    It never applies a fix, changes a setting, removes, installs or downloads
    anything. A static test enforces that.

    Usage (an elevated prompt gives the full picture):
      powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Scan.ps1 -OutJson C:\Reports\scan.json [-Deep]

    Exit codes: 0 clean, 1 items to review, 2 alerts, 3 error.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutJson,
    [switch]$Deep
)

$ErrorActionPreference = 'Stop'
$exitCode = 3
try {
    . (Join-Path $PSScriptRoot 'SecurityCore.ps1')
    Initialize-Core -ReadOnly | Out-Null
    $started = (Get-Date).ToUniversalTime()

    $security = @(Invoke-SecurityScan)
    $cards = @(Invoke-DfirTriage)
    $cards += @(Get-SysmonDfirFinding)
    if ($Deep) { $cards += @(Invoke-DeepScan) }
    $drift = @()
    if (Read-Baseline) { $drift = @(Invoke-BaselineDrift) }
    $allCards = @($cards) + @($drift)

    $exitCode = Get-ScanExitCode -SecurityFindings $security -Cards $allCards
    $result = [ordered]@{
        Tool        = [string]$script:Core.Name
        Version     = [string]$script:Core.Version
        Machine     = [string]$env:COMPUTERNAME
        Elevated    = [bool](Test-IsAdmin)
        Deep        = [bool]$Deep
        StartedUtc  = $started.ToString('o')
        FinishedUtc = (Get-Date).ToUniversalTime().ToString('o')
        ExitCode    = $exitCode
        Score       = (Get-SecurityScore $security)
        Security    = @($security)
        Investigate = @($cards)
        Drift       = @($drift)
    }
    $full = [System.IO.Path]::GetFullPath($OutJson)
    [System.IO.File]::WriteAllText($full, (ConvertTo-Json -InputObject $result -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ("Scan complete: exit code {0}. Results: {1}" -f $exitCode, $full)
} catch {
    $exitCode = 3
    [Console]::Error.WriteLine(("Scan failed: {0}" -f $_.Exception.Message))
}
exit $exitCode
