<#
    Build-Exe.ps1  --  OPTIONAL: compile the optimizer into a single .exe
    -------------------------------------------------------------------
    Author: Ahmad Shaukat
    The recommended way to run this tool is Start.bat (no build needed, no
    antivirus/SmartScreen friction). This script is only for maintainers who
    want to ship a packaged .exe and are prepared to CODE-SIGN it.

    IMPORTANT: An UNSIGNED .exe produced here will very likely be flagged by
    Microsoft Defender SmartScreen and some antivirus engines, and may be
    quarantined on other people's machines. Only distribute a signed build.

    Usage:
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-Exe.ps1

    What it does:
      * Installs the ps2exe module (current user scope) if missing.
      * Produces .\dist\Windows11SecurityOptimizer.exe that launches the GUI,
        requesting admin via an embedded manifest (requireAdministrator).

    To code-sign afterwards (example):
      Set-AuthenticodeSignature -FilePath .\dist\Windows11SecurityOptimizer.exe `
        -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0] `
        -TimestampServer "http://timestamp.digicert.com"
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $PSScriptRoot 'dist'),
    [switch]$RequireAdmin = $true
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Write-Host 'Windows 11 Security Optimizer - EXE builder' -ForegroundColor Cyan
Write-Host '-------------------------------------------' -ForegroundColor Cyan
Write-Host 'NOTE: Prefer Start.bat for distribution. Only ship a SIGNED .exe.' -ForegroundColor Yellow
Write-Host ''

$gui = Join-Path $PSScriptRoot 'src\Optimizer.ps1'
if (-not (Test-Path $gui)) { throw "Cannot find src\Optimizer.ps1 next to this script." }

# ps2exe cannot easily inline a dot-sourced dependency, so we build a temporary
# merged script = SecurityCore.ps1 + Optimizer.ps1 (minus its dot-source line).
$core = Join-Path $PSScriptRoot 'src\SecurityCore.ps1'
if (-not (Test-Path $core)) { throw "Cannot find src\SecurityCore.ps1." }

Write-Host 'Preparing merged source...' -ForegroundColor Gray
$guiText = Get-Content $gui -Raw
# Remove the runtime dot-source of SecurityCore (we inline it instead) and the
# bare "param()"/CmdletBinding at the top is kept; ps2exe honors it.
$guiText = $guiText -replace '(?m)^\s*\.\s+\$script:CorePath\s*$', '# (SecurityCore inlined by Build-Exe.ps1)'
$merged  = @"
# ============================================================
#  AUTO-MERGED BUILD  (SecurityCore + Optimizer)
#  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ============================================================
$(Get-Content $core -Raw)

# ------------------------------------------------------------
#  GUI layer
# ------------------------------------------------------------
$guiText
"@

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$tmp = Join-Path $OutDir '_merged_build.ps1'
Set-Content -Path $tmp -Value $merged -Encoding UTF8

# Ensure ps2exe is available
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installing ps2exe module (CurrentUser)...' -ForegroundColor Gray
    try {
        Install-Module ps2exe -Scope CurrentUser -Force -ErrorAction Stop
    } catch {
        throw "Could not install ps2exe automatically. Install it manually: Install-Module ps2exe -Scope CurrentUser"
    }
}
Import-Module ps2exe -ErrorAction Stop

$exe = Join-Path $OutDir 'Windows11SecurityOptimizer.exe'
Write-Host "Compiling -> $exe" -ForegroundColor Gray

$ps2exeArgs = @{
    inputFile   = $tmp
    outputFile  = $exe
    noConsole   = $true
    title       = 'Windows 11 Security Optimizer'
    product     = 'Windows 11 Security Optimizer'
    description = 'Audit, harden, debloat and investigate Windows 11 security.'
    version     = '1.0.0.0'
    STA         = $true
}
if ($RequireAdmin) { $ps2exeArgs['requireAdmin'] = $true }

Invoke-ps2exe @ps2exeArgs

Remove-Item $tmp -Force -ErrorAction SilentlyContinue

if (Test-Path $exe) {
    Write-Host ''
    Write-Host "Built: $exe" -ForegroundColor Green
    Write-Host 'REMINDER: code-sign this .exe before sharing, or users will see SmartScreen/AV warnings.' -ForegroundColor Yellow
} else {
    throw 'Build failed - no output produced.'
}
