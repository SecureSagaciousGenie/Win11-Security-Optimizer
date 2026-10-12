<#
    TestSetup.ps1
    Author: Ahmad Shaukat
    Dot-source in a top-level BeforeAll: points LOCALAPPDATA and ProgramData at
    TestDrive, loads the fakes, helpers and SecurityCore (with its features),
    and starts a non-elevated session. Call Restore-TestEnvironment in AfterAll.
#>
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SavedEnv = @{ LOCALAPPDATA = $env:LOCALAPPDATA; ProgramData = $env:ProgramData; W11SO_SESSION_LOG = $env:W11SO_SESSION_LOG; COMPUTERNAME = $env:COMPUTERNAME; SystemRoot = $env:SystemRoot }
# Non-Windows hosts have no SystemRoot; give path-building code somewhere to point.
if (-not $env:SystemRoot) { $env:SystemRoot = Join-Path $TestDrive 'Windows' }
$env:LOCALAPPDATA = Join-Path $TestDrive 'LocalAppData'
$env:ProgramData  = Join-Path $TestDrive 'ProgramData'
Remove-Item -Path Env:\W11SO_SESSION_LOG -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $env:LOCALAPPDATA, $env:ProgramData -Force | Out-Null

. (Join-Path $PSScriptRoot 'Fakes.ps1')
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
. (Join-Path $script:RepoRoot 'src\SecurityCore.ps1')

Mock Test-IsAdmin { $false }
Mock New-SystemRestorePointOnce { $true }
Initialize-Core | Out-Null

function Restore-TestEnvironment {
    foreach ($k in @('LOCALAPPDATA', 'ProgramData', 'W11SO_SESSION_LOG', 'COMPUTERNAME', 'SystemRoot')) {
        if ($script:SavedEnv[$k]) { Set-Item -Path ("Env:\{0}" -f $k) -Value $script:SavedEnv[$k] }
        else { Remove-Item -Path ("Env:\{0}" -f $k) -ErrorAction SilentlyContinue }
    }
}
