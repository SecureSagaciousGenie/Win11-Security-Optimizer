<#
    Sysmon.ps1
    Author: Ahmad Shaukat
    Sysmon: opt-in continuous logging. Detects the standalone Sysinternals
    service and the built-in Windows feature, enables logging with the bundled
    sysmon-modular configuration, and reports how many days of evidence the
    log holds. Sysmon records nothing that happened before it was installed.
    Dot-sourced by SecurityCore.ps1.
#>

$script:SysmonLogName      = 'Microsoft-Windows-Sysmon/Operational'
$script:SysmonLogMaxBytes  = 536870912
# SHA-256 of config\sysmon\sysmonconfig.xml exactly as vendored (header included).
$script:SysmonConfigSha256 = '14B90FF7E841F22E776C431AB70A7DDCDDFAE94B5A1AC5635C4A46D8336D660F'

function Get-SysmonServiceName {
    <# 'Sysmon64' or 'Sysmon' when a Sysmon service is installed, else $null. #>
    foreach ($n in @('Sysmon64', 'Sysmon')) {
        $svc = @(Get-Service -Name $n -ErrorAction SilentlyContinue)
        if ($svc.Count -gt 0) { return $n }
    }
    return $null
}

function Get-SysmonFeatureState {
    <# Built-in Windows feature: 'Enabled', 'Disabled', 'Absent', or 'Unknown'
       when not elevated or DISM fails. #>
    if (-not (Test-IsAdmin)) { return 'Unknown' }
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -ErrorAction Stop
    } catch {
        if ($_.Exception.HResult -eq $script:HResultUnknownFeature) { return 'Absent' }
        Write-CoreLog -Message ("Sysmon feature state could not be read: {0}" -f $_.Exception.Message) -Level WARN
        return 'Unknown'
    }
    if (-not $f) { return 'Absent' }
    $st = [string](@($f)[0].State)
    if ($st -like 'Enabled*') { return 'Enabled' }
    return 'Disabled'
}

function Get-SysmonLogInfo {
    <# Size, maximum size and oldest event of the Sysmon log, or $null when the
       log does not exist. #>
    $log = $null
    try { $log = Get-WinEvent -ListLog $script:SysmonLogName -ErrorAction Stop } catch { return $null }
    $oldest = $null
    try { $oldest = @(Get-WinEvent -LogName $script:SysmonLogName -MaxEvents 1 -Oldest -ErrorAction Stop)[0].TimeCreated } catch { $oldest = $null }
    $days = $null
    if ($oldest) { $days = [int][math]::Floor(((Get-Date) - $oldest).TotalDays) }
    return [pscustomobject]@{ SizeBytes = [int64]$log.FileSize; MaxBytes = [int64]$log.MaximumSizeInBytes; Oldest = $oldest; DaysOfEvidence = $days }
}

function Get-SysmonState {
    <# Read-only. State is Standalone, BuiltInEnabled, BuiltInAvailable,
       Unavailable or Unknown (not elevated, nothing installed). Installed is
       true when a Sysmon service exists, whichever kind. #>
    $service = Get-SysmonServiceName
    $feature = Get-SysmonFeatureState
    $state = if ($feature -eq 'Enabled') { 'BuiltInEnabled' }
             elseif ($service) { 'Standalone' }
             elseif ($feature -eq 'Disabled') { 'BuiltInAvailable' }
             elseif ($feature -eq 'Absent') { 'Unavailable' }
             else { 'Unknown' }
    return [pscustomobject]@{ State = $state; Service = $service; Feature = $feature; Installed = [bool]$service; Log = (Get-SysmonLogInfo) }
}

function Get-SysmonConfigSource {
    <# The vendored config, verified against its pinned hash. Throws otherwise. #>
    $p = Join-Path $script:Core.RootPath 'config\sysmon\sysmonconfig.xml'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw ("The bundled Sysmon configuration is missing: {0}" -f $p) }
    $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToUpper()
    if ($h -ne $script:SysmonConfigSha256) { throw ("The bundled Sysmon configuration does not match its pinned SHA-256 (got {0}). Refusing to use it." -f $h) }
    return $p
}

function Copy-SysmonConfigToSecureBase {
    <# Copies the verified config into the admin-locked base, re-owns it and
       verifies the copy, so sysmon reads a file no standard user can swap. #>
    $src = Get-SysmonConfigSource
    $dir = Join-Path $env:ProgramData 'Win11SecurityOptimizer\sysmon'
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-ItemOwnerAdministrators -Path $dir
    }
    $dest = Join-Path $dir 'sysmonconfig.xml'
    Copy-Item -LiteralPath $src -Destination $dest -Force
    Set-ItemOwnerAdministrators -Path $dest
    $h = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToUpper()
    if ($h -ne $script:SysmonConfigSha256) { throw 'The copied Sysmon configuration does not match its pinned SHA-256. Refusing to use it.' }
    return $dest
}

function Find-BuiltInSysmonExe {
    $cmd = @(Get-Command -Name 'sysmon.exe' -CommandType Application -ErrorAction SilentlyContinue) | Select-Object -First 1
    if ($cmd) { return [string]$cmd.Source }
    $p = Join-Path $env:windir 'System32\Sysmon.exe'
    if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    return $null
}

function Enable-SysmonLogging {
    <# Main thread, elevated. Changes nothing when any Sysmon service already
       exists. Otherwise uses the built-in feature when this Windows has it, or
       downloads standalone Sysmon from MS (Authenticode path), installs it with
       the bundled config and raises the log to 512 MB. Every step adds its own
       rollback entry. #>
    if (-not (Test-IsAdmin)) { throw 'Turning on Sysmon needs administrator rights.' }
    $st = Get-SysmonState
    if ($st.Installed) {
        Write-CoreLog -Message ("Sysmon is already installed (service {0}); nothing was changed." -f $st.Service) -Level INFO
        return
    }
    $cfg = Copy-SysmonConfigToSecureBase

    if ($st.Feature -eq 'Enabled' -or $st.Feature -eq 'Disabled') {
        if ($st.Feature -eq 'Disabled') {
            Enable-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -All -NoRestart -ErrorAction Stop | Out-Null
            Add-RollbackCommand "Disable-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -NoRestart | Out-Null" 'Turn the built-in Sysmon feature back off'
            Add-ChangeRecord 'Enabled the built-in Windows Sysmon feature'
        }
        $exe = Find-BuiltInSysmonExe
        if (-not $exe) { throw 'The built-in Sysmon feature is on, but sysmon.exe was not found.' }
        if (-not (Test-MicrosoftSigned -Path $exe)) { throw ("{0} is not signed by MS. Refusing to run it." -f $exe) }
        $help = Invoke-NativeCommand -FilePath $exe -ArgumentList @('-?')
        $installArgs = @()
        if ($help.Output -match '(?i)-accepteula') { $installArgs += '-accepteula' }
        $installArgs += @('-i', $cfg)
    } else {
        # No built-in feature: standalone Sysmon from download.sysinternals.com.
        [void](Initialize-SecureToolsRoot)
        $exe = Test-ExternalToolInstalled -Key 'sysmon'
        if (-not $exe) {
            $inst = Install-ExternalTool -Key 'sysmon' -ConsentAccepted -Resolution (Resolve-ExternalToolRelease -Key 'sysmon')
            if (-not $inst.Success) { throw ("Sysmon could not be downloaded: {0}" -f $inst.Message) }
            $exe = $inst.ExePath
        }
        Assert-ExternalToolIntegrity -Tool (Get-ExternalTool -Key 'sysmon') -ExePath $exe
        $installArgs = @('-accepteula', '-i', $cfg)
    }

    $r = Invoke-NativeCommand -FilePath $exe -ArgumentList $installArgs
    if ($r.ExitCode -ne 0) { throw ("Sysmon install failed with exit code {0}: {1}" -f $r.ExitCode, $r.Output) }
    $exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToUpper()
    $qExe = ConvertTo-PsSingleQuoted $exe
    # The rollback re-checks the exe hash before running it elevated.
    Add-RollbackCommand ("if ((Get-FileHash -LiteralPath {0} -Algorithm SHA256).Hash -eq '{1}') {{ & {0} -u }} else {{ Write-Warning 'The Sysmon program changed since it was installed; not running it. Uninstall Sysmon manually.' }}" -f $qExe, $exeHash) 'Uninstall Sysmon'
    Add-ChangeRecord ("Installed Sysmon ({0}) with the bundled sysmon-modular configuration" -f $exe)

    $oldMax = $null
    $log = Get-SysmonLogInfo
    if ($log) { $oldMax = [int64]$log.MaxBytes }
    $w = Invoke-NativeCommand -FilePath 'wevtutil.exe' -ArgumentList @('sl', $script:SysmonLogName, ('/ms:{0}' -f $script:SysmonLogMaxBytes))
    if ($w.ExitCode -ne 0) { throw ("Sysmon is installed, but its log size could not be set (wevtutil exit code {0}): {1}" -f $w.ExitCode, $w.Output) }
    if ($oldMax) {
        Add-RollbackCommand ("& wevtutil.exe sl '{0}' '/ms:{1}'" -f $script:SysmonLogName, $oldMax) 'Restore the Sysmon log size'
    }
    Add-ChangeRecord ("Set the Sysmon log maximum to {0} MB" -f ($script:SysmonLogMaxBytes / 1MB))
}

function Test-SysmonEnabled {
    return [bool](Get-SysmonServiceName)
}

function Test-SysmonToolInUse {
    <# True while Sysmon is installed and a downloaded copy exists in the tools
       tree; that copy is needed to uninstall it. #>
    if (-not (Get-SysmonServiceName)) { return $false }
    return (Test-Path -LiteralPath (Join-Path (Get-ExternalToolsRoot) 'sysmon'))
}

function Get-SysmonSecurityFinding {
    $st = Get-SysmonState
    $days = if ($st.Log -and $null -ne $st.Log.DaysOfEvidence) { $st.Log.DaysOfEvidence } else { $null }
    $observed = switch ($st.State) {
        'Standalone'       { 'On (Sysinternals Sysmon)' }
        'BuiltInEnabled'   { $(if ($st.Installed) { 'On (built-in Windows Sysmon)' } else { 'Built-in feature on, not installed' }) }
        'BuiltInAvailable' { 'Off (built into this Windows)' }
        'Unavailable'      { 'Off (will be downloaded from MS)' }
        default            { 'Unknown (needs administrator to check)' }
    }
    if ($st.Installed -and $null -ne $days) { $observed += (" | {0} day(s) of evidence" -f $days) }
    $f = New-Finding -Id 'SYSMON' -Category 'Continuous logging' -Name 'Continuous logging (Sysmon)' -Severity 'Low' `
        -Status $(if ($st.Installed) { 'Pass' } else { 'Info' }) -Observed $observed -Expected 'On, if you want evidence for later investigations' `
        -Detail 'Sysmon records process starts, network connections, driver loads and more, so Hayabusa and Chainsaw have evidence to match. It records nothing that happened before it was installed.' `
        -Advice $(if ($st.Installed) { '' } else { 'Optional. Turn it on to keep a detailed activity log from now on.' }) `
        -RiskTier 'HighRisk' -Fixable ((-not $st.Installed) -and $st.State -ne 'Unknown')
    $f | Add-Member -NotePropertyName IndividualOnly -NotePropertyValue $true -Force
    $f | Add-Member -NotePropertyName ConfirmText -NotePropertyValue 'This installs the Sysmon driver and service and lets its log use up to 512 MB of disk. If this Windows does not include Sysmon, it is downloaded from MS (download.sysinternals.com) and must carry a valid MS signature. Undo it with the rollback script.' -Force
    return $f
}

function Get-SysmonDfirFinding {
    <# Investigate card: Sysmon state and days of evidence. #>
    $st = Get-SysmonState
    if ($st.Installed) {
        $days = if ($st.Log -and $null -ne $st.Log.DaysOfEvidence) { $st.Log.DaysOfEvidence } else { 0 }
        $size = if ($st.Log) { [math]::Round($st.Log.SizeBytes / 1MB, 1) } else { 0 }
        return (New-DfirFinding -Id 'DFIR-SYSMON' -Category 'Logging' -Title ("Sysmon is recording: {0} day(s) of evidence" -f $days) -Severity 'Info' -Status 'Clean' `
            -What ("Sysmon ({0}) is installed. Its log holds {1} day(s) of activity ({2} MB)." -f $st.Service, $days, $size) `
            -Why 'Sysmon only knows what happened after it was installed; older activity is not in its log.' `
            -WhatToDo 'No action needed. Run Hayabusa or Chainsaw from Pro Tools to search this evidence.' -Evidence '')
    }
    return (New-DfirFinding -Id 'DFIR-SYSMON' -Category 'Logging' -Title 'Sysmon is not recording' -Severity 'Info' -Status 'Info' `
        -What 'Sysmon is not installed, so there is no detailed record of process starts, network connections or driver loads.' `
        -Why 'If something goes wrong later, Sysmon evidence is what investigators look for first. It records nothing that happened before it was installed.' `
        -WhatToDo 'Optional: turn on "Continuous logging (Sysmon)" on the Security page.' -Evidence '')
}

Register-SecurityCheck -Id 'SYSMON' -Check { Get-SysmonSecurityFinding } -FixAction { Enable-SysmonLogging } -FixTest { Test-SysmonEnabled }
