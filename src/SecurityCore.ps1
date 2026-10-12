<#
    SecurityCore.ps1
    ----------------
    Backend engine for the Windows 11 Security Optimizer.

    This module contains ALL logic (scanning, hardening, debloat, DFIR triage,
    startup management, restore/rollback). It is dot-sourced by the GUI
    (Optimizer.ps1) and exposes plain functions that RETURN OBJECTS rather than
    writing to the console, so the GUI can bind to the results.

    DESIGN RULES
      * Scanning is READ-ONLY. Nothing here changes the system unless a function
        whose name starts with Invoke-*Apply / Set-* / Disable-* / Remove-* is
        called explicitly by the user through the GUI.
      * Every state-changing action is routed through the backup/rollback engine
        so it can be reverted.
      * No external modules. Windows PowerShell 5.1 + built-in .NET only.
      * Functions never call exit / Write-Host colored UI; they log via Write-CoreLog
        and return structured data.
#>

Set-StrictMode -Version 2.0

# ----------------------------------------------------------------------------
#  Module-wide state
# ----------------------------------------------------------------------------
$script:Core = [ordered]@{
    Name          = 'Windows 11 Security Optimizer'
    Version       = '1.1.0'
    StartTime     = Get-Date
    RootPath      = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { (Get-Location).Path }
    DataPath      = $null
    LogFile       = $null
    BackupDir     = $null
    RollbackFile  = $null
    BackupFile    = $null
    TranscriptOn  = $false
    RestorePointMade = $false
    Rollback      = (New-Object System.Collections.ArrayList)   # apply-order rollback blocks
    Backups       = (New-Object System.Collections.ArrayList)   # structured before-state records
    Changes       = (New-Object System.Collections.ArrayList)   # applied-change audit trail
}

$script:SeverityWeight = @{ 'Critical'=10; 'High'=7; 'Medium'=4; 'Low'=2; 'Info'=0 }

function Initialize-Core {
    <# Sets up the data/log folder. Safe to call repeatedly.
       The session LOG file is shared across every runspace in this process so the
       Restore & Logs tab sees ALL activity (background scans run in child
       runspaces that each call Initialize-Core). We key it off an environment
       variable - env vars are per-process, so all runspaces inherit the same
       log path. Rollback/backup files remain per-call-timestamp.

       SECURITY: the rollback script is meant to be run ELEVATED, so it must not
       live anywhere a non-admin process could tamper with it before the user runs
       it. When elevated, rollback + backup files are written under an ACL-locked
       %ProgramData% tree (Administrators/SYSTEM write, Users read-only). Logs stay
       in %LOCALAPPDATA% because they are only ever read, never executed. #>
    param([string]$DataPath)
    if (-not $DataPath) {
        $DataPath = Join-Path $env:LOCALAPPDATA 'Win11SecurityOptimizer'
    }
    $script:Core.DataPath = $DataPath
    foreach ($sub in @('', 'logs', 'backups')) {
        $p = if ($sub) { Join-Path $DataPath $sub } else { $DataPath }
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    # Shared session log: reuse the one already chosen for this process if present.
    if ($env:W11SO_SESSION_LOG) {
        $script:Core.LogFile = $env:W11SO_SESSION_LOG
    } else {
        $script:Core.LogFile = Join-Path $DataPath ("logs\session_{0}.log" -f $stamp)
        $env:W11SO_SESSION_LOG = $script:Core.LogFile
    }
    # Rollback/backup go to the admin-locked ProgramData tree when elevated.
    $backupDir = Join-Path $DataPath 'backups'
    try {
        if (Test-IsAdmin) {
            $secureBase = Join-Path $env:ProgramData 'Win11SecurityOptimizer'
            Set-ToolsFolderAcl -Path $secureBase   # idempotent lock of the base
            $secureBackups = Join-Path $secureBase 'backups'
            if (-not (Test-Path $secureBackups)) { New-Item -ItemType Directory -Path $secureBackups -Force | Out-Null }
            $backupDir = $secureBackups
        }
    } catch { }
    $script:Core.BackupDir    = $backupDir
    $script:Core.RollbackFile = Join-Path $backupDir ("Rollback_{0}.ps1" -f $stamp)
    $script:Core.BackupFile   = Join-Path $backupDir ("Backup_{0}.json"  -f $stamp)
    Write-CoreLog -Message ("=== {0} v{1} session started ===" -f $script:Core.Name, $script:Core.Version) -Level INFO
    return $script:Core.DataPath
}

function Write-CoreLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK','ACTION','DEBUG')][string]$Level = 'INFO'
    )
    $line = ('{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message)
    if ($script:Core.LogFile) {
        try { Add-Content -Path $script:Core.LogFile -Value $line -Encoding UTF8 } catch { }
    }
    # Also surface to a UI callback if one is registered.
    if ($script:Core.Contains('LogCallback') -and $script:Core.LogCallback) {
        try { & $script:Core.LogCallback $line $Level } catch { }
    }
}

function Get-CoreLogTail {
    param([int]$Lines = 200)
    if ($script:Core.LogFile -and (Test-Path $script:Core.LogFile)) {
        return (Get-Content $script:Core.LogFile -Tail $Lines)
    }
    return @()
}

# ----------------------------------------------------------------------------
#  Environment helpers
# ----------------------------------------------------------------------------
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-CoreSystemInfo {
    $os = $null; $cs = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }
    $ramGB = 0; try { $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } catch { }
    [pscustomobject]@{
        Computer  = if ($cs) { $cs.Name } else { $env:COMPUTERNAME }
        OS        = if ($os) { $os.Caption } else { 'Unknown' }
        Version   = if ($os) { $os.Version } else { 'Unknown' }
        Build     = if ($os) { $os.BuildNumber } else { 'Unknown' }
        PS        = $PSVersionTable.PSVersion.ToString()
        User      = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
        Admin     = (Test-IsAdmin)
        RamGB     = $ramGB
        Timestamp = $script:Core.StartTime
    }
}

# ----------------------------------------------------------------------------
#  Registry helpers (safe read + backup-aware write)
# ----------------------------------------------------------------------------
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path $Path)) { return $null }
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function Backup-RegValue {
    param([string]$Path, [string]$Name, [string]$Type = 'DWord')
    $exists = $false; $current = $null
    try {
        if (Test-Path $Path) {
            $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $p -and ($p.PSObject.Properties.Name -contains $Name)) {
                $exists = $true; $current = $p.$Name
            }
        }
    } catch { }

    [void]$script:Core.Backups.Add([pscustomobject]@{
        Kind=' Registry'; Path=$Path; Name=$Name; Type=$Type; Existed=$exists; Value=$current; Time=(Get-Date -Format o)
    })

    if ($exists) {
        $val = if ($Type -in @('String','ExpandString')) { "'" + ([string]$current -replace "'","''") + "'" } else { $current }
        $cmd = "if (-not (Test-Path '$Path')) { New-Item -Path '$Path' -Force | Out-Null }`r`nNew-ItemProperty -Path '$Path' -Name '$Name' -Value $val -PropertyType $Type -Force | Out-Null"
    } else {
        $cmd = "if (Test-Path '$Path') { Remove-ItemProperty -Path '$Path' -Name '$Name' -ErrorAction SilentlyContinue }"
    }
    [void]$script:Core.Rollback.Add("# Restore $Path\$Name`r`n$cmd")
}

function Set-RegValueTracked {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    Backup-RegValue -Path $Path -Name $Name -Type $Type
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Add-ChangeRecord -Description ("Set {0}\{1} = {2}" -f $Path, $Name, $Value)
}

function Add-RollbackCommand {
    param([string]$Command, [string]$Comment = '')
    # Control characters are stripped from the comment so a crafted value name
    # containing CR/LF cannot break out of the comment onto a live code line.
    $block = if ($Comment) { "# $(ConvertTo-SafeComment $Comment)`r`n$Command" } else { $Command }
    [void]$script:Core.Rollback.Add($block)
}

function Add-ChangeRecord {
    param([string]$Description)
    [void]$script:Core.Changes.Add([pscustomobject]@{ Time=(Get-Date -Format o); Change=$Description })
    Write-CoreLog -Message ("CHANGE: {0}" -f $Description) -Level ACTION
}

function Save-RollbackArtifacts {
    if ($script:Core.Rollback.Count -eq 0) { return }
    $header = @"
<#
    AUTO-GENERATED ROLLBACK SCRIPT
    Tool    : $($script:Core.Name) v$($script:Core.Version)
    Created : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Purpose : Reverts changes applied during this session.

    HOW TO USE:
      1. Open an elevated PowerShell (Run as administrator).
      2. Run:  powershell -ExecutionPolicy Bypass -File "$($script:Core.RollbackFile)"
#>
Write-Host 'Rolling back Windows 11 Security Optimizer changes...' -ForegroundColor Cyan

"@
    $body = $script:Core.Rollback.ToArray(); [array]::Reverse($body)
    $full = $header + ($body -join "`r`n`r`n") + "`r`n`r`nWrite-Host 'Rollback complete. A restart is recommended.' -ForegroundColor Green`r`n"
    Set-Content -Path $script:Core.RollbackFile -Value $full -Encoding UTF8
    try { $script:Core.Backups.ToArray() | ConvertTo-Json -Depth 6 | Set-Content -Path $script:Core.BackupFile -Encoding UTF8 } catch { }
    Write-CoreLog -Message ("Rollback script written: {0}" -f $script:Core.RollbackFile) -Level OK
}

function New-SystemRestorePointOnce {
    <# Creates ONE restore point per session, before the first change. #>
    param([string]$Description = 'Win11 Security Optimizer - before changes')
    if ($script:Core.RestorePointMade) { return $true }
    if (-not (Test-IsAdmin)) { Write-CoreLog -Message 'Restore point skipped (not elevated).' -Level WARN; return $false }
    try {
        Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue
        $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        if (-not (Test-Path $srKey)) { New-Item -Path $srKey -Force -ErrorAction SilentlyContinue | Out-Null }
        New-ItemProperty -Path $srKey -Name 'SystemRestorePointCreationFrequency' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        $script:Core.RestorePointMade = $true
        Write-CoreLog -Message 'System Restore point created.' -Level OK
        return $true
    } catch {
        Write-CoreLog -Message ("Could not create a System Restore point: {0}" -f $_.Exception.Message) -Level WARN
        return $false
    }
}

function Assert-SafeToChange {
    <# Gate every state change: must be admin + a restore point attempt made. #>
    if (-not (Test-IsAdmin)) { throw 'This action requires Administrator rights.' }
    [void](New-SystemRestorePointOnce)
}

# ----------------------------------------------------------------------------
#  Result model
# ----------------------------------------------------------------------------
function New-Finding {
    param(
        [string]$Id, [string]$Category, [string]$Name,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [ValidateSet('Pass','Fail','Warning','Info','Error')][string]$Status,
        [string]$Observed, [string]$Expected, [string]$Detail, [string]$Advice,
        [ValidateSet('Safe','Elevated','HighRisk','AuditOnly')][string]$RiskTier = 'Safe',
        [bool]$Fixable = $false
    )
    [pscustomobject]@{
        Id=$Id; Category=$Category; Name=$Name; Severity=$Severity; Status=$Status
        Observed=$Observed; Expected=$Expected; Detail=$Detail; Advice=$Advice
        RiskTier=$RiskTier; Fixable=$Fixable
    }
}

# ============================================================================
#  SECURITY SCAN ENGINE  (read-only) -> returns an array of findings
# ============================================================================
function Invoke-SecurityScan {
    $findings = New-Object System.Collections.ArrayList
    $add = { param($f) [void]$findings.Add($f) }

    # ---- Microsoft Defender ----
    $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($mp) {
        $rtp = [bool]$mp.RealTimeProtectionEnabled
        & $add (New-Finding -Id 'DEF-RTP' -Category 'Microsoft Defender' -Name 'Real-time protection' -Severity 'Critical' `
            -Status $(if($rtp){'Pass'}else{'Fail'}) -Observed $(if($rtp){'Enabled'}else{'Disabled'}) -Expected 'Enabled' `
            -Detail 'Scans files as they are opened.' -Advice 'Turn real-time protection back on.' -RiskTier 'Safe' -Fixable (-not $rtp))

        $cloud = $false; try { $cloud = ((Get-MpPreference).MAPSReporting -ne 0) } catch { }
        & $add (New-Finding -Id 'DEF-CLOUD' -Category 'Microsoft Defender' -Name 'Cloud-delivered protection' -Severity 'High' `
            -Status $(if($cloud){'Pass'}else{'Fail'}) -Observed $(if($cloud){'Enabled'}else{'Disabled'}) -Expected 'Enabled' `
            -Detail 'Catches brand-new threats via Microsoft cloud.' -Advice 'Enable cloud protection (MAPS).' -RiskTier 'Safe' -Fixable (-not $cloud))

        $pua = $false; try { $pua = ((Get-MpPreference).PUAProtection -ne 0) } catch { }
        & $add (New-Finding -Id 'DEF-PUA' -Category 'Microsoft Defender' -Name 'Potentially Unwanted App protection' -Severity 'Medium' `
            -Status $(if($pua){'Pass'}else{'Fail'}) -Observed $(if($pua){'Enabled'}else{'Disabled'}) -Expected 'Enabled' `
            -Detail 'Blocks adware/bundleware.' -Advice 'Enable PUA protection.' -RiskTier 'Safe' -Fixable (-not $pua))

        $tamper = $false; try { $tamper = [bool]$mp.IsTamperProtected } catch { }
        & $add (New-Finding -Id 'DEF-TAMPER' -Category 'Microsoft Defender' -Name 'Tamper protection' -Severity 'High' `
            -Status $(if($tamper){'Pass'}else{'Warning'}) -Observed $(if($tamper){'Enabled'}else{'Disabled'}) -Expected 'Enabled' `
            -Detail 'Stops malware disabling Defender.' -Advice 'Enable in Windows Security app (by design, cannot be scripted).' -RiskTier 'AuditOnly')

        $age = $null; try { $age = [int]$mp.AntispywareSignatureAge } catch { }
        $sigStatus = if ($age -eq $null){'Info'} elseif ($age -le 3){'Pass'} elseif ($age -le 7){'Warning'} else {'Fail'}
        & $add (New-Finding -Id 'DEF-SIG' -Category 'Microsoft Defender' -Name 'Antimalware signature age' -Severity $(if($age -ne $null -and $age -gt 7){'High'}else{'Low'}) `
            -Status $sigStatus -Observed $(if($age -ne $null){"$age day(s) old"}else{'Unknown'}) -Expected 'Updated within 3 days' `
            -Detail 'Old signatures miss recent threats.' -Advice 'Update Defender signatures.' -RiskTier 'Safe' -Fixable ($age -ne $null -and $age -gt 3))

        # ASR: count rules actually set to BLOCK (action 1). A GUID present but set
        # to Disabled(0)/Audit(2)/Warn(6) does NOT count as protecting you.
        $asrBlock = 0; $asrOther = 0
        try {
            $p = Get-MpPreference
            $ids = @($p.AttackSurfaceReductionRules_Ids)
            $acts = @($p.AttackSurfaceReductionRules_Actions)
            for ($i=0; $i -lt $ids.Count; $i++) {
                if ($i -lt $acts.Count -and [int]$acts[$i] -eq 1) { $asrBlock++ } else { $asrOther++ }
            }
        } catch { }
        $asrObs = if ($asrBlock -gt 0 -or $asrOther -gt 0) { "$asrBlock in Block, $asrOther in Audit/Warn/Off" } else { 'none configured' }
        & $add (New-Finding -Id 'DEF-ASR' -Category 'Microsoft Defender' -Name 'Attack Surface Reduction rules' -Severity 'Medium' `
            -Status $(if($asrBlock -ge 3){'Pass'}else{'Warning'}) -Observed $asrObs -Expected 'Key rules in Block mode' `
            -Detail 'ASR rules block common exploit behaviors (e.g. Office spawning executables, LSASS credential theft). Only rules set to Block actually protect you.' -Advice 'Enable the baseline ASR rules in Block mode.' -RiskTier 'Elevated' -Fixable ($asrBlock -lt 3))
    } else {
        & $add (New-Finding -Id 'DEF-000' -Category 'Microsoft Defender' -Name 'Defender availability' -Severity 'Info' `
            -Status 'Info' -Observed 'Not queryable' -Expected 'Present' -Detail 'A third-party AV may be active.' -Advice 'Verify your AV is up to date.' -RiskTier 'AuditOnly')
    }

    # ---- Firewall ----
    $profiles = $null; try { $profiles = Get-NetFirewallProfile -ErrorAction Stop } catch { }
    if ($profiles) {
        foreach ($pr in $profiles) {
            $on = [bool]$pr.Enabled
            & $add (New-Finding -Id ("FW-{0}" -f $pr.Name) -Category 'Firewall' -Name ("Firewall profile: {0}" -f $pr.Name) -Severity 'Critical' `
                -Status $(if($on){'Pass'}else{'Fail'}) -Observed $(if($on){'Enabled'}else{'Disabled'}) -Expected 'Enabled' `
                -Detail ("Filters traffic on the {0} profile." -f $pr.Name) -Advice 'Enable this firewall profile.' -RiskTier 'Safe' -Fixable (-not $on))
        }
    }

    # ---- SmartScreen ----
    $ss = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled'
    $ssOk = ($ss -in @('RequireAdmin','Warn','Prompt','On'))
    & $add (New-Finding -Id 'SS-EXPLORER' -Category 'SmartScreen' -Name 'SmartScreen for apps & files' -Severity 'Medium' `
        -Status $(if($ssOk){'Pass'}else{'Warning'}) -Observed $(if($ss){$ss}else{'Off / not set'}) -Expected 'Warn or RequireAdmin' `
        -Detail 'Checks downloads against a reputation service.' -Advice 'Set SmartScreen to Warn.' -RiskTier 'Safe' -Fixable (-not $ssOk))

    # ---- UAC ----
    $uBase = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $enable=Get-RegValue -Path $uBase -Name 'EnableLUA'; $consent=Get-RegValue -Path $uBase -Name 'ConsentPromptBehaviorAdmin'; $secure=Get-RegValue -Path $uBase -Name 'PromptOnSecureDesktop'
    & $add (New-Finding -Id 'UAC-ENABLE' -Category 'User Account Control' -Name 'UAC enabled (EnableLUA)' -Severity 'Critical' `
        -Status $(if($enable -eq 1){'Pass'}else{'Fail'}) -Observed $(if($enable -ne $null){"$enable"}else{'Not set'}) -Expected '1' `
        -Detail 'Core privilege isolation.' -Advice 'Enable UAC.' -RiskTier 'Safe' -Fixable ($enable -ne 1))
    # ConsentPromptBehaviorAdmin: 0 = elevate silently (WEAK). 1 = prompt for
    # CREDENTIALS on the secure desktop (strictest). 2 = prompt for consent on
    # secure desktop. 5 = prompt for consent for non-Windows binaries (default).
    # Only 0 is bad; 1 is actually stricter than 2/5, so do not "fix" it.
    $consentOk = ($consent -ne $null -and $consent -ne 0)
    & $add (New-Finding -Id 'UAC-CONSENT' -Category 'User Account Control' -Name 'Admin consent prompt' -Severity 'Medium' `
        -Status $(if($consentOk){'Pass'}else{'Warning'}) -Observed $(if($consent -ne $null){"$consent"}else{'Not set'}) -Expected 'Non-zero (1, 2 or 5)' `
        -Detail '0 = silent elevation (weak). 1 = prompt for credentials (strictest). 2/5 = prompt for consent.' -Advice 'Require a prompt instead of silent elevation.' -RiskTier 'Safe' -Fixable ($consent -eq 0))
    & $add (New-Finding -Id 'UAC-SECUREDESK' -Category 'User Account Control' -Name 'Prompt on secure desktop' -Severity 'Low' `
        -Status $(if($secure -eq 1){'Pass'}else{'Warning'}) -Observed $(if($secure -ne $null){"$secure"}else{'Not set'}) -Expected '1' `
        -Detail 'Stops other apps spoofing the UAC prompt.' -Advice 'Enable secure-desktop prompting.' -RiskTier 'Safe' -Fixable ($secure -ne 1))

    # ---- Legacy protocols ----
    # Get-WindowsOptionalFeature needs elevation; without admin we must NOT claim a
    # false Pass. Fall back to the server-side registry switch; if neither is
    # readable, report Info/unknown.
    $smb1 = $null
    try { $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } catch { }
    $smb1srv = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
    if ($smb1 -ne $null) {
        $smb1on = ($smb1 -eq 'Enabled')
        & $add (New-Finding -Id 'SMB1' -Category 'Legacy Protocols' -Name 'SMBv1 protocol' -Severity 'High' `
            -Status $(if($smb1on){'Fail'}else{'Pass'}) -Observed ("Feature: {0}" -f $smb1) -Expected 'Disabled' `
            -Detail 'SMBv1 enabled WannaCry/EternalBlue.' -Advice 'Disable SMBv1 unless a legacy NAS needs it.' -RiskTier 'Elevated' -Fixable $smb1on)
    } elseif ($smb1srv -ne $null) {
        $smb1on = ($smb1srv -eq 1)
        & $add (New-Finding -Id 'SMB1' -Category 'Legacy Protocols' -Name 'SMBv1 protocol' -Severity 'High' `
            -Status $(if($smb1on){'Fail'}else{'Pass'}) -Observed ("Server SMB1 reg = {0}" -f $smb1srv) -Expected 'Disabled' `
            -Detail 'SMBv1 enabled WannaCry/EternalBlue. (Feature state needs admin; using the server registry switch.)' -Advice 'Disable SMBv1 unless a legacy NAS needs it.' -RiskTier 'Elevated' -Fixable $smb1on)
    } else {
        & $add (New-Finding -Id 'SMB1' -Category 'Legacy Protocols' -Name 'SMBv1 protocol' -Severity 'Medium' `
            -Status 'Info' -Observed 'Unknown (needs Administrator to read the feature state)' -Expected 'Disabled' `
            -Detail 'The SMBv1 feature state could not be read without elevation.' -Advice 'Relaunch via Start.bat (elevated) to check SMBv1.' -RiskTier 'AuditOnly')
    }

    $llmnr = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    & $add (New-Finding -Id 'LLMNR' -Category 'Legacy Protocols' -Name 'LLMNR multicast name resolution' -Severity 'Medium' `
        -Status $(if($llmnr -eq 0){'Pass'}else{'Warning'}) -Observed $(if($llmnr -ne $null){"EnableMulticast=$llmnr"}else{'Enabled (default)'}) -Expected 'Disabled (0)' `
        -Detail 'Abused for credential theft on untrusted LANs.' -Advice 'Disable LLMNR.' -RiskTier 'Elevated' -Fixable ($llmnr -ne 0))

    # ---- AutoRun ----
    $ar = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
    & $add (New-Finding -Id 'AUTORUN' -Category 'AutoRun / AutoPlay' -Name 'AutoRun disabled for all drives' -Severity 'Medium' `
        -Status $(if($ar -eq 255){'Pass'}else{'Warning'}) -Observed $(if($ar -ne $null){("0x{0:X}" -f [int]$ar)}else{'Not set'}) -Expected '0xFF (255)' `
        -Detail 'USB autorun is a classic worm vector.' -Advice 'Disable AutoRun on all drive types.' -RiskTier 'Safe' -Fixable ($ar -ne 255))

    # ---- Guest account ----
    $guest = $null; try { $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop } catch { }
    if ($guest) {
        $en = [bool]$guest.Enabled
        & $add (New-Finding -Id 'ACCT-GUEST' -Category 'Accounts' -Name 'Built-in Guest account' -Severity 'Medium' `
            -Status $(if($en){'Fail'}else{'Pass'}) -Observed $(if($en){'Enabled'}else{'Disabled'}) -Expected 'Disabled' `
            -Detail 'Enabled Guest = anonymous local access.' -Advice 'Disable the Guest account.' -RiskTier 'Safe' -Fixable $en)
    } else {
        & $add (New-Finding -Id 'ACCT-GUEST' -Category 'Accounts' -Name 'Built-in Guest account' -Severity 'Info' `
            -Status 'Pass' -Observed 'Not present' -Expected 'Disabled' -Detail 'No Guest account found.' -Advice '' -RiskTier 'AuditOnly')
    }

    # ---- Windows Update service ----
    $svc = $null; try { $svc = Get-Service wuauserv -ErrorAction Stop } catch { }
    if ($svc) {
        $bad = ($svc.StartType -eq 'Disabled')
        & $add (New-Finding -Id 'WU-SVC' -Category 'Patching' -Name 'Windows Update service' -Severity 'High' `
            -Status $(if($bad){'Fail'}else{'Pass'}) -Observed ("StartType={0}, {1}" -f $svc.StartType,$svc.Status) -Expected 'Not Disabled' `
            -Detail 'Disabled = no security patches.' -Advice 'Set Windows Update to Manual.' -RiskTier 'Safe' -Fixable $bad)
    }

    # ---- Secure Boot ----
    $sb=$null; try { $sb=[bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }
    if ($sb -eq $null) { $r=Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled'; if($r -ne $null){$sb=($r -eq 1)} }
    if ($sb -eq $null) {
        & $add (New-Finding -Id 'SECUREBOOT' -Category 'Firmware / Hardware' -Name 'Secure Boot' -Severity 'Medium' -Status 'Info' -Observed 'Unknown' -Expected 'Enabled' -Detail 'Requires UEFI.' -Advice 'Check UEFI firmware settings.' -RiskTier 'AuditOnly')
    } else {
        & $add (New-Finding -Id 'SECUREBOOT' -Category 'Firmware / Hardware' -Name 'Secure Boot' -Severity 'High' -Status $(if($sb){'Pass'}else{'Fail'}) -Observed $(if($sb){'Enabled'}else{'Disabled'}) -Expected 'Enabled' -Detail 'Blocks boot rootkits.' -Advice 'Enable Secure Boot in UEFI.' -RiskTier 'AuditOnly')
    }

    # ---- TPM ----
    $present=$null;$ready=$null;$ver=$null
    try { $w=Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop; if($w){$present=$true; try{$ready=[bool]$w.IsEnabled_InitialValue}catch{}; try{if($w.SpecVersion){$ver=($w.SpecVersion -split ',')[0].Trim()}}catch{}} } catch { }
    if ($present -eq $null) { try { $t=Get-Tpm -ErrorAction Stop; if($t){ if($t.PSObject.Properties.Name -contains 'TpmPresent'){$present=[bool]$t.TpmPresent}; if($t.PSObject.Properties.Name -contains 'TpmReady'){$ready=[bool]$t.TpmReady} } } catch { } }
    if ($present -ne $true) { try { $pnp=Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object {$_.Name -match 'Trusted Platform' -or $_.PNPClass -eq 'SecurityDevices'} | Select-Object -First 1; if($pnp){$present=$true; if($pnp.Name -match '2\.0'){$ver='2.0'}} } catch { } }
    if ($present -eq $true) {
        $good = ($ready -ne $false)
        $obs='Present=True'; if($ready -ne $null){$obs+=", Ready=$ready"}; if($ver){$obs+=", Spec=$ver"}
        & $add (New-Finding -Id 'TPM' -Category 'Firmware / Hardware' -Name 'TPM (Trusted Platform Module)' -Severity 'High' -Status $(if($good){'Pass'}else{'Warning'}) -Observed $obs -Expected 'Present & Ready (2.0)' -Detail 'Backs BitLocker/Windows Hello.' -Advice 'Enable TPM in firmware if off.' -RiskTier 'AuditOnly')
    } else {
        & $add (New-Finding -Id 'TPM' -Category 'Firmware / Hardware' -Name 'TPM (Trusted Platform Module)' -Severity 'Medium' -Status 'Info' -Observed 'Unable to query' -Expected 'Present & Ready' -Detail 'TPM not detected or access denied.' -Advice 'Check firmware; run as admin.' -RiskTier 'AuditOnly')
    }

    # ---- BitLocker ----
    $bl=$null; try { $bl=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch { }
    if ($bl) {
        $on = ($bl.ProtectionStatus -eq 'On' -or $bl.ProtectionStatus -eq 1)
        & $add (New-Finding -Id 'BITLOCKER' -Category 'Encryption' -Name ("BitLocker on {0}" -f $env:SystemDrive) -Severity 'High' -Status $(if($on){'Pass'}else{'Warning'}) -Observed ("Protection={0}" -f $bl.ProtectionStatus) -Expected 'On' -Detail 'Protects data if device is stolen.' -Advice 'Enable BitLocker and save the recovery key safely.' -RiskTier 'AuditOnly')
    } else {
        & $add (New-Finding -Id 'BITLOCKER' -Category 'Encryption' -Name ("BitLocker on {0}" -f $env:SystemDrive) -Severity 'Medium' -Status 'Info' -Observed 'Not queryable (needs admin / SKU)' -Expected 'On' -Detail 'Could not read BitLocker.' -Advice 'Run as admin to check.' -RiskTier 'AuditOnly')
    }

    # ---- Core Isolation / HVCI ----
    # Registry 'Enabled' is only the configured intent; actual enforcement shows
    # in Win32_DeviceGuard.SecurityServicesRunning (2 = HVCI running).
    $hvciCfg = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
    $hvciRunning = $false
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        $hvciRunning = (@($dg.SecurityServicesRunning) -contains 2)
    } catch { }
    $hvciStatus = if ($hvciRunning) { 'Pass' } elseif ($hvciCfg -eq 1) { 'Warning' } else { 'Warning' }
    $hvciObs = if ($hvciRunning) { 'Running' } elseif ($hvciCfg -eq 1) { 'Configured but NOT running (reboot or incompatible driver)' } else { 'Off' }
    & $add (New-Finding -Id 'HVCI' -Category 'Exploit Protection' -Name 'Memory Integrity (HVCI)' -Severity 'Medium' -Status $hvciStatus -Observed $hvciObs -Expected 'Running' -Detail 'Protects kernel code integrity. Needs compatible drivers; a blocking driver can stop it running even when enabled.' -Advice 'Enable Memory Integrity (may need driver updates), then reboot.' -RiskTier 'HighRisk' -Fixable (-not $hvciRunning))

    # ---- RDP ----
    $deny = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    $rdp = ($deny -eq 0)
    & $add (New-Finding -Id 'RDP-ENABLED' -Category 'Remote Access' -Name 'Remote Desktop (RDP) listener' -Severity 'Medium' -Status $(if($rdp){'Warning'}else{'Pass'}) -Observed $(if($rdp){'Enabled'}else{'Disabled'}) -Expected 'Disabled unless needed' -Detail 'Frequent brute-force/ransomware entry point.' -Advice 'Disable RDP if you never remote in.' -RiskTier 'HighRisk' -Fixable $rdp)
    if ($rdp) {
        $nla = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
        & $add (New-Finding -Id 'RDP-NLA' -Category 'Remote Access' -Name 'RDP Network Level Authentication' -Severity 'High' -Status $(if($nla -eq 1){'Pass'}else{'Fail'}) -Observed $(if($nla -ne $null){"NLA=$nla"}else{'Not set'}) -Expected 'Enabled (1)' -Detail 'Forces auth before a session starts.' -Advice 'Require NLA for RDP.' -RiskTier 'Elevated' -Fixable ($nla -ne 1))
    }

    Write-CoreLog -Message ("Security scan complete: {0} findings." -f $findings.Count) -Level INFO
    return $findings.ToArray()
}

function Get-SecurityScore {
    param($Findings)
    $penalty = 0
    foreach ($r in $Findings) {
        $w = $script:SeverityWeight[$r.Severity]
        if ($r.Status -eq 'Fail')    { $penalty += $w }
        elseif ($r.Status -eq 'Warning') { $penalty += ($w * 0.5) }
    }
    $score = [math]::Max(0, 100 - [math]::Round($penalty))
    $grade = switch ($score) { {$_ -ge 90}{'A';break} {$_ -ge 80}{'B';break} {$_ -ge 70}{'C';break} {$_ -ge 60}{'D';break} default{'F'} }
    [pscustomobject]@{ Score=$score; Grade=$grade
        Pass=@($Findings | Where-Object {$_.Status -eq 'Pass'}).Count
        Warn=@($Findings | Where-Object {$_.Status -eq 'Warning'}).Count
        Fail=@($Findings | Where-Object {$_.Status -eq 'Fail'}).Count }
}

# ============================================================================
#  SECURITY HARDENING  (state-changing; each fix is tracked + reversible)
# ============================================================================
function Get-SecurityFixAction {
    param([string]$Id)
    switch ($Id) {
        'DEF-RTP'   { return { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; Add-RollbackCommand 'Set-MpPreference -DisableRealtimeMonitoring $true' 'Revert real-time protection'; Add-ChangeRecord 'Enabled Defender real-time protection' } }
        'DEF-CLOUD' { return { $prev=$null; try { $prev=(Get-MpPreference).SubmitSamplesConsent } catch {}; Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop; Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue; Add-RollbackCommand ("Set-MpPreference -MAPSReporting Disabled -ErrorAction SilentlyContinue; Set-MpPreference -SubmitSamplesConsent " + $(if($prev -ne $null){$prev}else{'AlwaysPrompt'}) + " -ErrorAction SilentlyContinue") 'Revert cloud protection + sample submission'; Add-ChangeRecord 'Enabled cloud-delivered protection and set SubmitSamplesConsent=SendSafeSamples (auto-sends files Defender deems safe to Microsoft)' } }
        'DEF-PUA'   { return { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop; Add-RollbackCommand 'Set-MpPreference -PUAProtection Disabled' 'Revert PUA'; Add-ChangeRecord 'Enabled PUA protection' } }
        'DEF-SIG'   { return { Update-MpSignature -ErrorAction Stop; Add-ChangeRecord 'Updated Defender signatures' } }
        'DEF-ASR'   { return {
                        # MERGE our baseline rules into whatever ASR rules the user
                        # already has - DO NOT replace. Set-MpPreference with the full
                        # list would wipe any pre-existing ASR rule the user/their org
                        # configured; Add-MpPreference adds/updates only our own.
                        #
                        # Rule selection: the PSExec/WMI rule (D1E49AAC) is deliberately
                        # EXCLUDED - Microsoft documents it as incompatible with
                        # Configuration Manager and it is not in MS's standard set. In
                        # its place we enable two rules from MS's standard protection
                        # set: block abuse of exploited vulnerable signed drivers
                        # (56A863A9) and block persistence via WMI event subscription
                        # (E6DB77E5). Includes the LSASS credential-theft rule (9E6C4E1F).
                        $rules=@(
                          'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',  # executable content from email/webmail
                          'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',  # Office child processes
                          '3B576869-A4EC-4529-8536-B80A7769E899',  # Office executable content
                          '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',  # obfuscated scripts
                          '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',  # Win32 API from Office macros
                          '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2',  # block credential theft from LSASS
                          '56A863A9-875E-4185-98A7-B882C64B5CE5',  # block abuse of exploited vulnerable signed drivers
                          'E6DB77E5-3DF2-4CF1-B95A-636979351E5B'   # block persistence through WMI event subscription
                        ) | Select-Object -Unique

                        # Back up the user's PRIOR ASR state so rollback can restore it
                        # exactly (not just blindly disable our seven rules).
                        $prevIds=@(); $prevActs=@()
                        try { $pp=Get-MpPreference; $prevIds=@($pp.AttackSurfaceReductionRules_Ids | ForEach-Object { "$_" }); $prevActs=@($pp.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ }) } catch { }

                        # Apply by MERGE. Add-MpPreference adds/updates each rule to
                        # Block without touching the rest of the list.
                        foreach ($r in $rules) {
                            Add-MpPreference -AttackSurfaceReductionRules_Ids $r -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                        }

                        # Build a rollback that restores the PRIOR list: remove the rules
                        # we added that were not present before, then re-assert every
                        # prior rule's prior action verbatim. GUIDs/ints only -> safe to
                        # embed (they cannot contain quotes). ASR action ints are mapped
                        # back to their names so Add-MpPreference binds reliably
                        # (0=Disabled,1=Enabled/Block,2=AuditMode,6=Warn).
                        $actName = @{ 0='Disabled'; 1='Enabled'; 2='AuditMode'; 6='Warn' }
                        $prevSet = @{}; for ($i=0; $i -lt $prevIds.Count; $i++) { $prevSet[$prevIds[$i].ToUpper()] = $true }
                        $rb = New-Object System.Collections.Generic.List[string]
                        foreach ($r in $rules) {
                            if (-not $prevSet.ContainsKey($r.ToUpper())) {
                                $rb.Add("Remove-MpPreference -AttackSurfaceReductionRules_Ids '$r' -ErrorAction SilentlyContinue")
                            }
                        }
                        for ($i=0; $i -lt $prevIds.Count; $i++) {
                            if ($i -lt $prevActs.Count) {
                                $an = if ($actName.ContainsKey($prevActs[$i])) { $actName[$prevActs[$i]] } else { 'Enabled' }
                                $rb.Add("Add-MpPreference -AttackSurfaceReductionRules_Ids '$($prevIds[$i])' -AttackSurfaceReductionRules_Actions $an -ErrorAction SilentlyContinue")
                            }
                        }
                        if ($rb.Count -eq 0) { $rb.Add('# ASR: no rules existed before and none needed removing - nothing to roll back.') }
                        Add-RollbackCommand ($rb -join "`r`n") 'Restore ASR rules to their state before this tool ran'
                        Add-ChangeRecord 'Enabled baseline ASR rules in Block mode by merge (incl. LSASS, vulnerable-driver and WMI-persistence rules); prior ASR state backed up for rollback' } }
        'FW-Domain'  { return { Set-NetFirewallProfile -Profile Domain  -Enabled True -ErrorAction Stop; Add-RollbackCommand 'Set-NetFirewallProfile -Profile Domain -Enabled False' 'Revert Domain FW'; Add-ChangeRecord 'Enabled Domain firewall' } }
        'FW-Private' { return { Set-NetFirewallProfile -Profile Private -Enabled True -ErrorAction Stop; Add-RollbackCommand 'Set-NetFirewallProfile -Profile Private -Enabled False' 'Revert Private FW'; Add-ChangeRecord 'Enabled Private firewall' } }
        'FW-Public'  { return { Set-NetFirewallProfile -Profile Public  -Enabled True -ErrorAction Stop; Add-RollbackCommand 'Set-NetFirewallProfile -Profile Public -Enabled False' 'Revert Public FW'; Add-ChangeRecord 'Enabled Public firewall' } }
        'SS-EXPLORER'{ return { Set-RegValueTracked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Warn' -Type String } }
        'UAC-ENABLE' { return { Set-RegValueTracked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord } }
        'UAC-CONSENT'{ return { Set-RegValueTracked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 5 -Type DWord } }
        'UAC-SECUREDESK'{ return { Set-RegValueTracked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord } }
        'SMB1'       { return { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null; Add-RollbackCommand 'Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart' 'Re-enable SMBv1'; Add-ChangeRecord 'Disabled SMBv1 (restart may be needed)' } }
        'LLMNR'      { return { Set-RegValueTracked -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord } }
        'AUTORUN'    { return { Set-RegValueTracked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord } }
        'ACCT-GUEST' { return { Disable-LocalUser -Name 'Guest' -ErrorAction Stop; Add-RollbackCommand 'Enable-LocalUser -Name ''Guest''' 'Re-enable Guest'; Add-ChangeRecord 'Disabled Guest account' } }
        'WU-SVC'     { return { Set-Service -Name wuauserv -StartupType Manual -ErrorAction Stop; Add-RollbackCommand 'Set-Service -Name wuauserv -StartupType Disabled' 'Revert WU service'; Add-ChangeRecord 'Set Windows Update to Manual' } }
        'HVCI'       { return { Set-RegValueTracked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1 -Type DWord } }
        'RDP-ENABLED'{ return { Set-RegValueTracked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Type DWord } }
        'RDP-NLA'    { return { Set-RegValueTracked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord } }
        default      { return $null }
    }
}

function Invoke-SecurityFix {
    <# Applies ONE fix by Id. Returns @{Success;Message;Verified}. GUI calls this per-item. #>
    param([Parameter(Mandatory)][string]$Id)
    $action = Get-SecurityFixAction -Id $Id
    if (-not $action) { return [pscustomobject]@{ Success=$false; Message="No fix available for $Id"; Verified=$false } }
    try {
        Assert-SafeToChange
        & $action
        Save-RollbackArtifacts
        $verified = Test-SecurityFixApplied -Id $Id
        Write-CoreLog -Message ("Applied security fix {0} (verified={1})" -f $Id, $verified) -Level OK
        return [pscustomobject]@{ Success=$true; Message="Applied."; Verified=$verified }
    } catch {
        Write-CoreLog -Message ("Security fix {0} failed: {1}" -f $Id, $_.Exception.Message) -Level ERROR
        return [pscustomobject]@{ Success=$false; Message=$_.Exception.Message; Verified=$false }
    }
}

function Test-SecurityFixApplied {
    param([string]$Id)
    try {
        switch ($Id) {
            'DEF-RTP'    { return ([bool](Get-MpComputerStatus).RealTimeProtectionEnabled) }
            'DEF-CLOUD'  { return ((Get-MpPreference).MAPSReporting -ne 0) }
            'DEF-PUA'    { return ((Get-MpPreference).PUAProtection -ne 0) }
            'FW-Domain'  { return [bool](Get-NetFirewallProfile -Profile Domain).Enabled }
            'FW-Private' { return [bool](Get-NetFirewallProfile -Profile Private).Enabled }
            'FW-Public'  { return [bool](Get-NetFirewallProfile -Profile Public).Enabled }
            'SS-EXPLORER'{ return ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled') -in @('Warn','RequireAdmin','On','Prompt')) }
            'UAC-ENABLE' { return ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 1) }
            'UAC-CONSENT'{ return ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin') -ge 2) }
            'UAC-SECUREDESK'{ return ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop') -eq 1) }
            'LLMNR'      { return ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0) }
            'AUTORUN'    { return ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') -eq 255) }
            'ACCT-GUEST' { return (-not (Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled) }
            'WU-SVC'     { return ((Get-Service wuauserv).StartType -ne 'Disabled') }
            'DEF-ASR'    {
                try {
                    $p = Get-MpPreference
                    $ids = @($p.AttackSurfaceReductionRules_Ids); $acts = @($p.AttackSurfaceReductionRules_Actions)
                    $block = 0; for ($i=0; $i -lt $ids.Count; $i++) { if ($i -lt $acts.Count -and [int]$acts[$i] -eq 1) { $block++ } }
                    return ($block -ge 3)
                } catch { return $false }
            }
            'HVCI'       {
                # The registry key only expresses INTENT. Real enforcement is in
                # Win32_DeviceGuard.SecurityServicesRunning (2 = HVCI running).
                try {
                    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
                    if (@($dg.SecurityServicesRunning) -contains 2) { return $true }
                    # Configured but not yet running (needs reboot) -> report inconclusive as not-yet-verified.
                    return $false
                } catch {
                    return ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled') -eq 1)
                }
            }
            'RDP-ENABLED'{ return ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 1) }
            'RDP-NLA'    { return ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1) }
            'SMB1'       { try { return ((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State -ne 'Enabled') } catch { return $true } }
            default      { return $true }
        }
    } catch { return $false }
}


# ============================================================================
#  DEBLOAT ENGINE
#  Catalog of removable native/bundled apps. Nothing is auto-removed; the GUI
#  shows each with a checkbox and the user chooses. Only INSTALLED apps appear.
#  Removal uses Remove-AppxPackage / Remove-AppxProvisionedPackage and is logged
#  with the exact package family so it can be reinstalled.
# ============================================================================

function Get-DebloatCatalog {
    <#
      Returns the curated catalog (static metadata). Each entry:
        Key        - stable id
        Name       - friendly display name
        Publisher  - who makes it
        Description- what it is / why people remove it
        AppxName   - wildcard PackageName match for Get-AppxPackage
        Category   - grouping for the UI
        Recommended- whether it is a safe/common removal (UI hint only; NOT pre-ticked)
        ReinstallNote - how to get it back
    #>
    @(
        [pscustomobject]@{ Key='xbox';        Name='Xbox Game Bar & overlay';     Publisher='Microsoft'; Category='Gaming';        AppxName='Microsoft.XboxGamingOverlay*';            Recommended=$true;  Description='The Xbox Game Bar overlay (Win+G) and app companion. Safe to remove if you do not use it; PC games still run. Does NOT touch Game Pass sign-in.'; ReinstallNote='Reinstall "Xbox Game Bar" from the Microsoft Store.' }
        [pscustomobject]@{ Key='xboxtcui';    Name='Xbox Game UI (TCUI)';         Publisher='Microsoft'; Category='Gaming';        AppxName='Microsoft.Xbox.TCUI*';                    Recommended=$false; Description='In-game Xbox UI used by some titles for invites/profiles. Removing it CAN break in-game social features. Leave it unless you are sure.'; ReinstallNote='Reinstall "Xbox" components from the Microsoft Store.' }
        [pscustomobject]@{ Key='xboxspeech';  Name='Xbox Speech To Text';         Publisher='Microsoft'; Category='Gaming';        AppxName='Microsoft.XboxSpeechToTextOverlay*';      Recommended=$true;  Description='Game-chat speech-to-text overlay. Rarely used; safe to remove.'; ReinstallNote='Reinstall from the Microsoft Store.' }
        [pscustomobject]@{ Key='gamingapp';   Name='Xbox Gaming App';             Publisher='Microsoft'; Category='Gaming';        AppxName='Microsoft.GamingApp*';                    Recommended=$false; Description='The main Xbox PC gaming app / Game Pass launcher. Remove only if you do not use Game Pass.'; ReinstallNote='Reinstall "Xbox" from the Microsoft Store.' }
        [pscustomobject]@{ Key='bingnews';    Name='Microsoft News (Bing News)';  Publisher='Microsoft'; Category='Bing/News';     AppxName='Microsoft.BingNews*';                     Recommended=$true;  Description='News feed app that runs live-tile/background updates. Pure bloat for most users.'; ReinstallNote='Reinstall "Microsoft News" from the Store.' }
        [pscustomobject]@{ Key='bingweather'; Name='MSN Weather (Bing Weather)';  Publisher='Microsoft'; Category='Bing/News';     AppxName='Microsoft.BingWeather*';                  Recommended=$true;  Description='Weather app with background refresh. Removable; use a website or widget instead.'; ReinstallNote='Reinstall "MSN Weather" from the Store.' }
        [pscustomobject]@{ Key='clipchamp';   Name='Clipchamp Video Editor';      Publisher='Microsoft'; Category='Media';         AppxName='Clipchamp.Clipchamp*';                    Recommended=$true;  Description='Bundled video editor few people use. Removable without affecting playback.'; ReinstallNote='Reinstall "Clipchamp" from the Store.' }
        [pscustomobject]@{ Key='solitaire';   Name='Microsoft Solitaire Collection';Publisher='Microsoft';Category='Games';         AppxName='Microsoft.MicrosoftSolitaireCollection*'; Recommended=$true;  Description='Ad-supported solitaire games bundle. Pure bloat.'; ReinstallNote='Reinstall "Microsoft Solitaire Collection" from the Store.' }
        [pscustomobject]@{ Key='3dviewer';    Name='3D Viewer';                   Publisher='Microsoft'; Category='Media';         AppxName='Microsoft.Microsoft3DViewer*';            Recommended=$true;  Description='Views 3D models. Rarely used; safe to remove.'; ReinstallNote='Reinstall "3D Viewer" from the Store.' }
        [pscustomobject]@{ Key='paint3d';     Name='Paint 3D';                    Publisher='Microsoft'; Category='Media';         AppxName='Microsoft.MSPaint*';                      Recommended=$true;  Description='3D painting app (not classic Paint). Classic Paint is unaffected.'; ReinstallNote='Reinstall "Paint 3D" from the Store.' }
        [pscustomobject]@{ Key='mixedreality';Name='Mixed Reality Portal';        Publisher='Microsoft'; Category='Media';         AppxName='Microsoft.MixedReality.Portal*';          Recommended=$true;  Description='Windows Mixed Reality portal. Useless without a WMR headset.'; ReinstallNote='Reinstall "Mixed Reality Portal" from the Store.' }
        [pscustomobject]@{ Key='teamsconsumer';Name='Microsoft Teams (personal)'; Publisher='Microsoft'; Category='Communication'; AppxName='MicrosoftTeams*';                         Recommended=$true;  Description='Consumer Teams/Chat auto-installed with Windows 11. Does NOT remove work/school Teams installed separately.'; ReinstallNote='Reinstall "Microsoft Teams" from the Store.' }
        [pscustomobject]@{ Key='gethelp';     Name='Get Help';                    Publisher='Microsoft'; Category='System Extras';  AppxName='Microsoft.GetHelp*';                      Recommended=$false; Description='Microsoft support/help app. Minor; removable.'; ReinstallNote='Reinstall "Get Help" from the Store.' }
        [pscustomobject]@{ Key='tips';        Name='Tips';                        Publisher='Microsoft'; Category='System Extras';  AppxName='Microsoft.Getstarted*';                   Recommended=$true;  Description='"Tips" / Get Started suggestions app. Bloat.'; ReinstallNote='Reinstall "Tips" from the Store.' }
        [pscustomobject]@{ Key='feedback';    Name='Feedback Hub';                Publisher='Microsoft'; Category='System Extras';  AppxName='Microsoft.WindowsFeedbackHub*';           Recommended=$false; Description='Sends feedback to Microsoft. Removable if you never file feedback.'; ReinstallNote='Reinstall "Feedback Hub" from the Store.' }
        [pscustomobject]@{ Key='maps';        Name='Windows Maps';                Publisher='Microsoft'; Category='System Extras';  AppxName='Microsoft.WindowsMaps*';                  Recommended=$true;  Description='Offline maps app. Most people use a browser instead.'; ReinstallNote='Reinstall "Windows Maps" from the Store.' }
        [pscustomobject]@{ Key='soundrec';    Name='Sound Recorder';              Publisher='Microsoft'; Category='Media';         AppxName='Microsoft.WindowsSoundRecorder*';         Recommended=$false; Description='Voice recorder app. Remove only if unused.'; ReinstallNote='Reinstall "Windows Sound Recorder" from the Store.' }
        [pscustomobject]@{ Key='people';      Name='People';                      Publisher='Microsoft'; Category='Communication'; AppxName='Microsoft.People*';                       Recommended=$true;  Description='Legacy contacts aggregator. Largely abandoned; safe to remove.'; ReinstallNote='Reinstall "People" from the Store.' }
        [pscustomobject]@{ Key='yourphone';   Name='Phone Link (Your Phone)';     Publisher='Microsoft'; Category='Communication'; AppxName='Microsoft.YourPhone*';                    Recommended=$false; Description='Links your Android/iPhone to Windows. Remove only if you do not pair a phone.'; ReinstallNote='Reinstall "Phone Link" from the Store.' }
        [pscustomobject]@{ Key='bingsearch';  Name='Web Search (Bing) app';       Publisher='Microsoft'; Category='Bing/News';     AppxName='Microsoft.BingSearch*';                   Recommended=$false; Description='Bing web-search app component. Removing may reduce web results in Start search.'; ReinstallNote='Reinstall from the Store if Start search feels limited.' }
        [pscustomobject]@{ Key='quickassist'; Name='Quick Assist';                Publisher='Microsoft'; Category='Remote Access';  AppxName='MicrosoftCorporationII.QuickAssist*';     Recommended=$true;  Description='Remote-assistance tool frequently abused by tech-support scammers. Remove if you never use it.'; ReinstallNote='Reinstall "Quick Assist" from the Store.' }
        [pscustomobject]@{ Key='familysafety';Name='Family Safety';               Publisher='Microsoft'; Category='System Extras';  AppxName='MicrosoftCorporationII.MicrosoftFamily*'; Recommended=$false; Description='Family/parental controls companion. Remove if you do not use Microsoft Family.'; ReinstallNote='Reinstall "Microsoft Family Safety" from the Store.' }
        [pscustomobject]@{ Key='todos';       Name='Microsoft To Do';             Publisher='Microsoft'; Category='Productivity';   AppxName='Microsoft.Todos*';                        Recommended=$false; Description='Task/to-do list app. Remove only if unused.'; ReinstallNote='Reinstall "Microsoft To Do" from the Store.' }
        [pscustomobject]@{ Key='solitaire2';  Name='Solitaire (alt package)';     Publisher='Microsoft'; Category='Games';         AppxName='Microsoft.MicrosoftSolitaire*';           Recommended=$false; Description='Alternate solitaire package id (if present).'; ReinstallNote='Reinstall from the Store.' }
    )
}

function Get-DebloatInventory {
    <#
      Scans installed Appx packages for the current user and returns ONLY catalog
      entries that are actually installed, enriched with version + install state.
      Read-only.
    #>
    $catalog = Get-DebloatCatalog
    $installed = @()
    try { $installed = Get-AppxPackage -ErrorAction Stop } catch { Write-CoreLog -Message ("Get-AppxPackage failed: {0}" -f $_.Exception.Message) -Level WARN }

    $result = New-Object System.Collections.ArrayList
    foreach ($c in $catalog) {
        $pattern = $c.AppxName.TrimEnd('*')
        $match = $installed | Where-Object { $_.Name -like $c.AppxName } | Select-Object -First 1
        if ($match) {
            [void]$result.Add([pscustomobject]@{
                Key=$c.Key; Name=$c.Name; Publisher=$c.Publisher; Category=$c.Category
                Description=$c.Description; ReinstallNote=$c.ReinstallNote; Recommended=$c.Recommended
                PackageFullName=$match.PackageFullName; PackageFamilyName=$match.PackageFamilyName
                Version=$match.Version; Installed=$true
            })
        }
    }
    Write-CoreLog -Message ("Debloat inventory: {0} removable app(s) installed." -f $result.Count) -Level INFO
    return $result.ToArray()
}

function Remove-DebloatApp {
    <#
      Removes ONE app (current user + provisioned so it does not return for new
      users). Logs the package family for reinstall. GUI calls this per ticked item.
      Returns @{Success;Message}.
    #>
    param([Parameter(Mandatory)][string]$AppxName, [string]$FriendlyName = '')
    # Hard safety net: never remove packages that break OS/gaming sign-in or
    # core platform plumbing, even if a wildcard would otherwise match them.
    $protected = @(
        'Microsoft.XboxIdentityProvider',   # Xbox / Game Pass / Minecraft sign-in
        'Microsoft.GamingServices',         # Game Pass game installs
        'Microsoft.XboxGameCallableUI',
        'Microsoft.VCLibs',
        'Microsoft.NET',
        'Microsoft.UI.Xaml',
        'Microsoft.WindowsStore',           # the Store itself (needed to reinstall!)
        'Microsoft.DesktopAppInstaller',
        'Microsoft.StorePurchaseApp',
        'Microsoft.SecHealthUI',            # Windows Security UI
        'MicrosoftWindows.Client'
    )
    foreach ($pp in $protected) {
        if ($AppxName -like "$pp*") {
            return [pscustomobject]@{ Success=$false; Message=("Refused: '{0}' is a protected system/sign-in package and will not be removed." -f $pp) }
        }
    }
    try {
        Assert-SafeToChange
    } catch {
        return [pscustomobject]@{ Success=$false; Message=$_.Exception.Message }
    }
    $label = if ($FriendlyName) { $FriendlyName } else { $AppxName }
    $removedAny = $false
    $familyNames = @()
    try {
        $pkgs = @(Get-AppxPackage -Name $AppxName -ErrorAction SilentlyContinue) | Where-Object {
            # second guard: skip any protected package caught by a broad wildcard
            $n = $_.Name
            -not ($protected | Where-Object { $n -like "$_*" })
        }
        foreach ($pkg in $pkgs) {
            $familyNames += $pkg.PackageFamilyName
            Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
            $removedAny = $true
        }
        # Provisioned (so it is not reinstalled for new user profiles)
        try {
            $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like $AppxName }
            foreach ($pp in $prov) {
                Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction SilentlyContinue | Out-Null
            }
        } catch { }

        if ($removedAny) {
            $fam = ($familyNames | Select-Object -Unique) -join ', '
            Add-RollbackCommand -Command "# To reinstall '$label', open Microsoft Store and search for it, or run (if the package is still staged):`r`n# Get-AppxPackage -AllUsers -Name '$AppxName' | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register ""$($_.InstallLocation)\AppXManifest.xml"" }" -Comment "Reinstall note for $label (families: $fam)"
            Add-ChangeRecord -Description ("Removed app '{0}' ({1})" -f $label, $fam)
            Save-RollbackArtifacts
            return [pscustomobject]@{ Success=$true; Message=("Removed {0}." -f $label) }
        } else {
            return [pscustomobject]@{ Success=$false; Message=("{0} was not installed." -f $label) }
        }
    } catch {
        Write-CoreLog -Message ("Remove app '{0}' failed: {1}" -f $label, $_.Exception.Message) -Level ERROR
        return [pscustomobject]@{ Success=$false; Message=$_.Exception.Message }
    }
}

# ============================================================================
#  STARTUP MANAGER
#  Lists startup items from Run keys + Startup folders with signer/publisher.
#  Enable/disable is reversible (we move the value to a disabled store / rename
#  the shortcut), never a hard delete.
# ============================================================================

function Get-FileSignatureInfo {
    param([string]$Path)
    $res = [pscustomobject]@{ Signed=$false; Publisher='Unknown'; Status='Unknown' }
    if (-not $Path -or -not (Test-Path $Path)) { return $res }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $res.Status = "$($sig.Status)"
        $res.Signed = ($sig.Status -eq 'Valid')
        if ($sig.SignerCertificate) { $res.Publisher = $sig.SignerCertificate.Subject -replace '^CN=([^,]+).*','$1' }
    } catch { }
    return $res
}

function ConvertTo-CommandPath {
    <# Extracts the executable path from a Run-key command string for signing checks.
       Handles: quoted paths, unquoted paths WITH spaces (probes for the real .exe
       by testing successively longer prefixes), and bare paths. #>
    param([string]$Command)
    if (-not $Command) { return $null }
    $c = $Command.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"',1)
        if ($end -gt 1) { return $c.Substring(1,$end-1) }
    }
    # Unquoted. A naive split on the first space breaks "C:\Program Files\App\x.exe".
    # Expand env vars, then walk each space boundary and return the first prefix
    # that is an existing file (optionally with .exe appended).
    $expanded = [Environment]::ExpandEnvironmentVariables($c)
    if ($expanded -notmatch ' ') { return $expanded }
    $idx = 0
    while (($idx = $expanded.IndexOf(' ', $idx)) -ge 0) {
        $candidate = $expanded.Substring(0, $idx)
        if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) { return $candidate }
        if (Test-Path -LiteralPath ($candidate + '.exe') -PathType Leaf -ErrorAction SilentlyContinue) { return ($candidate + '.exe') }
        $idx++
    }
    # No existing-file prefix found; fall back to the first token.
    $space = $expanded.IndexOf(' ')
    if ($space -gt 0) { return $expanded.Substring(0,$space) }
    return $expanded
}

function Get-StartupItems {
    <# Read-only enumeration of startup entries, including items this tool has
       disabled (so they remain visible and can be re-enabled). #>
    $items = New-Object System.Collections.ArrayList
    $runKeys = @(
        @{ Scope='HKLM'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
        @{ Scope='HKLM'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Scope='HKCU'; Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
        @{ Scope='HKCU'; Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Scope='HKLM'; Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' }
    )

    # Helper: read the real registry value KIND so we can preserve REG_EXPAND_SZ.
    $getValueType = {
        param($RegPath, $ValueName)
        try {
            $noDrive = $RegPath -replace '^HK(LM|CU):\\', ''
            $root = if ($RegPath -match '^HKLM:') { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
            $sub = $root.OpenSubKey($noDrive)
            if ($sub) {
                $kind = $sub.GetValueKind($ValueName)
                $sub.Close()
                if ($kind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) { return 'ExpandString' }
            }
        } catch { }
        return 'String'
    }

    foreach ($rk in $runKeys) {
        # Active (enabled) entries
        if (Test-Path $rk.Path) {
            try {
                $props = Get-ItemProperty -Path $rk.Path -ErrorAction Stop
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                    $exe = ConvertTo-CommandPath -Command ([string]$p.Value)
                    $sig = Get-FileSignatureInfo -Path $exe
                    [void]$items.Add([pscustomobject]@{
                        Type='RegistryRun'; Scope=$rk.Scope; Location=$rk.Path; Name=$p.Name
                        Command=[string]$p.Value; ExePath=$exe; Publisher=$sig.Publisher; Signed=$sig.Signed; SignStatus=$sig.Status
                        Enabled=$true; ValueType=(& $getValueType $rk.Path $p.Name)
                    })
                }
            } catch { }
        }
        # Disabled store written by this tool (so disabled items stay visible)
        $disabledPath = ($rk.Path -replace '\\Run(Once)?$', '\RunDisabledByOptimizer')
        if (Test-Path $disabledPath) {
            try {
                $dprops = Get-ItemProperty -Path $disabledPath -ErrorAction Stop
                foreach ($p in $dprops.PSObject.Properties) {
                    if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                    $exe = ConvertTo-CommandPath -Command ([string]$p.Value)
                    $sig = Get-FileSignatureInfo -Path $exe
                    [void]$items.Add([pscustomobject]@{
                        Type='RegistryRun'; Scope=$rk.Scope; Location=$rk.Path; Name=$p.Name
                        Command=[string]$p.Value; ExePath=$exe; Publisher=$sig.Publisher; Signed=$sig.Signed; SignStatus=$sig.Status
                        Enabled=$false; ValueType=(& $getValueType $disabledPath $p.Name)
                    })
                }
            } catch { }
        }
    }
    # Startup folders (.lnk enabled, .lnk.disabled disabled)
    $folders = @(
        @{ Scope='User';   Path=[Environment]::GetFolderPath('Startup') },
        @{ Scope='Common'; Path=[Environment]::GetFolderPath('CommonStartup') }
    )
    foreach ($f in $folders) {
        if (-not $f.Path -or -not (Test-Path $f.Path)) { continue }
        try {
            Get-ChildItem -Path $f.Path -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
                $target = $null
                try { $sh = New-Object -ComObject WScript.Shell; $target = $sh.CreateShortcut($_.FullName).TargetPath } catch { }
                $sig = Get-FileSignatureInfo -Path $target
                [void]$items.Add([pscustomobject]@{
                    Type='StartupFolder'; Scope=$f.Scope; Location=$f.Path; Name=$_.BaseName
                    Command=$target; ExePath=$target; Publisher=$sig.Publisher; Signed=$sig.Signed; SignStatus=$sig.Status
                    Enabled=$true; ValueType='String'
                })
            }
            Get-ChildItem -Path $f.Path -Filter *.lnk.disabled -ErrorAction SilentlyContinue | ForEach-Object {
                $target = $null
                $realLnk = $_.FullName -replace '\.disabled$',''
                try { $sh = New-Object -ComObject WScript.Shell; $target = $sh.CreateShortcut($realLnk).TargetPath } catch { }
                $sig = Get-FileSignatureInfo -Path $target
                $base = ($_.BaseName -replace '\.lnk$','')
                [void]$items.Add([pscustomobject]@{
                    Type='StartupFolder'; Scope=$f.Scope; Location=$f.Path; Name=$base
                    Command=$target; ExePath=$target; Publisher=$sig.Publisher; Signed=$sig.Signed; SignStatus=$sig.Status
                    Enabled=$false; ValueType='String'
                })
            }
        } catch { }
    }
    Write-CoreLog -Message ("Startup scan: {0} item(s)." -f $items.Count) -Level INFO
    return $items.ToArray()
}

function ConvertTo-PsSingleQuoted {
    <# Safely encode an arbitrary string as a PowerShell single-quoted literal.
       Uses the official PowerShell escaper, which (unlike a naive '' doubling)
       also neutralises the Unicode curly single quotes U+2018/U+2019 that the
       parser treats as string delimiters. Verified against ASCII and both curly
       quotes. #>
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return "''" }
    return "'" + [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($Value) + "'"
}

function ConvertTo-SafeComment {
    <# Strip control characters (CR/LF/tabs/etc.) from text embedded into a
       generated-script COMMENT line, so a crafted value/name cannot break out of
       the comment onto a live code line. #>
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    return ($Value -replace '[\x00-\x1F\x7F]', ' ')
}

function Set-StartupItemState {
    <#
      Reversibly disable/enable a startup item.
      For registry Run entries: move the value to a parallel 'AutorunsDisabled'
      store (same technique Sysinternals Autoruns uses) instead of deleting.
      For Startup-folder shortcuts: rename .lnk <-> .lnk.disabled.
      Returns @{Success;Message}.

      SECURITY: every value interpolated into the rollback script is passed through
      ConvertTo-PsSingleQuoted so a malicious Run value (e.g. containing '; cmd; ')
      cannot inject live code into the generated Rollback_*.ps1.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('RegistryRun','StartupFolder')][string]$Type,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Enable,
        [string]$Command,
        [string]$ValueType = 'String'   # preserve REG_EXPAND_SZ when applicable
    )
    try {
        Assert-SafeToChange
        $qLoc  = ConvertTo-PsSingleQuoted $Location
        $qName = ConvertTo-PsSingleQuoted $Name
        if ($Type -eq 'RegistryRun') {
            $disabledPath = ($Location -replace '\\Run(Once)?$', '\RunDisabledByOptimizer')
            $qDis = ConvertTo-PsSingleQuoted $disabledPath
            $propType = if ($ValueType -eq 'ExpandString') { 'ExpandString' } else { 'String' }
            if ($Enable) {
                # move back from disabled store
                $v = Get-RegValue -Path $disabledPath -Name $Name
                if ($v -ne $null) {
                    if (-not (Test-Path $Location)) { New-Item -Path $Location -Force | Out-Null }
                    New-ItemProperty -Path $Location -Name $Name -Value $v -PropertyType $propType -Force | Out-Null
                    Remove-ItemProperty -Path $disabledPath -Name $Name -ErrorAction SilentlyContinue
                }
                Add-ChangeRecord "Re-enabled startup entry '$Name'"
                $qVal = ConvertTo-PsSingleQuoted ([string]$v)
                Add-RollbackCommand ("if (-not (Test-Path $qDis)) { New-Item -Path $qDis -Force | Out-Null }`r`nNew-ItemProperty -Path $qDis -Name $qName -Value $qVal -PropertyType $propType -Force | Out-Null`r`nRemove-ItemProperty -Path $qLoc -Name $qName -ErrorAction SilentlyContinue") "Re-disable startup '$Name'"
            } else {
                $cur = Get-RegValue -Path $Location -Name $Name
                if ($cur -eq $null -and $Command) { $cur = $Command }
                if (-not (Test-Path $disabledPath)) { New-Item -Path $disabledPath -Force | Out-Null }
                New-ItemProperty -Path $disabledPath -Name $Name -Value $cur -PropertyType $propType -Force | Out-Null
                Remove-ItemProperty -Path $Location -Name $Name -ErrorAction SilentlyContinue
                Add-ChangeRecord "Disabled startup entry '$Name'"
                $qVal = ConvertTo-PsSingleQuoted ([string]$cur)
                Add-RollbackCommand ("if (-not (Test-Path $qLoc)) { New-Item -Path $qLoc -Force | Out-Null }`r`nNew-ItemProperty -Path $qLoc -Name $qName -Value $qVal -PropertyType $propType -Force | Out-Null`r`nRemove-ItemProperty -Path $qDis -Name $qName -ErrorAction SilentlyContinue") "Re-enable startup '$Name'"
            }
        } else {
            # StartupFolder
            $lnk = Join-Path $Location ($Name + '.lnk')
            $dis = $lnk + '.disabled'
            $qLnk = ConvertTo-PsSingleQuoted $lnk
            $qDisLnk = ConvertTo-PsSingleQuoted $dis
            $qLnkName = ConvertTo-PsSingleQuoted ($Name + '.lnk')
            $qDisName = ConvertTo-PsSingleQuoted ($Name + '.lnk.disabled')
            if ($Enable) {
                if (Test-Path $dis) { Rename-Item -Path $dis -NewName ($Name + '.lnk') -Force }
                Add-ChangeRecord "Re-enabled startup shortcut '$Name'"
                Add-RollbackCommand ("Rename-Item -Path $qLnk -NewName $qDisName -Force -ErrorAction SilentlyContinue") "Re-disable '$Name'"
            } else {
                if (Test-Path $lnk) { Rename-Item -Path $lnk -NewName ($Name + '.lnk.disabled') -Force }
                Add-ChangeRecord "Disabled startup shortcut '$Name'"
                Add-RollbackCommand ("Rename-Item -Path $qDisLnk -NewName $qLnkName -Force -ErrorAction SilentlyContinue") "Re-enable '$Name'"
            }
        }
        Save-RollbackArtifacts
        return [pscustomobject]@{ Success=$true; Message=$(if($Enable){'Enabled.'}else{'Disabled.'}) }
    } catch {
        Write-CoreLog -Message ("Set-StartupItemState '{0}' failed: {1}" -f $Name, $_.Exception.Message) -Level ERROR
        return [pscustomobject]@{ Success=$false; Message=$_.Exception.Message }
    }
}


# ============================================================================
#  DFIR / COMPROMISE TRIAGE ENGINE  (100% read-only)
#  Designed for a non-expert: each finding has a Severity, a plain-English
#  explanation, and a "WhatToDo". Returns an array of finding objects.
# ============================================================================

function New-DfirFinding {
    param(
        [string]$Id, [string]$Category, [string]$Title,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [ValidateSet('Alert','Review','Clean','Info')][string]$Status,
        [string]$What, [string]$Why, [string]$WhatToDo, $Evidence
    )
    [pscustomobject]@{
        Id=$Id; Category=$Category; Title=$Title; Severity=$Severity; Status=$Status
        What=$What; Why=$Why; WhatToDo=$WhatToDo; Evidence=$Evidence
    }
}

function Invoke-DfirTriage {
    <# Runs the full compromise-triage sweep. Read-only. #>
    $f = New-Object System.Collections.ArrayList
    $add = { param($x) [void]$f.Add($x) }

    # ---------- 1. Local administrators ----------
    try {
        $adminMembers = @()
        try {
            $grp = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
            $adminMembers = $grp | ForEach-Object { $_.Name }
        } catch {
            # Fallback via net localgroup for odd SID/translation cases
            $raw = (net localgroup administrators) 2>$null
            if ($raw) {
                $capture=$false
                foreach ($line in $raw) {
                    if ($line -match '^----') { $capture=$true; continue }
                    if ($line -match 'completed successfully') { $capture=$false; continue }
                    if ($capture -and $line.Trim()) { $adminMembers += $line.Trim() }
                }
            }
        }
        $adminMembers = @($adminMembers | Where-Object { $_ } | Select-Object -Unique)
        # Known/expected: current user, built-in Administrator, Domain Admins
        $expectedPatterns = @('*\Administrator', 'Administrator', "*\$env:USERNAME", $env:USERNAME, '*\Domain Admins', '*\Enterprise Admins')
        $unexpected = @()
        foreach ($m in $adminMembers) {
            $isExpected = $false
            foreach ($pat in $expectedPatterns) { if ($m -like $pat) { $isExpected=$true; break } }
            if (-not $isExpected) { $unexpected += $m }
        }
        $unexpected = @($unexpected)
        $evidence = ($adminMembers -join "`n")
        if ($unexpected.Count -gt 0) {
            & $add (New-DfirFinding -Id 'DFIR-ADMIN' -Category 'Accounts & Access' -Title 'Extra accounts in the Administrators group' -Severity 'High' -Status 'Review' `
                -What ("These accounts have full administrator rights on this PC:`n  " + ($adminMembers -join "`n  ")) `
                -Why 'Attackers add a hidden admin account to keep control. Any account here can change anything, install software, and read all files.' `
                -WhatToDo ("Confirm you recognise every account above. If one is unfamiliar (especially these: " + ($unexpected -join ', ') + "), it may have been added without your knowledge. Investigate before removing. Remove with: Remove-LocalGroupMember -Group Administrators -Member '<name>'.") `
                -Evidence $evidence)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-ADMIN' -Category 'Accounts & Access' -Title 'Administrators group looks normal' -Severity 'Info' -Status 'Clean' `
                -What ("Administrator accounts:`n  " + ($adminMembers -join "`n  ")) -Why 'Only expected accounts have admin rights.' -WhatToDo 'No action needed. Still worth a glance to confirm you recognise them.' -Evidence $evidence)
        }
    } catch { & $add (New-DfirFinding -Id 'DFIR-ADMIN' -Category 'Accounts & Access' -Title 'Could not read Administrators group' -Severity 'Info' -Status 'Info' -What $_.Exception.Message -Why '' -WhatToDo 'Run the tool as Administrator for a complete check.' -Evidence '') }

    # ---------- 2. Enabled local user accounts + hidden ($-suffixed) ----------
    try {
        $users = @(Get-LocalUser -ErrorAction Stop)
        $enabled = @($users | Where-Object { $_.Enabled })
        $hidden  = @($users | Where-Object { $_.Name -like '*$' })   # trailing-$ hides from logon UI
        $lines = @($enabled | ForEach-Object { "  {0}{1}  (last logon: {2})" -f $_.Name, $(if($_.Name -like '*$'){' [HIDDEN]'}else{''}), $(if($_.LastLogon){$_.LastLogon}else{'never'}) })
        if ($hidden.Count -gt 0) {
            & $add (New-DfirFinding -Id 'DFIR-HIDDENUSER' -Category 'Accounts & Access' -Title 'Hidden user account(s) detected' -Severity 'High' -Status 'Alert' `
                -What ("Account name(s) ending in '$' are hidden from the sign-in screen:`n  " + (@($hidden|ForEach-Object{$_.Name}) -join "`n  ")) `
                -Why 'A trailing "$" hides an account from the normal logon screen. Legitimate for some service accounts, but also a classic backdoor trick.' `
                -WhatToDo 'If you did not create these, treat as suspicious. Check whether they are in the Administrators group above and investigate.' -Evidence (@($hidden|ForEach-Object{$_.Name}) -join "`n"))
        }
        & $add (New-DfirFinding -Id 'DFIR-USERS' -Category 'Accounts & Access' -Title ("Enabled local accounts: {0}" -f $enabled.Count) -Severity 'Info' -Status 'Info' `
            -What ("Currently enabled local accounts:`n" + ($lines -join "`n")) -Why 'Disabled or unknown accounts that are enabled can be a sign of tampering.' -WhatToDo 'Disable any local account you do not use: Disable-LocalUser -Name "<name>".' -Evidence ($lines -join "`n"))
    } catch { & $add (New-DfirFinding -Id 'DFIR-USERS-ERR' -Category 'Accounts & Access' -Title 'Could not read local accounts' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator.' -Evidence '') }

    # ---------- 3. Startup persistence: Run keys ----------
    try {
        $startup = @(Get-StartupItems)
        # High-confidence: unsigned AND launching from a user/temp folder, or from
        # an outright suspicious location (Temp/Downloads/Public). An unsigned app
        # in a normal install path (Program Files) is NOT flagged here to avoid
        # drowning the user in false positives (many legit apps are unsigned).
        $tempRe = '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\\$Recycle'
        $userRe = '\\AppData\\|\\ProgramData\\'
        $suspicious = @($startup | Where-Object {
            $_.ExePath -and (
                ($_.ExePath -match $tempRe) -or
                (($_.ExePath -match $userRe) -and (-not $_.Signed))
            )
        })
        if ($suspicious.Count -gt 0) {
            $ev = (@($suspicious | ForEach-Object { "  [{0}] {1} -> {2}  (signed: {3})" -f $_.Type, $_.Name, $_.Command, $_.Signed })) -join "`n"
            & $add (New-DfirFinding -Id 'DFIR-STARTUP' -Category 'Startup Persistence' -Title ("Startup entries worth reviewing: {0}" -f $suspicious.Count) -Severity 'Medium' -Status 'Review' `
                -What ("These programs run at startup from a temporary/user folder (unsigned ones in AppData are included):`n" + $ev) `
                -Why 'Malware persists by auto-starting from Temp/AppData. Note that some legitimate apps (OneDrive, Teams, Zoom, Discord) also start from AppData - so this is a review list, not a verdict.' `
                -WhatToDo 'Recognise each one? Then it is fine. If you do not, disable it in the Startup tab (reversible) and scan the file with Defender.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-STARTUP' -Category 'Startup Persistence' -Title 'No obviously suspicious startup entries' -Severity 'Info' -Status 'Clean' -What 'No startup entries run unsigned from temp/user folders.' -Why '' -WhatToDo 'No action needed. See the Startup tab for the full list.' -Evidence '')
        }
    } catch { & $add (New-DfirFinding -Id 'DFIR-STARTUP-ERR' -Category 'Startup Persistence' -Title 'Startup check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Note it as a tool issue if it persists.' -Evidence '') }

    # ---------- 4. Scheduled tasks running from odd locations ----------
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        $flagged = New-Object System.Collections.ArrayList
        foreach ($t in $tasks) {
            foreach ($act in @($t.Actions)) {
                $exe = $null
                try { $exe = $act.Execute } catch { }
                if ($exe -and ($exe -match 'Temp|AppData|ProgramData|Public|\\Downloads|powershell|cmd\.exe|mshta|wscript|cscript|rundll32' )) {
                    [void]$flagged.Add(("  {0}  ->  {1} {2}" -f $t.TaskName, $exe, $(try{$act.Arguments}catch{''})))
                }
            }
        }
        $flagged = @($flagged)
        if ($flagged.Count -gt 0) {
            $ev = ($flagged -join "`n")
            & $add (New-DfirFinding -Id 'DFIR-TASKS' -Category 'Startup Persistence' -Title ("Scheduled tasks worth reviewing: {0}" -f $flagged.Count) -Severity 'Medium' -Status 'Review' `
                -What ("These scheduled tasks launch scripts/interpreters or run from user/temp folders:`n" + $ev) `
                -Why 'Scheduled tasks are a common persistence method. Tasks that run PowerShell/mshta/rundll32 or execute from Temp/AppData deserve a look.' `
                -WhatToDo 'Open Task Scheduler and inspect each. Many are legitimate (updaters). Disable/delete only those you can confirm are malicious.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-TASKS' -Category 'Startup Persistence' -Title 'No scheduled tasks flagged' -Severity 'Info' -Status 'Clean' -What 'No scheduled tasks matched suspicious patterns.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch { & $add (New-DfirFinding -Id 'DFIR-TASKS-ERR' -Category 'Startup Persistence' -Title 'Scheduled-task check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator.' -Evidence '') }

    # ---------- 5. Non-Microsoft running services with unsigned/odd binaries ----------
    try {
        $svcs = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.State -eq 'Running' -and $_.PathName })
        $flagged = New-Object System.Collections.ArrayList
        foreach ($s in $svcs) {
            $exe = ConvertTo-CommandPath -Command ($s.PathName -replace '^"','' )
            if ($exe -match 'Temp|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\') {
                [void]$flagged.Add(("  {0}  ->  {1}" -f $s.Name, $s.PathName))
            }
        }
        $flagged = @($flagged)
        if ($flagged.Count -gt 0) {
            $ev = ($flagged -join "`n")
            & $add (New-DfirFinding -Id 'DFIR-SVC' -Category 'Startup Persistence' -Title ("Services running from user/temp folders: {0}" -f $flagged.Count) -Severity 'High' -Status 'Review' `
                -What ("Running services whose program lives in a temporary/user folder:`n" + $ev) `
                -Why 'Legitimate services run from Program Files or System32. A service pointing into Temp/AppData is a strong malware indicator.' `
                -WhatToDo 'Investigate each service name online. Do not stop critical services blindly; confirm first.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-SVC' -Category 'Startup Persistence' -Title 'No services from suspicious paths' -Severity 'Info' -Status 'Clean' -What 'All running services launch from standard locations.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch { & $add (New-DfirFinding -Id 'DFIR-SVC-ERR' -Category 'Startup Persistence' -Title 'Service check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator.' -Evidence '') }

    # ---------- 6. Remote access exposure: RDP ----------
    try {
        $deny = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
        $rdpOn = ($deny -eq 0)
        if ($rdpOn) {
            & $add (New-DfirFinding -Id 'DFIR-RDP' -Category 'Remote Access' -Title 'Remote Desktop (RDP) is enabled' -Severity 'Medium' -Status 'Review' `
                -What 'This PC accepts incoming Remote Desktop connections.' `
                -Why 'If you did not enable RDP, an attacker may have. Exposed RDP is a top ransomware entry point.' `
                -WhatToDo 'If you never remote into this PC, disable RDP (Security/Remote Access fix). If you do use it, ensure NLA is on and the account has a strong password.' -Evidence "fDenyTSConnections=$deny")
        } else {
            & $add (New-DfirFinding -Id 'DFIR-RDP' -Category 'Remote Access' -Title 'Remote Desktop is disabled' -Severity 'Info' -Status 'Clean' -What 'RDP listener is off.' -Why '' -WhatToDo 'No action needed.' -Evidence "fDenyTSConnections=$deny")
        }
    } catch { & $add (New-DfirFinding -Id 'DFIR-RDP-ERR' -Category 'Remote Access' -Title 'RDP check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Note it as a tool issue if it persists.' -Evidence '') }

    # ---------- 7. Listening TCP ports (exposure surface) ----------
    # 135 (RPC) and 445 (SMB) listen on essentially every Windows PC, so they are
    # NOT treated as notable on their own - only genuinely remote-access-y ports
    # (RDP/VNC/Telnet/FTP/WinRM) are surfaced as review items.
    try {
        $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $rows = New-Object System.Collections.ArrayList
        $notableRows = New-Object System.Collections.ArrayList
        $riskyPorts   = @{ 3389='RDP'; 5900='VNC'; 23='Telnet'; 21='FTP'; 5985='WinRM-HTTP'; 5986='WinRM-HTTPS' }
        $expectedPorts = @{ 445='SMB (normal on Windows)'; 135='RPC (normal on Windows)' }
        foreach ($conn in $listen) {
            $proc = $null; try { $proc = (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).ProcessName } catch { }
            $port = [int]$conn.LocalPort
            # Only surface listeners reachable from off-box (not loopback).
            if ($conn.LocalAddress -notmatch '^(127\.|::1$)') {
                $label = if ($riskyPorts.ContainsKey($port)) { " <- $($riskyPorts[$port])" }
                         elseif ($expectedPorts.ContainsKey($port)) { " ($($expectedPorts[$port]))" } else { '' }
                $line = "  {0}:{1}  ({2}){3}" -f $conn.LocalAddress, $port, $(if($proc){$proc}else{"PID $($conn.OwningProcess)"}), $label
                [void]$rows.Add($line)
                if ($riskyPorts.ContainsKey($port)) { [void]$notableRows.Add($line) }
            }
        }
        $uniq = @($rows.ToArray() | Select-Object -Unique)
        $risky = @($notableRows.ToArray() | Select-Object -Unique)
        if ($risky.Count -gt 0) {
            & $add (New-DfirFinding -Id 'DFIR-PORTS' -Category 'Network Exposure' -Title ("Remote-access ports listening: {0}" -f $risky.Count) -Severity 'Medium' -Status 'Review' `
                -What ("These remote-access ports are open to other machines:`n" + ($risky -join "`n") + "`n`nAll network-facing listeners:`n" + ($uniq -join "`n")) `
                -Why 'Remote-access ports (RDP/VNC/Telnet/FTP/WinRM) expand your attack surface. (Ports 135/445 always listen on Windows and are not flagged.)' `
                -WhatToDo 'Identify the program behind each remote-access port. Close/firewall anything you do not need listening to the network.' -Evidence ($uniq -join "`n"))
        } else {
            & $add (New-DfirFinding -Id 'DFIR-PORTS' -Category 'Network Exposure' -Title 'No high-risk remote-access ports exposed' -Severity 'Info' -Status 'Clean' -What (("Network-facing listeners (135/445 are normal on Windows):`n" + ($uniq -join "`n")).Trim()) -Why '' -WhatToDo 'No action needed.' -Evidence ($uniq -join "`n"))
        }
    } catch { & $add (New-DfirFinding -Id 'DFIR-PORTS-ERR' -Category 'Network Exposure' -Title 'Port check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Note it as a tool issue if it persists.' -Evidence '') }

    # ---------- 8. Non-default SMB shares ----------
    try {
        $shares = @(Get-SmbShare -ErrorAction Stop)
        $default = @('ADMIN$','C$','D$','E$','F$','IPC$','print$')
        $custom = @($shares | Where-Object { $default -notcontains $_.Name })
        if ($custom.Count -gt 0) {
            $ev = (@($custom | ForEach-Object { "  {0}  ->  {1}" -f $_.Name, $_.Path })) -join "`n"
            & $add (New-DfirFinding -Id 'DFIR-SMB' -Category 'Network Exposure' -Title ("Custom file shares: {0}" -f $custom.Count) -Severity 'Medium' -Status 'Review' `
                -What ("Folders shared on the network:`n" + $ev) `
                -Why 'Shared folders let other machines read/write files. A share you did not create can mean data exposure or an attacker foothold.' `
                -WhatToDo 'Remove shares you do not recognise: Remove-SmbShare -Name "<name>". Confirm first.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-SMB' -Category 'Network Exposure' -Title 'Only default administrative shares present' -Severity 'Info' -Status 'Clean' -What 'No custom network shares found.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch { & $add (New-DfirFinding -Id 'DFIR-SMB-ERR' -Category 'Network Exposure' -Title 'Share check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator.' -Evidence '') }

    # ---------- 9. Defender exclusions (classic attacker move) ----------
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $exPath = @($pref.ExclusionPath | Where-Object { $_ })
        $exProc = @($pref.ExclusionProcess | Where-Object { $_ })
        $exExt  = @($pref.ExclusionExtension | Where-Object { $_ })
        $total = $exPath.Count + $exProc.Count + $exExt.Count
        if ($total -gt 0) {
            $parts = @()
            if ($exPath.Count) { $parts += ("Paths:`n  "      + ($exPath -join "`n  ")) }
            if ($exProc.Count) { $parts += ("Processes:`n  "  + ($exProc -join "`n  ")) }
            if ($exExt.Count)  { $parts += ("Extensions:`n  " + ($exExt  -join "`n  ")) }
            $evStr = ($parts -join "`n")
            & $add (New-DfirFinding -Id 'DFIR-DEFEXCL' -Category 'Tampering Indicators' -Title ("Microsoft Defender has {0} exclusion(s)" -f $total) -Severity 'High' -Status 'Review' `
                -What ("Defender is told to SKIP scanning these:`n" + $evStr) `
                -Why 'Attackers add Defender exclusions so their malware is never scanned. Exclusions you did not set are a red flag.' `
                -WhatToDo 'Review each. Remove any you do not recognise in Windows Security > Virus & threat protection > Exclusions.' -Evidence $evStr)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-DEFEXCL' -Category 'Tampering Indicators' -Title 'No Defender exclusions set' -Severity 'Info' -Status 'Clean' -What 'Defender is scanning everything (no exclusions).' -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch {
        & $add (New-DfirFinding -Id 'DFIR-DEFEXCL' -Category 'Tampering Indicators' -Title 'Could not read Defender exclusions' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'Reading Defender preferences can require elevation or Defender may be managed by third-party AV.' -WhatToDo 'Run as Administrator for this check.' -Evidence '')
    }

    # ---------- 10. Hosts file tampering ----------
    try {
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if (Test-Path $hostsPath) {
            $lines = @(Get-Content $hostsPath -ErrorAction Stop)
            $entries = @($lines | Where-Object { $_ -and ($_ -notmatch '^\s*#') -and ($_ -match '\S') })
            # A redirect is only sketchy if it points a sensitive domain to a NON-blackhole
            # IP. Blocklists that send domains to 0.0.0.0 / 127.0.0.1 are benign (ad/
            # telemetry blockers) and must not raise an Alert.
            $sketchy = @($entries | Where-Object {
                ($_ -match 'microsoft|windowsupdate|defender|google|bank|antivirus|mcafee|norton|update') -and
                ($_ -notmatch '^\s*(0\.0\.0\.0|127\.0\.0\.1|::1)\s')
            })
            $blackholed = @($entries | Where-Object { $_ -match '^\s*(0\.0\.0\.0|127\.0\.0\.1|::1)\s' })
            if ($sketchy.Count -gt 0) {
                $ev = ($sketchy -join "`n")
                & $add (New-DfirFinding -Id 'DFIR-HOSTS' -Category 'Tampering Indicators' -Title 'Hosts file redirects security/update domains' -Severity 'High' -Status 'Alert' `
                    -What ("The hosts file redirects well-known domains to a specific server (not a blackhole):`n" + $ev) `
                    -Why 'Malware edits the hosts file to redirect banking/search/update sites to fake servers. (Entries that merely block domains via 0.0.0.0/127.0.0.1 are treated as benign ad-blockers.)' `
                    -WhatToDo ("Review these lines. Unless you added them deliberately, remove them (edit as admin). The file is at " + $hostsPath + ".") -Evidence $ev)
            } elseif ($entries.Count -gt 0) {
                $note = if ($blackholed.Count -gt 0) { " ($($blackholed.Count) look like ad/telemetry blocking via 0.0.0.0/127.0.0.1 - usually benign)" } else { '' }
                & $add (New-DfirFinding -Id 'DFIR-HOSTS' -Category 'Tampering Indicators' -Title ("Hosts file has {0} custom entr(y/ies){1}" -f $entries.Count, $note) -Severity 'Low' -Status 'Review' `
                    -What ("Active hosts-file entries:`n  " + ($entries -join "`n  ")) -Why 'Custom hosts entries can be legitimate (dev work, ad-blocking) or malicious.' -WhatToDo 'Confirm you recognise these mappings.' -Evidence ($entries -join "`n"))
            } else {
                & $add (New-DfirFinding -Id 'DFIR-HOSTS' -Category 'Tampering Indicators' -Title 'Hosts file is clean' -Severity 'Info' -Status 'Clean' -What 'No custom hosts entries.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
            }
        }
    } catch { & $add (New-DfirFinding -Id 'DFIR-HOSTS-ERR' -Category 'Tampering Indicators' -Title 'Hosts-file check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Note it as a tool issue if it persists.' -Evidence '') }

    Write-CoreLog -Message ("DFIR triage complete: {0} finding(s)." -f $f.Count) -Level INFO
    return $f.ToArray()
}

function Get-DfirSummary {
    param($Findings)
    [pscustomobject]@{
        Alerts  = @($Findings | Where-Object { $_.Status -eq 'Alert' }).Count
        Reviews = @($Findings | Where-Object { $_.Status -eq 'Review' }).Count
        Clean   = @($Findings | Where-Object { $_.Status -eq 'Clean' }).Count
        Total   = @($Findings).Count
    }
}


# ============================================================================
#  DEEP SCAN ENGINE  (read-only)  --  native process + event-log threat hunt
#  Inspired by what DFIR tools (Hayabusa/Chainsaw/THOR) look for, but written
#  from scratch (MIT, no bundled GPL/commercial code) and explained in plain
#  English. Returns the same finding shape as Invoke-DfirTriage so it plugs
#  straight into the Investigate view.
# ============================================================================

# Canonical Windows system processes and the ONLY folder they should run from.
# A process using one of these names from anywhere else is a classic
# masquerading trick (e.g. a "svchost.exe" sitting in your Downloads folder).
$script:SystemProcMap = @{
    'svchost'      = 'System32'
    'lsass'        = 'System32'
    'services'     = 'System32'
    'winlogon'     = 'System32'
    'csrss'        = 'System32'
    'smss'         = 'System32'
    'wininit'      = 'System32'
    'spoolsv'      = 'System32'
    'taskhostw'    = 'System32'
    'dllhost'      = 'System32'
    'conhost'      = 'System32'
    'lsaiso'       = 'System32'
    'fontdrvhost'  = 'System32'
    'sihost'       = 'System32'
    'RuntimeBroker'= 'System32'
    'SearchIndexer'= 'System32'
    'explorer'     = 'Windows'   # explorer lives in %SystemRoot% itself
}

# Names that LOOK like system processes but are not real ones = near-certain malware.
$script:LookalikeNames = @(
    'scvhost','svch0st','svchoct','svhost','lsas','1sass','lsasss','csrsss',
    'crss','winlogin','winlogon0','servlces','servces','explorerr','rundl132','rundII32'
)

function Get-ProcPathExpected {
    param([string]$BaseName)
    $dir = $script:SystemProcMap[$BaseName]
    if (-not $dir) { return $null }
    if ($dir -eq 'Windows') { return @($env:SystemRoot) }
    # System32 processes may also legitimately appear in SysWOW64
    return @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'))
}

function Invoke-ProcessThreatScan {
    <#
      Hunts running processes for malware indicators. Read-only.
      Looks for:
        * Masquerading (system name, wrong folder; or near-miss names)
        * Execution from Temp/AppData/ProgramData/Public/Downloads
        * Unsigned binaries that currently hold network connections
        * Suspicious command lines (encoded PowerShell, download cradles, LOLBins)
    #>
    $f = New-Object System.Collections.ArrayList
    $add = { param($x) [void]$f.Add($x) }

    # One CIM call gets path + command line + parent for every process.
    $procs = @()
    try { $procs = Get-CimInstance Win32_Process -ErrorAction Stop } catch {
        & $add (New-DfirFinding -Id 'DEEP-PROC-ERR' -Category 'Running Processes' -Title 'Could not read process list' -Severity 'Info' -Status 'Info' -What $_.Exception.Message -Why '' -WhatToDo 'Run the tool as Administrator for the full process scan.' -Evidence '')
        return $f.ToArray()
    }

    # Map PIDs that currently have network activity (established or listening, non-loopback).
    $netPids = @{}
    try {
        Get-NetTCPConnection -ErrorAction Stop | Where-Object {
            ($_.State -eq 'Established' -or $_.State -eq 'Listen') -and ($_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|::)$' -or $_.State -eq 'Established')
        } | ForEach-Object { $netPids[[int]$_.OwningProcess] = $true }
    } catch { }

    # Signature cache keyed by exe path (signing checks are the slow part).
    $sigCache = @{}
    $getSig = {
        param($path)
        if (-not $path) { return $null }
        if ($sigCache.ContainsKey($path)) { return $sigCache[$path] }
        $s = Get-FileSignatureInfo -Path $path
        $sigCache[$path] = $s
        return $s
    }

    $masq = New-Object System.Collections.ArrayList
    $badPath = New-Object System.Collections.ArrayList
    $unsignedNet = New-Object System.Collections.ArrayList
    $unsignedNetInstalled = New-Object System.Collections.ArrayList
    $badCmd = New-Object System.Collections.ArrayList
    $script:_cmdHasAlert = $false

    foreach ($p in $procs) {
        $name = $null; $exe = $null; $cmd = $null; $procId = $null
        try { $name = $p.Name } catch { }
        try { $exe = $p.ExecutablePath } catch { }
        try { $cmd = $p.CommandLine } catch { }
        try { $procId = [int]$p.ProcessId } catch { }
        if (-not $name) { continue }
        $base = [System.IO.Path]::GetFileNameWithoutExtension($name)

        # ---- 1. Masquerading as a system process ----
        if ($script:SystemProcMap.ContainsKey($base)) {
            $expected = Get-ProcPathExpected -BaseName $base
            if ($exe -and $expected) {
                $exeDir = [System.IO.Path]::GetDirectoryName($exe)
                $okDir = $false
                foreach ($d in $expected) { if ($exeDir -and $exeDir.TrimEnd('\') -ieq $d.TrimEnd('\')) { $okDir = $true; break } }
                if (-not $okDir) {
                    [void]$masq.Add(("  {0} (PID {1}) runs from: {2}  [should be in {3}]" -f $name, $procId, $exe, ($expected -join ' or ')))
                }
            }
        }
        # Near-miss lookalike names (scvhost, lsas, etc.)
        if ($script:LookalikeNames -contains $base.ToLower()) {
            [void]$masq.Add(("  {0} (PID {1}) at {2}  [name imitates a Windows process]" -f $name, $procId, $(if($exe){$exe}else{'unknown path'})))
        }

        # ---- 2. Running from a user/temp folder ----
        # Tier by signature the SAME way the startup check does, so we don't
        # blanket-flag every AppData process as High (OneDrive/Teams/Zoom/Discord
        # legitimately run signed from AppData). Temp/Downloads/Public/$Recycle are
        # always suspicious; AppData/ProgramData only when UNSIGNED.
        if ($exe) {
            $tempLoc = ($exe -match '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\\$Recycle')
            $userLoc = ($exe -match '\\AppData\\|\\ProgramData\\')
            if ($tempLoc -or $userLoc) {
                $sig = & $getSig $exe
                $isSigned = ($sig -and $sig.Signed)
                $signText = if ($isSigned) { "signed: $($sig.Publisher)" } else { 'UNSIGNED' }
                if ($tempLoc -or (-not $isSigned)) {
                    [void]$badPath.Add(("  {0} (PID {1}) -> {2}  ({3})" -f $name, $procId, $exe, $signText))
                }
            }
        }

        # ---- 3. Unsigned binary with live network connection ----
        # Tiered to avoid false alarms: an unsigned app in Program Files is common
        # (lots of legit open-source/indie software). The strong signal is an
        # unsigned networked binary running from a user-writable/temp location.
        if ($procId -ne $null -and $netPids.ContainsKey($procId) -and $exe) {
            $sig = & $getSig $exe
            if ($sig -and -not $sig.Signed -and $exe -notmatch '\\System32\\|\\SysWOW64\\') {
                if ($exe -match '\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\|\\\$Recycle') {
                    [void]$unsignedNet.Add(("  {0} (PID {1}) -> {2}  [unsigned + network, from a user/temp folder]" -f $name, $procId, $exe))
                } else {
                    [void]$unsignedNetInstalled.Add(("  {0} (PID {1}) -> {2}" -f $name, $procId, $exe))
                }
            }
        }

        # ---- 4. Suspicious command line ----
        if ($cmd) {
            $hit = $null; $hitSev = 'Review'
            switch -regex ($cmd) {
                '(?i)vssadmin.*delete\s+shadows'               { $hit = 'deleting Volume Shadow Copies (classic RANSOMWARE behavior!)'; $hitSev='Alert'; break }
                '(?i)\bwbadmin\b.*delete'                      { $hit = 'deleting Windows backups (classic RANSOMWARE behavior!)'; $hitSev='Alert'; break }
                '(?i)\bwmic\b.*shadowcopy\s+delete'            { $hit = 'deleting shadow copies via WMIC (classic RANSOMWARE behavior!)'; $hitSev='Alert'; break }
                '(?i)(IEX|Invoke-Expression)\b.*(DownloadString|DownloadData|Net\.WebClient|Invoke-WebRequest|iwr|curl|wget)' { $hit = 'download-and-execute cradle (fileless malware pattern)'; $hitSev='Alert'; break }
                '(?i)(DownloadString|DownloadData|Net\.WebClient|Invoke-WebRequest|iwr|curl|wget).*\|\s*(IEX|Invoke-Expression|iex)' { $hit = 'download piped into execution (fileless malware pattern)'; $hitSev='Alert'; break }
                '(?i)\b(mshta|regsvr32|rundll32)\b.*(http|\\\\|scrobj|javascript:)' { $hit = 'system tool loading remote/script content (LOLBin abuse)'; $hitSev='Alert'; break }
                '(?i)\b(certutil)\b.*(-urlcache|-decode|-f\s)'  { $hit = 'certutil used to download/decode a file (common malware trick)'; $hitSev='Review'; break }
                '(?i)\b(bitsadmin)\b.*(/transfer|/create)'      { $hit = 'bitsadmin used to fetch files from the internet'; $hitSev='Review'; break }
                '(?i)FromBase64String'                        { $hit = 'base64-decoded payload in the command line'; $hitSev='Review'; break }
                # PowerShell -EncodedCommand and its short forms (-e, -en, -ec, -enc...).
                # -e/-ec also need to not match -ExecutionPolicy/-Command, so require base64-ish tail.
                '(?i)(?:^|\s)-e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}' { $hit = 'encoded PowerShell command (-EncodedCommand / -e / -ec / -en) - note: also used by some LEGITIMATE management tools'; $hitSev='Review'; break }
                '(?i)-w(indowstyle)?\s+hidden'                { $hit = 'runs with a hidden window (used by malware, but also by some legit launchers)'; $hitSev='Review'; break }
                default { $hit = $null }
            }
            if ($hit) {
                $trim = if ($cmd.Length -gt 180) { $cmd.Substring(0,180) + '...' } else { $cmd }
                [void]$badCmd.Add(("  [{0}] {1} (PID {2}): {3}`n      cmd: {4}" -f $hitSev.ToUpper(), $name, $procId, $hit, $trim))
                if ($hitSev -eq 'Alert') { $script:_cmdHasAlert = $true }
            }
        }
    }

    # ---- Emit findings ----
    if ($masq.Count -gt 0) {
        $ev = ($masq.ToArray() | Select-Object -Unique) -join "`n"
        & $add (New-DfirFinding -Id 'DEEP-MASQ' -Category 'Running Processes' -Title ("Process masquerading as Windows: {0}" -f @($masq).Count) -Severity 'Critical' -Status 'Alert' `
            -What ("These running programs use a Windows system name but are NOT in the right place (or imitate a system name):`n" + $ev) `
            -Why 'Real Windows processes like svchost.exe/lsass.exe only run from the System32 folder. Malware copies these trusted names to hide. This is one of the strongest signs of infection.' `
            -WhatToDo 'Do not ignore this. Note the PID and path, scan the file with Defender (right-click > Scan), and search the exact path online. If confirmed malicious, end the process and remove the file.' -Evidence $ev)
    } else {
        & $add (New-DfirFinding -Id 'DEEP-MASQ' -Category 'Running Processes' -Title 'No process masquerading detected' -Severity 'Info' -Status 'Clean' -What 'All system-named processes run from their correct Windows folders.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
    }

    if ($badPath.Count -gt 0) {
        $ev = ($badPath.ToArray() | Select-Object -Unique) -join "`n"
        & $add (New-DfirFinding -Id 'DEEP-PROCPATH' -Category 'Running Processes' -Title ("Programs running from temporary/user folders: {0}" -f @($badPath).Count) -Severity 'High' -Status 'Review' `
            -What ("These programs are running from folders malware often hides in (Temp, Downloads, Public, or UNSIGNED from AppData/ProgramData). Signed programs in AppData/ProgramData - like OneDrive/Teams/Zoom - are deliberately excluded:`n" + $ev) `
            -Why 'Legitimate software usually runs from Program Files. Things running from Temp/Downloads, or UNSIGNED from AppData, are more suspicious.' `
            -WhatToDo 'Look at each. Installers and some updaters are normal here. Anything UNSIGNED that you do not recognise should be scanned with Defender and investigated.' -Evidence $ev)
    }

    if ($unsignedNet.Count -gt 0) {
        $ev = ($unsignedNet.ToArray() | Select-Object -Unique) -join "`n"
        & $add (New-DfirFinding -Id 'DEEP-UNSIGNEDNET' -Category 'Running Processes' -Title ("Unsigned networked programs in user/temp folders: {0}" -f @($unsignedNet).Count) -Severity 'High' -Status 'Review' `
            -What ("These programs have NO digital signature, are using the network, AND run from a user-writable/temp folder:`n" + $ev) `
            -Why 'That combination - unsigned + networked + running from Temp/AppData/Downloads - is a strong malware indicator. Trusted software is signed and installed under Program Files.' `
            -WhatToDo 'Identify each program. If you do not recognise it, disconnect from the internet, scan with Defender, and investigate the file path before allowing it.' -Evidence $ev)
    }

    if ($unsignedNetInstalled.Count -gt 0) {
        $ev = ($unsignedNetInstalled.ToArray() | Select-Object -Unique) -join "`n"
        & $add (New-DfirFinding -Id 'DEEP-UNSIGNEDNET-INST' -Category 'Running Processes' -Title ("Installed unsigned apps using the network: {0}" -f @($unsignedNetInstalled).Count) -Severity 'Low' -Status 'Review' `
            -What ("These installed programs have no digital signature but are using the network:`n" + $ev) `
            -Why 'Many legitimate open-source and indie apps are unsigned (code-signing certificates cost money). This is usually fine - it is listed only so you can confirm you recognise each one.' `
            -WhatToDo 'If you installed and trust these, no action is needed. Investigate only ones you do not recognise.' -Evidence $ev)
    }

    if ($badCmd.Count -gt 0) {
        $ev = ($badCmd.ToArray() | Select-Object -Unique) -join "`n"
        $cmdStatus = if ($script:_cmdHasAlert) { 'Alert' } else { 'Review' }
        $cmdSev    = if ($script:_cmdHasAlert) { 'Critical' } else { 'Medium' }
        & $add (New-DfirFinding -Id 'DEEP-CMDLINE' -Category 'Running Processes' -Title ("Command lines worth reviewing: {0}" -f @($badCmd).Count) -Severity $cmdSev -Status $cmdStatus `
            -What ("These running programs used command lines that match attacker techniques. Each line is tagged [ALERT] (high-confidence) or [REVIEW] (also used by legitimate software):`n" + $ev) `
            -Why 'Techniques like deleting shadow copies/backups or download-and-run one-liners are hallmark attacker/ransomware behavior. Encoded PowerShell and hidden windows are weaker signals - many legitimate management tools use them too.' `
            -WhatToDo 'Focus on [ALERT] items first. If you see "deleting shadow copies/backups", disconnect from the network immediately (possible ransomware) and seek help. For [REVIEW] items, confirm they belong to software you trust.' -Evidence $ev)
    } else {
        & $add (New-DfirFinding -Id 'DEEP-CMDLINE' -Category 'Running Processes' -Title 'No suspicious command lines found' -Severity 'Info' -Status 'Clean' -What 'No running process matched known attack command-line patterns.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
    }

    Write-CoreLog -Message ("Process threat scan: {0} finding(s)." -f $f.Count) -Level INFO
    return $f.ToArray()
}

function Get-ServiceInstallEventFields {
    <# Extract the STRUCTURED fields of a 7045 "service installed" event from its
       event XML, not from the localized message text. The <EventData> carries
       named <Data> elements (ServiceName, ImagePath, ServiceType, StartType,
       AccountName) that are the same regardless of OS display language, so a
       filter built on them cannot be dodged by naming a service after a trusted
       product. Falls back to positional Properties if the XML can't be read. #>
    param($Event)
    $out = [pscustomobject]@{ ServiceName=''; ImagePath=''; ServiceType=''; StartType=''; AccountName='' }
    if (-not $Event) { return $out }
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            switch ($d.Name) {
                'ServiceName' { $out.ServiceName = [string]$d.'#text' }
                'ImagePath'   { $out.ImagePath   = [string]$d.'#text' }
                'ServiceType' { $out.ServiceType = [string]$d.'#text' }
                'StartType'   { $out.StartType   = [string]$d.'#text' }
                'AccountName' { $out.AccountName = [string]$d.'#text' }
            }
        }
    } catch {
        # Fallback: 7045 Properties are positional [ServiceName, ImagePath, ServiceType, StartType, AccountName].
        try {
            $p = @($Event.Properties)
            if ($p.Count -ge 1) { $out.ServiceName = [string]$p[0].Value }
            if ($p.Count -ge 2) { $out.ImagePath   = [string]$p[1].Value }
            if ($p.Count -ge 3) { $out.ServiceType = [string]$p[2].Value }
            if ($p.Count -ge 4) { $out.StartType   = [string]$p[3].Value }
            if ($p.Count -ge 5) { $out.AccountName = [string]$p[4].Value }
        } catch { }
    }
    return $out
}

function Invoke-EventLogTriage {
    <#
      Reviews the Windows event logs for attacker footprints (the heart of what
      Hayabusa/Chainsaw do, distilled to the highest-signal events and explained
      plainly). Mostly needs admin to read the Security log. Read-only.
    #>
    param([int]$Days = 14)
    $f = New-Object System.Collections.ArrayList
    $add = { param($x) [void]$f.Add($x) }
    $after = (Get-Date).AddDays(-$Days)

    # Always returns an ARRAY (never $null/single) so .Count is safe under StrictMode.
    # $script:_lastQueryDenied is set when the failure looks like an access-denied,
    # so callers can distinguish "no events" from "could not read".
    $script:_lastQueryError = $null
    $queryEvents = {
        param($LogName, $Ids, $MaxEvents = 400)
        $script:_lastQueryError = $null
        try {
            return @(Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$Ids; StartTime=$after } -MaxEvents $MaxEvents -ErrorAction Stop)
        } catch {
            # "No events were found" is a normal empty result, not an error. Detect it
            # via the locale-INDEPENDENT FullyQualifiedErrorId rather than the English
            # message text (which would misread as access-denied on non-English
            # Windows and wrongly show "Security log needs Administrator" even when
            # elevated). Anything else is recorded as a genuine read error.
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $script:_lastQueryError = $_.Exception.Message }
            return @()
        }
    }

    $secDenied = $false

    # ---- Audit log cleared (very strong tamper signal) ----
    try {
        $cleared = @(& $queryEvents 'Security' 1102 50)
        if ($cleared.Count -eq 0 -and $script:_lastQueryError) {
            # could not read Security log -> treat as access denied
            $secDenied = $true
        }
        if ($cleared.Count -gt 0) {
            $ev = ($cleared | ForEach-Object { "  {0} - security log cleared" -f $_.TimeCreated }) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-CLEARED-SEC' -Category 'Event Log' -Title 'Security log was cleared' -Severity 'Critical' -Status 'Alert' `
                -What ("The Windows Security audit log was wiped:`n" + $ev) `
                -Why 'Clearing the security log is a deliberate act to destroy evidence. Windows does not do this on its own. This strongly suggests someone is covering their tracks.' `
                -WhatToDo 'If you did not clear it yourself, treat this PC as potentially compromised. Preserve the machine and seek expert help if it holds important data.' -Evidence $ev)
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-CLEARED-SEC-ERR' -Category 'Event Log' -Title 'Security-log check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported here rather than silently skipped, so you know it did not run.' -WhatToDo 'Re-run as Administrator; if it keeps failing, note it as a tool issue.' -Evidence '') }

    # ---- System log cleared ----
    try {
        $sysClear = @(& $queryEvents 'System' 104 50)
        if ($sysClear.Count -gt 0) {
            $ev = ($sysClear | ForEach-Object { "  {0} - {1}" -f $_.TimeCreated, (($_.Message -split "`n")[0]) }) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-CLEARED-SYS' -Category 'Event Log' -Title 'System log was cleared' -Severity 'High' -Status 'Review' `
                -What ("The System event log was cleared:`n" + $ev) -Why 'Can be routine maintenance, but is also used to hide driver/service tampering.' -WhatToDo 'Confirm whether you or an admin tool cleared it. If not, investigate alongside the other findings.' -Evidence $ev)
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-CLEARED-SYS-ERR' -Category 'Event Log' -Title 'System-log check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator.' -Evidence '') }

    # ---- New service installed (persistence) ----
    # Defender's own anti-malware definition-update drivers (MpKslDrv) are
    # reinstalled constantly under random-looking names. We filter THOSE out, but
    # match on the event's OWN structured fields (ServiceName + ImagePath), NOT a
    # substring of the message. A substring filter was bypassable: a malicious
    # service literally named "Windows Defender Update Service" running from
    # C:\Users\Public would vanish. The genuine Defender driver has BOTH a service
    # name like MpKsl + 8 hex chars AND an image path under the Defender
    # "Definition Updates" tree - a planted service can't fake both.
    try {
        $defUpdateRx = [regex]::Escape('\Windows Defender\Definition Updates\')
        $svc = @(& $queryEvents 'System' 7045 200) | Where-Object {
            if (-not $_) { return $false }
            $info = Get-ServiceInstallEventFields $_
            $isDefenderDefDriver = ($info.ServiceName -match '^MpKsl[0-9a-fA-F]{8}$') -and ($info.ImagePath -match $defUpdateRx)
            -not $isDefenderDefDriver
        }
        $svc = @($svc)
        if ($svc.Count -gt 0) {
            $ev = ($svc | ForEach-Object {
                $info = Get-ServiceInstallEventFields $_
                $name = if ($info.ServiceName) { $info.ServiceName } else { '(unknown)' }
                $img  = if ($info.ImagePath)   { $info.ImagePath }   else { '(unknown path)' }
                "  {0}: {1}  ->  {2}" -f $_.TimeCreated, $name, $img
            }) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-NEWSVC' -Category 'Event Log' -Title ("New service(s) installed recently: {0}" -f $svc.Count) -Severity 'Medium' -Status 'Review' `
                -What ("These Windows services were installed in the last $Days days (Defender's own definition-update drivers are filtered out):`n" + $ev) `
                -Why 'Installing a service is a common way malware stays running after reboot. Many are legitimate (apps, updates, drivers) - but attackers hide here too.' `
                -WhatToDo 'Recognise your recent installs? Then fine. An unfamiliar service - especially one running from Temp/AppData or with a random name - should be investigated.' -Evidence $ev)
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-NEWSVC-ERR' -Category 'Event Log' -Title 'New-service check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator.' -Evidence '') }

    # ---- Account created / added to admins ----
    try {
        $acct = New-Object System.Collections.ArrayList
        foreach ($e in @(& $queryEvents 'Security' @(4720) 200)) { if ($e) { [void]$acct.Add(("  {0} - new local user account created" -f $e.TimeCreated)) } }
        foreach ($e in @(& $queryEvents 'Security' @(4732,4728) 200)) {
            if ($e) {
                $m = (@($e.Message -split "`n" | Where-Object { $_ -match 'Group Name|Member|Account Name' } | Select-Object -First 3)) -join '; '
                [void]$acct.Add(("  {0} - account added to a group  {1}" -f $e.TimeCreated, $m.Trim()))
            }
        }
        if (@($acct).Count -gt 0) {
            $ev = (@($acct.ToArray())) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-ACCT' -Category 'Event Log' -Title ("Account changes in the last $Days days: {0}" -f @($acct).Count) -Severity 'High' -Status 'Review' `
                -What ("New accounts and/or privilege-group changes:`n" + $ev) `
                -Why 'Attackers create accounts or add themselves to Administrators to keep access. If you did not make these changes, it is a red flag.' `
                -WhatToDo 'Cross-check with the "Investigate" account findings. Remove or disable any account you did not create.' -Evidence $ev)
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-ACCT-ERR' -Category 'Event Log' -Title 'Account-change check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator (needs the Security log).' -Evidence '') }

    # ---- Brute force: many failed logons ----
    try {
        $failed = @(& $queryEvents 'Security' 4625 1000)
        if ($failed.Count -ge 10) {
            $sev = if ($failed.Count -ge 50) { 'High' } else { 'Medium' }
            & $add (New-DfirFinding -Id 'EVT-BRUTE' -Category 'Event Log' -Title ("Many failed sign-in attempts: {0}" -f $failed.Count) -Severity $sev -Status 'Review' `
                -What ("There were {0} failed logon attempts in the last {1} days (first seen {2})." -f $failed.Count, $Days, ($failed[-1].TimeCreated)) `
                -Why 'A burst of failed logons can mean someone (or a bot) is trying to guess a password - common when RDP or an account is exposed to the internet.' `
                -WhatToDo 'If this PC exposes Remote Desktop, consider disabling it (Security tab) or ensure strong passwords + account lockout. A few failures from your own typos are normal.' -Evidence ("Failed logon events: {0}" -f $failed.Count))
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-BRUTE-ERR' -Category 'Event Log' -Title 'Failed-logon check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator (needs the Security log).' -Evidence '') }

    # ---- Account lockouts ----
    try {
        $lock = @(& $queryEvents 'Security' 4740 100)
        if ($lock.Count -gt 0) {
            & $add (New-DfirFinding -Id 'EVT-LOCKOUT' -Category 'Event Log' -Title ("Account lockout(s): {0}" -f $lock.Count) -Severity 'Medium' -Status 'Review' `
                -What ("An account was locked out {0} time(s) recently." -f $lock.Count) -Why 'Lockouts often accompany password-guessing attacks.' -WhatToDo 'If unexpected, review which account and whether RDP/network access is exposed.' -Evidence ("Lockout events: {0}" -f $lock.Count))
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-LOCKOUT-ERR' -Category 'Event Log' -Title 'Lockout check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator.' -Evidence '') }

    # ---- Defender detections ----
    try {
        $det = @(& $queryEvents 'Microsoft-Windows-Windows Defender/Operational' @(1116,1117) 200)
        if ($det.Count -gt 0) {
            $ev = (@($det | Select-Object -First 15 | ForEach-Object {
                $threat = (@($_.Message -split "`n" | Where-Object { $_ -match 'Name:|Threat' } | Select-Object -First 1))
                "  {0} - {1}" -f $_.TimeCreated, (($threat -join ' ') -replace '\s+',' ').Trim()
            })) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-DEFENDER' -Category 'Event Log' -Title ("Microsoft Defender detected threats: {0}" -f $det.Count) -Severity 'High' -Status 'Review' `
                -What ("Defender logged {0} detection event(s) in the last {1} days:`n{2}" -f $det.Count, $Days, $ev) `
                -Why 'Defender already caught something. Usually it also blocked/quarantined it, but repeated detections can mean something keeps trying to run.' `
                -WhatToDo 'Open Windows Security > Protection history to see if each item was successfully removed. Run a full offline scan if detections keep recurring.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'EVT-DEFENDER' -Category 'Event Log' -Title 'No Defender detections recently' -Severity 'Info' -Status 'Clean' -What ("No Defender threat detections in the last $Days days.") -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-DEFENDER-ERR' -Category 'Event Log' -Title 'Defender-log check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Confirm the Defender operational log is available.' -Evidence '') }

    # ---- Scheduled task created ----
    try {
        $task = @(& $queryEvents 'Security' 4698 100)
        if ($task.Count -gt 0) {
            $ev = (@($task | ForEach-Object { $tn = (@($_.Message -split "`n" | Where-Object { $_ -match 'Task Name' } | Select-Object -First 1)); "  {0} - {1}" -f $_.TimeCreated, (($tn -join ' ') -replace '\s+',' ').Trim() })) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-TASK' -Category 'Event Log' -Title ("Scheduled task(s) created: {0}" -f $task.Count) -Severity 'Medium' -Status 'Review' `
                -What ("New scheduled tasks in the last $Days days:`n" + $ev) -Why 'Scheduled tasks are a favourite persistence trick. Legit apps make them too.' -WhatToDo 'Match against software you installed. Investigate unfamiliar ones in Task Scheduler.' -Evidence $ev)
        } else {
            # 4698 requires the "Audit Other Object Access Events" policy, which is OFF
            # by default on Windows. "No events" therefore does NOT prove no tasks were
            # created - so we SURFACE that caveat to the user instead of hiding it in a
            # comment, and point them at the native scheduled-task check which does not
            # depend on auditing being enabled.
            & $add (New-DfirFinding -Id 'EVT-TASK' -Category 'Event Log' -Title 'No scheduled-task-creation events logged' -Severity 'Info' -Status 'Info' `
                -What ("No task-creation (event 4698) records were found in the last $Days days.") `
                -Why 'Windows only logs event 4698 when the "Audit Other Object Access Events" policy is enabled, which is OFF by default. So an empty result here does NOT prove that no scheduled task was created - the event may simply never have been recorded.' `
                -WhatToDo 'Rely on the Startup / Investigate scheduled-task list (which inspects the tasks that exist now, regardless of auditing) rather than on this event-log card. To get this card working for the future, enable "Audit Other Object Access Events" in Local Security Policy.' -Evidence '')
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-TASK-ERR' -Category 'Event Log' -Title 'Scheduled-task-event check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator.' -Evidence '') }

    # ---- RDP interactive logons (Logon Type 10) ----
    # Match on the numeric field across locales rather than the English label.
    try {
        $rdp = @(& $queryEvents 'Security' 4624 1000) | Where-Object {
            $_ -and ($_.Properties -and @($_.Properties).Count -ge 9 -and "$($_.Properties[8].Value)" -eq '10')
        }
        $rdp = @($rdp)
        if ($rdp.Count -gt 0) {
            & $add (New-DfirFinding -Id 'EVT-RDPLOGON' -Category 'Event Log' -Title ("Remote Desktop logons: {0}" -f $rdp.Count) -Severity 'Medium' -Status 'Review' `
                -What ("There were {0} successful Remote Desktop sign-ins in the last {1} days." -f $rdp.Count, $Days) `
                -Why 'If you use RDP yourself this is expected. If you do NOT remote into this PC, someone else did.' `
                -WhatToDo 'If these are not you, disable RDP (Security tab) and change passwords immediately.' -Evidence ("RDP logon events: {0}" -f $rdp.Count))
        }
    } catch { & $add (New-DfirFinding -Id 'EVT-RDPLOGON-ERR' -Category 'Event Log' -Title 'RDP-logon check failed' -Severity 'Info' -Status 'Info' -What ("This check could not run: {0}" -f $_.Exception.Message) -Why 'A failed check is reported rather than silently skipped.' -WhatToDo 'Re-run as Administrator (needs the Security log).' -Evidence '') }

    if ($secDenied) {
        & $add (New-DfirFinding -Id 'EVT-DENIED' -Category 'Event Log' -Title 'Security log needs Administrator to read' -Severity 'Info' -Status 'Info' `
            -What 'The Windows Security log (where logons, account changes and log-clearing are recorded) could not be read.' `
            -Why 'Reading the Security log requires administrator rights.' `
            -WhatToDo 'Relaunch via Start.bat (it elevates) to include logon/brute-force/account-change checks.' -Evidence '')
    }

    Write-CoreLog -Message ("Event-log triage: {0} finding(s)." -f $f.Count) -Level INFO
    return $f.ToArray()
}

function Invoke-DeepScan {
    <# Convenience: run both deep engines and return the combined findings. #>
    $all = New-Object System.Collections.ArrayList
    foreach ($x in @(Invoke-ProcessThreatScan)) { [void]$all.Add($x) }
    foreach ($x in @(Invoke-EventLogTriage))   { [void]$all.Add($x) }
    return $all.ToArray()
}


# ============================================================================
#  EXTERNAL DFIR TOOL ORCHESTRATION  (opt-in, download-at-runtime, never bundled)
#  --------------------------------------------------------------------------
#  Lets the user OPTIONALLY download and run best-in-class open-source DFIR
#  tools (Hayabusa, Chainsaw) from their official GitHub releases, then parses
#  their output back into our plain-English finding cards.
#
#  WHY THIS DESIGN (licensing): Hayabusa and Chainsaw are GPL-3.0. Bundling an
#  unmodified copy would NOT relicense this project's own MIT code (that is mere
#  aggregation), but it WOULD attach GPL duties - ship the license, offer the
#  corresponding source - to that binary in every release, and the shipped copy
#  would go stale. Instead the END USER fetches them at runtime after an explicit
#  consent screen (vendor, license, source URL, version, size). We only INVOKE
#  them as separate processes and read their output - we never redistribute them.
#  See docs/DFIR-TOOLS.md and THIRD-PARTY-NOTICES.md.
#
#  SAFETY:
#   * Nothing downloads or runs unless the user clicks through consent.
#   * Downloads come only from api.github.com / github.com release assets of the
#     official repositories, over TLS 1.2+.
#   * The archive is verified (zip magic bytes), and its SHA-256 is checked against
#     a TRUSTED hash (project-pinned/reviewed, else GitHub's advertised digest)
#     BEFORE extraction. No trusted hash -> the download is REFUSED (fail closed),
#     because these binaries run elevated. The extracted exe's own hash is pinned
#     at install time and re-verified before every run.
#   * The tools are run strictly READ-ONLY against the local event logs.
#   * Everything lives under the admin-locked %ProgramData%\Win11SecurityOptimizer
#     \tools (Administrators/SYSTEM write, Users read-only) and can be deleted
#     anytime (Restore & Logs tab / "Remove downloaded tools").
# ============================================================================

function Get-ExternalToolRegistry {
    <#
      Static metadata for each supported external tool. No network calls.
      AssetPattern/ExePattern are regexes evaluated against release asset names
      and extracted file names respectively.
    #>
    @(
        [pscustomobject]@{
            Key          = 'hayabusa'
            Name         = 'Hayabusa'
            Vendor       = 'Yamato Security'
            Repo         = 'Yamato-Security/hayabusa'
            License      = 'GPL-3.0'
            HomeUrl      = 'https://github.com/Yamato-Security/hayabusa'
            Summary      = 'Fast Windows event-log threat hunter using Sigma + its own detection rules. Produces a timeline of attacker activity found in your logs.'
            # Windows asset by architecture; prefer the full build (bundles rules/ + config/).
            AssetPattern = @{
                'AMD64' = '^hayabusa-[\d\.]+-win-x64\.zip$'
                'ARM64' = '^hayabusa-[\d\.]+-win-aarch64\.zip$'
                'x86'   = '^hayabusa-[\d\.]+-win-x86\.zip$'
            }
            ExePattern   = '^hayabusa.*\.exe$'
            OutputKind   = 'HayabusaCsv'
            NeedsAdmin   = $true
            # PINNED version + per-asset SHA-256 (the strongest upstream integrity
            # anchor). This is the version the project has reviewed; the download is
            # verified against THESE hashes, not just whatever the API advertises at
            # runtime - so a malicious upstream re-release of the SAME tag is caught.
            # To adopt a newer version: verify its hashes out-of-band, then update here.
            PinnedVersion = 'v4.1.0'
            PinnedSha256 = @{
                'hayabusa-4.1.0-win-x64.zip'     = '4D304CC5BAAA750ED08CC24B7B89C58EA058740C7E344502D7B82554637543A8'
                'hayabusa-4.1.0-win-aarch64.zip' = 'F305183E49FCB65CC1F65921845BEA8C8522A5BD4E1A12117931532CA12F0D3D'
                'hayabusa-4.1.0-win-x86.zip'     = '2C2966AF9FCA074BCFCF48E1B0EBE645D8F25E0B77234D16BD76E5E24E7D2FB4'
            }
        },
        [pscustomobject]@{
            Key          = 'chainsaw'
            Name         = 'Chainsaw'
            Vendor       = 'WithSecure Labs'
            Repo         = 'WithSecureLabs/chainsaw'
            License      = 'GPL-3.0'
            HomeUrl      = 'https://github.com/WithSecureLabs/chainsaw'
            Summary      = 'Rapidly searches Windows event logs with Sigma rules and built-in detection logic. Flags known attack patterns with MITRE ATT&CK context.'
            # The "+rules" bundle contains the Windows exe AND the sigma/rules/mappings it needs.
            AssetPattern = @{
                'AMD64' = '^chainsaw_all_platforms\+rules\.zip$'
                'ARM64' = '^chainsaw_all_platforms\+rules\.zip$'
                'x86'   = '^chainsaw_all_platforms\+rules\.zip$'
            }
            ExePattern   = '^chainsaw.*windows.*\.exe$|^chainsaw\.exe$'
            OutputKind   = 'ChainsawJson'
            NeedsAdmin   = $true
            PinnedVersion = 'v2.16.5'
            PinnedSha256 = @{
                'chainsaw_all_platforms+rules.zip' = 'FBD5E12FBD70395BC7FDFDF2D3903E8545F27CA2F35E23059DF6177641B76205'
            }
        }
    )
}

function Get-ExternalTool {
    param([Parameter(Mandatory)][string]$Key)
    Get-ExternalToolRegistry | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
}

function Get-SystemArch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'AMD64' }
        'ARM64' { 'ARM64' }
        'x86'   { 'x86' }
        default { 'AMD64' }
    }
}

function Get-ExternalToolsRoot {
    <#
      Pure path accessor (NO side effects): returns the location external tools
      must live in. External tools run ELEVATED, so they must sit where a
      non-admin process cannot plant or replace a binary. That is an ACL-locked
      folder under %ProgramData%. Creating/locking/verifying is done separately by
      Initialize-SecureToolsRoot so that read-only checks never mutate state.
    #>
    return (Join-Path $env:ProgramData 'Win11SecurityOptimizer\tools')
}

function Test-FolderOwnedBySystemOrAdmins {
    <# Read-only: true only if the item's owner is Administrators (S-1-5-32-544)
       or SYSTEM (S-1-5-18). A standard user owning it (the classic ProgramData
       pre-creation attack) returns false. #>
    param([string]$Path)
    try {
        $owner = (Get-Acl -Path $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        return ($owner -eq 'S-1-5-32-544' -or $owner -eq 'S-1-5-18')
    } catch { return $false }
}

function Test-ToolsTreeOwnership {
    <# Read-only: true only if the tools root AND every item under it are owned by
       Administrators/SYSTEM. Catches a non-admin pre-planting tools\x\evil.exe. #>
    param([string]$Root)
    if (-not (Test-Path $Root)) { return $true }   # nothing there yet = fine
    if (-not (Test-FolderOwnedBySystemOrAdmins $Root)) { return $false }
    try {
        foreach ($item in Get-ChildItem -Path $Root -Recurse -Force -ErrorAction Stop) {
            if (-not (Test-FolderOwnedBySystemOrAdmins $item.FullName)) { return $false }
        }
        return $true
    } catch { return $false }
}

function Test-ToolsRootSecure {
    <# READ-ONLY security gate (never mutates). True only when the tools root is
       under ProgramData, is locked so standard Users cannot write, AND the whole
       tree is owned by Administrators/SYSTEM. Used to refuse running an elevated
       tool from a location a non-admin could have tampered with. #>
    $secureBase = Join-Path $env:ProgramData 'Win11SecurityOptimizer\tools'
    $root = Get-ExternalToolsRoot
    if ($root -ne $secureBase) { return $false }
    if (-not (Test-Path $root)) { return $false }
    try {
        $acl = Get-Acl -Path $root
        foreach ($ace in $acl.Access) {
            $id = "$($ace.IdentityReference)"
            if ($id -match 'Users|Everyone|Authenticated Users' -and $ace.AccessControlType -eq 'Allow') {
                $rights = $ace.FileSystemRights.ToString()
                if ($rights -match 'Write|Modify|FullControl|CreateFiles|CreateDirectories|AppendData') { return $false }
            }
        }
    } catch { return $false }
    return (Test-ToolsTreeOwnership -Root $root)
}

function Initialize-SecureToolsRoot {
    <# Admin-only: create the ProgramData tools tree, lock its ACL, and — crucially
       — if it (or anything in it) is NOT already owned by Administrators/SYSTEM
       (i.e. a standard user pre-created it to plant a binary), DELETE and recreate
       it so no attacker-planted content survives. Returns the secured root path,
       or throws if it cannot be secured. #>
    if (-not (Test-IsAdmin)) { throw 'Administrator rights are required to prepare the secure tools folder.' }
    $base = Join-Path $env:ProgramData 'Win11SecurityOptimizer'
    $root = Join-Path $base 'tools'

    if (Test-Path $root) {
        if (-not (Test-ToolsTreeOwnership -Root $root)) {
            Write-CoreLog -Message 'Tools folder (or an item in it) is not owned by Administrators/SYSTEM - deleting and recreating to drop any planted content.' -Level WARN
            Remove-Item -Path $root -Recurse -Force -ErrorAction Stop
        }
    }
    if (-not (Test-Path $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
    if (-not (Test-Path $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    Set-ToolsFolderAcl -Path $base
    Set-ToolsFolderAcl -Path $root
    if (-not (Test-ToolsRootSecure)) { throw 'The tools folder could not be secured (ACL/ownership check failed).' }
    return $root
}

function Set-ToolsFolderAcl {
    <# Lock the folder: Administrators + SYSTEM full control; Users read & execute
       only; disable inheritance; set owner to Administrators (so a user who
       pre-created it no longer owns it). #>
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited
        $admins = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
        $system = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
        $users  = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        $prop = [System.Security.AccessControl.PropagationFlags]::None
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'FullControl',$inherit,$prop,'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl',$inherit,$prop,'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($users,'ReadAndExecute',$inherit,$prop,'Allow')))
        $acl.SetOwner($admins)
        Set-Acl -Path $Path -AclObject $acl
    } catch {
        Write-CoreLog -Message ("Could not lock tools folder ACL: {0}" -f $_.Exception.Message) -Level WARN
    }
}

function Set-TreeOwnerToAdministrators {
    <# Recursively set the OWNER of a path (and everything under it) to the
       Administrators group (S-1-5-32-544). Our own freshly-extracted files are
       owned by the elevated admin USER by default, which would otherwise fail the
       Administrators/SYSTEM ownership gate; forcing the owner to Administrators
       lets legitimate installs pass while a non-admin's pre-planted content (owned
       by a standard-user SID) still fails. Requires elevation. #>
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    $admins = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $targets = @($Path)
    try { $targets += @(Get-ChildItem -Path $Path -Recurse -Force -ErrorAction Stop | ForEach-Object { $_.FullName }) } catch { }
    foreach ($p in $targets) {
        try {
            $acl = Get-Acl -Path $p
            $acl.SetOwner($admins)
            Set-Acl -Path $p -AclObject $acl
        } catch { }
    }
}

function Resolve-ExternalToolRelease {
    <#
      Queries the official GitHub repo for the latest release and selects the
      correct Windows asset for this machine's architecture. METADATA ONLY - does
      not download the binary. Returns a resolution object or throws a clear error.
    #>
    param([Parameter(Mandatory)][string]$Key)
    $tool = Get-ExternalTool -Key $Key
    if (-not $tool) { throw "Unknown tool '$Key'." }
    $arch = Get-SystemArch
    $pattern = $tool.AssetPattern[$arch]
    if (-not $pattern) { throw "$($tool.Name) has no build for architecture $arch." }

    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    $headers = @{ 'User-Agent' = 'Win11SecurityOptimizer'; 'Accept' = 'application/vnd.github+json' }
    $api = "https://api.github.com/repos/$($tool.Repo)/releases/latest"

    Write-CoreLog -Message ("Resolving latest release for {0} ({1})" -f $tool.Name, $tool.Repo) -Level INFO
    $rel = Invoke-RestMethod -Uri $api -Headers $headers -TimeoutSec 30 -ErrorAction Stop

    $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $asset) {
        $names = ($rel.assets | ForEach-Object { $_.name }) -join ', '
        throw "Could not find a Windows ($arch) asset for $($tool.Name) in release $($rel.tag_name). Assets were: $names"
    }

    # GitHub populates a 'digest' field like 'sha256:abc...' on current releases.
    # Capture it so the download can be cryptographically verified before use.
    $digest = $null
    try { if ($asset.PSObject.Properties.Name -contains 'digest' -and $asset.digest) { $digest = [string]$asset.digest } } catch { }
    $apiSha256 = $null
    if ($digest -and $digest -match '^sha256:([0-9a-fA-F]{64})$') { $apiSha256 = $Matches[1].ToUpper() }

    # PINNED hash is the strongest anchor: it was reviewed out-of-band and committed
    # to this registry, so it also catches a MALICIOUS UPSTREAM re-release of the
    # same tag (which the API digest, coming from that same release, would not).
    # Precedence for the hash we verify against:
    #   1. pinned hash for this exact asset name  (strongest)
    #   2. the API-advertised digest               (catches in-transit tampering)
    #   3. none                                     (caller fails closed)
    $pinnedSha = $null
    try { if ($tool.PSObject.Properties.Name -contains 'PinnedSha256' -and $tool.PinnedSha256 -and $tool.PinnedSha256.ContainsKey($asset.name)) { $pinnedSha = ([string]$tool.PinnedSha256[$asset.name]).ToUpper() } } catch { }
    $pinnedVersion = $null
    try { if ($tool.PSObject.Properties.Name -contains 'PinnedVersion') { $pinnedVersion = [string]$tool.PinnedVersion } } catch { }
    $versionMatchesPin = ($pinnedVersion -and ($rel.tag_name -eq $pinnedVersion))

    # If a newer tag than the pin shipped, the pinned hash won't match the new
    # asset. Warn clearly - but still verify against the API digest so the download
    # is at least transit-verified; the caller refuses if even that is missing.
    if ($pinnedVersion -and -not $versionMatchesPin) {
        Write-CoreLog -Message ("{0}: latest release {1} differs from the reviewed/pinned version {2}. Using the GitHub-advertised digest for this release; its hash has not been reviewed by this project." -f $tool.Name, $rel.tag_name, $pinnedVersion) -Level WARN
    }

    $sha256Expected = if ($pinnedSha) { $pinnedSha } elseif ($apiSha256) { $apiSha256 } else { $null }

    [pscustomobject]@{
        Key          = $Key
        Name         = $tool.Name
        Vendor       = $tool.Vendor
        License      = $tool.License
        HomeUrl      = $tool.HomeUrl
        Summary      = $tool.Summary
        Version      = $rel.tag_name
        AssetName    = $asset.name
        DownloadUrl  = $asset.browser_download_url
        SizeBytes    = [int64]$asset.size
        SizeMB       = [math]::Round($asset.size / 1MB, 1)
        Arch         = $arch
        NeedsAdmin   = $tool.NeedsAdmin
        Published    = $rel.published_at
        Sha256Expected = $sha256Expected   # pinned hash if we have one, else API digest, else $null
        Sha256Source   = if ($pinnedSha) { 'pinned' } elseif ($apiSha256) { 'github-digest' } else { 'none' }
        PinnedVersion  = $pinnedVersion
        VersionMatchesPin = $versionMatchesPin
    }
}

function Get-ExternalToolInstallPath {
    param([string]$Key, [string]$Version)
    Join-Path (Get-ExternalToolsRoot) ("{0}\{1}" -f $Key, ($Version -replace '[^\w\.\-]','_'))
}

function Find-ExternalToolExe {
    param([string]$InstallPath, [string]$ExePattern)
    if (-not (Test-Path $InstallPath)) { return $null }
    $exe = Get-ChildItem -Path $InstallPath -Recurse -Filter *.exe -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -match $ExePattern } |
           Sort-Object { $_.FullName.Length } | Select-Object -First 1
    if ($exe) { return $exe.FullName }
    return $null
}

function Test-ExternalToolInstalled {
    <# Returns the exe path if a matching version is already installed, else $null. #>
    param([Parameter(Mandatory)][string]$Key, [string]$Version)
    $tool = Get-ExternalTool -Key $Key
    if (-not $tool) { return $null }
    if ($Version) {
        $p = Get-ExternalToolInstallPath -Key $Key -Version $Version
        return (Find-ExternalToolExe -InstallPath $p -ExePattern $tool.ExePattern)
    }
    # any installed version
    $base = Join-Path (Get-ExternalToolsRoot) $Key
    if (-not (Test-Path $base)) { return $null }
    return (Find-ExternalToolExe -InstallPath $base -ExePattern $tool.ExePattern)
}

function Install-ExternalTool {
    <#
      Downloads + extracts + verifies an external tool. REQUIRES -ConsentAccepted
      (the GUI sets this only after the user accepts the consent screen).
      Idempotent: if the resolved version is already installed, it is reused.
      Returns @{Success;ExePath;Version;Sha256;Message}.
    #>
    param(
        [Parameter(Mandatory)][string]$Key,
        [switch]$ConsentAccepted,
        $Resolution,                       # optional pre-resolved release (from the consent screen)
        [scriptblock]$Progress             # optional: receives status strings
    )
    $report = { param($m) if ($Progress) { try { & $Progress $m } catch { } }; Write-CoreLog -Message $m -Level INFO }

    if (-not $ConsentAccepted) {
        return [pscustomobject]@{ Success=$false; Message='Consent was not given. Download aborted.'; ExePath=$null; Version=$null; Sha256=$null }
    }
    $tool = Get-ExternalTool -Key $Key
    if (-not $tool) { return [pscustomobject]@{ Success=$false; Message="Unknown tool '$Key'."; ExePath=$null; Version=$null; Sha256=$null } }

    # These tools run ELEVATED, so refuse to install anywhere a non-admin process
    # could tamper with the binary before it runs.
    if (-not (Test-IsAdmin)) {
        return [pscustomobject]@{ Success=$false; Message='Administrator rights are required to install external tools to a protected location.'; ExePath=$null; Version=$null; Sha256=$null }
    }

    try {
        if (-not $Resolution) { $Resolution = Resolve-ExternalToolRelease -Key $Key }

        # Prepare + lock the tools root BEFORE anything is written. This creates the
        # ProgramData tree, locks its ACL, and - critically - if a standard user
        # pre-created it (or planted content) so it is NOT owned by
        # Administrators/SYSTEM, deletes and recreates it. Mutating setup lives here;
        # the gate below (Test-ToolsRootSecure) stays read-only.
        [void](Initialize-SecureToolsRoot)
        if (-not (Test-ToolsRootSecure)) {
            throw 'The tools folder is not in a protected (admin-only) location, so an elevated download would be unsafe. Aborting.'
        }

        # Already installed AND hash still matches a locked copy? Reuse it.
        $existing = Test-ExternalToolInstalled -Key $Key -Version $Resolution.Version
        if ($existing) {
            & $report ("{0} {1} already present - reusing." -f $tool.Name, $Resolution.Version)
            return [pscustomobject]@{ Success=$true; Message='Already installed.'; ExePath=$existing; Version=$Resolution.Version; Sha256=$null }
        }

        $installPath = Get-ExternalToolInstallPath -Key $Key -Version $Resolution.Version
        if (-not (Test-Path $installPath)) { New-Item -ItemType Directory -Path $installPath -Force | Out-Null }
        $zipPath = Join-Path $installPath $Resolution.AssetName

        & $report ("Downloading {0} {1} ({2} MB) from {3}" -f $tool.Name, $Resolution.Version, $Resolution.SizeMB, $Resolution.DownloadUrl)
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

        $downloaded = $false
        # Prefer BITS (resumable, shows in Windows), fall back to WebClient.
        try {
            Import-Module BitsTransfer -ErrorAction Stop
            Start-BitsTransfer -Source $Resolution.DownloadUrl -Destination $zipPath -ErrorAction Stop
            $downloaded = $true
        } catch {
            & $report 'BITS unavailable - using direct download...'
            try {
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add('User-Agent','Win11SecurityOptimizer')
                $wc.DownloadFile($Resolution.DownloadUrl, $zipPath)
                $downloaded = $true
            } catch {
                throw "Download failed: $($_.Exception.Message)"
            }
        }
        if (-not $downloaded -or -not (Test-Path $zipPath)) { throw 'Download did not produce a file.' }

        # Verify it is really a ZIP (PK\x03\x04) before trusting Expand-Archive.
        $fs = [System.IO.File]::OpenRead($zipPath)
        try {
            $sig = New-Object byte[] 4
            [void]$fs.Read($sig, 0, 4)
        } finally { $fs.Close() }
        if (-not ($sig[0] -eq 0x50 -and $sig[1] -eq 0x4B)) {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            throw 'Downloaded file is not a valid ZIP archive (unexpected content). Aborting for safety.'
        }

        # Compute the SHA-256 and VERIFY it against the expected hash (pinned hash
        # preferred, else the digest GitHub advertised for this exact asset). This is
        # the real integrity gate - if it does not match, OR if there is NO expected
        # hash at all, the file is deleted and nothing is extracted or executed.
        # These binaries run ELEVATED, so we FAIL CLOSED rather than trusting an
        # unverifiable download.
        $sha = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToUpper()
        & $report ("SHA-256: {0}" -f $sha)
        $expected = $null; $expectedSource = 'none'
        try { if ($Resolution.PSObject.Properties.Name -contains 'Sha256Expected') { $expected = $Resolution.Sha256Expected } } catch { }
        try { if ($Resolution.PSObject.Properties.Name -contains 'Sha256Source') { $expectedSource = [string]$Resolution.Sha256Source } } catch { }

        if (-not $expected) {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            throw 'No trusted hash is available for this download (neither a project-pinned hash nor a GitHub-advertised digest). Because this tool runs with administrator rights, it will NOT be installed from an unverifiable download. Aborting.'
        }
        if ($sha -ne $expected.ToUpper()) {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            throw ("SHA-256 MISMATCH. Expected {0} ({1}) but got {2}. The download was corrupted or tampered with; it has been deleted and NOT run." -f $expected.ToUpper(), $expectedSource, $sha)
        }
        if ($expectedSource -eq 'pinned') {
            & $report 'SHA-256 verified against the project-pinned (reviewed) hash.'
            Write-CoreLog -Message ("{0} {1} SHA-256 verified against PINNED hash: {2}" -f $tool.Name, $Resolution.Version, $sha) -Level OK
        } else {
            & $report 'SHA-256 verified against the official GitHub release digest (this version is newer than the project-reviewed pin).'
            Write-CoreLog -Message ("{0} {1} SHA-256 verified against GitHub digest: {2}" -f $tool.Name, $Resolution.Version, $sha) -Level OK
        }

        & $report 'Extracting...'
        Expand-Archive -Path $zipPath -DestinationPath $installPath -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue   # keep only the extracted tool

        $exe = Find-ExternalToolExe -InstallPath $installPath -ExePattern $tool.ExePattern
        if (-not $exe) { throw "Extraction succeeded but no executable matching '$($tool.ExePattern)' was found." }

        # PIN THE EXE HASH NOW - at install time, immediately after extracting from
        # the hash-verified ZIP - so the trusted baseline is "what we just extracted
        # from a verified archive", NOT "whatever happens to be on disk at first run".
        $exeHash = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToUpper()
        $exeHashPath = Join-Path $installPath 'exe.sha256'
        Set-Content -Path $exeHashPath -Value $exeHash -Encoding ASCII

        # Verify the binary runs (sanity + anti-corruption check). Different tools
        # expose version differently (Hayabusa uses a 'help' subcommand, not
        # --version), so try a few and capture the first line of banner/output.
        $verText = ''
        foreach ($probe in @(@('help'), @('--version'), @('-V'), @('--help'))) {
            try {
                $out = (& $exe @probe 2>&1 | Out-String).Trim()
                if ($out -and $out -notmatch 'unexpected argument') { $verText = ($out -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim(); break }
            } catch { }
        }
        if (-not $verText) { $verText = 'ran (version banner not detected)' }
        & $report ("Verified binary: {0}" -f $verText)

        # Record install metadata (incl. both the verified ZIP hash and the pinned
        # exe hash) for later re-verification.
        $meta = [pscustomobject]@{
            Key=$Key; Name=$tool.Name; Version=$Resolution.Version; Vendor=$tool.Vendor; License=$tool.License
            Source=$Resolution.DownloadUrl; Sha256=$sha; Sha256Expected=$expected; ExeSha256=$exeHash; Exe=$exe; VersionText=$verText; InstalledAt=(Get-Date -Format o)
        }
        try { $meta | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $installPath 'install.json') -Encoding UTF8 } catch { }

        # LAST: force ownership of the WHOLE tools tree (every tool/version subfolder
        # and the files we just wrote - exe, rules, install.json, exe.sha256) to the
        # Administrators group, then re-assert the ACL lock. On modern Windows a
        # folder created by an elevated admin is owned by that USER, not the
        # Administrators group, so without this the ownership gate would fail on the
        # NEXT run. This must happen AFTER the manifests are written. A non-admin's
        # pre-planted file (owned by a standard-user SID) still fails the gate, which
        # is the whole point.
        if ((Get-ExternalToolsRoot) -eq (Join-Path $env:ProgramData 'Win11SecurityOptimizer\tools')) {
            Set-TreeOwnerToAdministrators -Path (Get-ExternalToolsRoot)
            Set-ToolsFolderAcl -Path (Join-Path $env:ProgramData 'Win11SecurityOptimizer')
            Set-ToolsFolderAcl -Path (Get-ExternalToolsRoot)
        }

        Add-ChangeRecord -Description ("Downloaded external tool {0} {1} (SHA256 {2}) from {3}" -f $tool.Name, $Resolution.Version, $sha.Substring(0,16), $Resolution.DownloadUrl)

        return [pscustomobject]@{ Success=$true; Message='Installed.'; ExePath=$exe; Version=$Resolution.Version; Sha256=$sha }
    } catch {
        Write-CoreLog -Message ("Install-ExternalTool {0} failed: {1}" -f $Key, $_.Exception.Message) -Level ERROR
        return [pscustomobject]@{ Success=$false; Message=$_.Exception.Message; ExePath=$null; Version=$null; Sha256=$null }
    }
}

function Remove-ExternalTools {
    <# Deletes everything under the tools folder. Returns count removed. #>
    $root = Get-ExternalToolsRoot
    $items = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue
    $n = @($items).Count
    foreach ($d in $items) { Remove-Item $d.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    Write-CoreLog -Message ("Removed {0} downloaded tool folder(s)." -f $n) -Level INFO
    return $n
}

# ----------------------------------------------------------------------------
#  Runners  (read-only; run the external tool against the live event logs)
# ----------------------------------------------------------------------------
function Invoke-HayabusaScan {
    param([Parameter(Mandatory)][string]$ExePath, [string]$MinLevel = 'medium', [scriptblock]$Progress)
    $report = { param($m) if ($Progress) { try { & $Progress $m } catch { } }; Write-CoreLog -Message $m -Level INFO }
    $toolDir = Split-Path $ExePath -Parent
    $outCsv  = Join-Path $script:Core.DataPath ("logs\hayabusa_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    # dfir-timeline over the LIVE local logs (-l). -w disables the interactive
    # wizard, -C overwrites, -m sets the minimum rule level, -p standard profile,
    # -K no color, -Q quiet errors. (Subcommand/flags verified against v4.x.)
    $hArgs = @('dfir-timeline','-l','-w','-C','-o', $outCsv, '-m', $MinLevel, '-p','standard','-K','-Q')
    & $report ("Running Hayabusa (min level: {0}) - this can take a few minutes..." -f $MinLevel)
    $stdout = ''
    try {
        Push-Location $toolDir
        $stdout = (& $ExePath @hArgs 2>&1 | Out-String)
    } finally { Pop-Location }
    Write-CoreLog -Message ("Hayabusa finished. Output: {0}" -f $outCsv) -Level INFO
    return [pscustomobject]@{ OutputPath=$outCsv; StdOut=$stdout; Kind='HayabusaCsv' }
}

function Invoke-ChainsawScan {
    param([Parameter(Mandatory)][string]$ExePath, [scriptblock]$Progress)
    $report = { param($m) if ($Progress) { try { & $Progress $m } catch { } }; Write-CoreLog -Message $m -Level INFO }
    $toolDir = Split-Path $ExePath -Parent
    $outJson = Join-Path $script:Core.DataPath ("logs\chainsaw_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $logDir  = Join-Path $env:SystemRoot 'System32\winevt\Logs'

    # Locate the sigma rules / detection rules / mapping that ship in the +rules bundle.
    $sigmaDir   = Get-ChildItem -Path $toolDir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'sigma' } | Select-Object -First 1
    $rulesDir   = Get-ChildItem -Path $toolDir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'rules' } | Select-Object -First 1
    $mappingFile= Get-ChildItem -Path $toolDir -Recurse -Filter *.yml -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'sigma.*(all|event).*\.yml$' -or $_.Name -match 'sigma-event-logs-all\.yml$' } | Select-Object -First 1

    $csArgs = @('hunt', $logDir, '--json', '-o', $outJson, '--skip-errors')
    if ($sigmaDir -and $mappingFile) { $csArgs += @('-s', $sigmaDir.FullName, '--mapping', $mappingFile.FullName) }
    if ($rulesDir) { $csArgs += @('-r', $rulesDir.FullName) }

    & $report 'Running Chainsaw against the local event logs - this can take a few minutes...'
    $stdout = ''
    try {
        Push-Location $toolDir
        $stdout = (& $ExePath @csArgs 2>&1 | Out-String)
    } finally { Pop-Location }
    Write-CoreLog -Message ("Chainsaw finished. Output: {0}" -f $outJson) -Level INFO
    return [pscustomobject]@{ OutputPath=$outJson; StdOut=$stdout; Kind='ChainsawJson' }
}

# ----------------------------------------------------------------------------
#  Parsers  (tool output -> our plain-English finding cards, aggregated)
# ----------------------------------------------------------------------------
function Convert-ExternalLevel {
    param([string]$Level)
    switch -regex (([string]$Level).ToLower()) {
        'crit'          { return @{ Sev='Critical'; Status='Alert' } }
        'high'          { return @{ Sev='High';     Status='Review' } }
        'med'           { return @{ Sev='Medium';   Status='Review' } }
        'low'           { return @{ Sev='Low';      Status='Review' } }
        default         { return @{ Sev='Info';     Status='Info' } }
    }
}

function ConvertFrom-HayabusaCsv {
    <# Aggregates Hayabusa's CSV timeline into finding cards (one per rule, capped). #>
    param([Parameter(Mandatory)][string]$CsvPath, [int]$MaxCards = 40)
    $f = New-Object System.Collections.ArrayList
    if (-not (Test-Path $CsvPath)) {
        [void]$f.Add((New-DfirFinding -Id 'HAYA-NONE' -Category 'Hayabusa (event-log hunt)' -Title 'Hayabusa produced no output' -Severity 'Info' -Status 'Info' -What 'No results file was created. Either no detections, or the scan could not read the logs (admin needed).' -Why '' -WhatToDo 'Re-run elevated via Start.bat if you expected results.' -Evidence ''))
        return $f.ToArray()
    }
    $rows = @()
    try { $rows = Import-Csv -Path $CsvPath -ErrorAction Stop } catch { }
    if (@($rows).Count -eq 0) {
        [void]$f.Add((New-DfirFinding -Id 'HAYA-CLEAN' -Category 'Hayabusa (event-log hunt)' -Title 'Hayabusa found no detections' -Severity 'Info' -Status 'Clean' -What 'Hayabusa scanned the event logs and did not flag anything at the chosen level.' -Why '' -WhatToDo 'No action needed.' -Evidence ''))
        return $f.ToArray()
    }

    # Column names vary by profile; resolve defensively.
    $cols = $rows[0].PSObject.Properties.Name
    $colLevel = ($cols | Where-Object { $_ -match '^(Level)$' } | Select-Object -First 1)
    $colTitle = ($cols | Where-Object { $_ -match '(RuleTitle|Rule Title|^Title$)' } | Select-Object -First 1)
    $colTime  = ($cols | Where-Object { $_ -match '(Timestamp|^Time$|DateTime)' } | Select-Object -First 1)
    $colChan  = ($cols | Where-Object { $_ -match '(Channel)' } | Select-Object -First 1)
    $colEid   = ($cols | Where-Object { $_ -match '(EventID|EvtID|Event ID)' } | Select-Object -First 1)
    $colComp  = ($cols | Where-Object { $_ -match '(Computer)' } | Select-Object -First 1)
    if (-not $colTitle) { $colTitle = $cols | Select-Object -First 1 }

    # Summary card
    $byLevel = $rows | Group-Object { if ($colLevel) { $_.$colLevel } else { 'info' } }
    $sumParts = ($byLevel | Sort-Object Name | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Count }) -join ', '
    [void]$f.Add((New-DfirFinding -Id 'HAYA-SUMMARY' -Category 'Hayabusa (event-log hunt)' -Title ("Hayabusa flagged {0} event(s)" -f @($rows).Count) -Severity 'Info' -Status 'Info' `
        -What ("Hayabusa scanned your Windows event logs and matched detection rules.`nBreakdown by level - {0}" -f $sumParts) `
        -Why 'Hayabusa uses community Sigma rules + its own ruleset to spot attacker techniques recorded in the logs.' `
        -WhatToDo 'Review the high/critical items below first. Each is a rule that matched real log events.' -Evidence ("Output CSV: {0}" -f $CsvPath)))

    # One card per rule (grouped), highest severity + count first.
    $groups = $rows | Group-Object { if ($colTitle) { $_.$colTitle } else { 'Detection' } }
    $ranked = $groups | ForEach-Object {
        $lvl = if ($colLevel) { ($_.Group[0].$colLevel) } else { 'info' }
        $m = Convert-ExternalLevel $lvl
        [pscustomobject]@{ Group=$_; Title=$_.Name; Count=$_.Count; Sev=$m.Sev; Status=$m.Status; LevelRaw=$lvl }
    }
    $sevOrder = @{ 'Critical'=0;'High'=1;'Medium'=2;'Low'=3;'Info'=4 }
    $ranked = $ranked | Sort-Object @{Expression={$sevOrder[$_.Sev]}}, @{Expression={-$_.Count}}
    $shown = 0
    foreach ($r in $ranked) {
        if ($shown -ge $MaxCards) { break }
        $shown++
        $samples = $r.Group.Group | Select-Object -First 3 | ForEach-Object {
            $t = if ($colTime) { $_.$colTime } else { '' }
            $ch = if ($colChan) { $_.$colChan } else { '' }
            $eid = if ($colEid) { $_.$colEid } else { '' }
            ("  {0}  channel={1} eventID={2}" -f $t, $ch, $eid)
        }
        $ev = ($samples -join "`n")
        [void]$f.Add((New-DfirFinding -Id ("HAYA-{0}" -f $shown) -Category 'Hayabusa (event-log hunt)' -Title ("[{0}] {1}" -f $r.LevelRaw, $r.Title) -Severity $r.Sev -Status $r.Status `
            -What ("Hayabusa matched this detection {0} time(s) in your event logs." -f $r.Count) `
            -Why 'This rule corresponds to a known attacker technique or suspicious activity recorded by Windows.' `
            -WhatToDo 'Look at the sample events below. If this is not activity you recognise, investigate the affected account/time. Full details are in the Hayabusa CSV (Restore & Logs tab).' -Evidence $ev))
    }
    if (@($ranked).Count -gt $shown) {
        [void]$f.Add((New-DfirFinding -Id 'HAYA-MORE' -Category 'Hayabusa (event-log hunt)' -Title ("+ {0} more rule(s) in the full report" -f (@($ranked).Count - $shown)) -Severity 'Info' -Status 'Info' -What 'Additional lower-priority detections were truncated here.' -Why '' -WhatToDo ("Open the full CSV: {0}" -f $CsvPath) -Evidence ''))
    }
    return $f.ToArray()
}

function ConvertFrom-ChainsawJson {
    <# Aggregates Chainsaw's JSON hunt output into finding cards (one per rule). #>
    param([Parameter(Mandatory)][string]$JsonPath, [int]$MaxCards = 40)
    $f = New-Object System.Collections.ArrayList
    if (-not (Test-Path $JsonPath)) {
        [void]$f.Add((New-DfirFinding -Id 'CHAIN-NONE' -Category 'Chainsaw (event-log hunt)' -Title 'Chainsaw produced no output' -Severity 'Info' -Status 'Info' -What 'No results file was created. Either no detections, or the logs could not be read (admin needed).' -Why '' -WhatToDo 'Re-run elevated via Start.bat if you expected results.' -Evidence ''))
        return $f.ToArray()
    }
    $data = $null
    try { $data = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json -ErrorAction Stop } catch { }
    if (-not $data -or @($data).Count -eq 0) {
        [void]$f.Add((New-DfirFinding -Id 'CHAIN-CLEAN' -Category 'Chainsaw (event-log hunt)' -Title 'Chainsaw found no detections' -Severity 'Info' -Status 'Clean' -What 'Chainsaw scanned the event logs and did not flag anything.' -Why '' -WhatToDo 'No action needed.' -Evidence ''))
        return $f.ToArray()
    }

    $items = @($data)
    # Normalize each detection (fields vary across versions).
    $norm = foreach ($d in $items) {
        $name  = $null; $level = 'info'; $ts = $null
        try { if ($d.PSObject.Properties.Name -contains 'name')  { $name  = $d.name } } catch { }
        try { if (-not $name -and ($d.PSObject.Properties.Name -contains 'group')) { $name = $d.group } } catch { }
        try { if ($d.PSObject.Properties.Name -contains 'level') { $level = $d.level } } catch { }
        try { if ($d.PSObject.Properties.Name -contains 'timestamp') { $ts = $d.timestamp } } catch { }
        if (-not $name) { $name = 'Detection' }
        [pscustomobject]@{ Name=$name; Level=$level; Ts=$ts }
    }

    $byLevel = $norm | Group-Object Level
    $sumParts = ($byLevel | Sort-Object Name | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Count }) -join ', '
    [void]$f.Add((New-DfirFinding -Id 'CHAIN-SUMMARY' -Category 'Chainsaw (event-log hunt)' -Title ("Chainsaw flagged {0} detection(s)" -f $items.Count) -Severity 'Info' -Status 'Info' `
        -What ("Chainsaw searched your Windows event logs with Sigma rules.`nBreakdown by level - {0}" -f $sumParts) `
        -Why 'Chainsaw maps log events to Sigma detection rules with MITRE ATT&CK context.' `
        -WhatToDo 'Review the high/critical items below first.' -Evidence ("Output JSON: {0}" -f $JsonPath)))

    $groups = $norm | Group-Object Name
    $ranked = $groups | ForEach-Object {
        $m = Convert-ExternalLevel ($_.Group[0].Level)
        [pscustomobject]@{ Group=$_; Title=$_.Name; Count=$_.Count; Sev=$m.Sev; Status=$m.Status; LevelRaw=$_.Group[0].Level }
    }
    $sevOrder = @{ 'Critical'=0;'High'=1;'Medium'=2;'Low'=3;'Info'=4 }
    $ranked = $ranked | Sort-Object @{Expression={$sevOrder[$_.Sev]}}, @{Expression={-$_.Count}}
    $shown = 0
    foreach ($r in $ranked) {
        if ($shown -ge $MaxCards) { break }
        $shown++
        $samples = $r.Group.Group | Select-Object -First 3 | ForEach-Object { "  {0}" -f $_.Ts }
        [void]$f.Add((New-DfirFinding -Id ("CHAIN-{0}" -f $shown) -Category 'Chainsaw (event-log hunt)' -Title ("[{0}] {1}" -f $r.LevelRaw, $r.Title) -Severity $r.Sev -Status $r.Status `
            -What ("Chainsaw matched this rule {0} time(s) in your event logs." -f $r.Count) `
            -Why 'This Sigma rule corresponds to a known attacker technique recorded by Windows.' `
            -WhatToDo 'Review the sample timestamps below. If unexpected, investigate. Full details are in the Chainsaw JSON (Restore & Logs tab).' -Evidence (($samples) -join "`n")))
    }
    if (@($ranked).Count -gt $shown) {
        [void]$f.Add((New-DfirFinding -Id 'CHAIN-MORE' -Category 'Chainsaw (event-log hunt)' -Title ("+ {0} more rule(s) in the full report" -f (@($ranked).Count - $shown)) -Severity 'Info' -Status 'Info' -What 'Additional lower-priority detections were truncated here.' -Why '' -WhatToDo ("Open the full JSON: {0}" -f $JsonPath) -Evidence ''))
    }
    return $f.ToArray()
}

function Invoke-ExternalDfirScan {
    <#
      Orchestrates a full external-tool run for an ALREADY-INSTALLED tool:
      run -> parse -> return finding cards. The GUI calls this after
      Install-ExternalTool has succeeded (which itself is consent-gated).
    #>
    param([Parameter(Mandatory)][string]$Key, [string]$ExePath, [scriptblock]$Progress)
    $tool = Get-ExternalTool -Key $Key
    if (-not $tool) { throw "Unknown tool '$Key'." }
    if (-not $ExePath) { $ExePath = Test-ExternalToolInstalled -Key $Key }
    if (-not $ExePath) { throw "$($tool.Name) is not installed. Download it first." }

    # Re-verify the binary's hash against the hash recorded at INSTALL time BEFORE
    # running it elevated. Fails CLOSED: if the install manifest or the pinned exe
    # hash is missing (e.g. a non-admin planted the exe without going through our
    # verified installer), we refuse to run rather than trusting whatever is there.
    try {
        # The tools root must be admin-locked first - a user-writable location means
        # anything in it (incl. install.json / exe.sha256) could have been forged.
        if (-not (Test-ToolsRootSecure)) {
            throw "$($tool.Name) lives in a non-protected folder; refusing to run it elevated. Delete it in Restore & Logs and re-download via Pro Tools (as admin)."
        }

        $installDir  = Split-Path $ExePath -Parent
        $metaPath    = Join-Path $installDir 'install.json'
        $exeHashPath = Join-Path $installDir 'exe.sha256'

        # Fail closed when the trust anchors our installer writes are absent.
        if (-not (Test-Path $metaPath)) {
            throw "$($tool.Name) has no install manifest (install.json) - it was not installed by this tool's verified downloader. Refusing to run. Delete it in Restore & Logs and re-download."
        }
        if (-not (Test-Path $exeHashPath)) {
            throw "$($tool.Name) has no pinned executable hash (exe.sha256) - it was not installed by this tool's verified downloader. Refusing to run. Delete it in Restore & Logs and re-download."
        }

        $pinned    = (Get-Content $exeHashPath -Raw).Trim().ToUpper()
        $curExeHash = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash.ToUpper()
        if (-not $pinned) {
            throw "$($tool.Name)'s pinned hash file is empty. Refusing to run. Delete it in Restore & Logs and re-download."
        }
        if ($pinned -ne $curExeHash) {
            throw "The $($tool.Name) executable's hash changed since it was installed (possible tampering). Refusing to run. Delete it in Restore & Logs and re-download."
        }
    } catch {
        if ($Progress) { try { & $Progress ("Integrity check failed: {0}" -f $_.Exception.Message) } catch { } }
        throw
    }

    switch ($tool.OutputKind) {
        'HayabusaCsv' {
            $run = Invoke-HayabusaScan -ExePath $ExePath -Progress $Progress
            return (ConvertFrom-HayabusaCsv -CsvPath $run.OutputPath)
        }
        'ChainsawJson' {
            $run = Invoke-ChainsawScan -ExePath $ExePath -Progress $Progress
            return (ConvertFrom-ChainsawJson -JsonPath $run.OutputPath)
        }
        default { throw "No parser for output kind '$($tool.OutputKind)'." }
    }
}

