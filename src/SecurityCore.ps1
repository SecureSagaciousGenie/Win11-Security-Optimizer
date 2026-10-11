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
    Version       = '1.0.0'
    StartTime     = Get-Date
    RootPath      = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { (Get-Location).Path }
    DataPath      = $null
    LogFile       = $null
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
    <# Sets up the data/log folder. Safe to call repeatedly. #>
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
    $script:Core.LogFile      = Join-Path $DataPath ("logs\session_{0}.log"     -f $stamp)
    $script:Core.RollbackFile = Join-Path $DataPath ("backups\Rollback_{0}.ps1" -f $stamp)
    $script:Core.BackupFile   = Join-Path $DataPath ("backups\Backup_{0}.json"  -f $stamp)
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
    $block = if ($Comment) { "# $Comment`r`n$Command" } else { $Command }
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

        $asr = 0; try { $p=Get-MpPreference; if($p.AttackSurfaceReductionRules_Ids){$asr=@($p.AttackSurfaceReductionRules_Ids).Count} } catch { }
        & $add (New-Finding -Id 'DEF-ASR' -Category 'Microsoft Defender' -Name 'Attack Surface Reduction rules' -Severity 'Medium' `
            -Status $(if($asr -ge 1){'Pass'}else{'Warning'}) -Observed "$asr rule(s)" -Expected 'Key rules enabled' `
            -Detail 'Blocks common exploit behaviors (e.g. Office spawning executables).' -Advice 'Enable baseline ASR rules.' -RiskTier 'Elevated' -Fixable ($asr -lt 1))
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
    & $add (New-Finding -Id 'UAC-CONSENT' -Category 'User Account Control' -Name 'Admin consent prompt' -Severity 'Medium' `
        -Status $(if($consent -ge 2){'Pass'}else{'Warning'}) -Observed $(if($consent -ne $null){"$consent"}else{'Not set'}) -Expected '2 or 5' `
        -Detail '0 = silent elevation (weak).' -Advice 'Prompt for consent on the secure desktop.' -RiskTier 'Safe' -Fixable ($consent -ne $null -and $consent -lt 2))
    & $add (New-Finding -Id 'UAC-SECUREDESK' -Category 'User Account Control' -Name 'Prompt on secure desktop' -Severity 'Low' `
        -Status $(if($secure -eq 1){'Pass'}else{'Warning'}) -Observed $(if($secure -ne $null){"$secure"}else{'Not set'}) -Expected '1' `
        -Detail 'Stops other apps spoofing the UAC prompt.' -Advice 'Enable secure-desktop prompting.' -RiskTier 'Safe' -Fixable ($secure -ne 1))

    # ---- Legacy protocols ----
    $smb1 = $null; try { $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } catch { }
    $smb1srv = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
    $smb1on = ($smb1 -eq 'Enabled') -or ($smb1srv -eq 1)
    & $add (New-Finding -Id 'SMB1' -Category 'Legacy Protocols' -Name 'SMBv1 protocol' -Severity 'High' `
        -Status $(if($smb1on){'Fail'}else{'Pass'}) -Observed $(if($smb1){"Feature: $smb1"}elseif($smb1srv -ne $null){"reg=$smb1srv"}else{'Not present'}) -Expected 'Disabled' `
        -Detail 'SMBv1 enabled WannaCry/EternalBlue.' -Advice 'Disable SMBv1 unless a legacy NAS needs it.' -RiskTier 'Elevated' -Fixable $smb1on)

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
    $hvci = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
    & $add (New-Finding -Id 'HVCI' -Category 'Exploit Protection' -Name 'Memory Integrity (HVCI)' -Severity 'Medium' -Status $(if($hvci -eq 1){'Pass'}else{'Warning'}) -Observed $(if($hvci -ne $null){"Enabled=$hvci"}else{'Not configured'}) -Expected 'Enabled (1)' -Detail 'Protects kernel code integrity. Needs compatible drivers.' -Advice 'Enable Memory Integrity (may need driver updates).' -RiskTier 'HighRisk' -Fixable ($hvci -ne 1))

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
        'DEF-CLOUD' { return { Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop; Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue; Add-RollbackCommand 'Set-MpPreference -MAPSReporting Disabled' 'Revert cloud protection'; Add-ChangeRecord 'Enabled cloud-delivered protection' } }
        'DEF-PUA'   { return { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop; Add-RollbackCommand 'Set-MpPreference -PUAProtection Disabled' 'Revert PUA'; Add-ChangeRecord 'Enabled PUA protection' } }
        'DEF-SIG'   { return { Update-MpSignature -ErrorAction Stop; Add-ChangeRecord 'Updated Defender signatures' } }
        'DEF-ASR'   { return {
                        $rules=@('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550','D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899','5BEB7EFE-FD9A-4556-801D-275E5FFC04CC','92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B')
                        foreach($g in $rules){ Set-MpPreference -AttackSurfaceReductionRules_Ids $g -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue }
                        Add-RollbackCommand ("@('"+($rules -join "','")+"') | ForEach-Object { Set-MpPreference -AttackSurfaceReductionRules_Ids `$_ -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue }") 'Disable ASR rules'
                        Add-ChangeRecord 'Enabled baseline ASR rules' } }
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
            'HVCI'       { return ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled') -eq 1) }
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
        [pscustomobject]@{ Key='xbox';        Name='Xbox apps & Game Bar';        Publisher='Microsoft'; Category='Gaming';        AppxName='Microsoft.Xbox*';                         Recommended=$true;  Description='Xbox console companion, Game Bar overlay and related background services. Safe to remove if you do not use Xbox features; PC games still run.'; ReinstallNote='Reinstall "Xbox" from the Microsoft Store.' }
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
    try {
        Assert-SafeToChange
    } catch {
        return [pscustomobject]@{ Success=$false; Message=$_.Exception.Message }
    }
    $label = if ($FriendlyName) { $FriendlyName } else { $AppxName }
    $removedAny = $false
    $familyNames = @()
    try {
        $pkgs = Get-AppxPackage -Name $AppxName -ErrorAction SilentlyContinue
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
    <# Extracts the executable path from a Run-key command string for signing checks. #>
    param([string]$Command)
    if (-not $Command) { return $null }
    $c = $Command.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"',1)
        if ($end -gt 1) { return $c.Substring(1,$end-1) }
    }
    $space = $c.IndexOf(' ')
    if ($space -gt 0) { return $c.Substring(0,$space) }
    return $c
}

function Get-StartupItems {
    <# Read-only enumeration of startup entries. #>
    $items = New-Object System.Collections.ArrayList
    $runKeys = @(
        @{ Scope='HKLM'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
        @{ Scope='HKLM'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Scope='HKCU'; Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
        @{ Scope='HKCU'; Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Scope='HKLM'; Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' }
    )
    foreach ($rk in $runKeys) {
        if (-not (Test-Path $rk.Path)) { continue }
        try {
            $props = Get-ItemProperty -Path $rk.Path -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                $exe = ConvertTo-CommandPath -Command ([string]$p.Value)
                $sig = Get-FileSignatureInfo -Path $exe
                [void]$items.Add([pscustomobject]@{
                    Type='RegistryRun'; Scope=$rk.Scope; Location=$rk.Path; Name=$p.Name
                    Command=[string]$p.Value; ExePath=$exe; Publisher=$sig.Publisher; Signed=$sig.Signed; SignStatus=$sig.Status
                    Enabled=$true
                })
            }
        } catch { }
    }
    # Startup folders (.lnk)
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
                    Enabled=$true
                })
            }
        } catch { }
    }
    Write-CoreLog -Message ("Startup scan: {0} item(s)." -f $items.Count) -Level INFO
    return $items.ToArray()
}

function Set-StartupItemState {
    <#
      Reversibly disable/enable a startup item.
      For registry Run entries: move the value to a parallel 'AutorunsDisabled'
      store (same technique Sysinternals Autoruns uses) instead of deleting.
      For Startup-folder shortcuts: rename .lnk <-> .lnk.disabled.
      Returns @{Success;Message}.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('RegistryRun','StartupFolder')][string]$Type,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Enable,
        [string]$Command
    )
    try {
        Assert-SafeToChange
        if ($Type -eq 'RegistryRun') {
            $disabledPath = ($Location -replace '\\Run(Once)?$', '\RunDisabledByOptimizer')
            if ($Enable) {
                # move back from disabled store
                $v = Get-RegValue -Path $disabledPath -Name $Name
                if ($v -ne $null) {
                    if (-not (Test-Path $Location)) { New-Item -Path $Location -Force | Out-Null }
                    New-ItemProperty -Path $Location -Name $Name -Value $v -PropertyType String -Force | Out-Null
                    Remove-ItemProperty -Path $disabledPath -Name $Name -ErrorAction SilentlyContinue
                }
                Add-ChangeRecord "Re-enabled startup entry '$Name'"
                Add-RollbackCommand "# Re-disable startup '$Name': handled by the app's Startup tab" "startup $Name enabled"
            } else {
                $cur = Get-RegValue -Path $Location -Name $Name
                if ($cur -eq $null -and $Command) { $cur = $Command }
                if (-not (Test-Path $disabledPath)) { New-Item -Path $disabledPath -Force | Out-Null }
                New-ItemProperty -Path $disabledPath -Name $Name -Value $cur -PropertyType String -Force | Out-Null
                Remove-ItemProperty -Path $Location -Name $Name -ErrorAction SilentlyContinue
                Add-ChangeRecord "Disabled startup entry '$Name'"
                Add-RollbackCommand "if (-not (Test-Path '$Location')) { New-Item -Path '$Location' -Force | Out-Null }`r`nNew-ItemProperty -Path '$Location' -Name '$Name' -Value '$cur' -PropertyType String -Force | Out-Null`r`nRemove-ItemProperty -Path '$disabledPath' -Name '$Name' -ErrorAction SilentlyContinue" "Re-enable startup '$Name'"
            }
        } else {
            # StartupFolder
            $lnk = Join-Path $Location ($Name + '.lnk')
            $dis = $lnk + '.disabled'
            if ($Enable) {
                if (Test-Path $dis) { Rename-Item -Path $dis -NewName ($Name + '.lnk') -Force }
                Add-ChangeRecord "Re-enabled startup shortcut '$Name'"
                Add-RollbackCommand "Rename-Item -Path '$lnk' -NewName '$($Name).lnk.disabled' -Force -ErrorAction SilentlyContinue" "Re-disable '$Name'"
            } else {
                if (Test-Path $lnk) { Rename-Item -Path $lnk -NewName ($Name + '.lnk.disabled') -Force }
                Add-ChangeRecord "Disabled startup shortcut '$Name'"
                Add-RollbackCommand "Rename-Item -Path '$dis' -NewName '$($Name).lnk' -Force -ErrorAction SilentlyContinue" "Re-enable '$Name'"
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
        $adminMembers = $adminMembers | Where-Object { $_ } | Select-Object -Unique
        # Known/expected: current user, built-in Administrator, Domain Admins
        $expectedPatterns = @('*\Administrator', 'Administrator', "*\$env:USERNAME", $env:USERNAME, '*\Domain Admins', '*\Enterprise Admins')
        $unexpected = @()
        foreach ($m in $adminMembers) {
            $isExpected = $false
            foreach ($pat in $expectedPatterns) { if ($m -like $pat) { $isExpected=$true; break } }
            if (-not $isExpected) { $unexpected += $m }
        }
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
        $users = Get-LocalUser -ErrorAction Stop
        $enabled = $users | Where-Object { $_.Enabled }
        $hidden  = $users | Where-Object { $_.Name -like '*$' }   # trailing-$ hides from logon UI
        $lines = $enabled | ForEach-Object { "  {0}{1}  (last logon: {2})" -f $_.Name, $(if($_.Name -like '*$'){' [HIDDEN]'}else{''}), $(if($_.LastLogon){$_.LastLogon}else{'never'}) }
        if ($hidden.Count -gt 0) {
            & $add (New-DfirFinding -Id 'DFIR-HIDDENUSER' -Category 'Accounts & Access' -Title 'Hidden user account(s) detected' -Severity 'High' -Status 'Alert' `
                -What ("Account name(s) ending in '$' are hidden from the sign-in screen:`n  " + (($hidden|ForEach-Object{$_.Name}) -join "`n  ")) `
                -Why 'A trailing "$" hides an account from the normal logon screen. Legitimate for some service accounts, but also a classic backdoor trick.' `
                -WhatToDo 'If you did not create these, treat as suspicious. Check whether they are in the Administrators group above and investigate.' -Evidence (($hidden|ForEach-Object{$_.Name}) -join "`n"))
        }
        & $add (New-DfirFinding -Id 'DFIR-USERS' -Category 'Accounts & Access' -Title ("Enabled local accounts: {0}" -f $enabled.Count) -Severity 'Info' -Status 'Info' `
            -What ("Currently enabled local accounts:`n" + ($lines -join "`n")) -Why 'Disabled or unknown accounts that are enabled can be a sign of tampering.' -WhatToDo 'Disable any local account you do not use: Disable-LocalUser -Name "<name>".' -Evidence ($lines -join "`n"))
    } catch { }

    # ---------- 3. Startup persistence: Run keys ----------
    try {
        $startup = Get-StartupItems
        $suspicious = $startup | Where-Object {
            $_.ExePath -and ($_.ExePath -match '\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\') -or (-not $_.Signed -and $_.ExePath)
        }
        if ($suspicious) {
            $ev = ($suspicious | ForEach-Object { "  [{0}] {1} -> {2}  (signed: {3})" -f $_.Type, $_.Name, $_.Command, $_.Signed }) -join "`n"
            & $add (New-DfirFinding -Id 'DFIR-STARTUP' -Category 'Startup Persistence' -Title ("Suspicious startup entries: {0}" -f @($suspicious).Count) -Severity 'High' -Status 'Review' `
                -What ("These programs run at startup and are either unsigned or launch from a temporary/user folder:`n" + $ev) `
                -Why 'Malware persists by auto-starting. Legit software is normally signed and lives in Program Files, not Temp/AppData/Downloads.' `
                -WhatToDo 'Review each in the Startup tab. If you do not recognise it, disable it (reversible) and scan the file with Defender.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-STARTUP' -Category 'Startup Persistence' -Title 'No obviously suspicious startup entries' -Severity 'Info' -Status 'Clean' -What 'All startup entries are signed and/or run from standard locations.' -Why '' -WhatToDo 'No action needed. See the Startup tab for the full list.' -Evidence '')
        }
    } catch { }

    # ---------- 4. Scheduled tasks running from odd locations ----------
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
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
        if ($flagged.Count -gt 0) {
            $ev = ($flagged.ToArray() -join "`n")
            & $add (New-DfirFinding -Id 'DFIR-TASKS' -Category 'Startup Persistence' -Title ("Scheduled tasks worth reviewing: {0}" -f $flagged.Count) -Severity 'Medium' -Status 'Review' `
                -What ("These scheduled tasks launch scripts/interpreters or run from user/temp folders:`n" + $ev) `
                -Why 'Scheduled tasks are a common persistence method. Tasks that run PowerShell/mshta/rundll32 or execute from Temp/AppData deserve a look.' `
                -WhatToDo 'Open Task Scheduler and inspect each. Many are legitimate (updaters). Disable/delete only those you can confirm are malicious.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-TASKS' -Category 'Startup Persistence' -Title 'No scheduled tasks flagged' -Severity 'Info' -Status 'Clean' -What 'No scheduled tasks matched suspicious patterns.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch { }

    # ---------- 5. Non-Microsoft running services with unsigned/odd binaries ----------
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.State -eq 'Running' -and $_.PathName }
        $flagged = New-Object System.Collections.ArrayList
        foreach ($s in $svcs) {
            $exe = ConvertTo-CommandPath -Command ($s.PathName -replace '^"','' )
            if ($exe -match 'Temp|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\') {
                [void]$flagged.Add(("  {0}  ->  {1}" -f $s.Name, $s.PathName))
            }
        }
        if ($flagged.Count -gt 0) {
            $ev = ($flagged.ToArray() -join "`n")
            & $add (New-DfirFinding -Id 'DFIR-SVC' -Category 'Startup Persistence' -Title ("Services running from user/temp folders: {0}" -f $flagged.Count) -Severity 'High' -Status 'Review' `
                -What ("Running services whose program lives in a temporary/user folder:`n" + $ev) `
                -Why 'Legitimate services run from Program Files or System32. A service pointing into Temp/AppData is a strong malware indicator.' `
                -WhatToDo 'Investigate each service name online. Do not stop critical services blindly; confirm first.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-SVC' -Category 'Startup Persistence' -Title 'No services from suspicious paths' -Severity 'Info' -Status 'Clean' -What 'All running services launch from standard locations.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch { }

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
    } catch { }

    # ---------- 7. Listening TCP ports (exposure surface) ----------
    try {
        $listen = Get-NetTCPConnection -State Listen -ErrorAction Stop
        $rows = New-Object System.Collections.ArrayList
        $riskyPorts = @{ 3389='RDP'; 5900='VNC'; 23='Telnet'; 21='FTP'; 445='SMB'; 135='RPC'; 5985='WinRM-HTTP'; 5986='WinRM-HTTPS' }
        foreach ($conn in $listen) {
            $proc = $null; try { $proc = (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).ProcessName } catch { }
            $port = $conn.LocalPort
            $tag = if ($riskyPorts.ContainsKey([int]$port)) { " <- $($riskyPorts[[int]$port])" } else { '' }
            # Only surface non-loopback listeners (actually reachable)
            if ($conn.LocalAddress -notmatch '^(127\.|::1$)') {
                [void]$rows.Add(("  {0}:{1}  ({2}){3}" -f $conn.LocalAddress, $port, $(if($proc){$proc}else{"PID $($conn.OwningProcess)"}), $tag))
            }
        }
        $uniq = $rows.ToArray() | Select-Object -Unique
        $risky = $uniq | Where-Object { $_ -match '<-' }
        if ($risky) {
            & $add (New-DfirFinding -Id 'DFIR-PORTS' -Category 'Network Exposure' -Title ("Notable listening ports: {0}" -f @($risky).Count) -Severity 'Medium' -Status 'Review' `
                -What ("These network ports are open to other machines:`n" + ($uniq -join "`n")) `
                -Why 'Open remote-access ports (RDP/VNC/Telnet/SMB/WinRM) expand your attack surface. Unexpected ones can indicate a backdoor.' `
                -WhatToDo 'Identify the program behind each risky port. Close/firewall anything you do not need listening to the network.' -Evidence ($uniq -join "`n"))
        } else {
            & $add (New-DfirFinding -Id 'DFIR-PORTS' -Category 'Network Exposure' -Title 'No high-risk ports exposed to the network' -Severity 'Info' -Status 'Clean' -What (("Network-facing listeners:`n" + ($uniq -join "`n")).Trim()) -Why '' -WhatToDo 'No action needed.' -Evidence ($uniq -join "`n"))
        }
    } catch { }

    # ---------- 8. Non-default SMB shares ----------
    try {
        $shares = Get-SmbShare -ErrorAction Stop
        $default = @('ADMIN$','C$','D$','E$','IPC$','print$')
        $custom = $shares | Where-Object { $default -notcontains $_.Name }
        if ($custom) {
            $ev = ($custom | ForEach-Object { "  {0}  ->  {1}" -f $_.Name, $_.Path }) -join "`n"
            & $add (New-DfirFinding -Id 'DFIR-SMB' -Category 'Network Exposure' -Title ("Custom file shares: {0}" -f @($custom).Count) -Severity 'Medium' -Status 'Review' `
                -What ("Folders shared on the network:`n" + $ev) `
                -Why 'Shared folders let other machines read/write files. A share you did not create can mean data exposure or an attacker foothold.' `
                -WhatToDo 'Remove shares you do not recognise: Remove-SmbShare -Name "<name>". Confirm first.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-SMB' -Category 'Network Exposure' -Title 'Only default administrative shares present' -Severity 'Info' -Status 'Clean' -What 'No custom network shares found.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch { }

    # ---------- 9. Defender exclusions (classic attacker move) ----------
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $exPath = @($pref.ExclusionPath); $exProc = @($pref.ExclusionProcess); $exExt = @($pref.ExclusionExtension)
        $total = ($exPath + $exProc + $exExt | Where-Object { $_ }).Count
        if ($total -gt 0) {
            $ev = @()
            if ($exPath -and $exPath[0]) { $ev += ('Paths:`n  ' + ($exPath -join "`n  ")) }
            if ($exProc -and $exProc[0]) { $ev += ('Processes:`n  ' + ($exProc -join "`n  ")) }
            if ($exExt  -and $exExt[0])  { $ev += ('Extensions:`n  ' + ($exExt -join "`n  ")) }
            $evStr = ($ev -join "`n") -replace '`n', "`n"
            & $add (New-DfirFinding -Id 'DFIR-DEFEXCL' -Category 'Tampering Indicators' -Title ("Microsoft Defender has {0} exclusion(s)" -f $total) -Severity 'High' -Status 'Review' `
                -What ("Defender is told to SKIP scanning these:`n" + $evStr) `
                -Why 'Attackers add Defender exclusions so their malware is never scanned. Exclusions you did not set are a red flag.' `
                -WhatToDo 'Review each. Remove any you do not recognise in Windows Security > Virus & threat protection > Exclusions.' -Evidence $evStr)
        } else {
            & $add (New-DfirFinding -Id 'DFIR-DEFEXCL' -Category 'Tampering Indicators' -Title 'No Defender exclusions set' -Severity 'Info' -Status 'Clean' -What 'Defender is scanning everything (no exclusions).' -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch {
        & $add (New-DfirFinding -Id 'DFIR-DEFEXCL' -Category 'Tampering Indicators' -Title 'Could not read Defender exclusions' -Severity 'Info' -Status 'Info' -What $_.Exception.Message -Why '' -WhatToDo 'Run as Administrator for this check.' -Evidence '')
    }

    # ---------- 10. Hosts file tampering ----------
    try {
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if (Test-Path $hostsPath) {
            $lines = Get-Content $hostsPath -ErrorAction Stop
            $entries = $lines | Where-Object { $_ -and ($_ -notmatch '^\s*#') -and ($_ -match '\S') }
            # Flag redirects of known security/update domains or unusual volume
            $sketchy = $entries | Where-Object { $_ -match 'microsoft|windowsupdate|defender|google|bank|antivirus|mcafee|norton|update' }
            if ($sketchy) {
                $ev = ($sketchy -join "`n")
                & $add (New-DfirFinding -Id 'DFIR-HOSTS' -Category 'Tampering Indicators' -Title 'Hosts file redirects security/update domains' -Severity 'High' -Status 'Alert' `
                    -What ("The hosts file contains entries that redirect well-known domains:`n" + $ev) `
                    -Why 'Malware edits the hosts file to block antivirus/Windows Update or redirect banking/search sites to fake servers.' `
                    -WhatToDo 'Review these lines. Unless you added them deliberately, remove them (edit as admin). The file is at ' + $hostsPath + '.' -Evidence $ev)
            } elseif (@($entries).Count -gt 0) {
                & $add (New-DfirFinding -Id 'DFIR-HOSTS' -Category 'Tampering Indicators' -Title ("Hosts file has {0} custom entr(y/ies)" -f @($entries).Count) -Severity 'Low' -Status 'Review' `
                    -What ("Active hosts-file entries:`n  " + ($entries -join "`n  ")) -Why 'Custom hosts entries can be legitimate (dev work) or malicious.' -WhatToDo 'Confirm you recognise these mappings.' -Evidence ($entries -join "`n"))
            } else {
                & $add (New-DfirFinding -Id 'DFIR-HOSTS' -Category 'Tampering Indicators' -Title 'Hosts file is clean' -Severity 'Info' -Status 'Clean' -What 'No custom hosts entries.' -Why '' -WhatToDo 'No action needed.' -Evidence '')
            }
        }
    } catch { }

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
        if ($exe -and $exe -match '\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\|\\\$Recycle') {
            $sig = & $getSig $exe
            $signText = if ($sig -and $sig.Signed) { "signed: $($sig.Publisher)" } else { 'UNSIGNED' }
            [void]$badPath.Add(("  {0} (PID {1}) -> {2}  ({3})" -f $name, $procId, $exe, $signText))
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
                '(?i)(IEX|Invoke-Expression)\b.*(DownloadString|DownloadData|Net\.WebClient|Invoke-WebRequest|iwr|curl|wget)' { $hit = 'download-and-execute cradle (fileless malware pattern)'; $hitSev='Alert'; break }
                '(?i)\b(mshta|regsvr32|rundll32)\b.*(http|\\\\|scrobj|javascript:)' { $hit = 'system tool loading remote/script content (LOLBin abuse)'; $hitSev='Alert'; break }
                '(?i)\b(certutil)\b.*(-urlcache|-decode|-f\s)'  { $hit = 'certutil used to download/decode a file (common malware trick)'; $hitSev='Review'; break }
                '(?i)\b(bitsadmin)\b.*(/transfer|/create)'      { $hit = 'bitsadmin used to fetch files from the internet'; $hitSev='Review'; break }
                '(?i)FromBase64String'                        { $hit = 'base64-decoded payload in the command line'; $hitSev='Review'; break }
                '(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{24,}' { $hit = 'encoded PowerShell command (-EncodedCommand) - note: also used by many LEGITIMATE management tools'; $hitSev='Review'; break }
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
            -What ("These programs are running from folders malware often hides in (Temp, AppData, Downloads, ProgramData):`n" + $ev) `
            -Why 'Legitimate software usually runs from Program Files. Things running from Temp/AppData/Downloads are more suspicious - especially if UNSIGNED.' `
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

    $queryEvents = {
        param($LogName, $Ids, $MaxEvents = 400)
        try {
            return Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$Ids; StartTime=$after } -MaxEvents $MaxEvents -ErrorAction Stop
        } catch { return $null }
    }

    $secDenied = $false

    # ---- Audit log cleared (very strong tamper signal) ----
    try {
        $cleared = & $queryEvents 'Security' 1102 50
        if ($cleared -eq $null) {
            # distinguish "no events" from "access denied" by probing
            try { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null } catch { $secDenied = $true }
        }
        if ($cleared) {
            $ev = ($cleared | ForEach-Object { "  {0} - security log cleared" -f $_.TimeCreated }) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-CLEARED-SEC' -Category 'Event Log' -Title 'Security log was cleared' -Severity 'Critical' -Status 'Alert' `
                -What ("The Windows Security audit log was wiped:`n" + $ev) `
                -Why 'Clearing the security log is a deliberate act to destroy evidence. Windows does not do this on its own. This strongly suggests someone is covering their tracks.' `
                -WhatToDo 'If you did not clear it yourself, treat this PC as potentially compromised. Preserve the machine and seek expert help if it holds important data.' -Evidence $ev)
        }
    } catch { }

    # ---- System log cleared ----
    try {
        $sysClear = & $queryEvents 'System' 104 50
        if ($sysClear) {
            $ev = ($sysClear | ForEach-Object { "  {0} - {1}" -f $_.TimeCreated, ($_.Message -split "`n")[0] }) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-CLEARED-SYS' -Category 'Event Log' -Title 'System log was cleared' -Severity 'High' -Status 'Review' `
                -What ("The System event log was cleared:`n" + $ev) -Why 'Can be routine maintenance, but is also used to hide driver/service tampering.' -WhatToDo 'Confirm whether you or an admin tool cleared it. If not, investigate alongside the other findings.' -Evidence $ev)
        }
    } catch { }

    # ---- New service installed (persistence) ----
    try {
        $svc = @()
        $svc += (& $queryEvents 'System' 7045 200)
        $svc = $svc | Where-Object { $_ }
        if ($svc.Count -gt 0) {
            $ev = ($svc | ForEach-Object {
                $m = $_.Message -replace "`r?`n", ' '
                "  {0}: {1}" -f $_.TimeCreated, ($m.Substring(0,[Math]::Min(160,$m.Length)))
            }) -join "`n"
            $sev = if ($svc.Count -ge 1) { 'Medium' } else { 'Info' }
            & $add (New-DfirFinding -Id 'EVT-NEWSVC' -Category 'Event Log' -Title ("New service(s) installed recently: {0}" -f $svc.Count) -Severity $sev -Status 'Review' `
                -What ("These Windows services were installed in the last $Days days:`n" + $ev) `
                -Why 'Installing a service is a common way malware stays running after reboot. Many are legitimate (apps, updates, drivers) - but attackers hide here too.' `
                -WhatToDo 'Recognise your recent installs? Then fine. An unfamiliar service - especially one running from Temp/AppData or with a random name - should be investigated.' -Evidence $ev)
        }
    } catch { }

    # ---- Account created / added to admins ----
    try {
        $acct = New-Object System.Collections.ArrayList
        foreach ($e in @(& $queryEvents 'Security' @(4720) 200)) { if ($e) { [void]$acct.Add("  {0} - new local user account created" -f $e.TimeCreated) } }
        foreach ($e in @(& $queryEvents 'Security' @(4732,4728) 200)) {
            if ($e) {
                $m = ($e.Message -split "`n" | Where-Object { $_ -match 'Group Name|Member|Account Name' } | Select-Object -First 3) -join '; '
                [void]$acct.Add(("  {0} - account added to a group  {1}" -f $e.TimeCreated, $m.Trim()))
            }
        }
        if ($acct.Count -gt 0) {
            $ev = ($acct.ToArray()) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-ACCT' -Category 'Event Log' -Title ("Account changes in the last $Days days: {0}" -f $acct.Count) -Severity 'High' -Status 'Review' `
                -What ("New accounts and/or privilege-group changes:`n" + $ev) `
                -Why 'Attackers create accounts or add themselves to Administrators to keep access. If you did not make these changes, it is a red flag.' `
                -WhatToDo 'Cross-check with the "Investigate" account findings. Remove or disable any account you did not create.' -Evidence $ev)
        }
    } catch { }

    # ---- Brute force: many failed logons ----
    try {
        $failed = @(& $queryEvents 'Security' 4625 1000)
        $failed = $failed | Where-Object { $_ }
        if ($failed.Count -ge 10) {
            $sev = if ($failed.Count -ge 50) { 'High' } else { 'Medium' }
            & $add (New-DfirFinding -Id 'EVT-BRUTE' -Category 'Event Log' -Title ("Many failed sign-in attempts: {0}" -f $failed.Count) -Severity $sev -Status 'Review' `
                -What ("There were {0} failed logon attempts in the last {1} days (first seen {2})." -f $failed.Count, $Days, ($failed[-1].TimeCreated)) `
                -Why 'A burst of failed logons can mean someone (or a bot) is trying to guess a password - common when RDP or an account is exposed to the internet.' `
                -WhatToDo 'If this PC exposes Remote Desktop, consider disabling it (Security tab) or ensure strong passwords + account lockout. A few failures from your own typos are normal.' -Evidence ("Failed logon events: {0}" -f $failed.Count))
        }
    } catch { }

    # ---- Account lockouts ----
    try {
        $lock = @(& $queryEvents 'Security' 4740 100) | Where-Object { $_ }
        if ($lock.Count -gt 0) {
            & $add (New-DfirFinding -Id 'EVT-LOCKOUT' -Category 'Event Log' -Title ("Account lockout(s): {0}" -f $lock.Count) -Severity 'Medium' -Status 'Review' `
                -What ("An account was locked out {0} time(s) recently." -f $lock.Count) -Why 'Lockouts often accompany password-guessing attacks.' -WhatToDo 'If unexpected, review which account and whether RDP/network access is exposed.' -Evidence ("Lockout events: {0}" -f $lock.Count))
        }
    } catch { }

    # ---- Defender detections ----
    try {
        $det = @()
        $det += (& $queryEvents 'Microsoft-Windows-Windows Defender/Operational' @(1116,1117) 200)
        $det = $det | Where-Object { $_ }
        if ($det.Count -gt 0) {
            $ev = ($det | Select-Object -First 15 | ForEach-Object {
                $threat = ($_.Message -split "`n" | Where-Object { $_ -match 'Name:|Threat' } | Select-Object -First 1)
                "  {0} - {1}" -f $_.TimeCreated, ($threat -replace '\s+',' ').Trim()
            }) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-DEFENDER' -Category 'Event Log' -Title ("Microsoft Defender detected threats: {0}" -f $det.Count) -Severity 'High' -Status 'Review' `
                -What ("Defender logged {0} detection event(s) in the last {1} days:`n{2}" -f $det.Count, $Days, $ev) `
                -Why 'Defender already caught something. Usually it also blocked/quarantined it, but repeated detections can mean something keeps trying to run.' `
                -WhatToDo 'Open Windows Security > Protection history to see if each item was successfully removed. Run a full offline scan if detections keep recurring.' -Evidence $ev)
        } else {
            & $add (New-DfirFinding -Id 'EVT-DEFENDER' -Category 'Event Log' -Title 'No Defender detections recently' -Severity 'Info' -Status 'Clean' -What ("No Defender threat detections in the last $Days days.") -Why '' -WhatToDo 'No action needed.' -Evidence '')
        }
    } catch { }

    # ---- Scheduled task created ----
    try {
        $task = @(& $queryEvents 'Security' 4698 100) | Where-Object { $_ }
        if ($task.Count -gt 0) {
            $ev = ($task | ForEach-Object { $tn = ($_.Message -split "`n" | Where-Object { $_ -match 'Task Name' } | Select-Object -First 1); "  {0} - {1}" -f $_.TimeCreated, ($tn -replace '\s+',' ').Trim() }) -join "`n"
            & $add (New-DfirFinding -Id 'EVT-TASK' -Category 'Event Log' -Title ("Scheduled task(s) created: {0}" -f $task.Count) -Severity 'Medium' -Status 'Review' `
                -What ("New scheduled tasks in the last $Days days:`n" + $ev) -Why 'Scheduled tasks are a favourite persistence trick. Legit apps make them too.' -WhatToDo 'Match against software you installed. Investigate unfamiliar ones in Task Scheduler.' -Evidence $ev)
        }
    } catch { }

    # ---- RDP interactive logons (type 10) ----
    try {
        $rdp = @(& $queryEvents 'Security' 4624 1000) | Where-Object { $_ -and ($_.Message -match 'Logon Type:\s*10') }
        if ($rdp.Count -gt 0) {
            & $add (New-DfirFinding -Id 'EVT-RDPLOGON' -Category 'Event Log' -Title ("Remote Desktop logons: {0}" -f $rdp.Count) -Severity 'Medium' -Status 'Review' `
                -What ("There were {0} successful Remote Desktop sign-ins in the last {1} days." -f $rdp.Count, $Days) `
                -Why 'If you use RDP yourself this is expected. If you do NOT remote into this PC, someone else did.' `
                -WhatToDo 'If these are not you, disable RDP (Security tab) and change passwords immediately.' -Evidence ("RDP logon events: {0}" -f $rdp.Count))
        }
    } catch { }

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
#  WHY THIS DESIGN (licensing): Hayabusa and Chainsaw are GPL-3.0. Bundling them
#  would force this whole MIT project to become GPL. Instead the END USER fetches
#  them at runtime after an explicit consent screen (vendor, license, source URL,
#  version, size). We only INVOKE them as separate processes and read their
#  output - we never redistribute them - so this project stays MIT. See
#  docs/DFIR-TOOLS.md and THIRD-PARTY-NOTICES.md.
#
#  SAFETY:
#   * Nothing downloads or runs unless the user clicks through consent.
#   * Downloads come only from api.github.com / github.com release assets of the
#     official repositories, over TLS 1.2+.
#   * The archive is verified (zip magic bytes), its SHA-256 is computed, logged
#     and shown to the user, the binary's --version is checked after extraction.
#   * The tools are run strictly READ-ONLY against the local event logs.
#   * Everything lives under %LOCALAPPDATA%\Win11SecurityOptimizer\tools and can
#     be deleted anytime (Restore & Logs tab / "Remove downloaded tools").
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
    $root = Join-Path $script:Core.DataPath 'tools'
    if (-not (Test-Path $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    return $root
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

    try {
        if (-not $Resolution) { $Resolution = Resolve-ExternalToolRelease -Key $Key }

        # Already installed?
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
            throw 'Downloaded file is not a valid ZIP archive (unexpected content). Aborting for safety.'
        }

        # SHA-256 for the record / user display.
        $sha = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
        & $report ("SHA-256: {0}" -f $sha)

        & $report 'Extracting...'
        Expand-Archive -Path $zipPath -DestinationPath $installPath -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue   # keep only the extracted tool

        $exe = Find-ExternalToolExe -InstallPath $installPath -ExePattern $tool.ExePattern
        if (-not $exe) { throw "Extraction succeeded but no executable matching '$($tool.ExePattern)' was found." }

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

        # Record install metadata.
        $meta = [pscustomobject]@{
            Key=$Key; Name=$tool.Name; Version=$Resolution.Version; Vendor=$tool.Vendor; License=$tool.License
            Source=$Resolution.DownloadUrl; Sha256=$sha; Exe=$exe; VersionText=$verText; InstalledAt=(Get-Date -Format o)
        }
        try { $meta | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $installPath 'install.json') -Encoding UTF8 } catch { }
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

