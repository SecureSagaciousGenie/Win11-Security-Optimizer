<#
    Hardening.ps1
    Author: Ahmad Shaukat
    Credential-theft hardening checks and fixes, registered into the Security
    scan through the extension hooks in SecurityCore.ps1. Checks are read-only.
    Every fix uses the tracked setters, adds a rollback entry, is idempotent and
    runs on the main thread through Invoke-SecurityFix.
    Dot-sourced by SecurityCore.ps1.
#>

$script:HardenCategory = 'Credential theft'
$script:LsaKey     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:WDigestKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$script:NetBtKey   = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$script:DnsKey     = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
$script:PsV2Feature = 'MicrosoftWindowsPowerShellV2Root'
# DISM "feature name is unknown" (0x800F080C): the feature does not exist on this build.
$script:HResultUnknownFeature = -2146498548

function Read-RegistryValue {
    <# Strict registry read: @{ Exists; Value }. Unlike Get-RegValue it throws
       when the key cannot be read, so "unreadable" never looks like "absent". #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Exists = $false; Value = $null } }
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    if ($item.PSObject.Properties.Name -contains $Name) { return [pscustomobject]@{ Exists = $true; Value = $item.$Name } }
    return [pscustomobject]@{ Exists = $false; Value = $null }
}

function Get-OsBuildNumber {
    <# Windows build number from the registry (CurrentBuildNumber), 0 if unknown. #>
    $b = 0
    $v = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber'
    [void][int]::TryParse([string]$v, [ref]$b)
    return $b
}

function New-HardenErrorFinding {
    param([string]$Id, [string]$Name, [string]$Message, [string]$Tier = 'AuditOnly')
    New-Finding -Id $Id -Category $script:HardenCategory -Name $Name -Severity 'Info' -Status 'Error' -Observed 'Could not read' -Expected '' `
        -Detail ("This check could not run: {0}" -f $Message) -Advice 'Re-run as Administrator. If it keeps failing, note it as a tool issue.' -RiskTier $Tier
}

# ---------------------------------------------------------------- LSA-PPL
function Get-LsaPplFinding {
    $name = 'LSA protection (RunAsPPL)'
    try { $r = Read-RegistryValue -Path $script:LsaKey -Name 'RunAsPPL' } catch { return (New-HardenErrorFinding -Id 'LSA-PPL' -Name $name -Message $_.Exception.Message -Tier 'HighRisk') }
    $val = if ($r.Exists) { [string]$r.Value } else { '' }
    $ok = ($val -eq '1' -or $val -eq '2')
    $build = Get-OsBuildNumber
    $fixable = (-not $ok) -and ($build -ge 22621)
    $advice = if ($ok) { '' } elseif ($build -ge 22621) { 'Turn on LSA protection (no UEFI lock, so it can be undone). Needs a restart. Some antivirus and LSA plug-ins stop working; check with your vendors first.' } else { ('This Windows build ({0}) is older than 22H2 (22621), where LSA protection without a UEFI lock is supported. Update Windows, then turn it on.' -f $build) }
    New-Finding -Id 'LSA-PPL' -Category $script:HardenCategory -Name $name -Severity 'High' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -Observed $(if ($r.Exists) { "RunAsPPL=$val" } else { 'Not set' }) -Expected '1 or 2' `
        -Detail 'Runs the process that holds your passwords (LSASS) as a protected process, so credential-dumping tools such as Mimikatz cannot read its memory.' `
        -Advice $advice -RiskTier 'HighRisk' -Fixable $fixable
}
function Invoke-LsaPplFix {
    if ((Get-OsBuildNumber) -lt 22621) { throw 'LSA protection without a UEFI lock needs Windows 11 22H2 (build 22621) or later. Nothing was changed.' }
    $r = Read-RegistryValue -Path $script:LsaKey -Name 'RunAsPPL'
    if ($r.Exists -and ([string]$r.Value -eq '1' -or [string]$r.Value -eq '2')) { return }
    Set-RegValueTracked -Path $script:LsaKey -Name 'RunAsPPL' -Value 2 -Type DWord
}
function Test-LsaPplApplied {
    $r = Read-RegistryValue -Path $script:LsaKey -Name 'RunAsPPL'
    return ($r.Exists -and ([string]$r.Value -eq '1' -or [string]$r.Value -eq '2'))
}

# ---------------------------------------------------------------- CRED-GUARD
function Get-CredGuardFinding {
    $name = 'Credential Guard'
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
    } catch { return (New-HardenErrorFinding -Id 'CRED-GUARD' -Name $name -Message $_.Exception.Message) }
    $running = @()
    if ($dg -and ($dg.PSObject.Properties.Name -contains 'SecurityServicesRunning')) { $running = @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ }) }
    $ok = $running -contains 1
    New-Finding -Id 'CRED-GUARD' -Category $script:HardenCategory -Name $name -Severity 'Medium' -Status $(if ($ok) { 'Pass' } else { 'Warning' }) `
        -Observed $(if ($ok) { 'Running' } else { 'Not running' }) -Expected 'Running' `
        -Detail 'Credential Guard isolates stored sign-in secrets in a virtualised area that even admin-level malware cannot read.' `
        -Advice $(if ($ok) { '' } else { 'Needs Windows 11 Enterprise or Education and a PC with virtualisation-based security. On supported editions it can be turned on through Group Policy or Intune; this tool does not change it.' }) `
        -RiskTier 'AuditOnly' -Fixable $false
}

# ---------------------------------------------------------------- WDIGEST
function Get-WDigestFinding {
    $name = 'WDigest plain-text password caching'
    try { $r = Read-RegistryValue -Path $script:WDigestKey -Name 'UseLogonCredential' } catch { return (New-HardenErrorFinding -Id 'WDIGEST' -Name $name -Message $_.Exception.Message -Tier 'Safe') }
    $ok = (-not $r.Exists) -or ([string]$r.Value -eq '0')
    New-Finding -Id 'WDIGEST' -Category $script:HardenCategory -Name $name -Severity 'High' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -Observed $(if ($r.Exists) { "UseLogonCredential=$($r.Value)" } else { 'Not set (off)' }) -Expected 'Not set or 0' `
        -Detail 'When on, Windows keeps your password in memory in plain text, where credential-dumping tools can read it. Attackers turn it on.' `
        -Advice $(if ($ok) { '' } else { 'Turn WDigest caching off.' }) -RiskTier 'Safe' -Fixable (-not $ok)
}
function Invoke-WDigestFix {
    $r = Read-RegistryValue -Path $script:WDigestKey -Name 'UseLogonCredential'
    if ((-not $r.Exists) -or ([string]$r.Value -eq '0')) { return }
    Set-RegValueTracked -Path $script:WDigestKey -Name 'UseLogonCredential' -Value 0 -Type DWord
}
function Test-WDigestApplied {
    $r = Read-RegistryValue -Path $script:WDigestKey -Name 'UseLogonCredential'
    return ((-not $r.Exists) -or ([string]$r.Value -eq '0'))
}

# ---------------------------------------------------------------- PSV2
function Get-PsV2State {
    <# 'Absent', 'Disabled', 'Enabled' or another DISM state. Throws when the
       feature list cannot be read. #>
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $script:PsV2Feature -ErrorAction Stop
    } catch {
        if ($_.Exception.HResult -eq $script:HResultUnknownFeature) { return 'Absent' }
        throw
    }
    if (-not $f) { return 'Absent' }
    return [string](@($f)[0].State)
}
function Get-PsV2Finding {
    $name = 'Windows PowerShell 2.0'
    if (-not (Test-IsAdmin)) {
        return (New-Finding -Id 'PSV2' -Category $script:HardenCategory -Name $name -Severity 'Info' -Status 'Info' -Observed 'Needs administrator to read' -Expected 'Removed or disabled' `
            -Detail 'Windows only lists optional features to administrators.' -Advice 'Relaunch via Start.bat to include this check.' -RiskTier 'Elevated')
    }
    try { $state = Get-PsV2State } catch { return (New-HardenErrorFinding -Id 'PSV2' -Name $name -Message $_.Exception.Message -Tier 'Elevated') }
    $ok = ($state -eq 'Absent' -or $state -like 'Disabled*')
    New-Finding -Id 'PSV2' -Category $script:HardenCategory -Name $name -Severity 'Medium' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -Observed $state -Expected 'Removed or disabled' `
        -Detail 'PowerShell 2.0 has none of the logging and anti-malware scanning of modern PowerShell. Attackers start it to run scripts unseen.' `
        -Advice $(if ($ok) { '' } else { 'Turn the PowerShell 2.0 feature off. A restart may be needed.' }) -RiskTier 'Elevated' -Fixable (-not $ok)
}
function Invoke-PsV2Fix {
    $state = Get-PsV2State
    if ($state -eq 'Absent' -or $state -like 'Disabled*') { return }
    Disable-WindowsOptionalFeature -Online -FeatureName $script:PsV2Feature -NoRestart -ErrorAction Stop | Out-Null
    Add-RollbackCommand ("Enable-WindowsOptionalFeature -Online -FeatureName '{0}' -All -NoRestart | Out-Null" -f $script:PsV2Feature) 'Re-enable Windows PowerShell 2.0'
    Add-ChangeRecord 'Disabled the Windows PowerShell 2.0 feature (restart may be needed)'
}
function Test-PsV2Applied {
    $state = Get-PsV2State
    return ($state -eq 'Absent' -or $state -like 'Disabled*')
}

# ---------------------------------------------------------------- NBTNS
function Get-NetBtInterface {
    <# NetBT interface keys (Tcpip_{GUID}) with their NetbiosOptions. Only names
       matching the GUID pattern are returned, so a key name can be embedded in
       the rollback script safely. #>
    $out = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $script:NetBtKey)) { return @() }
    foreach ($k in @(Get-ChildItem -LiteralPath $script:NetBtKey -ErrorAction Stop)) {
        $leaf = [string]$k.PSChildName
        if ($leaf -notmatch '^Tcpip_\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') { continue }
        $path = $script:NetBtKey + '\' + $leaf
        $r = Read-RegistryValue -Path $path -Name 'NetbiosOptions'
        [void]$out.Add([pscustomobject]@{ Name = $leaf; Path = $path; Value = $(if ($r.Exists) { [string]$r.Value } else { '' }) })
    }
    return @($out.ToArray())
}
function Get-NbtNsFinding {
    $name = 'NetBIOS over TCP/IP name resolution'
    try { $ifs = @(Get-NetBtInterface) } catch { return (New-HardenErrorFinding -Id 'NBTNS' -Name $name -Message $_.Exception.Message -Tier 'Elevated') }
    $bad = @($ifs | Where-Object { $_.Value -ne '2' })
    $ok = ($bad.Count -eq 0)
    New-Finding -Id 'NBTNS' -Category $script:HardenCategory -Name $name -Severity 'Medium' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -Observed $(if ($ifs.Count -eq 0) { 'No NetBIOS interfaces' } elseif ($ok) { "Off on all $($ifs.Count) interface(s)" } else { "On for $($bad.Count) of $($ifs.Count) interface(s)" }) -Expected 'Off (NetbiosOptions=2) on every interface' `
        -Detail 'NetBIOS name queries can be answered by any machine on the network. Tools like Responder answer them to capture password hashes.' `
        -Advice $(if ($ok) { '' } else { 'Turn NetBIOS over TCP/IP off on every network interface. Very old file shares or printers that need NetBIOS names may stop being found.' }) `
        -RiskTier 'Elevated' -Fixable (-not $ok)
}
function Invoke-NbtNsFix {
    foreach ($i in @(Get-NetBtInterface)) {
        if ($i.Value -eq '2') { continue }
        Set-RegValueTracked -Path $i.Path -Name 'NetbiosOptions' -Value 2 -Type DWord
    }
}
function Test-NbtNsApplied {
    return (@(Get-NetBtInterface | Where-Object { $_.Value -ne '2' }).Count -eq 0)
}

# ---------------------------------------------------------------- MDNS
function Get-MdnsFinding {
    $name = 'Multicast DNS (mDNS)'
    try { $r = Read-RegistryValue -Path $script:DnsKey -Name 'EnableMDNS' } catch { return (New-HardenErrorFinding -Id 'MDNS' -Name $name -Message $_.Exception.Message -Tier 'Elevated') }
    $ok = ($r.Exists -and [string]$r.Value -eq '0')
    New-Finding -Id 'MDNS' -Category $script:HardenCategory -Name $name -Severity 'Low' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -Observed $(if ($r.Exists) { "EnableMDNS=$($r.Value)" } else { 'Not set (on)' }) -Expected '0' `
        -Detail 'Like LLMNR and NetBIOS, mDNS name queries can be answered by an attacker on the same network to capture password hashes.' `
        -Advice $(if ($ok) { '' } else { 'Turn mDNS off. Casting to TVs and finding some printers automatically may stop working.' }) -RiskTier 'Elevated' -Fixable (-not $ok)
}
function Invoke-MdnsFix {
    $r = Read-RegistryValue -Path $script:DnsKey -Name 'EnableMDNS'
    if ($r.Exists -and [string]$r.Value -eq '0') { return }
    Set-RegValueTracked -Path $script:DnsKey -Name 'EnableMDNS' -Value 0 -Type DWord
}
function Test-MdnsApplied {
    $r = Read-RegistryValue -Path $script:DnsKey -Name 'EnableMDNS'
    return ($r.Exists -and [string]$r.Value -eq '0')
}

# ---------------------------------------------------------------- SMB-SIGN
function Get-SmbSigningState {
    $srv = Get-SmbServerConfiguration -ErrorAction Stop
    $cli = Get-SmbClientConfiguration -ErrorAction Stop
    return [pscustomobject]@{ Server = [bool]$srv.RequireSecuritySignature; Client = [bool]$cli.RequireSecuritySignature }
}
function Get-SmbSignFinding {
    $name = 'SMB signing required'
    try { $st = Get-SmbSigningState } catch { return (New-HardenErrorFinding -Id 'SMB-SIGN' -Name $name -Message $_.Exception.Message -Tier 'Elevated') }
    $ok = $st.Server -and $st.Client
    New-Finding -Id 'SMB-SIGN' -Category $script:HardenCategory -Name $name -Severity 'Medium' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -Observed ("Server: {0}, client: {1}" -f $(if ($st.Server) { 'required' } else { 'not required' }), $(if ($st.Client) { 'required' } else { 'not required' })) -Expected 'Required for both' `
        -Detail 'Without signing, an attacker on the network can relay your sign-in to another machine and act as you (NTLM relay).' `
        -Advice $(if ($ok) { '' } else { 'Require SMB signing for both directions. Some old NAS boxes and printers that cannot sign will stop working.' }) -RiskTier 'Elevated' -Fixable (-not $ok)
}
function Invoke-SmbSignFix {
    $st = Get-SmbSigningState
    if (-not $st.Server) {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
        Add-RollbackCommand 'Set-SmbServerConfiguration -RequireSecuritySignature $false -Force' 'Restore SMB server signing to not required'
        Add-ChangeRecord 'Required SMB signing on the SMB server'
    }
    if (-not $st.Client) {
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
        Add-RollbackCommand 'Set-SmbClientConfiguration -RequireSecuritySignature $false -Force' 'Restore SMB client signing to not required'
        Add-ChangeRecord 'Required SMB signing on the SMB client'
    }
}
function Test-SmbSignApplied {
    $st = Get-SmbSigningState
    return ($st.Server -and $st.Client)
}

# ---------------------------------------------------------------- PATCH-AGE
# Windows Update category IDs. Definition updates arrive daily and drivers are
# not OS patches, so neither may make an unpatched PC look current.
$script:WuCategoryDefinitions = 'e0789628-ce08-4437-be74-2495b842f43b'
$script:WuCategoryDrivers     = 'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0'

function Get-UpdateHistory {
    <# Windows Update install history through Microsoft.Update.Session:
       Date (UTC), ResultCode (2 = succeeded), Operation (1 = install), Title
       and category IDs. Throws when the history cannot be read. #>
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $count = [int]$searcher.GetTotalHistoryCount()
    $out = New-Object System.Collections.ArrayList
    if ($count -le 0) { return @() }
    foreach ($e in @($searcher.QueryHistory(0, $count))) {
        $cats = @()
        try { foreach ($c in @($e.Categories)) { $cats += ([string]$c.CategoryID).ToLowerInvariant() } } catch { $cats = @() }
        # IUpdateHistoryEntry.Date is UTC; mark it so ToUniversalTime does not shift it.
        [void]$out.Add([pscustomobject]@{ Date = [datetime]::SpecifyKind([datetime]$e.Date, [System.DateTimeKind]::Utc); ResultCode = [int]$e.ResultCode; Operation = [int]$e.Operation; Title = [string]$e.Title; CategoryIds = $cats })
    }
    return @($out.ToArray())
}
function Get-PatchAgeFinding {
    param([datetime]$Now = (Get-Date).ToUniversalTime())
    $name = 'Days since the last Windows update'
    try { $hist = @(Get-UpdateHistory) } catch { return (New-HardenErrorFinding -Id 'PATCH-AGE' -Name $name -Message $_.Exception.Message) }
    $ok = @($hist | Where-Object {
        $_.ResultCode -eq 2 -and $_.Operation -eq 1 -and
        ($_.CategoryIds -notcontains $script:WuCategoryDefinitions) -and ($_.CategoryIds -notcontains $script:WuCategoryDrivers) -and
        ($_.Title -notmatch 'KB2267602|KB4052623|KB915597')
    } | Sort-Object Date -Descending)
    if ($ok.Count -eq 0) {
        return (New-Finding -Id 'PATCH-AGE' -Category $script:HardenCategory -Name $name -Severity 'High' -Status 'Warning' -Observed 'No successful update found in the history' -Expected '35 days or less' `
            -Detail 'Windows Update history shows no successfully installed Windows update.' -Advice 'Open Settings > Windows Update and install updates. If history was cleared, this may be a false alarm.' -RiskTier 'AuditOnly')
    }
    $last = $ok[0]
    $days = [int][math]::Floor(($Now - $last.Date.ToUniversalTime()).TotalDays)
    $status = if ($days -le 35) { 'Pass' } elseif ($days -le 60) { 'Warning' } else { 'Fail' }
    New-Finding -Id 'PATCH-AGE' -Category $script:HardenCategory -Name $name -Severity 'High' -Status $status `
        -Observed ("{0} day(s) ago ({1:yyyy-MM-dd})" -f $days, $last.Date.ToLocalTime()) -Expected '35 days or less' `
        -Detail 'Most attacks use flaws that already have a fix. MS ships fixes monthly, so a PC more than a month behind is exposed to known attacks.' `
        -Advice $(if ($status -eq 'Pass') { '' } else { 'Open Settings > Windows Update, install all updates and restart.' }) -RiskTier 'AuditOnly'
}

# ---------------------------------------------------------------- registration
Register-SecurityCheck -Id 'LSA-PPL'    -Check { Get-LsaPplFinding }   -FixAction { Invoke-LsaPplFix }  -FixTest { Test-LsaPplApplied }
Register-SecurityCheck -Id 'CRED-GUARD' -Check { Get-CredGuardFinding }
Register-SecurityCheck -Id 'WDIGEST'    -Check { Get-WDigestFinding }  -FixAction { Invoke-WDigestFix } -FixTest { Test-WDigestApplied }
Register-SecurityCheck -Id 'PSV2'       -Check { Get-PsV2Finding }     -FixAction { Invoke-PsV2Fix }    -FixTest { Test-PsV2Applied }
Register-SecurityCheck -Id 'NBTNS'      -Check { Get-NbtNsFinding }    -FixAction { Invoke-NbtNsFix }   -FixTest { Test-NbtNsApplied }
Register-SecurityCheck -Id 'MDNS'       -Check { Get-MdnsFinding }     -FixAction { Invoke-MdnsFix }    -FixTest { Test-MdnsApplied }
Register-SecurityCheck -Id 'SMB-SIGN'   -Check { Get-SmbSignFinding }  -FixAction { Invoke-SmbSignFix } -FixTest { Test-SmbSignApplied }
Register-SecurityCheck -Id 'PATCH-AGE'  -Check { Get-PatchAgeFinding }
