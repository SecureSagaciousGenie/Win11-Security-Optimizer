<#
    EventGuidance.ps1
    Author: Ahmad Shaukat
    What the Windows event behind a Hayabusa or Chainsaw match is, what to do
    about it and what to search for. Also reads the event details both tools
    report, so a card shows the real threat, file, account and program.
    Dot-sourced by SecurityCore.ps1.
#>

# Hayabusa shortens channel names in its CSV; map them back to the real log.
$script:ChannelAliases = @{
    'sec'         = 'Security'
    'sys'         = 'System'
    'app'         = 'Application'
    'defender'    = 'Microsoft-Windows-Windows Defender/Operational'
    'pwsh'        = 'Microsoft-Windows-PowerShell/Operational'
    'pwshclassic' = 'Windows PowerShell'
    'sysmon'      = 'Microsoft-Windows-Sysmon/Operational'
    'tasksch'     = 'Microsoft-Windows-TaskScheduler/Operational'
    'firewall'    = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    'wmi'         = 'Microsoft-Windows-WMI-Activity/Operational'
    'bitscli'     = 'Microsoft-Windows-Bits-Client/Operational'
    'codeinteg'   = 'Microsoft-Windows-CodeIntegrity/Operational'
}

$script:EventGuidance = @(
    # MS Defender
    @{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116, 1006)
       What = 'MS Defender detected malware or a potentially unwanted app.'
       Do = 'Open Windows Security > Virus & threat protection > Protection history. It shows the file, the program that touched it and what Defender did. Look up the threat name below. If the file came from Downloads, email or a USB stick and you did not expect it, delete it and run a full scan.' },
    @{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1117, 1007)
       What = 'MS Defender acted on a detection (quarantined, removed or blocked it).'
       Do = 'Check Protection history for the file and the action. A blocked or removed threat is contained, but find out how it arrived: the path and the program below tell you which download, attachment or tool brought it.' },
    @{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1118, 1119, 1008)
       What = 'MS Defender tried to act on a detection and failed. The threat may still be on the PC.'
       Do = 'Treat this as active. Run a Microsoft Defender Offline scan (Windows Security > Scan options), then check Protection history. If it keeps failing, disconnect the PC from the network and get help.' },
    @{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1015)
       What = 'MS Defender flagged suspicious behaviour by a running program.'
       Do = 'Check Protection history and the program named below. If you did not run it, scan the file with Defender and look at what started it.' },
    @{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1121, 1122)
       What = 'An attack surface reduction (ASR) rule blocked (1121) or audited (1122) an action.'
       Do = 'The program and file below show what was stopped. Office or a script starting a program is a classic malware sign; a line-of-business app hitting a rule is a false positive.' },
    @{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(5001, 5010, 5012)
       What = 'MS Defender protection was turned off (real-time protection or scanning).'
       Do = 'Turn it back on in Windows Security. If you did not turn it off, malware often does this first: check what ran just before (see the time below) and run a full scan.' },
    @{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(5004, 5007)
       What = 'MS Defender settings were changed.'
       Do = 'The details show the setting. New exclusions or disabled features you did not make are a strong sign of tampering; undo them and find out who changed them.' },
    @{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(5013)
       What = 'Tamper Protection blocked a change to MS Defender.'
       Do = 'Something tried to weaken Defender and was stopped. Find the program from the time below and remove it if you do not trust it.' },
    # Logs cleared
    @{ Channel = 'Security'; Ids = @(1102)
       What = 'The Security event log was cleared.'
       Do = 'Clearing the Security log hides what happened before. If you or IT did not clear it on purpose, treat the PC as suspicious: note the account below and check other logs for what happened just before.' },
    @{ Channel = 'System'; Ids = @(104)
       What = 'An event log was cleared.'
       Do = 'Find out who cleared it and why. Attackers clear logs to hide their tracks.' },
    # Accounts and groups
    @{ Channel = 'Security'; Ids = @(4720)
       What = 'A user account was created.'
       Do = 'Check that you expect the new account name below. An unknown account, especially one ending in $ or added to Administrators, is a common backdoor.' },
    @{ Channel = 'Security'; Ids = @(4722, 4738)
       What = 'A user account was enabled or changed.'
       Do = 'Check the account below. Re-enabled Guest or old accounts you did not touch are worth investigating.' },
    @{ Channel = 'Security'; Ids = @(4724, 4723)
       What = 'An account password was reset or changed.'
       Do = 'Confirm the reset was you or IT. An unexpected reset can mean someone took over the account.' },
    @{ Channel = 'Security'; Ids = @(4726)
       What = 'A user account was deleted.'
       Do = 'Confirm the deletion was planned. Attackers sometimes delete the account they used.' },
    @{ Channel = 'Security'; Ids = @(4728, 4732, 4756)
       What = 'An account was added to a security group (for example Administrators).'
       Do = 'Check the group and the member below. A new member of Administrators you did not add is a serious finding.' },
    # Logons
    @{ Channel = 'Security'; Ids = @(4624)
       What = 'An account signed in.'
       Do = 'Look at the logon type and the source address. Type 10 is Remote Desktop and type 3 is over the network; sign-ins from addresses you do not know are worth checking.' },
    @{ Channel = 'Security'; Ids = @(4625, 4771, 4776)
       What = 'A sign-in failed (or NTLM/Kerberos checked a password).'
       Do = 'Many failures for one account or from one address is password guessing. Check the source address and lock down Remote Desktop if it is exposed.' },
    @{ Channel = 'Security'; Ids = @(4740)
       What = 'An account was locked out after too many wrong passwords.'
       Do = 'Find the source of the attempts below. Repeated lockouts usually mean password guessing or a device with an old saved password.' },
    @{ Channel = 'Security'; Ids = @(4648)
       What = 'A program signed in with explicitly supplied credentials (runas or similar).'
       Do = 'Check the program and target account below. Tools that move between machines with stolen passwords show up here.' },
    @{ Channel = 'Security'; Ids = @(4672)
       What = 'An account received special (admin-level) privileges at sign-in.'
       Do = 'Expected for admins and system accounts. An ordinary user account here deserves a look.' },
    @{ Channel = 'Security'; Ids = @(4769)
       What = 'A Kerberos service ticket was requested.'
       Do = 'Many requests with weak encryption (0x17) in a short time is Kerberoasting, an attack on service account passwords.' },
    # Services, tasks, processes
    @{ Channel = 'System'; Ids = @(7045)
       What = 'A new Windows service was installed.'
       Do = 'Check the service name and the program path below. Services running from Temp, AppData or a user folder, or with an encoded command line, are a classic way to keep malware running.' },
    @{ Channel = 'Security'; Ids = @(4697)
       What = 'A new Windows service was installed.'
       Do = 'Check the service name and program path below. A path in a user, Temp or AppData folder is a red flag.' },
    @{ Channel = 'System'; Ids = @(7040, 7036)
       What = 'A service changed its start type or state.'
       Do = 'Security services (Defender, Windows Update, firewall) being stopped or disabled is a warning sign.' },
    @{ Channel = 'Security'; Ids = @(4698, 4702)
       What = 'A scheduled task was created or changed.'
       Do = 'Check the task name and the command it runs. Tasks that run scripts or programs from user folders are a common way to keep malware running.' },
    @{ Channel = 'Security'; Ids = @(4699)
       What = 'A scheduled task was deleted.'
       Do = 'Confirm it was expected. Attackers delete tasks to clean up.' },
    @{ Channel = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(106, 140, 141, 200, 201)
       What = 'A scheduled task was registered, changed, deleted or run.'
       Do = 'Check the task name below in Task Scheduler and what it runs.' },
    @{ Channel = 'Security'; Ids = @(4688)
       What = 'A process was started.'
       Do = 'Check the program, its command line and its parent below. Encoded PowerShell, downloads with certutil or bitsadmin and programs in Temp folders are typical attacker activity.' },
    @{ Channel = 'Security'; Ids = @(4657)
       What = 'A registry value was changed.'
       Do = 'Check the key below. Run keys, Winlogon and image file execution options are common persistence spots.' },
    @{ Channel = 'Security'; Ids = @(5140, 5145)
       What = 'A network share was accessed.'
       Do = 'Check the share and source address. Access to admin shares (C$, ADMIN$) from other machines is how attackers move around a network.' },
    @{ Channel = 'Security'; Ids = @(4719, 4907)
       What = 'Audit policy or auditing settings were changed.'
       Do = 'Turning auditing off hides later activity. Confirm IT made the change.' },
    # PowerShell
    @{ Channel = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4104)
       What = 'PowerShell logged the text of a script it ran (script block logging).'
       Do = 'Read the script text in the details. Download commands (Invoke-WebRequest, DownloadString), Invoke-Expression, encoded or obfuscated text and Defender changes are the usual red flags.' },
    @{ Channel = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4103)
       What = 'PowerShell logged a command it ran (module logging).'
       Do = 'Check the command and its parameters in the details.' },
    @{ Channel = 'Windows PowerShell'; Ids = @(400, 403, 600, 800)
       What = 'PowerShell started a session or ran a pipeline.'
       Do = 'Check the host application and command line in the details. powershell -enc, -nop or -w hidden are often malicious.' },
    # Sysmon
    @{ Channel = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1)
       What = 'Sysmon recorded a process start.'
       Do = 'Check the image, command line and parent process below.' },
    @{ Channel = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(3)
       What = 'Sysmon recorded a network connection.'
       Do = 'Check which program connected and to which address and port.' },
    @{ Channel = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(8, 10)
       What = 'Sysmon recorded one process injecting into or opening another.'
       Do = 'Access to lsass.exe by an unexpected program is credential theft. Check the source program below.' },
    @{ Channel = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(11, 23, 26)
       What = 'Sysmon recorded a file being created or deleted.'
       Do = 'Check the file and the program below.' },
    @{ Channel = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(12, 13, 14)
       What = 'Sysmon recorded a registry change.'
       Do = 'Check the key and the program below; Run keys and services are common persistence spots.' },
    @{ Channel = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(22)
       What = 'Sysmon recorded a DNS lookup.'
       Do = 'Check the domain and the program that looked it up.' },
    # Firewall, WMI, BITS, code integrity, Remote Desktop
    @{ Channel = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Ids = @(2004, 2005, 2006, 2033, 2071, 2097)
       What = 'A Windows Firewall rule was added, changed or deleted.'
       Do = 'Check the rule name and program below. New allow rules for programs in user folders, or deleted rules you did not touch, are suspicious.' },
    @{ Channel = 'Microsoft-Windows-WMI-Activity/Operational'; Ids = @(5861)
       What = 'A permanent WMI event subscription was created.'
       Do = 'WMI subscriptions are a stealthy way to keep malware running. Check the consumer command below; legitimate ones are rare on home PCs.' },
    @{ Channel = 'Microsoft-Windows-Bits-Client/Operational'; Ids = @(3, 59, 60)
       What = 'A BITS background transfer job was created or ran.'
       Do = 'Check the URL and file below. BITS is used by Windows Update, but also by malware to download files quietly.' },
    @{ Channel = 'Microsoft-Windows-CodeIntegrity/Operational'; Ids = @(3033, 3063, 3077)
       What = 'Windows blocked a file or driver that failed a signature or policy check.'
       Do = 'Check the file below. An unsigned driver blocked by memory integrity is often an old hardware driver; an unknown file is worth scanning.' },
    @{ Channel = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149)
       What = 'A Remote Desktop connection passed authentication.'
       Do = 'Check the user and source address. If you do not use Remote Desktop, turn it off on the Security tab.' }
)

function Resolve-EventChannel {
    <# Full log name for a channel, mapping Hayabusa's abbreviations back. #>
    param([AllowEmptyString()][string]$Channel)
    $c = ([string]$Channel).Trim()
    $k = $c.ToLowerInvariant()
    if ($script:ChannelAliases.ContainsKey($k)) { return $script:ChannelAliases[$k] }
    return $c
}

function Get-EventGuidance {
    <# What the event is and what to do. Known is $false for an event not in the
       table; the text then names the log and event ID so it can be looked up. #>
    param([AllowEmptyString()][string]$Channel, [AllowEmptyString()][string]$EventId)
    $full = Resolve-EventChannel -Channel $Channel
    $id = 0
    [void][int]::TryParse(([string]$EventId).Trim(), [ref]$id)
    foreach ($g in $script:EventGuidance) {
        if ([string]::Equals($g.Channel, $full, [System.StringComparison]::OrdinalIgnoreCase) -and (@($g.Ids) -contains $id)) {
            return [pscustomobject]@{ Known = $true; Channel = $full; EventId = [string]$id; What = $g.What; Do = $g.Do }
        }
    }
    return [pscustomobject]@{
        Known = $false; Channel = $full; EventId = $(if ($id) { [string]$id } else { '' })
        What = 'This tool has no plain-English note for this event yet; the details and search terms below show what it was.'
        Do = 'Check the sample events below: when it happened, which account and which program. If you do not recognise the activity, look up the rule and the event with the search terms below.'
    }
}

function ConvertFrom-HayabusaDetail {
    <# Hayabusa's "Key: value ¦ Key: value" details as an ordered dictionary.
       The separator is U+00A6; read in the wrong code page it becomes "Â¦". #>
    param([AllowEmptyString()][string]$Text)
    $out = [ordered]@{}
    $t = ([string]$Text).Trim()
    if (-not $t -or $t -eq '-') { return $out }
    foreach ($part in ($t -split ('\s*' + [char]0x00C2 + '?' + [char]0x00A6 + '\s*'))) {
        $i = $part.IndexOf(': ')
        if ($i -le 0) { continue }
        $k = $part.Substring(0, $i).Trim()
        if (-not $out.Contains($k)) { $out[$k] = $part.Substring($i + 2).Trim() }
    }
    return $out
}

function Get-EventFilePath {
    <# File paths an event names: the path-like fields first (Defender writes
       "file:_C:\x\y.exe; ..."), then any C:\ path in the text. #>
    param([AllowEmptyString()][string]$Text = '', [System.Collections.IDictionary]$Fields)
    $paths = New-Object System.Collections.ArrayList
    $candidates = New-Object System.Collections.ArrayList
    if ($Fields) {
        foreach ($k in @($Fields.Keys)) {
            if ([string]$k -notmatch '(?i)^(Path|Proc|Process|Process ?Name|Image|TgtImage|SrcImage|ParentImage|ImagePath|TargetFilename|File|FileName)$') { continue }
            foreach ($v in ([string]$Fields[$k] -split ';')) { [void]$candidates.Add(($v.Trim() -replace '(?i)^[a-z]*:_', '')) }
        }
    }
    foreach ($m in [regex]::Matches([string]$Text, '(?i)(?<![A-Za-z])([A-Z]:\\[^;|"<>\r\n' + [char]0x00A6 + ']+?\.[A-Za-z0-9]{1,8})(?=$|[\s;|"<>,' + [char]0x00A6 + '])')) { [void]$candidates.Add($m.Groups[1].Value) }
    foreach ($c in $candidates) {
        $c = ([string]$c).Trim().Trim('"')
        if (-not $c -or $c -notmatch '[\\/]' -or $c -notmatch '\.[A-Za-z0-9]{1,8}$') { continue }
        if (-not ($paths -contains $c)) { [void]$paths.Add($c) }
    }
    return @($paths.ToArray())
}

function Get-DetectionSearchTerm {
    <# Search terms that find something useful on the web: the Defender threat
       name, the files involved, the rule and the event. #>
    param(
        [AllowEmptyString()][string]$RuleTitle,
        [AllowEmptyString()][string]$Channel,
        [AllowEmptyString()][string]$EventId,
        [AllowEmptyString()][string]$DetailText = '',
        [AllowEmptyCollection()][string[]]$Path = @()
    )
    $terms = New-Object System.Collections.ArrayList
    $threat = [regex]::Match([string]$DetailText, '(?i)Threat(?: Name)?\s*[:=]\s*([^' + [char]0x00A6 + ';|\r\n]+?)\s*(?:$|[' + [char]0x00A6 + ';|\r\n])')
    if ($threat.Success) { [void]$terms.Add(('"{0}" (MS malware encyclopedia: microsoft.com/wdsi/threats)' -f $threat.Groups[1].Value.Trim())) }
    foreach ($p in @($Path | Select-Object -First 3)) {
        $leaf = [string]($p -split '[\\/]')[-1]
        $q = '"{0}"' -f $leaf
        if ($leaf -and -not ($terms -contains $q)) { [void]$terms.Add($q) }
    }
    if ($RuleTitle) { [void]$terms.Add(('"{0}" Sigma rule' -f $RuleTitle)) }
    if ($EventId) { [void]$terms.Add(('Windows event {0} "{1}"' -f $EventId, (Resolve-EventChannel -Channel $Channel))) }
    return @($terms.ToArray())
}

function Format-DetectionGuidance {
    <# The "What to do" text: the event-specific step, then the search terms. #>
    param([Parameter(Mandatory)]$Guidance, [AllowEmptyCollection()][string[]]$SearchTerm = @(), [string]$FullReport = '')
    $text = [string]$Guidance.Do
    if (@($SearchTerm).Count -gt 0) { $text += "`nSearch for: " + (@($SearchTerm) -join '  |  ') }
    if ($FullReport) { $text += "`nEvery match is in the full report: " + $FullReport }
    return $text
}

function Limit-Text {
    <# One line, at most $Max characters. #>
    param([AllowEmptyString()][string]$Text, [int]$Max = 300)
    $t = (([string]$Text) -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function Format-MatchSummary {
    <# "Hayabusa matched this rule 2 time(s), on <log> event <id>. <meaning>" #>
    param([Parameter(Mandatory)][string]$Tool, [int]$Count, [Parameter(Mandatory)]$Guidance)
    $where = ''
    if ($Guidance.Channel -and $Guidance.EventId) { $where = (", on {0} event {1}" -f $Guidance.Channel, $Guidance.EventId) }
    elseif ($Guidance.Channel) { $where = (", in the {0} log" -f $Guidance.Channel) }
    return ("{0} matched this rule {1} time(s){2}. {3}" -f $Tool, $Count, $where, $Guidance.What)
}

function Get-PropertyValue {
    <# A property of a parsed JSON object or a key of a dictionary; $null if absent. #>
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Add-EventField {
    <# Flattens EventData/UserData into name=value pairs (two levels deep). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Into, $Node, [int]$Depth = 0)
    if ($null -eq $Node -or $Depth -gt 2) { return }
    $props = if ($Node -is [System.Collections.IDictionary]) { @($Node.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Node[$_] } }) } else { @($Node.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in $props) {
        if ($p.Name -like '*_attributes' -or $p.Name -eq 'xmlns') { continue }
        $v = $p.Value
        if ($null -eq $v) { continue }
        if ($v -is [string] -or $v -is [ValueType]) {
            if (-not $Into.Contains($p.Name) -and ([string]$v).Trim()) { $Into[$p.Name] = [string]$v }
        } elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [System.Collections.IDictionary])) {
            $scalars = @($v | Where-Object { $_ -is [string] -or $_ -is [ValueType] })
            if ($scalars.Count -gt 0 -and -not $Into.Contains($p.Name)) { $Into[$p.Name] = ($scalars -join '; ') }
        } else {
            Add-EventField -Into $Into -Node $v -Depth ($Depth + 1)
        }
    }
}

function Get-ChainsawEventInfo {
    <# Channel, event ID, computer and fields of the event behind one Chainsaw
       detection (document.data.Event; the first document of an aggregate). #>
    param($Detection)
    $info = [ordered]@{ Channel = ''; EventId = ''; Computer = ''; Fields = [ordered]@{} }
    $doc = Get-PropertyValue $Detection 'document'
    if (-not $doc) { $doc = @(Get-PropertyValue $Detection 'documents') | Select-Object -First 1 }
    $ev = Get-PropertyValue (Get-PropertyValue $doc 'data') 'Event'
    if ($ev) {
        $sys = Get-PropertyValue $ev 'System'
        $info.Channel = [string](Get-PropertyValue $sys 'Channel')
        $eid = Get-PropertyValue $sys 'EventID'
        if ($null -ne $eid -and -not ($eid -is [string] -or $eid -is [ValueType])) { $eid = Get-PropertyValue $eid '#text' }
        $info.EventId = [string]$eid
        $info.Computer = [string](Get-PropertyValue $sys 'Computer')
        foreach ($section in @('EventData', 'UserData')) { Add-EventField -Into $info.Fields -Node (Get-PropertyValue $ev $section) }
    }
    return [pscustomobject]$info
}

$script:EventFieldPriority = @(
    'Threat Name', 'Severity Name', 'Category Name', 'Path', 'Process Name', 'Detection User', 'Action Name',
    'TargetUserName', 'TargetDomainName', 'SubjectUserName', 'MemberName', 'LogonType', 'IpAddress', 'WorkstationName',
    'ServiceName', 'ImagePath', 'ServiceFileName', 'TaskName', 'NewProcessName', 'CommandLine', 'ParentProcessName',
    'Image', 'ParentImage', 'TargetFilename', 'TargetObject', 'Details', 'QueryName', 'DestinationIp', 'DestinationPort',
    'ScriptBlockText', 'RuleName', 'ApplicationPath'
)

function Format-EventField {
    <# "Name=value; Name=value" with the most telling fields first. #>
    param([System.Collections.IDictionary]$Fields, [int]$Max = 8)
    if (-not $Fields -or $Fields.Count -eq 0) { return '' }
    $names = @(@($script:EventFieldPriority | Where-Object { $Fields.Contains($_) }) + @($Fields.Keys | Where-Object { $script:EventFieldPriority -notcontains $_ }))
    $parts = foreach ($n in @($names | Select-Object -First $Max)) {
        $lim = if ($n -eq 'ScriptBlockText') { 300 } else { 160 }
        '{0}={1}' -f $n, (Limit-Text -Text ([string]$Fields[$n]) -Max $lim)
    }
    return (@($parts) -join '; ')
}
