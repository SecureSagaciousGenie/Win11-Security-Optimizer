<#
    Baseline.ps1
    Author: Ahmad Shaukat
    Baseline and drift: snapshot persistence and exposure state, save it as a
    baseline and report what is new since then. Long one-off lists become short
    "new since last time" alerts.
    Dot-sourced by SecurityCore.ps1.
#>

$script:SnapshotSchemaVersion = 1

function Get-BaselinePath {
    <# Pure path accessor: the current and previous baseline files. #>
    $dir = Join-Path $env:ProgramData 'Win11SecurityOptimizer\baselines'
    return [pscustomobject]@{
        Dir      = $dir
        Current  = (Join-Path $dir 'baseline.json')
        Previous = (Join-Path $dir 'baseline.prev.json')
    }
}

function ConvertTo-StableText {
    <# Lower-cases, expands environment variables and replaces version-number
       path segments (1.2.3 and longer) with *. Product updates move programs
       into a new version folder; without this every browser or Defender update
       would look like a changed command line. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not $Value) { return '' }
    $v = [Environment]::ExpandEnvironmentVariables($Value.Trim()).ToLowerInvariant()
    return ($v -replace '(?<=[\\/])\d+(\.\d+){2,}(-\d+)?(?=[\\/])', '*')
}

function Add-SnapshotEntry {
    <# Adds Key -> Value to a collection table, skipping empty keys (PS 5.1
       ConvertFrom-Json cannot read an empty property name). #>
    param([Parameter(Mandatory)][hashtable]$Table, [AllowEmptyString()][string]$Key, [Parameter(Mandatory)]$Value)
    $k = ([string]$Key).Trim().ToLowerInvariant()
    if (-not $k) { return }
    $Table[$k] = $Value
}

function Get-SnapshotCollector {
    <# Ordered name -> scriptblock. Each returns a hashtable keyed by a stable
       lowercase key. Read-only. #>
    $c = [ordered]@{}
    $c['startup'] = {
        $t = @{}
        foreach ($i in @(Get-StartupItems)) {
            Add-SnapshotEntry -Table $t -Key ('{0}|{1}|{2}|{3}' -f $i.Type, $i.Scope, $i.Location, $i.Name) -Value ([ordered]@{ command = (ConvertTo-StableText $i.Command); enabled = [string][bool]$i.Enabled })
        }
        $t
    }
    $c['services'] = {
        $t = @{}
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            Add-SnapshotEntry -Table $t -Key $s.Name -Value ([ordered]@{ path = (ConvertTo-StableText $s.PathName); startmode = [string]$s.StartMode; account = ([string]$s.StartName).ToLowerInvariant() })
        }
        $t
    }
    $c['tasks'] = {
        $t = @{}
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
            $exe = @(); $arg = @()
            foreach ($a in @($task.Actions)) {
                if ($a.PSObject.Properties.Name -contains 'Execute') { $exe += (ConvertTo-StableText ([string]$a.Execute)) }
                if ($a.PSObject.Properties.Name -contains 'Arguments') { $arg += (ConvertTo-StableText ([string]$a.Arguments)) }
            }
            $principal = ''
            if ($task.Principal -and ($task.Principal.PSObject.Properties.Name -contains 'UserId')) { $principal = ([string]$task.Principal.UserId).ToLowerInvariant() }
            Add-SnapshotEntry -Table $t -Key ([string]$task.TaskPath + [string]$task.TaskName) -Value ([ordered]@{ execute = ($exe -join ' ; '); arguments = ($arg -join ' ; '); principal = $principal })
        }
        $t
    }
    $c['localadmins'] = {
        $t = @{}
        foreach ($m in @(Get-LocalAdminMember)) {
            $k = if ($m.Sid) { $m.Sid } else { 'name:' + $m.Name }
            Add-SnapshotEntry -Table $t -Key $k -Value ([ordered]@{ name = [string]$m.Name })
        }
        $t
    }
    $c['localusers'] = {
        $t = @{}
        foreach ($u in @(Get-LocalUser -ErrorAction Stop)) {
            Add-SnapshotEntry -Table $t -Key ([string]$u.SID.Value) -Value ([ordered]@{ name = [string]$u.Name; enabled = [string][bool]$u.Enabled })
        }
        $t
    }
    $c['defenderexclusions'] = {
        $t = @{}
        $p = Get-MpPreference -ErrorAction Stop
        foreach ($pair in @(@('path', 'ExclusionPath'), @('process', 'ExclusionProcess'), @('extension', 'ExclusionExtension'), @('ip', 'ExclusionIpAddress'))) {
            if ($p.PSObject.Properties.Name -contains $pair[1]) {
                foreach ($x in @($p.($pair[1]) | Where-Object { $_ })) { Add-SnapshotEntry -Table $t -Key ('{0}|{1}' -f $pair[0], (ConvertTo-StableText ([string]$x))) -Value ([ordered]@{ type = $pair[0] }) }
            }
        }
        $t
    }
    $c['listeningports'] = {
        $t = @{}
        foreach ($l in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
            $name = ''; $path = ''
            try {
                $proc = Get-Process -Id $l.OwningProcess -ErrorAction Stop
                $name = ([string]$proc.ProcessName).ToLowerInvariant()
                if ($proc.PSObject.Properties.Name -contains 'Path') { $path = ConvertTo-StableText ([string]$proc.Path) }
            } catch { $name = '(unknown)' }
            Add-SnapshotEntry -Table $t -Key ('tcp|{0}|{1}' -f $l.LocalAddress, $l.LocalPort) -Value ([ordered]@{ process = $name; path = $path })
        }
        $t
    }
    $c['hosts'] = {
        $t = @{}
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        foreach ($line in @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)) {
            $x = ([string]$line -replace '#.*$', '').Trim()
            if ($x) { Add-SnapshotEntry -Table $t -Key ($x -replace '\s+', ' ') -Value ([ordered]@{ entry = 'present' }) }
        }
        $t
    }
    $c['asr'] = {
        $t = @{}
        $p = Get-MpPreference -ErrorAction Stop
        $ids = @($p.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
        $acts = @($p.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            $act = if ($i -lt $acts.Count) { [string]$acts[$i] } else { '' }
            Add-SnapshotEntry -Table $t -Key ([string]$ids[$i]) -Value ([ordered]@{ action = $act })
        }
        $t
    }
    $c['firewall'] = {
        $t = @{}
        foreach ($fp in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            Add-SnapshotEntry -Table $t -Key ([string]$fp.Name) -Value ([ordered]@{ enabled = [string]$fp.Enabled })
        }
        $t
    }
    $c['wmi'] = {
        $t = @{}
        foreach ($f in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop)) {
            Add-SnapshotEntry -Table $t -Key ('filter|' + [string]$f.Name) -Value ([ordered]@{ detail = ([string]$f.Query).ToLowerInvariant() })
        }
        foreach ($cons in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)) {
            $cls = [string]$cons.CimClass.CimClassName
            $detail = ''
            foreach ($prop in @('CommandLineTemplate', 'ExecutablePath', 'ScriptText', 'ScriptFileName', 'FileName')) {
                if (($cons.PSObject.Properties.Name -contains $prop) -and $cons.$prop) { $detail = ConvertTo-StableText ([string]$cons.$prop); break }
            }
            Add-SnapshotEntry -Table $t -Key ('consumer|{0}|{1}' -f $cls, [string]$cons.Name) -Value ([ordered]@{ detail = $detail })
        }
        foreach ($b in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)) {
            $fn = ''; $cn = ''
            try { $fn = [string]$b.Filter.Name } catch { $fn = [string]$b.Filter }
            try { $cn = [string]$b.Consumer.Name } catch { $cn = [string]$b.Consumer }
            Add-SnapshotEntry -Table $t -Key ('binding|{0}|{1}' -f $fn, $cn) -Value ([ordered]@{ detail = 'bound' })
        }
        $t
    }
    return $c
}

function Get-SystemSnapshot {
    <# Read-only. Works unelevated with reduced scope: a collection that cannot
       be read is recorded under Errors and set to $null, never left empty, so a
       failed read can never look like "nothing there". #>
    param([string]$AutorunsCsv)
    $collections = [ordered]@{}
    $errors = [ordered]@{}
    $collectors = Get-SnapshotCollector
    foreach ($name in @($collectors.Keys)) {
        try {
            $collections[$name] = (& $collectors[$name])
        } catch {
            $collections[$name] = $null
            $errors[$name] = $_.Exception.Message
            Write-CoreLog -Message ("Snapshot: {0} could not be read: {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    }
    if ($AutorunsCsv) {
        try {
            $t = @{}
            foreach ($r in @(Read-AutorunsCsv -Path $AutorunsCsv)) {
                Add-SnapshotEntry -Table $t -Key ('{0}|{1}|{2}' -f $r.Category, $r.EntryLocation, $r.Entry) -Value ([ordered]@{ imagepath = (ConvertTo-StableText $r.ImagePath); sha256 = ([string]$r.Sha256).ToLowerInvariant() })
            }
            $collections['autoruns'] = $t
        } catch {
            $collections['autoruns'] = $null
            $errors['autoruns'] = $_.Exception.Message
        }
    }
    return [pscustomobject][ordered]@{
        SchemaVersion = $script:SnapshotSchemaVersion
        MachineName   = [string]$env:COMPUTERNAME
        ToolVersion   = [string]$script:Core.Version
        CreatedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        Elevated      = [bool](Test-IsAdmin)
        Collections   = $collections
        Errors        = $errors
    }
}

function ConvertTo-SnapshotTable {
    <# Normalises a snapshot that came from JSON (PSCustomObjects) or from
       Get-SystemSnapshot (hashtables) into nested hashtables, so Compare works
       the same either way under StrictMode. Missing collections stay absent;
       an errored collection stays $null. #>
    param([Parameter(Mandatory)]$Snapshot)
    $toTable = {
        param($obj)
        $h = @{}
        if ($null -eq $obj) { return $h }
        if ($obj -is [System.Collections.IDictionary]) { foreach ($k in @($obj.Keys)) { $h[[string]$k] = $obj[$k] } }
        else { foreach ($p in @($obj.PSObject.Properties)) { $h[[string]$p.Name] = $p.Value } }
        return $h
    }
    $names = @('SchemaVersion', 'MachineName', 'ToolVersion', 'CreatedUtc', 'Elevated', 'Collections', 'Errors')
    $out = @{}
    foreach ($n in $names) {
        if ($Snapshot -is [System.Collections.IDictionary]) { if ($Snapshot.Contains($n)) { $out[$n] = $Snapshot[$n] } else { $out[$n] = $null } }
        elseif ($Snapshot.PSObject.Properties.Name -contains $n) { $out[$n] = $Snapshot.$n } else { $out[$n] = $null }
    }
    # PowerShell 7 ConvertFrom-Json turns ISO dates into DateTime; keep the
    # round-trip string form so both engines compare and parse the same.
    if ($out.CreatedUtc -is [datetime]) { $out.CreatedUtc = $out.CreatedUtc.ToUniversalTime().ToString('o') }
    $cols = & $toTable $out.Collections
    $norm = @{}
    foreach ($c in @($cols.Keys)) {
        if ($null -eq $cols[$c]) { $norm[$c] = $null; continue }
        $entries = & $toTable $cols[$c]
        $t = @{}
        foreach ($k in @($entries.Keys)) {
            $fields = & $toTable $entries[$k]
            $f = @{}
            foreach ($fk in @($fields.Keys)) { $f[[string]$fk] = [string]$fields[$fk] }
            $t[$k] = $f
        }
        $norm[$c] = $t
    }
    $out.Collections = $norm
    $out.Errors = & $toTable $out.Errors
    return $out
}

function Save-Baseline {
    <# Main thread, elevated. Writes the snapshot as the baseline, keeping the
       previous one as baseline.prev.json. Refuses a snapshot with any errored
       collection so a partial read never becomes the reference. #>
    param([Parameter(Mandatory)]$Snapshot)
    if (-not (Test-IsAdmin)) { throw 'Saving a baseline needs administrator rights.' }
    $snap = ConvertTo-SnapshotTable -Snapshot $Snapshot
    $errs = @($snap.Errors.Keys)
    if ($errs.Count -gt 0) {
        throw ("The baseline was not saved because these checks could not be read: {0}. Run as administrator and try again." -f ($errs -join ', '))
    }
    $paths = Get-BaselinePath
    if (-not (Test-Path -LiteralPath $paths.Dir -PathType Container)) {
        New-Item -ItemType Directory -Path $paths.Dir -Force | Out-Null
        Set-ItemOwnerAdministrators -Path $paths.Dir
    }
    if (Test-Path -LiteralPath $paths.Current -PathType Leaf) {
        Move-Item -LiteralPath $paths.Current -Destination $paths.Previous -Force
        Set-ItemOwnerAdministrators -Path $paths.Previous
    }
    Write-SecureFile -Path $paths.Current -Value (ConvertTo-Json -InputObject $Snapshot -Depth 6)
    Add-ChangeRecord -Description ("Saved a baseline of this PC ({0} UTC) to {1}" -f $snap.CreatedUtc, $paths.Current)
    return $paths.Current
}

function Read-Baseline {
    <# Reads the saved baseline, or $null when there is none. Refuses a file
       that is not owned by Administrators/SYSTEM. #>
    param([string]$Path = (Get-BaselinePath).Current)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    if (-not (Test-FolderOwnedBySystemOrAdmins $Path)) { throw ("The baseline file {0} is not owned by Administrators, so it cannot be trusted. Save a new baseline." -f $Path) }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Get-BaselineInfo {
    <# Date and machine of the saved baseline for the sidebar chip, or $null. #>
    try {
        $b = Read-Baseline
        if (-not $b) { return $null }
        $t = ConvertTo-SnapshotTable -Snapshot $b
        $when = [datetime]::Parse([string]$t.CreatedUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        return [pscustomobject]@{ CreatedUtc = $when; MachineName = [string]$t.MachineName }
    } catch {
        Write-CoreLog -Message ("Could not read the baseline: {0}" -f $_.Exception.Message) -Level WARN
        return $null
    }
}

function Compare-Baseline {
    <# Added, Removed and Changed per collection. A collection missing or
       errored on either side is listed under Skipped, never as a difference.
       Throws when the machine names differ. #>
    param([Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Current)
    $b = ConvertTo-SnapshotTable -Snapshot $Baseline
    $c = ConvertTo-SnapshotTable -Snapshot $Current
    if (-not [string]::Equals([string]$b.MachineName, [string]$c.MachineName, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("The baseline was saved on {0}, not on this PC ({1}). Save a baseline on this PC first." -f $b.MachineName, $c.MachineName)
    }
    $result = [ordered]@{}
    $skipped = [ordered]@{}
    $names = @(@($b.Collections.Keys) + @($c.Collections.Keys) | Select-Object -Unique | Sort-Object)
    foreach ($n in $names) {
        $old = $null; $new = $null
        if ($b.Collections.ContainsKey($n)) { $old = $b.Collections[$n] }
        if ($c.Collections.ContainsKey($n)) { $new = $c.Collections[$n] }
        if ($null -eq $old -or $null -eq $new) {
            $why = if (-not $b.Collections.ContainsKey($n)) { 'not in the baseline' } elseif (-not $c.Collections.ContainsKey($n)) { 'not collected this time' } elseif ($null -eq $old) { 'could not be read when the baseline was saved' } else { 'could not be read now' }
            $skipped[$n] = $why
            continue
        }
        $added = New-Object System.Collections.ArrayList
        $removed = New-Object System.Collections.ArrayList
        $changed = New-Object System.Collections.ArrayList
        foreach ($k in @($new.Keys | Sort-Object)) {
            if (-not $old.ContainsKey($k)) { [void]$added.Add([pscustomobject]@{ Key = $k; Value = $new[$k] }); continue }
            $diffs = @()
            foreach ($fk in @(@($old[$k].Keys) + @($new[$k].Keys) | Select-Object -Unique | Sort-Object)) {
                $ov = if ($old[$k].ContainsKey($fk)) { [string]$old[$k][$fk] } else { '' }
                $nv = if ($new[$k].ContainsKey($fk)) { [string]$new[$k][$fk] } else { '' }
                if ($ov -ne $nv) { $diffs += [pscustomobject]@{ Field = $fk; Old = $ov; New = $nv } }
            }
            if ($diffs.Count -gt 0) { [void]$changed.Add([pscustomobject]@{ Key = $k; Old = $old[$k]; New = $new[$k]; Fields = @($diffs) }) }
        }
        foreach ($k in @($old.Keys | Sort-Object)) {
            if (-not $new.ContainsKey($k)) { [void]$removed.Add([pscustomobject]@{ Key = $k; Value = $old[$k] }) }
        }
        $result[$n] = [pscustomobject]@{ Added = @($added.ToArray()); Removed = @($removed.ToArray()); Changed = @($changed.ToArray()) }
    }
    return [pscustomobject]@{
        BaselineUtc = [string]$b.CreatedUtc
        CurrentUtc  = [string]$c.CreatedUtc
        Collections = $result
        Skipped     = $skipped
    }
}

$script:DriftLabel = @{
    startup = 'startup items'; services = 'services'; tasks = 'scheduled tasks'; localadmins = 'local administrators'
    localusers = 'local user accounts'; defenderexclusions = 'Defender exclusions'; listeningports = 'listening network ports'
    hosts = 'hosts-file entries'; asr = 'attack surface reduction rules'; firewall = 'firewall profiles'
    wmi = 'WMI subscriptions'; autoruns = 'Autoruns entries'
}

function Format-DriftEntry {
    param([string]$Key, $Value)
    $parts = @()
    if ($Value -is [System.Collections.IDictionary]) { foreach ($k in @($Value.Keys | Sort-Object)) { if ($Value[$k]) { $parts += ('{0}={1}' -f $k, $Value[$k]) } } }
    if ($parts.Count -gt 0) { return ('  {0}  ({1})' -f $Key, ($parts -join '; ')) }
    return ('  {0}' -f $Key)
}

function ConvertTo-DriftFinding {
    <# Turns a Compare-Baseline result into Investigate cards titled
       "New since {date}". #>
    param([Parameter(Mandatory)]$Diff, [int]$MaxLines = 25)
    $since = '(unknown date)'
    try { $since = ([datetime]::Parse($Diff.BaselineUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } catch { Write-CoreLog -Message 'Baseline date could not be parsed.' -Level DEBUG }
    $cat = 'Changes since baseline'
    $f = New-Object System.Collections.ArrayList
    $buckets = @{}
    $addLine = {
        param([string]$Sev, [string]$Collection, [string]$Line, [string]$Path)
        $k = '{0}|{1}' -f $Sev, $Collection
        if (-not $buckets.ContainsKey($k)) { $buckets[$k] = [pscustomobject]@{ Sev = $Sev; Collection = $Collection; Lines = (New-Object System.Collections.ArrayList); Paths = (New-Object System.Collections.ArrayList) } }
        [void]$buckets[$k].Lines.Add($Line)
        if ($Path) { [void]$buckets[$k].Paths.Add($Path) }
    }
    $pathOf = {
        param($v)
        foreach ($fk in @('path', 'execute', 'command', 'imagepath')) { if (($v -is [System.Collections.IDictionary]) -and $v.ContainsKey($fk) -and $v[$fk]) { return (ConvertTo-CommandPath -Command ([string]$v[$fk])) } }
        return ''
    }
    foreach ($n in @($Diff.Collections.Keys)) {
        $d = $Diff.Collections[$n]
        foreach ($a in @($d.Added)) {
            $line = Format-DriftEntry -Key $a.Key -Value $a.Value
            $p = & $pathOf $a.Value
            switch ($n) {
                'localadmins'        { & $addLine 'High' $n $line '' }
                'localusers'         { & $addLine 'High' $n $line '' }
                'wmi'                { & $addLine 'High' $n $line '' }
                'defenderexclusions' { & $addLine 'High' $n $line '' }
                { $_ -in @('services', 'tasks') } { if (Test-UserWritablePath -Path $p) { & $addLine 'High' $n $line $p } else { & $addLine 'Medium' $n $line $p } }
                { $_ -in @('startup', 'autoruns', 'hosts') } { & $addLine 'Medium' $n $line $p }
                'listeningports'     {
                    $port = 0; [void][int]::TryParse(([string]$a.Key -split '\|')[-1], [ref]$port)
                    $addr = ([string]$a.Key -split '\|')[1]
                    if ($port -ge 49152 -or $addr -match '^(127\.|::1$)') { & $addLine 'Info' $n $line $p } else { & $addLine 'Medium' $n $line $p }
                }
                default              { & $addLine 'Medium' $n $line $p }
            }
        }
        foreach ($c in @($d.Changed)) {
            $fields = @($c.Fields | ForEach-Object { $_.Field })
            $detail = @($c.Fields | ForEach-Object { '      {0}: {1}  ->  {2}' -f $_.Field, $(if ($_.Old) { $_.Old } else { '(empty)' }), $(if ($_.New) { $_.New } else { '(empty)' }) }) -join "`n"
            $line = ('  {0}' -f $c.Key) + "`n" + $detail
            $p = & $pathOf $c.New
            $cmdChanged = (($n -eq 'startup') -and ($fields -contains 'command')) -or (($n -eq 'services') -and ($fields -contains 'path'))
            if ($cmdChanged) { & $addLine 'High' ($n + '-changed') $line $p }
            elseif ($n -in @('firewall', 'asr', 'tasks', 'autoruns', 'localusers', 'wmi')) { & $addLine 'Medium' ($n + '-changed') $line $p }
            else { & $addLine 'Info' ($n + '-changed') $line $p }
        }
        foreach ($r in @($d.Removed)) { & $addLine 'Info' ($n + '-removed') (Format-DriftEntry -Key $r.Key -Value $r.Value) '' }
    }

    $sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Info' = 2 }
    foreach ($b in @($buckets.Values | Sort-Object @{ Expression = { $sevOrder[$_.Sev] } }, Collection)) {
        $base = ($b.Collection -replace '-(changed|removed)$', '')
        $label = if ($script:DriftLabel.ContainsKey($base)) { $script:DriftLabel[$base] } else { $base }
        $lines = @($b.Lines.ToArray())
        $shown = @($lines | Select-Object -First $MaxLines)
        $ev = ($shown -join "`n")
        if ($lines.Count -gt $shown.Count) { $ev += ("`n  ... and {0} more" -f ($lines.Count - $shown.Count)) }
        $paths = @(Get-ExistingFilePath -Path @($b.Paths.ToArray()))
        $id = ('DRIFT-{0}-{1}' -f ($b.Collection -replace '[^A-Za-z0-9]', '').ToUpperInvariant(), $b.Sev.ToUpperInvariant())
        if ($b.Collection -like '*-removed') {
            [void]$f.Add((New-DfirFinding -Id $id -Category $cat -Title ("Gone since {0}: {1} {2}" -f $since, $lines.Count, $label) -Severity 'Info' -Status 'Info' `
                -What ("These {0} were in the baseline and are no longer there:`n{1}" -f $label, $ev) -Why 'Removals are usually uninstalls or clean-ups. Listed so nothing changes silently.' -WhatToDo 'No action needed unless you did not expect one of these to go.' -Evidence $ev -Paths $paths))
        } elseif ($b.Collection -like '*-changed') {
            $status = if ($b.Sev -eq 'High') { 'Alert' } elseif ($b.Sev -eq 'Medium') { 'Review' } else { 'Info' }
            $why = if ($b.Sev -eq 'High') { 'Malware often takes over an existing, trusted-looking entry by changing its command line instead of adding a new one.' } else { 'A changed setting can be an update or someone weakening protection.' }
            [void]$f.Add((New-DfirFinding -Id $id -Category $cat -Title ("Changed since {0}: {1} {2}" -f $since, $lines.Count, $label) -Severity $b.Sev -Status $status `
                -What ("These {0} changed since the baseline:`n{1}" -f $label, $ev) -Why $why `
                -WhatToDo 'Check that each change matches something you did (an update, a setting you changed). If not, investigate the program it now points to and scan it with Defender.' -Evidence $ev -Paths $paths))
        } else {
            $status = if ($b.Sev -eq 'High') { 'Alert' } elseif ($b.Sev -eq 'Medium') { 'Review' } else { 'Info' }
            $why = switch ($base) {
                'localadmins'        { 'A new administrator can change anything on this PC. Attackers add one to keep control.' }
                'localusers'         { 'A new account you did not create is a common backdoor.' }
                'wmi'                { 'WMI subscriptions run code invisibly when an event happens. Legitimate software rarely adds new ones.' }
                'defenderexclusions' { 'Attackers add Defender exclusions so their files are never scanned.' }
                default              { 'New autostart and network entries are how malware stays on a PC. Most are new software you installed.' }
            }
            [void]$f.Add((New-DfirFinding -Id $id -Category $cat -Title ("New since {0}: {1} {2}" -f $since, $lines.Count, $label) -Severity $b.Sev -Status $status `
                -What ("These {0} were not in the baseline:`n{1}" -f $label, $ev) -Why $why `
                -WhatToDo 'Match each item against software you installed or changes you made since the baseline. Investigate anything you do not recognise; once you are happy with the current state, save a new baseline.' -Evidence $ev -Paths $paths))
        }
    }
    foreach ($n in @($Diff.Skipped.Keys)) {
        $label = if ($script:DriftLabel.ContainsKey($n)) { $script:DriftLabel[$n] } else { $n }
        [void]$f.Add((New-DfirFinding -Id ('DRIFT-SKIPPED-' + ($n -replace '[^A-Za-z0-9]', '').ToUpperInvariant()) -Category $cat -Title ("Not compared: {0}" -f $label) -Severity 'Info' -Status 'Info' `
            -What ("{0} could not be compared: {1}." -f $label, $Diff.Skipped[$n]) -Why 'A check that could not be compared is reported rather than silently treated as unchanged.' -WhatToDo 'Run as administrator, and save a new baseline if this keeps happening.' -Evidence ''))
    }
    if (@($buckets.Keys).Count -eq 0) {
        [void]$f.Add((New-DfirFinding -Id 'DRIFT-NONE' -Category $cat -Title ("No changes since {0}" -f $since) -Severity 'Info' -Status 'Clean' `
            -What 'Every compared startup item, service, task, account, exclusion, port and setting matches the baseline.' -Why '' -WhatToDo 'No action needed.' -Evidence ''))
    }
    return @($f.ToArray())
}

function Invoke-BaselineDrift {
    <# Read-only: snapshot now, compare with the saved baseline and return
       cards. One Info card when there is no baseline. #>
    param([string]$AutorunsCsv)
    $base = Read-Baseline
    if (-not $base) {
        return @(New-DfirFinding -Id 'DRIFT-NOBASELINE' -Category 'Changes since baseline' -Title 'No baseline saved yet' -Severity 'Info' -Status 'Info' `
            -What 'There is no saved baseline to compare with.' -Why 'A baseline records how this PC looks today, so later scans can show only what is new.' -WhatToDo 'When you are happy the PC is clean, click "Save as baseline" (needs administrator rights).' -Evidence '')
    }
    $now = Get-SystemSnapshot -AutorunsCsv $AutorunsCsv
    return @(ConvertTo-DriftFinding -Diff (Compare-Baseline -Baseline $base -Current $now))
}
