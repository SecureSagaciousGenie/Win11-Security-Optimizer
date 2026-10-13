<#
    Evidence.ps1
    Author: Ahmad Shaukat
    Evidence pack: event logs, a snapshot, processes, TCP connections and the
    current findings, zipped with a manifest of SHA-256 hashes. Also the
    "Scan with Defender" card action and the headless-scan exit code.
    Dot-sourced by SecurityCore.ps1.
#>

$script:EvidenceLogs = @(
    'Security', 'System', 'Application',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-Sysmon/Operational'
)
$script:EvidenceWarnBytes = 1GB

function Get-ProcessEvidence {
    <# Running processes with path, SHA-256, signer and command line. Read-only. #>
    $sigCache = @{}
    $out = New-Object System.Collections.ArrayList
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
        $path = [string]$p.ExecutablePath
        $sha = ''; $signer = ''; $sigStatus = ''
        if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            if (-not $sigCache.ContainsKey($path)) {
                $h = ''; $s = ''; $st = ''
                try { $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $h = 'unreadable' }
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
                    $st = [string]$sig.Status
                    if ($sig.SignerCertificate) { $s = [string]$sig.SignerCertificate.Subject }
                } catch { $st = 'unreadable' }
                $sigCache[$path] = @($h, $s, $st)
            }
            $sha = $sigCache[$path][0]; $signer = $sigCache[$path][1]; $sigStatus = $sigCache[$path][2]
        }
        [void]$out.Add([pscustomobject][ordered]@{
            ProcessId = [int]$p.ProcessId; ParentProcessId = [int]$p.ParentProcessId; Name = [string]$p.Name
            Path = $path; Sha256 = $sha; Signer = $signer; SignatureStatus = $sigStatus; CommandLine = [string]$p.CommandLine
        })
    }
    return @($out.ToArray())
}

function Get-TcpEvidence {
    <# All TCP connections with the owning process name and path. Read-only. #>
    $names = @{}
    $out = New-Object System.Collections.ArrayList
    foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop)) {
        $owner = [int]$c.OwningProcess
        if (-not $names.ContainsKey($owner)) {
            $n = ''; $pth = ''
            try {
                $proc = Get-Process -Id $owner -ErrorAction Stop
                $n = [string]$proc.ProcessName
                if ($proc.PSObject.Properties.Name -contains 'Path') { $pth = [string]$proc.Path }
            } catch { $n = '(exited)' }
            $names[$owner] = @($n, $pth)
        }
        [void]$out.Add([pscustomobject][ordered]@{
            LocalAddress = [string]$c.LocalAddress; LocalPort = [int]$c.LocalPort; RemoteAddress = [string]$c.RemoteAddress; RemotePort = [int]$c.RemotePort
            State = [string]$c.State; ProcessId = $owner; ProcessName = $names[$owner][0]; ProcessPath = $names[$owner][1]
        })
    }
    return @($out.ToArray())
}

function Get-EvidenceLogFileName {
    param([Parameter(Mandatory)][string]$LogName)
    return (($LogName -replace '[\\/:*?"<>| ]', '_') + '.evtx')
}

function New-EvidencePack {
    <# Main thread, elevated. Stages everything in a new folder under the secure
       base, writes manifest.json with the SHA-256 of every file, zips it to
       $Destination and deletes the staging folder. Returns the zip path, size,
       file count and a warning when it is over 1 GB. #>
    param(
        [Parameter(Mandatory)][string]$Destination,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [scriptblock]$Progress
    )
    $report = { param($m) if ($Progress) { try { & $Progress $m } catch { Write-CoreLog -Message 'Progress callback failed.' -Level DEBUG } }; Write-CoreLog -Message $m -Level INFO }
    if (-not (Test-IsAdmin)) { throw 'An evidence pack needs administrator rights (the Security log is admin-only).' }
    $base = Join-Path $env:ProgramData 'Win11SecurityOptimizer'
    if (-not (Test-Path -LiteralPath $base -PathType Container)) { throw 'The secure data folder is not ready. Restart the tool as administrator.' }
    $evRoot = Join-Path $base 'evidence'
    if (-not (Test-Path -LiteralPath $evRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $evRoot -Force | Out-Null
        Set-ItemOwnerAdministrators -Path $evRoot
    }
    $stage = Join-Path $evRoot ('stage_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Set-ItemOwnerAdministrators -Path $stage
    $logsDir = Join-Path $stage 'logs'
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    Set-ItemOwnerAdministrators -Path $logsDir
    $notes = New-Object System.Collections.ArrayList
    try {
        foreach ($log in $script:EvidenceLogs) {
            $exists = $true
            try { [void](Get-WinEvent -ListLog $log -ErrorAction Stop) } catch { $exists = $false }
            if (-not $exists) { [void]$notes.Add(("Skipped {0}: this log does not exist on this PC." -f $log)); continue }
            & $report ("Exporting the {0} log..." -f $log)
            $dest = Join-Path $logsDir (Get-EvidenceLogFileName -LogName $log)
            $r = Invoke-NativeCommand -FilePath 'wevtutil.exe' -ArgumentList @('epl', $log, $dest)
            if ($r.ExitCode -ne 0) { [void]$notes.Add(("Could not export {0} (wevtutil exit code {1}): {2}" -f $log, $r.ExitCode, $r.Output)); continue }
            if (Test-Path -LiteralPath $dest -PathType Leaf) { Set-ItemOwnerAdministrators -Path $dest }
        }
        $json = [ordered]@{
            'snapshot.json'  = { Get-SystemSnapshot }
            'processes.json' = { Get-ProcessEvidence }
            'tcp.json'       = { Get-TcpEvidence }
            'findings.json'  = { @($Findings) }
        }
        foreach ($name in @($json.Keys)) {
            & $report ("Collecting {0}..." -f $name)
            $value = $null
            try { $value = & $json[$name] } catch { [void]$notes.Add(("Could not collect {0}: {1}" -f $name, $_.Exception.Message)); continue }
            if ($name -ne 'snapshot.json') { $value = @($value) }
            Write-SecureFile -Path (Join-Path $stage $name) -Value (ConvertTo-Json -InputObject $value -Depth 6)
        }
        & $report 'Hashing the collected files...'
        $files = New-Object System.Collections.ArrayList
        foreach ($f in @(Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName)) {
            $rel = $f.FullName.Substring($stage.Length).TrimStart('\', '/') -replace '\\', '/'
            [void]$files.Add([pscustomobject][ordered]@{ Path = $rel; Bytes = [int64]$f.Length; Sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash })
        }
        $manifest = [ordered]@{
            Tool = [string]$script:Core.Name; ToolVersion = [string]$script:Core.Version
            Machine = [string]$env:COMPUTERNAME; Operator = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
            CreatedUtc = (Get-Date).ToUniversalTime().ToString('o'); Files = @($files.ToArray()); Notes = @($notes.ToArray())
        }
        Write-SecureFile -Path (Join-Path $stage 'manifest.json') -Value (ConvertTo-Json -InputObject $manifest -Depth 6)
        & $report 'Compressing the evidence pack...'
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $Destination -Force
    } finally {
        # Our own freshly created folder; nothing in it is a link.
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $stage) { Write-CoreLog -Message ("The staging folder could not be removed: {0}" -f $stage) -Level WARN }
    }
    $size = (Get-Item -LiteralPath $Destination).Length
    $warning = ''
    if ($size -gt $script:EvidenceWarnBytes) { $warning = ("The evidence pack is {0:N1} GB. Large files can be hard to send; share it through a file transfer service rather than email." -f ($size / 1GB)) }
    Add-ChangeRecord -Description ("Created an evidence pack: {0} ({1:N1} MB, {2} files)" -f $Destination, ($size / 1MB), $files.Count)
    return [pscustomobject]@{ Path = $Destination; SizeBytes = [int64]$size; FileCount = $files.Count; Warning = $warning; Notes = @($notes.ToArray()) }
}

function Invoke-DefenderPathScan {
    <# Card action, run in a background runspace: a Defender custom scan of
       each path, then the detections recorded since the scan started. Defender
       decides what to do with anything it finds; this only asks it to look. #>
    param([Parameter(Mandatory)][string[]]$Path)
    $start = Get-Date
    $scanned = New-Object System.Collections.ArrayList
    $errors = New-Object System.Collections.ArrayList
    foreach ($p in @($Path | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { [void]$errors.Add(("{0}: file no longer exists" -f $p)); continue }
        try { Start-MpScan -ScanType CustomScan -ScanPath $p -ErrorAction Stop; [void]$scanned.Add($p) }
        catch { [void]$errors.Add(("{0}: {1}" -f $p, $_.Exception.Message)) }
    }
    $detections = @()
    try {
        $detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $start } | ForEach-Object {
            [pscustomobject]@{ ThreatId = [string]$_.ThreatID; Time = $_.InitialDetectionTime; Resources = (@($_.Resources) -join '; '); ActionSuccess = [bool]$_.ActionSuccess }
        })
    } catch { [void]$errors.Add(("Detections could not be read: {0}" -f $_.Exception.Message)) }
    return [pscustomobject]@{ Scanned = @($scanned.ToArray()); Detections = @($detections); Errors = @($errors.ToArray()) }
}

function Get-ScanExitCode {
    <# Headless scan result: 2 when any card is an Alert, 1 when any card is to
       Review or any security check failed or warned, otherwise 0. #>
    param([AllowEmptyCollection()][object[]]$SecurityFindings = @(), [AllowEmptyCollection()][object[]]$Cards = @())
    if (@($Cards | Where-Object { $_ -and $_.Status -eq 'Alert' }).Count -gt 0) { return 2 }
    if (@($Cards | Where-Object { $_ -and $_.Status -eq 'Review' }).Count -gt 0) { return 1 }
    if (@($SecurityFindings | Where-Object { $_ -and ($_.Status -eq 'Fail' -or $_.Status -eq 'Warning') }).Count -gt 0) { return 1 }
    return 0
}
