<#
    Autoruns.ps1
    Author: Ahmad Shaukat
    Autoruns Pro Tool: run autorunsc from MS Sysinternals, parse its CSV and turn
    it into Investigate cards. Autoruns covers WMI, image hijacks, Winlogon,
    AppInit, KnownDLLs, LSA providers, services, drivers and tasks with logic MS
    maintains, so this file only runs it and explains the results.
    Dot-sourced by SecurityCore.ps1.
#>

# Categories whose non-MS entries are an Alert on their own. Matched as
# case-insensitive keywords against the Category column (Autoruns prints
# "Image Hijacks", "AppInit", "Known DLLs", "LSA Providers", "Boot Execute",
# "Winlogon" and "WMI").
$script:AutorunsHighCategoryPattern = '(?i)hijack|appinit|known ?dlls?|lsa|boot ?execute|winlogon|wmi'

# Plain-English reason per category keyword (regex), first match wins.
$script:AutorunsCategoryWhy = [ordered]@{
    'hijack'          = 'Image hijacks make Windows start a different program whenever a normal one runs. Debuggers and accessibility-tool swaps are a classic backdoor.'
    'appinit'         = 'AppInit DLLs are loaded into almost every program. MS disables this feature on modern Windows because malware abused it.'
    'known ?dll'      = 'KnownDLLs tell Windows which system libraries to trust. An extra entry here can load attacker code into every process.'
    'lsa'             = 'LSA providers run inside the process that handles your passwords. A third-party entry here can read credentials.'
    'boot ?execute'   = 'Boot-execute programs run before Windows has fully started, before most security tools.'
    'winlogon'        = 'Winlogon entries run every time anyone signs in. Malware hides here to start with full rights.'
    'wmi'             = 'WMI subscriptions run code when an event happens, with no file in a normal startup folder. Attackers use them for hidden persistence.'
    'service|driver'  = 'Services and drivers start with the PC and run with high privileges. Malware installs itself as one to survive reboots.'
    'task'            = 'Scheduled tasks are a favourite way for malware to come back after a reboot or at set times.'
}

function Invoke-AutorunsScan {
    <# Runs autorunsc elevated and writes its CSV inside the tools tree. Never
       passes -v/-vs/-vt (VirusTotal) or -m (filtering is done here after the
       signature check). Integrity is checked by the caller immediately before. #>
    param([Parameter(Mandatory)][string]$ExePath, [scriptblock]$Progress)
    $report = { param($m) if ($Progress) { try { & $Progress $m } catch { Write-CoreLog -Message 'Progress callback failed.' -Level DEBUG } }; Write-CoreLog -Message $m -Level INFO }
    $outDir = Join-Path (Get-ExternalToolsRoot) 'autoruns\output'
    if (-not (Test-Path -LiteralPath $outDir -PathType Container)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        Set-ItemOwnerAdministrators -Path $outDir
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $out = Join-Path $outDir ("autoruns_{0}.csv" -f $stamp)
    $err = Join-Path $outDir ("autoruns_{0}.err.txt" -f $stamp)
    $argList = @('-accepteula', '-a', '*', '-c', '-h', '-s', '-t', '*')
    & $report 'Running Autoruns (checks every startup location and verifies signatures; this can take a few minutes)...'
    $p = Start-Process -FilePath $ExePath -ArgumentList $argList -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -Wait -PassThru
    foreach ($f in @($out, $err)) {
        if (Test-Path -LiteralPath $f -PathType Leaf) { Set-ItemOwnerAdministrators -Path $f }
    }
    if ($p.ExitCode -ne 0) {
        $detail = ''
        if (Test-Path -LiteralPath $err -PathType Leaf) { $detail = ([string](Get-Content -LiteralPath $err -Raw)).Trim() }
        throw ("Autoruns exited with code {0}. {1}" -f $p.ExitCode, $detail)
    }
    if (-not (Test-Path -LiteralPath $out -PathType Leaf)) { throw 'Autoruns did not produce an output file.' }
    Write-CoreLog -Message ("Autoruns finished. Output: {0}" -f $out) -Level INFO
    return [pscustomobject]@{ OutputPath = $out; Kind = 'AutorunsCsv' }
}

function ConvertFrom-AutorunsText {
    <# Decodes autorunsc output bytes: FF FE = Unicode, EF BB BF = UTF8, a zero
       second byte = Unicode without BOM, otherwise the ANSI code page. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    if ($Bytes.Length -eq 0) { return '' }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [System.Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [System.Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3) }
    if ($Bytes.Length -ge 2 -and $Bytes[1] -eq 0) { return [System.Text.Encoding]::Unicode.GetString($Bytes) }
    return [System.Text.Encoding]::Default.GetString($Bytes)
}

function Read-AutorunsCsv {
    <# Parses an autorunsc CSV into rows with fixed property names. Lines before
       the header (banner text) are skipped; columns are resolved by name, so a
       reordered or extended column set still parses. Rows with no Entry (the
       location header lines Autoruns prints) are dropped. #>
    param([Parameter(Mandatory)][string]$Path)
    $text = ConvertFrom-AutorunsText -Bytes ([System.IO.File]::ReadAllBytes($Path))
    $lines = @($text -split "`r?`n")
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'Entry Location') { $start = $i; break } }
    if ($start -lt 0) { throw ("No Autoruns header row (with 'Entry Location') was found in {0}." -f $Path) }
    $body = @($lines[$start..($lines.Count - 1)] | Where-Object { $_ -and $_.Trim() })
    $raw = @(ConvertFrom-Csv -InputObject $body)
    $map = [ordered]@{
        Time = 'Time'; EntryLocation = 'Entry Location'; Entry = 'Entry'; Enabled = 'Enabled'; Category = 'Category'
        Signer = 'Signer'; Company = 'Company'; ImagePath = 'Image Path'; LaunchString = 'Launch String'; Sha256 = 'SHA-256'
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($r in $raw) {
        $names = @($r.PSObject.Properties.Name)
        $row = [ordered]@{}
        foreach ($k in $map.Keys) {
            $col = $map[$k]
            $row[$k] = if ($names -contains $col) { ([string]$r.$col).Trim() } else { '' }
        }
        if (-not $row.Entry) { continue }
        [void]$out.Add([pscustomobject]$row)
    }
    return @($out.ToArray())
}

function Get-AutorunsRowClass {
    <# Hidden: signed and verified as MS. Medium when the file is missing: it
       cannot run, and clean Windows lists some (for example _wow64cpu in Known
       DLLs). High: anything else in a category that is risky on its own.
       Medium: unverified or unsigned, or from a user-writable folder.
       Low: verified non-MS publisher. #>
    param([Parameter(Mandatory)]$Row)
    $signer = [string]$Row.Signer
    if ($signer -match '^\(Verified\) Microsoft') { return 'Hidden' }
    if (([string]$Row.ImagePath -match '(?i)file not found') -or ([string]$Row.LaunchString -match '(?i)file not found')) { return 'Medium' }
    if ([string]$Row.Category -match $script:AutorunsHighCategoryPattern) { return 'High' }
    if ((-not $signer.Trim()) -or ($signer -match '^\(Not verified\)')) { return 'Medium' }
    if (Test-UserWritablePath -Path $Row.ImagePath) { return 'Medium' }
    return 'Low'
}

function Get-ExistingFilePath {
    <# The paths that exist as files right now, de-duplicated. #>
    param([AllowEmptyCollection()][string[]]$Path)
    $seen = @{}
    $out = New-Object System.Collections.ArrayList
    foreach ($p in @($Path)) {
        if (-not $p) { continue }
        $x = [Environment]::ExpandEnvironmentVariables($p.Trim().Trim('"'))
        if ($seen.ContainsKey($x.ToLowerInvariant())) { continue }
        $seen[$x.ToLowerInvariant()] = $true
        try { if (Test-Path -LiteralPath $x -PathType Leaf) { [void]$out.Add($x) } } catch { Write-CoreLog -Message ("Path check failed for {0}: {1}" -f $x, $_.Exception.Message) -Level DEBUG }
    }
    return @($out.ToArray())
}

function ConvertFrom-AutorunsCsv {
    <# Turns an autorunsc CSV into Investigate cards: one card per category for
       High and Medium rows (at most 25 evidence lines each, the rest in the CSV)
       and one count card for verified non-MS publishers. #>
    param([Parameter(Mandatory)][string]$CsvPath, [int]$MaxLines = 25)
    $cat = 'Autoruns (startup locations)'
    $f = New-Object System.Collections.ArrayList
    $rows = @(Read-AutorunsCsv -Path $CsvPath)
    $classed = @($rows | ForEach-Object { [pscustomobject]@{ Row = $_; Class = (Get-AutorunsRowClass -Row $_) } })
    $hiddenCount = @($classed | Where-Object { $_.Class -eq 'Hidden' }).Count
    $flagged = @($classed | Where-Object { $_.Class -eq 'High' -or $_.Class -eq 'Medium' })
    $low = @($classed | Where-Object { $_.Class -eq 'Low' })

    foreach ($g in @($flagged | Group-Object { [string]$_.Row.Category } | Sort-Object Name)) {
        $items = @($g.Group)
        $isHigh = @($items | Where-Object { $_.Class -eq 'High' }).Count -gt 0
        $category = if ($g.Name) { $g.Name } else { 'Other' }
        $lines = @($items | Select-Object -First $MaxLines | ForEach-Object {
            $r = $_.Row
            $state = if ([string]$r.Enabled -match '(?i)^enabled$') { '' } else { ' [disabled]' }
            $signer = if ($r.Signer) { $r.Signer } else { '(no signature)' }
            "  {0}{1}  ->  {2}  |  {3}  |  {4}" -f $r.Entry, $state, $(if ($r.ImagePath) { $r.ImagePath } else { $r.LaunchString }), $signer, $r.EntryLocation
        })
        $more = $items.Count - $lines.Count
        $ev = ($lines -join "`n")
        if ($more -gt 0) { $ev += ("`n  ... and {0} more. See the full list in {1}" -f $more, $CsvPath) }
        $why = 'Programs here start automatically. Unsigned or unverified entries, and entries running from folders any user can write to, are the usual places malware hides.'
        foreach ($k in $script:AutorunsCategoryWhy.Keys) { if ($category -match ('(?i)' + $k)) { $why = $script:AutorunsCategoryWhy[$k]; break } }
        $id = 'AUTORUNS-' + (($category -replace '[^A-Za-z0-9]', '').ToUpperInvariant())
        $paths = @(Get-ExistingFilePath -Path @($items | ForEach-Object { $_.Row.ImagePath }))
        if ($isHigh) {
            [void]$f.Add((New-DfirFinding -Id $id -Category $cat -Title ("{0}: {1} non-MS entr{2} found" -f $category, $items.Count, $(if ($items.Count -eq 1) { 'y' } else { 'ies' })) -Severity 'High' -Status 'Alert' `
                -What ("Autoruns found these entries in {0}, a place where almost everything should come from MS:`n{1}" -f $category, $ev) `
                -Why $why `
                -WhatToDo ("Look up each entry. If you did not install the software it belongs to, treat the PC as compromised: disconnect it from the network and get expert help. Scan the files with Defender. Full details: {0}" -f $CsvPath) `
                -Evidence $ev -Paths $paths))
        } else {
            [void]$f.Add((New-DfirFinding -Id $id -Category $cat -Title ("{0}: {1} entr{2} to review" -f $category, $items.Count, $(if ($items.Count -eq 1) { 'y' } else { 'ies' })) -Severity 'Medium' -Status 'Review' `
                -What ("These {0} entries are unsigned, not verified, run from a folder any user can write to, or point at a missing file:`n{1}" -f $category, $ev) `
                -Why $why `
                -WhatToDo ("Recognise each one? Then it is fine. If not, scan the file with Defender and turn the entry off in Autoruns or the Startup tab. Full details: {0}" -f $CsvPath) `
                -Evidence $ev -Paths $paths))
        }
    }

    if ($flagged.Count -eq 0) {
        [void]$f.Add((New-DfirFinding -Id 'AUTORUNS-CLEAN' -Category $cat -Title 'Autoruns found nothing unusual' -Severity 'Info' -Status 'Clean' `
            -What ("Autoruns checked {0} startup entr{1}. {2} are signed by MS and hidden; none of the rest are unsigned, unverified, in a risky location or in a high-risk category." -f $rows.Count, $(if ($rows.Count -eq 1) { 'y' } else { 'ies' }), $hiddenCount) `
            -Why '' -WhatToDo ("No action needed. The full list is in {0}" -f $CsvPath) -Evidence ''))
    }

    if ($low.Count -gt 0) {
        $byCompany = @($low | Group-Object { $(if ($_.Row.Company) { $_.Row.Company } else { ($_.Row.Signer -replace '^\(Verified\)\s*', '') }) } | Sort-Object Count -Descending)
        $top = @($byCompany | Select-Object -First $MaxLines | ForEach-Object { "  {0}: {1}" -f $_.Name, $_.Count })
        $ev = ($top -join "`n")
        if ($byCompany.Count -gt $top.Count) { $ev += ("`n  ... and {0} more publisher(s). See {1}" -f ($byCompany.Count - $top.Count), $CsvPath) }
        [void]$f.Add((New-DfirFinding -Id 'AUTORUNS-VERIFIED' -Category $cat -Title ("Autoruns: {0} entr{1} from verified non-MS publishers" -f $low.Count, $(if ($low.Count -eq 1) { 'y' } else { 'ies' })) -Severity 'Low' -Status 'Info' `
            -What ("These start automatically and carry a verified signature from a publisher other than MS:`n{0}" -f $ev) `
            -Why 'A verified signature tells you who made the program. It does not tell you that you wanted it.' `
            -WhatToDo ("Glance over the publishers. Remove software you do not use. Full details: {0}" -f $CsvPath) `
            -Evidence $ev -Paths @(Get-ExistingFilePath -Path @($low | ForEach-Object { $_.Row.ImagePath }))))
    }
    Write-CoreLog -Message ("Autoruns: {0} rows, {1} hidden (MS), {2} flagged, {3} verified non-MS." -f $rows.Count, $hiddenCount, $flagged.Count, $low.Count) -Level INFO
    return @($f.ToArray())
}
