<#
    Report.ps1
    Author: Ahmad Shaukat
    HTML report: one self-contained, print-friendly file of this session. Inline
    CSS only; no script and no external fonts. Every dynamic value is encoded
    with [System.Net.WebUtility]::HtmlEncode.
    Dot-sourced by SecurityCore.ps1.
#>

function ConvertTo-HtmlText {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-InstalledToolSummary {
    <# Installed external tools with version and recorded exe SHA-256, read from
       each install.json. Read-only. #>
    $out = New-Object System.Collections.ArrayList
    foreach ($t in @(Get-ExternalToolRegistry)) {
        $exe = $null
        try { $exe = Test-ExternalToolInstalled -Key $t.Key } catch { $exe = $null }
        if (-not $exe) { continue }
        $ver = ''; $sha = ''
        $dir = Get-ExternalToolInstallDir -ExePath $exe
        if (-not $dir) { $dir = Split-Path -Path $exe -Parent }
        $meta = Join-Path $dir 'install.json'
        try {
            if (Test-Path -LiteralPath $meta -PathType Leaf) {
                $m = Get-Content -LiteralPath $meta -Raw | ConvertFrom-Json
                if ($m.PSObject.Properties.Name -contains 'Version') { $ver = [string]$m.Version }
                if (($m.PSObject.Properties.Name -contains 'VersionText') -and $ver -eq 'latest') { $ver = [string]$m.VersionText }
                if ($m.PSObject.Properties.Name -contains 'ExeSha256') { $sha = [string]$m.ExeSha256 }
            }
        } catch { Write-CoreLog -Message ("Could not read {0}: {1}" -f $meta, $_.Exception.Message) -Level WARN }
        [void]$out.Add([pscustomobject]@{ Name = $t.Name; Vendor = $t.Vendor; License = $t.License; Version = $ver; ExePath = $exe; Sha256 = $sha })
    }
    return @($out.ToArray())
}

function Get-DfirCardGroup {
    <# Splits Investigate cards into native, drift and Pro Tools results by Id. #>
    param([AllowEmptyCollection()][object[]]$Cards)
    $drift = @(); $pro = @(); $native = @()
    foreach ($c in @($Cards | Where-Object { $_ })) {
        $id = [string]$c.Id
        if ($id -like 'DRIFT-*') { $drift += $c }
        elseif ($id -match '^(HAYA|CHAIN|AUTORUNS)-') { $pro += $c }
        else { $native += $c }
    }
    return [pscustomobject]@{ Native = @($native); Drift = @($drift); Pro = @($pro) }
}

function New-HtmlReport {
    <# Returns the report HTML as a string. Pure: it reads nothing it is not
       given except the installed-tool manifests. #>
    param(
        [AllowEmptyCollection()][object[]]$SecurityFindings = @(),
        $Score,
        [AllowEmptyCollection()][object[]]$DfirCards = @(),
        [AllowEmptyCollection()][object[]]$Changes = @(),
        [string]$RollbackPath,
        [AllowEmptyCollection()][object[]]$Tools = @(),
        [datetime]$SessionStart = (Get-Date),
        [string]$MachineName = $env:COMPUTERNAME
    )
    $h = { param($v) ConvertTo-HtmlText $v }
    $sb = New-Object System.Text.StringBuilder
    $now = Get-Date
    $groups = Get-DfirCardGroup -Cards $DfirCards
    $sevClass = @{ 'Critical' = 'crit'; 'High' = 'high'; 'Medium' = 'med'; 'Low' = 'low'; 'Info' = 'info' }

    $cardHtml = {
        param($list, [string]$emptyText)
        $x = New-Object System.Text.StringBuilder
        $items = @(Sort-DfirFinding -Findings @($list))
        if ($items.Count -eq 0) { [void]$x.AppendLine(('<p class="muted">{0}</p>' -f (& $h $emptyText))); return $x.ToString() }
        foreach ($c in $items) {
            $cls = if ($sevClass.ContainsKey([string]$c.Severity)) { $sevClass[[string]$c.Severity] } else { 'info' }
            [void]$x.AppendLine(('<div class="card {0}"><div class="card-head"><span class="badge {0}">{1}</span> <span class="status">{2}</span> <strong>{3}</strong></div>' -f $cls, (& $h $c.Severity), (& $h $c.Status), (& $h $c.Title)))
            if ($c.What) { [void]$x.AppendLine(('<pre>{0}</pre>' -f (& $h $c.What))) }
            if ($c.Why) { [void]$x.AppendLine(('<p><em>Why it matters:</em> {0}</p>' -f (& $h $c.Why))) }
            if ($c.WhatToDo) { [void]$x.AppendLine(('<p><em>What to do:</em> {0}</p>' -f (& $h $c.WhatToDo))) }
            $paths = @()
            if ($c.PSObject.Properties.Name -contains 'Paths') { $paths = @($c.Paths | Where-Object { $_ }) }
            if ($paths.Count -gt 0) { [void]$x.AppendLine(('<p class="muted">Files: {0}</p>' -f ((@($paths | ForEach-Object { & $h $_ })) -join '; '))) }
            [void]$x.AppendLine('</div>')
        }
        return $x.ToString()
    }

    $alerts = @($DfirCards | Where-Object { $_ -and $_.Status -eq 'Alert' }).Count
    $reviews = @($DfirCards | Where-Object { $_ -and $_.Status -eq 'Review' }).Count
    $fails = @($SecurityFindings | Where-Object { $_ -and ($_.Status -eq 'Fail' -or $_.Status -eq 'Warning') }).Count
    $scoreText = ''
    $gradeText = ''
    if ($Score) {
        if ($Score.PSObject.Properties.Name -contains 'Score') { $scoreText = [string]$Score.Score }
        if ($Score.PSObject.Properties.Name -contains 'Grade') { $gradeText = [string]$Score.Grade }
    }

    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine(('<title>Security report for {0}</title>' -f (& $h $MachineName)))
    [void]$sb.AppendLine(@'
<style>
body { font-family: "Segoe UI", Arial, sans-serif; color: #1F2328; background: #FFFFFF; margin: 24px; font-size: 13px; line-height: 1.45; }
h1 { font-size: 22px; margin: 0 0 4px 0; } h2 { font-size: 17px; border-bottom: 2px solid #2F81F7; padding-bottom: 4px; margin-top: 28px; }
.warn { background: #FFF4E5; border: 1px solid #D29922; padding: 8px 12px; border-radius: 6px; font-weight: 600; }
.muted { color: #6E7681; } table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th, td { border: 1px solid #D0D7DE; padding: 5px 8px; text-align: left; vertical-align: top; } th { background: #F6F8FA; }
.card { border: 1px solid #D0D7DE; border-left: 5px solid #2F81F7; border-radius: 6px; padding: 8px 12px; margin: 10px 0; page-break-inside: avoid; }
.card.crit, .card.high { border-left-color: #F85149; } .card.med { border-left-color: #D29922; } .card.low { border-left-color: #6E7681; }
.badge { display: inline-block; padding: 1px 6px; border-radius: 4px; color: #FFFFFF; background: #2F81F7; font-size: 11px; font-weight: 700; }
.badge.crit, .badge.high { background: #F85149; } .badge.med { background: #D29922; } .badge.low { background: #6E7681; }
.status { color: #6E7681; font-size: 11px; text-transform: uppercase; }
pre { white-space: pre-wrap; word-wrap: break-word; font-family: Consolas, monospace; font-size: 12px; background: #F6F8FA; padding: 6px 8px; border-radius: 4px; }
.pass { color: #1A7F37; font-weight: 600; } .fail { color: #CF222E; font-weight: 600; } .warning { color: #9A6700; font-weight: 600; }
@media print { body { margin: 10mm; } h2 { page-break-after: avoid; } }
</style>
'@)
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine(('<h1>Windows 11 Security Optimizer report: {0}</h1>' -f (& $h $MachineName)))
    [void]$sb.AppendLine('<p class="warn">Contains user names and file paths. Share carefully.</p>')

    [void]$sb.AppendLine('<h2>Summary</h2><table>')
    [void]$sb.AppendLine(('<tr><th>Security score</th><td>{0} {1}</td></tr>' -f (& $h $scoreText), (& $h $gradeText)))
    [void]$sb.AppendLine(('<tr><th>Security checks needing attention</th><td>{0} of {1}</td></tr>' -f $fails, @($SecurityFindings).Count))
    [void]$sb.AppendLine(('<tr><th>Investigate</th><td>{0} alert(s), {1} to review, {2} card(s) in total</td></tr>' -f $alerts, $reviews, @($DfirCards).Count))
    [void]$sb.AppendLine(('<tr><th>Tool version</th><td>{0}</td></tr>' -f (& $h $script:Core.Version)))
    [void]$sb.AppendLine(('<tr><th>Session started</th><td>{0}</td></tr>' -f (& $h $SessionStart.ToString('yyyy-MM-dd HH:mm:ss'))))
    [void]$sb.AppendLine(('<tr><th>Report created</th><td>{0} (UTC {1})</td></tr>' -f (& $h $now.ToString('yyyy-MM-dd HH:mm:ss')), (& $h $now.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))))
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Security findings</h2>')
    if (@($SecurityFindings).Count -eq 0) { [void]$sb.AppendLine('<p class="muted">No security scan was run in this session.</p>') }
    else {
        [void]$sb.AppendLine('<table><tr><th>Status</th><th>Check</th><th>Severity</th><th>Current</th><th>Expected</th><th>Advice</th></tr>')
        foreach ($f in @($SecurityFindings | Where-Object { $_ })) {
            $cls = ([string]$f.Status).ToLowerInvariant()
            [void]$sb.AppendLine(('<tr><td class="{0}">{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f (& $h $cls), (& $h $f.Status), (& $h $f.Name), (& $h $f.Severity), (& $h $f.Observed), (& $h $f.Expected), (& $h $f.Advice)))
        }
        [void]$sb.AppendLine('</table>')
    }

    [void]$sb.AppendLine('<h2>Investigate</h2>')
    [void]$sb.AppendLine((& $cardHtml $groups.Native 'No investigation was run in this session.'))
    [void]$sb.AppendLine('<h2>Changes since baseline</h2>')
    [void]$sb.AppendLine((& $cardHtml $groups.Drift 'No baseline comparison was run in this session.'))
    [void]$sb.AppendLine('<h2>Pro Tools results</h2>')
    [void]$sb.AppendLine((& $cardHtml $groups.Pro 'No Pro Tool was run in this session.'))

    [void]$sb.AppendLine('<h2>Changes made this session</h2>')
    if (@($Changes).Count -eq 0) { [void]$sb.AppendLine('<p class="muted">No changes were made.</p>') }
    else {
        [void]$sb.AppendLine('<table><tr><th>Time</th><th>Change</th></tr>')
        foreach ($c in @($Changes | Where-Object { $_ })) { [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $h $c.Time), (& $h $c.Change))) }
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine('<h2>Rollback</h2>')
    if ($RollbackPath -and @($Changes).Count -gt 0) {
        [void]$sb.AppendLine(('<p>To undo this session''s changes, run this script in an elevated PowerShell after reviewing it:</p><pre>powershell -ExecutionPolicy Bypass -File "{0}"</pre>' -f (& $h $RollbackPath)))
    } else { [void]$sb.AppendLine('<p class="muted">Nothing to roll back.</p>') }

    [void]$sb.AppendLine('<h2>External tools</h2>')
    if (@($Tools).Count -eq 0) { [void]$sb.AppendLine('<p class="muted">No external tools are installed.</p>') }
    else {
        [void]$sb.AppendLine('<table><tr><th>Tool</th><th>Vendor</th><th>Version</th><th>License</th><th>Executable SHA-256</th></tr>')
        foreach ($t in @($Tools | Where-Object { $_ })) { [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td><code>{4}</code></td></tr>' -f (& $h $t.Name), (& $h $t.Vendor), (& $h $t.Version), (& $h $t.License), (& $h $t.Sha256))) }
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine(('<p class="muted">Generated by {0} v{1} on {2}.</p>' -f (& $h $script:Core.Name), (& $h $script:Core.Version), (& $h $now.ToString('yyyy-MM-dd HH:mm:ss'))))
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}
