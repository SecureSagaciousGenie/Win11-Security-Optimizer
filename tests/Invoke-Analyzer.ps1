<#
    Invoke-Analyzer.ps1
    Author: Ahmad Shaukat
    Runs PSScriptAnalyzer with the repo settings over every script. Exits 1 when
    any Error-severity result is found. Warnings are printed only.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
$files = @(Get-ChildItem -Path $root -Recurse -Include *.ps1, *.psm1 -File | Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })
$results = New-Object System.Collections.ArrayList
foreach ($f in $files) {
    foreach ($r in @(Invoke-ScriptAnalyzer -Path $f.FullName -Settings $settings)) { [void]$results.Add($r) }
}
$all = @($results.ToArray())
$errors = @($all | Where-Object { "$($_.Severity)" -eq 'Error' })
$all | Sort-Object Severity, ScriptName, Line | Format-Table Severity, RuleName, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 220 | Write-Output
Write-Output ("Analyzer: {0} error(s), {1} warning(s) across {2} file(s)." -f $errors.Count, ($all.Count - $errors.Count), $files.Count)
if ($errors.Count -gt 0) { exit 1 }
exit 0
