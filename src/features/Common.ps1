<#
    Common.ps1
    Author: Ahmad Shaukat
    Shared helpers for the feature files. Dot-sourced by SecurityCore.ps1.
#>

function Test-MicrosoftSigned {
    <# True only for a valid Authenticode signature whose signer organisation is
       Microsoft Corporation and whose chain ends at a Microsoft Root Certificate
       Authority. Used for MS tools downloaded at runtime (Sysinternals). #>
    param([Parameter(Mandatory)][string]$Path)
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return $false }
    if ($sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') { return $false }
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    [void]$chain.Build($sig.SignerCertificate)
    $elements = @($chain.ChainElements)
    if ($elements.Count -eq 0) { return $false }
    $root = $elements[$elements.Count - 1].Certificate
    return ($root.Subject -match 'CN=Microsoft Root Certificate Authority')
}

function Register-SecurityCheck {
    <# Adds a read-only check to the Security scan and, optionally, its fix and
       verify scriptblocks. Re-registering the same Id replaces the entry. #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][scriptblock]$Check,
        [scriptblock]$FixAction,
        [scriptblock]$FixTest
    )
    $script:ExtraSecurityChecks[$Id] = $Check
    if ($FixAction) { $script:ExtraFixActions[$Id] = $FixAction }
    if ($FixTest)   { $script:ExtraFixTests[$Id]   = $FixTest }
}

function Test-UserWritablePath {
    <# True when a path sits in a folder standard users can normally write to:
       a user profile (AppData, Downloads, Desktop), Public, a Temp folder,
       ProgramData or the Recycle Bin. A string test only; it never touches the
       file system, so it is safe on paths from untrusted data. #>
    param([AllowEmptyString()][AllowNull()][string]$Path)
    if (-not $Path) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    return ($p -match '(?i)^([a-z]:)?\\(Users\\[^\\]+\\|ProgramData\\|Windows\\Temp\\|\$Recycle\.Bin\\)|\\AppData\\|\\Temp\\')
}

function Invoke-NativeCommand {
    <# Runs an external program with arguments passed as separate tokens and
       returns its combined output and exit code. One place to mock in tests;
       never builds a command string. #>
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$ArgumentList = @())
    # Windows PowerShell 5.1 turns redirected stderr into a terminating error
    # when the caller runs with ErrorActionPreference Stop (the GUI does). Many
    # tools print usage text to stderr, so collect it as output instead; the
    # exit code decides success.
    $ErrorActionPreference = 'Continue'
    $out = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($out -join "`n") }
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
