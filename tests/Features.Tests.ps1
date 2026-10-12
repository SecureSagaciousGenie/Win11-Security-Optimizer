<#
    Features.Tests.ps1
    Author: Ahmad Shaukat
    Tests for src/features and the extension points in SecurityCore.ps1.
    Every system call is mocked. LOCALAPPDATA and ProgramData point at TestDrive.
#>

BeforeDiscovery {
    $script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Test-Path variable:IsWindows) -and $IsWindows)
}

Describe 'Features' {
    BeforeAll {
        $script:RepoRoot = Split-Path -Parent $PSScriptRoot
        $script:SavedEnv = @{ LOCALAPPDATA = $env:LOCALAPPDATA; ProgramData = $env:ProgramData; W11SO_SESSION_LOG = $env:W11SO_SESSION_LOG }
        $env:LOCALAPPDATA = Join-Path $TestDrive 'LocalAppData'
        $env:ProgramData  = Join-Path $TestDrive 'ProgramData'
        Remove-Item -Path Env:\W11SO_SESSION_LOG -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $env:LOCALAPPDATA, $env:ProgramData -Force | Out-Null

        . (Join-Path $PSScriptRoot 'Fakes.ps1')
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        . (Join-Path $script:RepoRoot 'src\SecurityCore.ps1')

        Mock Test-IsAdmin { $false }
        Mock New-SystemRestorePointOnce { $true }
        Initialize-Core | Out-Null

        function New-TestZip {
            <# Builds a zip whose entries are given as name = content. #>
            param([string]$Path, [hashtable]$Entries)
            Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
            if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
            $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($k in $Entries.Keys) {
                    $e = $zip.CreateEntry($k)
                    $w = New-Object System.IO.StreamWriter($e.Open())
                    try { $w.Write([string]$Entries[$k]) } finally { $w.Dispose() }
                }
            } finally { $zip.Dispose() }
        }
    }
    AfterAll {
        $env:LOCALAPPDATA = $script:SavedEnv.LOCALAPPDATA
        $env:ProgramData  = $script:SavedEnv.ProgramData
        if ($script:SavedEnv.W11SO_SESSION_LOG) { $env:W11SO_SESSION_LOG = $script:SavedEnv.W11SO_SESSION_LOG }
        else { Remove-Item -Path Env:\W11SO_SESSION_LOG -ErrorAction SilentlyContinue }
    }
    BeforeEach { Set-StrictMode -Version 2.0 }

    Describe 'Phase 3: feature loading' {
        It 'lists every feature file explicitly and in a fixed order' {
            $parsed = Get-ScriptAst -Path (Join-Path $script:RepoRoot 'src\SecurityCore.ps1')
            $listed = @(Get-FeatureFileList -Ast $parsed.Ast)
            $listed | Should -Be @('Common.ps1', 'Autoruns.ps1', 'Baseline.ps1', 'Hardening.ps1', 'Sysmon.ps1', 'Report.ps1', 'Evidence.ps1')
            $onDisk = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src\features') -Filter *.ps1 | ForEach-Object { $_.Name } | Sort-Object)
            $onDisk | Should -Be @($listed | Sort-Object)
        }
        It 'loads the shared helpers' {
            Get-Command Test-MicrosoftSigned -CommandType Function | Should -Not -BeNullOrEmpty
            Get-Command Register-SecurityCheck -CommandType Function | Should -Not -BeNullOrEmpty
        }
        It 'every feature file carries the author line' {
            foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src\features') -Filter *.ps1) {
                (Get-Content -LiteralPath $f.FullName -TotalCount 6) -join "`n" | Should -Match 'Author: Ahmad Shaukat'
            }
        }
    }

    Describe 'Phase 3: extension hooks' {
        AfterEach {
            [void]$script:ExtraSecurityChecks.Remove('TEST-X')
            [void]$script:ExtraFixActions.Remove('TEST-X')
            [void]$script:ExtraFixTests.Remove('TEST-X')
        }
        It 'runs registered checks and keeps single results as findings' {
            Register-SecurityCheck -Id 'TEST-X' -Check { New-Finding -Id 'TEST-X' -Category 'T' -Name 'x' -Severity 'Low' -Status 'Fail' -Observed 'a' -Expected 'b' }
            $r = @(Invoke-ExtraSecurityCheck)
            @($r | Where-Object { $_.Id -eq 'TEST-X' }).Count | Should -Be 1
        }
        It 'turns a throwing check into an Error finding that names it' {
            Register-SecurityCheck -Id 'TEST-X' -Check { throw 'boom' }
            $r = @(Invoke-ExtraSecurityCheck | Where-Object { $_.Id -eq 'TEST-X' })
            $r.Count | Should -Be 1
            $r[0].Status | Should -Be 'Error'
            $r[0].Detail | Should -Match 'boom'
        }
        It 'Invoke-SecurityScan appends the registered checks' {
            $parsed = Get-ScriptAst -Path (Join-Path $script:RepoRoot 'src\SecurityCore.ps1')
            $fn = $parsed.Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-SecurityScan' }, $true)
            $fn.Extent.Text | Should -Match 'Invoke-ExtraSecurityCheck'
        }
        It 'falls back to registered fix actions and fix tests' {
            Register-SecurityCheck -Id 'TEST-X' -Check { } -FixAction { 'fixed' } -FixTest { $false }
            & (Get-SecurityFixAction -Id 'TEST-X') | Should -Be 'fixed'
            Test-SecurityFixApplied -Id 'TEST-X' | Should -BeFalse
            Get-SecurityFixAction -Id 'NO-SUCH-ID' | Should -BeNullOrEmpty
        }
    }

    Describe 'Phase 3: Test-MicrosoftSigned' {
        It 'rejects an unsigned file' {
            Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }
            Test-MicrosoftSigned -Path 'C:\x.exe' | Should -BeFalse
        }
        It 'accepts a real MS-signed binary' -Skip:(-not $script:OnWindows) {
            Test-MicrosoftSigned -Path (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') | Should -BeTrue
        }
        It 'rejects a non-MS file' -Skip:(-not $script:OnWindows) {
            $p = Join-Path $TestDrive 'x.ps1'; Set-Content -LiteralPath $p -Value 'x'
            Test-MicrosoftSigned -Path $p | Should -BeFalse
        }
    }

    Describe 'Phase 3: Authenticode downloads' {
        BeforeAll {
            $script:FakeTool = [pscustomobject]@{
                Key = 'faketool'; Name = 'FakeTool'; Vendor = 'MS Sysinternals'; License = 'test'; HomeUrl = 'https://learn.microsoft.com/'
                Summary = 's'; Url = 'https://download.sysinternals.com/files/FakeTool.zip'; Verify = 'Authenticode'
                ExeByArch = @{ 'AMD64' = 'faketoolc64.exe'; 'x86' = 'faketoolc.exe'; 'ARM64' = 'faketoolc64a.exe' }
                ExtraFiles = @('Eula.txt'); OutputKind = 'None'; NeedsAdmin = $true
            }
            $real = @(Get-ExternalToolRegistry)
            $script:RegWithFake = @($real) + @($script:FakeTool)
            Mock Get-ExternalToolRegistry { $script:RegWithFake }
            Mock Get-SystemArch { 'AMD64' }
            Mock Test-IsAdmin { $true }
            Mock Test-ToolsRootSecure { $true }
            Mock Test-ExternalToolInstalled { $null }
            Mock Import-Module { } -ParameterFilter { $Name -eq 'BitsTransfer' }
            Mock Start-BitsTransfer { Copy-Item -LiteralPath $script:SourceZip -Destination ([string]$Destination[0]) -Force }
            Mock Set-TreeOwnerToAdministrators { }
            Mock Set-ToolsFolderAcl { }
            Mock Set-ItemOwnerAdministrators { }
            $script:InstallDir = Get-ExternalToolInstallPath -Key 'faketool' -Version 'latest'
        }
        BeforeEach {
            if (Test-Path -LiteralPath $script:InstallDir) { Remove-Item -LiteralPath $script:InstallDir -Recurse -Force }
            $script:SourceZip = Join-Path $TestDrive 'FakeTool.zip'
        }
        It 'resolves the fixed URL with a HEAD request and no hash' {
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Headers = @{ 'Content-Length' = '2097152' } } }
            $r = Resolve-ExternalToolRelease -Key 'faketool'
            $r.DownloadUrl | Should -Be 'https://download.sysinternals.com/files/FakeTool.zip'
            $r.Sha256Source | Should -Be 'authenticode'
            $r.SizeMB | Should -Be 2
            Should -Invoke Invoke-WebRequest -ParameterFilter { $Method -eq 'Head' } -Times 1 -Exactly
        }
        It 'refuses a registry URL that is not a fixed Sysinternals file' {
            $script:FakeTool.Url = 'https://example.com/FakeTool.zip'
            try { { Resolve-ExternalToolRelease -Key 'faketool' } | Should -Throw '*download.sysinternals.com*' }
            finally { $script:FakeTool.Url = 'https://download.sysinternals.com/files/FakeTool.zip' }
        }
        It 'extracts only the expected files, checks the signature and records the exe hash' {
            New-TestZip -Path $script:SourceZip -Entries @{ 'faketoolc64.exe' = 'x64'; 'faketoolc.exe' = 'x86'; 'Eula.txt' = 'eula'; 'other.exe' = 'no'; '../evil.exe' = 'evil' }
            Mock Test-MicrosoftSigned { $true }
            $res = [pscustomobject]@{ Key = 'faketool'; Name = 'FakeTool'; Version = 'latest'; AssetName = 'FakeTool.zip'; DownloadUrl = 'https://download.sysinternals.com/files/FakeTool.zip'; SizeMB = 1; Sha256Expected = $null; Sha256Source = 'authenticode' }
            $r = Install-ExternalTool -Key 'faketool' -ConsentAccepted -Resolution $res
            $r.Message | Should -Be 'Installed.'
            $r.ExePath | Should -Be (Join-Path $script:InstallDir 'faketoolc64.exe')
            Test-Path -LiteralPath (Join-Path $script:InstallDir 'other.exe') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $script:InstallDir 'Eula.txt') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path (Split-Path $script:InstallDir -Parent) 'evil.exe') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $script:InstallDir 'FakeTool.zip') | Should -BeFalse
            Should -Invoke Test-MicrosoftSigned -ParameterFilter { $Path -like '*faketoolc64.exe' } -Times 1
            (Get-Content -LiteralPath (Join-Path $script:InstallDir 'exe.sha256') -Raw).Trim() | Should -Be (Get-FileHash -LiteralPath $r.ExePath -Algorithm SHA256).Hash
        }
        It 'deletes and refuses an exe that is not MS-signed' {
            New-TestZip -Path $script:SourceZip -Entries @{ 'faketoolc64.exe' = 'x64'; 'Eula.txt' = 'eula' }
            Mock Test-MicrosoftSigned { $false }
            $res = [pscustomobject]@{ Key = 'faketool'; Name = 'FakeTool'; Version = 'latest'; AssetName = 'FakeTool.zip'; DownloadUrl = 'https://download.sysinternals.com/files/FakeTool.zip'; SizeMB = 1; Sha256Expected = $null; Sha256Source = 'authenticode' }
            $r = Install-ExternalTool -Key 'faketool' -ConsentAccepted -Resolution $res
            $r.Success | Should -BeFalse
            $r.Message | Should -Match 'not signed by MS'
            Test-Path -LiteralPath (Join-Path $script:InstallDir 'faketoolc64.exe') | Should -BeFalse
        }
        It 'fails clearly when the zip has no exe for this architecture' {
            New-TestZip -Path $script:SourceZip -Entries @{ 'faketoolc.exe' = 'x86'; 'Eula.txt' = 'eula' }
            Mock Test-MicrosoftSigned { $true }
            $res = [pscustomobject]@{ Key = 'faketool'; Name = 'FakeTool'; Version = 'latest'; AssetName = 'FakeTool.zip'; DownloadUrl = 'https://download.sysinternals.com/files/FakeTool.zip'; SizeMB = 1; Sha256Expected = $null; Sha256Source = 'authenticode' }
            $r = Install-ExternalTool -Key 'faketool' -ConsentAccepted -Resolution $res
            $r.Success | Should -BeFalse
            $r.Message | Should -Match 'faketoolc64\.exe'
            $r.Message | Should -Match 'AMD64'
        }
        It 'never lets a Sha256 tool skip the hash check by claiming authenticode' {
            New-TestZip -Path $script:SourceZip -Entries @{ 'hayabusa-4.1.0-win-x64.exe' = 'x' }
            $res = [pscustomobject]@{ Key = 'hayabusa'; Name = 'Hayabusa'; Version = 'v4.1.0'; AssetName = 'h.zip'; DownloadUrl = 'https://github.com/x/h.zip'; SizeMB = 1; Sha256Expected = $null; Sha256Source = 'authenticode' }
            $r = Install-ExternalTool -Key 'hayabusa' -ConsentAccepted -Resolution $res
            $r.Success | Should -BeFalse
            $r.Message | Should -Match 'No trusted hash'
        }
    }

    Describe 'Phase 3: integrity before each run' {
        BeforeAll {
            $script:Dir = Join-Path $env:ProgramData 'Win11SecurityOptimizer\tools\x\v1'
            New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
            $script:Exe = Join-Path $script:Dir 'tool.exe'
            Set-Content -LiteralPath $script:Exe -Value 'binary'
            Set-Content -LiteralPath (Join-Path $script:Dir 'install.json') -Value '{}'
            Mock Test-ToolsRootSecure { $true }
        }
        BeforeEach {
            Set-Content -LiteralPath (Join-Path $script:Dir 'exe.sha256') -Value (Get-FileHash -LiteralPath $script:Exe -Algorithm SHA256).Hash
        }
        It 'passes when the hash matches (Sha256 mode)' {
            { Assert-ExternalToolIntegrity -Tool ([pscustomobject]@{ Name = 'X'; Verify = 'Sha256' }) -ExePath $script:Exe } | Should -Not -Throw
        }
        It 'refuses when one byte changed' {
            Set-Content -LiteralPath (Join-Path $script:Dir 'exe.sha256') -Value ('0' * 64)
            { Assert-ExternalToolIntegrity -Tool ([pscustomobject]@{ Name = 'X'; Verify = 'Sha256' }) -ExePath $script:Exe } | Should -Throw '*hash changed*'
        }
        It 're-checks the MS signature in Authenticode mode' {
            Mock Test-MicrosoftSigned { $false }
            { Assert-ExternalToolIntegrity -Tool ([pscustomobject]@{ Name = 'X'; Verify = 'Authenticode' }) -ExePath $script:Exe } | Should -Throw '*signature*'
        }
        It 'refuses without the install manifest' {
            Remove-Item -LiteralPath (Join-Path $script:Dir 'install.json')
            try { { Assert-ExternalToolIntegrity -Tool ([pscustomobject]@{ Name = 'X'; Verify = 'Sha256' }) -ExePath $script:Exe } | Should -Throw '*install.json*' }
            finally { Set-Content -LiteralPath (Join-Path $script:Dir 'install.json') -Value '{}' }
        }
    }

    Describe 'Phase 3: Build-Exe merged text' {
        It 'inlines the feature files in order and the merged text parses' {
            $out = Join-Path $TestDrive 'dist'
            & (Join-Path $script:RepoRoot 'Build-Exe.ps1') -OutDir $out -MergeOnly | Out-Null
            $merged = Join-Path $out '_merged_build.ps1'
            Test-Path -LiteralPath $merged | Should -BeTrue
            $parsed = Get-ScriptAst -Path $merged
            @($parsed.Errors) | Should -BeNullOrEmpty
            $text = Get-Content -LiteralPath $merged -Raw
            $text | Should -Not -Match 'foreach \(\$featureFile'
            $text | Should -Not -Match '#region FeatureLoader'
            $text | Should -Match 'function Test-MicrosoftSigned'
            $text.IndexOf('Common.ps1') | Should -BeLessThan $text.IndexOf('Evidence.ps1')
        }
    }
}
