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
        # Run against an empty registry: the real feature checks touch the live
        # system (Windows Update COM, DISM, SMB) and must not run in unit tests.
        BeforeEach {
            $script:SavedChecks = $script:ExtraSecurityChecks
            $script:ExtraSecurityChecks = [ordered]@{}
        }
        AfterEach {
            $script:ExtraSecurityChecks = $script:SavedChecks
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
        # Real signature checks run with the real ProgramData: Windows signature
        # verification keeps state files open under %ProgramData%, which would
        # otherwise land in TestDrive and block its clean-up.
        It 'accepts a real MS-signed binary' -Skip:(-not $script:OnWindows) {
            $saved = $env:ProgramData; $env:ProgramData = $script:SavedEnv.ProgramData
            try { Test-MicrosoftSigned -Path (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') | Should -BeTrue }
            finally { $env:ProgramData = $saved }
        }
        It 'rejects a non-MS file' -Skip:(-not $script:OnWindows) {
            $p = Join-Path $TestDrive 'x.ps1'; Set-Content -LiteralPath $p -Value 'x'
            $saved = $env:ProgramData; $env:ProgramData = $script:SavedEnv.ProgramData
            try { Test-MicrosoftSigned -Path $p | Should -BeFalse }
            finally { $env:ProgramData = $saved }
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

    Describe 'Phase 4: Autoruns CSV parser' {
        BeforeAll {
            $script:Fixture = Join-Path $PSScriptRoot 'fixtures\autoruns.csv'
            function New-AutorunsCsvText {
                param([object[]]$Rows)
                $h = '"Time","Entry Location","Entry","Enabled","Category","Profile","Description","Signer","Company","Image Path","Version","Launch String","MD5","SHA-1","PESHA-1","PESHA-256","SHA-256","IMP"'
                $lines = @($h)
                foreach ($r in $Rows) {
                    $lines += ('"{0}","{1}","{2}","{3}","{4}","System-wide","","{5}","{6}","{7}","","{8}","","","","","{9}",""' -f $r.Time, $r.Loc, $r.Entry, $r.Enabled, $r.Category, $r.Signer, $r.Company, $r.Image, $r.Launch, $r.Sha)
                }
                return ($lines -join "`r`n")
            }
            function New-AutorunsRow {
                param([string]$Category = 'Services', [string]$Entry = 'x', [string]$Signer = '', [string]$Image = 'C:\Program Files\x\x.exe', [string]$Company = '', [string]$Enabled = 'enabled')
                [pscustomobject]@{ Time = '20260101-000000'; Loc = 'HKLM\System\CurrentControlSet\Services'; Entry = $Entry; Enabled = $Enabled; Category = $Category; Signer = $Signer; Company = $Company; Image = $Image; Launch = $Image; Sha = ('AB' * 32) }
            }
        }
        It 'reads the real autorunsc output (UTF-16 LE with BOM) by column name' {
            $bytes = [System.IO.File]::ReadAllBytes($script:Fixture)
            $bytes[0] | Should -Be 0xFF
            $bytes[1] | Should -Be 0xFE
            $rows = @(Read-AutorunsCsv -Path $script:Fixture)
            $rows.Count | Should -Be 65
            @($rows | Where-Object { -not $_.Entry }).Count | Should -Be 0
            $chrome = @($rows | Where-Object { $_.Entry -eq 'Google Chrome' })[0]
            $chrome.Category | Should -Be 'Logon'
            $chrome.Signer | Should -Be '(Verified) Google LLC'
            $chrome.ImagePath | Should -Match '^C:\\Program Files\\Google\\Chrome\\'
            $chrome.Time | Should -Match '^\d{8}-\d{6}$'
        }
        It 'decodes UTF8 with BOM, Unicode without BOM and ANSI' {
            $t = 'Time,Entry Location'
            ConvertFrom-AutorunsText -Bytes ([byte[]](@(0xEF, 0xBB, 0xBF) + [System.Text.Encoding]::UTF8.GetBytes($t))) | Should -Be $t
            ConvertFrom-AutorunsText -Bytes ([System.Text.Encoding]::Unicode.GetBytes($t)) | Should -Be $t
            ConvertFrom-AutorunsText -Bytes ([System.Text.Encoding]::ASCII.GetBytes($t)) | Should -Be $t
        }
        It 'skips banner lines before the header' {
            $p = Join-Path $TestDrive 'banner.csv'
            $text = "Sysinternals Autoruns v14.3 - Autostart program viewer`r`nCopyright 2002-2026 Mark Russinovich`r`n`r`n" + (New-AutorunsCsvText -Rows @(New-AutorunsRow -Entry 'one'))
            [System.IO.File]::WriteAllText($p, $text, [System.Text.Encoding]::Unicode)
            $rows = @(Read-AutorunsCsv -Path $p)
            $rows.Count | Should -Be 1
            $rows[0].Entry | Should -Be 'one'
        }
        It 'fails clearly when there is no header' {
            $p = Join-Path $TestDrive 'noheader.csv'
            Set-Content -LiteralPath $p -Value 'nothing useful'
            { Read-AutorunsCsv -Path $p } | Should -Throw '*Entry Location*'
        }
    }

    Describe 'Phase 4: Autoruns classification and cards' {
        BeforeAll {
            $script:Fixture = Join-Path $PSScriptRoot 'fixtures\autoruns.csv'
            function New-Row { param($Category, $Signer, $Image, $Launch = '') [pscustomobject]@{ Category = $Category; Signer = $Signer; ImagePath = $Image; LaunchString = $Launch } }
        }
        It 'classifies <Label> as <Class>' -ForEach @(
            @{ Label = 'a verified MS entry';                Class = 'Hidden'; Row = @{ Category = 'Known DLLs';  Signer = '(Verified) Microsoft Windows'; Image = 'C:\Windows\System32\kernel32.dll' } }
            @{ Label = 'a non-MS Known DLL';                 Class = 'High';   Row = @{ Category = 'Known DLLs';  Signer = '(Verified) Contoso Ltd'; Image = 'C:\Windows\System32\evil.dll' } }
            @{ Label = 'an unsigned image hijack';           Class = 'High';   Row = @{ Category = 'Image Hijacks'; Signer = ''; Image = 'C:\Tools\dbg.exe' } }
            @{ Label = 'a WMI consumer';                     Class = 'High';   Row = @{ Category = 'WMI'; Signer = '(Not verified) x'; Image = 'C:\Windows\x.exe' } }
            @{ Label = 'an LSA provider';                    Class = 'High';   Row = @{ Category = 'LSA Providers'; Signer = '(Verified) Contoso'; Image = 'C:\Windows\System32\c.dll' } }
            @{ Label = 'a missing Known DLL (clean Windows)'; Class = 'Medium'; Row = @{ Category = 'Known DLLs';  Signer = ''; Image = 'File not found: C:\Windows\Syswow64\wow64cpu.dll' } }
            @{ Label = 'an unverified service';              Class = 'Medium'; Row = @{ Category = 'Services'; Signer = '(Not verified) (Not Verified) Docker Inc'; Image = 'C:\Windows\system32\dockerd.exe' } }
            @{ Label = 'a verified task in ProgramData';     Class = 'Medium'; Row = @{ Category = 'Scheduled Tasks'; Signer = '(Verified) Contoso'; Image = 'C:\ProgramData\Contoso\agent.exe' } }
            @{ Label = 'a verified non-MS logon entry';      Class = 'Low';    Row = @{ Category = 'Logon'; Signer = '(Verified) Google LLC'; Image = 'C:\Program Files\Google\Chrome\chrome.exe' } }
        ) {
            Get-AutorunsRowClass -Row (New-Row -Category $Row.Category -Signer $Row.Signer -Image $Row.Image) | Should -Be $Class
        }
        It 'turns the real fixture into review cards per category and one verified-publisher card' {
            $cards = @(ConvertFrom-AutorunsCsv -CsvPath $script:Fixture)
            @($cards | Where-Object { $_.Status -eq 'Alert' }).Count | Should -Be 0
            $review = @($cards | Where-Object { $_.Status -eq 'Review' })
            @($review | ForEach-Object { $_.Id } | Sort-Object) | Should -Be @('AUTORUNS-DRIVERS', 'AUTORUNS-EXPLORER', 'AUTORUNS-KNOWNDLLS', 'AUTORUNS-SCHEDULEDTASKS', 'AUTORUNS-SERVICES')
            @($review | ForEach-Object { [int]($_.Title -replace '^.*: (\d+) entr.*$', '$1') } | Measure-Object -Sum).Sum | Should -Be 13
            $low = @($cards | Where-Object { $_.Id -eq 'AUTORUNS-VERIFIED' })
            $low.Count | Should -Be 1
            $low[0].Title | Should -Match ': 7 entries'
            foreach ($c in $cards) { @($c.PSObject.Properties.Name) | Should -Contain 'Paths' }
        }
        It 'caps evidence at 25 lines and points to the CSV for the rest' {
            $rows = @(1..30 | ForEach-Object { [pscustomobject]@{ Time = ''; Loc = 'HKLM\x'; Entry = "svc$_"; Enabled = 'enabled'; Category = 'Services'; Signer = ''; Company = ''; Image = "C:\Program Files\s$_.exe"; Launch = ''; Sha = '' } })
            $h = '"Time","Entry Location","Entry","Enabled","Category","Signer","Company","Image Path","Launch String","SHA-256"'
            $lines = @($h) + @($rows | ForEach-Object { '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}"' -f $_.Time, $_.Loc, $_.Entry, $_.Enabled, $_.Category, $_.Signer, $_.Company, $_.Image, $_.Launch, $_.Sha })
            $p = Join-Path $TestDrive 'many.csv'
            [System.IO.File]::WriteAllText($p, ($lines -join "`r`n"), [System.Text.Encoding]::Unicode)
            $card = @(ConvertFrom-AutorunsCsv -CsvPath $p | Where-Object { $_.Id -eq 'AUTORUNS-SERVICES' })[0]
            $card.Title | Should -Match ': 30 entries'
            @($card.Evidence -split "`n" | Where-Object { $_ -match '^\s+svc\d+' }).Count | Should -Be 25
            $card.Evidence | Should -Match ([regex]::Escape("and 5 more. See the full list in $p"))
        }
        It 'raises a High alert for a non-MS LSA provider and fills Paths with existing files only' {
            $dll = Join-Path $TestDrive 'evil.dll'; Set-Content -LiteralPath $dll -Value 'x'
            $h = '"Time","Entry Location","Entry","Enabled","Category","Signer","Company","Image Path","Launch String","SHA-256"'
            $lines = @($h, ('"","HKLM\System\CurrentControlSet\Control\Lsa\Security Packages","evil","enabled","LSA Providers","(Not verified) Evil","Evil","{0}","evil",""' -f $dll),
                           '"","HKLM\System\CurrentControlSet\Control\Lsa\Security Packages","gone","enabled","LSA Providers","(Not verified) Evil","Evil","C:\nope\gone.dll","gone",""')
            $p = Join-Path $TestDrive 'lsa.csv'
            [System.IO.File]::WriteAllText($p, ($lines -join "`r`n"), [System.Text.Encoding]::Unicode)
            $card = @(ConvertFrom-AutorunsCsv -CsvPath $p | Where-Object { $_.Id -eq 'AUTORUNS-LSAPROVIDERS' })[0]
            $card.Status | Should -Be 'Alert'
            $card.Severity | Should -Be 'High'
            @($card.Paths) | Should -Be @($dll)
        }
        It 'New-DfirFinding defaults Paths to an empty array' {
            $c = New-DfirFinding -Id 'x' -Severity 'Info' -Status 'Info'
            @($c.Paths).Count | Should -Be 0
        }
    }

    Describe 'Phase 4: running Autoruns' {
        BeforeAll {
            Mock Set-ItemOwnerAdministrators { }
            Mock New-Item { } -ParameterFilter { $ItemType -eq 'Directory' }
            Mock Test-Path { $true } -ParameterFilter { $PathType -eq 'Container' }
        }
        It 'runs autorunsc with the agreed arguments and never with -v, -vs, -vt or -m' {
            Mock Start-Process { Set-Content -LiteralPath $RedirectStandardOutput -Value 'x'; [pscustomobject]@{ ExitCode = 0 } }
            $outRoot = Join-Path $env:ProgramData 'Win11SecurityOptimizer\tools\autoruns\output'
            [System.IO.Directory]::CreateDirectory($outRoot) | Out-Null
            $r = Invoke-AutorunsScan -ExePath 'C:\x\autorunsc64.exe'
            $r.OutputPath.StartsWith((Get-ExternalToolsRoot), [System.StringComparison]::OrdinalIgnoreCase) | Should -BeTrue
            Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
                (($ArgumentList -join ' ') -eq '-accepteula -a * -c -h -s -t *') -and (@($ArgumentList | Where-Object { $_ -in @('-v', '-vs', '-vt', '-m') }).Count -eq 0)
            }
            Should -Invoke Set-ItemOwnerAdministrators -ParameterFilter { $Path -eq $r.OutputPath } -Times 1
        }
        It 'throws when autorunsc exits with an error' {
            Mock Start-Process { [pscustomobject]@{ ExitCode = 5 } }
            { Invoke-AutorunsScan -ExePath 'C:\x\autorunsc64.exe' } | Should -Throw '*code 5*'
        }
        It 'checks integrity before running and returns cards' {
            Mock Assert-ExternalToolIntegrity { }
            Mock Invoke-AutorunsScan { [pscustomobject]@{ OutputPath = (Join-Path $PSScriptRoot 'fixtures\autoruns.csv'); Kind = 'AutorunsCsv' } }
            $cards = @(Invoke-ExternalDfirScan -Key 'autoruns' -ExePath 'C:\x\autorunsc64.exe')
            $cards.Count | Should -BeGreaterThan 0
            Should -Invoke Assert-ExternalToolIntegrity -Times 1 -Exactly
        }
        It 'registers Autoruns as an Authenticode tool with one console exe per architecture' {
            $t = Get-ExternalTool -Key 'autoruns'
            Get-ExternalToolVerifyMode -Tool $t | Should -Be 'Authenticode'
            $t.Url | Should -Be 'https://download.sysinternals.com/files/Autoruns.zip'
            $t.ExeByArch['AMD64'] | Should -Be 'autorunsc64.exe'
            $t.ExeByArch['x86'] | Should -Be 'autorunsc.exe'
            $t.ExeByArch['ARM64'] | Should -Be 'autorunsc64a.exe'
        }
    }

    Describe 'Phase 4: level filters' {
        It 'passes the chosen minimum level to Hayabusa' {
            Mock Assert-ExternalToolIntegrity { }
            Mock Invoke-HayabusaScan { [pscustomobject]@{ OutputPath = 'none.csv' } }
            Mock ConvertFrom-HayabusaCsv { }
            Invoke-ExternalDfirScan -Key 'hayabusa' -ExePath 'C:\x\hayabusa.exe' -MinLevel 'high' | Out-Null
            Should -Invoke Invoke-HayabusaScan -ParameterFilter { $MinLevel -eq 'high' } -Times 1 -Exactly
        }
        It 'lists levels at or above the minimum' {
            Get-ExternalLevelAtOrAbove -MinLevel 'high' | Should -Be @('high', 'critical')
            Get-ExternalLevelAtOrAbove -MinLevel 'low' | Should -Be @('low', 'medium', 'high', 'critical')
        }
        It 'filters Chainsaw detections below the minimum level' {
            $p = Join-Path $TestDrive 'cs.json'
            $json = ConvertTo-Json -InputObject @(
                [pscustomobject]@{ name = 'A'; level = 'critical'; timestamp = 't1' },
                [pscustomobject]@{ name = 'B'; level = 'medium'; timestamp = 't2' },
                [pscustomobject]@{ name = 'C'; level = 'low'; timestamp = 't3' }
            ) -Depth 6
            Set-Content -LiteralPath $p -Value $json
            $cards = @(ConvertFrom-ChainsawJson -JsonPath $p -MinLevel 'high')
            @($cards | Where-Object { $_.Id -like 'CHAIN-[0-9]*' }).Count | Should -Be 1
            (@($cards | Where-Object { $_.Id -eq 'CHAIN-SUMMARY' })[0]).Title | Should -Match '1 detection'
            @(ConvertFrom-ChainsawJson -JsonPath $p -MinLevel 'low' | Where-Object { $_.Id -like 'CHAIN-[0-9]*' }).Count | Should -Be 3
        }
        It 'reports clean when nothing reaches the minimum level' {
            $p = Join-Path $TestDrive 'cs2.json'
            Set-Content -LiteralPath $p -Value (ConvertTo-Json -InputObject @([pscustomobject]@{ name = 'B'; level = 'low' }) -Depth 6)
            (@(ConvertFrom-ChainsawJson -JsonPath $p -MinLevel 'high')[0]).Id | Should -Be 'CHAIN-CLEAN'
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
