<#
    Reporting.Tests.ps1
    Author: Ahmad Shaukat
    Tests for Phase 8: HTML report, evidence pack, Defender card action,
    headless-scan exit codes and the read-only guarantee of Scan.ps1.
#>

Describe 'Reporting and responder actions' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestSetup.ps1')
    }
    AfterAll { Restore-TestEnvironment }
    BeforeEach { Set-StrictMode -Version 2.0 }

    Describe 'HTML report' {
        BeforeAll {
            $script:Html = New-HtmlReport -SecurityFindings @(
                (New-Finding -Id 'WDIGEST' -Category 'c' -Name 'WDigest <b>bold</b>' -Severity 'High' -Status 'Fail' -Observed '1' -Expected '0' -Advice 'Fix it & go')
            ) -Score ([pscustomobject]@{ Score = 82; Grade = 'B' }) -DfirCards @(
                (New-DfirFinding -Id 'DFIR-X' -Category 'c' -Title '<script>alert(1)</script>' -Severity 'High' -Status 'Alert' -What 'C:\Users\bob\evil.exe "x"' -Why 'why' -WhatToDo 'do' -Paths @('C:\Users\bob\evil.exe')),
                (New-DfirFinding -Id 'DRIFT-LOCALADMINS-HIGH' -Category 'c' -Title 'New since 2026-10-01: 1 local administrators' -Severity 'High' -Status 'Alert'),
                (New-DfirFinding -Id 'AUTORUNS-SERVICES' -Category 'c' -Title 'Services: 2 entries to review' -Severity 'Medium' -Status 'Review')
            ) -Changes @([pscustomobject]@{ Time = '2026-10-12T10:00:00'; Change = 'Set HKLM:\x = <1>' }) -RollbackPath 'C:\ProgramData\Win11SecurityOptimizer\backups\Rollback_1.ps1' `
              -Tools @([pscustomobject]@{ Name = 'Autoruns'; Vendor = 'MS Sysinternals'; License = 'Sysinternals'; Version = '14.3'; ExePath = 'x'; Sha256 = ('AB' * 32) }) -MachineName 'PC1'
        }
        It 'HTML-encodes a finding title containing a script tag' {
            $script:Html | Should -Match ([regex]::Escape('&lt;script&gt;alert(1)&lt;/script&gt;'))
            $script:Html | Should -Not -Match '<script'
        }
        It 'encodes every other dynamic value' {
            $script:Html | Should -Match ([regex]::Escape('WDigest &lt;b&gt;bold&lt;/b&gt;'))
            $script:Html | Should -Match ([regex]::Escape('Fix it &amp; go'))
            $script:Html | Should -Match ([regex]::Escape('&quot;x&quot;'))
            $script:Html | Should -Match ([regex]::Escape('Set HKLM:\x = &lt;1&gt;'))
        }
        It 'carries the sharing warning, every section and no external resources' {
            $script:Html | Should -Match 'Contains user names and file paths\. Share carefully\.'
            foreach ($h in @('Summary', 'Security findings', 'Investigate', 'Changes since baseline', 'Pro Tools results', 'Changes made this session', 'Rollback', 'External tools')) {
                $script:Html | Should -Match ('<h2>{0}</h2>' -f [regex]::Escape($h))
            }
            $script:Html | Should -Not -Match '(?i)<link|src=|@import|https?://'
            $script:Html | Should -Match ('AB' * 32)
            $script:Html | Should -Match 'Rollback_1\.ps1'
        }
        It 'puts drift and Pro Tools cards in their own sections' {
            $g = Get-DfirCardGroup -Cards @(
                (New-DfirFinding -Id 'DFIR-X' -Severity 'Info' -Status 'Info'),
                (New-DfirFinding -Id 'DRIFT-NONE' -Severity 'Info' -Status 'Clean'),
                (New-DfirFinding -Id 'HAYA-1' -Severity 'High' -Status 'Review'),
                (New-DfirFinding -Id 'CHAIN-1' -Severity 'High' -Status 'Review')
            )
            @($g.Native).Count | Should -Be 1
            @($g.Drift).Count | Should -Be 1
            @($g.Pro).Count | Should -Be 2
        }
    }

    Describe 'Evidence pack' {
        BeforeEach {
            Mock Test-IsAdmin { $true }
            Mock Set-ItemOwnerAdministrators { }
            New-Item -ItemType Directory -Path (Join-Path $env:ProgramData 'Win11SecurityOptimizer') -Force | Out-Null
            Mock Get-WinEvent { if ($ListLog -contains 'Security' -or $ListLog -contains 'System') { [pscustomobject]@{ LogName = $ListLog[0] } } else { throw 'No such log' } } -ParameterFilter { $ListLog }
            Mock Invoke-NativeCommand {
                if ($FilePath -eq 'wevtutil.exe' -and $ArgumentList[0] -eq 'epl') { Set-Content -LiteralPath $ArgumentList[2] -Value ('evtx for ' + $ArgumentList[1]) }
                [pscustomobject]@{ ExitCode = 0; Output = '' }
            }
            Mock Get-SystemSnapshot { [pscustomobject]@{ MachineName = 'PC1'; Collections = @{ services = @{ spooler = @{ path = 'c:\x' } } }; Errors = @{} } }
            Mock Get-ProcessEvidence { [pscustomobject]@{ ProcessId = 4; Name = 'System'; Path = ''; Sha256 = ''; Signer = ''; SignatureStatus = ''; CommandLine = '' } }
            Mock Get-TcpEvidence { [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 445; State = 'Listen'; ProcessId = 4; ProcessName = 'System' } }
        }
        It 'writes a manifest whose hashes match every file, then removes the staging folder' {
            $zip = Join-Path $TestDrive 'pack.zip'
            $r = New-EvidencePack -Destination $zip -Findings @(New-DfirFinding -Id 'X' -Severity 'Info' -Status 'Info')
            $r.Path | Should -Be $zip
            $out = Join-Path $TestDrive 'unzipped'
            Expand-Archive -LiteralPath $zip -DestinationPath $out -Force
            $m = Get-Content -LiteralPath (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json
            $m.Machine | Should -Be $env:COMPUTERNAME
            $m.ToolVersion | Should -Be $script:Core.Version
            @($m.Files).Count | Should -Be 6
            foreach ($f in @($m.Files)) {
                (Get-FileHash -LiteralPath (Join-Path $out $f.Path) -Algorithm SHA256).Hash | Should -Be $f.Sha256
            }
            @($m.Files | ForEach-Object { $_.Path }) | Should -Contain 'logs/Security.evtx'
            @($m.Notes | Where-Object { $_ -match 'Skipped Microsoft-Windows-Sysmon/Operational' }).Count | Should -Be 1
            @(Get-ChildItem -LiteralPath (Join-Path $env:ProgramData 'Win11SecurityOptimizer\evidence') -Directory -Filter 'stage_*').Count | Should -Be 0
            $r.Warning | Should -BeNullOrEmpty
        }
        It 'warns when the pack is over the size limit' {
            $saved = $script:EvidenceWarnBytes
            try {
                $script:EvidenceWarnBytes = 10
                (New-EvidencePack -Destination (Join-Path $TestDrive 'big.zip')).Warning | Should -Match 'GB'
            } finally { $script:EvidenceWarnBytes = $saved }
        }
        It 'refuses without admin' {
            Mock Test-IsAdmin { $false }
            { New-EvidencePack -Destination (Join-Path $TestDrive 'x.zip') } | Should -Throw '*administrator*'
        }
    }

    Describe 'Scan with Defender card action' {
        It 'scans each existing path and lists only detections since the scan started' {
            $a = Join-Path $TestDrive 'a.exe'; Set-Content -LiteralPath $a -Value 'x'
            Mock Start-MpScan { }
            Mock Get-MpThreatDetection {
                [pscustomobject]@{ ThreatID = 1; InitialDetectionTime = (Get-Date).AddDays(-3); Resources = @('file:_C:\old.exe'); ActionSuccess = $true }
                [pscustomobject]@{ ThreatID = 2; InitialDetectionTime = (Get-Date).AddMinutes(1); Resources = @("file:_$a"); ActionSuccess = $true }
            }
            $r = Invoke-DefenderPathScan -Path @($a, (Join-Path $TestDrive 'gone.exe'))
            @($r.Scanned) | Should -Be @($a)
            @($r.Detections).Count | Should -Be 1
            $r.Detections[0].ThreatId | Should -Be '2'
            @($r.Errors).Count | Should -Be 1
            Should -Invoke Start-MpScan -ParameterFilter { $ScanType -eq 'CustomScan' -and $ScanPath -eq $a } -Times 1 -Exactly
        }
    }

    Describe 'Headless scan' {
        It 'exit code for "<Name>" is <ExpectedExit>' -ForEach @(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\scan-cases.json') -Raw | ConvertFrom-Json | ForEach-Object { @{ Name = $_.Name; Security = @($_.Security); Investigate = @($_.Investigate); ExpectedExit = [int]$_.ExpectedExit } }) {
            Get-ScanExitCode -SecurityFindings $Security -Cards $Investigate | Should -Be $ExpectedExit
        }
        It 'Scan.ps1 calls no fix, set, remove, install or download function' {
            $parsed = Get-ScriptAst -Path (Join-Path $script:RepoRoot 'src\Scan.ps1')
            @($parsed.Errors) | Should -BeNullOrEmpty
            $names = @($parsed.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            $names | Should -Contain 'Invoke-SecurityScan'
            $bad = @($names | Where-Object { $_ -match '(?i)fix|^(set|remove|install|uninstall|enable|disable|save|clear|stop|restart)-|download|^invoke-(webrequest|restmethod)$|^start-(bitstransfer|mpscan|process)$|^new-evidencepack$' })
            $bad | Should -BeNullOrEmpty
            $members = @($parsed.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) | ForEach-Object { [string]$_.Member.Value })
            @($members | Where-Object { $_ -match '(?i)delete|move|download' }) | Should -BeNullOrEmpty
        }
        It 'Scan.ps1 starts the core read-only' {
            (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Scan.ps1') -Raw) | Should -Match 'Initialize-Core -ReadOnly'
        }
    }
}
