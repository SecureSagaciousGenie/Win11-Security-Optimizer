<#
    Sysmon.Tests.ps1
    Author: Ahmad Shaukat
    Tests for src/features/Sysmon.ps1: state detection in all four states,
    enable and rollback for each path, the pinned config and tool retention.
#>

Describe 'Sysmon' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestSetup.ps1')
        $script:UnknownFeature = New-Object System.Runtime.InteropServices.COMException('Feature name Sysmon is unknown.', -2146498548)
        function Set-SysmonWorld {
            <# Service: $null, 'Sysmon64' or 'Sysmon'. Feature: Enabled, Disabled or Absent. #>
            param($Service, [string]$Feature, [bool]$Admin = $true)
            $script:WService = $Service; $script:WFeature = $Feature; $script:WAdmin = $Admin
            Mock Test-IsAdmin { $script:WAdmin }
            Mock Get-Service { if ($script:WService -and (@($Name) -contains $script:WService)) { [pscustomobject]@{ Name = $script:WService; Status = 'Running' } } }
            Mock Get-WindowsOptionalFeature {
                if ($script:WFeature -eq 'Absent') { throw $script:UnknownFeature }
                [pscustomobject]@{ FeatureName = 'Sysmon'; State = $script:WFeature }
            }
            Mock Get-SysmonLogInfo { if ($script:WService) { [pscustomobject]@{ SizeBytes = 10MB; MaxBytes = 64MB; Oldest = (Get-Date).AddDays(-12); DaysOfEvidence = 12 } } }
        }
        function Get-RollbackText { return ($script:Core.Rollback.ToArray() -join "`r`n") }
        function Assert-ParsesCleanly {
            param([string]$Text)
            $t = $null; $e = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$t, [ref]$e)
            @($e) | Should -BeNullOrEmpty
        }
    }
    AfterAll { Restore-TestEnvironment }
    BeforeEach {
        Set-StrictMode -Version 2.0
        $script:Core.Rollback.Clear(); $script:Core.Changes.Clear()
    }

    Describe 'State detection' {
        It 'detects <Expect>' -ForEach @(
            @{ Service = 'Sysmon64'; Feature = 'Absent';   Expect = 'Standalone';       Installed = $true }
            @{ Service = $null;      Feature = 'Disabled'; Expect = 'BuiltInAvailable'; Installed = $false }
            @{ Service = 'Sysmon';   Feature = 'Enabled';  Expect = 'BuiltInEnabled';   Installed = $true }
            @{ Service = $null;      Feature = 'Absent';   Expect = 'Unavailable';      Installed = $false }
        ) {
            Set-SysmonWorld -Service $Service -Feature $Feature
            $s = Get-SysmonState
            $s.State | Should -Be $Expect
            $s.Installed | Should -Be $Installed
        }
        It 'reports Unknown without admin when nothing is installed' {
            Set-SysmonWorld -Service $null -Feature 'Disabled' -Admin $false
            (Get-SysmonState).State | Should -Be 'Unknown'
            Should -Invoke Get-WindowsOptionalFeature -Times 0 -Exactly
        }
        It 'still sees a standalone service without admin' {
            Set-SysmonWorld -Service 'Sysmon64' -Feature 'Absent' -Admin $false
            (Get-SysmonState).State | Should -Be 'Standalone'
        }
        It 'reads the log size and the days of evidence' {
            Mock Get-WinEvent { [pscustomobject]@{ FileSize = 5MB; MaximumSizeInBytes = 512MB } } -ParameterFilter { $ListLog }
            Mock Get-WinEvent { New-FakeEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -Id 1 } -ParameterFilter { -not $ListLog }
            $i = Get-SysmonLogInfo
            $i.MaxBytes | Should -Be 512MB
            $i.DaysOfEvidence | Should -Be 0
        }
        It 'returns no log info when the log does not exist' {
            Mock Get-WinEvent { throw 'There is not an event log on the localhost computer that matches.' } -ParameterFilter { $ListLog }
            Get-SysmonLogInfo | Should -BeNullOrEmpty
        }
    }

    Describe 'Bundled config' {
        It 'matches the pinned SHA-256 and names its source, commit and license' {
            $p = Join-Path $script:RepoRoot 'config\sysmon\sysmonconfig.xml'
            (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash | Should -Be $script:SysmonConfigSha256
            $head = (Get-Content -LiteralPath $p -TotalCount 8) -join "`n"
            $head | Should -Match 'olafhartong/sysmon-modular'
            $head | Should -Match 'a9ff298f6d228c181be71b213c73d111c6096f41'
            $head | Should -Match 'MIT'
            ([xml](Get-Content -LiteralPath $p -Raw)).Sysmon.schemaversion | Should -Be '4.90'
            (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'THIRD-PARTY-NOTICES.md') -Raw) | Should -Match 'a9ff298f6d228c181be71b213c73d111c6096f41'
        }
        It 'refuses a config that does not match the pin' {
            $root = Join-Path $TestDrive 'fakeroot'
            New-Item -ItemType Directory -Path (Join-Path $root 'config\sysmon') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $root 'config\sysmon\sysmonconfig.xml') -Value '<Sysmon/>'
            $saved = $script:Core.RootPath
            try {
                $script:Core.RootPath = $root
                { Get-SysmonConfigSource } | Should -Throw '*pinned SHA-256*'
            } finally { $script:Core.RootPath = $saved }
        }
        It 'copies the verified config into the secure base and re-owns it' {
            Mock Set-ItemOwnerAdministrators { }
            $dest = Copy-SysmonConfigToSecureBase
            $dest | Should -Be (Join-Path $env:ProgramData 'Win11SecurityOptimizer\sysmon\sysmonconfig.xml')
            (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash | Should -Be $script:SysmonConfigSha256
            Should -Invoke Set-ItemOwnerAdministrators -ParameterFilter { $Path -eq $dest } -Times 1 -Exactly
        }
    }

    Describe 'Enable-SysmonLogging' {
        BeforeEach {
            Mock Copy-SysmonConfigToSecureBase { 'C:\ProgramData\Win11SecurityOptimizer\sysmon\sysmonconfig.xml' }
            Mock Get-FileHash { [pscustomobject]@{ Hash = ('AB' * 32) } } -ParameterFilter { $LiteralPath -like '*ysmon*.exe' }
            Mock Find-BuiltInSysmonExe { 'C:\Windows\System32\Sysmon.exe' }
            Mock Test-MicrosoftSigned { $true }
            Mock Enable-WindowsOptionalFeature { }
            $script:Help = 'Usage: sysmon [-accepteula] -i [configfile]'
            Mock Invoke-NativeCommand {
                if (@($ArgumentList) -contains '-?') { return [pscustomobject]@{ ExitCode = 0; Output = $script:Help } }
                [pscustomobject]@{ ExitCode = 0; Output = 'ok' }
            }
        }
        It 'changes nothing when Sysmon is already installed' {
            Set-SysmonWorld -Service 'Sysmon64' -Feature 'Absent'
            Enable-SysmonLogging
            Should -Invoke Invoke-NativeCommand -Times 0 -Exactly
            Should -Invoke Copy-SysmonConfigToSecureBase -Times 0 -Exactly
            $script:Core.Rollback.Count | Should -Be 0
        }
        It 'enables the built-in feature, installs with the config and sets 512 MB, with a full rollback' {
            Set-SysmonWorld -Service $null -Feature 'Disabled'
            Mock Get-SysmonLogInfo { [pscustomobject]@{ SizeBytes = 1MB; MaxBytes = 67108864; Oldest = $null; DaysOfEvidence = $null } }
            Enable-SysmonLogging
            Should -Invoke Enable-WindowsOptionalFeature -ParameterFilter { $All -and $NoRestart -and (@($FeatureName) -contains 'Sysmon') } -Times 1 -Exactly
            Should -Invoke Invoke-NativeCommand -ParameterFilter { $FilePath -like '*Sysmon.exe' -and (($ArgumentList -join ' ') -eq '-accepteula -i C:\ProgramData\Win11SecurityOptimizer\sysmon\sysmonconfig.xml') } -Times 1 -Exactly
            Should -Invoke Invoke-NativeCommand -ParameterFilter { $FilePath -eq 'wevtutil.exe' -and (($ArgumentList -join ' ') -eq 'sl Microsoft-Windows-Sysmon/Operational /ms:536870912') } -Times 1 -Exactly
            $text = Get-RollbackText
            $text | Should -Match "Disable-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -NoRestart"
            $text | Should -Match ([regex]::Escape("-eq '$('AB' * 32)') { & 'C:\Windows\System32\Sysmon.exe' -u }"))
            $text | Should -Match ([regex]::Escape("& wevtutil.exe sl 'Microsoft-Windows-Sysmon/Operational' '/ms:67108864'"))
            Assert-ParsesCleanly $text
        }
        It 'skips the feature step and -accepteula when the feature is on and the help does not list it' {
            Set-SysmonWorld -Service $null -Feature 'Enabled'
            $script:Help = 'Usage: sysmon -i [configfile]'
            Enable-SysmonLogging
            Should -Invoke Enable-WindowsOptionalFeature -Times 0 -Exactly
            Should -Invoke Invoke-NativeCommand -ParameterFilter { $FilePath -like '*Sysmon.exe' -and (($ArgumentList -join ' ') -eq '-i C:\ProgramData\Win11SecurityOptimizer\sysmon\sysmonconfig.xml') } -Times 1 -Exactly
            Get-RollbackText | Should -Not -Match 'Disable-WindowsOptionalFeature'
        }
        It 'downloads standalone Sysmon through the Authenticode path when Windows has no built-in feature' {
            Set-SysmonWorld -Service $null -Feature 'Absent'
            Mock Initialize-SecureToolsRoot { 'x' }
            Mock Test-ExternalToolInstalled { $null }
            Mock Resolve-ExternalToolRelease { [pscustomobject]@{ Key = 'sysmon' } }
            $tools = Get-ExternalToolsRoot
            Mock Install-ExternalTool { [pscustomobject]@{ Success = $true; ExePath = (Join-Path (Get-ExternalToolsRoot) 'sysmon\latest\Sysmon64.exe'); Message = 'Installed.' } }
            Mock Assert-ExternalToolIntegrity { }
            Enable-SysmonLogging
            Should -Invoke Install-ExternalTool -ParameterFilter { $Key -eq 'sysmon' -and $ConsentAccepted } -Times 1 -Exactly
            Should -Invoke Assert-ExternalToolIntegrity -Times 1 -Exactly
            Should -Invoke Invoke-NativeCommand -ParameterFilter { $FilePath -like '*Sysmon64.exe' -and ($ArgumentList[0] -eq '-accepteula') -and ($ArgumentList[1] -eq '-i') } -Times 1 -Exactly
            (Get-ExternalTool -Key 'sysmon').Url | Should -Be 'https://download.sysinternals.com/files/Sysmon.zip'
            Get-ExternalToolVerifyMode -Tool (Get-ExternalTool -Key 'sysmon') | Should -Be 'Authenticode'
        }
        It 'throws when the install fails' {
            Set-SysmonWorld -Service $null -Feature 'Enabled'
            Mock Invoke-NativeCommand {
                if (@($ArgumentList) -contains '-?') { return [pscustomobject]@{ ExitCode = 0; Output = '' } }
                [pscustomobject]@{ ExitCode = 1; Output = 'driver failed to load' }
            }
            { Enable-SysmonLogging } | Should -Throw '*exit code 1*'
        }
        It 'refuses a built-in sysmon.exe that is not MS-signed' {
            Set-SysmonWorld -Service $null -Feature 'Enabled'
            Mock Test-MicrosoftSigned { $false }
            { Enable-SysmonLogging } | Should -Throw '*not signed by MS*'
            Should -Invoke Invoke-NativeCommand -Times 0 -Exactly
        }
        It 'refuses without admin' {
            Set-SysmonWorld -Service $null -Feature 'Disabled' -Admin $false
            { Enable-SysmonLogging } | Should -Throw '*administrator*'
        }
    }

    Describe 'Cards and tool retention' {
        It 'offers an individual-only HighRisk fix with the disk and driver warning' {
            Set-SysmonWorld -Service $null -Feature 'Disabled'
            $f = Get-SysmonSecurityFinding
            $f.Name | Should -Be 'Continuous logging (Sysmon)'
            $f.RiskTier | Should -Be 'HighRisk'
            $f.Fixable | Should -BeTrue
            $f.IndividualOnly | Should -BeTrue
            $f.ConfirmText | Should -Match 'driver'
            $f.ConfirmText | Should -Match 'service'
            $f.ConfirmText | Should -Match '512 MB'
            $f.Detail | Should -Match 'nothing that happened before'
        }
        It 'offers no fix when the state is unknown' {
            Set-SysmonWorld -Service $null -Feature 'Disabled' -Admin $false
            (Get-SysmonSecurityFinding).Fixable | Should -BeFalse
        }
        It 'shows days of evidence on the Investigate card' {
            Set-SysmonWorld -Service 'Sysmon64' -Feature 'Absent'
            (Get-SysmonDfirFinding).Title | Should -Be 'Sysmon is recording: 12 day(s) of evidence'
        }
        It 'keeps the downloaded Sysmon while Sysmon is installed' {
            $root = Get-ExternalToolsRoot
            foreach ($d in @('sysmon', 'autoruns')) { New-Item -ItemType Directory -Path (Join-Path $root $d) -Force | Out-Null }
            Mock Get-SysmonServiceName { 'Sysmon64' }
            Remove-ExternalTools | Should -Be 1
            Test-Path -LiteralPath (Join-Path $root 'sysmon') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $root 'autoruns') | Should -BeFalse
        }
    }
}
