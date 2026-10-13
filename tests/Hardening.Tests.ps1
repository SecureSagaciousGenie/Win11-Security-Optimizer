<#
    Hardening.Tests.ps1
    Author: Ahmad Shaukat
    Tests for src/features/Hardening.ps1: pass, fail and unreadable for every
    check; apply, verify, idempotence and rollback for every fix.
#>

Describe 'Credential-theft hardening' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestSetup.ps1')
        function New-RegRead { param([bool]$Exists, $Value) [pscustomobject]@{ Exists = $Exists; Value = $Value } }
        function Get-RollbackText { return ($script:Core.Rollback.ToArray() -join "`r`n") }
        function Assert-ParsesCleanly {
            param([string]$Text)
            $t = $null; $e = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$t, [ref]$e)
            @($e) | Should -BeNullOrEmpty
        }
        function Set-RegistryWriteMock {
            <# Lets Set-RegValueTracked and Backup-RegValue run for real against a
               fake prior value, without touching the registry. #>
            param($PriorValue)
            $script:Prior = $PriorValue
            Mock Test-Path { $true } -ParameterFilter { $Path -like 'HKLM:*' }
            Mock Get-ItemProperty {
                $o = New-Object PSObject
                if ($null -ne $script:Prior) { $o | Add-Member -NotePropertyName ([string]@($Name)[0]) -NotePropertyValue $script:Prior }
                $o
            } -ParameterFilter { $Path -like 'HKLM:*' }
            Mock New-Item { }
            Mock New-ItemProperty { }
        }
    }
    AfterAll { Restore-TestEnvironment }
    BeforeEach {
        Set-StrictMode -Version 2.0
        $script:Core.Rollback.Clear(); $script:Core.Changes.Clear(); $script:Core.Backups.Clear()
    }

    Describe 'Registration' {
        It 'adds all eight checks to the Security scan' {
            foreach ($id in @('LSA-PPL', 'CRED-GUARD', 'WDIGEST', 'PSV2', 'NBTNS', 'MDNS', 'SMB-SIGN', 'PATCH-AGE')) {
                $script:ExtraSecurityChecks.Contains($id) | Should -BeTrue
            }
            foreach ($id in @('LSA-PPL', 'WDIGEST', 'PSV2', 'NBTNS', 'MDNS', 'SMB-SIGN')) {
                $script:ExtraFixActions.ContainsKey($id) | Should -BeTrue
                $script:ExtraFixTests.ContainsKey($id) | Should -BeTrue
            }
            $script:ExtraFixActions.ContainsKey('CRED-GUARD') | Should -BeFalse
            $script:ExtraFixActions.ContainsKey('PATCH-AGE') | Should -BeFalse
        }
    }

    Describe 'LSA-PPL' {
        It 'passes for RunAsPPL=<V>' -ForEach @(@{ V = 1 }, @{ V = 2 }) {
            Mock Read-RegistryValue { New-RegRead $true $V }
            Mock Get-OsBuildNumber { 26100 }
            (Get-LsaPplFinding).Status | Should -Be 'Pass'
        }
        It 'fails and offers a fix on 22621 or later' {
            Mock Read-RegistryValue { New-RegRead $false $null }
            Mock Get-OsBuildNumber { 22621 }
            $f = Get-LsaPplFinding
            $f.Status | Should -Be 'Fail'
            $f.Fixable | Should -BeTrue
            $f.RiskTier | Should -Be 'HighRisk'
        }
        It 'reports only, with no fix, below build 22621' {
            Mock Read-RegistryValue { New-RegRead $true 0 }
            Mock Get-OsBuildNumber { 22000 }
            $f = Get-LsaPplFinding
            $f.Status | Should -Be 'Fail'
            $f.Fixable | Should -BeFalse
            { Invoke-LsaPplFix } | Should -Throw '*22621*'
        }
        It 'reports Error when unreadable' {
            Mock Read-RegistryValue { throw 'Access denied' }
            (Get-LsaPplFinding).Status | Should -Be 'Error'
        }
        It 'applies 2 with a rollback that removes the absent value, and is idempotent' {
            Mock Get-OsBuildNumber { 26100 }
            $script:Ppl = $null
            Mock Read-RegistryValue { if ($null -eq $script:Ppl) { New-RegRead $false $null } else { New-RegRead $true $script:Ppl } }
            Set-RegistryWriteMock -PriorValue $null
            Invoke-LsaPplFix
            Should -Invoke New-ItemProperty -ParameterFilter { $Name -eq 'RunAsPPL' -and $Value -eq 2 } -Times 1 -Exactly
            $text = Get-RollbackText
            $text | Should -Match "Remove-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL'"
            Assert-ParsesCleanly $text
            $script:Ppl = 2
            Test-LsaPplApplied | Should -BeTrue
            Invoke-LsaPplFix
            $script:Core.Rollback.Count | Should -Be 1
        }
    }

    Describe 'CRED-GUARD' {
        It 'passes when service 1 is running' {
            Mock Get-CimInstance { [pscustomobject]@{ SecurityServicesRunning = @(1, 2) } } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }
            (Get-CredGuardFinding).Status | Should -Be 'Pass'
        }
        It 'warns, audit only, when it is not running' {
            Mock Get-CimInstance { [pscustomobject]@{ SecurityServicesRunning = @(2) } } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }
            $f = Get-CredGuardFinding
            $f.Status | Should -Be 'Warning'
            $f.Fixable | Should -BeFalse
            $f.RiskTier | Should -Be 'AuditOnly'
        }
        It 'reports Error when unreadable' {
            Mock Get-CimInstance { throw 'Invalid namespace' } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }
            (Get-CredGuardFinding).Status | Should -Be 'Error'
        }
    }

    Describe 'WDIGEST' {
        It 'passes when absent or 0' -ForEach @(@{ E = $false; V = $null }, @{ E = $true; V = 0 }) {
            Mock Read-RegistryValue { New-RegRead $E $V }
            (Get-WDigestFinding).Status | Should -Be 'Pass'
        }
        It 'fails when 1' {
            Mock Read-RegistryValue { New-RegRead $true 1 }
            $f = Get-WDigestFinding
            $f.Status | Should -Be 'Fail'
            $f.RiskTier | Should -Be 'Safe'
        }
        It 'reports Error when unreadable' {
            Mock Read-RegistryValue { throw 'Access denied' }
            (Get-WDigestFinding).Status | Should -Be 'Error'
        }
        It 'sets 0, restores 1 on rollback and is idempotent' {
            $script:Wd = 1
            Mock Read-RegistryValue { New-RegRead $true $script:Wd }
            Set-RegistryWriteMock -PriorValue 1
            Invoke-WDigestFix
            Should -Invoke New-ItemProperty -ParameterFilter { $Name -eq 'UseLogonCredential' -and $Value -eq 0 } -Times 1 -Exactly
            $text = Get-RollbackText
            $text | Should -Match "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 1 -PropertyType DWord"
            Assert-ParsesCleanly $text
            $script:Wd = 0
            Test-WDigestApplied | Should -BeTrue
            Invoke-WDigestFix
            $script:Core.Rollback.Count | Should -Be 1
        }
        It 'goes through Invoke-SecurityFix and verifies' {
            $script:Wd = 1
            Mock Read-RegistryValue { New-RegRead $true $script:Wd }
            Mock Assert-SafeToChange { }
            Mock Save-RollbackArtifacts { }
            Mock Set-RegValueTracked { $script:Wd = 0 }
            $r = Invoke-SecurityFix -Id 'WDIGEST'
            $r.Success | Should -BeTrue
            $r.Verified | Should -BeTrue
        }
    }

    Describe 'PSV2' {
        BeforeEach { Mock Test-IsAdmin { $true } }
        It 'passes when <Label>' -ForEach @(
            @{ Label = 'disabled'; Mode = 'disabled' }, @{ Label = 'the feature is unknown on this build'; Mode = 'unknown' }, @{ Label = 'nothing is returned'; Mode = 'none' }
        ) {
            $script:PsMode = $Mode
            Mock Get-WindowsOptionalFeature {
                switch ($script:PsMode) {
                    'disabled' { [pscustomobject]@{ State = 'Disabled' } }
                    'unknown'  { throw (New-Object System.Runtime.InteropServices.COMException('Feature name is unknown.', -2146498548)) }
                    default    { }
                }
            }
            (Get-PsV2Finding).Status | Should -Be 'Pass'
        }
        It 'fails when enabled' {
            Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = 'Enabled' } }
            $f = Get-PsV2Finding
            $f.Status | Should -Be 'Fail'
            $f.RiskTier | Should -Be 'Elevated'
        }
        It 'reports Error when DISM fails for another reason' {
            Mock Get-WindowsOptionalFeature { throw (New-Object System.Runtime.InteropServices.COMException('Class not registered', -2147221164)) }
            (Get-PsV2Finding).Status | Should -Be 'Error'
        }
        It 'reports Info without administrator rights' {
            Mock Test-IsAdmin { $false }
            Mock Get-WindowsOptionalFeature { throw 'must not be called' }
            (Get-PsV2Finding).Status | Should -Be 'Info'
        }
        It 'disables with -NoRestart, rolls back with Enable and is idempotent' {
            $script:PsState = 'Enabled'
            Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = $script:PsState } }
            Mock Disable-WindowsOptionalFeature { $script:PsState = 'Disabled' }
            Invoke-PsV2Fix
            Should -Invoke Disable-WindowsOptionalFeature -ParameterFilter { $NoRestart -and ($FeatureName -contains 'MicrosoftWindowsPowerShellV2Root') } -Times 1 -Exactly
            $text = Get-RollbackText
            $text | Should -Match "Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -All -NoRestart"
            Assert-ParsesCleanly $text
            Test-PsV2Applied | Should -BeTrue
            Invoke-PsV2Fix
            Should -Invoke Disable-WindowsOptionalFeature -Times 1 -Exactly
            $script:Core.Rollback.Count | Should -Be 1
        }
    }

    Describe 'NBTNS' {
        It 'reads only GUID-named interfaces' {
            Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*NetBT*' }
            Mock Get-ChildItem {
                [pscustomobject]@{ PSChildName = 'Tcpip_{11111111-2222-3333-4444-555555555555}' }
                [pscustomobject]@{ PSChildName = "Tcpip_x'; Start-Process calc; '" }
            } -ParameterFilter { $LiteralPath -like '*NetBT*' }
            Mock Read-RegistryValue { New-RegRead $true 2 }
            $ifs = @(Get-NetBtInterface)
            $ifs.Count | Should -Be 1
            $ifs[0].Name | Should -Be 'Tcpip_{11111111-2222-3333-4444-555555555555}'
        }
        It 'passes when every interface is 2' {
            Mock Get-NetBtInterface { [pscustomobject]@{ Name = 'Tcpip_{a}'; Path = 'HKLM:\x\Tcpip_{a}'; Value = '2' } }
            (Get-NbtNsFinding).Status | Should -Be 'Pass'
        }
        It 'fails when one interface is not 2' {
            Mock Get-NetBtInterface {
                [pscustomobject]@{ Name = 'Tcpip_{a}'; Path = 'HKLM:\x\Tcpip_{a}'; Value = '2' }
                [pscustomobject]@{ Name = 'Tcpip_{b}'; Path = 'HKLM:\x\Tcpip_{b}'; Value = '0' }
            }
            $f = Get-NbtNsFinding
            $f.Status | Should -Be 'Fail'
            $f.Observed | Should -Be 'On for 1 of 2 interface(s)'
        }
        It 'reports Error when unreadable' {
            Mock Get-NetBtInterface { throw 'Access denied' }
            (Get-NbtNsFinding).Status | Should -Be 'Error'
        }
        It 'sets 2 per interface with one rollback entry each and is idempotent' {
            $script:Nb = @{ a = '0'; b = '2' }
            Mock Get-NetBtInterface {
                foreach ($k in @('a', 'b')) { [pscustomobject]@{ Name = "Tcpip_{$k}"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{$k}"; Value = $script:Nb[$k] } }
            }
            Set-RegistryWriteMock -PriorValue 0
            Invoke-NbtNsFix
            Should -Invoke New-ItemProperty -ParameterFilter { $Name -eq 'NetbiosOptions' -and $Value -eq 2 } -Times 1 -Exactly
            $text = Get-RollbackText
            $text | Should -Match ([regex]::Escape("-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{a}' -Name 'NetbiosOptions' -Value 0"))
            Assert-ParsesCleanly $text
            $script:Nb.a = '2'
            Test-NbtNsApplied | Should -BeTrue
            Invoke-NbtNsFix
            $script:Core.Rollback.Count | Should -Be 1
        }
    }

    Describe 'MDNS' {
        It 'passes when 0' {
            Mock Read-RegistryValue { New-RegRead $true 0 }
            (Get-MdnsFinding).Status | Should -Be 'Pass'
        }
        It 'fails when absent' {
            Mock Read-RegistryValue { New-RegRead $false $null }
            $f = Get-MdnsFinding
            $f.Status | Should -Be 'Fail'
            $f.Detail + $f.Advice | Should -Match 'Casting'
        }
        It 'reports Error when unreadable' {
            Mock Read-RegistryValue { throw 'Access denied' }
            (Get-MdnsFinding).Status | Should -Be 'Error'
        }
        It 'sets 0, removes the value on rollback and is idempotent' {
            $script:Md = $null
            Mock Read-RegistryValue { if ($null -eq $script:Md) { New-RegRead $false $null } else { New-RegRead $true $script:Md } }
            Set-RegistryWriteMock -PriorValue $null
            Invoke-MdnsFix
            Should -Invoke New-ItemProperty -ParameterFilter { $Name -eq 'EnableMDNS' -and $Value -eq 0 } -Times 1 -Exactly
            $text = Get-RollbackText
            $text | Should -Match "Remove-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name 'EnableMDNS'"
            Assert-ParsesCleanly $text
            $script:Md = 0
            Test-MdnsApplied | Should -BeTrue
            Invoke-MdnsFix
            $script:Core.Rollback.Count | Should -Be 1
        }
    }

    Describe 'SMB-SIGN' {
        It 'passes when both require signing' {
            Mock Get-SmbServerConfiguration { [pscustomobject]@{ RequireSecuritySignature = $true } }
            Mock Get-SmbClientConfiguration { [pscustomobject]@{ RequireSecuritySignature = $true } }
            (Get-SmbSignFinding).Status | Should -Be 'Pass'
        }
        It 'fails when either does not' {
            Mock Get-SmbServerConfiguration { [pscustomobject]@{ RequireSecuritySignature = $false } }
            Mock Get-SmbClientConfiguration { [pscustomobject]@{ RequireSecuritySignature = $true } }
            (Get-SmbSignFinding).Status | Should -Be 'Fail'
        }
        It 'reports Error when unreadable' {
            Mock Get-SmbServerConfiguration { throw 'Access denied' }
            (Get-SmbSignFinding).Status | Should -Be 'Error'
        }
        It 'requires signing, restores only what changed and is idempotent' {
            $script:Smb = @{ Server = $false; Client = $true }
            Mock Get-SmbServerConfiguration { [pscustomobject]@{ RequireSecuritySignature = $script:Smb.Server } }
            Mock Get-SmbClientConfiguration { [pscustomobject]@{ RequireSecuritySignature = $script:Smb.Client } }
            Mock Set-SmbServerConfiguration { $script:Smb.Server = $true }
            Mock Set-SmbClientConfiguration { $script:Smb.Client = $true }
            Invoke-SmbSignFix
            Should -Invoke Set-SmbServerConfiguration -ParameterFilter { $RequireSecuritySignature -and $Force } -Times 1 -Exactly
            Should -Invoke Set-SmbClientConfiguration -Times 0 -Exactly
            $text = Get-RollbackText
            $text | Should -Match ([regex]::Escape('Set-SmbServerConfiguration -RequireSecuritySignature $false -Force'))
            $text | Should -Not -Match 'Set-SmbClientConfiguration'
            Assert-ParsesCleanly $text
            Test-SmbSignApplied | Should -BeTrue
            Invoke-SmbSignFix
            $script:Core.Rollback.Count | Should -Be 1
        }
    }

    Describe 'PATCH-AGE' {
        BeforeAll {
            $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-12 12:00:00', [System.DateTimeKind]::Utc)
            function New-Hist { param([int]$DaysAgo, [int]$Result = 2, [string]$Title = '2026-09 Cumulative Update for Windows 11 (KB5099999)', [string[]]$Cats = @('0fa1201d-4330-4fa8-8ae9-b877473b6441'))
                [pscustomobject]@{ Date = $script:Now.AddDays(-$DaysAgo); ResultCode = $Result; Operation = 1; Title = $Title; CategoryIds = $Cats } }
        }
        It 'is <Status> at <Days> days' -ForEach @(@{ Days = 10; Status = 'Pass' }, @{ Days = 35; Status = 'Pass' }, @{ Days = 36; Status = 'Warning' }, @{ Days = 60; Status = 'Warning' }, @{ Days = 61; Status = 'Fail' }) {
            $script:D = $Days
            Mock Get-UpdateHistory { New-Hist -DaysAgo $script:D }
            (Get-PatchAgeFinding -Now $script:Now).Status | Should -Be $Status
        }
        It 'ignores failed installs, Defender definitions and drivers' {
            Mock Get-UpdateHistory {
                New-Hist -DaysAgo 1 -Result 4
                New-Hist -DaysAgo 0 -Title 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.4)' -Cats @('e0789628-ce08-4437-be74-2495b842f43b')
                New-Hist -DaysAgo 2 -Title 'Intel - System - 1.2.3' -Cats @('ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0')
                New-Hist -DaysAgo 90
            }
            $f = Get-PatchAgeFinding -Now $script:Now
            $f.Status | Should -Be 'Fail'
            $f.Observed | Should -Match '^90 day'
        }
        It 'warns when there is no successful update at all' {
            Mock Get-UpdateHistory { }
            (Get-PatchAgeFinding -Now $script:Now).Status | Should -Be 'Warning'
        }
        It 'reports Error when the history cannot be read' {
            Mock Get-UpdateHistory { throw 'COM object not available' }
            (Get-PatchAgeFinding -Now $script:Now).Status | Should -Be 'Error'
        }
    }
}
