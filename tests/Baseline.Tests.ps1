<#
    Baseline.Tests.ps1
    Author: Ahmad Shaukat
    Tests for src/features/Baseline.ps1: snapshot, save, compare and drift cards.
#>

Describe 'Baseline and drift' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestSetup.ps1')
        $script:OldSnap = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\snapshot-baseline.json') -Raw | ConvertFrom-Json
        $script:NewSnap = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\snapshot-current.json') -Raw | ConvertFrom-Json
        function Get-Keys { param($Items) return @(@($Items) | ForEach-Object { $_.Key } | Sort-Object) }
        function Get-Card { param($Cards, [string]$Id) return (@(@($Cards) | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1) }
        function Set-SnapshotMock {
            <# Every collector source returns exactly one item, the single-hit case. #>
            Mock Get-StartupItems { [pscustomobject]@{ Type = 'RegistryRun'; Scope = 'HKCU'; Location = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Name = 'OneDrive'; Command = 'C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background'; Enabled = $true } }
            Mock Get-CimInstance { [pscustomobject]@{ Name = 'Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe'; StartMode = 'Auto'; StartName = 'LocalSystem' } } -ParameterFilter { $ClassName -eq 'Win32_Service' }
            Mock Get-CimInstance { } -ParameterFilter { $Namespace -eq 'root\subscription' }
            Mock Get-ScheduledTask { [pscustomobject]@{ TaskPath = '\Contoso\'; TaskName = 'Update'; Actions = @([pscustomobject]@{ Execute = 'C:\Program Files\Contoso\update.exe'; Arguments = '' }); Principal = [pscustomobject]@{ UserId = 'SYSTEM' } } }
            Mock Get-LocalAdminMember { [pscustomobject]@{ Name = 'PC1\Administrator'; Sid = 'S-1-5-21-1-2-3-500' } }
            Mock Get-LocalUser { New-FakeUser -Name 'bob' -Sid 'S-1-5-21-1-2-3-1001' }
            Mock Get-MpPreference {
                $p = New-Object W11SOTest.FakeMpPreference
                $p.ExclusionPath = [string[]]@('C:\Temp')
                $p.AttackSurfaceReductionRules_Ids = [string[]]@('D4F940AB-401B-4EFC-AADC-AD5F3C50688A')
                $p.AttackSurfaceReductionRules_Actions = [byte[]]@(1)
                $p
            }
            Mock Get-NetTCPConnection { [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 135; OwningProcess = 4 } }
            Mock Get-Process { [pscustomobject]@{ ProcessName = 'svchost'; Path = 'C:\Windows\System32\svchost.exe' } }
            Mock Get-NetFirewallProfile { [pscustomobject]@{ Name = 'Public'; Enabled = $true } }
            Mock Get-Content { '127.0.0.1 localhost' } -ParameterFilter { $LiteralPath -like '*hosts' }
        }
    }
    AfterAll { Restore-TestEnvironment }
    BeforeEach { Set-StrictMode -Version 2.0 }

    Describe 'ConvertTo-StableText' {
        It 'lower-cases and replaces version folders' {
            ConvertTo-StableText 'C:\Program Files\Google\Chrome\Application\154.0.8037.58\elevation_service.exe' | Should -Be 'c:\program files\google\chrome\application\*\elevation_service.exe'
            ConvertTo-StableText 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25080.5-0\MsMpEng.exe' | Should -Be 'c:\programdata\microsoft\windows defender\platform\*\msmpeng.exe'
            ConvertTo-StableText 'C:\Tools\v2\x.exe' | Should -Be 'c:\tools\v2\x.exe'
        }
    }

    Describe 'Get-SystemSnapshot' {
        It 'collects every source with single results under StrictMode' {
            Set-SnapshotMock
            $s = Get-SystemSnapshot
            ($s.Errors.Keys | ForEach-Object { '{0}: {1}' -f $_, $s.Errors[$_] }) | Should -BeNullOrEmpty
            $s.Collections['services'].Keys | Should -Be @('spooler')
            $s.Collections['localusers'].Keys | Should -Be @('s-1-5-21-1-2-3-1001')
            $s.Collections['defenderexclusions'].Keys | Should -Be @('path|c:\temp')
            $s.Collections['asr']['d4f940ab-401b-4efc-aadc-ad5f3c50688a'].action | Should -Be '1'
            $s.Collections['tasks']['\contoso\update'].execute | Should -Be 'c:\program files\contoso\update.exe'
            $s.Collections['listeningports']['tcp|0.0.0.0|135'].process | Should -Be 'svchost'
            @($s.Collections['wmi'].Keys).Count | Should -Be 0
        }
        It 'records a failed collection as an error and never as empty' {
            Set-SnapshotMock
            Mock Get-CimInstance { throw 'Access denied' } -ParameterFilter { $Namespace -eq 'root\subscription' }
            $s = Get-SystemSnapshot
            $s.Errors['wmi'] | Should -Match 'Access denied'
            $s.Collections['wmi'] | Should -BeNullOrEmpty
            $s.Collections.Contains('wmi') | Should -BeTrue
        }
        It 'adds Autoruns rows when this session has an Autoruns CSV' {
            Set-SnapshotMock
            $s = Get-SystemSnapshot -AutorunsCsv (Join-Path $PSScriptRoot 'fixtures\autoruns.csv')
            @($s.Collections['autoruns'].Keys).Count | Should -BeGreaterThan 0
        }
        It 'survives a JSON round trip with single-element collections' {
            Set-SnapshotMock
            $s = Get-SystemSnapshot
            $json = ConvertTo-Json -InputObject $s -Depth 6
            $back = ConvertTo-SnapshotTable -Snapshot ($json | ConvertFrom-Json)
            @($back.Collections['localusers'].Keys) | Should -Be @('s-1-5-21-1-2-3-1001')
            $back.Collections['localusers']['s-1-5-21-1-2-3-1001']['name'] | Should -Be 'bob'
            $d = Compare-Baseline -Baseline ($json | ConvertFrom-Json) -Current $s
            foreach ($n in @($d.Collections.Keys)) {
                @($d.Collections[$n].Added).Count + @($d.Collections[$n].Removed).Count + @($d.Collections[$n].Changed).Count | Should -Be 0
            }
        }
    }

    Describe 'Compare-Baseline on the fixture pair' {
        BeforeAll { $script:Diff = Compare-Baseline -Baseline $script:OldSnap -Current $script:NewSnap }
        It 'finds exactly the expected additions' {
            Get-Keys $script:Diff.Collections['startup'].Added | Should -Be @('registryrun|hkcu|hkcu:\software\microsoft\windows\currentversion\run|updater')
            Get-Keys $script:Diff.Collections['services'].Added | Should -Be @('evilsvc', 'goodsvc')
            Get-Keys $script:Diff.Collections['localadmins'].Added | Should -Be @('s-1-5-21-1-2-3-1002')
            Get-Keys $script:Diff.Collections['localusers'].Added | Should -Be @('s-1-5-21-1-2-3-1002')
            Get-Keys $script:Diff.Collections['defenderexclusions'].Added | Should -Be @('path|c:\temp')
            Get-Keys $script:Diff.Collections['listeningports'].Added | Should -Be @('tcp|0.0.0.0|4444', 'tcp|0.0.0.0|49700')
            Get-Keys $script:Diff.Collections['wmi'].Added | Should -Be @('consumer|commandlineeventconsumer|updater')
            foreach ($n in @('tasks', 'hosts', 'asr', 'firewall')) { @($script:Diff.Collections[$n].Added).Count | Should -Be 0 }
        }
        It 'finds exactly the expected removals and changes' {
            Get-Keys $script:Diff.Collections['services'].Removed | Should -Be @('contososvc')
            $removedTotal = 0; foreach ($n in @($script:Diff.Collections.Keys)) { $removedTotal += @($script:Diff.Collections[$n].Removed).Count }
            $removedTotal | Should -Be 1
            Get-Keys $script:Diff.Collections['startup'].Changed | Should -Be @('registryrun|hkcu|hkcu:\software\microsoft\windows\currentversion\run|onedrive')
            @($script:Diff.Collections['startup'].Changed[0].Fields | ForEach-Object { $_.Field }) | Should -Be @('command')
            Get-Keys $script:Diff.Collections['asr'].Changed | Should -Be @('d4f940ab-401b-4efc-aadc-ad5f3c50688a')
            Get-Keys $script:Diff.Collections['firewall'].Changed | Should -Be @('public')
            $changedTotal = 0; foreach ($n in @($script:Diff.Collections.Keys)) { $changedTotal += @($script:Diff.Collections[$n].Changed).Count }
            $changedTotal | Should -Be 3
        }
        It 'skips a collection that only one side has' {
            $script:Diff.Skipped['autoruns'] | Should -Be 'not collected this time'
            $script:Diff.Collections.Contains('autoruns') | Should -BeFalse
        }
        It 'refuses to compare snapshots from different machines' {
            $other = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\snapshot-current.json') -Raw | ConvertFrom-Json
            $other.MachineName = 'PC2'
            { Compare-Baseline -Baseline $script:OldSnap -Current $other } | Should -Throw '*PC1*PC2*'
        }
    }

    Describe 'Drift cards' {
        BeforeAll { $script:Cards = @(ConvertTo-DriftFinding -Diff (Compare-Baseline -Baseline $script:OldSnap -Current $script:NewSnap)) }
        It 'raises Alerts for <Id>' -ForEach @(
            @{ Id = 'DRIFT-LOCALADMINS-HIGH' }, @{ Id = 'DRIFT-LOCALUSERS-HIGH' }, @{ Id = 'DRIFT-WMI-HIGH' },
            @{ Id = 'DRIFT-DEFENDEREXCLUSIONS-HIGH' }, @{ Id = 'DRIFT-SERVICES-HIGH' }, @{ Id = 'DRIFT-STARTUPCHANGED-HIGH' }
        ) {
            $c = Get-Card $script:Cards $Id
            $c | Should -Not -BeNullOrEmpty
            $c.Status | Should -Be 'Alert'
            $c.Severity | Should -Be 'High'
        }
        It 'titles new items "New since" the baseline date' {
            (Get-Card $script:Cards 'DRIFT-LOCALADMINS-HIGH').Title | Should -Match '^New since 2026-10-01'
        }
        It 'puts the user-writable service in the Alert and the Program Files one in Review' {
            (Get-Card $script:Cards 'DRIFT-SERVICES-HIGH').Evidence | Should -Match 'evilsvc'
            (Get-Card $script:Cards 'DRIFT-SERVICES-HIGH').Evidence | Should -Not -Match 'goodsvc'
            (Get-Card $script:Cards 'DRIFT-SERVICES-MEDIUM').Evidence | Should -Match 'goodsvc'
        }
        It 'reviews other new startup items, ports, ASR and firewall changes' {
            (Get-Card $script:Cards 'DRIFT-STARTUP-MEDIUM').Status | Should -Be 'Review'
            (Get-Card $script:Cards 'DRIFT-LISTENINGPORTS-MEDIUM').Evidence | Should -Match '4444'
            (Get-Card $script:Cards 'DRIFT-LISTENINGPORTS-INFO').Evidence | Should -Match '49700'
            (Get-Card $script:Cards 'DRIFT-ASRCHANGED-MEDIUM').Status | Should -Be 'Review'
            (Get-Card $script:Cards 'DRIFT-FIREWALLCHANGED-MEDIUM').Evidence | Should -Match 'enabled: true  ->  false'
        }
        It 'reports removals as Info' {
            $c = Get-Card $script:Cards 'DRIFT-SERVICESREMOVED-INFO'
            $c.Status | Should -Be 'Info'
            $c.Title | Should -Match '^Gone since'
        }
        It 'reports the skipped Autoruns comparison' {
            (Get-Card $script:Cards 'DRIFT-SKIPPED-AUTORUNS').Status | Should -Be 'Info'
        }
        It 'reports no changes when nothing differs' {
            $same = @(ConvertTo-DriftFinding -Diff (Compare-Baseline -Baseline $script:OldSnap -Current $script:OldSnap))
            $same.Count | Should -Be 1
            $same[0].Id | Should -Be 'DRIFT-NONE'
            $same[0].Status | Should -Be 'Clean'
        }
    }

    Describe 'Save-Baseline' {
        BeforeEach {
            Mock Test-IsAdmin { $true }
            Mock Set-ItemOwnerAdministrators { }
            Mock Add-ChangeRecord { }
            $paths = Get-BaselinePath
            if (Test-Path -LiteralPath $paths.Dir) { Remove-Item -LiteralPath $paths.Dir -Recurse -Force }
        }
        It 'writes the baseline through Write-SecureFile and keeps the previous one' {
            Save-Baseline -Snapshot $script:OldSnap | Should -Be (Get-BaselinePath).Current
            Save-Baseline -Snapshot $script:NewSnap | Out-Null
            $paths = Get-BaselinePath
            (ConvertTo-SnapshotTable -Snapshot (Get-Content -LiteralPath $paths.Current -Raw | ConvertFrom-Json)).CreatedUtc | Should -Match '^2026-10-12'
            (ConvertTo-SnapshotTable -Snapshot (Get-Content -LiteralPath $paths.Previous -Raw | ConvertFrom-Json)).CreatedUtc | Should -Match '^2026-10-01'
            Should -Invoke Set-ItemOwnerAdministrators -ParameterFilter { $Path -eq $paths.Current } -Times 2 -Exactly
        }
        It 'refuses a snapshot with an errored collection' {
            $bad = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\snapshot-current.json') -Raw | ConvertFrom-Json
            $bad.Errors = [pscustomobject]@{ wmi = 'Access denied' }
            { Save-Baseline -Snapshot $bad } | Should -Throw '*wmi*'
            Test-Path -LiteralPath (Get-BaselinePath).Current | Should -BeFalse
        }
        It 'refuses when not elevated' {
            Mock Test-IsAdmin { $false }
            { Save-Baseline -Snapshot $script:OldSnap } | Should -Throw '*administrator*'
        }
    }

    Describe 'Invoke-BaselineDrift' {
        It 'returns one Info card when there is no baseline' {
            Mock Read-Baseline { $null }
            $c = @(Invoke-BaselineDrift)
            $c.Count | Should -Be 1
            $c[0].Id | Should -Be 'DRIFT-NOBASELINE'
        }
        It 'refuses a baseline file not owned by Administrators' {
            $paths = Get-BaselinePath
            New-Item -ItemType Directory -Path $paths.Dir -Force | Out-Null
            Set-Content -LiteralPath $paths.Current -Value '{}'
            Mock Test-FolderOwnedBySystemOrAdmins { $false }
            { Read-Baseline } | Should -Throw '*not owned by Administrators*'
        }
    }
}
