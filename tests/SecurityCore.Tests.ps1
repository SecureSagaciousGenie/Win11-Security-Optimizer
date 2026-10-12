<#
    SecurityCore.Tests.ps1
    Author: Ahmad Shaukat
    Unit and regression tests for src/SecurityCore.ps1 (Pester 5).
    Every system call is mocked. LOCALAPPDATA and ProgramData point at TestDrive.
#>

BeforeDiscovery {
    $script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Test-Path variable:IsWindows) -and $IsWindows)
}

Describe 'SecurityCore' {
    BeforeAll {
        $script:RepoRoot = Split-Path -Parent $PSScriptRoot
        $script:SavedEnv = @{
            LOCALAPPDATA      = $env:LOCALAPPDATA
            ProgramData       = $env:ProgramData
            W11SO_SESSION_LOG = $env:W11SO_SESSION_LOG
        }
        $env:LOCALAPPDATA = Join-Path $TestDrive 'LocalAppData'
        $env:ProgramData  = Join-Path $TestDrive 'ProgramData'
        Remove-Item -Path Env:\W11SO_SESSION_LOG -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $env:LOCALAPPDATA, $env:ProgramData -Force | Out-Null

        . (Join-Path $PSScriptRoot 'Fakes.ps1')
        . (Join-Path $script:RepoRoot 'src\SecurityCore.ps1')

        Mock Test-IsAdmin { $false }
        Mock New-SystemRestorePointOnce { $true }
        Initialize-Core | Out-Null

        function Get-CardIds { param($Cards) return @(@($Cards) | ForEach-Object { $_.Id }) }
        function Get-Card { param($Cards, [string]$Id) return (@(@($Cards) | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1) }
    }

    AfterAll {
        $env:LOCALAPPDATA = $script:SavedEnv.LOCALAPPDATA
        $env:ProgramData  = $script:SavedEnv.ProgramData
        if ($script:SavedEnv.W11SO_SESSION_LOG) { $env:W11SO_SESSION_LOG = $script:SavedEnv.W11SO_SESSION_LOG }
        else { Remove-Item -Path Env:\W11SO_SESSION_LOG -ErrorAction SilentlyContinue }
    }

    BeforeEach {
        Set-StrictMode -Version 2.0
    }

    Describe 'Test harness' {
        It 'runs under StrictMode 2.0 so scalar .Count throws on compiled fakes' {
            $u = New-FakeUser -Name 'x'
            { $null = $u.Count } | Should -Throw
        }
    }

    Describe 'a. Invoke-EventLogTriage single-hit counts' {
        BeforeAll {
            $svcXml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>7045</EventID></System>
  <EventData>
    <Data Name="ServiceName">EvilSvc</Data>
    <Data Name="ImagePath">C:\Users\Public\evil.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">auto start</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>
'@
            $rdpProps = @('S-1-5-18', 'PC$', 'WORKGROUP', '0x3e7', 'S-1-5-21-1-2-3-1001', 'bob', 'PC', '0x1234', [uint32]10)
            $script:FakeEvents = @(
                (New-FakeEvent -LogName 'System' -Id 7045 -Message 'A service was installed in the system.' -Xml $svcXml -Properties @('EvilSvc', 'C:\Users\Public\evil.exe', 'user mode service', 'auto start', 'LocalSystem')),
                (New-FakeEvent -LogName 'Security' -Id 4740 -Message 'A user account was locked out.'),
                (New-FakeEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -Id 1116 -Message "Microsoft Defender Antivirus has detected malware.`n Name: Trojan:Win32/Fake"),
                (New-FakeEvent -LogName 'Security' -Id 4698 -Message "A scheduled task was created.`n Task Name: \Evil"),
                (New-FakeEvent -LogName 'Security' -Id 4624 -Message 'An account was successfully logged on.' -Properties $rdpProps)
            )
            Mock Get-WinEvent {
                $h = $FilterHashtable[0]
                $ids = @($h['Id'])
                $hits = @($script:FakeEvents | Where-Object { ($_.LogName -eq $h['LogName']) -and ($ids -contains $_.Id) })
                if ($hits.Count -eq 0) {
                    $ex = New-Object System.Exception 'No events were found that match the specified selection criteria.'
                    throw (New-Object System.Management.Automation.ErrorRecord($ex, 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', 'ObjectNotFound', $null))
                }
                foreach ($e in $hits) { $e }
            }
            $script:EvtCards = @(Invoke-EventLogTriage -Days 14)
        }

        It 'produces no error cards' {
            @(Get-CardIds $script:EvtCards | Where-Object { $_ -like '*-ERR' }) | Should -BeNullOrEmpty
        }
        It 'reports one new service from the structured 7045 fields' {
            $c = Get-Card $script:EvtCards 'EVT-NEWSVC'
            $c | Should -Not -BeNullOrEmpty
            $c.Title | Should -Match ': 1$'
            $c.Evidence | Should -Match 'EvilSvc'
            $c.Evidence | Should -Match 'evil\.exe'
        }
        It 'reports one account lockout (4740)' {
            (Get-Card $script:EvtCards 'EVT-LOCKOUT').Title | Should -Match ': 1$'
        }
        It 'reports one Defender detection (1116/1117)' {
            (Get-Card $script:EvtCards 'EVT-DEFENDER').Title | Should -Match 'detected threats: 1$'
        }
        It 'reports one scheduled task creation (4698)' {
            (Get-Card $script:EvtCards 'EVT-TASK').Title | Should -Match 'created: 1$'
        }
        It 'reports one RDP logon (4624 with Properties[8] = 10)' {
            (Get-Card $script:EvtCards 'EVT-RDPLOGON').Title | Should -Match ': 1$'
        }
    }

    Describe 'b. Invoke-DfirTriage single-hit counts' {
        BeforeAll {
            Mock Get-LocalGroupMember {
                $m = New-Object W11SOTest.FakeGroupMember
                $m.Name = 'PC\Administrator'; $m.ObjectClass = 'User'
                $m.SID = New-Object W11SOTest.FakeSid -ArgumentList 'S-1-5-21-1000-2000-3000-500'
                $m
            }
            Mock Get-LocalUser { New-FakeUser -Name 'support$' -Enabled $true -Sid 'S-1-5-21-1000-2000-3000-1005' }
            Mock Get-StartupItems { }
            Mock Get-ScheduledTask { }
            Mock Get-CimInstance { }
            Mock Get-RegValue { 1 }
            Mock Get-NetTCPConnection { }
            Mock Get-SmbShare { }
        }

        It 'flags exactly one hidden user and counts one enabled account' {
            Mock Get-MpPreference { New-Object W11SOTest.FakeMpPreference }
            $cards = @(Invoke-DfirTriage)
            $hidden = Get-Card $cards 'DFIR-HIDDENUSER'
            $hidden | Should -Not -BeNullOrEmpty
            $hidden.Evidence | Should -Be 'support$'
            (Get-Card $cards 'DFIR-USERS').Title | Should -Be 'Enabled local accounts: 1'
            (Get-Card $cards 'DFIR-ADMIN').Title | Should -Not -Match 'Could not read'
            @(Get-CardIds $cards) | Should -Not -Contain 'DFIR-USERS-ERR'
        }

        It 'reports <Count> Defender exclusion(s) correctly' -ForEach @(
            @{ Count = 0; Paths = $null;            Procs = $null;           Status = 'Clean'  }
            @{ Count = 1; Paths = @('C:\Temp');     Procs = $null;           Status = 'Review' }
            @{ Count = 2; Paths = @('C:\Temp');     Procs = @('evil.exe');   Status = 'Review' }
        ) {
            $script:ExPaths = $Paths; $script:ExProcs = $Procs
            Mock Get-MpPreference {
                $p = New-Object W11SOTest.FakeMpPreference
                if ($script:ExPaths) { $p.ExclusionPath = [string[]]$script:ExPaths }
                if ($script:ExProcs) { $p.ExclusionProcess = [string[]]$script:ExProcs }
                $p
            }
            $c = Get-Card @(Invoke-DfirTriage) 'DFIR-DEFEXCL'
            $c.Status | Should -Be $Status
            if ($Count -gt 0) { $c.Title | Should -Be ("Microsoft Defender has {0} exclusion(s)" -f $Count) }
        }
    }

    Describe 'c. Set-StartupItemState rollback escaping' {
        BeforeAll {
            Mock Assert-SafeToChange { }
            Mock Test-Path { $true }
            Mock New-Item { }
            Mock New-ItemProperty { }
            Mock Remove-ItemProperty { }
            Mock Save-RollbackArtifacts { }
            function Get-StartProcessCalls {
                param([string]$Text)
                $tokens = $null; $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
                return @($ast.FindAll({ param($n) ($n -is [System.Management.Automation.Language.CommandAst]) -and ($n.GetCommandName() -eq 'Start-Process') }, $true))
            }
        }

        It 'never lets <Label> become live code (Enable=<Enable>)' -ForEach @(
            @{ Label = 'an ASCII quote in the value';  Name = 'App';  Value = "C:\x.exe'; Start-Process calc; '";                 Enable = $false }
            @{ Label = 'a U+2019 quote in the value';  Name = 'App';  Value = ("C:\x.exe{0}; Start-Process calc; {0}" -f [char]0x2019); Enable = $false }
            @{ Label = 'CR/LF in the value name';      Name = "App`r`nStart-Process calc`r`n#"; Value = 'C:\x.exe';            Enable = $false }
            @{ Label = 'an ASCII quote in the value';  Name = 'App';  Value = "C:\x.exe'; Start-Process calc; '";                 Enable = $true }
            @{ Label = 'a U+2019 quote in the value';  Name = 'App';  Value = ("C:\x.exe{0}; Start-Process calc; {0}" -f [char]0x2019); Enable = $true }
            @{ Label = 'CR/LF in the value name';      Name = "App`r`nStart-Process calc`r`n#"; Value = 'C:\x.exe';            Enable = $true }
        ) {
            $script:Core.Rollback.Clear()
            $script:Crafted = $Value
            Mock Get-RegValue { $script:Crafted }
            $r = Set-StartupItemState -Type RegistryRun -Location 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $Name -Enable $Enable -Command $Value
            $r.Success | Should -BeTrue
            $text = ($script:Core.Rollback.ToArray() -join "`r`n")
            $text | Should -Not -BeNullOrEmpty
            @(Get-StartProcessCalls -Text $text).Count | Should -Be 0
        }
    }

    Describe 'd. Test-IsDefenderDefinitionDriver' -Skip:(-not $script:OnWindows) {
        BeforeAll {
            $script:DefPrefix = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Definition Updates\'
        }
        It 'accepts the genuine driver path' {
            Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ($script:DefPrefix + '{11111111-2222-3333-4444-555555555555}\MpKslDrv.sys') | Should -BeTrue
        }
        It 'accepts the genuine driver path with a \??\ prefix' {
            Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ('\??\' + $script:DefPrefix + '{11111111-2222-3333-4444-555555555555}\MpKslDrv.sys') | Should -BeTrue
        }
        It 'rejects an evil exe with the trusted path appended as an argument' {
            Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ('C:\Users\Public\evil.exe "' + $script:DefPrefix + 'x\MpKslDrv.sys"') | Should -BeFalse
        }
        It 'rejects a path that climbs out of Definition Updates with ..\' {
            Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ($script:DefPrefix + '..\..\..\..\Users\Public\MpKslDrv.sys') | Should -BeFalse
        }
    }

    Describe 'e. Resolve-ExternalToolRelease hash source' {
        BeforeAll {
            Mock Get-SystemArch { 'AMD64' }
            $script:Digest = 'sha256:' + ('AB' * 32)
        }
        It 'uses the pinned hash for the pinned tag' {
            Mock Invoke-RestMethod {
                [pscustomobject]@{ tag_name = 'v4.1.0'; published_at = '2025-01-01'; assets = @(
                    [pscustomobject]@{ name = 'hayabusa-4.1.0-win-x64.zip'; browser_download_url = 'https://github.com/x/y.zip'; size = 1048576; digest = $script:Digest }) }
            }
            $r = Resolve-ExternalToolRelease -Key 'hayabusa'
            $r.Sha256Source | Should -Be 'pinned'
            $r.Sha256Expected | Should -Be '4D304CC5BAAA750ED08CC24B7B89C58EA058740C7E344502D7B82554637543A8'
        }
        It 'uses the GitHub digest for any other tag' {
            Mock Invoke-RestMethod {
                [pscustomobject]@{ tag_name = 'v9.9.9'; published_at = '2026-01-01'; assets = @(
                    [pscustomobject]@{ name = 'hayabusa-9.9.9-win-x64.zip'; browser_download_url = 'https://github.com/x/y.zip'; size = 1048576; digest = $script:Digest }) }
            }
            $r = Resolve-ExternalToolRelease -Key 'hayabusa' -UseLatest
            $r.Sha256Source | Should -Be 'github-digest'
            $r.Sha256Expected | Should -Be ('AB' * 32)
        }
        It 'reports none when there is no digest' {
            Mock Invoke-RestMethod {
                [pscustomobject]@{ tag_name = 'v9.9.9'; published_at = '2026-01-01'; assets = @(
                    [pscustomobject]@{ name = 'hayabusa-9.9.9-win-x64.zip'; browser_download_url = 'https://github.com/x/y.zip'; size = 1048576 }) }
            }
            $r = Resolve-ExternalToolRelease -Key 'hayabusa' -UseLatest
            $r.Sha256Source | Should -Be 'none'
            $r.Sha256Expected | Should -BeNullOrEmpty
        }
    }

    Describe 'f. Save-RollbackArtifacts re-owns files in the secure base' {
        It 'calls Set-ItemOwnerAdministrators on the rollback script' {
            if (-not (Get-Command Set-ItemOwnerAdministrators -ErrorAction SilentlyContinue)) {
                function script:Set-ItemOwnerAdministrators { param([string]$Path) }
            }
            Mock Set-ItemOwnerAdministrators { }
            $base = Join-Path $env:ProgramData 'Win11SecurityOptimizer'
            New-Item -ItemType Directory -Path (Join-Path $base 'backups') -Force | Out-Null
            $oldR = $script:Core.RollbackFile; $oldB = $script:Core.BackupFile
            try {
                $script:Core.RollbackFile = $base + '\backups\Rollback_test.ps1'
                $script:Core.BackupFile   = $base + '\backups\Backup_test.json'
                $script:Core.Rollback.Clear(); [void]$script:Core.Rollback.Add("# test`r`nWrite-Output 'x'")
                $script:Core.Backups.Clear(); [void]$script:Core.Backups.Add([pscustomobject]@{ Kind = 'Registry'; Path = 'HKCU:\x'; Name = 'y' })
                Save-RollbackArtifacts
                $rf = $script:Core.RollbackFile
                Should -Invoke Set-ItemOwnerAdministrators -ParameterFilter { $Path -eq $rf } -Times 1
            } finally {
                $script:Core.RollbackFile = $oldR; $script:Core.BackupFile = $oldB
                $script:Core.Rollback.Clear(); $script:Core.Backups.Clear()
            }
        }
    }

    Describe 'g. Initialize-Core -ReadOnly never mutates the secure base' {
        It 'does not call the securing helpers even when elevated' {
            Mock Test-IsAdmin { $true }
            Mock Initialize-SecureBase { Join-Path $env:ProgramData 'Win11SecurityOptimizer' }
            Mock Set-ToolsFolderAcl { }
            Mock Set-TreeOwnerToAdministrators { }
            Mock Test-FolderOwnedBySystemOrAdmins { $true }
            Initialize-Core -ReadOnly | Out-Null
            Should -Invoke Initialize-SecureBase -Times 0 -Exactly
            Should -Invoke Set-ToolsFolderAcl -Times 0 -Exactly
            Should -Invoke Set-TreeOwnerToAdministrators -Times 0 -Exactly
        }
    }

    Describe 'Fail-closed downloads (regression lock)' {
        BeforeAll {
            Mock Test-IsAdmin { $true }
            Mock Initialize-SecureToolsRoot { Get-ExternalToolsRoot }
            Mock Test-ToolsRootSecure { $true }
            Mock Test-ExternalToolInstalled { $null }
            Mock Import-Module { } -ParameterFilter { $Name -eq 'BitsTransfer' }
            Mock Start-BitsTransfer {
                $bytes = [byte[]](0x50, 0x4B, 0x03, 0x04, 1, 2, 3, 4, 5, 6, 7, 8)
                [System.IO.File]::WriteAllBytes([string]$Destination[0], $bytes)
            }
            Mock Expand-Archive { }
            Mock Set-TreeOwnerToAdministrators { }
            Mock Set-ToolsFolderAcl { }
            function New-TestResolution {
                param($Sha, [string]$Source)
                [pscustomobject]@{
                    Key = 'hayabusa'; Name = 'Hayabusa'; Vendor = 'v'; License = 'GPL-3.0'; HomeUrl = 'h'; Summary = 's'
                    Version = 'v4.1.0'; AssetName = 'hayabusa-4.1.0-win-x64.zip'; DownloadUrl = 'https://github.com/x/y.zip'
                    SizeBytes = 12; SizeMB = 0; Arch = 'AMD64'; NeedsAdmin = $true; Published = ''
                    Sha256Expected = $Sha; Sha256Source = $Source; PinnedVersion = 'v4.1.0'; VersionMatchesPin = $true; IsLatest = $false
                }
            }
        }
        It 'refuses a download with no trusted hash and deletes it' {
            $r = Install-ExternalTool -Key 'hayabusa' -ConsentAccepted -Resolution (New-TestResolution -Sha $null -Source 'none')
            $r.Success | Should -BeFalse
            $r.Message | Should -Match 'No trusted hash'
            Should -Invoke Expand-Archive -Times 0 -Exactly
            Test-Path -LiteralPath (Join-Path (Get-ExternalToolInstallPath -Key 'hayabusa' -Version 'v4.1.0') 'hayabusa-4.1.0-win-x64.zip') | Should -BeFalse
        }
        It 'refuses a download whose hash does not match' {
            $r = Install-ExternalTool -Key 'hayabusa' -ConsentAccepted -Resolution (New-TestResolution -Sha ('00' * 32) -Source 'pinned')
            $r.Success | Should -BeFalse
            $r.Message | Should -Match 'MISMATCH'
            Should -Invoke Expand-Archive -Times 0 -Exactly
        }
        It 'refuses without consent' {
            (Install-ExternalTool -Key 'hayabusa').Success | Should -BeFalse
        }
    }

    Describe 'ASR rollback restores the prior state (regression lock)' {
        It 'removes only new rules and re-asserts each prior rule with its prior action' {
            $prior = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
            $other = '01443614-CD74-433A-B99E-2ECDC07BFC25'
            Mock Get-MpPreference {
                $p = New-Object W11SOTest.FakeMpPreference
                $p.AttackSurfaceReductionRules_Ids = [string[]]@('D4F940AB-401B-4EFC-AADC-AD5F3C50688A', '01443614-CD74-433A-B99E-2ECDC07BFC25')
                $p.AttackSurfaceReductionRules_Actions = [byte[]]@(2, 6)
                $p
            }
            Mock Add-MpPreference { }
            $script:Core.Rollback.Clear()
            & (Get-SecurityFixAction -Id 'DEF-ASR')
            $text = $script:Core.Rollback.ToArray() -join "`r`n"
            $text | Should -Not -Match ("Remove-MpPreference -AttackSurfaceReductionRules_Ids '{0}'" -f $prior)
            $text | Should -Match ("Remove-MpPreference -AttackSurfaceReductionRules_Ids 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'")
            $text | Should -Match ("Add-MpPreference -AttackSurfaceReductionRules_Ids '{0}' -AttackSurfaceReductionRules_Actions AuditMode" -f $prior)
            $text | Should -Match ("Add-MpPreference -AttackSurfaceReductionRules_Ids '{0}' -AttackSurfaceReductionRules_Actions Warn" -f $other)
            $script:Core.Rollback.Clear()
        }
    }
}
