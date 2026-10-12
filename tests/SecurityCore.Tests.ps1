<#
    SecurityCore.Tests.ps1
    Author: Ahmad Shaukat

    Regression suite for src/SecurityCore.ps1. Every case here encodes a bug that
    shipped once. Run: Invoke-Pester -Path tests
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot '..\src\SecurityCore.ps1')
    Mock Test-IsAdmin { $false }
    Initialize-Core | Out-Null
}

Describe 'Event-log triage reports single events (StrictMode .Count)' {
    BeforeAll {
        Mock Get-WinEvent {
            $ids = @($FilterHashtable.Id)
            if ($ids -contains 7045) { return (New-TestEvent -Id 7045 -Xml (New-ServiceInstallXml -ServiceName 'EvilSvc' -ImagePath 'C:\Users\Public\evil.exe')) }
            if ($ids -contains 4740) { return (New-TestEvent -Id 4740 -Message 'locked') }
            if ($ids -contains 1116) { return (New-TestEvent -Id 1116 -Message 'Name: Trojan:Win32/Test') }
            if ($ids -contains 4698) { return (New-TestEvent -Id 4698 -Message 'Task Name: \Evil') }
            if ($ids -contains 4624) { return (New-TestEvent -Id 4624 -Props @('a','b','c','d','e','f','g','h',[uint32]10,'j')) }
            $ex = New-Object System.Exception 'No events were found that match the specified selection criteria.'
            throw (New-Object System.Management.Automation.ErrorRecord $ex, 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', 'ObjectNotFound', $null)
        }
        $script:evt = @(Invoke-EventLogTriage)
    }
    It 'reports one new service' { @($script:evt | Where-Object Id -eq 'EVT-NEWSVC').Count | Should -Be 1 }
    It 'reports one lockout' { @($script:evt | Where-Object Id -eq 'EVT-LOCKOUT').Count | Should -Be 1 }
    It 'reports one Defender detection' { (@($script:evt | Where-Object Id -eq 'EVT-DEFENDER'))[0].Status | Should -Be 'Review' }
    It 'reports one task creation' { (@($script:evt | Where-Object Id -eq 'EVT-TASK'))[0].Status | Should -Be 'Review' }
    It 'reports one RDP logon from the structured field' { @($script:evt | Where-Object Id -eq 'EVT-RDPLOGON').Count | Should -Be 1 }
    It 'does not claim the Security log needs admin when it was simply empty' { @($script:evt | Where-Object Id -eq 'EVT-DENIED').Count | Should -Be 0 }
    It 'produces no error cards' { @($script:evt | Where-Object { $_.Id -like '*-ERR' }).Count | Should -Be 0 }
}

Describe 'Compromise triage: hidden users and Defender exclusions' {
    It 'flags exactly one hidden account' {
        Mock Get-LocalUser { @((New-TestUser -Name 'Admin'), (New-TestUser -Name 'support$' -Sid 'S-1-5-21-1-2-3-1002')) }
        $f = @(Invoke-DfirTriage)
        @($f | Where-Object Id -eq 'DFIR-HIDDENUSER').Count | Should -Be 1
        (@($f | Where-Object Id -eq 'DFIR-USERS'))[0].Title | Should -Match ': 2$'
    }
    It 'reports <n> Defender exclusion(s) correctly' -ForEach @(
        @{ n = 0; title = 'No Defender exclusions set' }
        @{ n = 1; title = 'has 1 exclusion' }
        @{ n = 2; title = 'has 2 exclusion' }
    ) {
        $script:n = $n
        Mock Get-MpPreference { [pscustomobject]@{ ExclusionPath = @(1..3 | Select-Object -First $script:n | ForEach-Object { "C:\x$_" }); ExclusionProcess = $null; ExclusionExtension = $null } }
        $f = @(Invoke-DfirTriage)
        (@($f | Where-Object Id -eq 'DFIR-DEFEXCL'))[0].Title | Should -Match $title
    }
}

Describe 'Rollback script cannot be injected' {
    BeforeEach {
        $script:Core.Rollback.Clear()
        Mock Test-IsAdmin { $true }
        Mock New-SystemRestorePointOnce { $true }
        Mock New-ItemProperty { }
        Mock Remove-ItemProperty { }
        Mock New-Item { }
    }
    It 'keeps a <label> inert' -ForEach @(
        @{ label = 'ASCII quote';            name = 'Updater';                                   value = "C:\x.exe'; Start-Process calc.exe; '" }
        @{ label = 'curly quote U+2019';     name = 'Updater';                                   value = ("C:\x.exe{0}; Start-Process calc.exe; {0}" -f [char]0x2019) }
        @{ label = 'CR/LF in the value name'; name = "Updater`r`nStart-Process calc.exe`r`n#"; value = 'C:\Users\Public\u.exe' }
    ) {
        $script:v = $value
        Mock Get-RegValue { $script:v }
        $r = Set-StartupItemState -Type RegistryRun -Location 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $name -Enable $false
        $r.Success | Should -BeTrue
        $text = Get-Content -LiteralPath $script:Core.RollbackFile -Raw
        $tok = $null; $err = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tok, [ref]$err)
        @($err).Count | Should -Be 0
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        $cmds | Should -Not -Contain 'Start-Process'
    }
}

Describe 'Defender definition-driver filter' {
    BeforeAll {
        $script:savedPD = $env:ProgramData
        $env:ProgramData = 'C:\ProgramData'
        $script:pfx = 'C:\ProgramData\Microsoft\Windows Defender\Definition Updates\'
    }
    AfterAll { $env:ProgramData = $script:savedPD }
    It 'accepts the genuine driver path' { Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ($script:pfx + '{0A1B2C3D-0000-0000-0000-000000000000}\MpKslDrv.sys') | Should -BeTrue }
    It 'accepts the NT-prefixed genuine path' { Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ('\??\' + $script:pfx + '{0A1B2C3D}\MpKslDrv.sys') | Should -BeTrue }
    It 'rejects an evil exe with the trusted path as an argument' { Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ('C:\Users\Public\evil.exe "' + $script:pfx + 'x"') | Should -BeFalse }
    It 'rejects .. traversal out of the tree' { Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ($script:pfx + '..\..\..\..\Users\Public\MpKslDrv.sys') | Should -BeFalse }
    It 'rejects forward-slash traversal' { Test-IsDefenderDefinitionDriver -ServiceName 'MpKsl1a2b3c4d' -ImagePath ($script:pfx + 'x/../../../../Users/Public\MpKslDrv.sys') | Should -BeFalse }
    It 'rejects a non-MpKsl service name' { Test-IsDefenderDefinitionDriver -ServiceName 'Windows Defender Update' -ImagePath ($script:pfx + '{0A1B2C3D}\MpKslDrv.sys') | Should -BeFalse }
}

Describe 'Pinned release resolution' {
    It 'uses the pinned hash for the pinned tag, the GitHub digest otherwise and none when absent' -ForEach @(
        @{ tag = 'v2.16.5'; digest = 'sha256:' + ('ab' * 32); want = 'pinned' }
        @{ tag = 'v2.16.6'; digest = 'sha256:' + ('ab' * 32); want = 'github-digest' }
        @{ tag = 'v2.16.6'; digest = $null;                    want = 'none' }
    ) {
        $script:tag = $tag; $script:dg = $digest
        Mock Invoke-RestMethod {
            $asset = [pscustomobject]@{ name = 'chainsaw_all_platforms+rules.zip'; browser_download_url = 'https://example.invalid/x.zip'; size = 1048576; digest = $script:dg }
            [pscustomobject]@{ tag_name = $script:tag; published_at = '2026-01-01'; assets = @($asset) }
        }
        (Resolve-ExternalToolRelease -Key 'chainsaw' -UseLatest).Sha256Source | Should -Be $want
    }
}

Describe 'Secure-base writes and read-only runspaces' {
    It 'Save-RollbackArtifacts re-owns files written inside the secure base' {
        Mock Set-ItemOwnerAdministrators { }
        $secure = Join-Path (Join-Path $env:ProgramData 'Win11SecurityOptimizer') 'backups'
        New-Item -ItemType Directory -Path $secure -Force | Out-Null
        $savedR = $script:Core.RollbackFile; $savedB = $script:Core.BackupFile
        try {
            $script:Core.RollbackFile = Join-Path $secure 'Rollback_test.ps1'
            $script:Core.BackupFile   = Join-Path $secure 'Backup_test.json'
            $script:Core.Rollback.Clear(); [void]$script:Core.Rollback.Add('# x')
            Save-RollbackArtifacts
            Should -Invoke Set-ItemOwnerAdministrators -Times 2 -Exactly
        } finally { $script:Core.RollbackFile = $savedR; $script:Core.BackupFile = $savedB }
    }
    It 'Save-RollbackArtifacts does not re-own files in the user profile' {
        Mock Set-ItemOwnerAdministrators { }
        $script:Core.Rollback.Clear(); [void]$script:Core.Rollback.Add('# x')
        Save-RollbackArtifacts
        Should -Invoke Set-ItemOwnerAdministrators -Times 0 -Exactly
    }
    It 'writes a single backup record as a JSON array' {
        $script:Core.Backups.Clear()
        [void]$script:Core.Backups.Add([pscustomobject]@{ Kind = 'Registry'; Path = 'HKLM:\x'; Name = 'y' })
        $script:Core.Rollback.Clear(); [void]$script:Core.Rollback.Add('# x')
        Save-RollbackArtifacts
        (Get-Content -LiteralPath $script:Core.BackupFile -Raw).Trim() | Should -Match '^\['
    }
    It 'Initialize-Core -ReadOnly never secures, locks or re-owns' {
        Mock Test-IsAdmin { $true }
        Mock Initialize-SecureBase { throw 'must not be called' }
        Mock Set-ToolsFolderAcl { throw 'must not be called' }
        Mock Set-TreeOwnerToAdministrators { throw 'must not be called' }
        Mock Test-FolderOwnedBySystemOrAdmins { $true }
        Initialize-Core -ReadOnly | Out-Null
        Should -Invoke Initialize-SecureBase -Times 0 -Exactly
        Should -Invoke Set-ToolsFolderAcl -Times 0 -Exactly
        Should -Invoke Set-TreeOwnerToAdministrators -Times 0 -Exactly
    }
    It 'Initialize-SecureBase quarantines an untrusted base instead of deleting it' {
        Mock Test-IsAdmin { $true }
        Mock Set-ToolsFolderAcl { }
        $base = Join-Path $env:ProgramData 'Win11SecurityOptimizer'
        New-Item -ItemType Directory -Path (Join-Path $base 'backups') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $base 'backups\planted.ps1') -Value 'x'
        Mock Test-FolderOwnedBySystemOrAdmins { param($Path) -not ($Path -like '*planted*') }
        $null = Initialize-SecureBase
        $moved = @(Get-ChildItem -LiteralPath $env:ProgramData -Directory | Where-Object Name -like 'Win11SecurityOptimizer.untrusted-*')
        $moved.Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $moved[0].FullName 'backups\planted.ps1') | Should -BeTrue
        $script:Core.SecureSetupNotice | Should -Match 'untrusted'
    }
}

Describe 'Locale-safe identities' {
    It 'finds Guest by RID 501, not by name' {
        Mock Get-LocalUser { @((New-TestUser -Name 'Admin'), (New-TestUser -Name 'Invite' -Enabled $false -Sid 'S-1-5-21-11-22-33-501')) }
        (Get-GuestAccount).Name | Should -Be 'Invite'
    }
    It 'parses net localgroup output in any language' {
        $lines = @('Nom alias     Administrateurs', 'Commentaire   x', '', 'Membres', '', '-------------------------------------------------------------------------------', 'Administrateur', 'alice', 'La commande s''est termine correctement.')
        $m = @(ConvertFrom-NetLocalGroupOutput -Lines $lines)
        $m.Count | Should -Be 2
        $m[1].Name | Should -Be 'alice'
    }
    It 'treats RID 500 and the current user as expected admins by SID' {
        $me = [System.Security.Principal.WindowsIdentity]
        Mock Get-LocalAdminMembers { @([pscustomobject]@{ Name = 'PC\Administrateur'; Sid = 'S-1-5-21-1-2-3-500' }, [pscustomobject]@{ Name = 'PC\mallory'; Sid = 'S-1-5-21-1-2-3-1099' }) }
        $f = @(Invoke-DfirTriage | Where-Object Id -eq 'DFIR-ADMIN')
        $f[0].WhatToDo | Should -Match 'mallory'
        $f[0].WhatToDo | Should -Not -Match 'Administrateur,'
    }
}
