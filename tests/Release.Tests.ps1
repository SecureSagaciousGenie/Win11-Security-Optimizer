<#
    Release.Tests.ps1
    Author: Ahmad Shaukat
    Release checks: version, the README fix table and licensing table, the
    project documents and the release workflow.
#>

Describe 'Release' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestSetup.ps1')
        $script:Root = Get-RepoRoot
        function Read-RepoText {
            param([Parameter(Mandatory)][string]$Relative)
            $p = Join-Path $script:Root $Relative
            if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw ("Missing file: {0}" -f $Relative) }
            return [System.IO.File]::ReadAllText($p)
        }
        function Get-BuiltInFixId {
            <# The quoted Ids of the switch in Get-SecurityFixAction, read from the AST. #>
            $ast = (Get-ScriptAst -Path (Join-Path $script:Root 'src\SecurityCore.ps1')).Ast
            $fn = $ast.Find({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and $n.Name -eq 'Get-SecurityFixAction' }, $true)
            $sw = $fn.Body.Find({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)
            return @($sw.Clauses | ForEach-Object { [string]$_.Item1.Value })
        }
        $script:Readme = Read-RepoText 'README.md'
    }
    AfterAll { Restore-TestEnvironment }
    BeforeEach { Set-StrictMode -Version 2.0 }

    It 'is version 1.2.0' {
        $script:Core.Version | Should -Be '1.2.0'
    }
    It 'documents every fix in the README fix table' {
        $ids = @(Get-BuiltInFixId) + @($script:ExtraFixActions.Keys)
        $ids.Count | Should -BeGreaterThan 20
        $missing = @($ids | Where-Object { $script:Readme -notmatch ('\|\s*`{0}`\s*\|' -f [regex]::Escape($_)) })
        $missing | Should -BeNullOrEmpty
    }
    It 'has the licensing table rows' {
        $rows = @(
            '| Hayabusa, Chainsaw | GPL-3.0 | downloaded at runtime |',
            '| Autoruns, standalone Sysmon | Sysinternals license | downloaded at runtime, never redistributed |',
            '| Built-in Sysmon | Windows feature | enabled, not downloaded |',
            '| sysmon-modular config | MIT | bundled with notice |',
            '| Sigma rules | DRL 1.1 | via Hayabusa and Chainsaw |'
        )
        foreach ($r in $rows) { $script:Readme.Contains($r) | Should -BeTrue -Because $r }
    }
    It 'has the CI badge, a screenshots section and script-signing steps' {
        $script:Readme | Should -Match ([regex]::Escape('actions/workflows/ci.yml/badge.svg'))
        $script:Readme | Should -Match '(?m)^## Screenshots'
        $script:Readme | Should -Match '(?m)^## .*[Ss]igning'
        $script:Readme | Should -Match 'Set-AuthenticodeSignature'
    }
    It 'has a changelog entry for this version and a security policy' {
        (Read-RepoText 'CHANGELOG.md') | Should -Match ('(?m)^## \[{0}\]' -f [regex]::Escape($script:Core.Version))
        (Read-RepoText 'SECURITY.md') | Should -Match '(?m)^## Reporting a vulnerability'
    }
    It 'names Sigma and its DRL 1.1 license in the third-party notices' {
        (Read-RepoText 'THIRD-PARTY-NOTICES.md') | Should -Match 'Detection Rule License \(DRL\) 1\.1'
    }
    It 'keeps em-dashes out of <file>' -ForEach @(
        @{ file = 'README.md' }, @{ file = 'CHANGELOG.md' }, @{ file = 'SECURITY.md' },
        @{ file = 'THIRD-PARTY-NOTICES.md' }, @{ file = 'docs\REINSTALL.md' }
    ) {
        (Read-RepoText $file).Contains([string][char]0x2014) | Should -BeFalse
    }
    It 'puts the author line in <file>' -ForEach @(
        @{ file = 'CHANGELOG.md' }, @{ file = 'SECURITY.md' }, @{ file = '.github\workflows\release.yml' }, @{ file = 'tests\Release.Tests.ps1' }
    ) {
        (Read-RepoText $file) | Should -Match 'Author: Ahmad Shaukat'
    }
    It 'releases on v* tags with the zip and SHA256SUMS.txt, gated on the tests' {
        $y = Read-RepoText '.github\workflows\release.yml'
        $y | Should -Match "(?m)^\s+tags:\s*\r?\n\s+- 'v\*'"
        $y | Should -Match 'SHA256SUMS\.txt'
        $y | Should -Match 'git archive --format=zip'
        $y | Should -Match 'sha256sum -c SHA256SUMS\.txt'
        $y | Should -Match 'uses: \./\.github/workflows/ci\.yml'
        $y | Should -Match 'contents: write'
        (Read-RepoText '.github\workflows\ci.yml') | Should -Match '(?m)^\s+workflow_call:'
    }
}
