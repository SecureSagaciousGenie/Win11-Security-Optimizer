<#
    Static.Tests.ps1
    Author: Ahmad Shaukat
    Parse, XAML and AST checks. Nothing here runs the GUI: Optimizer.ps1 starts
    the window when executed, so its XAML is read from the AST instead.
#>

BeforeDiscovery {
    $script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Test-Path variable:IsWindows) -and $IsWindows)
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $root = Get-RepoRoot
    $script:SrcFiles = @(Get-ChildItem -Path (Join-Path $root 'src') -Recurse -Filter *.ps1 | ForEach-Object {
        @{ Name = $_.FullName.Substring($root.Length + 1); Path = $_.FullName }
    })
    $script:XamlCases = @(Get-XamlStringFromScript -Path (Join-Path $root 'src\Optimizer.ps1') | ForEach-Object {
        @{ Name = $_.Name; Line = $_.Line; Xaml = $_.Xaml }
    })
}

Describe 'Static checks' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        function Invoke-XamlLoad {
            <# XamlReader needs an STA thread. Load in a fresh STA runspace so the
               result does not depend on how the host was started. Parse only;
               the window is never shown. #>
            param([string]$Xaml)
            $rs = [runspacefactory]::CreateRunspace()
            $rs.ApartmentState = 'STA'
            $rs.Open()
            try {
                $ps = [powershell]::Create()
                $ps.Runspace = $rs
                [void]$ps.AddScript({
                    param($x)
                    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
                    $reader = New-Object System.Xml.XmlNodeReader ([xml]$x)
                    $obj = [Windows.Markup.XamlReader]::Load($reader)
                    $obj.GetType().FullName
                }).AddArgument($Xaml)
                $out = $ps.Invoke()
                if ($ps.HadErrors) { throw ($ps.Streams.Error | Select-Object -First 1).Exception }
                return [string]($out | Select-Object -First 1)
            } finally { $rs.Close(); $rs.Dispose() }
        }
    }

    Context 'Parsing' {
        It '<Name> parses with zero errors' -ForEach $script:SrcFiles {
            $parsed = Get-ScriptAst -Path $Path
            @($parsed.Errors | ForEach-Object { '{0}: {1}' -f $_.Extent.StartLineNumber, $_.Message }) | Should -BeNullOrEmpty
        }
    }

    Context 'Unwrapped pipeline .Count' {
        It '<Name> has no $x.Count after an unwrapped multi-command pipeline assignment' -ForEach $script:SrcFiles {
            $parsed = Get-ScriptAst -Path $Path
            @(Get-UnwrappedCountViolation -Ast $parsed.Ast) | Should -BeNullOrEmpty
        }
    }

    Context 'Closures' {
        It '<Name> uses no $script: variable inside a GetNewClosure block' -ForEach $script:SrcFiles {
            $parsed = Get-ScriptAst -Path $Path
            @(Get-ScriptScopeInClosureViolation -Ast $parsed.Ast) | Should -BeNullOrEmpty
        }
    }

    Context 'XAML' {
        It 'finds the XAML strings in Optimizer.ps1' {
            @($script:XamlCases).Count | Should -BeGreaterThan 0
        }
        It '<Name> (line <Line>) is well-formed XML' -ForEach $script:XamlCases {
            { [xml]$Xaml } | Should -Not -Throw
        }
        It '<Name> (line <Line>) loads with XamlReader' -ForEach $script:XamlCases -Skip:(-not $script:OnWindows) {
            Invoke-XamlLoad -Xaml $Xaml | Should -Not -BeNullOrEmpty
        }
    }
}
