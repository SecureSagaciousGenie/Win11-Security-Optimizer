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
        It '<Name> has no -OnDone or -Next block that reads a local of its caller' -ForEach $script:SrcFiles {
            $parsed = Get-ScriptAst -Path $Path
            @(Get-DeferredBlockLocalViolation -Ast $parsed.Ast) | Should -BeNullOrEmpty
        }
        It '<Name> has no UI event handler that reads a local of the function that wired it' -ForEach $script:SrcFiles {
            $parsed = Get-ScriptAst -Path $Path
            @(Get-HandlerLocalViolation -Ast $parsed.Ast) | Should -BeNullOrEmpty
        }
        It '<Name> has no -Work block that reads a variable it was not given' -ForEach $script:SrcFiles {
            $parsed = Get-ScriptAst -Path $Path
            @(Get-WorkBlockVariableViolation -Ast $parsed.Ast) | Should -BeNullOrEmpty
        }
    }

    Context 'Background jobs' {
        BeforeAll {
            $script:OptAst = (Get-ScriptAst -Path (Join-Path (Get-RepoRoot) 'src\Optimizer.ps1')).Ast
            function Get-OptFunction {
                param([string]$Name)
                return $script:OptAst.Find({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and $n.Name -eq $Name }, $true)
            }
        }
        # Only one background job runs at a time, so a second Start-* call in a
        # row is dropped by the busy guard. Full Scan must chain them instead.
        It 'Start-FullScan starts one scan directly and chains the rest' {
            $fn = Get-OptFunction 'Start-FullScan'
            $starts = @($fn.Body.FindAll({ param($n) ($n -is [System.Management.Automation.Language.CommandAst]) -and ($n.GetCommandName() -match '^Start-.+Scan$') }, $true))
            @($starts | ForEach-Object { $_.GetCommandName() }) | Should -Be @('Start-SecurityScan', 'Start-BloatScan', 'Start-DfirScan', 'Start-StartupScan')
            $direct = @($starts | Where-Object {
                $p = $_.Parent; $nested = $false
                while ($p -and $p -ne $fn.Body) { if ($p -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $nested = $true }; $p = $p.Parent }
                -not $nested
            })
            $direct.Count | Should -Be 1
        }
        # A scriptblock stays bound to the runspace that created it; run on the
        # background thread it would use the UI runspace from two threads.
        It 'Invoke-Background hands the work to the runspace as text' {
            $fn = Get-OptFunction 'Invoke-Background'
            $sets = @($fn.Body.FindAll({ param($n) ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and $n.Member.Extent.Text -eq 'SetVariable' }, $true))
            $sets.Count | Should -BeGreaterThan 0
            $passed = @($sets | ForEach-Object { $_.Arguments[1].Extent.Text })
            @($passed | Where-Object { $_ -in @('$Work', '$OnDone', '$Next') }) | Should -BeNullOrEmpty
            $passed | Should -Contain '$Work.ToString()'
        }
        It 'every -Work block calls only functions the background runspace loads' {
            $root = Get-RepoRoot
            $coreFns = @(@((Join-Path $root 'src\SecurityCore.ps1')) + @(Get-ChildItem -LiteralPath (Join-Path $root 'src\features') -Filter *.ps1 | ForEach-Object { $_.FullName }) | ForEach-Object {
                (Get-ScriptAst -Path $_).Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name }
            })
            $uiFns = @($script:OptAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
            $calls = @($script:OptAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.CommandAst]) -and $n.GetCommandName() -eq 'Invoke-Background' }, $true))
            $calls.Count | Should -BeGreaterThan 5
            $bad = foreach ($c in $calls) {
                $els = $c.CommandElements
                for ($i = 0; $i -lt $els.Count - 1; $i++) {
                    if (($els[$i] -is [System.Management.Automation.Language.CommandParameterAst]) -and $els[$i].ParameterName -eq 'Work') {
                        foreach ($cmd in @($els[$i + 1].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))) {
                            $name = $cmd.GetCommandName()
                            if ($name -and ($uiFns -contains $name) -and ($coreFns -notcontains $name)) { '{0} (line {1})' -f $name, $cmd.Extent.StartLineNumber }
                        }
                    }
                }
            }
            @($bad) | Should -BeNullOrEmpty
        }
        # The self-test drives every action; a direct modal would block it.
        It 'every message box and Save dialog goes through the self-test aware wrappers' {
            $direct = @($script:OptAst.FindAll({ param($n)
                (($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and ($n.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) -and
                 ($n.Expression.TypeName.FullName -eq 'System.Windows.MessageBox')) -or
                (($n -is [System.Management.Automation.Language.CommandAst]) -and $n.GetCommandName() -eq 'New-Object' -and $n.Extent.Text -match 'SaveFileDialog|OpenFileDialog')
            }, $true) | Where-Object {
                $p = $_.Parent
                while ($p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $p = $p.Parent }
                -not ($p -and $p.Name -in @('Show-AppMessage', 'Select-SaveFilePath'))
            } | ForEach-Object { 'line {0}: {1}' -f $_.Extent.StartLineNumber, $_.Extent.Text.Substring(0, [Math]::Min(60, $_.Extent.Text.Length)) })
            $direct | Should -BeNullOrEmpty
        }
        It '<_> forwards -Next to Invoke-Background' -ForEach @('Start-SecurityScan', 'Start-BloatScan', 'Start-DfirScan', 'Start-StartupScan') {
            $fn = Get-OptFunction $_
            @($fn.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) | Should -Contain 'Next'
            $call = $fn.Body.Find({ param($n) ($n -is [System.Management.Automation.Language.CommandAst]) -and $n.GetCommandName() -eq 'Invoke-Background' }, $true)
            $call.Extent.Text | Should -Match '-Next \$Next\b'
        }
    }

    Context 'XAML' {
        It 'finds the XAML strings in Optimizer.ps1' {
            @($script:XamlCases).Count | Should -BeGreaterThan 0
        }
        It '<Name> (line <Line>) is well-formed XML' -ForEach $script:XamlCases {
            { [xml]$Xaml } | Should -Not -Throw
        }
        It 'every element New-OptimizerWindow looks up exists in the main window XAML' {
            $parsed = Get-ScriptAst -Path (Join-Path (Get-RepoRoot) 'src\Optimizer.ps1')
            $fn = $parsed.Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-OptimizerWindow' }, $true)
            $assign = $fn.Find({ param($n) ($n -is [System.Management.Automation.Language.AssignmentStatementAst]) -and ($n.Left.Extent.Text -eq '$names') }, $true)
            $wanted = @($assign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
            $wanted.Count | Should -BeGreaterThan 10
            $main = @(Get-XamlStringFromScript -Path (Join-Path (Get-RepoRoot) 'src\Optimizer.ps1') | Where-Object { $_.Name -eq 'script:Xaml' })[0].Xaml
            $defined = @([regex]::Matches($main, 'x:Name="([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
            @($wanted | Where-Object { $defined -notcontains $_ }) | Should -BeNullOrEmpty
        }
        It '<Name> (line <Line>) loads with XamlReader' -ForEach $script:XamlCases -Skip:(-not $script:OnWindows) {
            Invoke-XamlLoad -Xaml $Xaml | Should -Not -BeNullOrEmpty
        }
    }
}
