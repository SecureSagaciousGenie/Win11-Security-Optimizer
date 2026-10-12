<#
    Static.Tests.ps1
    Author: Ahmad Shaukat

    Checks that need no Windows APIs: parsing, encoding, author headers, the
    StrictMode .Count rule and (on Windows only) that every XAML window loads.
#>

BeforeDiscovery {
    $root = Split-Path $PSScriptRoot -Parent
    $script:Scripts = @(Get-ChildItem -Path (Join-Path $root 'src') -Filter *.ps1 -Recurse | ForEach-Object { @{ Path = $_.FullName; Name = $_.Name } })
    $script:IsWin = ([System.Environment]::OSVersion.Platform -eq 'Win32NT')
}

BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    function Get-Ast {
        param([string]$Path)
        $t = $null; $e = $null
        $a = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$t, [ref]$e)
        return @{ Ast = $a; Errors = @($e) }
    }
}

Describe 'Source file <Name>' -ForEach $script:Scripts {
    It 'parses with no errors' {
        (Get-Ast $Path).Errors.Count | Should -Be 0
    }
    It 'is pure ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
    It 'names Ahmad Shaukat as author in its header' {
        $head = (Get-Content -LiteralPath $Path -TotalCount 25) -join "`n"
        $head | Should -Match 'Author:\s+Ahmad Shaukat'
    }
    It 'never reads .Count on an unwrapped multi-command pipeline' {
        $ast = (Get-Ast $Path).Ast
        $bad = @()
        $members = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Member.Extent.Text -eq 'Count' -and $n.Expression -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
        foreach ($m in $members) {
            $name = $m.Expression.VariablePath.UserPath
            $fn = $m; while ($fn -and -not ($fn -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $fn = $fn.Parent }
            if (-not $fn) { continue }
            $assigns = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq ('$' + $name) -and $n.Extent.StartOffset -lt $m.Extent.StartOffset }, $true))
            if ($assigns.Count -eq 0) { continue }
            $last = $assigns | Sort-Object { $_.Extent.StartOffset } | Select-Object -Last 1
            if ($last.Operator -ne 'Equals') { continue }
            $right = $last.Right
            if ($right -is [System.Management.Automation.Language.PipelineAst] -and $right.PipelineElements.Count -gt 1) {
                $bad += ('L{0}: ${1}.Count' -f $m.Extent.StartLineNumber, $name)
            }
        }
        $bad | Should -BeNullOrEmpty
    }
}

Describe 'GUI XAML' -Skip:(-not $script:IsWin) {
    It 'every XAML string in Optimizer.ps1 loads' {
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
        $files = @(Get-ChildItem -Path (Join-Path $script:root 'src') -Filter *.ps1 -Recurse)
        $loaded = 0
        foreach ($f in $files) {
            $ast = (Get-Ast $f.FullName).Ast
            $assign = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -match 'Xaml$' }, $true)
            foreach ($a in $assign) {
                $str = $a.Right.Find({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
                if (-not $str) { continue }
                $reader = New-Object System.Xml.XmlNodeReader ([xml]$str.Value)
                $w = [Windows.Markup.XamlReader]::Load($reader)
                $w | Should -Not -BeNullOrEmpty
                $loaded++
            }
        }
        $loaded | Should -BeGreaterThan 1
    }
}
