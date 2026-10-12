<#
    TestHelpers.ps1
    Author: Ahmad Shaukat
    Shared helpers for the Pester suites. Pure AST and file helpers; nothing here
    touches the system.
#>

function Get-RepoRoot {
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-ScriptAst {
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    return [pscustomobject]@{ Ast = $ast; Errors = @($errors) }
}

function Get-UnwrappedCountViolation {
    <# For each $x.Count, the last plain assignment to $x before it in the same
       function must not be a bare pipeline of two or more commands. Such a
       pipeline returns a scalar for one hit, and .Count on a scalar throws
       under StrictMode 2.0 in Windows PowerShell 5.1. #>
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast)
    $out = New-Object System.Collections.ArrayList
    $countRefs = @($Ast.FindAll({
        param($n)
        ($n -is [System.Management.Automation.Language.MemberExpressionAst]) -and
        ($n.Expression -is [System.Management.Automation.Language.VariableExpressionAst]) -and
        ($n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
        ($n.Member.Value -eq 'Count')
    }, $true))
    foreach ($ref in $countRefs) {
        $name = $ref.Expression.VariablePath.UserPath
        $scope = $ref.Parent
        while ($scope -and -not ($scope -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $scope = $scope.Parent }
        if (-not $scope) { $scope = $Ast }
        $assigns = @($scope.FindAll({
            param($n)
            ($n -is [System.Management.Automation.Language.AssignmentStatementAst]) -and
            ($n.Operator -eq [System.Management.Automation.Language.TokenKind]::Equals) -and
            ($n.Left -is [System.Management.Automation.Language.VariableExpressionAst]) -and
            ($n.Left.VariablePath.UserPath -eq $name)
        }, $true) | Where-Object { $_.Extent.EndOffset -le $ref.Extent.StartOffset })
        if ($assigns.Count -eq 0) { continue }
        $last = @($assigns | Sort-Object { $_.Extent.EndOffset })[-1]
        $right = $last.Right
        if ($right -is [System.Management.Automation.Language.PipelineAst] -and @($right.PipelineElements).Count -ge 2) {
            [void]$out.Add(('{0}:{1} ${2}.Count follows an unwrapped pipeline assignment at line {3}' -f $ref.Extent.File, $ref.Extent.StartLineNumber, $name, $last.Extent.StartLineNumber))
        }
    }
    return @($out.ToArray())
}

function Get-XamlStringFromScript {
    <# String constants assigned to variables whose names end in Xaml. Read from
       the AST so the GUI script is never executed. #>
    param([Parameter(Mandatory)][string]$Path)
    $parsed = Get-ScriptAst -Path $Path
    $assigns = @($parsed.Ast.FindAll({
        param($n)
        ($n -is [System.Management.Automation.Language.AssignmentStatementAst]) -and
        ($n.Left -is [System.Management.Automation.Language.VariableExpressionAst]) -and
        ($n.Left.VariablePath.UserPath -match 'Xaml$')
    }, $true))
    $out = New-Object System.Collections.ArrayList
    foreach ($a in $assigns) {
        $consts = @($a.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true))
        foreach ($c in $consts) {
            if ($c.Value -match '<Window') {
                [void]$out.Add([pscustomobject]@{ Name = $a.Left.VariablePath.UserPath; Line = $a.Extent.StartLineNumber; Xaml = $c.Value })
            }
        }
    }
    return @($out.ToArray())
}
