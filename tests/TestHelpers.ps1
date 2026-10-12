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
        # "$x = if (...) { @(...) } else { ... }" unrolls the branch output: one
        # item becomes a scalar and none becomes $null. This crashed the Alert
        # filter chip in v1.2.0.
        if ($right -is [System.Management.Automation.Language.IfStatementAst] -or $right -is [System.Management.Automation.Language.SwitchStatementAst]) {
            [void]$out.Add(('{0}:{1} ${2}.Count follows an unwrapped if/switch assignment at line {3}' -f $ref.Extent.File, $ref.Extent.StartLineNumber, $name, $last.Extent.StartLineNumber))
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

function Get-FeatureFileList {
    <# The string constants in SecurityCore's $script:FeatureFiles list, in order. #>
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast)
    $assign = $Ast.Find({
        param($n)
        ($n -is [System.Management.Automation.Language.AssignmentStatementAst]) -and
        ($n.Left -is [System.Management.Automation.Language.VariableExpressionAst]) -and
        ($n.Left.VariablePath.UserPath -eq 'script:FeatureFiles')
    }, $true)
    if (-not $assign) { return @() }
    return @($assign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
}

function Get-ScriptScopeInClosureViolation {
    <# A scriptblock turned into a closure with .GetNewClosure() runs in its own
       dynamic module, so $script: inside it reads $null and writes are lost.
       Returns one line per $script: variable used inside such a block. #>
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast)
    $out = New-Object System.Collections.ArrayList
    $calls = @($Ast.FindAll({
        param($n)
        ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
        ($n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
        ($n.Member.Value -eq 'GetNewClosure')
    }, $true))
    foreach ($c in $calls) {
        $vars = @($c.Expression.FindAll({ param($n) ($n -is [System.Management.Automation.Language.VariableExpressionAst]) -and $n.VariablePath.IsScript }, $true))
        foreach ($v in $vars) { [void]$out.Add(('{0}:{1} {2} inside a GetNewClosure block' -f $v.Extent.File, $v.Extent.StartLineNumber, $v.Extent.Text)) }
    }
    return @($out.ToArray())
}

function Get-DeferredBlockLocalViolation {
    <# The -OnDone and -Next blocks of Invoke-Background run later, from the
       dispatcher timer, after the calling function has returned. A variable
       they read that is a local or parameter of that function no longer exists
       then, and reading it throws under StrictMode. This is how Pro Tools lost
       every result in v1.2.0 ($tool and $Key inside OnDone).
       Returns one line per such variable. #>
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast)
    $L = 'System.Management.Automation.Language'
    $auto = @('_', 'PSItem', 'true', 'false', 'null', 'args', 'input', 'this', 'Matches', 'LASTEXITCODE', 'PSScriptRoot', 'PSVersionTable', 'ErrorActionPreference', 'PWD', 'HOME', 'Host', 'ExecutionContext', 'MyInvocation', 'PSBoundParameters', 'PSCmdlet', 'Error', '?')
    $out = New-Object System.Collections.ArrayList
    $calls = @($Ast.FindAll({ param($n) ($n -is [System.Management.Automation.Language.CommandAst]) -and $n.GetCommandName() -eq 'Invoke-Background' }, $true))
    foreach ($c in $calls) {
        $fn = $c.Parent
        while ($fn -and -not ($fn -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $fn = $fn.Parent }
        if (-not $fn) { continue }
        $fnLocals = @{}
        foreach ($a in @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))) {
            $lv = $a.Left
            if ($lv -is [System.Management.Automation.Language.ConvertExpressionAst]) { $lv = $lv.Child }
            if ($lv -is [System.Management.Automation.Language.VariableExpressionAst] -and -not $lv.VariablePath.IsScript -and -not $lv.VariablePath.IsGlobal) { $fnLocals[$lv.VariablePath.UserPath] = $true }
        }
        foreach ($p in @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true))) { $fnLocals[$p.Name.VariablePath.UserPath] = $true }
        if ($fn.Parameters) { foreach ($p in @($fn.Parameters)) { $fnLocals[$p.Name.VariablePath.UserPath] = $true } }
        $els = $c.CommandElements
        for ($i = 0; $i -lt $els.Count - 1; $i++) {
            if (-not (($els[$i] -is [System.Management.Automation.Language.CommandParameterAst]) -and ($els[$i].ParameterName -in @('OnDone', 'Next')))) { continue }
            if (-not ($els[$i + 1] -is [System.Management.Automation.Language.ScriptBlockExpressionAst])) { continue }
            $sb = $els[$i + 1].ScriptBlock
            $own = @{}
            foreach ($a in @($sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))) {
                $lv = $a.Left
                if ($lv -is [System.Management.Automation.Language.ConvertExpressionAst]) { $lv = $lv.Child }
                if ($lv -is [System.Management.Automation.Language.VariableExpressionAst]) { $own[$lv.VariablePath.UserPath] = $true }
            }
            foreach ($fe in @($sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true))) { $own[$fe.Variable.VariablePath.UserPath] = $true }
            foreach ($p in @($sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true))) { $own[$p.Name.VariablePath.UserPath] = $true }
            foreach ($v in @($sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) {
                $vp = $v.VariablePath
                if ($vp.IsScript -or $vp.IsGlobal -or $vp.DriveName) { continue }
                $n = $vp.UserPath
                if (($auto -contains $n) -or $own.ContainsKey($n)) { continue }
                if ($fnLocals.ContainsKey($n)) {
                    [void]$out.Add(('{0}:{1} -{2} block of {3} reads ${4}, a local of the caller that is gone when the block runs' -f $v.Extent.File, $v.Extent.StartLineNumber, $els[$i].ParameterName, $fn.Name, $n))
                }
            }
        }
    }
    return @($out.ToArray())
}

function Get-HandlerLocalViolation {
    <# A UI event handler ({ ... } passed to Add_Click, Add_Checked, AddHandler
       and so on) runs when the user acts, long after the function that wired it
       has returned, unless that same function is still inside ShowDialog. A
       local of the wiring function read from such a handler throws under
       StrictMode. Closures made with GetNewClosure() capture locals and are
       fine. Returns one line per violation. #>
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast)
    $auto = @('_', 'PSItem', 'true', 'false', 'null', 'args', 'input', 'this', 'Matches', 'LASTEXITCODE', 'PSScriptRoot', 'PSVersionTable', 'ErrorActionPreference', 'PWD', 'HOME', 'Host', 'ExecutionContext', 'MyInvocation', 'PSBoundParameters', 'PSCmdlet', 'Error', '?')
    $out = New-Object System.Collections.ArrayList
    $wires = @($Ast.FindAll({ param($n) ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and (($n.Member.Extent.Text -like 'Add_*') -or ($n.Member.Extent.Text -eq 'AddHandler')) }, $true))
    foreach ($m in $wires) {
        $fn = $m.Parent
        while ($fn -and -not ($fn -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $fn = $fn.Parent }
        if (-not $fn) { continue }
        $sync = [bool]($fn.Body.Find({ param($n) ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and $n.Member.Extent.Text -eq 'ShowDialog' }, $true))
        if ($sync) { continue }
        $locals = @{}
        foreach ($a in @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))) {
            $lv = $a.Left
            if ($lv -is [System.Management.Automation.Language.ConvertExpressionAst]) { $lv = $lv.Child }
            if ($lv -is [System.Management.Automation.Language.VariableExpressionAst] -and -not $lv.VariablePath.IsScript -and -not $lv.VariablePath.IsGlobal) { $locals[$lv.VariablePath.UserPath] = $true }
        }
        foreach ($p in @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true))) { $locals[$p.Name.VariablePath.UserPath] = $true }
        foreach ($fe in @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true))) { $locals[$fe.Variable.VariablePath.UserPath] = $true }
        foreach ($arg in @($m.Arguments)) {
            if ($arg.Extent.Text -match 'GetNewClosure\(\)\s*\)?\s*$') { continue }
            $sbe = $arg.Find({ param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true)
            if (-not $sbe) { continue }
            $sb = $sbe.ScriptBlock
            $own = @{}
            foreach ($a in @($sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))) {
                $lv = $a.Left
                if ($lv -is [System.Management.Automation.Language.ConvertExpressionAst]) { $lv = $lv.Child }
                if ($lv -is [System.Management.Automation.Language.VariableExpressionAst]) { $own[$lv.VariablePath.UserPath] = $true }
            }
            foreach ($p in @($sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true))) { $own[$p.Name.VariablePath.UserPath] = $true }
            foreach ($fe in @($sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true))) { $own[$fe.Variable.VariablePath.UserPath] = $true }
            foreach ($v in @($sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) {
                $vp = $v.VariablePath
                if ($vp.IsScript -or $vp.IsGlobal -or $vp.DriveName) { continue }
                $n = $vp.UserPath
                if (($auto -contains $n) -or $own.ContainsKey($n)) { continue }
                if ($locals.ContainsKey($n)) {
                    [void]$out.Add(('{0}:{1} {2} handler wired in {3} reads ${4}, a local that is gone when the event fires' -f $v.Extent.File, $v.Extent.StartLineNumber, $m.Member.Extent.Text, $fn.Name, $n))
                }
            }
        }
    }
    return @($out.ToArray())
}
