# PSScriptAnalyzer settings for Win11-Security-Optimizer
# Author: Ahmad Shaukat
# CI fails on Error severity only. Write-Host is used deliberately in the
# self-test and the generated rollback script.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        'PSAvoidUsingEmptyCatchBlock'
    )
}
