# PSScriptAnalyzerSettings.psd1
# Author: Ahmad Shaukat
# CI fails on Error severity. Warnings are reported but do not fail the build.
# Write-Host is used on purpose by the launcher, rollback scripts and self-test.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @('PSAvoidUsingWriteHost')
}
