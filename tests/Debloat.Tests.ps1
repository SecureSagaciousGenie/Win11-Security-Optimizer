<#
    Debloat.Tests.ps1
    Author: Ahmad Shaukat
    Tests for the debloat catalog: impact, risk notes and presets.
#>

Describe 'Debloat catalog' {
    BeforeAll { . (Join-Path $PSScriptRoot 'TestSetup.ps1') }
    AfterAll { Restore-TestEnvironment }
    BeforeEach { Set-StrictMode -Version 2.0 }

    It 'gives every entry an impact, a one-line risk note and a reinstall route' {
        foreach ($e in @(Get-DebloatCatalog)) {
            $e.Impact | Should -BeIn @('Low', 'Medium', 'High')
            $e.Risk | Should -Not -BeNullOrEmpty
            $e.Risk | Should -Not -Match "`n"
            $e.ReinstallNote | Should -Not -BeNullOrEmpty
        }
    }
    It 'keeps Minimal inside Recommended and Low impact only' {
        $cat = @(Get-DebloatCatalog)
        $rec = @($cat | Where-Object { Test-DebloatPreset -Entry $_ -Preset 'Recommended' })
        $min = @($cat | Where-Object { Test-DebloatPreset -Entry $_ -Preset 'Minimal' })
        $min.Count | Should -BeGreaterThan 0
        $min.Count | Should -BeLessThan $rec.Count
        foreach ($m in $min) { $rec.Key | Should -Contain $m.Key; $m.Impact | Should -Be 'Low' }
        @($rec | ForEach-Object { $_.Recommended } | Where-Object { -not $_ }).Count | Should -Be 0
    }
    It 'passes impact and risk through the inventory' {
        Mock Get-AppxPackage { [pscustomobject]@{ Name = 'Microsoft.BingNews'; PackageFullName = 'Microsoft.BingNews_1.0_x64'; PackageFamilyName = 'Microsoft.BingNews_8wekyb3d8bbwe'; Version = '1.0' } }
        $inv = @(Get-DebloatInventory)
        $inv.Count | Should -Be 1
        $inv[0].Impact | Should -Be 'Low'
        $inv[0].Risk | Should -Match 'news'
    }
}
