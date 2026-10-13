<#
    EventGuidance.Tests.ps1
    Author: Ahmad Shaukat
    Hayabusa and Chainsaw cards must say what the matched Windows event is,
    show the real event details and give concrete search terms.
#>

Describe 'Event guidance' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestSetup.ps1')
        function Write-Utf8NoBom { param([string]$Path, [string]$Text) [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false))) }
        $script:Bar = [string][char]0x00A6
    }
    AfterAll { Restore-TestEnvironment }
    BeforeEach { Set-StrictMode -Version 2.0 }

    Context 'Get-EventGuidance' {
        It 'knows a Defender detection by its full channel name and by the Hayabusa abbreviation' {
            foreach ($ch in @('Microsoft-Windows-Windows Defender/Operational', 'Defender')) {
                $g = Get-EventGuidance -Channel $ch -EventId '1116'
                $g.Known | Should -BeTrue
                $g.What | Should -Match 'detected'
                $g.Do | Should -Match 'Protection history'
            }
        }
        It 'knows a cleared Security log as Sec 1102' {
            $g = Get-EventGuidance -Channel 'Sec' -EventId '1102'
            $g.Known | Should -BeTrue
            $g.What | Should -Match 'cleared'
            $g.Channel | Should -Be 'Security'
        }
        It 'falls back to the channel and event ID for an unknown event' {
            $g = Get-EventGuidance -Channel 'Microsoft-Windows-Example/Operational' -EventId '42'
            $g.Known | Should -BeFalse
            $g.Channel | Should -Be 'Microsoft-Windows-Example/Operational'
            $g.EventId | Should -Be '42'
            Format-MatchSummary -Tool 'Hayabusa' -Count 3 -Guidance $g | Should -Match 'Hayabusa matched this rule 3 time\(s\), on Microsoft-Windows-Example/Operational event 42\.'
        }
    }

    Context 'ConvertFrom-HayabusaDetail' {
        It 'splits Hayabusa details into fields' {
            $d = ConvertFrom-HayabusaDetail -Text ("Threat: Trojan:Win32/Wacatac.B!ml {0} Severity: Severe {0} Path: file:_C:\Users\a b\x.exe" -f $script:Bar)
            $d['Threat'] | Should -Be 'Trojan:Win32/Wacatac.B!ml'
            $d['Severity'] | Should -Be 'Severe'
            $d['Path'] | Should -Be 'file:_C:\Users\a b\x.exe'
        }
        It 'copes with a separator read in the wrong code page and with an empty value' {
            $d = ConvertFrom-HayabusaDetail -Text ("Threat: X " + [char]0x00C2 + [char]0x00A6 + " User: PC\me")
            $d['User'] | Should -Be 'PC\me'
            @((ConvertFrom-HayabusaDetail -Text '-').Keys).Count | Should -Be 0
        }
    }

    Context 'Hayabusa cards' {
        BeforeAll {
            $script:BadFile = Join-Path $TestDrive 'invoice.exe'
            Set-Content -LiteralPath $script:BadFile -Value 'x'
            $details = "Threat: Trojan:Win32/Wacatac.B!ml {0} Severity: Severe {0} Type: Trojan {0} User: PC-01\ahmad {0} Path: file:_{1} {0} Proc: C:\Windows\explorer.exe" -f $script:Bar, $script:BadFile
            $csv = @(
                '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"',
                ('"2026-10-10 09:15:02.123 +05:00","Defender Alert (Severe)","crit","PC-01","Defender","1116","5501","{0}","Detection ID: 1","rule-def-1"' -f $details),
                ('"2026-10-10 09:16:40.000 +05:00","Defender Alert (Severe)","crit","PC-01","Defender","1116","5502","{0}","Detection ID: 2","rule-def-1"' -f $details),
                ('"2026-10-11 22:01:00.000 +05:00","Log Cleared","high","PC-01","Sec","1102","9001","User: ahmad","-","rule-clr-1"')
            ) -join "`r`n"
            $script:Csv = Join-Path $TestDrive 'hayabusa.csv'
            Write-Utf8NoBom -Path $script:Csv -Text $csv
            $script:Cards = @(ConvertFrom-HayabusaCsv -CsvPath $script:Csv)
            $script:Def = @($script:Cards | Where-Object { $_.Title -eq '[crit] Defender Alert (Severe)' })[0]
        }
        It 'says which Windows event the rule matched and what it means' {
            $script:Def.What | Should -Match '2 time'
            $script:Def.What | Should -Match 'Defender detected'
            $script:Def.What | Should -Match '1116'
        }
        It 'shows the real event details as evidence' {
            $script:Def.Evidence | Should -Match 'PC-01'
            $script:Def.Evidence | Should -Match ([regex]::Escape('Threat: Trojan:Win32/Wacatac.B!ml'))
            $script:Def.Evidence | Should -Match 'invoice\.exe'
            $script:Def.Evidence | Should -Match 'rule-def-1'
        }
        It 'gives concrete next steps and search terms' {
            $script:Def.WhatToDo | Should -Match 'Protection history'
            $script:Def.WhatToDo | Should -Match ([regex]::Escape('"Trojan:Win32/Wacatac.B!ml"'))
            $script:Def.WhatToDo | Should -Match '"invoice\.exe"'
        }
        It 'turns a file that still exists into card paths' {
            @($script:Def.Paths) | Should -Contain $script:BadFile
        }
        It 'explains the cleared log from the abbreviated channel' {
            $clr = @($script:Cards | Where-Object { $_.Title -eq '[high] Log Cleared' })[0]
            $clr.What | Should -Match 'cleared'
            $clr.Evidence | Should -Match 'Security event 1102'
        }
    }

    Context 'Chainsaw cards' {
        BeforeAll {
            $items = @(
                [pscustomobject]@{ name = 'Security Audit Logs Cleared'; level = 'critical'; timestamp = '2026-10-11T22:01:00Z'; group = 'Sigma'; kind = 'individual'
                    document = [pscustomobject]@{ kind = 'evtx'; data = [pscustomobject]@{ Event = [pscustomobject]@{
                        System = [pscustomobject]@{ Channel = 'Security'; EventID = 1102; Computer = 'PC-01' }
                        UserData = [pscustomobject]@{ LogFileCleared = [pscustomobject]@{ SubjectUserName = 'ahmad'; SubjectDomainName = 'PC-01' } } } } } },
                [pscustomobject]@{ name = 'Defender Threat Detected'; level = 'high'; timestamp = '2026-10-10T04:15:02Z'
                    document = [pscustomobject]@{ kind = 'evtx'; data = [pscustomobject]@{ Event = [pscustomobject]@{
                        System = [pscustomobject]@{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; EventID = 1116; Computer = 'PC-01' }
                        EventData = [pscustomobject]@{ 'Threat Name' = 'HackTool:Win64/Mimikatz'; 'Severity Name' = 'High'; Path = 'file:_C:\Tools\m.exe'; 'Process Name' = 'C:\Windows\explorer.exe' } } } } }
            )
            $script:Json = Join-Path $TestDrive 'chainsaw.json'
            Set-Content -LiteralPath $script:Json -Value (ConvertTo-Json -InputObject $items -Depth 8)
            $script:CsCards = @(ConvertFrom-ChainsawJson -JsonPath $script:Json -MinLevel 'low')
        }
        It 'shows the computer, the event and its fields' {
            $c = @($script:CsCards | Where-Object { $_.Title -like '*Security Audit Logs Cleared' })[0]
            $c.Evidence | Should -Match 'PC-01'
            $c.Evidence | Should -Match 'Security event 1102'
            $c.Evidence | Should -Match 'SubjectUserName=ahmad'
            $c.What | Should -Match 'cleared'
        }
        It 'searches for the Defender threat name' {
            $c = @($script:CsCards | Where-Object { $_.Title -like '*Defender Threat Detected' })[0]
            $c.WhatToDo | Should -Match ([regex]::Escape('"HackTool:Win64/Mimikatz"'))
            $c.Evidence | Should -Match 'Threat Name=HackTool:Win64/Mimikatz'
        }
    }
}
