<#
    TestHelpers.ps1
    Author: Ahmad Shaukat

    Shared setup for the Pester suite. Dot-source from BeforeAll.
    - Points LOCALAPPDATA and ProgramData at a temp folder.
    - Compiles fake event and user types. They are real .NET classes, not
      [pscustomobject], because PowerShell 7 answers .Count on a PSCustomObject
      under StrictMode and would hide the single-item bug class these tests guard.
    - Defines stub commands for Windows-only cmdlets when they are missing (Linux
      dev boxes), so Pester can mock them. On Windows the real cmdlets are mocked.
#>

$script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('w11so-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null
$env:LOCALAPPDATA = Join-Path $script:TestRoot 'local'
$env:ProgramData  = Join-Path $script:TestRoot 'programdata'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null
New-Item -ItemType Directory -Path $env:ProgramData -Force | Out-Null
Remove-Item Env:\W11SO_SESSION_LOG -ErrorAction SilentlyContinue

if (-not ('W11SOTest.FakeEvent' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace W11SOTest {
    public class FakeProp {
        public object Value { get; set; }
        public FakeProp(object v) { Value = v; }
    }
    public class FakeEvent {
        public DateTime TimeCreated { get; set; }
        public string Message { get; set; }
        public int Id { get; set; }
        public string Xml { get; set; }
        public List<FakeProp> Properties { get; set; }
        public FakeEvent() { TimeCreated = DateTime.Now; Message = ""; Xml = ""; Properties = new List<FakeProp>(); }
        public string ToXml() { return Xml; }
    }
    public class FakeSid {
        public string Value { get; set; }
        public FakeSid(string v) { Value = v; }
        public override string ToString() { return Value; }
    }
    public class FakeUser {
        public string Name { get; set; }
        public bool Enabled { get; set; }
        public object LastLogon { get; set; }
        public FakeSid SID { get; set; }
    }
}
'@
}

$stubs = @{
    'Get-WinEvent'          = 'param($FilterHashtable, $MaxEvents, $LogName, $ErrorAction)'
    'Get-LocalUser'         = 'param($Name, $SID, $ErrorAction)'
    'Get-LocalGroupMember'  = 'param($Group, $SID, $ErrorAction)'
    'Get-MpPreference'      = 'param($ErrorAction)'
    'Get-MpComputerStatus'  = 'param($ErrorAction)'
    'Get-ScheduledTask'     = 'param($ErrorAction)'
    'Get-CimInstance'       = 'param($ClassName, $Namespace, $Filter, $ErrorAction)'
    'Get-NetTCPConnection'  = 'param($State, $ErrorAction)'
    'Get-SmbShare'          = 'param($ErrorAction)'
    'Get-Acl'               = 'param($Path, $LiteralPath)'
    'Set-Acl'               = 'param($Path, $LiteralPath, $AclObject)'
    'Disable-LocalUser'     = 'param($Name, $SID, $ErrorAction)'
    'Get-AuthenticodeSignature' = 'param($FilePath, $LiteralPath)'
}
foreach ($k in $stubs.Keys) {
    if (-not (Get-Command $k -ErrorAction SilentlyContinue)) {
        Set-Item -Path ("Function:\global:{0}" -f $k) -Value ([scriptblock]::Create($stubs[$k] + ' throw "stub: not available on this platform"'))
    }
}

function New-TestEvent {
    param([int]$Id = 0, [string]$Message = '', [object[]]$Props = @(), [string]$Xml = '')
    $e = New-Object W11SOTest.FakeEvent
    $e.Id = $Id; $e.Message = $Message; $e.Xml = $Xml
    foreach ($p in $Props) { $e.Properties.Add((New-Object W11SOTest.FakeProp -ArgumentList (,$p))) }
    return $e
}

function New-TestUser {
    param([string]$Name, [bool]$Enabled = $true, [string]$Sid = 'S-1-5-21-1-2-3-1001')
    $u = New-Object W11SOTest.FakeUser
    $u.Name = $Name; $u.Enabled = $Enabled; $u.SID = New-Object W11SOTest.FakeSid -ArgumentList $Sid
    return $u
}

function New-ServiceInstallXml {
    param([string]$ServiceName, [string]$ImagePath)
    $n = [System.Security.SecurityElement]::Escape($ServiceName)
    $i = [System.Security.SecurityElement]::Escape($ImagePath)
    return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>7045</EventID></System><EventData><Data Name='ServiceName'>$n</Data><Data Name='ImagePath'>$i</Data><Data Name='ServiceType'>kernel mode driver</Data><Data Name='StartType'>demand start</Data><Data Name='AccountName'></Data></EventData></Event>"
}
