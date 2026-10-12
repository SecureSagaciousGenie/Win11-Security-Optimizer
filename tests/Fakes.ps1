<#
    Fakes.ps1
    Author: Ahmad Shaukat
    Compiled fake types and command stubs for the Pester suites.

    Fakes are C# classes, not [pscustomobject]. Under StrictMode, PowerShell 7
    answers .Count on a PSCustomObject, which would hide the single-hit .Count bug
    class these tests exist to catch. A compiled type has no Count member, so a
    scalar that slipped through unwrapped throws exactly as it does on 5.1.

    Stubs are defined only when the real command is missing (Linux or a trimmed
    Windows image) so Pester can Mock it. On Windows CI the real cmdlets are
    mocked instead.
#>

if (-not ('W11SOTest.FakeEvent' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace W11SOTest {
    public class FakeEventProperty {
        public object Value { get; set; }
        public FakeEventProperty(object value) { Value = value; }
    }
    public class FakeEvent {
        private string _xml;
        public int Id { get; set; }
        public string LogName { get; set; }
        public DateTime TimeCreated { get; set; }
        public string Message { get; set; }
        public List<FakeEventProperty> Properties { get; set; }
        public FakeEvent(string logName, int id, string message, string xml, object[] props) {
            LogName = logName; Id = id; Message = message; _xml = xml;
            TimeCreated = DateTime.Now.AddHours(-1);
            Properties = new List<FakeEventProperty>();
            if (props != null) { foreach (object p in props) { Properties.Add(new FakeEventProperty(p)); } }
        }
        public string ToXml() { return _xml; }
    }
    public class FakeSid {
        public string Value { get; set; }
        public FakeSid(string value) { Value = value; }
        public override string ToString() { return Value; }
    }
    public class FakeLocalUser {
        public string Name { get; set; }
        public bool Enabled { get; set; }
        public Nullable<DateTime> LastLogon { get; set; }
        public FakeSid SID { get; set; }
    }
    public class FakeGroupMember {
        public string Name { get; set; }
        public FakeSid SID { get; set; }
        public string ObjectClass { get; set; }
    }
    public class FakeMpPreference {
        public string[] ExclusionPath { get; set; }
        public string[] ExclusionProcess { get; set; }
        public string[] ExclusionExtension { get; set; }
        public string[] AttackSurfaceReductionRules_Ids { get; set; }
        public byte[] AttackSurfaceReductionRules_Actions { get; set; }
    }
}
'@
}

function New-FakeEvent {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int]$Id,
        [string]$Message = '',
        [string]$Xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData/></Event>',
        [object[]]$Properties = @()
    )
    return (New-Object W11SOTest.FakeEvent -ArgumentList $LogName, $Id, $Message, $Xml, $Properties)
}

function New-FakeUser {
    param([string]$Name, [bool]$Enabled = $true, [string]$Sid = 'S-1-5-21-1000-2000-3000-1001')
    $u = New-Object W11SOTest.FakeLocalUser
    $u.Name = $Name; $u.Enabled = $Enabled; $u.SID = (New-Object W11SOTest.FakeSid -ArgumentList $Sid)
    return $u
}

# ---- Stubs for Windows-only commands (only when missing) --------------------
$stubs = [ordered]@{
    'Get-WinEvent'            = '[CmdletBinding()] param([hashtable[]]$FilterHashtable, [long]$MaxEvents, [string[]]$LogName, [string[]]$ListLog, [switch]$Oldest)'
    'Get-LocalGroupMember'    = '[CmdletBinding()] param([Parameter(Position=0)][string]$Group, [string]$SID, [string]$Name, [string]$Member)'
    'Get-LocalUser'           = '[CmdletBinding()] param([Parameter(Position=0)][string[]]$Name, [object[]]$SID)'
    'Disable-LocalUser'       = '[CmdletBinding()] param([Parameter(Position=0)][string[]]$Name, [object[]]$SID, $InputObject)'
    'Enable-LocalUser'        = '[CmdletBinding()] param([Parameter(Position=0)][string[]]$Name, [object[]]$SID, $InputObject)'
    'Get-ScheduledTask'       = '[CmdletBinding()] param([string]$TaskName, [string]$TaskPath)'
    'Get-CimInstance'         = '[CmdletBinding()] param([Parameter(Position=0)][string]$ClassName, [string]$Namespace, [string]$Filter, [string]$Query)'
    'Get-NetTCPConnection'    = '[CmdletBinding()] param([string[]]$State, [int[]]$LocalPort)'
    'Get-SmbShare'            = '[CmdletBinding()] param([string[]]$Name)'
    'Get-MpPreference'        = '[CmdletBinding()] param()'
    'Set-MpPreference'        = '[CmdletBinding()] param([Parameter(ValueFromRemainingArguments)]$Rest)'
    'Add-MpPreference'        = '[CmdletBinding()] param([string[]]$AttackSurfaceReductionRules_Ids, [string[]]$AttackSurfaceReductionRules_Actions, [string[]]$ExclusionPath)'
    'Remove-MpPreference'     = '[CmdletBinding()] param([string[]]$AttackSurfaceReductionRules_Ids, [string[]]$ExclusionPath)'
    'Get-Acl'                 = '[CmdletBinding()] param([Parameter(Position=0)][string[]]$Path, [string[]]$LiteralPath)'
    'Set-Acl'                 = '[CmdletBinding()] param([Parameter(Position=0)][string[]]$Path, [string[]]$LiteralPath, $AclObject)'
    'Get-AuthenticodeSignature' = '[CmdletBinding()] param([Parameter(Position=0)][string[]]$FilePath, [string[]]$LiteralPath)'
    'Get-WindowsOptionalFeature' = '[CmdletBinding()] param([switch]$Online, [string]$FeatureName)'
    'Enable-WindowsOptionalFeature' = '[CmdletBinding()] param([switch]$Online, [string[]]$FeatureName, [switch]$All, [switch]$NoRestart)'
    'Disable-WindowsOptionalFeature' = '[CmdletBinding()] param([switch]$Online, [string[]]$FeatureName, [switch]$NoRestart)'
    'Get-SmbServerConfiguration' = '[CmdletBinding()] param()'
    'Get-SmbClientConfiguration' = '[CmdletBinding()] param()'
    'Set-SmbServerConfiguration' = '[CmdletBinding()] param([bool]$RequireSecuritySignature, [switch]$Force, [switch]$Confirm)'
    'Set-SmbClientConfiguration' = '[CmdletBinding()] param([bool]$RequireSecuritySignature, [switch]$Force, [switch]$Confirm)'
    'Start-BitsTransfer'      = '[CmdletBinding()] param([string[]]$Source, [string[]]$Destination)'
    'Start-MpScan'            = '[CmdletBinding()] param([string]$ScanType, [string]$ScanPath)'
    'Get-MpThreatDetection'   = '[CmdletBinding()] param()'
    'Get-NetFirewallProfile'  = '[CmdletBinding()] param([string[]]$Name, [string[]]$Profile)'
    'Get-NetUDPEndpoint'      = '[CmdletBinding()] param()'
    'Get-LocalGroup'          = '[CmdletBinding()] param([string[]]$Name, [object[]]$SID)'
    'Get-Service'             = '[CmdletBinding()] param([Parameter(Position=0)][string[]]$Name)'
    'Get-AppxPackage'         = '[CmdletBinding()] param([string]$Name, [switch]$AllUsers)'
}
foreach ($name in $stubs.Keys) {
    if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
        $body = $stubs[$name] + ' throw ("{0} is a test stub; mock it." -f $MyInvocation.MyCommand.Name)'
        Set-Item -Path ("function:global:{0}" -f $name) -Value ([scriptblock]::Create($body))
    }
}
