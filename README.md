# Windows 11 Security Optimizer

[![CI](https://github.com/SecureSagaciousGenie/Win11-Security-Optimizer/actions/workflows/ci.yml/badge.svg)](https://github.com/SecureSagaciousGenie/Win11-Security-Optimizer/actions/workflows/ci.yml)

Author: Ahmad Shaukat

A free, open-source tool that hardens a Windows 11 PC, checks it for signs of
compromise and removes bloat, all from one window. No installer. Download,
double-click **`Start.bat`** and it runs on the Windows PowerShell 5.1 that ships
with Windows.

> **Nothing changes until you tick a box and confirm.** Before the first change
> the tool creates a System Restore point and starts a rollback script, so every
> change can be undone.

---

## Features

**Harden**
- Audits Defender, firewall, SmartScreen, UAC, SMBv1, LLMNR, AutoRun, RDP,
  Secure Boot, TPM, BitLocker and more. Each finding has a risk tier and a fix.
- Credential-theft hardening: LSA protection, WDigest, PowerShell 2.0, NetBIOS
  and mDNS name resolution, SMB signing, Credential Guard and patch age.
- Opt-in continuous logging with Sysmon: enables the built-in Windows feature or
  installs MS Sysmon with a bundled, pinned sysmon-modular config.
- Every fix is backed up, verified after it runs and safe to apply twice.

**Investigate**
- Plain-English compromise checks: hidden or extra admins, backdoor accounts,
  startup persistence, exposed remote access, risky ports and shares, Defender
  exclusions and hosts-file tampering.
- Deep Scan: masquerading processes, programs running from Temp or AppData,
  suspicious command lines and event-log triage.
- Pro Tools (opt-in, downloaded on demand): Hayabusa and Chainsaw event-log hunts
  with a minimum level, and Sysinternals Autoruns for every autostart location.
- Baseline and drift: save a known-good snapshot and see what is new since.
- Card actions: Scan with Defender, Open location and Copy details. Filter by
  Alert, Review, Info or Clean.

**Report and respond**
- One self-contained HTML report, safe to open anywhere.
- Evidence pack: event logs, processes with hashes and signers, TCP connections,
  a snapshot and the findings, zipped with a SHA-256 manifest.
- Headless scan for scripts and RMM tools, with exit codes.

**Clean up**
- Debloat with an impact level, a one-line risk note and a reinstall route per
  app, plus Recommended and Minimal presets.
- Startup manager with publisher and signature status; disabling is reversible.

---

## Quick start

1. Download the latest release zip and `SHA256SUMS.txt` from
   [Releases](https://github.com/SecureSagaciousGenie/Win11-Security-Optimizer/releases)
   and check the hash (see [Verifying a release](#verifying-a-release)).
2. Extract it, keeping `Start.bat` next to the `src` folder.
3. Double-click **`Start.bat`** and accept the admin prompt. Scanning works
   without admin; applying fixes does not.
4. Click **Run Full Scan**.

> **Why a `.bat` and not an `.exe`?** An unsigned `.exe` from the internet is
> flagged by SmartScreen and often quarantined. `Start.bat` runs the same tool
> with the built-in PowerShell, so there is nothing to quarantine and every line
> is readable. Maintainers with a code-signing certificate can build a signed
> `.exe` with `Build-Exe.ps1`.

## Requirements

- Windows 11 (Windows 10 works).
- Windows PowerShell 5.1, built into Windows.
- Administrator rights to apply changes. `Start.bat` asks for them.

The core tool needs no internet connection and sends nothing to the project.
Outbound traffic happens only for features you opt into:
- **Cloud-delivered protection** (`DEF-CLOUD`) turns on Defender's own cloud
  lookups and safe-sample submission to MS.
- **Update signatures** (`DEF-SIG`) asks Defender to fetch new definitions.
- **Pro Tools** download Hayabusa and Chainsaw from GitHub, or Autoruns from
  Sysinternals, after a consent screen.
- **Sysmon** downloads standalone Sysmon from Sysinternals only when Windows
  has no built-in Sysmon feature.

---

## Safety: how every change is protected

1. **Read-only by default.** Scans only read. Nothing changes until you confirm.
2. **Restore point first.** Created before the first change in a session.
3. **Backup before every change.** The previous value is saved to a JSON backup.
4. **Rollback script.** Each change adds its own undo step to `Rollback_*.ps1`.
5. **Verify after apply.** Each fix is read back to confirm it took effect.
6. **Idempotent.** A fix that is already in place changes nothing and adds no
   rollback step.
7. **Admin-owned data.** Everything that runs elevated lives in a folder only
   Administrators and SYSTEM can write. Ownership is checked before every use.
   A folder that fails the check is moved aside, never trusted and never deleted.
8. **Verified downloads.** Hayabusa and Chainsaw must match a pinned or
   GitHub-published SHA-256. Autoruns and Sysmon must carry a valid MS signature.
   Both checks run again before every run. Anything that fails is refused.

### Where your data lives

```
%ProgramData%\Win11SecurityOptimizer\     Administrators and SYSTEM write, Users read
  backups\     Backup_*.json, Rollback_*.ps1
  baselines\   baseline.json, baseline.prev.json
  tools\       downloaded Pro Tools, Autoruns and Sysmon
  sysmon\      verified copy of the bundled Sysmon config
  evidence\    staging for evidence packs (deleted after zipping)

%LOCALAPPDATA%\Win11SecurityOptimizer\
  logs\        session_*.log (read-only record, never executed)
```

Reports and evidence packs are saved where you choose (Documents by default).

### To undo changes

Run the rollback script shown in the **Restore & Logs** tab from an elevated
PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\Win11SecurityOptimizer\backups\Rollback_<timestamp>.ps1"
```

Or open it and run only the steps you want to undo. The System Restore point
rolls back the whole machine.

---

## Fixes

Each fix has a risk tier:

- **Safe:** widely recommended, low risk.
- **Elevated:** standard hardening that may affect some setups.
- **High-risk:** can break things. Hidden unless you tick **Include high-risk
  fixes**.
- **Audit-only:** reported, never changed (Secure Boot, TPM, BitLocker, Tamper
  Protection, Credential Guard and patch age).

**Apply Recommended Fixes** applies Safe and Elevated items, and High-risk only
when ticked. Its confirm dialog groups every change by tier. Sysmon is never
part of a bulk apply.

"Rollback" below means the step the tool writes to `Rollback_*.ps1`. For a
registry value it restores the previous value, or deletes the value when it did
not exist before.

| ID | Tier | What it changes | How to undo |
|---|---|---|---|
| `DEF-RTP` | Safe | Turns Defender real-time protection on. | Rollback turns it off again. |
| `DEF-CLOUD` | Safe | Defender MAPS reporting to Advanced and sample submission to SendSafeSamples. | Rollback sets MAPS to Disabled and restores the previous sample setting. |
| `DEF-PUA` | Safe | Turns on blocking of potentially unwanted apps. | Rollback disables it. |
| `DEF-SIG` | Safe | Asks Defender to download new definitions. | Nothing to undo; definitions update on their own anyway. |
| `DEF-ASR` | Elevated | Adds eight ASR rules in Block mode, merged into existing rules (Office child processes, obfuscated scripts, LSASS credential theft, vulnerable drivers, WMI persistence and more). | Rollback removes the rules it added and restores every earlier rule's action. |
| `FW-Domain` | Safe | Turns the Domain firewall profile on. | Rollback turns it off. |
| `FW-Private` | Safe | Turns the Private firewall profile on. | Rollback turns it off. |
| `FW-Public` | Safe | Turns the Public firewall profile on. | Rollback turns it off. |
| `SS-EXPLORER` | Safe | `HKLM\...\CurrentVersion\Explorer` `SmartScreenEnabled` = `Warn`. | Rollback restores the value. |
| `UAC-ENABLE` | Safe | `HKLM\...\Policies\System` `EnableLUA` = 1. Restart needed. | Rollback restores the value. |
| `UAC-CONSENT` | Safe | `ConsentPromptBehaviorAdmin` = 5 (prompt for consent for non-Windows binaries). | Rollback restores the value. |
| `UAC-SECUREDESK` | Safe | `PromptOnSecureDesktop` = 1. | Rollback restores the value. |
| `SMB1` | Elevated | Disables the SMB1Protocol optional feature. Restart may be needed. | Rollback re-enables the feature. |
| `LLMNR` | Elevated | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` `EnableMulticast` = 0. | Rollback restores the value. |
| `AUTORUN` | Safe | `HKLM\...\Policies\Explorer` `NoDriveTypeAutoRun` = 255 (AutoRun off for all drives). | Rollback restores the value. |
| `ACCT-GUEST` | Safe | Disables the built-in Guest account (RID 501). | Rollback re-enables it by SID. |
| `WU-SVC` | Safe | Sets a disabled Windows Update service to Manual. | Rollback sets it back to Disabled. |
| `HVCI` | High-risk | Memory integrity: `HKLM\SYSTEM\...\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` `Enabled` = 1. Restart needed; old drivers can fail to load. | Rollback restores the value, then restart. |
| `RDP-ENABLED` | High-risk | Turns Remote Desktop off: `fDenyTSConnections` = 1. | Rollback restores the value. |
| `RDP-NLA` | Elevated | Requires Network Level Authentication for RDP: `UserAuthentication` = 1. | Rollback restores the value. |
| `LSA-PPL` | High-risk | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `RunAsPPL` = 2 (no UEFI lock). Build 22621 or later only. Restart needed; some LSA plug-ins stop loading. | Rollback restores the value, then restart. |
| `WDIGEST` | Safe | `...\SecurityProviders\WDigest` `UseLogonCredential` = 0, so no plain-text passwords in memory. | Rollback restores the value. |
| `PSV2` | Elevated | Disables the Windows PowerShell 2.0 optional feature. | Rollback re-enables the feature. |
| `NBTNS` | Elevated | `NetbiosOptions` = 2 on every `NetBT\Parameters\Interfaces\Tcpip_{GUID}` key. | Rollback restores each interface's value. |
| `MDNS` | Elevated | `HKLM\SYSTEM\...\Dnscache\Parameters` `EnableMDNS` = 0. Casting and printer discovery may stop. | Rollback restores the value. |
| `SMB-SIGN` | Elevated | Requires SMB signing on the server side, the client side or both (only the side that needs it). | Rollback sets that side back to not required. |
| `SYSMON` | High-risk | Enables the built-in Sysmon feature or installs MS Sysmon, with the bundled config and a 512 MB log. Installs a driver and a service. | Rollback uninstalls Sysmon (after re-checking its hash), restores the log size and turns the feature off if the tool turned it on. |

Other changes: **Debloat** removals are undone from the MS Store (see
[docs/REINSTALL.md](docs/REINSTALL.md)). **Startup** toggles move or rename the
entry and can be switched back on in the same tab.

---

## Investigate

Written for someone who is not a security expert. Each card says what was found,
why it matters and what to do. Cards sort by status, then severity.

- **Built-in checks:** extra or hidden admins, enabled local accounts (including
  names ending in `$`), startup persistence, RDP, risky listening ports and
  shares, Defender exclusions and hosts-file redirects.
- **Deep Scan:** processes masquerading as Windows files, programs running from
  Temp, AppData or Downloads, unsigned programs on the network, encoded
  PowerShell and download cradles, shadow-copy deletion, cleared logs, new
  services, new admins and logon brute force.
- **Pro Tools:** Hayabusa and Chainsaw hunt the event logs with Sigma rules.
  Autoruns lists every autostart location and flags non-MS entries in image
  hijack, AppInit, Known DLLs, LSA, boot execute, Winlogon and WMI. Each tool is
  downloaded only after a consent screen that names its author, license, source
  and size. See [docs/DFIR-TOOLS.md](docs/DFIR-TOOLS.md).
- **Baseline and drift:** **Save as baseline** stores a snapshot. **Compare with
  baseline** shows new admins, users, services, tasks, autostarts, Defender
  exclusions, WMI subscriptions, ports, hosts entries and ASR or firewall changes.
- **Sysmon:** a card shows whether Sysmon runs and how many days of evidence
  its log holds.

This is triage, not a forensic suite. When in doubt, investigate before you
delete anything.

## Debloat

Only apps that are actually installed are listed. Each row shows:

- **Impact:** Low, Medium or High, for how much you might miss it.
- **If removed:** one line on what stops working.
- **Reinstall route** in the confirm dialog, which lists every app before
  anything is removed.

**Preset: Recommended** ticks the apps most people never use. **Preset: Minimal**
ticks only the Low-impact ones among them. Removal uninstalls the app for your
account and removes the provisioned copy, so new accounts do not get it. Work or
school Teams is not affected.
Every app is reinstallable; see [docs/REINSTALL.md](docs/REINSTALL.md).

## Reports, evidence and headless scans

- **Save report** (Restore & Logs tab) writes one HTML file with the score,
  findings, cards, drift, Pro Tools results, the changes made this session and
  the installed tool versions with their SHA-256. It has no scripts and no
  external resources. It contains user names and file paths, so share it with
  care.
- **Evidence pack** (admin) exports the Security, System, Application, Defender,
  PowerShell, Task Scheduler and Sysmon logs, a snapshot, processes, TCP
  connections and the findings. `manifest.json` records the SHA-256 of every
  file, the machine, the operator and the UTC time.
- **Headless scan:**

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Scan.ps1 -OutJson C:\Temp\scan.json [-Deep]
  ```

  Read-only. Exit code 0 clean, 1 something to review, 2 an alert, 3 the scan
  failed. Suits Action1, Intune or any RMM that reads exit codes.

---

## Licensing

This project is MIT. It ships no third-party program.

| Component | License | How it ships |
|---|---|---|
| Hayabusa, Chainsaw | GPL-3.0 | downloaded at runtime |
| Autoruns, standalone Sysmon | Sysinternals license | downloaded at runtime, never redistributed |
| Built-in Sysmon | Windows feature | enabled, not downloaded |
| sysmon-modular config | MIT | bundled with notice |
| Sigma rules | DRL 1.1 | via Hayabusa and Chainsaw |

Full attribution and the reasons behind each choice:
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Screenshots

<!-- Maintainer: save PNGs under docs/screenshots/ and uncomment the lines below. -->
<!-- ![Dashboard](docs/screenshots/dashboard.png) -->
<!-- ![Security fixes](docs/screenshots/security.png) -->
<!-- ![Investigate cards](docs/screenshots/investigate.png) -->
<!-- ![Pro Tools](docs/screenshots/pro-tools.png) -->
<!-- ![Debloat presets](docs/screenshots/debloat.png) -->
<!-- ![HTML report](docs/screenshots/report.png) -->

_Screenshots will be added by the maintainer._

---

## Verifying a release

Each release has a zip and `SHA256SUMS.txt`, built by the release workflow from
the tagged commit. Check the zip before extracting it:

```powershell
$expected = (Get-Content .\SHA256SUMS.txt).Split(' ')[0]
$actual = (Get-FileHash .\Win11-Security-Optimizer-v1.2.0.zip -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw 'Hash mismatch. Do not use this zip.' }
```

## Script signing (maintainers)

Releases are not signed automatically; signing needs your own certificate and is
done by hand. Signed scripts help where an execution policy is set by Group
Policy (`AllSigned` or `RemoteSigned`), because Group Policy overrides the
`-ExecutionPolicy Bypass` that `Start.bat` passes.

1. Get an Authenticode code-signing certificate: a public CA for wide use, or an
   enterprise CA for in-house use. Its root must be trusted on target machines,
   and the publisher must be in Trusted Publishers to run without a prompt.
2. Download the release zip, verify its hash and extract it.
3. Sign every script from an elevated or certificate-owning session:

   ```powershell
   $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
   if (-not $cert) { throw 'No code-signing certificate found.' }
   $files = @(Get-ChildItem -LiteralPath .\src -Recurse -Filter *.ps1) + @(Get-Item -LiteralPath .\Build-Exe.ps1)
   foreach ($f in $files) {
       $r = Set-AuthenticodeSignature -LiteralPath $f.FullName -Certificate $cert -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.digicert.com'
       if ($r.Status -ne 'Valid') { throw ("{0}: {1}" -f $f.Name, $r.StatusMessage) }
   }
   ```

4. Check the result:

   ```powershell
   Get-ChildItem -LiteralPath .\src -Recurse -Filter *.ps1 | Get-AuthenticodeSignature | Where-Object Status -ne 'Valid'
   ```

   No output means every script is signed and valid.
5. Zip the signed folder, write a new SHA-256 for it and attach both to the
   release under a distinct name such as `-signed.zip`.

Notes:
- A signature covers the exact bytes. Any later edit, including a line-ending
  change, breaks it. Sign last.
- Do not edit or re-encode `config/sysmon/sysmonconfig.xml`. It is pinned by
  SHA-256 and the tool refuses a changed copy.
- `Start.bat` cannot carry a signature. Under `AllSigned`, users run
  `src\Optimizer.ps1` from an elevated PowerShell with `-STA`.
- The rollback script is written on each machine, so it is unsigned. Under
  `AllSigned`, sign it with the same certificate before running it, or paste its
  commands into an elevated PowerShell.
- To sign the `.exe` from `Build-Exe.ps1`, use the same command on
  `dist\Windows11SecurityOptimizer.exe`.

---

## Project layout

```
Start.bat                    double-click this
Build-Exe.ps1                optional: build an .exe (maintainers)
src\Optimizer.ps1            the GUI
src\SecurityCore.ps1         scan, harden, debloat, DFIR, downloads, rollback
src\Scan.ps1                 headless scan
src\features\                Autoruns, baseline, hardening, Sysmon, report, evidence
config\sysmon\               bundled sysmon-modular config (MIT, pinned)
docs\                        REINSTALL.md, DFIR-TOOLS.md
tests\                       Pester tests and fixtures
.github\workflows\           CI, integration on a real Windows runner, release
```

## Development

```powershell
Invoke-Pester -Path .\tests -Output Detailed          # Pester 5.5 or later
.\tests\Invoke-Analyzer.ps1                            # PSScriptAnalyzer, fails on errors
powershell -NoProfile -ExecutionPolicy Bypass -STA -File .\src\Optimizer.ps1 -SelfTest
```

The self-test renders the window, loads the Pro Tools dialogs, runs the
read-only engines, prints `SELFTEST_OK` and exits. CI runs Pester and the
analyzer on Windows PowerShell 5.1. The integration workflow applies real fixes,
downloads and rollbacks on an elevated Windows runner.

## FAQ

**Does scanning change anything?** No. Scans only read.

**Can I use it without admin?** Yes, for scanning and investigating. Fixes,
debloat, startup toggles, baselines and evidence packs need admin.

**Can I undo everything?** Yes: the rollback script, the JSON backups and the
System Restore point.

**Will my antivirus flag it?** `Start.bat` uses the built-in PowerShell, so
there is no unsigned binary. Some products flag DFIR tools such as Hayabusa by
category; that is expected.

## Contributing

Issues and pull requests are welcome. Keep the rules: read-only by default,
every change backed up and reversible, plain-English explanations, tests first.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Provided as-is, without warranty. You are responsible for the
changes you choose to apply. Review the source and test before broad use.
