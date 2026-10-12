# Windows 11 Security Optimizer

A free, open-source tool that makes your Windows 11 PC **safer, leaner, and
easier to trust** — all from one simple window. No command line, no installer.
Download, double-click **`Start.bat`**, and everything runs from a clean dark UI.

> **Your PC, your call.** Nothing is ever changed without you ticking a box and
> confirming. Before the first change the tool creates a **System Restore point**
> and writes a **rollback script**, so anything it does can be undone.

---

## What it does

| Tab | What it's for |
|-----|---------------|
| **Dashboard** | One-click "Run Full Scan" and at-a-glance cards: security score, hardening issues, investigation items, removable bloat. |
| **Security** | Audits Windows security settings and lets you fix each one (or all safe ones at once). Firewall, Defender, SmartScreen, UAC, SMBv1, LLMNR, AutoRun, RDP, and more. |
| **Debloat** | Lists the pre-installed apps you probably don't need (Xbox, Bing News/Weather, Clipchamp, Solitaire, consumer Teams, 3D Viewer, Quick Assist…). **You tick each one.** Everything is reinstallable. |
| **Investigate** | A plain-English compromise check for non-experts: hidden/extra administrators, backdoor accounts, startup persistence, exposed remote access, suspicious network ports/shares, Defender exclusions, and hosts-file tampering. Plus **Deep Scan** (process + event-log threat hunt) and optional **Pro Tools** (opt-in Hayabusa/Chainsaw). |
| **Startup** | Shows what launches at boot, with publisher and signed/unsigned status. Flip a switch to disable (reversible) anything you don't want. |
| **Restore & Logs** | Open your backups and rollback script, create a restore point on demand, and read the full activity log for the session. |

---

## Quick start

1. **Download** this repository (green **Code** button → **Download ZIP**), or
   clone it.
2. **Extract** the ZIP somewhere, keeping `Start.bat` next to the `src` folder.
3. **Double-click `Start.bat`.**
4. Click **Yes** on the Windows admin prompt (needed to apply fixes; scanning
   alone works without it).
5. The window opens → click **Run Full Scan**.

That's it. Explore each tab, tick what you want, and confirm.

> **Why a `.bat` and not an `.exe`?** An unsigned `.exe` downloaded from the
> internet gets flagged by SmartScreen/antivirus and is often quarantined.
> `Start.bat` launches the exact same tool using Windows' own built-in
> PowerShell — nothing to install, nothing to quarantine, and you can read every
> line of what it does. (Maintainers who have a code-signing certificate can
> still build a signed `.exe` with `Build-Exe.ps1`.)

---

## Requirements

- **Windows 11** (also works on Windows 10).
- **Windows PowerShell 5.1** — built into Windows, nothing to install.
- **Administrator rights** to *apply* changes (`Start.bat` asks for this). You
  can scan and investigate without admin.

The core tool needs no internet connection and sends none of your files or
activity to any third party. Two **opt-in** features are the only exceptions, and
both are clearly flagged in-app: enabling **cloud-delivered protection** turns on
Microsoft Defender's normal cloud sample submission (`SubmitSamplesConsent =
SendSafeSamples` — Defender may upload files it deems safe to Microsoft; this is
reverted by the rollback script), and **Pro Tools** downloads Hayabusa/Chainsaw
from GitHub. Nothing else leaves your PC.

---

## Safety: how every change is protected

This tool is **defensive** and built for the owner of the machine. It is designed
so you can trust it:

1. **Read-only by default.** Every "scan" only reads settings. Nothing changes
   until you tick an item and confirm a dialog.
2. **Restore point first.** Before the first change in a session, a Windows
   System Restore point is created automatically.
3. **Backup before every change.** The previous value of each setting is saved to
   a JSON backup.
4. **Automatic rollback script.** Each change appends an undo step to a
   timestamped `Rollback_*.ps1`. Run it to revert everything (or open it and
   delete the steps you want to keep).
5. **Verify after apply.** Each fix is re-read to confirm it actually took effect.
6. **Reversible debloat.** Removed apps are logged with reinstall notes; all are
   available again from the Microsoft Store.
7. **Reversible startup toggles.** Disabling a startup item moves/renames it
   rather than deleting it.
8. **Full transcript.** Everything is written to a session log you can read in the
   **Restore & Logs** tab.

### Where your backups live
The rollback script is designed to be run **elevated**, so it must not sit anywhere
a non-admin process could tamper with it first. When you run the optimizer as
administrator (the normal case, via `Start.bat`), the undo script and the
before-state backups are written to an **ACL-locked folder** that only
Administrators/SYSTEM can write to:
```
%ProgramData%\Win11SecurityOptimizer\        (admin-locked: Administrators/SYSTEM write, Users read-only)
└─ backups\    Backup_*.json         (before-state of every change)
               Rollback_*.ps1        (undo script)

%LOCALAPPDATA%\Win11SecurityOptimizer\
└─ logs\       session_*.log         (activity log — read-only record, never executed)
```
(If the optimizer is ever run without elevation, the backups fall back to
`%LOCALAPPDATA%`; the logs always live under `%LOCALAPPDATA%` because they are only
ever read, never executed.)

### To undo changes
Open an **elevated** PowerShell and run the rollback script shown in the
**Restore & Logs** tab (the tab shows its exact path):
```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\Win11SecurityOptimizer\backups\Rollback_<timestamp>.ps1"
```
Or roll the whole machine back using the System Restore point the tool created.

---

## Risk tiers (Security tab)

Each fix is labelled so you know its impact before applying:

- **Safe** – widely recommended, low risk (firewall, Defender toggles,
  SmartScreen, UAC, AutoRun, Guest account, Windows Update service).
- **Elevated** – standard hardening that *may* affect some setups (disable SMBv1,
  disable LLMNR, enable ASR rules, enforce RDP NLA).
- **High-risk** – powerful but can break things; hidden unless you tick
  **"Include high-risk fixes"** (Memory Integrity/HVCI, disabling RDP).
- **Audit-only** – reported but never changed by the tool, because they belong in
  firmware or need careful handling (Secure Boot, TPM, BitLocker, Tamper
  Protection).

The **"Apply Recommended Fixes"** button applies **Safe** and **Elevated** items
(and High-risk only if you tick **"Include high-risk fixes"**). Before it runs it
shows a confirmation that **groups every change by its risk tier**, so you can see
exactly which items are the more impactful Elevated ones (SMBv1, LLMNR, ASR in
Block mode, RDP NLA) rather than just low-risk toggles. Nothing is applied until
you confirm.

---

## What the "Investigate" tab checks

Written for someone who is **not** a security expert. Each finding says *what* was
found, *why it matters*, and *what to do*:

- Extra or **hidden** accounts in the local **Administrators** group.
- Enabled local user accounts, including names ending in `$` (hidden from logon).
- **Startup persistence**: Run keys, Startup folders, scheduled tasks and
  services — flagged if unsigned or launching from Temp/AppData/Downloads.
- **Remote access**: whether Remote Desktop (RDP) is listening.
- **Network exposure**: risky listening ports (RDP/VNC/Telnet/SMB/WinRM) and
  non-default file shares.
- **Tampering indicators**: Microsoft Defender exclusions you didn't set, and
  hosts-file entries that redirect security/update/banking domains.

### Deep Scan (the "+ Deep Scan" button)
A heavier, targeted hunt — the kind of thing DFIR tools like Hayabusa/Chainsaw do,
reimplemented natively (MIT, nothing to download) and explained in plain English:

- **Running-process threat hunt**: processes **masquerading** as Windows system
  files (e.g. an `svchost.exe` outside System32), programs running from
  Temp/AppData/Downloads, unsigned binaries using the network, and **suspicious
  command lines** (encoded PowerShell, download-and-run cradles, LOLBin abuse,
  and shadow-copy/backup deletion a.k.a. ransomware). Each line is tagged
  `[ALERT]` (high-confidence) or `[REVIEW]` (also used by legit software).
- **Event-log triage**: security/system **log cleared**, **new service**
  installed, **account created / added to Administrators**, **brute-force**
  failed-logon bursts, Defender detections, new scheduled tasks, and RDP logons.

### Pro Tools — real Hayabusa / Chainsaw (the "+ Pro Tools" button)
For a professional-grade event-log hunt, the Investigate tab can run the
best-in-class open-source DFIR scanners **Hayabusa** (Yamato Security) and
**Chainsaw** (WithSecure) and fold their results into the same plain-English
cards.

Because these tools are **GPL-3.0**, they are **not bundled** — shipping them would
attach GPL obligations (ship the license, offer the source) to those binaries in
every release, and the copies would go stale. (Bundling would not relicense this
project's own MIT code, but downloading on demand is simpler and lower-obligation.)
Instead, the first time you use them:

1. A **consent screen** shows the tool's author, its **GPL-3.0 license**, the
   official GitHub source URL, the version, and the download size.
2. On your acceptance, the app downloads the arch-matched Windows build from the
   project's **official GitHub release**, verifies it's a valid archive, and
   checks its **SHA-256 against a trusted hash** (a project-pinned, reviewed hash
   for the shipped versions, or GitHub's advertised digest for a newer release).
   If no trusted hash is available it **refuses** the download rather than running
   an unverified admin binary; otherwise it extracts it and smoke-tests the binary.
3. It runs the tool **read-only** against your event logs and parses the output
   into result cards. Downloaded tools live under the admin-locked
   `%ProgramData%\Win11SecurityOptimizer\tools` and can be removed anytime.

> Hayabusa's live-log mode needs administrator rights (the tool enforces this).
> Note that some antivirus/EDR products flag DFIR tools by category — that's
> expected for this class of software. Full attribution:
> [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

This is **triage**, not a full forensic suite — it points you at things worth a
closer look. When in doubt, don't delete; investigate first.

> **Why not bundle KAPE / Hayabusa / THOR directly?** Licensing. THOR and KAPE are
> proprietary and can't be freely redistributed. Hayabusa/Chainsaw are GPL-3.0:
> bundling them wouldn't relicense this project's own MIT code, but it *would*
> attach GPL obligations (ship the license, offer the source) to that binary in
> every release — more to carry, and the tools go stale. So the built-in Deep Scan
> is our own MIT code, and the heavier external tools are **opt-in, downloaded at
> runtime by you** (verified against a pinned SHA-256), never shipped in the repo.
> Full explanation: [docs/DFIR-TOOLS.md](docs/DFIR-TOOLS.md).

---

## Debloat: what can be removed

The catalog only ever shows apps that are **actually installed** on your PC. Each
row explains what the app is and why people remove it. Removal uninstalls it for
your account and removes the provisioned copy so it doesn't come back for new
accounts. Examples: Xbox apps & Game Bar, Microsoft/Bing News, MSN Weather,
Clipchamp, Solitaire Collection, 3D Viewer, Paint 3D, Mixed Reality Portal,
consumer Microsoft Teams/Chat, Tips, Maps, People, Phone Link, Quick Assist.

Removing consumer Teams does **not** affect work/school Teams installed
separately. Every removal is logged with a reinstall note (search the same name
in the Microsoft Store to get it back).

---

## Project layout
```
Win11-Security-Optimizer\
├─ Start.bat                 ← double-click this
├─ Build-Exe.ps1            ← OPTIONAL: build a signed .exe (maintainers only)
├─ README.md
├─ LICENSE                   ← MIT (this project)
├─ THIRD-PARTY-NOTICES.md    ← attribution for opt-in Hayabusa/Chainsaw (GPL-3.0)
├─ docs\
│  ├─ REINSTALL.md          ← how to reinstall removed apps
│  └─ DFIR-TOOLS.md         ← why KAPE/Hayabusa/THOR aren't bundled; Pro Tools design
└─ src\
   ├─ Optimizer.ps1         ← the GUI (presentation only)
   └─ SecurityCore.ps1      ← all logic (scan / harden / debloat / DFIR / deep scan / pro tools / rollback)
```

Downloaded Pro Tools and all logs/backups live outside the repo, under
`%LOCALAPPDATA%\Win11SecurityOptimizer\` (git-ignored).

Developers: validate without clicking via the headless self-test —
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -STA -File .\src\Optimizer.ps1 -SelfTest
```
It builds and renders the window, runs every read-only engine, prints
`SELFTEST_OK …`, and closes itself.

---

## FAQ

**Does scanning change anything?** No. Scans are strictly read-only.

**Will my antivirus flag this?** `Start.bat` uses the built-in PowerShell, so
there's no unsigned binary to quarantine. You can read every line of the source.

**I'm not an admin, can I still use it?** Yes, for scanning and investigation.
Applying fixes, removing apps, or toggling startup needs admin (relaunch via
`Start.bat`).

**Can I undo everything?** Yes, the rollback script, the per-change JSON backup,
and the System Restore point all let you revert.

**Is my data sent anywhere?** The tool itself does not upload your files or
activity. Three things can cause outbound traffic, all opt-in and flagged: the
**cloud-protection fix** turns on Defender's own cloud sample submission
(`SendSafeSamples` — reverted by the rollback script), **Pro Tools** downloads
Hayabusa/Chainsaw from GitHub, and the **update-signatures fix** fetches Defender
updates from Microsoft. No telemetry is sent to the project authors.

---

## Contributing

Issues and pull requests welcome. Good first contributions: more debloat catalog
entries, extra DFIR checks, and additional hardening items. Keep the golden rules:
**read-only by default, every change backed up and reversible, plain-English
explanations.**

## License

[MIT](LICENSE). Provided **as-is, without warranty**. You are responsible for
changes you choose to apply. Review the source and test before broad use.
