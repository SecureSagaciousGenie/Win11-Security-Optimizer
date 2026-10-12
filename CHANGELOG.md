# Changelog

Author: Ahmad Shaukat

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-10-12

### Security
- Every file written into `%ProgramData%\Win11SecurityOptimizer` is owned by
  Administrators straight after the write. Before, an elevated write left the
  file owned by the admin user; the next launch failed the ownership check and
  deleted the whole folder, rollback scripts included.
- Background runspaces start read-only. They never secure, lock, re-own or
  quarantine the data folder.
- An untrusted data folder is moved aside to `*.untrusted-<guid>`, never
  deleted. A dialog names it and warns that its old rollback scripts are not
  trusted. Nothing in it is run.
- The Defender driver path check canonicalises the path first, closing a `..\`
  traversal bypass.
- Administrators are found by SID S-1-5-32-544 and Guest by RID 501, so both
  checks work in every Windows language.
- Every external tool run is preceded by an integrity check: locked tools
  folder, install record, recorded SHA-256 and, for Sysinternals tools, a valid
  MS signature.
- Native programs take separate argument tokens and their exit codes are
  checked. Their stderr no longer aborts a run under Windows PowerShell 5.1.

### Added
- **Autoruns Pro Tool.** Downloads autorunsc from Sysinternals on demand,
  requires an MS signature, never sends anything to VirusTotal and turns the
  results into Investigate cards.
- **Pro Tools dialog** with purpose, license, installed version and a minimum
  level for Hayabusa and Chainsaw.
- **Baseline and drift.** Save a snapshot of autostarts, services, tasks,
  admins, users, Defender exclusions, listeners, hosts entries, ASR rules,
  firewall profiles and WMI subscriptions; later scans show what is new.
- **Credential-theft hardening:** LSA protection, Credential Guard (audit),
  WDigest, PowerShell 2.0, NetBIOS name resolution, mDNS, SMB signing and
  patch age.
- **Sysmon (opt-in).** Enables the built-in Windows Sysmon feature or installs
  standalone Sysmon with a bundled, SHA-256 pinned sysmon-modular config and a
  512 MB log. Fully reversible.
- **HTML report** with every value encoded and no scripts.
- **Evidence pack:** event logs, a system snapshot, processes, TCP connections
  and findings, zipped with a SHA-256 manifest.
- **Card actions:** Scan with Defender, Open location and Copy details. Filter
  chips All, Alert, Review, Info and Clean.
- **Headless scan** `src\Scan.ps1 -OutJson <file> [-Deep]` with exit codes
  0 clean, 1 review, 2 alert and 3 error.
- **Debloat** shows an impact level and a one-line risk note per app, with
  Recommended and Minimal presets. The confirm dialog lists each removal with
  how to get it back.
- Sidebar chips for elevation, Sysmon, baseline and Pro Tools.
- Pester test suite, PSScriptAnalyzer gate and an integration workflow that
  runs the real fixes, downloads and rollbacks on an elevated Windows runner.
- Release workflow: tags `v*` publish a zip of the repository and
  `SHA256SUMS.txt`.

### Fixed
- In 1.1.0 the window closed with "The property 'Visibility' cannot be found
  on this object" as soon as a background scan finished, so Run Full Scan never
  showed results. Handlers built with `GetNewClosure()` could not see script
  state; the same flaw meant the Pro Tools consent was never accepted.
- Background scans ran their work against the window's own runspace from a
  second thread, because a script block stays bound to the runspace that
  created it. That could corrupt state and close the window a few seconds into
  a scan. The work is now rebuilt inside the background runspace.
- Run Full Scan runs the security, app, investigation and startup scans one
  after another and reports any scan that failed. The CI self-test now clicks
  it on a real Windows runner and waits for every scan.
- Only one background job runs at a time, and the button that started it is
  disabled until it finishes.
- Investigate cards sort by status, then severity.
- `Build-Exe.ps1` produced a script that did not parse; it now inlines the
  feature files and has `-MergeOnly`.
- Several `.Count` and JSON array cases that broke under Windows PowerShell
  5.1 StrictMode.

## [1.1.0] and earlier

See the git history.
