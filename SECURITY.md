# Security policy

Author: Ahmad Shaukat

## Supported versions

Only the latest release gets security fixes.

| Version | Supported |
|---|---|
| 1.2.x | Yes |
| older | No |

## Reporting a vulnerability

Report privately. Do not open a public issue for a vulnerability.

1. Use GitHub's private reporting: the **Security** tab of this repository,
   then **Report a vulnerability**.
2. Include the version, the Windows build, the steps to reproduce and what an
   attacker gains (for example a standard user getting code to run elevated).
   A proof of concept helps; keep it minimal.
3. Do not include real credentials, evidence packs or logs from production
   machines. They contain user names and file paths.

You should get an acknowledgement within 7 days. A fix or a mitigation plan
follows within 30 days for high-impact issues. You will be credited in the
changelog unless you ask not to be.

## Scope

In scope:

- Anything that lets a non-admin process influence what the tool runs
  elevated: the rollback script, backups, downloaded tools or the Sysmon
  config under `%ProgramData%\Win11SecurityOptimizer`.
- Bypassing the SHA-256 or Authenticode checks on downloaded tools.
- Untrusted text (file names, registry values, event data, tool output)
  turning into code in a rollback script, the HTML report or the UI.
- A fix that weakens security, cannot be rolled back or reports success when
  it did not apply.

Out of scope:

- Vulnerabilities in Hayabusa, Chainsaw, Autoruns, Sysmon or Windows itself.
  Report those to their authors.
- Findings that need an attacker who is already an administrator.
- Antivirus or EDR alerts on the DFIR tools; they are expected for this class
  of software.

## Verifying a release

Each release has `SHA256SUMS.txt` next to the zip. Check the zip before you
extract it:

```powershell
(Get-FileHash .\Win11-Security-Optimizer-v1.2.0.zip -Algorithm SHA256).Hash
Get-Content .\SHA256SUMS.txt
```

The two hashes must match. If the maintainer signed the scripts, check them
with `Get-AuthenticodeSignature` as shown in the README.
