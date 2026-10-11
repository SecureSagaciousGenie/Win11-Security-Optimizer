# Third-Party Notices

The **Windows 11 Security Optimizer** is licensed under the MIT License (see
`LICENSE`). It does **not** bundle, include, or redistribute any third-party
security tool.

The optional **"Pro Tools"** feature (Investigate tab) can, **only when you
explicitly choose to and accept a consent screen**, download the following
independent open-source programs from their **official GitHub release pages** and
run them locally against your Windows event logs. These programs are the property
of their respective authors and are governed by **their own licenses**, not this
project's MIT license. This project merely invokes them as separate processes and
reads their output.

---

## Hayabusa

- **Project:** Hayabusa
- **Author / Copyright:** Yamato Security (© Yamato Security)
- **Source:** https://github.com/Yamato-Security/hayabusa
- **License:** GNU General Public License v3.0 (GPL-3.0)
- **License text:** https://github.com/Yamato-Security/hayabusa/blob/main/LICENSE.txt
- **How it is obtained:** Downloaded on demand, with your consent, from the
  official GitHub Releases of the above repository (Windows build matching your
  CPU architecture). It is stored under
  `%LOCALAPPDATA%\Win11SecurityOptimizer\tools\hayabusa\<version>` and is never
  committed to this repository.
- **Detection rules:** Hayabusa ships and uses Sigma-format rules and the
  `hayabusa-rules` repository, which carry their own licenses/attribution. See the
  Hayabusa repository for details.

## Chainsaw

- **Project:** Chainsaw
- **Author / Copyright:** WithSecure Labs (formerly F-Secure) (© WithSecure)
- **Source:** https://github.com/WithSecureLabs/chainsaw
- **License:** GNU General Public License v3.0 (GPL-3.0)
- **License text:** https://github.com/WithSecureLabs/chainsaw/blob/master/LICENSE
- **How it is obtained:** Downloaded on demand, with your consent, from the
  official GitHub Releases of the above repository (the
  `all_platforms+rules` package, which includes the Sigma/detection rules).
  Stored under `%LOCALAPPDATA%\Win11SecurityOptimizer\tools\chainsaw\<version>`
  and never committed to this repository.
- **Detection rules:** Chainsaw uses Sigma rules and its own mapping files, which
  carry their own licenses/attribution. See the Chainsaw repository for details.

---

## Why these tools are downloaded, not bundled

Hayabusa and Chainsaw are licensed under the **GPL-3.0**, a strong copyleft
license. If this project **bundled** or **linked** them, the combined work would
have to be distributed under the GPL-3.0 as well — this project could no longer be
MIT-licensed.

To keep this project MIT **and** respect the GPL, the tools are:

1. **Never included** in this repository or any release of it.
2. **Fetched by the end user at runtime**, from the authors' official
   distribution channel, after an explicit in-app consent screen that names the
   tool, its author, its GPL-3.0 license, the exact source URL, the version, and
   the download size.
3. **Invoked as separate, unmodified executables** (via the command line); this
   project reads their output files and presents a summary. This is "mere
   aggregation" / use of a separate program, not a derivative work.

If you redistribute copies of those tools yourself (as opposed to letting the end
user download them), you must comply with the GPL-3.0, including providing the
corresponding source and license text.

---

## Microsoft Windows components

This project calls built-in Windows features and cmdlets (Microsoft Defender,
Windows Firewall, BitLocker, AppX, Event Log, etc.) through their public
PowerShell/CIM interfaces. Those components are part of Windows and are governed
by your Windows license, not by this project.

---

*If you are a rights holder and believe attribution here is incomplete or
incorrect, please open an issue so it can be corrected.*
