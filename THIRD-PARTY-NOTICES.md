# Third-Party Notices

The **Windows 11 Security Optimizer** is licensed under the MIT License (see
`LICENSE`). It does **not** bundle or redistribute any third-party program. The
only third-party file it ships is the sysmon-modular configuration (MIT), listed
below with its notice.

| Component | License | How it ships |
|---|---|---|
| Hayabusa, Chainsaw | GPL-3.0 | downloaded at runtime |
| Autoruns, standalone Sysmon | Sysinternals license | downloaded at runtime, never redistributed |
| Built-in Sysmon | Windows feature | enabled, not downloaded |
| sysmon-modular config | MIT | bundled with notice |
| Sigma rules | DRL 1.1 | via Hayabusa and Chainsaw |

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
  CPU architecture), and verified against a trusted SHA-256 before use. It is
  stored under the admin-locked
  `%ProgramData%\Win11SecurityOptimizer\tools\hayabusa\<version>` and is never
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
  `all_platforms+rules` package, which includes the Sigma/detection rules), and
  verified against a trusted SHA-256 before use. Stored under the admin-locked
  `%ProgramData%\Win11SecurityOptimizer\tools\chainsaw\<version>`
  and never committed to this repository.
- **Detection rules:** Chainsaw uses Sigma rules and its own mapping files, which
  carry their own licenses/attribution. See the Chainsaw repository for details.

## Sigma rules

- **Project:** Sigma, the generic signature format for SIEM systems, and its
  community rule set (SigmaHQ)
- **Source:** https://github.com/SigmaHQ/sigma
- **License:** Detection Rule License (DRL) 1.1.
  https://github.com/SigmaHQ/Detection-Rule-License
- **How they are obtained:** never by this project directly. Sigma rules arrive
  inside the Hayabusa and Chainsaw downloads described above, which ship and load
  them. This project does not copy, modify or redistribute any rule.
- **Attribution:** each rule file keeps its author and reference fields as
  published. Every Hayabusa or Chainsaw card names the rule that matched, and the
  tool's full output file (with its rule fields) is kept next to the results.

## Autoruns (Pro Tools) and Sysmon (continuous logging)

- **Projects:** Autoruns (autorunsc) and System Monitor (Sysmon), MS Sysinternals
- **Author / Copyright:** Microsoft Corporation
- **Source:** https://learn.microsoft.com/sysinternals/downloads/autoruns and
  https://learn.microsoft.com/sysinternals/downloads/sysmon
- **License:** Sysinternals Software License Terms (free to use, not
  redistributable). https://learn.microsoft.com/sysinternals/license-terms
- **How they are obtained:** downloaded on demand, after a consent screen or a
  confirmation, from the fixed URLs `https://download.sysinternals.com/files/Autoruns.zip`
  and `https://download.sysinternals.com/files/Sysmon.zip`. Only the console
  program for your CPU architecture (and `Eula.txt`) is extracted. It must carry a
  valid MS Authenticode signature chaining to a Microsoft Root Certificate
  Authority, otherwise it is deleted and never run. Its SHA-256 is recorded and,
  together with the signature, re-checked before every run. They are stored under
  the admin-locked `%ProgramData%\Win11SecurityOptimizer\tools` and are never
  committed to this repository or included in a release.
- **Built-in Sysmon:** on Windows builds that include Sysmon as an optional
  feature, the tool enables that Windows feature instead of downloading anything.
  It is part of Windows and governed by your Windows license.
- **Privacy:** Autoruns is never run with `-v`, `-vs` or `-vt`, so no file or
  hash is sent to VirusTotal.

## sysmon-modular configuration (bundled)

- **Project:** sysmon-modular, by Olaf Hartong
- **Source:** https://github.com/olafhartong/sysmon-modular
- **File:** `config/sysmon/sysmonconfig.xml`, the balanced default configuration,
  taken unmodified from commit `a9ff298f6d228c181be71b213c73d111c6096f41`
  (2023-09-20), the last commit that kept the generated default config in the
  repository root:
  https://github.com/olafhartong/sysmon-modular/blob/a9ff298f6d228c181be71b213c73d111c6096f41/sysmonconfig.xml
- **Upstream file SHA-256:** `4516404FA30EE87CEA558567820CDC78863CC4AB07889519E49EAC3CCA92E0D2`.
  A provenance comment was added at the top; the vendored file is pinned in
  `src/features/Sysmon.ps1` by its own SHA-256 and verified before every use. It is
  never fetched at runtime.
- **License:** MIT License, reproduced here as published in the repository's
  `license.md`:

  > Permission is hereby granted, free of charge, to any person obtaining a copy
  > of this software and associated documentation files (the "Software"), to deal
  > in the Software without restriction, including without limitation the rights
  > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  > copies of the Software, and to permit persons to whom the Software is
  > furnished to do so, subject to the following conditions:
  >
  > The above copyright notice and this permission notice shall be included in
  > all copies or substantial portions of the Software.
  >
  > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  > SOFTWARE.

---

## Why these tools are downloaded, not bundled

Hayabusa and Chainsaw are licensed under the **GPL-3.0**, a strong copyleft
license. Bundling an unmodified copy of either as a separate executable that this
project merely invokes would **not** relicense this project's own MIT code; that
is "mere aggregation" / use of a separate program. It **would**, however, attach
GPL-3.0 obligations to *that binary* in every release that shipped it (provide the
license text and offer the corresponding source), and the shipped copy would go
stale as the upstream tool is updated.

To keep this project MIT, low-obligation and always current, the tools are:

1. **Never included** in this repository or any release of it.
2. **Fetched by the end user at runtime**, from the authors' official
   distribution channel, after an explicit in-app consent screen that names the
   tool, its author, its GPL-3.0 license, the exact source URL, the version and
   the download size, and only after the download's SHA-256 is verified against a
   trusted (project-pinned or GitHub-advertised) hash.
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
