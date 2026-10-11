# DFIR tools: what we built in, and what we deliberately did NOT bundle

You asked about merging **KAPE**, **Hayabusa**, **THOR**, and similar DFIR tools
into the optimizer. Here's the honest licensing + design reality, and what the
tool does instead.

## TL;DR

We built a **native "Deep Scan"** engine (MIT, our own code) that does the
high-value things those tools do — hunt malicious processes and triage the event
logs — and explains every finding in plain English. We **did not bundle** KAPE,
Hayabusa, or THOR, because their licenses make bundling into a free, open-source,
"anyone can download and run" tool either **not allowed** or **legally messy**.

## The license problem (why bundling is a trap)

| Tool | What it is | License | Can we bundle it in an MIT open-source app anyone downloads? |
|------|-----------|---------|---------------------------------------------------------------|
| **THOR / THOR Lite** (Nextron) | APT scanner, YARA/IOC engine | **Proprietary, commercial.** THOR Lite is free *for personal use* but is **not open source** and its EULA restricts redistribution/commercial use. | **No.** You already spotted this. Bundling it would break their license and can't be MIT. |
| **KAPE** (Kroll) | Artifact collector (`.tkape`/`.mkape`) | **Free but proprietary.** Free for most, **license required for commercial use**, and redistribution is restricted. | **No** — can't redistribute it inside your repo, and the commercial-use limit is incompatible with "anyone can use this." |
| **Hayabusa** (Yamato Security) | Fast Windows event-log hunter (Sigma rules) | **GPL-3.0** (open source). | **Technically** (GPL allows redistribution) **but it would force your whole combined work to GPL-3.0**, not MIT, and you'd have to ship full GPL notices + source offer. It also pulls in Sigma rules under their own terms. |
| **Chainsaw** (WithSecure) | Event-log/MFT hunter (Sigma) | **GPL-3.0**/BSD-ish depending on component. | Same GPL "copyleft" catch as Hayabusa. |
| **Velociraptor** | Endpoint DFIR/hunting | **AGPL-3.0** (very strong copyleft). | **Worst fit** for bundling — AGPL is even stricter than GPL. |

**The core issue:** your optimizer is **MIT** so anyone (including businesses) can
use it freely. The moment you *bundle* a GPL/AGPL tool, the combined product must
become GPL/AGPL too — you'd lose MIT. And THOR/KAPE simply don't permit free
redistribution at all. So "merge them in" isn't a packaging detail; it changes
what your project legally *is*.

## What we did instead: native "Deep Scan" (MIT, no bundling)

Rather than ship someone else's licensed binary, the optimizer now has its own
**Deep Scan** on the Investigate tab. It reimplements the highest-signal checks
these tools are famous for, from scratch, and — crucially for your goal — says
*what it found, why it matters, and what to do* in beginner language.

**Process threat hunt** (what an EDR/THOR-style scan looks for):
- **Masquerading** — a process using a Windows system name (svchost, lsass…) from
  the wrong folder, or a look-alike name (`scvhost`, `lsas`). *Critical / Alert.*
- **Runs-from-temp** — programs executing from Temp/AppData/Downloads/ProgramData.
- **Unsigned + networked** — tiered so legit indie apps in Program Files are
  low-priority, while unsigned networked binaries in user/temp folders are flagged.
- **Suspicious command lines** — encoded PowerShell, download-and-run cradles,
  LOLBin abuse (mshta/regsvr32/rundll32/certutil/bitsadmin), hidden windows, and
  **shadow-copy/backup deletion** (ransomware) — each tagged `[ALERT]` (high
  confidence) vs `[REVIEW]` (also used by legit software) to cut false alarms.

**Event-log triage** (what Hayabusa/Chainsaw do with Sigma rules, distilled):
- Security/System **log cleared** (1102/104) — strong anti-forensics signal.
- **New service installed** (7045) — persistence.
- **Account created / added to Administrators** (4720/4728/4732).
- **Brute force** — bursts of failed logons (4625), lockouts (4740).
- **Defender detections** (1116/1117).
- **Scheduled task created** (4698), **RDP logons** (4624 type 10).

This gets a non-expert ~80% of the practical value with **zero license risk,
zero downloads, and the same clear-language explanations** as the rest of the app.

## If you later want the *real* Hayabusa/Chainsaw power

> **Status: IMPLEMENTED.** This is now the **"+ Pro Tools"** button on the
> Investigate tab. The design below is what shipped.

The right pattern is **opt-in orchestration, not bundling**:

1. The tools are kept **out of the repo** entirely (see `.gitignore`; they live
   under `%LOCALAPPDATA%\Win11SecurityOptimizer\tools` at runtime).
2. The **"+ Pro Tools"** button lets the user pick Hayabusa or Chainsaw. Before
   anything downloads, a **consent screen** shows the tool name, author, its
   **GPL-3.0 license**, the official source URL, the resolved version, and the
   download size, with a mandatory "I understand/accept" checkbox.
3. On accept, the tool is downloaded from its **official GitHub release** (arch-
   matched Windows build), the archive is validated (ZIP magic bytes), its
   **SHA-256 is computed and logged**, it is extracted, and the binary is
   smoke-tested before use.
4. It is run **read-only** against the local event logs, and its output
   (Hayabusa CSV / Chainsaw JSON) is **parsed back into the same plain-English
   finding cards** as everything else, merged into the Investigate list.
5. Attribution lives in `THIRD-PARTY-NOTICES.md`; the download location can be
   cleared anytime from the Restore & Logs tab ("Remove downloaded tools").

Because the GPL tool is fetched by the end user at runtime and merely *invoked*
(not linked or redistributed by us), this project stays MIT. This is exactly how
many MIT-licensed front-ends legally drive GPL command-line tools.

### Implementation notes (verified on the test machine)
- Hayabusa v4.1.0 and Chainsaw v2.16.5 release assets resolve correctly via the
  GitHub API; the Windows x64 builds are selected automatically.
- Hayabusa's live-log analysis (`dfir-timeline -l`) **requires administrator**
  (the tool enforces this itself); the app surfaces that if you're not elevated.
- A real elevated run produced results that parsed into cards (e.g. a critical
  Defender alert plus several high-severity rule hits), confirming the end-to-end
  download → verify → run → parse → display path.

## Bottom line

- **THOR** — you were right, it's commercial; we can't bundle it. ✗
- **KAPE** — free but can't be redistributed / commercial-limited. ✗
- **Hayabusa / Chainsaw** — great and open, but **GPL copyleft** would relicense
  your whole project if bundled; so they are **opt-in, downloaded at runtime** via
  the "+ Pro Tools" button, never shipped in the repo. ✓ (implemented)
- **Our native Deep Scan** — MIT, no downloads, plain-English, always available. ✓
