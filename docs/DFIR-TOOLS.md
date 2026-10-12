# DFIR tools: what we built in, and what we deliberately did NOT bundle

This document explains why the optimizer does not **bundle** KAPE, Hayabusa, THOR
or similar DFIR tools, and what it does instead.

## TL;DR

The optimizer has a native **Deep Scan** engine (MIT, its own code) that does some
of the high-value things those tools do — hunt suspicious processes and triage the
event logs — and explains every finding in plain English. It does **not bundle**
KAPE, Hayabusa, THOR or Chainsaw, because their licenses make bundling into a
free, open-source, "anyone can download and run" tool either **not allowed** or
**legally messy**. Hayabusa and Chainsaw can instead be **downloaded on demand**
by the user (see "Pro Tools"), which keeps their GPL duties attached only to those
separate binaries.

## The license problem (why bundling is avoided)

| Tool | What it is | License | Can it be bundled in an MIT app anyone downloads? |
|------|-----------|---------|---------------------------------------------------------------|
| **THOR / THOR Lite** (Nextron) | APT scanner, YARA/IOC engine | **Proprietary, commercial.** THOR Lite is free *for personal use* but is **not open source** and its EULA restricts redistribution/commercial use. | **No** — bundling or redistributing it would break their license. |
| **KAPE** (Kroll) | Artifact collector (`.tkape`/`.mkape`) | **Free but proprietary.** Free for most, **license required for commercial use**, redistribution restricted. | **No** — can't redistribute it inside the repo, and the commercial-use limit conflicts with "anyone can use this." |
| **Hayabusa** (Yamato Security) | Fast Windows event-log hunter (Sigma rules) | **GPL-3.0** (open source). | **Not bundled.** Shipping it inside the app would attach GPL-3.0 obligations to that distribution. Downloaded at runtime instead (see below). |
| **Chainsaw** (WithSecure) | Event-log/MFT hunter (Sigma) | **GPL-3.0**. | Same as Hayabusa — downloaded at runtime, not bundled. |
| **Velociraptor** | Endpoint DFIR/hunting | **AGPL-3.0** (very strong copyleft). | Not used; AGPL is even stricter. |

**The core issue (plain English, not legal advice):** the optimizer is **MIT** so
anyone — including businesses — can use it freely. THOR and KAPE don't permit free
redistribution at all, so they can't ship with it. Hayabusa and Chainsaw are
GPL-3.0: you *can* redistribute them, but doing so puts GPL obligations on that
distribution (provide the licence, offer the corresponding source, etc.). The
cleanest way to keep the project simple and MIT is to not ship them at all and let
the user fetch them on demand. (See the "soft" note at the bottom — I'm not a
lawyer; this is an engineering decision, not legal counsel.)

## What it does instead: native "Deep Scan" (MIT, no bundling)

Rather than ship someone else's licensed binary, the optimizer has its own
**Deep Scan** on the Investigate tab. It reimplements several high-signal checks
these tools are known for, and says *what it found, why it matters, and what to do*
in beginner language.

**Process threat hunt** (EDR/THOR-style, at a basic level):
- **Masquerading** — a process using a Windows system name (svchost, lsass…) from
  the wrong folder, or a look-alike name (`scvhost`, `lsas`). *Critical / Alert.*
- **Runs-from-temp** — programs executing from Temp/AppData/Downloads/ProgramData.
- **Unsigned + networked** — tiered so legit indie apps in Program Files are
  low-priority, while unsigned networked binaries in user/temp folders are flagged.
- **Suspicious command lines** — encoded PowerShell (incl. `-e`/`-ec`/`-en` short
  forms and `… | iex` ordering), download-and-run cradles, LOLBin abuse
  (mshta/regsvr32/rundll32/certutil/bitsadmin), hidden windows, and
  **shadow-copy/backup deletion** (ransomware, incl. the WMIC variant) — each
  tagged `[ALERT]` (high confidence) vs `[REVIEW]` (also used by legit software).

**Event-log triage** (a distilled subset of what Hayabusa/Chainsaw do with full
Sigma rulesets):
- Security/System **log cleared** (1102/104) — strong anti-forensics signal.
- **New service installed** (7045, with Defender's own driver installs filtered).
- **Account created / added to Administrators** (4720/4728/4732).
- **Brute force** — bursts of failed logons (4625), lockouts (4740).
- **Defender detections** (1116/1117).
- **Scheduled task created** (4698), **RDP logons** (4624, matched by numeric logon
  type so it works on non-English Windows).

### Honest limits of the native Deep Scan
This is **lightweight triage, not a replacement** for Hayabusa/Chainsaw/THOR. Known gaps:
- **Process/command-line checks only see what is running at scan time** — a
  ransomware `vssadmin delete shadows` that already finished is caught only if the
  event-log/Defender side recorded it, not by the live-process check.
- **Event 4698 (scheduled-task created) needs "Audit Other Object Access", which is
  OFF by default** — so a missing 4698 card does **not** prove no task was created.
  (The native current-task scan in Investigate covers existing tasks regardless.)
- It does **not** yet cover several persistence spots a full tool would: Winlogon
  Shell/Userinit, Image File Execution Options, WMI event subscriptions, service
  `ServiceDll`, and `SpecialAccounts\UserList`-hidden accounts.
- It uses a small hand-written pattern set, **not** the thousands of community
  Sigma rules Hayabusa/Chainsaw ship.

For a thorough hunt, use the **Pro Tools** button to run the real Hayabusa/Chainsaw
(below). Treat the native Deep Scan as a fast first look that points you at obvious
problems.

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

- **THOR** — proprietary/commercial; cannot be bundled or redistributed. ✗
- **KAPE** — free but redistribution-restricted / commercial-limited. ✗
- **Hayabusa / Chainsaw** — open source but **GPL-3.0**. Bundling them would attach
  GPL obligations to the distribution; to keep things simple and MIT they are
  **opt-in, downloaded at runtime** via the "+ Pro Tools" button, never shipped in
  the repo. ✓ (implemented)
- **Native Deep Scan** — MIT, no downloads, plain-English, always available —
  a fast first look, not a full forensic suite. ✓

## A note on the GPL reasoning (not legal advice)

An earlier draft said bundling a GPL tool would "relicense your whole MIT project."
That overstates it. Shipping Hayabusa as a **separate, unmodified binary** that the
app merely invokes is generally treated as *aggregation / use of a separate
program* — it would add GPL duties **for that binary** (ship its license, offer its
source), not automatically relicense this project's own MIT code. Downloading at
runtime is still the cleaner choice here (less to ship, always current, obligations
stay entirely on the upstream project), but the honest reason is "simpler and
lower-obligation," not "bundling forces MIT→GPL on our code." I'm not a lawyer —
treat this as an engineering read, and get real legal advice before redistributing
GPL binaries yourself.
