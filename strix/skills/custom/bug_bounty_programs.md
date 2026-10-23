---
name: bug-bounty-programs
description: Operate inside a bug bounty or VDP program - scope and authorization gates, duplicate economics, surface prioritization, impact chaining, and triage-ready reporting
---

# Bug Bounty Programs

A bounty target is a different beast from a pentest engagement: an unbounded
population of other hunters is testing the same surface, a triager decides
whether your finding is worth anything, and every request you send is governed
by a published policy rather than a scope document you negotiated.

The engineering goal is therefore not "find something" — it is **find something
nobody else has reported, prove it, and present it in a form triage accepts
without a round of questions**.

## Preconditions — verify before the first request

Confirm and record, in this order:

1. **Authorization exists.** Program registration, a signed engagement, or an
   explicit invite. A public marketing page, a "we care about security"
   statement, or a `security.txt` is *not* authorization to test.
2. **The asset is in scope.** Wildcard scopes do not always include the apex;
   subdomains of a listed host may be explicitly excluded; mobile apps, APIs,
   and staging environments are frequently separate entries.
3. **Automation is permitted.** Many policies forbid automated scanners, fuzzing,
   or "AI/LLM-generated" submissions, and some forbid any non-manual traffic.
   If tooling is restricted, the agent works analytically (source review, spec
   review, single targeted requests) rather than by crawling.
4. **Rate and blast-radius limits.** Default to conservative pacing (roughly
   2 requests/second) and never run volumetric or destructive tests.
5. **Reward and duplicate posture.** A VDP pays reputation, not money. A program
   with no published rewards, or where the payout table is $50 flat, is a poor
   target for an expensive deep run.

If any of these is unverified, stop and ask the user. Out-of-scope testing is a
legal exposure and a permanent ban, and both are unrecoverable.

## Duplicate economics

Duplicates are the dominant failure mode, and they are predictable:

| Class | Duplicate risk | Reason |
|---|---|---|
| Missing headers, banner/version disclosure, SPF/DMARC, clickjacking on a non-sensitive page | Very high | Automated hunters and every scanner report these first; programs often close them as informational |
| Reflected XSS on an unauthenticated page | High | Decades of coverage |
| Open redirect, SSRF without metadata access, self-XSS | High | Mass-scanned |
| **BOLA/IDOR on a specific object** | Medium | Needs a second account and hypothesis |
| **Business-logic abuse** (negative amount, workflow skip, coupon reuse) | Low | Requires understanding intent, not pattern matching |
| **Chained impact** (low + low → account takeover) | Low | Requires reasoning across findings |
| **Authorization failure on a newly shipped endpoint** | Low | Fresh surface, nobody has mapped it yet |

Bias the whole engagement toward the bottom of that table. If a candidate
finding is in the top three rows, treat it as context for a stronger chain, not
as a submission.

## Surface prioritization

Rank the attack surface before spending any budget:

1. **Recently changed surface.** New endpoints, new API versions, new features,
   new mobile releases. Find them via changelogs, release notes, app store
   "what's new", JS bundle diffs, and repository history where source is public.
2. **Version drift.** `/api/v1` frequently keeps the authorization bug that was
   fixed in `/api/v2`, because the old handler was never deleted. Diff the
   behavior of every version you find.
3. **Undocumented siblings.** If the spec declares `GET /resource/{id}` and
   `PATCH /resource/{id}`, assume `DELETE`, `POST /resource/{id}/transfer`, and
   `/resource/{id}/export` exist too. Specs under-document writes and bulk
   operations.
4. **Second-order surfaces.** Exports, reports, webhooks, integrations, admin
   consoles, and "connect your account" OAuth flows are lower-traffic and
   usually less hardened.
5. **Object-scoped endpoints with sequential identifiers.** Highest probability
   of a "yes" from an authorization test.

## Impact chaining and severity

A triager pays for demonstrated impact, not for a category name. Chain until
the next step requires an assumption:

- unauthorized read → can the same object be **written** or **deleted**?
- read of self → read of **another account**; another account → **another tenant**
- one record → **enumerable** (note the id format, state the count)
- password hash disclosure → is it **crackable** (unsalted MD5/SHA1 → credential
  stuffing chain)? Hash disclosure alone is medium; cracked credentials is high.
- missing rate limit → **does it complete an attack** (OTP brute force → account
  takeover; login spraying → valid credential)? Without the chain, it is
  informational.
- SSRF → **can it reach cloud metadata or internal services**, and can it return
  the response?

State the highest impact actually proved, and list the unproven escalation as a
note rather than as the severity basis. Rating the worst imaginable outcome is
the fastest way to lose a triager's trust, and trust is the only currency that
compounds across submissions.

## Evidence discipline

- Use **accounts and data you own**. Never demonstrate on another customer's
  record even when it is reachable; one record of your own is sufficient proof.
- Capture the **full request and response**: method, path, headers (redact only
  your own secrets), body, status, and timestamps.
- Re-run from a **clean session** before writing the report; cached tokens and
  stale state produce phantom findings.
- Delete what you created, and do not modify or destroy third-party data even
  where authorization would technically permit it.
- Keep a **coverage ledger**: endpoint, actor/role, verb, tested, result. The
  ledger is what lets you answer "did you test X?" and what prevents re-testing
  the same surface across sessions.

## Report shape that survives triage

1. **Title** — asset, vulnerability class, and impact in one line.
2. **Severity** — CVSS 3.1 vector plus a one-sentence justification.
3. **Affected** — exact host/path, and the scope entry that authorizes it.
4. **Summary** — the root cause in two or three sentences, phrased as a missing
   check, not as a payload.
5. **Reproduction** — numbered, deterministic, minimal auth setup, raw
   request/response blocks.
6. **Impact** — what an attacker gains, at what scale (id format, record count).
7. **Remediation** — the specific control that is missing, with the correct
   response code where it matters (404 over 403 to prevent enumeration).
8. **Notes** — accounts used, rate respected, no data modified.

Avoid: marketing language, severity inflation, screenshots without raw traffic,
and multi-issue reports. One finding per report triages faster and pays
independently.

## Budget and time control

Bounty work is a negative-expected-value activity until a hypothesis is
supported. Treat LLM spend the same way:

- Bound every run (a per-run budget and turn cap) and stop at the first strong
  hypothesis instead of exhaustively scanning.
- Spend cheap reconnaissance effort first; reserve deep, expensive testing for
  the single best surface.
- One target, two runs. If the second run on the same surface finds nothing new,
  move to different surface rather than a bigger scan.
- If a program's published maximum payout is below the cost of a deep run, skip
  it — that is arithmetic, not judgement.

## Program-tier guidance

- **Wide public programs** — huge duplicate pressure; only fresh surface and
  logic flaws pay.
- **Mid-size SaaS with a real payout table** — best ratio of competition to
  reward for an agent-assisted hunter; triage is usually responsive.
- **Vendor VRPs** (platform/OS level) — deep, expensive, and dominated by
  specialists; the entry tier is reachable, the top tier is not a first target.
- **VDP-only** — useful for reputation and for learning triage behavior; no cash.
- **Private invites** — highest signal, lowest competition; they arrive after a
  couple of accepted public findings, so early work should optimize for
  acceptance rate rather than payout size.
