# Security Policy

<!--
  Canonical security policy for this repository.

  It lives at the repository root because GitHub only surfaces a policy from
  /SECURITY.md, /.github/SECURITY.md or /docs/SECURITY.md. A copy in a
  subdirectory is not shown on the Security tab and does not enable the
  "Report a vulnerability" button.

  PLACEHOLDER NOTES FOR MAINTAINERS (visible in raw source, so keep them free
  of anything not intended to be public):
    - Hall of Fame entries are added as reporters approve being named.
    - The programme-status line is written to be true at all times; update it
      when the position changes rather than leaving it aspirational.
-->

## Reporting a Vulnerability

If you discover a security vulnerability, **please report it responsibly**. Do
not open a public GitHub issue.

Preferred: **[Report a vulnerability](../../security/advisories/new)** through
GitHub's private reporting. It creates a private draft advisory that only you
and the maintainer can see, and it is the same object the eventual public
advisory is published from — so you can review and correct it before anything
goes out.

Alternative: **security@llmsecrets.com**
PGP key available on request (reply to your initial report).

### What to Include

- Description of the vulnerability and its impact
- Steps to reproduce (proof of concept)
- Affected component (daemon, CLI, relay, protocol)
- Your suggested severity (Critical / High / Medium / Low)

### Response Timeline

| Stage | Target |
|-------|--------|
| First response | 48 hours |
| Triage & severity assessment | 7 days |
| Fix for Critical/High | 14 days |
| Fix for Medium/Low | 30 days |
| Public disclosure | After the fix is released, coordinated with the reporter |

---

## Rewards

**Read this before you spend time on this project.** We would rather you decide
with accurate information than find out afterwards.

This is an unfunded project. It has no revenue and no security budget.

**There is no cash reward.** What we offer is recognition, and we try to offer it
at full weight rather than as an apology for the absence of money. The detail is
below, along with an honest account of why the payout table that used to sit here
is gone.

If you reported against that old table, contact us — we will not treat you as
having missed a window.

### Recognition — offered at full weight

This is the part we can deliver, so we treat it as the primary reward rather
than a consolation for the money.

| | |
|---|---|
| **Front-page credit** | Your name and your finding on the front page of llmsecrets.com — not a buried credits page. This is the reward, not a consolation for the absence of one. |
| **CVE** | Requested through a GitHub Security Advisory, formally crediting you. GitHub is a CNA, so the identifier is assigned directly. Permanent, indexed in the national vulnerability databases, citable indefinitely. |
| **Advisory credit** | Your GitHub account in the advisory's structured Credits field, and an invitation onto the draft advisory before it is published. |
| **Hall of Fame** | A permanent entry in this repository. |
| **Commit credit** | `Co-Authored-By` on the commits your report shaped, plus changelog and release-note credit. |
| **Reference** | A written reference from the maintainer at any point, if it is ever useful to you. |

Credit goes up as soon as you approve it. We will not ask you to wait on work
that is already done.

**The published advisory is the one thing that waits**, and we would rather
explain than let it look like a stall. An advisory carries the vulnerability
details, and it is only useful to a reader once the fixed build is something
they can actually install. Publishing before that point hands a working
description of a live issue to the people still running the old version. So the
advisory ships with the release that carries the fix — which is also the moment
its "patched versions" field becomes a true statement rather than an aspiration.

**Anonymity is always available** — before, during or after — and choosing it
costs you nothing else on this list.

### Money — there isn't any, and we would rather say so

**There is no cash reward.** This project has no revenue and no security budget.

An earlier version of this document promised $500–$2,000 for a Critical. We
could not honour it. We are not going to replace that with a smaller figure we
might also fail to pay, or with a share of revenue that does not exist — the
mistake was publishing a number, not publishing the wrong number.

If that makes this programme not worth your time, we would much rather you knew
before you started than after.

If the project ever earns anything, we will revisit this — and we will go back
to the people who reported before it changed, rather than treating them as
having missed a window.

### What we will not do

- Publish a payout figure we cannot honour. That is the mistake this section
  exists to correct.
- Argue a finding down in severity to reduce what we owe. Severity is assessed
  on impact; if you disagree with our assessment, say so and we will genuinely
  reconsider.
- Pursue legal action against anyone acting in good faith within this policy.

---

## Scope

### In Scope

- The daemon and its socket / named-pipe protocol
- The CLI clients
- The browser-based authentication page and its relay
- Vault storage format and key wrapping
- Anything that lets a caller obtain a secret value without the authorisation
  the product claims to require

### Out of Scope

- Attacks requiring physical access to an unlocked machine
- Social engineering of the maintainer or of users
- Denial of service through resource exhaustion
- Vulnerabilities in third-party dependencies without a demonstrated exploit
  path through this project
- Findings from automated scanners without a working proof of concept
- Anything requiring a build with authentication deliberately disabled

---

## Disclosure Policy

- We practise **coordinated disclosure**. Reporters get credit in the changelog
  and release notes unless they prefer anonymity.
- We aim to fix Critical/High issues before public disclosure.
- If we are unresponsive beyond our stated timelines, reporters may disclose
  after 90 days.
- We will never pursue legal action against researchers acting in good faith
  within this policy.

---

## Programme Status

This programme received its first reports in **August 2026**. It is being
formalised as it goes: private vulnerability reporting, the advisory workflow
and this policy were all put in place in response to those first reports rather
than before them. If something here is unclear or looks wrong, say so — the
process is young enough that it is still worth changing.

## Hall of Fame

<!-- Entries are added as reporters approve being named. -->

*No entries published yet.*
