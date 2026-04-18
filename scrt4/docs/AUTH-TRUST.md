# Auth Flow Trust Model

> What does a user need to trust when they run scrt4 against `auth.llmsecrets.com`,
> and what can we prove about that trust boundary cryptographically vs. what must
> be taken on faith?

## TL;DR

Running scrt4 means trusting:

1. **Your hardware authenticator** (YubiKey, passkey provider, Bitwarden, phone).
   The master key is derived here via FIDO2 `hmac-secret` / WebAuthn PRF and
   **never leaves the device.** This part is cryptographic — nothing scrt4
   does can weaken it.

2. **Your local machine** (daemon + CLI). The daemon holds decrypted secrets
   in memory while a session is active and writes the encrypted vault to
   `~/.scrt4/`. If your machine is compromised, nothing else matters.

3. **`auth.llmsecrets.com`** to serve honest JavaScript and not exfiltrate
   the PRF output. The current architecture requires this trust. This document
   explains exactly what that means and what we propose to reduce the trust
   surface.

The core cryptography (hmac-secret, AES-256-GCM vault) is sound and
independently auditable. The trust gap is at the **relay layer**, not the
crypto layer.

## What `auth.llmsecrets.com` does

The relay exists because scrt4's daemon runs on a desktop (Linux/macOS) that
may not have a local FIDO2 authenticator wired in, and because cross-device
WebAuthn with caBLE needs a browser to act as the WebAuthn client. Flow:

```
┌─────────────┐                ┌──────────────────────┐              ┌──────────────┐
│ scrt4       │ 1. QR code w/  │ auth.llmsecrets.com  │ 4. encrypted │ User's phone │
│ daemon      │─── URL ──────▶ │  - serves auth.html  │◀─ payload ───│ (browser +   │
│ (desktop)   │                │  - relays blob       │              │  FIDO2 auth) │
│             │ 5. polls,      │                      │              │              │
│             │◀── gets ───────│                      │              │              │
│             │    encrypted   │                      │ 3. runs JS,  │              │
└─────────────┘    payload     └──────────────────────┘   does       └──────────────┘
                                                          WebAuthn
                                                          PRF ceremony
                                                          locally
```

1. Desktop daemon generates: `prf_salt` (32B), `session_id` (20B), `wrapping_key` (32B).
2. Daemon encodes these into a URL served as a QR code.
3. User scans QR with phone. Phone's browser loads the auth page from
   `auth.llmsecrets.com/auth.html`. Page runs WebAuthn with PRF extension,
   talking to the local authenticator.
4. Phone encrypts the 32-byte PRF output with `wrapping_key` (AES-256-GCM)
   and POSTs it to `auth.llmsecrets.com/api/relay/<session_id>`.
5. Desktop daemon polls the relay, retrieves the encrypted blob, and
   decrypts it with the same `wrapping_key`.

The daemon then uses the PRF output as the master key to decrypt the vault.

## Cryptographic layer — sound

**What the authenticator does:**
- Input: the challenge + `prf_salt`.
- Output: `HMAC-SHA256(CredRandom, prf_salt)` — the hmac-secret result.
- The `CredRandom` material is bound to the hardware and only released
  after user presence (tap / biometric).
- The authenticator's cryptographic core is not scrt4 code; it's the
  FIDO2 authenticator firmware. Any claim about what it does can be
  verified against the WebAuthn + CTAP2 specs.

**What the vault does:**
- AES-256-GCM (authenticated encryption) keyed on the PRF output.
- Nonce + ciphertext + tag written to disk at `~/.scrt4/secrets.enc`.
- A malicious relay that never sees the PRF output cannot decrypt the vault.

**What the relay payload looks like on the wire:**
- AES-256-GCM ciphertext of `{ "prf_output": "<base64>" }`
- Keyed on `wrapping_key` — a 32-byte random value generated client-side
  on the desktop.
- The relay sees only the ciphertext + nonce. The plaintext PRF output
  is never in any packet the relay handles.

## Trust boundary — where the claim gets honest

The QR code URL on this branch looks like this:

```
https://auth.llmsecrets.com/auth.html?m=register&s=<session>&c=<challenge>&salt=<prf_salt>&rp=auth.llmsecrets.com#k=<wrapping_key>
```

Note that `k=<wrapping_key>` is in the **URL fragment** (after `#`), not
the query (after `?`). Fragments are never sent to the server by any
compliant HTTP client — the phone's browser strips them before
constructing the GET request, so the server cannot see the wrapping
key in its access logs, request lines, or any proxy it sits behind.
The JS on the auth page reads the fragment via `location.hash`.

This closes the passive-log scenario: a post-incident forensic dump
of the relay server would not reveal wrapping keys. One trust point
remains:

**The JS that runs in the phone's browser is served by `auth.llmsecrets.com`.**
Even though `wrapping_key` is in the URL fragment (not visible server-side),
the page's JavaScript runs after the fragment is delivered to the
browser and has full access to it via `location.hash`. A malicious
JS deploy could read the wrapping key (or the raw PRF output before
it's encrypted) and exfiltrate it to an arbitrary endpoint.

So the honest claim is: **the current architecture requires trusting
`auth.llmsecrets.com` to serve honest JavaScript.** A compromise of
the relay server at the asset-serving layer in combination with
separate malware that exfiltrates the encrypted vault file = full
vault disclosure.

## What a user can verify today

- **The daemon is open source.** Every byte that crosses the relay is
  constructed by code in this repo (`daemon/src/webauthn.rs`). You can
  audit that the daemon never sends unencrypted PRF output anywhere.
- **The crypto primitives are standard.** AES-256-GCM, HMAC-SHA256 —
  no custom schemes.
- **The relay never sees the master-key-derivation inputs.** The `CredRandom`
  that seeds the PRF output is inside the authenticator. Even a fully
  compromised relay cannot forge a registration without the authenticator.
- **Session replay is bounded.** Each session has a fresh `session_id`,
  `challenge`, and `wrapping_key`. Logging one session's keys does not
  compromise past or future sessions.

## What a user must still trust (today)

- `auth.llmsecrets.com/auth.html`'s JavaScript behaves as documented —
  WebAuthn ceremony, AES-GCM wrap, POST, done. No silent keylog, no
  exfil to a side channel.
- The server operator does not log `wrapping_key` from request URLs.

## Deployment requirement

The daemon on this branch writes `k` (wrapping_key) into the URL
fragment. The `auth.html` served at `https://auth.llmsecrets.com/auth.html`
**must be updated to read `k` from `location.hash` instead of
`location.search`** before this daemon version can authenticate
successfully. If the deployed auth.html still reads the query
string, the wrapping key will appear missing and the ceremony
will fail with a decrypt error.

The auth.html source lives in a separate (not-yet-public) repository.
Coordinate the daemon release with the auth.html deploy.

## Proposed hardening (not yet implemented)

### Publish `auth.html` source + SRI hashes

The HTML + JS served at `/auth.html` should live in a public repo
(this one, once the relay code is added) so anyone can audit what
the phone's browser runs. Pinning the deployed asset's SHA256 in
released scrt4 binaries lets the daemon refuse to proceed if the
served JS doesn't match the audited version.

**Effort: medium.** Requires publishing the relay server + auth page
source, building a hash-check into the daemon, and CI-driven deployment
pinning.

### Offer self-hosting (not configurable today — by design)

Long-term, an open-source scrt4 user should be able to run their own
relay. Today the relay URL is hardcoded to `auth.llmsecrets.com` in
`daemon/src/webauthn.rs` for two reasons:

1. Configurability introduces attack surface (misconfiguration = downgrade).
   We want that decision to be a deliberate code change, not a config flag.
2. The relay server source isn't public yet.

Once the relay is open-sourced with SRI-pinned assets, making the URL
configurable (with SHA pinning) becomes the natural next step.

## Threat scenarios

| Threat                                                                         | Protected? | Why / Why not                                                       |
|--------------------------------------------------------------------------------|------------|---------------------------------------------------------------------|
| Passive network observer sees traffic                                          | Yes        | TLS on the wire; PRF output is encrypted inside the TLS stream      |
| Attacker steals the vault file (`secrets.enc`)                                 | Yes        | AES-256-GCM keyed on hardware-derived PRF output                    |
| Attacker has only the hardware authenticator (no `secrets.enc`)                | Yes        | Hardware auth alone produces PRF output but no vault to decrypt     |
| Attacker logs `wrapping_key` from relay request URL + later gets `secrets.enc` | Yes        | `k` is in URL fragment (`#k=...`); never sent in HTTP requests      |
| Malicious JS served by relay                                                   | **No**     | Can read `location.hash` and PRF output directly before encryption  |
| Malicious daemon build                                                         | **No**     | Daemon already has the PRF output in cleartext                      |
| Phishing: user scans QR from wrong source                                      | Partial    | `rp_id` binds the credential to `auth.llmsecrets.com`; cross-origin attacks are scoped by WebAuthn |
| Cross-session replay                                                           | Yes        | `session_id`, `challenge`, `wrapping_key` all fresh per session     |

The remaining **No** row — malicious JS — is what published, SRI-pinned
auth page code would close. A malicious daemon build is covered by the
"don't install a backdoored daemon" precondition: the daemon already
holds the PRF output in plaintext after decryption, so no architectural
defense can protect a user from their own tampered binary. Verify the
daemon's SHA256 against `SHA256SUMS` on each release.

## Recommendation to users

- For most users, the current architecture is acceptable: the `auth.llmsecrets.com`
  operator is in the trust boundary but not the crypto boundary, and the
  hardware authenticator remains the root of trust.
- For users with a higher threat model, wait for the published
  `auth.html` source + SRI pinning before adopting scrt4.
- For anyone: do not treat `auth.llmsecrets.com` as out of scope. It is
  a trust-bearing party today. This document is the honest accounting
  of what that means.
