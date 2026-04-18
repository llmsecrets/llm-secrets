# scrt4 — WebAuthn PRF Authentication

## Problem Statement

In scrt3, the daemon holds the session key in memory after unlock. If the daemon process is compromised while unlocked, an attacker can read secrets from memory. The passphrase-based Argon2id derivation is strong at rest, but the symmetric nature means the daemon must hold the decryption capability.

**scrt4 Goal:** Even if the daemon is fully compromised, an attacker cannot decrypt secrets without authenticating via WebAuthn (Bitwarden, passkeys, or hardware keys through the browser).

## Architecture

### scrt3 (Current)

```
Passphrase ──→ Argon2id(passphrase, salt) ──→ wrapping_key [32 bytes]
                                                      │
                                          AES-256-GCM decrypt
                                                      │
                                                      ▼
                                               master_key [32 bytes]
                                                      │
                                          AES-256-CBC decrypt
                                                      │
                                                      ▼
                                               secrets.enc → HashMap
```

### scrt4

```
Bitwarden / Passkey / YubiKey
         │
         ▼
Browser WebAuthn API ──→ PRF extension(credential_id, salt)
                                        │
                              wrapping_key [32 bytes]
                                        │
                            AES-256-GCM decrypt    ← SAME as scrt3
                                        │
                                        ▼
                                 master_key [32 bytes]
                                        │
                            AES-256-CBC decrypt    ← SAME as scrt3
                                        │
                                        ▼
                                 secrets.enc → HashMap  ← SAME as scrt3
```

**Only the top layer changes.** The daemon acts as a local WebAuthn server. The browser
handles the credential provider — Bitwarden, Apple/Google passkeys, or hardware keys
(YubiKey, SoloKeys) — all through the same WebAuthn API. No direct USB HID code needed.

**Key insight:** WebAuthn PRF subsumes hardware key support. When a user plugs in a
YubiKey, the browser's credential picker offers it automatically. Hardware keys work
"for free" through the browser without needing the `ctap-hid-fido2` crate.

## Security Model Comparison

| Threat | scrt3 | scrt4 |
|--------|-------|-------|
| Daemon compromised (locked) | Attacker gets encrypted master.key, needs passphrase | Attacker gets encrypted master.key, needs authenticator |
| Daemon compromised (unlocked) | Attacker reads secrets from memory | Attacker reads secrets from memory (same) |
| Passphrase brute force | Argon2id (64MB, 3 iterations) | N/A — no passphrase |
| Shoulder surfing | Passphrase can be observed | Touch/biometric only, nothing to observe |
| Remote attack | Passphrase can be phished | WebAuthn is phishing-resistant by design |
| Stolen disk | Encrypted at rest, need passphrase | Encrypted at rest, need authenticator |
| Lost authenticator | N/A | Recovery flow needed (see below) |

### Key Advantage
The daemon only stores **public data** (credential_id, salt, public key, encrypted master key). None of these are useful without the authenticator. In scrt3, if an attacker gets the `master.key` file + a keylogger captures the passphrase, they have everything. In scrt4, even with all stored data + full daemon access, they need the physical token or Bitwarden passkey.

### Bitwarden Zero-Knowledge
Bitwarden's passkey implementation is zero-knowledge. The FIDO2 private key is encrypted
with the user's master password before syncing. Bitwarden's servers never see the private
key in plaintext. When scrt4 requests a WebAuthn assertion, Bitwarden decrypts the passkey
locally, signs the challenge locally, and only the assertion (signature + PRF output) is
returned to the daemon.

## Key Derivation: WebAuthn PRF Extension

The PRF extension is the WebAuthn (browser-facing) equivalent of CTAP2's hmac-secret.
When a relying party requests PRF via the browser, the browser translates it to
hmac-secret at the CTAP2 level for hardware keys, or the software authenticator
(Bitwarden, OS passkey provider) computes it internally.

```
Input:  salt [32 bytes] (passed via PRF extension in navigator.credentials.get())
Output: HMAC-SHA-256(per_credential_secret, salt) → 32 bytes
```

- The per-credential secret is generated during `navigator.credentials.create()` and never exported
- The same (credential, salt) always produces the same 32-byte output
- Different salts produce cryptographically independent outputs
- The output is only produced after user verification (touch/PIN/biometric)
- Works with ANY WebAuthn-compatible credential provider
- Communication: browser → WebAuthn API → credential provider → daemon callback

### Supported Authenticators (all via WebAuthn — no special code per provider)

| Authenticator | Type | PRF Support |
|---------------|------|-------------|
| Bitwarden | Software passkey | Yes (via browser extension / OS integration) |
| Apple Passkeys | Platform authenticator | Yes (iOS 17+, macOS Sonoma+) |
| Google Passkeys | Platform authenticator | Yes (Android 14+, Chrome) |
| 1Password | Software passkey | Yes |
| YubiKey | Hardware (USB/NFC) | Yes (browser translates PRF → hmac-secret) |
| SoloKeys | Hardware (USB) | Yes |
| Google Titan | Hardware (USB/NFC/BLE) | Yes |

**No authenticator-specific code.** The browser handles the protocol translation.

## What Changes in the Crypto Core

### `keystore.rs` Modifications

**New on-disk format (version 2):**

```rust
#[derive(serde::Serialize, serde::Deserialize)]
struct MasterKeyFile {
    version: u32,                    // 2 (was 1)
    salt: String,                    // 32 bytes, base64 (was 16) — PRF salt
    nonce: String,                   // 12 bytes, base64 — same as v1
    ciphertext: String,              // AES-256-GCM encrypted master key — same as v1
    auth_method: AuthMethod,         // NEW
    webauthn: Option<WebAuthnConfig>,  // NEW
    argon2_params: Option<Argon2Params>,  // Only present for v1 compat
}

#[derive(serde::Serialize, serde::Deserialize)]
enum AuthMethod {
    Argon2id,      // scrt3 passphrase-based
    WebAuthnPrf,   // scrt4 WebAuthn PRF
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WebAuthnConfig {
    credential_id: String,   // base64 — identifies which credential to use
    rp_id: String,           // relying party ID ("localhost")
    public_key: String,      // base64 — for assertion signature verification
    aaguid: String,          // authenticator identifier (e.g., Bitwarden's AAGUID)
    authenticator_name: String,  // human-readable (e.g., "Bitwarden", "YubiKey 5 NFC")
    registered_at: String,   // ISO 8601
}
```

**New key derivation function:**

```rust
/// Derive wrapping key from WebAuthn PRF extension.
/// The browser/authenticator computes HMAC-SHA-256(per_credential_secret, salt).
/// This requires user interaction (touch/PIN/biometric) via the browser.
///
/// The daemon doesn't call this directly — it receives the PRF output
/// from the browser via the /auth/callback HTTP endpoint.
pub fn decrypt_master_key_with_prf(prf_output: &[u8; 32], master_key_file: &MasterKeyFile) -> Result<[u8; 32], String> {
    // prf_output IS the wrapping key (no further derivation needed)
    // Use it to AES-256-GCM decrypt the master key — same as scrt3's decrypt path
    let nonce = base64_decode(&master_key_file.nonce)?;
    let ciphertext = base64_decode(&master_key_file.ciphertext)?;
    aes_256_gcm_decrypt(prf_output, &nonce, &ciphertext)
}
```

**Functions that stay identical:**
- `generate_new_master_key()` — same random 32-byte key
- `decrypt_env_content_with_master_key()` — same AES-256-CBC
- `encrypt_env_content_with_master_key()` — same AES-256-CBC
- `parse_env()` — same .env parsing
- `decrypt_secrets()` / `save_encrypted_env()` — same vault operations

**Functions that need a new code path:**
- `save_master_key()` — use WebAuthn PRF output as wrapping key instead of Argon2id
- `load_master_key()` — receive PRF output from browser callback, unwrap master key
- `unlock_secrets()` — replace TOTP+passphrase flow with WebAuthn browser flow

### `totp.rs` → `webauthn.rs`

New module replacing TOTP:

```rust
// scrt4/src/webauthn.rs
//! WebAuthn PRF authentication via the daemon's local HTTP server.
//!
//! Replaces TOTP + Argon2id(passphrase) as the authentication and
//! key derivation mechanism. The daemon serves a WebAuthn challenge
//! page, the browser handles credential provider selection, and the
//! PRF output serves as the wrapping key.

/// WebAuthn credential configuration stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub credential_id: String,       // base64
    pub public_key: String,          // base64 (COSE key)
    pub rp_id: String,               // "localhost"
    pub aaguid: String,              // authenticator model identifier
    pub authenticator_name: String,  // human-readable
    pub registered_at: String,       // ISO 8601
}

/// Start the local HTTP server for WebAuthn authentication.
/// Serves GET /auth (challenge page) and POST /auth/callback (PRF receiver).
/// Returns the 32-byte PRF output after successful authentication.
pub async fn authenticate_via_browser(
    credential: &WebAuthnCredential,
    salt: &[u8; 32],
) -> Result<[u8; 32], String> {
    // 1. Generate random challenge
    // 2. Start HTTP listener on 127.0.0.1:8443
    // 3. Open browser to http://localhost:8443/auth?challenge=...&salt=...&cred_id=...
    // 4. Browser page calls navigator.credentials.get() with PRF extension
    // 5. User approves (touch/PIN/biometric) via their chosen authenticator
    // 6. Browser POSTs PRF output to /auth/callback
    // 7. Validate challenge, extract PRF output
    // 8. Shut down HTTP listener
    // 9. Return [u8; 32]
    todo!()
}

/// Register a new WebAuthn credential via the browser.
/// Opens browser for navigator.credentials.create() with PRF extension.
/// Returns credential info + initial PRF output for master key encryption.
pub async fn register_via_browser(
    rp_id: &str,
    salt: &[u8; 32],
) -> Result<(WebAuthnCredential, [u8; 32]), String> {
    // 1. Start HTTP listener
    // 2. Open browser to http://localhost:8443/register
    // 3. Browser calls navigator.credentials.create() with PRF extension
    // 4. User creates credential via Bitwarden/passkey/hardware key
    // 5. Browser POSTs credential + PRF output back
    // 6. Return credential info + initial wrapping key
    todo!()
}
```

## Unlock Flow

The daemon serves a WebAuthn challenge page. The browser handles credential
provider selection (Bitwarden, OS passkeys, hardware keys). No external server needed.

```
┌───────────┐  ┌──────────────────────────┐  ┌───────────┐  ┌──────────────┐
│   CLI      │  │   scrt4 Daemon           │  │  Browser   │  │  Bitwarden / │
│            │  │   (+ local HTTP server)  │  │            │  │  Passkey /   │
│            │  │                          │  │            │  │  YubiKey     │
└─────┬──────┘  └───────────┬──────────────┘  └─────┬──────┘  └──────┬───────┘
      │                     │                       │                │
      │  scrt4 unlock       │                       │                │
      │────────────────────>│                       │                │
      │                     │                       │                │
      │                     │  Generate challenge   │                │
      │                     │  (random bytes +      │                │
      │                     │   salt from config)   │                │
      │                     │                       │                │
      │                     │  Start HTTP listener  │                │
      │                     │  127.0.0.1:8443       │                │
      │                     │                       │                │
      │                     │  Open browser to      │                │
      │                     │  http://localhost:     │                │
      │                     │  8443/auth?challenge=… │                │
      │                     │──────────────────────>│                │
      │                     │                       │                │
      │                     │    navigator.credentials.get({        │
      │                     │      publicKey: {                     │
      │                     │        challenge,                     │
      │                     │        rpId: "localhost",             │
      │                     │        allowCredentials: [cred_id],   │
      │                     │        extensions: {                  │
      │                     │          prf: { eval: { first: salt }}│
      │                     │        }                              │
      │                     │      }                                │
      │                     │    })                                 │
      │                     │                       │                │
      │                     │                       │  Credential    │
      │                     │                       │  provider      │
      │                     │                       │  prompt        │
      │                     │                       │───────────────>│
      │                     │                       │                │
      │                     │                       │  User approves │
      │                     │                       │  (touch/PIN/   │
      │                     │                       │   biometric)   │
      │                     │                       │                │
      │                     │                       │  PRF output +  │
      │                     │                       │  assertion     │
      │                     │                       │<───────────────│
      │                     │                       │                │
      │                     │  POST /auth/callback  │                │
      │                     │  { prf_output: [32B], │                │
      │                     │    signature, etc }   │                │
      │                     │<──────────────────────│                │
      │                     │                       │                │
      │                     │  ✓ Validated           │                │
      │                     │──────────────────────>│  (auto-close)  │
      │                     │                       │                │
      │                     │  Shut down HTTP listener               │
      │                     │                       │                │
      │                     │  AES-256-GCM decrypt  │                │
      │                     │  master.key with PRF  │                │
      │                     │                       │                │
      │                     │  AES-256-CBC decrypt  │                │
      │                     │  secrets.enc          │                │
      │                     │                       │                │
      │  "Unlocked (42      │                       │                │
      │   secrets, 2h TTL)" │                       │                │
      │<────────────────────│                       │                │
```

## Daemon as WebAuthn Server — Implementation Details

The daemon already runs as a long-lived process. For authentication, it adds a
lightweight HTTP listener that serves three endpoints:

### Endpoints

**1. `GET /auth?challenge=…&salt=…&cred_id=…`** — Serves the WebAuthn assertion page

A single self-contained HTML page (~50 lines) with inline JavaScript that:
- Calls `navigator.credentials.get()` with the PRF extension
- Posts the PRF output back to the daemon
- Shows success/failure and auto-closes

```html
<!-- Served by the daemon — no external dependencies -->
<html>
<body>
  <h2>scrt4 — Authenticate</h2>
  <p id="status">Waiting for authenticator...</p>
  <script>
    (async () => {
      const params = new URLSearchParams(location.search);
      const challenge = Uint8Array.from(atob(params.get('challenge')), c => c.charCodeAt(0));
      const salt = Uint8Array.from(atob(params.get('salt')), c => c.charCodeAt(0));
      const credentialId = Uint8Array.from(atob(params.get('cred_id')), c => c.charCodeAt(0));

      try {
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge,
            rpId: 'localhost',
            allowCredentials: [{ type: 'public-key', id: credentialId }],
            extensions: {
              prf: { eval: { first: salt } }
            }
          }
        });

        const prfResult = assertion.getClientExtensionResults().prf?.results?.first;
        if (!prfResult) throw new Error('PRF extension not supported by this authenticator');

        const resp = await fetch('/auth/callback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            prf_output: btoa(String.fromCharCode(...new Uint8Array(prfResult))),
            authenticator_data: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
            signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)))
          })
        });

        document.getElementById('status').textContent = resp.ok
          ? '✓ Authenticated — you can close this tab'
          : '✗ Failed — check terminal';
      } catch (e) {
        document.getElementById('status').textContent = '✗ ' + e.message;
      }
    })();
  </script>
</body>
</html>
```

**2. `GET /register`** — Serves the WebAuthn credential creation page (setup only)

Similar page that calls `navigator.credentials.create()` with PRF extension enabled.
Used during `scrt4 setup` to register the initial credential.

**3. `POST /auth/callback`** — Receives the PRF output

- Validates the one-time challenge token (prevents replay)
- Extracts the 32-byte PRF output
- Optionally verifies the assertion signature against stored public key
- Uses PRF output as wrapping key for AES-256-GCM master key decryption
- Shuts down the HTTP listener (single-use)

### Security of the Local Server

| Concern | Mitigation |
|---------|------------|
| TLS | Not required — WebAuthn spec treats `localhost` as secure context even over HTTP |
| Replay attacks | One-time challenge token, invalidated after first callback |
| Cross-origin attacks | CORS restricted to `localhost` only |
| Port hijacking | Daemon binds `127.0.0.1` only (not `0.0.0.0`), random port with fallback |
| PRF output in transit | Never leaves `localhost` — browser → daemon on same machine |
| Page served by daemon | No CDN, no external scripts, fully self-contained inline HTML |
| Browser tab left open | Auto-closes after callback; challenge expires after 60 seconds |

### localhost and TLS

Per the WebAuthn spec, `localhost` is treated as a secure context even over plain HTTP.
This means **TLS is not needed**. The daemon serves `http://localhost:8443/auth`
and `navigator.credentials.get()` works. No self-signed certificate warnings.

## Setup Flow

```bash
$ scrt4 setup
[1/3] Opening browser to register a WebAuthn credential...
      (Select Bitwarden, a passkey, or insert a hardware key)
      ✓ Credential registered (Bitwarden, aaguid: d548826e...)
[2/3] Authenticate again to verify...
      ✓ PRF extension working — wrapping key derived
[3/3] Generating master key and encrypting with WebAuthn PRF...
      ✓ Master key encrypted (AES-256-GCM)

Setup complete!
  Config:     ~/.scrt4/webauthn.json
  Master key: ~/.scrt4/master.key (encrypted, needs authenticator to decrypt)
  Vault:      ~/.scrt4/vault/secrets.enc

To unlock: scrt4 unlock (opens browser for authentication)
```

## Migration from scrt3

```bash
$ scrt4 migrate-from-scrt3
[1/3] Unlock scrt3 first...
      Enter passphrase: ********
      Enter TOTP code: 123456
      ✓ scrt3 unlocked (42 secrets)
[2/3] Register WebAuthn credential for scrt4...
      (Opens browser — select Bitwarden or insert hardware key)
      ✓ Credential registered
[3/3] Re-encrypting secrets with WebAuthn PRF...
      ✓ 42 secrets migrated to scrt4

scrt3 data preserved at ~/.scrt3 (can be removed after verification)
```

## Recovery Flow

**Problem:** If the authenticator is lost (Bitwarden account locked, hardware key lost),
all secrets are unrecoverable (by design — this IS the security property).

**Solutions:**

### Option A: Backup Authenticator [Pro]
- Register a second WebAuthn credential during setup (different provider or second hardware key)
- Store backup hardware key in a safe/deposit box
- `~/.scrt4/master.key` has two encrypted copies of the master key (one per credential)

### Option B: Recovery Passphrase [Pro]
- During setup, also derive a backup wrapping key via Argon2id (like scrt3)
- Store this as a second entry in `master.key` with `auth_method: Argon2id`
- Recovery: `scrt4 recover --passphrase`
- Trade-off: Re-introduces passphrase as a backup vector (but it's optional)

### Option C: Shamir Secret Sharing [Pro]
- Split the master key into N shares (e.g., 3-of-5)
- Distribute to trusted parties
- Recovery requires assembling threshold shares
- Most secure but most complex

**Recommended: Option A (backup authenticator) + Option B (emergency passphrase)**

## On-Disk File Structure

```
~/.scrt4/
├── webauthn.json     # Credential ID, public key, rp_id, aaguid (PUBLIC data)
├── master.key        # AES-256-GCM encrypted master key (needs authenticator to decrypt)
├── vault/
│   └── secrets.enc   # AES-256-CBC encrypted secrets (same format as scrt3)
└── backup/
    └── master.key.bak # Optional: second credential or passphrase backup
```

## Rust Dependencies

```toml
[dependencies]
# ── WebAuthn Server ──────────────────────────────────
axum = "0.7"                    # Local HTTP server (2 endpoints)
webauthn-rs = "0.5"             # Server-side assertion verification
tokio = { version = "1", features = ["full"] }  # Async runtime

# ── Crypto (same as scrt3) ───────────────────────────
aes-gcm = "0.10"                # Master key wrapping
aes = "0.8"                     # Vault encryption
cbc = "0.1"                     # Vault encryption mode
rand = "0.8"                    # Challenge generation, salt generation
base64 = "0.21"                 # Encoding

# ── Serialization ────────────────────────────────────
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# ── Daemon ───────────────────────────────────────────
tracing = "0.1"                 # Logging
tracing-subscriber = "0.3"
dirs = "5"                      # Home directory

# ── Migration (optional) ────────────────────────────
argon2 = { version = "0.5", optional = true }  # Only for scrt3 migration

[features]
default = []
migrate = ["argon2"]            # Enable scrt3 migration support
```

**Notable:** No `ctap-hid-fido2` crate. All authenticator communication goes through
the browser's WebAuthn API. This eliminates USB HID platform-specific code entirely.

## What Stays the Same

| Component | Changes? | Notes |
|-----------|----------|-------|
| `keystore.rs` AES-256-GCM wrapping | No | Same encrypt/decrypt, different wrapping key source |
| `keystore.rs` AES-256-CBC vault | No | Identical format |
| `session.rs` | No | Same session management, TTL, challenges |
| `subprocess.rs` | No | Same `$env[NAME]` injection |
| `sanitize.rs` | No | Same output redaction |
| `audit.rs` | Minor | Add WebAuthn event types |
| `handlers.rs` | Yes | New unlock handler (WebAuthn browser flow) |
| `protocol.rs` | Yes | New request/response for WebAuthn unlock |
| `main.rs` | Yes | Config dir `.scrt4`, HTTP listener for WebAuthn |
| `totp.rs` | Replaced | By `webauthn.rs` |

## Implementation Plan

### Phase 1: WebAuthn Server + Auth Page
1. Add `axum` + `webauthn-rs` dependencies
2. Implement HTTP listener on `127.0.0.1:8443`
3. Serve WebAuthn assertion page at `GET /auth`
4. Implement `POST /auth/callback` to receive PRF output
5. Serve WebAuthn registration page at `GET /register`
6. One-time challenge validation (anti-replay)
7. Auto-open browser via `xdg-open` / `open` / `start`

### Phase 2: Keystore Integration
1. Extend `MasterKeyFile` to version 2 with `AuthMethod` enum
2. New `WebAuthnConfig` struct (credential_id, public_key, rp_id, aaguid)
3. `save_master_key_webauthn()` — uses PRF output as wrapping key
4. `load_master_key_webauthn()` — receives PRF from browser callback → unwrap
5. Keep v1 compatibility for migration

### Phase 3: Daemon Integration
1. New `setup` handler — opens browser for credential registration
2. New `unlock` handler — opens browser for WebAuthn assertion
3. Update `protocol.rs` with WebAuthn request/response types
4. Update config dir to `~/.scrt4`
5. Store `webauthn.json` on disk (public credential data)

### Phase 4: CLI + Migration
1. `scrt4 setup` command (register credential via browser)
2. `scrt4 unlock` command (authenticate via browser)
3. `scrt4 migrate-from-scrt3` command
4. `scrt4 status`, `scrt4 run`, `scrt4 list` (same as scrt3)
5. `scrt4 unlock --no-browser` (print URL instead of auto-opening)

### Phase 5: Recovery + Multi-Auth [Pro]
1. Register additional credentials (`scrt4 auth add`)
2. Multiple encrypted copies of master key in `master.key`
3. Optional passphrase backup (Argon2id)
4. `scrt4 recover` command
5. Shamir secret sharing (N-of-M)
6. Per-credential audit trail

### Future: Direct CTAP2 Path (Optional Optimization)
- Add `ctap-hid-fido2` crate for direct USB HID communication
- `scrt4 unlock --usb` bypasses browser entirely
- Same PRF/hmac-secret math, different transport
- Useful for headless servers or environments without a browser
- Not needed for v1 — WebAuthn covers all authenticator types

## Open Questions

1. **Should scrt4 be a new binary or a mode in scrt3?**
   - Recommendation: New binary (`scrt4-daemon`), separate config dir (`~/.scrt4`)
   - Allows running both simultaneously during migration

2. **PIN policy?**
   - Authenticators can require a PIN before touch
   - Should scrt4 enforce PIN? (Adds a knowledge factor back)
   - Recommendation: Let the authenticator's policy decide

3. ~~**Bitwarden CLI integration?**~~ DECIDED: No
   - Bitwarden CLI (`bw`) doesn't expose passkey assertions or PRF
   - WebAuthn PRF via browser is the standard, vendor-neutral approach
   - Works with any credential provider, not just Bitwarden

4. ~~**Direct CTAP2 USB support?**~~ DEFERRED to post-v1
   - WebAuthn PRF handles hardware keys through the browser
   - Direct USB is a future optimization for headless/no-browser environments

5. **Browser auto-open behavior?**
   - `scrt4 unlock` auto-opens browser by default
   - `scrt4 unlock --no-browser` prints URL for manual navigation
   - Recommendation: Auto-open with `xdg-open` / `open` / `start`

## Licensing

This project uses a dual-license model. See `LICENSE.md` for full details.

| Tier | License | Features |
|------|---------|----------|
| Community | GPLv3 | WebAuthn auth (any provider), full CLI, crypto core, single credential |
| Pro | Commercial (source-available) | Multi-auth, recovery flows, team vaults, Shamir sharing |

The `src/pro/` directory is gated behind the `pro` Cargo feature flag
and governed by `LICENSE_COMMERCIAL.txt`. All other code is GPLv3.
