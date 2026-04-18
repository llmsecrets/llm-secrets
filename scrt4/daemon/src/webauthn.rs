//! WebAuthn PRF authentication module for scrt4.
//!
//! Uses auth.llmsecrets.com as a relay: the daemon shows a QR code in the
//! terminal, the user scans it with their phone, the phone runs the WebAuthn
//! ceremony locally (with Bitwarden as the authenticator), encrypts the PRF
//! output, and posts it to the relay. The daemon polls the relay and decrypts.
//!
//! State files:
//!   ~/.scrt4/webauthn.json       — credential config (public data)
//!   ~/.scrt4/wa-2fa.state        — 2FA enabled/disabled for reveal operations
//!   ~/.scrt4/wa-2fa-unlock.state — 2FA enabled/disabled for unlock operations

use std::path::PathBuf;

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::keystore;

// ── Types ──────────────────────────────────────────────────────────

/// WebAuthn credential configuration stored on disk at ~/.scrt4/webauthn.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub credential_id: String,       // base64
    pub public_key: String,          // base64 COSE key
    pub rp_id: String,               // "auth.llmsecrets.com"
    pub aaguid: String,              // authenticator model identifier
    pub authenticator_name: String,  // human-readable (e.g., "Bitwarden")
    pub registered_at: String,       // ISO 8601
}

/// Result from WebAuthn registration
#[derive(Debug)]
pub struct RegistrationResult {
    pub credential: WebAuthnCredential,
    pub prf_output: [u8; 32],
}

/// Result from WebAuthn authentication (assertion)
#[derive(Debug)]
pub struct AuthResult {
    pub prf_output: [u8; 32],
}

// ── Path helpers ───────────────────────────────────────────────────

/// Get the WebAuthn credential config path (~/.scrt4/webauthn.json)
pub fn get_credential_path() -> PathBuf {
    keystore::config_dir().join("webauthn.json")
}

/// Get the 2FA state file path for reveal operations
pub fn get_wa_state_path() -> PathBuf {
    keystore::config_dir().join("wa-2fa.state")
}

/// Get the 2FA state file path for unlock operations
pub fn get_wa_unlock_state_path() -> PathBuf {
    keystore::config_dir().join("wa-2fa-unlock.state")
}

// ── Credential persistence ────────────────────────────────────────

/// Check if a WebAuthn credential has been registered
pub fn is_wa_configured() -> bool {
    get_credential_path().exists()
}

/// Load the stored WebAuthn credential
pub fn load_credential() -> Result<WebAuthnCredential, String> {
    let path = get_credential_path();
    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read WebAuthn credential at {:?}: {}. Run 'scrt4 setup' first.", path, e))?;
    serde_json::from_str(&json)
        .map_err(|e| format!("Invalid WebAuthn credential file: {}", e))
}

/// Save a WebAuthn credential to disk with restricted permissions
pub fn save_credential(credential: &WebAuthnCredential) -> Result<(), String> {
    let path = get_credential_path();

    // Create parent directory
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create ~/.scrt4 directory: {}", e))?;
    }

    let json = serde_json::to_string_pretty(credential)
        .map_err(|e| format!("Failed to serialize credential: {}", e))?;

    std::fs::write(&path, &json)
        .map_err(|e| format!("Failed to write WebAuthn credential: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    tracing::info!("WebAuthn credential saved to {:?}", path);
    Ok(())
}

// ── Localhost credential persistence ─────────────────────────────

/// Get the localhost credential config path (~/.scrt4/webauthn-local.json)
pub fn get_local_credential_path() -> PathBuf {
    keystore::config_dir().join("webauthn-local.json")
}

/// Check if a localhost WebAuthn credential has been registered
pub fn is_local_configured() -> bool {
    get_local_credential_path().exists()
}

/// Load the stored localhost WebAuthn credential
pub fn load_local_credential() -> Result<WebAuthnCredential, String> {
    let path = get_local_credential_path();
    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("No localhost credential: {}", e))?;
    serde_json::from_str(&json)
        .map_err(|e| format!("Invalid localhost credential file: {}", e))
}

/// Save a localhost WebAuthn credential to disk
pub fn save_local_credential(credential: &WebAuthnCredential) -> Result<(), String> {
    let path = get_local_credential_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create ~/.scrt4 directory: {}", e))?;
    }

    let json = serde_json::to_string_pretty(credential)
        .map_err(|e| format!("Failed to serialize credential: {}", e))?;
    std::fs::write(&path, &json)
        .map_err(|e| format!("Failed to write localhost credential: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    tracing::info!("Localhost WebAuthn credential saved to {:?}", path);
    Ok(())
}

// ── 2FA state management ──────────────────────────────────────────

/// Check if WebAuthn 2FA is enabled for reveal operations.
/// Returns true if credential is configured AND state is not explicitly "disabled".
pub fn is_wa_enabled() -> bool {
    if !is_wa_configured() {
        return false;
    }
    let state_path = get_wa_state_path();
    match std::fs::read_to_string(&state_path) {
        Ok(contents) => contents.trim() != "disabled",
        Err(_) => true, // File absent + credential configured = enabled
    }
}

/// Set the WebAuthn 2FA state for reveal operations.
pub fn set_wa_state(enabled: bool) -> Result<(), String> {
    let state_path = get_wa_state_path();

    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create ~/.scrt4 directory: {}", e))?;
    }

    let content = if enabled { "enabled" } else { "disabled" };
    std::fs::write(&state_path, content)
        .map_err(|e| format!("Failed to write WA 2FA state: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    Ok(())
}

/// Check if WebAuthn 2FA is enabled for unlock operations.
pub fn is_wa_unlock_enabled() -> bool {
    if !is_wa_configured() {
        return false;
    }
    let state_path = get_wa_unlock_state_path();
    match std::fs::read_to_string(&state_path) {
        Ok(contents) => contents.trim() != "disabled",
        Err(_) => true,
    }
}

/// Set the WebAuthn 2FA state for unlock operations.
pub fn set_wa_unlock_state(enabled: bool) -> Result<(), String> {
    let state_path = get_wa_unlock_state_path();

    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create ~/.scrt4 directory: {}", e))?;
    }

    let content = if enabled { "enabled" } else { "disabled" };
    std::fs::write(&state_path, content)
        .map_err(|e| format!("Failed to write WA 2FA unlock state: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    Ok(())
}

// ── PRF salt management ───────────────────────────────────────────

/// Generate a random 32-byte PRF salt
pub fn generate_prf_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

// ── Relay-based WebAuthn flow via auth.llmsecrets.com ─────────────

const AUTH_PAGE_BASE: &str = "https://auth.llmsecrets.com/auth.html";
const RELAY_BASE: &str = "https://auth.llmsecrets.com/api/relay";

/// Generate a random hex string of given byte length (internal)
fn generate_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a random hex string of given byte length (public, for localhost module)
pub fn generate_hex_public(len: usize) -> String {
    generate_hex(len)
}

/// Render a QR code as Unicode block characters to stdout
fn print_qr_to_terminal(url: &str) {
    use qrcode::QrCode;

    let code = match QrCode::new(url.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to generate QR code: {}", e);
            eprintln!("Open this URL on your phone: {}", url);
            return;
        }
    };

    let width = code.width();
    let data = code.into_colors();

    // Use Unicode half-block characters for compact rendering
    // Each character row encodes 2 QR rows using ▀ ▄ █ and space
    let quiet = 2;
    let total_w = width + quiet * 2;
    let total_h = width + quiet * 2;

    println!();
    let mut row = 0;
    while row < total_h {
        print!("  "); // left margin
        for col in 0..total_w {
            let top_dark = if row >= quiet && row < quiet + width && col >= quiet && col < quiet + width {
                data[(row - quiet) * width + (col - quiet)] == qrcode::Color::Dark
            } else {
                false
            };
            let bot_dark = if row + 1 >= quiet && row + 1 < quiet + width && col >= quiet && col < quiet + width {
                data[(row + 1 - quiet) * width + (col - quiet)] == qrcode::Color::Dark
            } else {
                false
            };

            match (top_dark, bot_dark) {
                (true, true)   => print!("█"),
                (true, false)  => print!("▀"),
                (false, true)  => print!("▄"),
                (false, false) => print!(" "),
            }
        }
        println!();
        row += 2;
    }
    println!();
}

/// Decrypt an AES-256-GCM encrypted payload from the relay.
/// Format: base64(iv[12] || ciphertext || tag[16])
fn decrypt_relay_payload(encrypted_b64: &str, key_hex: &str) -> Result<serde_json::Value, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    use base64::Engine;

    let engine = base64::engine::general_purpose::STANDARD;
    let combined = engine.decode(encrypted_b64)
        .map_err(|e| format!("Failed to decode relay payload: {}", e))?;

    if combined.len() < 12 + 16 {
        return Err("Relay payload too short".into());
    }

    let key_bytes = hex::decode(key_hex)
        .map_err(|e| format!("Invalid wrapping key: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Wrapping key must be 32 bytes".into());
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    let nonce = Nonce::from_slice(&combined[..12]);
    let ciphertext = &combined[12..];

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Failed to decrypt relay payload (wrong key or tampered data)".to_string())?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Invalid JSON in decrypted payload: {}", e))
}

/// Poll the relay until the phone posts a result, or timeout.
async fn poll_relay(session_id: &str, timeout_secs: u64) -> Result<String, String> {
    let url = format!("{}/{}", RELAY_BASE, session_id);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        if std::time::Instant::now() >= deadline {
            return Err("Timed out waiting for phone authentication (120s)".into());
        }

        // Simple HTTP GET using a TCP connection
        let response = tokio::task::spawn_blocking({
            let url = url.clone();
            move || {
                std::process::Command::new("curl")
                    .args(&["-sf", &url])
                    .output()
            }
        }).await
            .map_err(|e| format!("Poll task failed: {}", e))?
            .map_err(|e| format!("curl failed: {}", e))?;

        if response.status.success() {
            let body = String::from_utf8(response.stdout)
                .map_err(|e| format!("Invalid UTF-8 from relay: {}", e))?;
            return Ok(body);
        }

        // Not ready yet, wait 1.5 seconds before polling again
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }
}

/// Parameters for a pending WebAuthn setup via relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySetupParams {
    pub url: String,
    pub session_id: String,
    pub wrapping_key: String,
    pub prf_salt_b64: String,
}

/// Percent-encode an action label for safe use as a URL query value.
/// Keeps RFC 3986 unreserved chars as-is; everything else becomes `%XX`.
/// This is used for the display-only `a=` param the auth page renders
/// above the FIDO2 prompt — it is NOT part of the signed WebAuthn
/// assertion, so treat the output as display guidance only.
fn percent_encode_action(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Generate relay setup parameters for registration.
/// Returns the URL for the QR code and session info.
/// The CLI displays the QR code and polls the relay.
///
/// `action` is an optional short human-readable label (e.g. "register new
/// passkey") rendered by auth.llmsecrets.com above the tap prompt so the
/// user sees what their computer asked for. It is NOT part of the WebAuthn
/// assertion's signed data — a compromised daemon could lie about it.
/// It's a UX hint, not a cryptographic claim.
pub fn generate_register_params(action: Option<&str>) -> Result<RelaySetupParams, String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let prf_salt = generate_prf_salt();
    let session_id = generate_hex(20);
    let wrapping_key = generate_hex(32);
    let mut challenge_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);

    let action_part = action
        .map(|a| format!("&a={}", percent_encode_action(a)))
        .unwrap_or_default();

    // wrapping_key lives in the URL fragment (#k=...), not the query.
    // Fragments are never sent to the server in HTTP requests, so the
    // relay operator cannot log the key from request lines / access logs.
    // See docs/AUTH-TRUST.md for the full trust model.
    let url = format!(
        "{}?m=register&s={}&c={}&salt={}&rp={}{}#k={}",
        AUTH_PAGE_BASE,
        session_id,
        engine.encode(challenge_bytes),
        engine.encode(&prf_salt),
        "auth.llmsecrets.com",
        action_part,
        wrapping_key
    );

    Ok(RelaySetupParams {
        url,
        session_id,
        wrapping_key,
        prf_salt_b64: engine.encode(prf_salt),
    })
}

/// Generate relay auth parameters for authentication (unlock).
///
/// See `generate_register_params` for the `action` label contract —
/// display-only, not part of the signed assertion.
pub fn generate_auth_params(
    credential: &WebAuthnCredential,
    salt: &[u8; 32],
    action: Option<&str>,
) -> Result<RelaySetupParams, String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let session_id = generate_hex(20);
    let wrapping_key = generate_hex(32);
    let mut challenge_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);

    let action_part = action
        .map(|a| format!("&a={}", percent_encode_action(a)))
        .unwrap_or_default();

    // See the register flow above — wrapping_key moves to the URL
    // fragment so the relay server never receives it in request URLs.
    let url = format!(
        "{}?m=auth&s={}&c={}&salt={}&cred={}&rp={}{}#k={}",
        AUTH_PAGE_BASE,
        session_id,
        engine.encode(challenge_bytes),
        engine.encode(salt),
        &credential.credential_id,
        "auth.llmsecrets.com",
        action_part,
        wrapping_key
    );

    Ok(RelaySetupParams {
        url,
        session_id,
        wrapping_key,
        prf_salt_b64: engine.encode(salt),
    })
}

/// Complete registration by decrypting the relay payload.
/// Called after the CLI polls the relay and gets the encrypted blob.
pub fn complete_registration(
    encrypted_payload: &str,
    wrapping_key: &str,
) -> Result<RegistrationResult, String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let data = decrypt_relay_payload(encrypted_payload, wrapping_key)?;

    let credential_id = data.get("credential_id")
        .and_then(|v| v.as_str())
        .ok_or("Missing credential_id")?;
    let public_key = data.get("public_key")
        .and_then(|v| v.as_str())
        .ok_or("Missing public_key")?;
    let prf_output_b64 = data.get("prf_output")
        .and_then(|v| v.as_str())
        .ok_or("Missing prf_output")?;
    let aaguid = data.get("aaguid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let authenticator_name = data.get("authenticator_name")
        .and_then(|v| v.as_str())
        .unwrap_or("WebAuthn Credential");

    let prf_bytes = engine.decode(prf_output_b64)
        .map_err(|e| format!("Invalid PRF output: {}", e))?;
    if prf_bytes.len() != 32 {
        return Err(format!("PRF output must be 32 bytes, got {}", prf_bytes.len()));
    }
    let mut prf_output = [0u8; 32];
    prf_output.copy_from_slice(&prf_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let credential = WebAuthnCredential {
        credential_id: credential_id.to_string(),
        public_key: public_key.to_string(),
        rp_id: "auth.llmsecrets.com".to_string(),
        aaguid: aaguid.to_string(),
        authenticator_name: authenticator_name.to_string(),
        registered_at: format!("{}Z", now),
    };

    tracing::info!("WebAuthn registration completed via relay");
    Ok(RegistrationResult { credential, prf_output })
}

/// Complete registration via localhost (uses rpId "localhost" instead of relay domain).
pub fn complete_registration_local(
    encrypted_payload: &str,
    wrapping_key: &str,
) -> Result<RegistrationResult, String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let data = decrypt_relay_payload(encrypted_payload, wrapping_key)?;

    let credential_id = data.get("credential_id")
        .and_then(|v| v.as_str())
        .ok_or("Missing credential_id")?;
    let public_key = data.get("public_key")
        .and_then(|v| v.as_str())
        .ok_or("Missing public_key")?;
    let prf_output_b64 = data.get("prf_output")
        .and_then(|v| v.as_str())
        .ok_or("Missing prf_output")?;
    let aaguid = data.get("aaguid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let authenticator_name = data.get("authenticator_name")
        .and_then(|v| v.as_str())
        .unwrap_or("WebAuthn Credential");

    let prf_bytes = engine.decode(prf_output_b64)
        .map_err(|e| format!("Invalid PRF output: {}", e))?;
    if prf_bytes.len() != 32 {
        return Err(format!("PRF output must be 32 bytes, got {}", prf_bytes.len()));
    }
    let mut prf_output = [0u8; 32];
    prf_output.copy_from_slice(&prf_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let credential = WebAuthnCredential {
        credential_id: credential_id.to_string(),
        public_key: public_key.to_string(),
        rp_id: "localhost".to_string(),
        aaguid: aaguid.to_string(),
        authenticator_name: authenticator_name.to_string(),
        registered_at: format!("{}Z", now),
    };

    tracing::info!("WebAuthn registration completed via localhost");
    Ok(RegistrationResult { credential, prf_output })
}

/// Complete authentication by decrypting the relay payload.
pub fn complete_authentication(
    encrypted_payload: &str,
    wrapping_key: &str,
) -> Result<AuthResult, String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let data = decrypt_relay_payload(encrypted_payload, wrapping_key)?;

    let prf_output_b64 = data.get("prf_output")
        .and_then(|v| v.as_str())
        .ok_or("Missing prf_output")?;

    let prf_bytes = engine.decode(prf_output_b64)
        .map_err(|e| format!("Invalid PRF output: {}", e))?;
    if prf_bytes.len() != 32 {
        return Err(format!("PRF output must be 32 bytes, got {}", prf_bytes.len()));
    }
    let mut prf_output = [0u8; 32];
    prf_output.copy_from_slice(&prf_bytes);

    tracing::info!("WebAuthn authentication completed via relay");
    Ok(AuthResult { prf_output })
}

/// Render a QR code as Unicode block characters and return as a string.
pub fn render_qr_string(url: &str) -> String {
    use qrcode::QrCode;
    use std::fmt::Write;

    let code = match QrCode::new(url.as_bytes()) {
        Ok(c) => c,
        Err(_) => return format!("Open this URL on your phone:\n{}\n", url),
    };

    let width = code.width();
    let data = code.into_colors();
    let quiet = 2;
    let total_w = width + quiet * 2;
    let total_h = width + quiet * 2;

    let mut out = String::new();
    let _ = writeln!(out);
    let mut row = 0;
    while row < total_h {
        let _ = write!(out, "  ");
        for col in 0..total_w {
            let top_dark = if row >= quiet && row < quiet + width && col >= quiet && col < quiet + width {
                data[(row - quiet) * width + (col - quiet)] == qrcode::Color::Dark
            } else {
                false
            };
            let bot_dark = if row + 1 >= quiet && row + 1 < quiet + width && col >= quiet && col < quiet + width {
                data[(row + 1 - quiet) * width + (col - quiet)] == qrcode::Color::Dark
            } else {
                false
            };
            let _ = write!(out, "{}", match (top_dark, bot_dark) {
                (true, true) => "\u{2588}",
                (true, false) => "\u{2580}",
                (false, true) => "\u{2584}",
                (false, false) => " ",
            });
        }
        let _ = writeln!(out);
        row += 2;
    }
    let _ = writeln!(out);
    out
}

/// Relay base URL
pub const RELAY_URL: &str = RELAY_BASE;

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_credential_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let cred_path = dir.path().join("webauthn.json");

        let cred = WebAuthnCredential {
            credential_id: "dGVzdF9jcmVkX2lk".to_string(),
            public_key: "dGVzdF9wdWJrZXk=".to_string(),
            rp_id: "localhost".to_string(),
            aaguid: "d548826e-79b4-db40-a3d8-11116f7e8349".to_string(),
            authenticator_name: "Bitwarden".to_string(),
            registered_at: "2026-03-09T00:00:00Z".to_string(),
        };

        // Save
        let json = serde_json::to_string_pretty(&cred).unwrap();
        std::fs::write(&cred_path, &json).unwrap();

        // Load
        let loaded_json = std::fs::read_to_string(&cred_path).unwrap();
        let loaded: WebAuthnCredential = serde_json::from_str(&loaded_json).unwrap();

        assert_eq!(loaded.credential_id, cred.credential_id);
        assert_eq!(loaded.public_key, cred.public_key);
        assert_eq!(loaded.rp_id, "localhost");
        assert_eq!(loaded.aaguid, cred.aaguid);
        assert_eq!(loaded.authenticator_name, "Bitwarden");
    }

    #[test]
    fn test_wa_state_enabled_disabled() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("wa-2fa.state");

        // Write "enabled"
        std::fs::write(&state_path, "enabled").unwrap();
        let content = std::fs::read_to_string(&state_path).unwrap();
        assert_ne!(content.trim(), "disabled");

        // Write "disabled"
        std::fs::write(&state_path, "disabled").unwrap();
        let content = std::fs::read_to_string(&state_path).unwrap();
        assert_eq!(content.trim(), "disabled");
    }

    #[test]
    fn test_wa_unlock_state() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("wa-2fa-unlock.state");

        std::fs::write(&state_path, "enabled").unwrap();
        assert_ne!(std::fs::read_to_string(&state_path).unwrap().trim(), "disabled");

        std::fs::write(&state_path, "disabled").unwrap();
        assert_eq!(std::fs::read_to_string(&state_path).unwrap().trim(), "disabled");
    }

    #[test]
    fn test_config_dir_path() {
        let path = get_credential_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".scrt4"), "credential path should contain .scrt4, got: {}", path_str);
        assert!(path_str.ends_with("webauthn.json"), "should end with webauthn.json, got: {}", path_str);
    }

    #[test]
    fn test_prf_salt_generation() {
        let salt1 = generate_prf_salt();
        let salt2 = generate_prf_salt();
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2, "Two random salts should differ");
    }

    #[test]
    fn test_hex_generation() {
        let token1 = generate_hex(32);
        let token2 = generate_hex(32);
        assert_eq!(token1.len(), 64, "32 bytes = 64 hex chars");
        assert!(token1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(token1, token2);
    }
}
