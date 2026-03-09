//! TOTP (Time-based One-Time Password) authentication module
//!
//! Google Authenticator-compatible TOTP for scrt3.
//! The TOTP secret is stored at ~/.scrt3/totp.secret with 0600 permissions.

use std::path::PathBuf;
use totp_rs::{Algorithm, TOTP, Secret};

const TOTP_DIGITS: usize = 6;
const TOTP_STEP: u64 = 30;
const TOTP_SKEW: u8 = 1; // Allow 1-step skew (90s window)
const TOTP_ISSUER: &str = "LLM Secrets";
const TOTP_ACCOUNT: &str = "wsl-daemon";

/// Get the path to the TOTP secret file
pub fn get_totp_secret_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".scrt3").join("totp.secret")
}

/// Check if TOTP has been configured (secret file exists)
pub fn is_totp_configured() -> bool {
    get_totp_secret_path().exists()
}

/// Build a TOTP instance from a base32-encoded secret
fn build_totp(secret_b32: &str) -> Result<TOTP, String> {
    let secret = Secret::Encoded(secret_b32.to_string());
    let secret_bytes = secret.to_bytes()
        .map_err(|e| format!("Invalid TOTP secret: {}", e))?;

    TOTP::new(Algorithm::SHA1, TOTP_DIGITS, TOTP_SKEW, TOTP_STEP, secret_bytes, Some(TOTP_ISSUER.into()), TOTP_ACCOUNT.into())
        .map_err(|e| format!("Failed to create TOTP: {}", e))
}

/// Verify a TOTP code against the stored secret
pub fn verify_totp_code(code: &str) -> Result<bool, String> {
    let secret_path = get_totp_secret_path();
    let secret_b32 = std::fs::read_to_string(&secret_path)
        .map_err(|e| format!("Failed to read TOTP secret at {:?}: {}. Run 'scrt setup-totp' first.", secret_path, e))?;
    let secret_b32 = secret_b32.trim();

    let totp = build_totp(secret_b32)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs();

    Ok(totp.check(code, now))
}

/// Generate a new TOTP secret
/// Returns (base32_secret, otpauth_uri)
pub fn generate_totp_secret() -> Result<(String, String), String> {
    let secret = Secret::generate_secret();
    let secret_b32 = secret.to_encoded().to_string();

    let totp = build_totp(&secret_b32)?;
    let otpauth_uri = totp.get_url();

    Ok((secret_b32, otpauth_uri))
}

/// Save a TOTP secret to disk with restricted permissions
pub fn save_totp_secret(secret_b32: &str) -> Result<(), String> {
    let secret_path = get_totp_secret_path();

    // Create parent directory
    if let Some(parent) = secret_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create ~/.scrt3 directory: {}", e))?;
    }

    // Write secret
    std::fs::write(&secret_path, secret_b32)
        .map_err(|e| format!("Failed to write TOTP secret: {}", e))?;

    // Set permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions on TOTP secret: {}", e))?;
    }

    Ok(())
}

/// Get the path to the 2FA state file
pub fn get_tfa_state_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".scrt3").join("2fa.state")
}

/// Check if 2FA is enabled for reveal operations.
/// Returns true if TOTP is configured AND state is not explicitly "disabled".
/// Default (no state file) = enabled when TOTP is configured.
pub fn is_tfa_enabled() -> bool {
    if !is_totp_configured() {
        return false;
    }
    let state_path = get_tfa_state_path();
    match std::fs::read_to_string(&state_path) {
        Ok(contents) => contents.trim() != "disabled",
        Err(_) => true, // File absent + totp configured = enabled
    }
}

/// Set the 2FA state (enabled or disabled).
/// Writes to ~/.scrt3/2fa.state with 0600 permissions.
pub fn set_tfa_state(enabled: bool) -> Result<(), String> {
    let state_path = get_tfa_state_path();

    // Create parent directory
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create ~/.scrt3 directory: {}", e))?;
    }

    let content = if enabled { "enabled" } else { "disabled" };
    std::fs::write(&state_path, content)
        .map_err(|e| format!("Failed to write 2FA state: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions on 2FA state file: {}", e))?;
    }

    Ok(())
}

/// Get the path to the 2FA unlock state file
pub fn get_tfa_unlock_state_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".scrt3").join("2fa-unlock.state")
}

/// Check if 2FA is enabled for unlock operations.
/// Returns true if TOTP is configured AND unlock state is not explicitly "disabled".
/// Default (no state file) = enabled when TOTP is configured.
pub fn is_tfa_unlock_enabled() -> bool {
    if !is_totp_configured() {
        return false;
    }
    let state_path = get_tfa_unlock_state_path();
    match std::fs::read_to_string(&state_path) {
        Ok(contents) => contents.trim() != "disabled",
        Err(_) => true, // File absent + totp configured = enabled
    }
}

/// Set the 2FA unlock state (enabled or disabled).
/// Writes to ~/.scrt3/2fa-unlock.state with 0600 permissions.
pub fn set_tfa_unlock_state(enabled: bool) -> Result<(), String> {
    let state_path = get_tfa_unlock_state_path();

    // Create parent directory
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create ~/.scrt3 directory: {}", e))?;
    }

    let content = if enabled { "enabled" } else { "disabled" };
    std::fs::write(&state_path, content)
        .map_err(|e| format!("Failed to write 2FA unlock state: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions on 2FA unlock state file: {}", e))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify() {
        let (secret_b32, uri) = generate_totp_secret().unwrap();
        assert!(!secret_b32.is_empty());
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("LLM"));

        // Generate a current code and verify it
        let totp = build_totp(&secret_b32).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = totp.generate(now);
        assert!(totp.check(&code, now));
    }

    #[test]
    fn test_invalid_code() {
        let (secret_b32, _) = generate_totp_secret().unwrap();
        let totp = build_totp(&secret_b32).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!totp.check("000000", now));
    }
}
