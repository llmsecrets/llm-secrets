// scrt4/src/keystore.rs
//! Master key protection and AES-256-CBC vault encryption.
//!
//! In scrt4, the master key is protected by WebAuthn PRF output (wrapping key)
//! via AES-256-GCM. Vault secrets are encrypted with AES-256-CBC (same format as scrt3).
//!
//! The PRF output (32 bytes) from the browser's WebAuthn assertion is used directly
//! as the AES-256-GCM wrapping key. No Argon2id derivation needed.

use std::collections::HashMap;
use std::path::PathBuf;

use aes::Aes256;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use cbc::{Decryptor, Encryptor, cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit}};
use rand::RngCore;

type Aes256CbcDec = Decryptor<Aes256>;
type Aes256CbcEnc = Encryptor<Aes256>;

// ── On-disk file format ────────────────────────────────────────────

/// Authentication method for the master key file
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum AuthMethod {
    /// scrt4: WebAuthn PRF output as wrapping key
    WebAuthnPrf,
    /// scrt3 compatibility (migration only)
    Argon2id,
}

/// On-disk master key file format (version 2)
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MasterKeyFile {
    pub version: u32,
    pub salt: String,                           // base64 — PRF salt (32 bytes)
    pub nonce: String,                          // 12 bytes, base64 — AES-256-GCM nonce
    pub ciphertext: String,                     // AES-256-GCM encrypted master key, base64
    pub auth_method: AuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webauthn_credential_id: Option<String>, // base64 — which credential was used
}

/// Get the scrt4 config directory (`~/.scrt4`).
pub fn config_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".scrt4")
}

/// Get the vault directory (~/.scrt4/vault)
pub fn vault_dir() -> PathBuf {
    config_dir().join("vault")
}

/// Get the master key file path (~/.scrt4/master.key)
pub fn master_key_path() -> PathBuf {
    config_dir().join("master.key")
}

/// Get the localhost master key file path (~/.scrt4/master-local.key)
pub fn master_key_local_path() -> PathBuf {
    config_dir().join("master-local.key")
}

/// Save master key wrapped with localhost PRF output
pub fn save_master_key_local(
    master_key_b64: &str,
    prf_output: &[u8; 32],
    prf_salt: &[u8; 32],
    credential_id: Option<&str>,
) -> Result<(), String> {
    save_master_key_webauthn_to(master_key_b64, prf_output, prf_salt, credential_id, &master_key_local_path())
}

/// Load master key using localhost PRF output
pub fn load_master_key_local(prf_output: &[u8; 32]) -> Result<String, String> {
    load_master_key_webauthn_from(prf_output, &master_key_local_path())
}

/// Load PRF salt from the localhost master key file
pub fn load_prf_salt_local() -> Result<[u8; 32], String> {
    load_prf_salt_from(&master_key_local_path())
}

/// Get the secrets file path (~/.scrt4/vault/secrets.enc)
pub fn secrets_path() -> PathBuf {
    vault_dir().join("secrets.enc")
}

/// Check if scrt4 has been initialized (master.key exists)
pub fn is_initialized() -> bool {
    master_key_path().exists()
}

// ── Master key management (WebAuthn PRF) ───────────────────────────

/// Generate a new random 32-byte master key, returned as base64
pub fn generate_new_master_key() -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    Ok(engine.encode(key_bytes))
}

/// Save a master key to disk, protected by WebAuthn PRF output.
pub fn save_master_key_webauthn(
    master_key_b64: &str,
    prf_output: &[u8; 32],
    prf_salt: &[u8; 32],
    credential_id: Option<&str>,
) -> Result<(), String> {
    save_master_key_webauthn_to(master_key_b64, prf_output, prf_salt, credential_id, &master_key_path())
}

fn save_master_key_webauthn_to(
    master_key_b64: &str,
    prf_output: &[u8; 32],
    prf_salt: &[u8; 32],
    credential_id: Option<&str>,
    path: &std::path::Path,
) -> Result<(), String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(prf_output)
        .map_err(|e| format!("AES-GCM init failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, master_key_b64.as_bytes())
        .map_err(|e| format!("AES-GCM encrypt failed: {}", e))?;

    let file = MasterKeyFile {
        version: 2,
        salt: engine.encode(prf_salt),
        nonce: engine.encode(nonce_bytes),
        ciphertext: engine.encode(ciphertext),
        auth_method: AuthMethod::WebAuthnPrf,
        webauthn_credential_id: credential_id.map(|s| s.to_string()),
    };

    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| format!("JSON serialize failed: {}", e))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    std::fs::write(path, &json)
        .map_err(|e| format!("Failed to write master key file: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    tracing::info!("Master key saved (WebAuthn PRF + AES-256-GCM protected)");
    Ok(())
}

/// Load and decrypt the master key using WebAuthn PRF output.
pub fn load_master_key_webauthn(prf_output: &[u8; 32]) -> Result<String, String> {
    load_master_key_webauthn_from(prf_output, &master_key_path())
}

fn load_master_key_webauthn_from(prf_output: &[u8; 32], path: &std::path::Path) -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read master key file: {}. Run 'scrt4 setup' first.", e))?;

    let file: MasterKeyFile = serde_json::from_str(&json)
        .map_err(|e| format!("Invalid master key file: {}", e))?;

    if file.auth_method != AuthMethod::WebAuthnPrf {
        return Err("Master key file uses a different auth method (expected WebAuthnPrf)".into());
    }

    let nonce_bytes = engine.decode(&file.nonce)
        .map_err(|e| format!("Invalid nonce: {}", e))?;
    let ciphertext = engine.decode(&file.ciphertext)
        .map_err(|e| format!("Invalid ciphertext: {}", e))?;

    let cipher = Aes256Gcm::new_from_slice(prf_output)
        .map_err(|e| format!("AES-GCM init failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "WebAuthn authentication failed (wrong PRF output)".to_string())?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("Decrypted master key is not valid UTF-8: {}", e))
}

/// Load the PRF salt from the master key file
pub fn load_prf_salt() -> Result<[u8; 32], String> {
    load_prf_salt_from(&master_key_path())
}

fn load_prf_salt_from(path: &std::path::Path) -> Result<[u8; 32], String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read master key file: {}", e))?;
    let file: MasterKeyFile = serde_json::from_str(&json)
        .map_err(|e| format!("Invalid master key file: {}", e))?;
    let salt_bytes = engine.decode(&file.salt)
        .map_err(|e| format!("Invalid salt: {}", e))?;

    if salt_bytes.len() != 32 {
        return Err(format!("PRF salt must be 32 bytes, got {}", salt_bytes.len()));
    }

    let mut salt = [0u8; 32];
    salt.copy_from_slice(&salt_bytes);
    Ok(salt)
}

// ── Unlock flow ────────────────────────────────────────────────────

/// Full unlock flow using WebAuthn PRF output.
pub fn unlock_secrets_webauthn(prf_output: &[u8; 32]) -> Result<(HashMap<String, String>, String), String> {
    tracing::info!("Starting unlock flow (WebAuthn PRF)");

    let master_key = load_master_key_webauthn(prf_output)?;
    tracing::info!("Master key decrypted with WebAuthn PRF");

    let secrets = decrypt_secrets(&master_key)?;
    tracing::info!("Decrypted {} secrets", secrets.len());

    Ok((secrets, master_key))
}

// ── Vault (secrets.enc) management ──────────────────────────────────

fn extract_data_from_env_json(json_content: &str) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct EncryptedEnv {
        #[serde(rename = "Data")]
        data: String,
    }
    let parsed: EncryptedEnv = serde_json::from_str(json_content)
        .map_err(|e| format!("Invalid env JSON: {}", e))?;
    Ok(parsed.data)
}

fn decrypt_env_content_with_master_key(
    encrypted_base64: &str,
    master_key_base64: &str,
) -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let key_bytes = engine.decode(master_key_base64)
        .map_err(|e| format!("Invalid master key base64: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(format!("Master key must be 32 bytes, got {}", key_bytes.len()));
    }

    let encrypted_bytes = engine.decode(encrypted_base64)
        .map_err(|e| format!("Invalid encrypted data base64: {}", e))?;
    if encrypted_bytes.len() < 17 {
        return Err("Encrypted data too short (need at least IV + 1 block)".into());
    }

    let iv = &encrypted_bytes[0..16];
    let ciphertext = &encrypted_bytes[16..];
    let key: [u8; 32] = key_bytes.try_into().map_err(|_| "Key conversion failed")?;
    let iv_arr: [u8; 16] = iv.try_into().map_err(|_| "IV conversion failed")?;

    let decryptor = Aes256CbcDec::new(&key.into(), &iv_arr.into());
    let mut buffer = ciphertext.to_vec();
    let decrypted = decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    String::from_utf8(decrypted.to_vec())
        .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e))
}

fn encrypt_env_content_with_master_key(
    plaintext: &str,
    master_key_base64: &str,
) -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let key_bytes = engine.decode(master_key_base64)
        .map_err(|e| format!("Invalid master key base64: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(format!("Master key must be 32 bytes, got {}", key_bytes.len()));
    }

    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let key: [u8; 32] = key_bytes.try_into().map_err(|_| "Key conversion failed")?;
    let encryptor = Aes256CbcEnc::new(&key.into(), &iv.into());

    let plaintext_bytes = plaintext.as_bytes();
    let mut buffer = vec![0u8; plaintext_bytes.len() + 16];
    buffer[..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);
    let ciphertext = encryptor
        .encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer, plaintext_bytes.len())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    let mut combined = Vec::with_capacity(16 + ciphertext.len());
    combined.extend_from_slice(&iv);
    combined.extend_from_slice(ciphertext);

    Ok(engine.encode(&combined))
}

pub fn parse_env(content: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            let value = trimmed[eq_pos + 1..].to_string();
            if !key.is_empty() && key.chars().all(|c| c.is_alphanumeric() || c == '_') {
                vars.insert(key.to_string(), value);
            }
        }
    }
    vars
}

pub fn decrypt_secrets(master_key_b64: &str) -> Result<HashMap<String, String>, String> {
    decrypt_secrets_from(master_key_b64, &secrets_path())
}

fn decrypt_secrets_from(master_key_b64: &str, path: &std::path::Path) -> Result<HashMap<String, String>, String> {
    let json_content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read secrets file: {}", e))?;
    let encrypted_base64 = extract_data_from_env_json(json_content.trim())?;
    let plaintext = decrypt_env_content_with_master_key(&encrypted_base64, master_key_b64)?;
    Ok(parse_env(&plaintext))
}

pub fn save_encrypted_env(
    secrets: &HashMap<String, String>,
    master_key: &str,
) -> Result<(), String> {
    save_encrypted_env_to(secrets, master_key, &secrets_path())
}

fn save_encrypted_env_to(
    secrets: &HashMap<String, String>,
    master_key: &str,
    path: &std::path::Path,
) -> Result<(), String> {
    let mut lines: Vec<String> = secrets.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    lines.sort();
    let plaintext = lines.join("\n");

    let encrypted_base64 = encrypt_env_content_with_master_key(&plaintext, master_key)?;
    let json = format!(r#"{{"Data":"{}"}}"#, encrypted_base64);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create vault directory: {}", e))?;
    }

    std::fs::write(path, &json)
        .map_err(|e| format!("Failed to write secrets file: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    tracing::info!("Persisted secrets to disk");
    Ok(())
}

pub fn reset_encrypted_env(master_key: &str) -> Result<(), String> {
    let path = secrets_path();
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to remove old secrets file: {}", e))?;
    }
    save_encrypted_env(&HashMap::new(), master_key)?;
    tracing::info!("Reset encrypted env to empty store");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_master_key_webauthn_roundtrip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("master.key");

        let master_key = generate_new_master_key().unwrap();
        let mut prf_output = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_output);
        let mut prf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_salt);

        save_master_key_webauthn_to(&master_key, &prf_output, &prf_salt, Some("test_cred"), &key_path).unwrap();
        let loaded = load_master_key_webauthn_from(&prf_output, &key_path).unwrap();
        assert_eq!(master_key, loaded);
    }

    #[test]
    fn test_master_key_wrong_prf() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("master.key");

        let master_key = generate_new_master_key().unwrap();
        let mut prf_output = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_output);
        let mut prf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_salt);

        save_master_key_webauthn_to(&master_key, &prf_output, &prf_salt, None, &key_path).unwrap();

        let mut wrong_prf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut wrong_prf);
        let result = load_master_key_webauthn_from(&wrong_prf, &key_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("WebAuthn authentication failed"));
    }

    #[test]
    fn test_v2_file_format() {
        let file = MasterKeyFile {
            version: 2,
            salt: "dGVzdF9zYWx0".to_string(),
            nonce: "dGVzdF9ub25jZQ==".to_string(),
            ciphertext: "dGVzdF9jaXBoZXJ0ZXh0".to_string(),
            auth_method: AuthMethod::WebAuthnPrf,
            webauthn_credential_id: Some("Y3JlZF9pZA==".to_string()),
        };

        let json = serde_json::to_string_pretty(&file).unwrap();
        assert!(json.contains("\"version\": 2"));
        assert!(json.contains("\"WebAuthnPrf\""));

        let loaded: MasterKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.auth_method, AuthMethod::WebAuthnPrf);
    }

    #[test]
    fn test_prf_salt_roundtrip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("master.key");

        let master_key = generate_new_master_key().unwrap();
        let mut prf_output = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_output);
        let mut prf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_salt);

        save_master_key_webauthn_to(&master_key, &prf_output, &prf_salt, None, &key_path).unwrap();
        let loaded_salt = load_prf_salt_from(&key_path).unwrap();
        assert_eq!(prf_salt, loaded_salt);
    }

    #[test]
    fn test_env_encrypt_decrypt() {
        let master_key = generate_new_master_key().unwrap();
        let plaintext = "API_KEY=secret123\nDB_PASSWORD=p@ssw0rd!";
        let encrypted = encrypt_env_content_with_master_key(plaintext, &master_key).unwrap();
        let decrypted = decrypt_env_content_with_master_key(&encrypted, &master_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_parse_env() {
        let content = "# Comment\nAPI_KEY=secret123\nDB_PASSWORD=p@ssw0rd!\nEMPTY=\nINVALID LINE\n";
        let vars = parse_env(content);
        assert_eq!(vars.get("API_KEY"), Some(&"secret123".to_string()));
        assert_eq!(vars.get("DB_PASSWORD"), Some(&"p@ssw0rd!".to_string()));
        assert_eq!(vars.get("EMPTY"), Some(&"".to_string()));
        assert!(!vars.contains_key("INVALID LINE"));
    }

    #[test]
    fn test_save_and_load_vault() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.enc");

        let master_key = generate_new_master_key().unwrap();
        let mut secrets = HashMap::new();
        secrets.insert("API_KEY".to_string(), "sk-123456".to_string());
        secrets.insert("DB_PASS".to_string(), "hunter2".to_string());

        save_encrypted_env_to(&secrets, &master_key, &vault_path).unwrap();
        let loaded = decrypt_secrets_from(&master_key, &vault_path).unwrap();
        assert_eq!(loaded.get("API_KEY"), Some(&"sk-123456".to_string()));
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_generate_new_master_key() {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let key = generate_new_master_key().unwrap();
        assert_eq!(key.len(), 44);
        assert_eq!(engine.decode(&key).unwrap().len(), 32);
    }

    #[test]
    fn test_config_dir_path() {
        let path = config_dir();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".scrt4"));
    }
}
