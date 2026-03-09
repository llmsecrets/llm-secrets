// scrt3/src/keystore.rs
//! Argon2id-based master key protection and AES-256-CBC vault encryption.
//!
//! Replaces dpapi.rs — no Windows dependencies, no PowerShell, no DPAPI.
//! Master key is protected by a user-chosen passphrase via Argon2id + AES-256-GCM.
//! Vault secrets are encrypted with AES-256-CBC (same format as before).

use std::collections::HashMap;
use std::path::PathBuf;

use aes::Aes256;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::{Argon2, Algorithm, Version, Params};
use cbc::{Decryptor, Encryptor, cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit}};
use rand::RngCore;

type Aes256CbcDec = Decryptor<Aes256>;
type Aes256CbcEnc = Encryptor<Aes256>;

/// On-disk master key file format
#[derive(serde::Serialize, serde::Deserialize)]
struct MasterKeyFile {
    version: u32,
    salt: String,       // 16 bytes, base64
    nonce: String,      // 12 bytes, base64
    ciphertext: String, // AES-256-GCM encrypted master key, base64
    argon2_params: Argon2Params,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Argon2Params {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost_kib: 65536, // 64 MiB
            t_cost: 3,
            p_cost: 1,
            output_len: 32,
        }
    }
}

// ── Path helpers ────────────────────────────────────────────────────

/// Get the scrt3 config directory (~/.scrt3)
pub fn config_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".scrt3")
}

/// Get the vault directory (~/.scrt3/vault)
pub fn vault_dir() -> PathBuf {
    config_dir().join("vault")
}

/// Get the master key file path (~/.scrt3/master.key)
pub fn master_key_path() -> PathBuf {
    config_dir().join("master.key")
}

/// Get the secrets file path (~/.scrt3/vault/secrets.enc)
pub fn secrets_path() -> PathBuf {
    vault_dir().join("secrets.enc")
}

/// Check if scrt3 has been initialized (master.key exists)
pub fn is_initialized() -> bool {
    master_key_path().exists()
}

// ── Argon2id key derivation ─────────────────────────────────────────

/// Derive a 32-byte key from passphrase + salt using Argon2id
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;
    Ok(output)
}

// ── Master key management ───────────────────────────────────────────

/// Generate a new random 32-byte master key, returned as base64
pub fn generate_new_master_key() -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    Ok(engine.encode(key_bytes))
}

/// Save a master key to disk, protected by passphrase via Argon2id + AES-256-GCM.
/// Writes to ~/.scrt3/master.key with 0600 permissions.
pub fn save_master_key(master_key_b64: &str, passphrase: &str) -> Result<(), String> {
    save_master_key_to(master_key_b64, passphrase, &master_key_path())
}

/// Save master key to a specific path (for testability)
fn save_master_key_to(master_key_b64: &str, passphrase: &str, path: &std::path::Path) -> Result<(), String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    // Generate random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive wrapping key from passphrase
    let wrapping_key = derive_key(passphrase, &salt)?;

    // AES-256-GCM encrypt the master key
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| format!("AES-GCM init failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, master_key_b64.as_bytes())
        .map_err(|e| format!("AES-GCM encrypt failed: {}", e))?;

    // Build on-disk structure
    let file = MasterKeyFile {
        version: 1,
        salt: engine.encode(salt),
        nonce: engine.encode(nonce_bytes),
        ciphertext: engine.encode(ciphertext),
        argon2_params: Argon2Params::default(),
    };

    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| format!("JSON serialize failed: {}", e))?;

    // Create parent directories
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    // Write with restricted permissions
    std::fs::write(path, &json)
        .map_err(|e| format!("Failed to write master key file: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    tracing::info!("Master key saved (Argon2id + AES-256-GCM protected)");
    Ok(())
}

/// Load and decrypt the master key using passphrase.
/// Returns the base64-encoded master key.
pub fn load_master_key(passphrase: &str) -> Result<String, String> {
    load_master_key_from(passphrase, &master_key_path())
}

/// Load master key from a specific path (for testability)
fn load_master_key_from(passphrase: &str, path: &std::path::Path) -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read master key file: {}. Run 'scrt3 setup-2fa' first.", e))?;

    let file: MasterKeyFile = serde_json::from_str(&json)
        .map_err(|e| format!("Invalid master key file: {}", e))?;

    let salt = engine.decode(&file.salt)
        .map_err(|e| format!("Invalid salt: {}", e))?;
    let nonce_bytes = engine.decode(&file.nonce)
        .map_err(|e| format!("Invalid nonce: {}", e))?;
    let ciphertext = engine.decode(&file.ciphertext)
        .map_err(|e| format!("Invalid ciphertext: {}", e))?;

    // Derive wrapping key from passphrase
    let wrapping_key = derive_key(passphrase, &salt)?;

    // AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| format!("AES-GCM init failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Wrong passphrase".to_string())?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("Decrypted master key is not valid UTF-8: {}", e))
}

// ── Vault (secrets.enc) management ──────────────────────────────────

/// Extract the Data field from encrypted env JSON
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

/// Decrypt env content using AES-256-CBC
/// Format: base64(IV[16 bytes] + ciphertext), key is 44-char base64 (32 bytes)
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

    let key: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "Key conversion failed")?;
    let iv_arr: [u8; 16] = iv.try_into()
        .map_err(|_| "IV conversion failed")?;

    let decryptor = Aes256CbcDec::new(&key.into(), &iv_arr.into());

    let mut buffer = ciphertext.to_vec();
    let decrypted = decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    String::from_utf8(decrypted.to_vec())
        .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e))
}

/// Encrypt env content using AES-256-CBC
/// Format: base64(IV[16 bytes] + ciphertext), key is 44-char base64 (32 bytes)
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

    let key: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "Key conversion failed")?;
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

/// Parse .env content into HashMap
pub fn parse_env(content: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

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

/// Decrypt secrets from the vault file using master key.
/// Returns a HashMap of secret name -> value pairs.
pub fn decrypt_secrets(master_key_b64: &str) -> Result<HashMap<String, String>, String> {
    decrypt_secrets_from(master_key_b64, &secrets_path())
}

/// Decrypt secrets from a specific path (for testability)
fn decrypt_secrets_from(master_key_b64: &str, path: &std::path::Path) -> Result<HashMap<String, String>, String> {
    let json_content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read secrets file: {}", e))?;

    let encrypted_base64 = extract_data_from_env_json(json_content.trim())?;
    let plaintext = decrypt_env_content_with_master_key(&encrypted_base64, master_key_b64)?;
    Ok(parse_env(&plaintext))
}

/// Save secrets to the encrypted vault file.
/// Format: {"Data":"base64(IV+ciphertext)"}
pub fn save_encrypted_env(
    secrets: &HashMap<String, String>,
    master_key: &str,
) -> Result<(), String> {
    save_encrypted_env_to(secrets, master_key, &secrets_path())
}

/// Save secrets to a specific path (for testability)
fn save_encrypted_env_to(
    secrets: &HashMap<String, String>,
    master_key: &str,
    path: &std::path::Path,
) -> Result<(), String> {
    // Build .env content
    let mut lines: Vec<String> = secrets.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    lines.sort();
    let plaintext = lines.join("\n");

    // Encrypt
    let encrypted_base64 = encrypt_env_content_with_master_key(&plaintext, master_key)?;

    // Build JSON
    let json = format!(r#"{{"Data":"{}"}}"#, encrypted_base64);

    // Create parent directories
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create vault directory: {}", e))?;
    }

    // Write
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

/// Delete existing secrets file and create a fresh empty one.
pub fn reset_encrypted_env(master_key: &str) -> Result<(), String> {
    let path = secrets_path();

    // Remove existing file if present
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to remove old secrets file: {}", e))?;
    }

    // Create fresh empty store
    save_encrypted_env(&HashMap::new(), master_key)?;

    tracing::info!("Reset encrypted env to empty store");
    Ok(())
}

/// Full unlock flow: TOTP verify -> passphrase -> decrypt secrets.
/// Returns (secrets, master_key).
pub async fn unlock_secrets(totp_code: &str, passphrase: &str) -> Result<(HashMap<String, String>, String), String> {
    tracing::info!("Starting unlock flow with TOTP");

    // Step 1: Verify TOTP code
    match crate::totp::verify_totp_code(totp_code) {
        Ok(true) => {}
        Ok(false) => return Err("Invalid TOTP code".into()),
        Err(e) => return Err(e),
    }
    tracing::info!("TOTP authentication successful");

    // Step 2: Passphrase-based decrypt
    unlock_secrets_passphrase_only(passphrase).await
}

/// Unlock secrets using only passphrase (no TOTP verification).
/// Used when 2FA is disabled — passphrase is the sole authentication gate.
pub async fn unlock_secrets_passphrase_only(passphrase: &str) -> Result<(HashMap<String, String>, String), String> {
    tracing::info!("Starting unlock flow (passphrase only)");

    // Step 1: Load master key using passphrase
    let master_key = load_master_key(passphrase)?;
    tracing::info!("Master key decrypted with passphrase");

    // Step 2: Decrypt secrets with master key
    let secrets = decrypt_secrets(&master_key)?;
    tracing::info!("Decrypted {} secrets", secrets.len());

    Ok((secrets, master_key))
}

/// Migrate secrets from old master key to new passphrase-protected key.
/// 1. Decrypts secrets with old_key
/// 2. Generates new master key, protects with passphrase
/// 3. Re-encrypts secrets with new key
/// Returns (secrets, new_master_key, count)
pub fn migrate_secrets(old_key: &str, passphrase: &str) -> Result<(HashMap<String, String>, String, usize), String> {
    // Decrypt secrets with old key
    let secrets = decrypt_secrets(old_key)?;
    let count = secrets.len();
    tracing::info!("Decrypted {} secrets with old key", count);

    // Generate new master key and protect with passphrase
    let new_key = generate_new_master_key()?;
    save_master_key(&new_key, passphrase)?;
    tracing::info!("Generated new master key, protected with passphrase");

    // Re-encrypt secrets with new key
    save_encrypted_env(&secrets, &new_key)?;
    tracing::info!("Re-encrypted secrets with new key");

    Ok((secrets, new_key, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_argon2id_key_derivation() {
        let salt = b"test_salt_16byt!"; // 16 bytes
        let key1 = derive_key("correct_passphrase", salt).unwrap();
        let key2 = derive_key("correct_passphrase", salt).unwrap();
        let key3 = derive_key("wrong_passphrase", salt).unwrap();

        // Same passphrase + salt → same key
        assert_eq!(key1, key2);
        // Different passphrase → different key
        assert_ne!(key1, key3);
        // Key is 32 bytes
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_master_key_encrypt_decrypt() {
        let master_key = generate_new_master_key().unwrap();
        let passphrase = "test_passphrase_123";

        // Generate salt/nonce, encrypt/decrypt manually
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let wrapping_key = derive_key(passphrase, &salt).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&wrapping_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, master_key.as_bytes()).unwrap();
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(String::from_utf8(plaintext).unwrap(), master_key);
    }

    #[test]
    fn test_master_key_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("master.key");

        let master_key = generate_new_master_key().unwrap();
        save_master_key_to(&master_key, "correct_passphrase", &key_path).unwrap();

        // Wrong passphrase should fail
        let result = load_master_key_from("wrong_passphrase", &key_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Wrong passphrase"));
    }

    #[test]
    fn test_master_key_roundtrip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("master.key");

        let master_key = generate_new_master_key().unwrap();
        save_master_key_to(&master_key, "my_passphrase", &key_path).unwrap();

        let loaded = load_master_key_from("my_passphrase", &key_path).unwrap();
        assert_eq!(master_key, loaded);
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
        let content = r#"
# Comment
API_KEY=secret123
DB_PASSWORD=p@ssw0rd!
EMPTY=
INVALID LINE

SPACED_KEY = spaced_value
"#;
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
        assert_eq!(loaded.get("DB_PASS"), Some(&"hunter2".to_string()));
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_generate_new_master_key() {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;

        let key = generate_new_master_key().unwrap();
        assert_eq!(key.len(), 44); // 32 bytes → 44 chars base64

        let decoded = engine.decode(&key).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_reset_vault() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault").join("secrets.enc");

        let master_key = generate_new_master_key().unwrap();
        let mut secrets = HashMap::new();
        secrets.insert("KEY".to_string(), "value".to_string());
        save_encrypted_env_to(&secrets, &master_key, &vault_path).unwrap();

        // Verify it was saved
        let loaded = decrypt_secrets_from(&master_key, &vault_path).unwrap();
        assert_eq!(loaded.len(), 1);

        // Reset by writing empty
        save_encrypted_env_to(&HashMap::new(), &master_key, &vault_path).unwrap();
        let loaded2 = decrypt_secrets_from(&master_key, &vault_path).unwrap();
        assert_eq!(loaded2.len(), 0);
    }

    #[test]
    fn test_config_dir_path() {
        let path = config_dir();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".scrt3"), "config_dir should contain .scrt3, got: {}", path_str);
        assert!(!path_str.contains(".scrt2"), "config_dir should NOT contain .scrt2, got: {}", path_str);
    }
}
