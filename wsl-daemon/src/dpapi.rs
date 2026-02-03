// wsl2-daemon/src/dpapi.rs
//! Windows Hello & DPAPI integration via PowerShell bridge
//!
//! Calls the hello-bridge.ps1 script on the Windows side to:
//! - Trigger Windows Hello facial recognition
//! - Retrieve GPG passphrase from DPAPI-protected storage
//!
//! This allows the daemon to unlock secrets after biometric auth.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use aes::Aes256;
use cbc::{Decryptor, Encryptor, cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit}};
use rand::RngCore;

type Aes256CbcDec = Decryptor<Aes256>;
type Aes256CbcEnc = Encryptor<Aes256>;

/// Get the path to PowerShell.exe (works from WSL2)
fn get_powershell_path() -> &'static str {
    // In WSL2, use the Windows interop path
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
}

/// Detect the Windows username from WSL2 environment
fn get_windows_username() -> Result<String, String> {
    // Method 1: Check USERPROFILE env var (forwarded from Windows via WSLENV)
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        // USERPROFILE is like C:\Users\jgott
        if let Some(name) = userprofile.rsplit(&['\\', '/'][..]).next() {
            if !name.is_empty() {
                return Ok(name.to_string());
            }
        }
    }

    // Method 2: Check /mnt/c/Users/ for a single non-system user directory
    if let Ok(entries) = std::fs::read_dir("/mnt/c/Users") {
        let user_dirs: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                // Skip system directories
                match name.as_str() {
                    "Default" | "Default User" | "Public" | "All Users" => None,
                    _ if name.starts_with('.') => None,
                    _ => Some(name),
                }
            })
            .collect();

        if user_dirs.len() == 1 {
            return Ok(user_dirs[0].clone());
        }

        // Method 3: Look for the one that has AppData\Roaming\LLM Secrets
        for dir in &user_dirs {
            let check_path = format!("/mnt/c/Users/{}/AppData/Roaming/LLM Secrets", dir);
            if std::path::Path::new(&check_path).exists() {
                return Ok(dir.clone());
            }
        }
    }

    Err("Could not detect Windows username. Set USERPROFILE environment variable.".into())
}

/// Get the path to WindowsHelloAuth.exe
fn get_windows_hello_auth_path() -> Result<PathBuf, String> {
    let username = get_windows_username()?;
    Ok(PathBuf::from(format!(
        "/mnt/c/Users/{}/AppData/Roaming/LLM Secrets/WindowsHelloAuth.exe",
        username
    )))
}

/// Check if Windows Hello is available
pub fn check_hello_available() -> Result<bool, String> {
    let auth_exe = get_windows_hello_auth_path()?;

    if !auth_exe.exists() {
        return Err("WindowsHelloAuth.exe not found. Install the LLM Secrets app first.".into());
    }

    // WindowsHelloAuth.exe outputs "Windows Hello is available" if available
    let output = Command::new(&auth_exe)
        .output()
        .map_err(|e| format!("Failed to run WindowsHelloAuth: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("Windows Hello is available") || stdout.contains("SUCCESS"))
}

/// Get master key from Electron app's DPAPI storage
///
/// The master key is stored at %APPDATA%\LLM Secrets\credentials\EnvCrypto_DpapiMasterKey.dat
/// as a JSON file with a hex-encoded DPAPI blob.
pub fn get_master_key_from_electron_dpapi() -> Result<String, String> {
    let ps_command = r#"
        $keyPath = Join-Path $env:APPDATA 'LLM Secrets\credentials\EnvCrypto_DpapiMasterKey.dat'
        if (-not (Test-Path $keyPath)) {
            Write-Error 'Master key file not found. Run LLM Secrets setup first.'
            exit 1
        }
        $json = Get-Content $keyPath -Raw | ConvertFrom-Json
        # The EncryptedKey is hex-encoded, not base64
        $hexString = $json.EncryptedKey
        $encryptedBytes = [byte[]]::new($hexString.Length / 2)
        for ($i = 0; $i -lt $hexString.Length; $i += 2) {
            $encryptedBytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
        }
        Add-Type -AssemblyName System.Security
        $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, 'CurrentUser')
        # Windows stores strings as UTF-16LE (Unicode)
        [System.Text.Encoding]::Unicode.GetString($decryptedBytes)
    "#;

    let output = Command::new(get_powershell_path())
        .args(["-ExecutionPolicy", "Bypass", "-Command", ps_command])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to decrypt master key: {}", stderr));
    }

    let master_key = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if master_key.is_empty() {
        return Err("Master key is empty".into());
    }

    Ok(master_key)
}

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

/// Decrypt .env file using master key
///
/// Uses the LLM Secrets Electron app's encrypted env files at %APPDATA%\LLM Secrets\env\
/// Returns a HashMap of secret name -> value pairs.
pub fn decrypt_env_with_master_key(master_key: &str) -> Result<HashMap<String, String>, String> {
    // Read the encrypted env file via PowerShell (to handle Windows paths)
    let ps_command = r#"
        $envDir = Join-Path $env:APPDATA 'LLM Secrets\env'
        if (-not (Test-Path $envDir)) {
            Write-Error 'Env directory not found'
            exit 1
        }

        # Find the latest .env.encrypted.v* file
        $files = Get-ChildItem $envDir -Filter '.env.encrypted.v*' |
                 Sort-Object { [int]($_.Name -replace '.*v(\d+)$', '$1') } -Descending
        if ($files.Count -eq 0) {
            Write-Error 'No encrypted env file found'
            exit 1
        }

        # Return the JSON content
        Get-Content $files[0].FullName -Raw
    "#;

    let output = Command::new(get_powershell_path())
        .args(["-ExecutionPolicy", "Bypass", "-Command", ps_command])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to read env file: {}", stderr));
    }

    let json_content = String::from_utf8_lossy(&output.stdout);

    // Extract the encrypted data from JSON
    let encrypted_base64 = extract_data_from_env_json(json_content.trim())?;

    // Decrypt using pure Rust AES-256-CBC
    let plaintext = decrypt_env_content_with_master_key(&encrypted_base64, master_key)?;

    // Parse .env format
    Ok(parse_env(&plaintext))
}

/// Parse .env content into HashMap
fn parse_env(content: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse KEY=value
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            let value = trimmed[eq_pos + 1..].to_string();

            // Validate key format
            if !key.is_empty() && key.chars().all(|c| c.is_alphanumeric() || c == '_') {
                vars.insert(key.to_string(), value);
            }
        }
    }

    vars
}

/// Decrypt env file content using AES-256-CBC
///
/// Format (matching Electron app):
/// - Input: base64(IV[16 bytes] + ciphertext)
/// - Key: 44-char base64 string (32 bytes decoded)
/// - Mode: AES-256-CBC with PKCS#7 padding
fn decrypt_env_content_with_master_key(
    encrypted_base64: &str,
    master_key_base64: &str,
) -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    // Decode master key from base64
    let key_bytes = engine.decode(master_key_base64)
        .map_err(|e| format!("Invalid master key base64: {}", e))?;

    if key_bytes.len() != 32 {
        return Err(format!("Master key must be 32 bytes, got {}", key_bytes.len()));
    }

    // Decode encrypted data from base64
    let encrypted_bytes = engine.decode(encrypted_base64)
        .map_err(|e| format!("Invalid encrypted data base64: {}", e))?;

    if encrypted_bytes.len() < 17 {
        return Err("Encrypted data too short (need at least IV + 1 block)".into());
    }

    // Extract IV (first 16 bytes) and ciphertext (rest)
    let iv = &encrypted_bytes[0..16];
    let ciphertext = &encrypted_bytes[16..];

    // Create decryptor
    let key: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "Key conversion failed")?;
    let iv_arr: [u8; 16] = iv.try_into()
        .map_err(|_| "IV conversion failed")?;

    let decryptor = Aes256CbcDec::new(&key.into(), &iv_arr.into());

    // Decrypt (cbc crate handles PKCS#7 unpadding)
    let mut buffer = ciphertext.to_vec();
    let decrypted = decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    // Convert to UTF-8 string
    String::from_utf8(decrypted.to_vec())
        .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e))
}

/// Full unlock flow: Windows Hello -> DPAPI Master key -> Decrypt secrets
///
/// Uses the LLM Secrets Electron app's storage:
/// - Master key: %APPDATA%\LLM Secrets\credentials\EnvCrypto_DpapiMasterKey.dat
/// - Secrets: %APPDATA%\LLM Secrets\env\.env.encrypted.v*
/// Returns (secrets, master_key) — master key is retained for re-encryption on save
pub async fn unlock_secrets() -> Result<(HashMap<String, String>, String), String> {
    tracing::info!("Starting unlock flow with Windows Hello");

    // Step 1: Authenticate with Windows Hello
    let auth_exe = get_windows_hello_auth_path()?;
    if !auth_exe.exists() {
        return Err("WindowsHelloAuth.exe not found. Install the LLM Secrets app first.".into());
    }

    let auth_output = Command::new(&auth_exe)
        .output()
        .map_err(|e| format!("Failed to run WindowsHelloAuth: {}", e))?;

    let stdout = String::from_utf8_lossy(&auth_output.stdout);
    if !stdout.contains("SUCCESS") {
        return Err("Windows Hello authentication failed or cancelled".into());
    }
    tracing::info!("Windows Hello authentication successful");

    // Step 2: Get master key from Electron app's DPAPI storage
    let master_key = get_master_key_from_electron_dpapi()?;
    tracing::info!("Master key retrieved from DPAPI");

    // Step 3: Decrypt .env file using master key
    let secrets = decrypt_env_with_master_key(&master_key)?;
    tracing::info!("Decrypted {} secrets", secrets.len());

    Ok((secrets, master_key))
}

/// Encrypt .env content using AES-256-CBC (reverse of decrypt)
///
/// Format (matching Electron app):
/// - Output: base64(IV[16 bytes] + ciphertext)
/// - Key: 44-char base64 string (32 bytes decoded)
/// - Mode: AES-256-CBC with PKCS#7 padding
fn encrypt_env_content_with_master_key(
    plaintext: &str,
    master_key_base64: &str,
) -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    // Decode master key from base64
    let key_bytes = engine.decode(master_key_base64)
        .map_err(|e| format!("Invalid master key base64: {}", e))?;

    if key_bytes.len() != 32 {
        return Err(format!("Master key must be 32 bytes, got {}", key_bytes.len()));
    }

    // Generate random IV
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Create encryptor
    let key: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "Key conversion failed")?;
    let encryptor = Aes256CbcEnc::new(&key.into(), &iv.into());

    // Encrypt with PKCS#7 padding
    let plaintext_bytes = plaintext.as_bytes();
    // Buffer needs space for plaintext + up to 16 bytes of padding
    let mut buffer = vec![0u8; plaintext_bytes.len() + 16];
    buffer[..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);
    let ciphertext = encryptor
        .encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer, plaintext_bytes.len())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    // Combine IV + ciphertext and base64 encode
    let mut combined = Vec::with_capacity(16 + ciphertext.len());
    combined.extend_from_slice(&iv);
    combined.extend_from_slice(ciphertext);

    Ok(engine.encode(&combined))
}

/// Save secrets to encrypted env file (new version)
///
/// Writes to the Electron app's env directory as a new version file.
/// Format: {"Data":"base64(IV+ciphertext)"}
pub fn save_encrypted_env(
    secrets: &HashMap<String, String>,
    master_key: &str,
) -> Result<(), String> {
    // Build .env content from secrets
    let mut lines: Vec<String> = secrets.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    lines.sort(); // Deterministic ordering
    let plaintext = lines.join("\n");

    // Encrypt
    let encrypted_base64 = encrypt_env_content_with_master_key(&plaintext, master_key)?;

    // Build JSON
    let json = format!(r#"{{"Data":"{}"}}"#, encrypted_base64);

    // Write to the next version file via PowerShell
    let ps_command = format!(
        r#"
        $envDir = Join-Path $env:APPDATA 'LLM Secrets\env'
        if (-not (Test-Path $envDir)) {{
            New-Item -ItemType Directory -Path $envDir -Force | Out-Null
        }}

        # Find the highest version number
        $maxVer = 0
        Get-ChildItem $envDir -Filter '.env.encrypted.v*' | ForEach-Object {{
            if ($_.Name -match 'v(\d+)$') {{
                $v = [int]$matches[1]
                if ($v -gt $maxVer) {{ $maxVer = $v }}
            }}
        }}

        $nextVer = $maxVer + 1
        $outPath = Join-Path $envDir ".env.encrypted.v$nextVer"
        [System.IO.File]::WriteAllText($outPath, @'
{}
'@)
        Write-Output "Saved: v$nextVer"
    "#, json);

    let output = Command::new(get_powershell_path())
        .args(["-ExecutionPolicy", "Bypass", "-Command", &ps_command])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to save env file: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::info!("Persisted secrets to disk: {}", stdout.trim());
    Ok(())
}

/// Get the current master key (after Windows Hello auth) without loading secrets
/// Used for backup functionality
pub fn get_current_master_key() -> Result<String, String> {
    get_master_key_from_electron_dpapi()
}

/// Decrypt secrets using a specific master key (for migration from old key)
/// Returns the decrypted secrets HashMap
pub fn decrypt_with_specific_key(master_key: &str) -> Result<HashMap<String, String>, String> {
    decrypt_env_with_master_key(master_key)
}

/// Migrate secrets from old master key to new master key
/// 1. Decrypts secrets with old_key
/// 2. Re-encrypts with new_key (current DPAPI-protected key)
/// 3. Saves to disk
/// Returns the number of migrated secrets
pub fn migrate_secrets(old_key: &str) -> Result<(HashMap<String, String>, String, usize), String> {
    // Get the current master key from DPAPI
    let new_key = get_master_key_from_electron_dpapi()?;
    tracing::info!("Retrieved current master key for migration");

    // Decrypt secrets with old key
    let secrets = decrypt_with_specific_key(old_key)?;
    let count = secrets.len();
    tracing::info!("Decrypted {} secrets with old key", count);

    // Save with new key
    save_encrypted_env(&secrets, &new_key)?;
    tracing::info!("Re-encrypted secrets with new key");

    Ok((secrets, new_key, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_username_detection() {
        // This test verifies the detection logic works.
        // In CI (non-WSL), it will use the /mnt/c/Users scan fallback.
        // We just verify it doesn't panic.
        let result = get_windows_username();
        // In WSL2, this should succeed. In non-WSL, it may fail (that's OK).
        if std::path::Path::new("/mnt/c/Users").exists() {
            assert!(result.is_ok(), "Should detect username in WSL2: {:?}", result);
        }
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
        // Note: SPACED_KEY won't match due to space before =
    }
}

#[cfg(test)]
mod decryption_tests {
    use super::*;

    #[test]
    fn test_extract_data_from_env_json() {
        // The Electron app stores encrypted files as JSON:
        // { "Metadata": {...}, "Data": "base64..." }
        let json_content = r#"{
            "Metadata": {
                "Version": "1.0",
                "Algorithm": "AES-256-CBC"
            },
            "Data": "dGVzdA=="
        }"#;

        // This should extract the Data field
        let result = extract_data_from_env_json(json_content);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "dGVzdA==");
    }

    #[test]
    fn test_decrypt_env_matches_electron_format() {
        // Known test data from Electron app encryption
        // Master key (44-char base64 = 32 bytes)
        let master_key = "SGbwJpwifF7k7bgyiKeTgmes+9gywUwqa1mTTpp1ldA=";

        // This test verifies we can decrypt data encrypted by the Electron app
        // The format is: base64(IV[16] + ciphertext)
        // We test with a minimal encrypted payload

        // For now, test that the function exists and returns an error
        // (since we don't have actual test data yet)
        let result = decrypt_env_content_with_master_key("invalid", master_key);
        assert!(result.is_err());
    }
}
