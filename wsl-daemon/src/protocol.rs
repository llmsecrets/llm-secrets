// scrt3/src/protocol.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Request from client to daemon
#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum Request {
    /// Store session with secrets
    #[serde(rename = "store")]
    Store {
        token: String,  // Base64-encoded random token
        secrets: HashMap<String, String>,
        ttl: u64,  // Seconds, 0 = no expiry
    },

    /// Clear the session
    #[serde(rename = "clear")]
    Clear,

    /// Check session status
    #[serde(rename = "status")]
    Status,

    /// List secret names (not values)
    #[serde(rename = "list")]
    List,

    /// Run command with $env[NAME] substitution
    #[serde(rename = "run")]
    Run {
        command: String,
        working_dir: Option<String>,
        /// Optional list of secret names to scope (only these will be substituted)
        /// If not specified, all secrets are available
        scope: Option<Vec<String>>,
    },

    /// Reveal single secret (Phase 1: returns a challenge)
    #[serde(rename = "reveal")]
    Reveal {
        name: String,
    },

    /// Confirm a reveal challenge (second phase of authenticated reveal)
    #[serde(rename = "reveal_confirm")]
    RevealConfirm {
        challenge: String,  // Nonce from Phase 1
        code: String,       // Display code the user typed in Zenity
    },

    /// Reveal all secrets (requires single GUI challenge)
    #[serde(rename = "reveal_all")]
    RevealAll,

    /// Confirm reveal_all
    #[serde(rename = "reveal_all_confirm")]
    RevealAllConfirm {
        challenge: String,
        code: String,
    },

    /// Add secrets to an active session (merge, no reveal needed)
    #[serde(rename = "add_secrets")]
    AddSecrets {
        secrets: HashMap<String, String>,
    },

    /// Unlock secrets via passphrase (+ optional TOTP)
    /// Decrypts master key with passphrase, then decrypts secrets
    #[serde(rename = "unlock")]
    Unlock {
        ttl: Option<u64>,           // Session TTL in seconds, default 7200 (2 hours)
        totp_code: Option<String>,  // 6-digit TOTP code (required when 2FA enabled)
        passphrase: String,         // Vault passphrase (always required)
    },

    /// Check if TOTP is configured
    #[serde(rename = "check_totp")]
    CheckTotp,

    /// Generate a new TOTP secret (for initial setup)
    #[serde(rename = "setup_totp")]
    SetupTotp,

    /// Verify a TOTP code during setup (confirms user scanned QR correctly)
    #[serde(rename = "verify_totp_setup")]
    VerifyTotpSetup {
        code: String,
    },

    /// Extend the current session (reset timer, optionally change TTL)
    #[serde(rename = "extend")]
    Extend {
        ttl: Option<u64>,  // New TTL in seconds; if None, keep current TTL
    },

    /// Backup the current master key (requires active session)
    #[serde(rename = "backup_key")]
    BackupKey,

    /// Migrate secrets from an old master key to a new passphrase-protected key
    #[serde(rename = "migrate")]
    Migrate {
        old_key: String,     // Base64-encoded old master key (44 chars)
        passphrase: String,  // New passphrase to protect the new master key
    },

    /// Generate fresh encryption keys and reset the secret store
    /// Called during setup-2fa to bind new auth to new encryption
    #[serde(rename = "initialize_keys")]
    InitializeKeys {
        passphrase: String,  // Passphrase to protect the new master key
    },

    /// Check 2FA state (configured + enabled/disabled)
    #[serde(rename = "check_tfa_state")]
    CheckTfaState,

    /// Disable 2FA for reveal operations (requires valid TOTP to prove authenticator access)
    #[serde(rename = "disable_tfa")]
    DisableTfa { totp_code: String },

    /// Re-enable 2FA for reveal operations (requires valid TOTP)
    #[serde(rename = "enable_tfa")]
    EnableTfa { totp_code: String },

    /// Check 2FA unlock state (configured + enabled/disabled for unlock)
    #[serde(rename = "check_tfa_unlock_state")]
    CheckTfaUnlockState,

    /// Disable 2FA for unlock operations (requires valid TOTP)
    #[serde(rename = "disable_tfa_unlock")]
    DisableTfaUnlock { totp_code: String },

    /// Re-enable 2FA for unlock operations (requires valid TOTP)
    #[serde(rename = "enable_tfa_unlock")]
    EnableTfaUnlock { totp_code: String },
}

/// Response from daemon to client
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ResponseData>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ResponseData {
    Status { active: bool, remaining: i64 },
    List { names: Vec<String> },
    Run { exit_code: i32, output: String },
    Reveal { value: String },
    Challenge { challenge: String, prompt: String, code: String },
    RevealAll { secrets: HashMap<String, String> },
    TotpConfigured { configured: bool },
    TotpSetup { secret: String, otpauth_uri: String },
    Unlocked { count: usize },
    Extended { remaining: i64 },
    BackupKey { key: String },
    Migrated { count: usize },
    TfaState { configured: bool, enabled: bool, unlock_enabled: bool },
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
}

impl Response {
    pub fn ok() -> Self {
        Response::Success(SuccessResponse { success: true, data: None })
    }

    pub fn ok_with_data(data: ResponseData) -> Self {
        Response::Success(SuccessResponse { success: true, data: Some(data) })
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Response::Error(ErrorResponse { success: false, error: msg.into() })
    }
}
