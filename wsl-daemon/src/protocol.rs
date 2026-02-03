// wsl2-helper/src/protocol.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Request from client to daemon
#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum Request {
    /// Store session with secrets (GUI sends this after DPAPI decrypt)
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

    /// Unlock secrets via Windows Hello (triggers biometric auth)
    /// This decrypts secrets from disk and loads them into memory
    #[serde(rename = "unlock")]
    Unlock {
        ttl: Option<u64>,  // Session TTL in seconds, default 7200 (2 hours)
    },

    /// Check if Windows Hello is available
    #[serde(rename = "check_hello")]
    CheckHello,

    /// Extend the current session (reset timer, optionally change TTL)
    #[serde(rename = "extend")]
    Extend {
        ttl: Option<u64>,  // New TTL in seconds; if None, keep current TTL
    },

    /// Backup the current master key (requires Windows Hello + GUI challenge)
    #[serde(rename = "backup_key")]
    BackupKey,

    /// Migrate secrets from an old master key to the current one
    #[serde(rename = "migrate")]
    Migrate {
        old_key: String,  // Base64-encoded old master key (44 chars)
    },
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
    HelloAvailable { available: bool },
    Unlocked { count: usize },
    Extended { remaining: i64 },
    BackupKey { key: String },
    Migrated { count: usize },
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
