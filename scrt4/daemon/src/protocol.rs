// scrt4/src/protocol.rs
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
        challenge: String,
        code: String,
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

    /// Unlock secrets via WebAuthn PRF (opens browser for authentication)
    #[serde(rename = "unlock_webauthn")]
    UnlockWebauthn {
        ttl: Option<u64>,  // Session TTL in seconds, default 7200 (2 hours)
    },

    /// Setup WebAuthn credential — phase 1: get relay URL for QR code
    #[serde(rename = "setup_webauthn")]
    SetupWebauthn,

    /// Setup WebAuthn credential — phase 2: complete with relay payload
    #[serde(rename = "setup_webauthn_complete")]
    SetupWebauthnComplete {
        encrypted_payload: String,
        wrapping_key: String,
        prf_salt_b64: String,
    },

    /// Unlock WebAuthn — phase 2: complete with relay payload
    #[serde(rename = "unlock_webauthn_complete")]
    UnlockWebauthnComplete {
        encrypted_payload: String,
        wrapping_key: String,
        ttl: Option<u64>,
    },

    /// Extend the current session (reset timer, optionally change TTL)
    #[serde(rename = "extend")]
    Extend {
        ttl: Option<u64>,
    },

    /// Backup the current master key (requires active session)
    #[serde(rename = "backup_key")]
    BackupKey,

    /// Generate fresh encryption keys via WebAuthn registration
    /// Opens browser for credential registration, then encrypts master key with PRF
    #[serde(rename = "initialize_keys_webauthn")]
    InitializeKeysWebauthn,

    /// Check WebAuthn 2FA state (configured + enabled/disabled)
    #[serde(rename = "check_wa_state")]
    CheckWaState,

    /// Disable WebAuthn 2FA for reveal operations
    #[serde(rename = "disable_wa")]
    DisableWa,

    /// Re-enable WebAuthn 2FA for reveal operations
    #[serde(rename = "enable_wa")]
    EnableWa,

    /// Disable WebAuthn 2FA for unlock operations
    #[serde(rename = "disable_wa_unlock")]
    DisableWaUnlock,

    /// Re-enable WebAuthn 2FA for unlock operations
    #[serde(rename = "enable_wa_unlock")]
    EnableWaUnlock,

    /// Start localhost WebAuthn server for unlock (phase 1)
    #[serde(rename = "unlock_local")]
    UnlockLocal {
        ttl: Option<u64>,
    },

    /// Wait for localhost callback and complete unlock (phase 2)
    #[serde(rename = "unlock_local_complete")]
    UnlockLocalComplete {
        ttl: Option<u64>,
    },

    /// Start localhost WebAuthn server for setup/registration (phase 1)
    #[serde(rename = "setup_local")]
    SetupLocal,

    /// Wait for localhost callback and complete setup (phase 2)
    #[serde(rename = "setup_local_complete")]
    SetupLocalComplete,

    // ── Share module (issue #61) ─────────────────────────────────────
    //
    // The share module's bash side calls these three methods. They live
    // in core (not behind a module gate) because:
    //   1. The crypto runs daemon-side and is in the TCB
    //   2. The protocol surface is tiny and stable
    //   3. Any module that wants to ship a share-like UX over wormhole
    //      can reuse this same protocol

    /// Encrypt a subset of secrets into a temp file using a fresh
    /// ephemeral key. Returns the path to the encrypted file plus the
    /// count of secrets sealed.
    #[serde(rename = "share_seal")]
    ShareSeal {
        /// Specific secret names to share. Mutually exclusive with `all`.
        #[serde(default)]
        names: Option<Vec<String>>,
        /// Share all secrets in the active session.
        #[serde(default)]
        all: Option<bool>,
    },

    /// Decrypt a received share file and return only the secret NAMES
    /// (no values). Used by the receive flow to show the user what's
    /// coming before they confirm the import.
    #[serde(rename = "share_inventory")]
    ShareInventory {
        path: String,
    },

    /// Decrypt a received share file and merge its contents into the
    /// active session's vault. Returns the number of secrets imported.
    /// The caller is responsible for shredding the file afterward.
    #[serde(rename = "share_import")]
    ShareImport {
        path: String,
    },

    // ── Core: Encrypted-folder inventory (F027, F028) ──────────
    //
    // Tracks .scrt4 archives produced by `scrt4 encrypt-folder` so
    // the user can list them later and clean up entries whose files
    // have been moved or deleted. Reclassified from encrypt-folder
    // module stubs to Core on 2026-04-13 — the inventory is part of
    // the daemon's cryptographic bookkeeping, not a module concern.

    #[serde(rename = "register_encrypted")]
    RegisterEncrypted {
        path: String,
        folder_name: String,
        file_count: u32,
        archive_size: u64,
    },

    #[serde(rename = "unregister_encrypted")]
    UnregisterEncrypted { id: String },

    #[serde(rename = "mark_decrypted")]
    MarkDecrypted { path: String },

    #[serde(rename = "list_encrypted")]
    ListEncrypted,

    #[serde(rename = "cleanup_encrypted")]
    CleanupEncrypted { remove_missing: bool },
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
    Unlocked { count: usize },
    Extended { remaining: i64 },
    BackupKey { key: String },
    WaState { configured: bool, enabled: bool, unlock_enabled: bool },
    RelaySetup { url: String, session_id: String, wrapping_key: String, prf_salt_b64: String },
    LocalUrl { url: String },
    ShareSealed { path: String, count: usize },
    ShareInventoried { names: Vec<String>, count: usize },
    ShareImported { count: usize },

    // ── Core: Encrypted-folder inventory (F027, F028) ──────────
    EncryptedRegistered { id: String, path: String },
    EncryptedUnregistered { removed: bool, id: String },
    EncryptedMarkedDecrypted { path: String },
    EncryptedList { entries: Vec<serde_json::Value> },
    EncryptedCleanup {
        present_count: usize,
        missing_count: usize,
        removed_count: usize,
        missing_paths: Vec<String>,
    },
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
