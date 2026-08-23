// scrt4/src/protocol.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The wire envelope that carries the session token (INV-SK-1).
///
/// Parsed SEPARATELY from `Request` so the token authenticates the CHANNEL
/// while the request describes the OPERATION. Keeping them apart means a
/// token can never be mistaken for part of the operation.
#[derive(Debug, Default, Deserialize)]
pub struct Envelope {
    /// Session token from the unlock that established this session, base64.
    #[serde(default)]
    pub session_token: Option<String>,
}

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






    //
    // Re-encrypt the entire vault under a freshly generated master
    // key. Requires active session + WebAuthn step-up (or dev-mode
    // bypass). In hardened mode this atomically replaces the secrets
    // file but leaves the master.key WebAuthn wrapper stale — the
    // caller is responsible for immediately backing up the new key
    // (scrt4 backup-key --save) or re-enrolling (scrt4 setup). The
    // daemon returns the new master key in the response so the CLI
    // can drive that follow-up. Full two-phase rotation that also
    // re-wraps master.key under a fresh PRF is a future follow-up.
    #[serde(rename = "rotate_vault")]
    RotateVault,

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

    // Encrypt TO a public share address instead of to a transport, so a
    // blob is safe at rest and sender/recipient need not be online
    // together. See issues #86 (design) and #87 (why `share` can't).

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
    Unlocked {
        count: usize,
        /// INV-SK-1: the session token, returned ONLY here — on the
        /// connection that performed the unlock ceremony. Never in
        /// `status`, an error, or a log line.
        #[serde(skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },
    Extended { remaining: i64 },
    BackupKey { key: String },
    WaState { configured: bool, enabled: bool, unlock_enabled: bool },
    RelaySetup { url: String, session_id: String, wrapping_key: String, prf_salt_b64: String, qr: String },
    LocalUrl { url: String },
    VaultRotated {
        new_master_key_b64: String,
        secret_count: usize,
        /// True when the hardened master.key wrapper is now stale and
        /// the caller must follow up with backup-key or setup.
        wrapper_stale: bool,
    },

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
