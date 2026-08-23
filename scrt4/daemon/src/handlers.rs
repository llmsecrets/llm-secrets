// scrt4/src/handlers.rs
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::audit::{self, AuditEvent, EventType, EventResult};
use crate::keystore;
use crate::localhost;
use crate::webauthn;
use crate::protocol::{Envelope, Request, Response, ResponseData};
use crate::session::SharedSession;
use crate::subprocess::run_with_secrets;

/// WebAuthn verification window for sensitive operations (seconds).
/// After completing a WebAuthn ceremony, sensitive operations are allowed
/// for this many seconds before requiring re-verification.
const WA_VERIFY_WINDOW_SECS: u64 = 120;

/// Global session state (initialized in main)
static SESSION: std::sync::OnceLock<SharedSession> = std::sync::OnceLock::new();

pub fn init_session(session: SharedSession) {
    SESSION.set(session).expect("Session already initialized");
}

fn get_session() -> &'static SharedSession {
    SESSION.get().expect("Session not initialized")
}

/// Handle a request from a JSON string (used by remote connections)
pub async fn handle_request_string(json: &str) -> String {
    let response = handle_request(json).await;
    serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"success":false,"error":"Serialization failed"}"#.to_string()
    })
}

/// Handle a client connection. Generic over the transport so the same
/// loop serves the Unix socket (WSL/Linux) and the named pipe (Windows).
pub async fn handle_connection<S>(stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();

        match reader.read_line(&mut line).await {
            Ok(0) => break,  // Connection closed
            Ok(_) => {
                let response = handle_request(&line).await;
                let json = serde_json::to_string(&response).unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization failed"}"#.to_string()
                });

                if let Err(e) = writer.write_all(format!("{}\n", json).as_bytes()).await {
                    tracing::error!("Write error: {}", e);
                    break;
                }
            }
            Err(e) => {
                tracing::error!("Read error: {}", e);
                break;
            }
        }
    }
}

async fn handle_request(line: &str) -> Response {
    let request: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::InvalidRequest, EventResult::Failure)
                    .with_error(&e.to_string())
            );
            return Response::error(format!("Invalid request: {}", e));
        }
    };

    // a request that uses the unlocked session must present the token
    // minted when it was unlocked. Checked HERE, once, ahead of the dispatch —
    // not inside each handler — so a handler cannot be added without the check,
    // and so the classification lives in exactly one place
    // (`session_binding::binding`, which has no wildcard arm).
    //
    // The envelope is parsed separately from `Request`: the token authenticates
    // the CHANNEL, the request describes the OPERATION.
    //
    // A malformed envelope is treated as "no token" rather than a parse error —
    // its only field is optional, so the sole way to fail is a line that is not
    // an object, which `Request` has already rejected above.
    if crate::session_binding::requires_token(&request) {
        let envelope: Envelope = serde_json::from_str(line).unwrap_or_default();

        let ok = match envelope.session_token.as_deref() {
            Some(t) => get_session().read().await.verify_token(t),
            None => false,
        };

        if !ok {
            // ⚠️ ONE message for absent, malformed, wrong, and no-active-session.
            // Distinguishing them would hand an unauthenticated caller an oracle
            // for session state — which is the reconnaissance step (`status`,
            // then `run`) that this layer exists to break.
            audit::log_event(
                AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                    .with_error("session token missing or invalid")
            );
            tracing::warn!(
                "refused a request that requires the session token; \
                 token_presented={}",
                envelope.session_token.is_some()
            );
            return Response::error(
                "This request requires the session token from `scrt4 unlock`. \
                 Run `scrt4 unlock` in this shell, or re-run it if the session \
                 was started elsewhere."
            );
        }
    }

    match request {
        Request::Store { token, secrets, ttl } => handle_store(token, secrets, ttl).await,
        Request::Clear => handle_clear().await,
        Request::Status => handle_status().await,
        Request::List => handle_list().await,
        Request::Run { command, working_dir, scope } => handle_run(command, working_dir, scope).await,
        Request::Reveal { name } => handle_reveal(name).await,
        Request::RevealConfirm { challenge, code } => handle_reveal_confirm(challenge, code).await,
        Request::RevealAll => handle_reveal_all().await,
        Request::RevealAllConfirm { challenge, code } => handle_reveal_all_confirm(challenge, code).await,
        Request::AddSecrets { secrets } => handle_add_secrets(secrets).await,
        Request::UnlockWebauthn { ttl } => handle_unlock_webauthn(ttl).await,
        Request::SetupWebauthn => handle_setup_webauthn_init().await,
        Request::SetupWebauthnComplete { encrypted_payload, wrapping_key, prf_salt_b64 } =>
            handle_setup_webauthn_complete(encrypted_payload, wrapping_key, prf_salt_b64).await,
        Request::UnlockWebauthnComplete { encrypted_payload, wrapping_key, ttl } =>
            handle_unlock_webauthn_complete(encrypted_payload, wrapping_key, ttl).await,
        Request::Extend { ttl } => handle_extend(ttl).await,
        Request::BackupKey => handle_backup_key().await,
        Request::InitializeKeysWebauthn => handle_initialize_keys_webauthn().await,
        Request::CheckWaState => handle_check_wa_state().await,
        Request::DisableWa => handle_disable_wa().await,
        Request::EnableWa => handle_enable_wa().await,
        Request::DisableWaUnlock => handle_disable_wa_unlock().await,
        Request::EnableWaUnlock => handle_enable_wa_unlock().await,
        Request::UnlockLocal { ttl } => handle_unlock_local(ttl).await,
        Request::UnlockLocalComplete { ttl } => handle_unlock_local_complete(ttl).await,
        Request::SetupLocal => handle_setup_local().await,
        Request::SetupLocalComplete => handle_setup_local_complete().await,







        Request::RotateVault => handle_rotate_vault().await,

        // ── Core: Encrypted-folder inventory (F027, F028) ───────
        Request::RegisterEncrypted { path, folder_name, file_count, archive_size } =>
            handle_register_encrypted(path, folder_name, file_count, archive_size).await,
        Request::UnregisterEncrypted { id } => handle_unregister_encrypted(id).await,
        Request::MarkDecrypted { path } => handle_mark_decrypted(path).await,
        Request::ListEncrypted => handle_list_encrypted().await,
        Request::CleanupEncrypted { remove_missing } => handle_cleanup_encrypted(remove_missing).await,
    }
}

// ── Share module handlers (issue #61) ────────────────────────────────
//
// Format of the encrypted share file (designed to be tiny and readable):
//
//   Bytes 0..11    "SCRT4SHARE\n"  (11-byte magic header)
//   Bytes 11..55   base64 of ephemeral 32-byte AES-GCM key (44 chars)
//   Byte 55        '\n'
//   Bytes 56..68   12-byte AES-GCM nonce
//   Bytes 68..end  AES-256-GCM ciphertext of JSON {NAME: VALUE, ...}
//
// The ephemeral key is single-use and travels in the same blob — the
// "encryption" is against accidental disclosure (e.g. wormhole relay
// operator logging the file), not against an attacker who has the file.
// The wormhole transport itself is end-to-end encrypted via SPAKE2.
//
// TCB note: the AES-GCM seal/unseal here is in the trusted computing
// base — a bug could leak secrets to the wormhole-relay-operator threat
// model. The handlers themselves are intentionally short.

//
// key to unseal the vault's signing identity. That means an active
// session, exactly like reveal/backup-key. No new key material is
// exposed to the client — seal returns ciphertext, open returns only
// the secrets already destined for this vault.

async fn handle_store(
    token_b64: String,
    secrets: std::collections::HashMap<String, String>,
    ttl: u64,
) -> Response {
    let token = match base64::engine::general_purpose::STANDARD.decode(&token_b64) {
        Ok(t) => t,
        Err(_) => return Response::error("Invalid base64 token"),
    };

    let mut session = get_session().write().await;

    // Preserve master key across store (edit flow clears and re-stores)
    let saved_master_key = session.master_key().map(|k| k.to_string());

    match session.store(token, secrets, ttl) {
        Ok(()) => {
            // Restore master key if we had one (from a previous unlock)
            if let Some(key) = saved_master_key {
                session.set_master_key(key);
            }

            // Persist updated secrets to encrypted env file on disk
            if let (Some(all_secrets), Some(master_key)) = (session.secrets(), session.master_key()) {
                if let Err(e) = keystore::save_encrypted_env(all_secrets, master_key) {
                    tracing::error!("Failed to persist secrets to disk: {}", e);
                }
            }

            Response::ok()
        }
        Err(e) => Response::error(e),
    }
}

async fn handle_add_secrets(
    secrets: std::collections::HashMap<String, String>,
) -> Response {
    let count = secrets.len();
    let mut session = get_session().write().await;
    match session.add_secrets(secrets) {
        Ok(added) => {
            // Persist updated secrets to encrypted env file on disk
            if let (Some(all_secrets), Some(master_key)) = (session.secrets(), session.master_key()) {
                if let Err(e) = keystore::save_encrypted_env(all_secrets, master_key) {
                    tracing::error!("Failed to persist secrets to disk: {}", e);
                }
            }

            audit::log_event(
                AuditEvent::new(EventType::SecretsAdded, EventResult::Success)
                    .with_secret_count(added)
            );
            Response::ok_with_data(ResponseData::Unlocked {
                count,
                // Not an unlock: this reuses an existing session, so it must
                // not reissue the token to whoever called it.
                session_token: None,
            })
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::SecretsAdded, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

async fn handle_clear() -> Response {
    let mut session = get_session().write().await;
    session.clear();
    audit::log_simple(EventType::SessionEnd, EventResult::Success);
    Response::ok()
}

async fn handle_status() -> Response {
    let session = get_session().read().await;
    Response::ok_with_data(ResponseData::Status {
        active: session.is_active(),
        remaining: session.remaining_secs(),
    })
}

async fn handle_list() -> Response {
    let session = get_session().read().await;
    match session.secret_names() {
        Some(names) => {
            audit::log_event(
                AuditEvent::new(EventType::SecretList, EventResult::Success)
                    .with_secret_count(names.len())
            );
            Response::ok_with_data(ResponseData::List { names })
        }
        None => {
            audit::log_event(
                AuditEvent::new(EventType::SecretList, EventResult::Failure)
                    .with_error("No active session")
            );
            Response::error("No active session")
        }
    }
}

async fn handle_run(command: String, working_dir: Option<String>, scope: Option<Vec<String>>) -> Response {
    let session = get_session().read().await;

    let all_secrets = match session.secrets() {
        Some(s) => s.clone(),
        None => {
            audit::log_event(
                AuditEvent::new(EventType::CommandRun, EventResult::Failure)
                    .with_command(&command)
                    .with_error("No active session")
            );
            return Response::error("No active session - authenticate first");
        }
    };

    drop(session);  // Release lock before we do the classification work

    // Apply scope filter if specified
    let secrets = if let Some(ref allowed_names) = scope {
        let mut filtered = std::collections::HashMap::new();
        for name in allowed_names {
            if let Some(value) = all_secrets.get(name) {
                filtered.insert(name.clone(), value.clone());
            }
        }
        filtered
    } else {
        all_secrets
    };

    let secret_count = secrets.len();

    match run_with_secrets(&command, working_dir.as_deref(), &secrets).await {
        Ok(result) => {
            audit::log_event(
                AuditEvent::new(EventType::CommandRun, EventResult::Success)
                    .with_command(&command)
                    .with_secret_count(secret_count)
                    .with_exit_code(result.exit_code)
            );
            Response::ok_with_data(ResponseData::Run {
                exit_code: result.exit_code,
                output: result.output,
            })
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::CommandError, EventResult::Failure)
                    .with_command(&command)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

async fn handle_reveal(name: String) -> Response {
    let mut session = get_session().write().await;

    // Always require recent WebAuthn verification for reveal operations.
    // Exception: dev mode (SCRT4_DEV_MODE=1) skips this check — the whole
    // point of the dev distribution is to exercise CLI flows without the
    // WebAuthn ceremony. See keystore::is_dev_mode and issue #59.
    if !keystore::is_dev_mode() && !session.consume_wa_verification(WA_VERIFY_WINDOW_SECS) {
        audit::log_event(
            AuditEvent::new(EventType::RevealChallengeIssued, EventResult::Failure)
                .with_secret_name(&name)
                .with_error("WebAuthn verification required")
        );
        return Response::error("WebAuthn verification required for reveal operations");
    }

    match session.create_challenge(&name) {
        Ok((nonce, display_code)) => {
            audit::log_event(
                AuditEvent::new(EventType::RevealChallengeIssued, EventResult::Pending)
                    .with_secret_name(&name)
            );

            Response::ok_with_data(ResponseData::Challenge {
                challenge: nonce,
                prompt: format!("Reveal secret: {}", name),
                code: display_code,
            })
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::RevealChallengeFailed, EventResult::Failure)
                    .with_secret_name(&name)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

async fn handle_reveal_confirm(challenge: String, code: String) -> Response {
    let mut session = get_session().write().await;

    match session.validate_challenge(&challenge, &code) {
        Ok(value) => {
            audit::log_event(
                AuditEvent::new(EventType::RevealChallengeCompleted, EventResult::Success)
            );
            Response::ok_with_data(ResponseData::Reveal { value })
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::RevealChallengeFailed, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

async fn handle_reveal_all() -> Response {
    let mut session = get_session().write().await;

    // See handle_reveal: same WA gate, same dev-mode exception.
    if !keystore::is_dev_mode() && !session.consume_wa_verification(WA_VERIFY_WINDOW_SECS) {
        audit::log_event(
            AuditEvent::new(EventType::BulkRevealChallengeIssued, EventResult::Failure)
                .with_error("WebAuthn verification required")
        );
        return Response::error("WebAuthn verification required for reveal operations");
    }

    match session.create_bulk_challenge() {
        Ok((nonce, display_code)) => {
            audit::log_event(
                AuditEvent::new(EventType::BulkRevealChallengeIssued, EventResult::Pending)
            );

            Response::ok_with_data(ResponseData::Challenge {
                challenge: nonce,
                prompt: "Reveal all secrets".to_string(),
                code: display_code,
            })
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::RevealChallengeFailed, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

async fn handle_reveal_all_confirm(challenge: String, code: String) -> Response {
    let mut session = get_session().write().await;

    match session.validate_bulk_challenge(&challenge, &code) {
        Ok(secrets) => {
            let count = secrets.len();
            audit::log_event(
                AuditEvent::new(EventType::BulkRevealChallengeCompleted, EventResult::Success)
                    .with_secret_count(count)
            );
            Response::ok_with_data(ResponseData::RevealAll { secrets })
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::RevealChallengeFailed, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

/// Unlock secrets via WebAuthn PRF — phase 1: return relay params for QR code
async fn handle_unlock_webauthn(_ttl: Option<u64>) -> Response {
    audit::log_simple(EventType::AuthAttempt, EventResult::Pending);

    // Check if WebAuthn is configured
    if !webauthn::is_wa_configured() {
        audit::log_event(
            AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                .with_error("WebAuthn not configured — run setup first")
        );
        return Response::error("WebAuthn not configured. Run 'scrt4 setup' first.");
    }

    // Load the stored credential
    let credential = match webauthn::load_credential() {
        Ok(c) => c,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(format!("Failed to load credential: {}", e));
        }
    };

    // Load the PRF salt from the master key file
    let prf_salt = match keystore::load_prf_salt() {
        Ok(s) => s,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(format!("Failed to load PRF salt: {}", e));
        }
    };

    // Generate relay auth params for QR code
    let params = match webauthn::generate_auth_params(&credential, &prf_salt) {
        Ok(p) => p,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(format!("Failed to generate auth params: {}", e));
        }
    };

    tracing::info!("Unlock phase 1: relay URL generated");
    let qr = webauthn::render_qr_string(&params.url);
    Response::ok_with_data(ResponseData::RelaySetup {
        url: params.url,
        session_id: params.session_id,
        wrapping_key: params.wrapping_key,
        prf_salt_b64: params.prf_salt_b64,
        qr,
    })
}

/// Extend the current session (reset timer, optionally change TTL)
async fn handle_extend(ttl: Option<u64>) -> Response {
    let mut session = get_session().write().await;

    match session.extend(ttl) {
        Ok(remaining) => {
            audit::log_event(
                AuditEvent::new(EventType::SessionExtend, EventResult::Success)
                    .with_ttl(ttl.unwrap_or(0))
            );
            Response::ok_with_data(ResponseData::Extended { remaining })
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::SessionExtend, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

/// Check WebAuthn 2FA state (configured + enabled/disabled)
async fn handle_check_wa_state() -> Response {
    let configured = webauthn::is_wa_configured();
    let enabled = webauthn::is_wa_enabled();
    let unlock_enabled = webauthn::is_wa_unlock_enabled();
    Response::ok_with_data(ResponseData::WaState { configured, enabled, unlock_enabled })
}

/// Setup WebAuthn — phase 1: generate relay params and return QR URL to CLI
async fn handle_setup_webauthn_init() -> Response {
    let params = match webauthn::generate_register_params() {
        Ok(p) => p,
        Err(e) => return Response::error(format!("Failed to generate setup params: {}", e)),
    };

    tracing::info!("Setup phase 1: relay URL generated");
    let qr = webauthn::render_qr_string(&params.url);
    Response::ok_with_data(ResponseData::RelaySetup {
        url: params.url,
        session_id: params.session_id,
        wrapping_key: params.wrapping_key,
        prf_salt_b64: params.prf_salt_b64,
        qr,
    })
}

/// Setup WebAuthn — phase 2: complete registration with encrypted relay payload
async fn handle_setup_webauthn_complete(
    encrypted_payload: String,
    wrapping_key: String,
    prf_salt_b64: String,
) -> Response {
    audit::log_event(
        AuditEvent::new(EventType::KeysInitialized, EventResult::Pending)
    );

    let engine = base64::engine::general_purpose::STANDARD;

    // Decrypt relay payload to get registration result
    let reg_result = match webauthn::complete_registration(&encrypted_payload, &wrapping_key) {
        Ok(r) => r,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::KeysInitialized, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(format!("WebAuthn registration failed: {}", e));
        }
    };

    // Decode PRF salt
    let prf_salt_bytes = match engine.decode(&prf_salt_b64) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return Response::error("Invalid PRF salt");
        }
    };

    // Save credential
    if let Err(e) = webauthn::save_credential(&reg_result.credential) {
        audit::log_event(
            AuditEvent::new(EventType::KeysInitialized, EventResult::Failure)
                .with_error(&e)
        );
        return Response::error(format!("Failed to save credential: {}", e));
    }

    // Generate fresh master key
    let master_key = match keystore::generate_new_master_key() {
        Ok(k) => k,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::KeysInitialized, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(format!("Key generation failed: {}", e));
        }
    };

    // NEVER log PRF bytes or any part of the master key. The PRF output IS the
    // wrapping key, and a prefix of the master key is still master key. The
    // only thing worth knowing here is that we got a well-formed one.
    tracing::info!("Setup: PRF output received ({} bytes)", reg_result.prf_output.len());
    tracing::info!("Setup: master key generated ({} chars, base64)", master_key.len());

    // Encrypt master key with PRF output
    if let Err(e) = keystore::save_master_key_webauthn(
        &master_key,
        &reg_result.prf_output,
        &prf_salt_bytes,
        Some(&reg_result.credential.credential_id),
    ) {
        audit::log_event(
            AuditEvent::new(EventType::KeysInitialized, EventResult::Failure)
                .with_error(&e)
        );
        return Response::error(format!("Failed to save master key: {}", e));
    }

    // Create fresh empty secret store
    if let Err(e) = keystore::reset_encrypted_env(&master_key) {
        audit::log_event(
            AuditEvent::new(EventType::KeysInitialized, EventResult::Failure)
                .with_error(&e)
        );
        return Response::error(format!("Failed to initialize secret store: {}", e));
    }

    // Clear any existing session to prevent stale master keys from being used.
    // Without this, a subsequent `add` would persist secrets.enc with the OLD
    // master key, making the vault unreadable after unlock with the NEW key.
    {
        let mut session = get_session().write().await;
        session.clear();
        tracing::info!("Cleared old session after setup (prevents stale master key usage)");
    }

    audit::log_event(
        AuditEvent::new(EventType::KeysInitialized, EventResult::Success)
    );
    Response::ok()
}

/// Unlock WebAuthn — phase 2: complete with encrypted relay payload
async fn handle_unlock_webauthn_complete(
    encrypted_payload: String,
    wrapping_key: String,
    ttl: Option<u64>,
) -> Response {
    let auth_result = match webauthn::complete_authentication(&encrypted_payload, &wrapping_key) {
        Ok(r) => r,
        Err(e) => return Response::error(format!("WebAuthn auth failed: {}", e)),
    };

    // See the note in handle_setup_webauthn_complete: no PRF bytes, no master
    // key bytes, not even a prefix.
    tracing::info!("PRF output received ({} bytes)", auth_result.prf_output.len());

    // Load master key using PRF output
    let master_key = match keystore::load_master_key_webauthn(&auth_result.prf_output) {
        Ok(k) => {
            tracing::info!("Master key unwrapped OK ({} chars, base64)", k.len());
            k
        }
        Err(e) => return Response::error(format!("Failed to decrypt master key: {}", e)),
    };

    // Log vault file info for debugging
    {
        let vault_path = keystore::secrets_path();
        if let Ok(contents) = std::fs::read_to_string(&vault_path) {
            tracing::info!("Vault file ({} bytes): {}", contents.len(),
                &contents[..contents.len().min(80)]);
        } else {
            tracing::warn!("Cannot read vault file at {:?}", vault_path);
        }
    }

    // Decrypt secrets using master key
    let secrets = match keystore::decrypt_secrets(&master_key) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Vault decryption failed with master key len={}: {}", master_key.len(), e);
            return Response::error(format!("Failed to load secrets: {}", e));
        }
    };

    let count = secrets.len();
    let ttl_secs = ttl.unwrap_or(7200);

    // Generate a random token and store secrets in session
    let token: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let mut session = get_session().write().await;
    match session.store(token, secrets, ttl_secs) {
        Ok(()) => {
            session.set_master_key(master_key);
            session.set_wa_verified();
            audit::log_event(
                AuditEvent::new(EventType::AuthSuccess, EventResult::Success)
            );
            audit::log_event(
                AuditEvent::new(EventType::SessionStart, EventResult::Success)
                    .with_ttl(ttl_secs)
                    .with_secret_count(count)
            );
            Response::ok_with_data(ResponseData::Unlocked {
                count,
                // the only path the token leaves the daemon by.
                session_token: session.token_b64(),
            })
        }
        Err(e) => Response::error(e),
    }
}

/// Backup the current master key
async fn handle_backup_key() -> Response {
    let mut session = get_session().write().await;

    // Always require recent WebAuthn verification for backup key access
    // (single-use). Dev mode skips this gate — the dev master key is a
    // hardcoded constant in the source anyway, so requiring auth would
    // be theatre. See issue #59.
    if !keystore::is_dev_mode() && !session.consume_wa_verification(WA_VERIFY_WINDOW_SECS) {
        audit::log_event(
            AuditEvent::new(EventType::BackupKeyRequested, EventResult::Failure)
                .with_error("WebAuthn verification required")
        );
        return Response::error("WebAuthn verification required for backup key access");
    }

    match session.master_key() {
        Some(key) => {
            audit::log_event(
                AuditEvent::new(EventType::BackupKeyRequested, EventResult::Success)
            );
            Response::ok_with_data(ResponseData::BackupKey { key: key.to_string() })
        }
        None => {
            audit::log_event(
                AuditEvent::new(EventType::BackupKeyRequested, EventResult::Failure)
                    .with_error("No active session or master key not available")
            );
            Response::error("No active session. Run 'scrt4 unlock' first to access the master key.")
        }
    }
}

/// Generate fresh encryption keys via WebAuthn registration
/// (Redirects to the relay-based setup flow)
async fn handle_initialize_keys_webauthn() -> Response {
    handle_setup_webauthn_init().await
}

/// Disable WebAuthn 2FA for reveal operations
async fn handle_disable_wa() -> Response {
    // Require active session + recent WebAuthn verification (single-use).
    // Dev mode skips both — auth is off across the board, see issue #59.
    if !keystore::is_dev_mode() {
        let mut session = get_session().write().await;
        if !session.is_active() {
            return Response::error("Active session required to change WebAuthn settings");
        }
        if !session.consume_wa_verification(WA_VERIFY_WINDOW_SECS) {
            audit::log_event(
                AuditEvent::new(EventType::WaDisabled, EventResult::Failure)
                    .with_error("WebAuthn verification required")
            );
            return Response::error("WebAuthn verification required to disable WebAuthn 2FA");
        }
    }

    match webauthn::set_wa_state(false) {
        Ok(()) => {
            audit::log_event(
                AuditEvent::new(EventType::WaDisabled, EventResult::Success)
            );
            Response::ok()
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::WaDisabled, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

/// Re-enable WebAuthn 2FA for reveal operations
async fn handle_enable_wa() -> Response {
    match webauthn::set_wa_state(true) {
        Ok(()) => {
            audit::log_event(
                AuditEvent::new(EventType::WaEnabled, EventResult::Success)
            );
            Response::ok()
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::WaEnabled, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

/// Disable WebAuthn 2FA for unlock operations
async fn handle_disable_wa_unlock() -> Response {
    // Require active session + recent WebAuthn verification (single-use).
    // Dev mode skips both — auth is off across the board, see issue #59.
    if !keystore::is_dev_mode() {
        let mut session = get_session().write().await;
        if !session.is_active() {
            return Response::error("Active session required to change WebAuthn settings");
        }
        if !session.consume_wa_verification(WA_VERIFY_WINDOW_SECS) {
            audit::log_event(
                AuditEvent::new(EventType::WaUnlockDisabled, EventResult::Failure)
                    .with_error("WebAuthn verification required")
            );
            return Response::error("WebAuthn verification required to disable WebAuthn unlock");
        }
    }

    match webauthn::set_wa_unlock_state(false) {
        Ok(()) => {
            audit::log_event(
                AuditEvent::new(EventType::WaUnlockDisabled, EventResult::Success)
            );
            Response::ok()
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::WaUnlockDisabled, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

/// Re-enable WebAuthn 2FA for unlock operations
async fn handle_enable_wa_unlock() -> Response {
    match webauthn::set_wa_unlock_state(true) {
        Ok(()) => {
            audit::log_event(
                AuditEvent::new(EventType::WaUnlockEnabled, EventResult::Success)
            );
            Response::ok()
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::WaUnlockEnabled, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

// ── Localhost WebAuthn handlers ──────────────────────────────────────

/// Unlock via localhost browser — phase 1: start HTTP server, return URL
async fn handle_unlock_local(_ttl: Option<u64>) -> Response {
    audit::log_simple(EventType::AuthAttempt, EventResult::Pending);

    // Check if localhost credential exists
    if !webauthn::is_local_configured() {
        return Response::error("No localhost credential. Run 'scrt4 setup --local' after unlocking via phone.");
    }

    let credential = match webauthn::load_local_credential() {
        Ok(c) => c,
        Err(e) => return Response::error(format!("Failed to load localhost credential: {}", e)),
    };

    // Load PRF salt from the localhost master key file
    let prf_salt = match keystore::load_prf_salt_local() {
        Ok(s) => s,
        Err(e) => return Response::error(format!("Failed to load local PRF salt: {}", e)),
    };

    let engine = base64::engine::general_purpose::STANDARD;
    let salt_b64 = base64::Engine::encode(&engine, &prf_salt);

    let wrapping_key = webauthn::generate_hex_public(32);

    let mut challenge_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge_bytes);
    let challenge_b64 = base64::Engine::encode(&engine, challenge_bytes);

    let server = match localhost::start(
        "auth",
        &challenge_b64,
        &salt_b64,
        &wrapping_key,
        Some(&credential.credential_id),
    ).await {
        Ok(s) => s,
        Err(e) => return Response::error(format!("Failed to start local server: {}", e)),
    };

    let url = server.url.clone();

    localhost::set_pending(localhost::PendingLocalAuth {
        server,
        wrapping_key,
        prf_salt_b64: salt_b64,
    }).await;

    tracing::info!("Unlock local phase 1: server started at {}", url);
    Response::ok_with_data(ResponseData::LocalUrl { url })
}

/// Unlock via localhost browser — phase 2: wait for callback, decrypt, unlock
async fn handle_unlock_local_complete(ttl: Option<u64>) -> Response {
    let mut pending = match localhost::take_pending().await {
        Some(p) => p,
        None => return Response::error("No pending local auth — call unlock_local first"),
    };

    let encrypted_payload = match pending.server.wait_for_callback(120).await {
        Ok(p) => p,
        Err(e) => {
            pending.server.shutdown();
            return Response::error(e);
        }
    };

    pending.server.shutdown();

    let auth_result = match webauthn::complete_authentication(&encrypted_payload, &pending.wrapping_key) {
        Ok(r) => r,
        Err(e) => return Response::error(format!("WebAuthn auth failed: {}", e)),
    };

    tracing::info!("Local auth: PRF output received ({} bytes)", auth_result.prf_output.len());

    // Load master key from the LOCAL key file
    let master_key = match keystore::load_master_key_local(&auth_result.prf_output) {
        Ok(k) => k,
        Err(e) => return Response::error(format!("Failed to decrypt master key: {}", e)),
    };

    let secrets = match keystore::decrypt_secrets(&master_key) {
        Ok(s) => s,
        Err(e) => return Response::error(format!("Failed to load secrets: {}", e)),
    };

    let count = secrets.len();
    let ttl_secs = ttl.unwrap_or(7200);

    let token: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let mut session = get_session().write().await;
    match session.store(token, secrets, ttl_secs) {
        Ok(()) => {
            session.set_master_key(master_key);
            session.set_wa_verified();
            audit::log_event(AuditEvent::new(EventType::AuthSuccess, EventResult::Success));
            audit::log_event(
                AuditEvent::new(EventType::SessionStart, EventResult::Success)
                    .with_ttl(ttl_secs)
                    .with_secret_count(count)
            );
            Response::ok_with_data(ResponseData::Unlocked {
                count,
                // the only path the token leaves the daemon by.
                session_token: session.token_b64(),
            })
        }
        Err(e) => Response::error(e),
    }
}

/// Setup localhost credential — phase 1: start server (requires active session)
async fn handle_setup_local() -> Response {
    // Require active session — user must have unlocked via phone first
    {
        let session = get_session().read().await;
        if !session.is_active() {
            return Response::error(
                "Session not active. Unlock via phone first ('scrt4 unlock --remote'), then run 'scrt4 setup --local'."
            );
        }
        if session.master_key().is_none() {
            return Response::error("No master key in session. Unlock via phone first.");
        }
    }

    // Enrolling a NEW unlock credential is the most privileged thing this
    // daemon does, and it was the one sensitive handler with no step-up while
    // six others (reveal, reveal_all, backup_key, disable_wa,
    // disable_wa_unlock, rotate_vault) all required one.
    //
    // The credential this creates is a permanent, session-independent path to
    // the vault: it outlives the session that authorised it, survives logout,
    // and keeps working after a master-key rotation. An active session is
    // therefore not sufficient authority for it — otherwise any process able to
    // reach the daemon socket while the user happened to be unlocked could
    // enrol its own authenticator and retain access indefinitely, with no
    // visible symptom because the vault keeps working normally.
    //
    // Dev mode skips the gate, matching the six handlers above.
    {
        let mut session = get_session().write().await;
        if !keystore::is_dev_mode() && !session.consume_wa_verification(WA_VERIFY_WINDOW_SECS) {
            audit::log_event(
                AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                    .with_error("setup_local without a WebAuthn step-up")
            );
            return Response::error(
                "WebAuthn verification required before enrolling a local credential"
            );
        }
    }

    let engine = base64::engine::general_purpose::STANDARD;

    let prf_salt = webauthn::generate_prf_salt();
    let prf_salt_b64 = base64::Engine::encode(&engine, &prf_salt);
    let wrapping_key = webauthn::generate_hex_public(32);
    let mut challenge_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge_bytes);
    let challenge_b64 = base64::Engine::encode(&engine, &challenge_bytes);

    let server = match localhost::start(
        "register",
        &challenge_b64,
        &prf_salt_b64,
        &wrapping_key,
        None,
    ).await {
        Ok(s) => s,
        Err(e) => return Response::error(format!("Failed to start local server: {}", e)),
    };

    let url = server.url.clone();

    localhost::set_pending(localhost::PendingLocalAuth {
        server,
        wrapping_key,
        prf_salt_b64,
    }).await;

    tracing::info!("Setup local phase 1: server started at {}", url);
    Response::ok_with_data(ResponseData::LocalUrl { url })
}

/// Setup localhost credential — phase 2: wrap existing master key with localhost PRF
async fn handle_setup_local_complete() -> Response {
    // Get the existing master key from the active session
    let master_key = {
        let session = get_session().read().await;
        match session.master_key() {
            Some(k) => k.to_string(),
            None => return Response::error("No master key in session — unlock via phone first"),
        }
    };

    let mut pending = match localhost::take_pending().await {
        Some(p) => p,
        None => return Response::error("No pending local auth — call setup_local first"),
    };

    let encrypted_payload = match pending.server.wait_for_callback(120).await {
        Ok(p) => p,
        Err(e) => {
            pending.server.shutdown();
            return Response::error(e);
        }
    };

    pending.server.shutdown();

    let engine = base64::engine::general_purpose::STANDARD;

    let reg_result = match webauthn::complete_registration_local(&encrypted_payload, &pending.wrapping_key) {
        Ok(r) => r,
        Err(e) => return Response::error(format!("WebAuthn registration failed: {}", e)),
    };

    let prf_salt_bytes = match base64::Engine::decode(&engine, &pending.prf_salt_b64) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return Response::error("Invalid PRF salt"),
    };

    // Save localhost credential (separate file from the remote one)
    if let Err(e) = webauthn::save_local_credential(&reg_result.credential) {
        return Response::error(format!("Failed to save localhost credential: {}", e));
    }

    tracing::info!("Setup local: wrapping existing master key with localhost PRF");

    // Wrap the EXISTING master key with the localhost PRF output
    if let Err(e) = keystore::save_master_key_local(
        &master_key,
        &reg_result.prf_output,
        &prf_salt_bytes,
        Some(&reg_result.credential.credential_id),
    ) {
        return Response::error(format!("Failed to save local master key: {}", e));
    }

    audit::log_event(AuditEvent::new(EventType::KeysInitialized, EventResult::Success));
    tracing::info!("Localhost credential registered, master key wrapped");
    Response::ok()
}
// ══════════════════════════════════════════════════════════════════

// ── Lease Handlers ─────────────────────────────────────────────

// ── Bundle Handlers ────────────────────────────────────────────




//
// Mirrors the `handle_migrate` pattern from the legacy llm-secrets
// daemon (wsl-daemon/src/handlers.rs + keystore.rs::migrate_secrets):
//
//   1. Read the secrets and the current master key from the active
//      session (the migrate flow takes these from the client; we have
//      them already because the session is unlocked).
//   2. Generate a new 32-byte master key via generate_new_master_key.
//   3. Re-encrypt every secret under the new key via save_encrypted_env.
//   4. Update the session's cached master_key so subsequent AddSecrets
//      / RevealAll / Run operations stay consistent with the new key.
//   5. Return the new master key to the caller so it can be backed up.
//
// This rotates the VAULT encryption key (~/.scrt4(-dev)/vault/secrets.env).
// It does NOT touch the hardened ~/.scrt4/master.key wrapper, which
// is WebAuthn-PRF-protected and cannot be re-wrapped without a fresh
// PRF ceremony. In hardened mode the caller is responsible for one
// of the follow-up actions:
//
//   - `scrt4 backup-key --save DIR` — save the new raw master key so
//     the vault can be recovered if the WebAuthn credential is lost.
//   - `scrt4 setup` — re-enroll WebAuthn against the new master key,
//     which writes a new master.key wrapper under a fresh PRF.
//
// The response carries `wrapper_stale: true` in hardened mode so the
// CLI knows to drive one of those flows before the session ends.
// Until a follow-up re-wrap happens, the in-memory session still
// works, but a fresh unlock (cold start) would fail because the
// master.key wrapper unwraps to the OLD key.
//
// Dev mode: the daemon bootstraps with a fixed in-memory key at
// startup and does not persist a WebAuthn wrapper, so rotation is
// purely in-memory + the vault file. A daemon restart re-bootstraps
// with the original fixed key and the rotated vault will no longer
// decrypt. This is expected — dev is a scratch harness.
//
// Step-up: require a fresh WebAuthn verification (same window as
// reveal paths) before allowing rotation, unless in dev mode.

async fn handle_rotate_vault() -> Response {
    let mut session = get_session().write().await;
    if !session.is_active() {
        return Response::error("No active session");
    }

    if !keystore::is_dev_mode() && !session.consume_wa_verification(WA_VERIFY_WINDOW_SECS) {
        return Response::error(
            "WebAuthn step-up required before vault rotation — unlock again first",
        );
    }

    let current_secrets = match session.secrets() {
        Some(s) => s.clone(),
        None => return Response::error("No secrets in session"),
    };
    let secret_count = current_secrets.len();

    let new_master_key = match keystore::generate_new_master_key() {
        Ok(k) => k,
        Err(e) => return Response::error(format!("Failed to generate new master key: {}", e)),
    };

    // Atomic-ish replace: save_encrypted_env uses `std::fs::write` which
    // on POSIX is a single syscall for files under the filesystem's
    // atomic-write block size, and the vault file is small. A partial
    // failure leaves the OLD vault on disk (because `write` truncates
    // and replaces, it doesn't destroy on failure) — the session
    // still has the new key in memory if we succeed past this point.
    if let Err(e) = keystore::save_encrypted_env(&current_secrets, &new_master_key) {
        return Response::error(format!("Failed to write rotated vault: {}", e));
    }

    session.set_master_key(new_master_key.clone());

    drop(session);

    let wrapper_stale = !keystore::is_dev_mode();

    audit::log_event(
        AuditEvent::new(EventType::SecretsAdded, EventResult::Success)
            .with_error(&format!(
                "VaultRotated secret_count={} wrapper_stale={}",
                secret_count, wrapper_stale
            ))
    );

    tracing::warn!(
        "Vault rotated: secret_count={} wrapper_stale={}",
        secret_count,
        wrapper_stale
    );

    Response::ok_with_data(ResponseData::VaultRotated {
        new_master_key_b64: new_master_key,
        secret_count,
        wrapper_stale,
    })
}

// ── Core: Encrypted-folder inventory handlers (F027, F028) ──────────
//
// Thin wrappers over crate::encrypted_inventory. All RPCs require an
// active session — the inventory is vault-adjacent bookkeeping and
// should not be readable/writable without authentication. Dev mode
// already has an active session via the bootstrap, so there's no
// special case here.

async fn handle_register_encrypted(
    path: String,
    folder_name: String,
    file_count: u32,
    archive_size: u64,
) -> Response {
    let session = get_session().read().await;
    if !session.is_active() {
        return Response::error("No active session");
    }
    drop(session);

    match crate::encrypted_inventory::register(&path, &folder_name, file_count, archive_size) {
        Ok(entry) => Response::ok_with_data(ResponseData::EncryptedRegistered {
            id: entry.id,
            path: entry.path,
        }),
        Err(e) => Response::error(format!("register_encrypted: {}", e)),
    }
}

async fn handle_unregister_encrypted(id: String) -> Response {
    let session = get_session().read().await;
    if !session.is_active() {
        return Response::error("No active session");
    }
    drop(session);

    match crate::encrypted_inventory::unregister(&id) {
        Ok(removed) => Response::ok_with_data(ResponseData::EncryptedUnregistered { removed, id }),
        Err(e) => Response::error(format!("unregister_encrypted: {}", e)),
    }
}

async fn handle_mark_decrypted(path: String) -> Response {
    let session = get_session().read().await;
    if !session.is_active() {
        return Response::error("No active session");
    }
    drop(session);

    match crate::encrypted_inventory::mark_decrypted(&path) {
        Ok(()) => Response::ok_with_data(ResponseData::EncryptedMarkedDecrypted { path }),
        Err(e) => Response::error(format!("mark_decrypted: {}", e)),
    }
}

async fn handle_list_encrypted() -> Response {
    let session = get_session().read().await;
    if !session.is_active() {
        return Response::error("No active session");
    }
    drop(session);

    let rows = crate::encrypted_inventory::list_with_existence();
    let entries: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(entry, exists)| {
            serde_json::json!({
                "id": entry.id,
                "path": entry.path,
                "folder_name": entry.folder_name,
                "file_count": entry.file_count,
                "archive_size": entry.archive_size,
                "created_at": entry.created_at,
                "last_decrypted_at": entry.last_decrypted_at,
                "exists": exists,
            })
        })
        .collect();
    Response::ok_with_data(ResponseData::EncryptedList { entries })
}

async fn handle_cleanup_encrypted(remove_missing: bool) -> Response {
    let session = get_session().read().await;
    if !session.is_active() {
        return Response::error("No active session");
    }
    drop(session);

    match crate::encrypted_inventory::cleanup(remove_missing) {
        Ok(summary) => Response::ok_with_data(ResponseData::EncryptedCleanup {
            present_count: summary.present_count,
            missing_count: summary.missing_count,
            removed_count: summary.removed_count,
            missing_paths: summary.missing_paths,
        }),
        Err(e) => Response::error(format!("cleanup_encrypted: {}", e)),
    }
}

