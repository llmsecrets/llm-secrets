// wsl2-helper/src/handlers.rs
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::audit::{self, AuditEvent, EventType, EventResult};
use crate::dpapi;
use crate::totp;
use crate::protocol::{Request, Response, ResponseData};
use crate::session::SharedSession;
use crate::subprocess::run_with_secrets;

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

/// Handle a client connection
pub async fn handle_connection(stream: UnixStream) {
    let (reader, mut writer) = stream.into_split();
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
        Request::Unlock { ttl, totp_code } => handle_unlock(ttl, totp_code).await,
        Request::CheckTotp => handle_check_totp().await,
        Request::SetupTotp => handle_setup_totp().await,
        Request::VerifyTotpSetup { code } => handle_verify_totp_setup(code).await,
        Request::Extend { ttl } => handle_extend(ttl).await,
        Request::BackupKey => handle_backup_key().await,
        Request::Migrate { old_key } => handle_migrate(old_key).await,
        Request::InitializeKeys => handle_initialize_keys().await,
        Request::RevealAllTotp { totp_code } => handle_reveal_all_totp(totp_code).await,
        Request::RevealTotp { name, totp_code } => handle_reveal_totp(name, totp_code).await,
        Request::CheckTfaState => handle_check_tfa_state().await,
        Request::DisableTfa { totp_code } => handle_disable_tfa(totp_code).await,
        Request::EnableTfa { totp_code } => handle_enable_tfa(totp_code).await,
    }
}

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
                if let Err(e) = dpapi::save_encrypted_env(all_secrets, master_key) {
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
                if let Err(e) = dpapi::save_encrypted_env(all_secrets, master_key) {
                    tracing::error!("Failed to persist secrets to disk: {}", e);
                    // Don't fail the request — in-memory update succeeded
                }
            }

            audit::log_event(
                AuditEvent::new(EventType::SecretsAdded, EventResult::Success)
                    .with_secret_count(added)
            );
            Response::ok_with_data(ResponseData::Unlocked { count })
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

    drop(session);  // Release lock before running subprocess

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

    match session.create_challenge(&name) {
        Ok((nonce, display_code)) => {
            audit::log_event(
                AuditEvent::new(EventType::RevealChallengeIssued, EventResult::Pending)
                    .with_secret_name(&name)
            );

            // Return the code to the CLI — it handles display via Zenity --info (Pango markup)
            // then shows a Zenity --entry for the user to type the code
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

    match session.create_bulk_challenge() {
        Ok((nonce, display_code)) => {
            audit::log_event(
                AuditEvent::new(EventType::BulkRevealChallengeIssued, EventResult::Pending)
            );

            // Return the code to the CLI — it handles display via Zenity --info (Pango markup)
            // then shows a Zenity --entry for the user to type the code
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

/// Unlock secrets — uses TOTP + DPAPI when 2FA enabled, DPAPI-only when 2FA disabled
async fn handle_unlock(ttl: Option<u64>, totp_code: String) -> Response {
    let ttl = ttl.unwrap_or(7200);  // Default 2 hours
    let tfa_enabled = totp::is_tfa_enabled();

    audit::log_simple(EventType::AuthAttempt, EventResult::Pending);

    // TOTP when 2FA enabled, DPAPI-only when 2FA disabled
    let (secrets, master_key) = match if tfa_enabled {
        tracing::info!("Unlock via TOTP + DPAPI");
        dpapi::unlock_secrets(&totp_code).await
    } else {
        tracing::info!("Unlock via DPAPI only (2FA disabled)");
        dpapi::unlock_secrets_dpapi_only().await
    } {
        Ok(s) => s,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(e);
        }
    };

    let count = secrets.len();

    // Generate a random token for this session
    let token: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    // Store secrets in session
    let mut session = get_session().write().await;
    match session.store(token, secrets, ttl) {
        Ok(()) => {
            // Retain master key for re-encryption when secrets are modified
            session.set_master_key(master_key);

            audit::log_event(
                AuditEvent::new(EventType::AuthSuccess, EventResult::Success)
            );
            audit::log_event(
                AuditEvent::new(EventType::SessionStart, EventResult::Success)
                    .with_ttl(ttl)
                    .with_secret_count(count)
            );
            Response::ok_with_data(ResponseData::Unlocked { count })
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
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

/// Check if TOTP is configured
async fn handle_check_totp() -> Response {
    let configured = totp::is_totp_configured();
    Response::ok_with_data(ResponseData::TotpConfigured { configured })
}

/// Generate a new TOTP secret for initial setup
/// Secret is saved to disk only — not returned in the response to avoid leaking
/// through socket/logs. The CLI reads it directly from ~/.scrt2/totp.secret.
async fn handle_setup_totp() -> Response {
    match totp::generate_totp_secret() {
        Ok((secret, _otpauth_uri)) => {
            if let Err(e) = totp::save_totp_secret(&secret) {
                return Response::error(e);
            }
            // Return only success — secret and URI stay on disk, never cross the socket
            Response::ok()
        }
        Err(e) => Response::error(e),
    }
}

/// Verify a TOTP code during setup to confirm the user has configured their authenticator
async fn handle_verify_totp_setup(code: String) -> Response {
    match totp::verify_totp_code(&code) {
        Ok(true) => {
            audit::log_simple(EventType::AuthSuccess, EventResult::Success);
            Response::ok()
        }
        Ok(false) => {
            audit::log_event(
                AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                    .with_error("Invalid TOTP code during setup verification")
            );
            Response::error("Invalid TOTP code. Check your authenticator app and try again.")
        }
        Err(e) => Response::error(e),
    }
}

/// Backup the current master key
/// Requires an active session (must unlock first) to access the stored master key
async fn handle_backup_key() -> Response {
    let session = get_session().read().await;

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
            Response::error("No active session. Run 'scrt unlock' first to access the master key.")
        }
    }
}

/// Migrate secrets from an old master key to the current one
/// This re-encrypts all secrets with the new DPAPI-protected key
async fn handle_migrate(old_key: String) -> Response {
    audit::log_event(
        AuditEvent::new(EventType::KeyMigration, EventResult::Pending)
    );

    // Validate key format (should be 44-char base64 = 32 bytes)
    if old_key.len() != 44 {
        audit::log_event(
            AuditEvent::new(EventType::KeyMigration, EventResult::Failure)
                .with_error("Invalid key format")
        );
        return Response::error("Invalid key format. Master key should be 44 characters (base64-encoded 32 bytes).");
    }

    // Perform the migration
    match dpapi::migrate_secrets(&old_key) {
        Ok((secrets, new_key, count)) => {
            // Store the migrated secrets in the current session
            let token: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let mut session = get_session().write().await;

            match session.store(token, secrets, 7200) {
                Ok(()) => {
                    session.set_master_key(new_key);
                    audit::log_event(
                        AuditEvent::new(EventType::KeyMigration, EventResult::Success)
                            .with_secret_count(count)
                    );
                    Response::ok_with_data(ResponseData::Migrated { count })
                }
                Err(e) => {
                    audit::log_event(
                        AuditEvent::new(EventType::KeyMigration, EventResult::Failure)
                            .with_error(&e)
                    );
                    Response::error(format!("Migration succeeded but failed to store session: {}", e))
                }
            }
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::KeyMigration, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(format!("Migration failed: {}. Check that the old key is correct.", e))
        }
    }
}

/// Reveal all secrets using TOTP authentication (bypasses GUI challenge)
async fn handle_reveal_all_totp(totp_code: String) -> Response {
    let session = get_session().read().await;

    if !session.is_active() {
        audit::log_event(
            AuditEvent::new(EventType::TfaRevealAll, EventResult::Failure)
                .with_error("No active session")
        );
        return Response::error("No active session - authenticate first");
    }

    // Verify TOTP
    match totp::verify_totp_code(&totp_code) {
        Ok(true) => {}
        Ok(false) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaRevealAll, EventResult::Failure)
                    .with_error("Invalid TOTP code")
            );
            return Response::error("Invalid 2FA code");
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaRevealAll, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(e);
        }
    }

    match session.secrets() {
        Some(secrets) => {
            let count = secrets.len();
            audit::log_event(
                AuditEvent::new(EventType::TfaRevealAll, EventResult::Success)
                    .with_secret_count(count)
            );
            Response::ok_with_data(ResponseData::RevealAll { secrets: secrets.clone() })
        }
        None => {
            audit::log_event(
                AuditEvent::new(EventType::TfaRevealAll, EventResult::Failure)
                    .with_error("No secrets loaded")
            );
            Response::error("No secrets loaded")
        }
    }
}

/// Reveal a single secret using TOTP authentication (bypasses GUI challenge)
async fn handle_reveal_totp(name: String, totp_code: String) -> Response {
    let session = get_session().read().await;

    if !session.is_active() {
        audit::log_event(
            AuditEvent::new(EventType::TfaReveal, EventResult::Failure)
                .with_secret_name(&name)
                .with_error("No active session")
        );
        return Response::error("No active session - authenticate first");
    }

    // Verify TOTP
    match totp::verify_totp_code(&totp_code) {
        Ok(true) => {}
        Ok(false) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaReveal, EventResult::Failure)
                    .with_secret_name(&name)
                    .with_error("Invalid TOTP code")
            );
            return Response::error("Invalid 2FA code");
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaReveal, EventResult::Failure)
                    .with_secret_name(&name)
                    .with_error(&e)
            );
            return Response::error(e);
        }
    }

    match session.secrets() {
        Some(secrets) => {
            match secrets.get(&name) {
                Some(value) => {
                    audit::log_event(
                        AuditEvent::new(EventType::TfaReveal, EventResult::Success)
                            .with_secret_name(&name)
                    );
                    Response::ok_with_data(ResponseData::Reveal { value: value.clone() })
                }
                None => {
                    audit::log_event(
                        AuditEvent::new(EventType::TfaReveal, EventResult::Failure)
                            .with_secret_name(&name)
                            .with_error("Secret not found")
                    );
                    Response::error(format!("Secret '{}' not found", name))
                }
            }
        }
        None => {
            audit::log_event(
                AuditEvent::new(EventType::TfaReveal, EventResult::Failure)
                    .with_secret_name(&name)
                    .with_error("No secrets loaded")
            );
            Response::error("No secrets loaded")
        }
    }
}

/// Check 2FA state (configured + enabled/disabled)
async fn handle_check_tfa_state() -> Response {
    let configured = totp::is_totp_configured();
    let enabled = totp::is_tfa_enabled();
    Response::ok_with_data(ResponseData::TfaState { configured, enabled })
}

/// Disable 2FA for reveal operations (requires valid TOTP to prove authenticator access)
async fn handle_disable_tfa(totp_code: String) -> Response {
    // Must prove authenticator access to disable
    match totp::verify_totp_code(&totp_code) {
        Ok(true) => {}
        Ok(false) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaDisabled, EventResult::Failure)
                    .with_error("Invalid TOTP code")
            );
            return Response::error("Invalid 2FA code");
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaDisabled, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(e);
        }
    }

    match totp::set_tfa_state(false) {
        Ok(()) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaDisabled, EventResult::Success)
            );
            Response::ok()
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaDisabled, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

/// Re-enable 2FA for reveal operations (requires valid TOTP)
async fn handle_enable_tfa(totp_code: String) -> Response {
    // Must prove authenticator access to re-enable
    match totp::verify_totp_code(&totp_code) {
        Ok(true) => {}
        Ok(false) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaEnabled, EventResult::Failure)
                    .with_error("Invalid TOTP code")
            );
            return Response::error("Invalid 2FA code");
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaEnabled, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(e);
        }
    }

    match totp::set_tfa_state(true) {
        Ok(()) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaEnabled, EventResult::Success)
            );
            Response::ok()
        }
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::TfaEnabled, EventResult::Failure)
                    .with_error(&e)
            );
            Response::error(e)
        }
    }
}

/// Generate fresh encryption keys and reset the secret store
/// Called during setup-2fa to ensure new auth = new keys = clean store
async fn handle_initialize_keys() -> Response {
    audit::log_event(
        AuditEvent::new(EventType::KeysInitialized, EventResult::Pending)
    );

    // Step 1: Generate fresh DPAPI-encrypted master key
    let master_key = match dpapi::generate_new_master_key() {
        Ok(k) => k,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::KeysInitialized, EventResult::Failure)
                    .with_error(&e)
            );
            return Response::error(format!("Key generation failed: {}", e));
        }
    };

    // Step 2: Delete old env files and create fresh empty store
    if let Err(e) = dpapi::reset_encrypted_env(&master_key) {
        audit::log_event(
            AuditEvent::new(EventType::KeysInitialized, EventResult::Failure)
                .with_error(&e)
        );
        return Response::error(format!("Failed to reset encrypted env: {}", e));
    }

    audit::log_event(
        AuditEvent::new(EventType::KeysInitialized, EventResult::Success)
    );
    Response::ok()
}
