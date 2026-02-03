// wsl2-helper/src/handlers.rs
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::audit::{self, AuditEvent, EventType, EventResult};
use crate::dpapi;
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
        Request::Unlock { ttl } => handle_unlock(ttl).await,
        Request::CheckHello => handle_check_hello().await,
        Request::Extend { ttl } => handle_extend(ttl).await,
        Request::BackupKey => handle_backup_key().await,
        Request::Migrate { old_key } => handle_migrate(old_key).await,
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

/// Unlock secrets via Windows Hello
/// This triggers biometric authentication, decrypts secrets, and loads them into memory
async fn handle_unlock(ttl: Option<u64>) -> Response {
    let ttl = ttl.unwrap_or(7200);  // Default 2 hours

    audit::log_simple(EventType::AuthAttempt, EventResult::Pending);

    // Run the unlock flow (Windows Hello -> DPAPI -> decrypt)
    let (secrets, master_key) = match dpapi::unlock_secrets().await {
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

/// Check if Windows Hello is available
async fn handle_check_hello() -> Response {
    match dpapi::check_hello_available() {
        Ok(available) => Response::ok_with_data(ResponseData::HelloAvailable { available }),
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
