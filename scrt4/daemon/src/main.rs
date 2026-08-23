// scrt4/src/main.rs
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use tokio::net::UnixListener;

mod protocol;
mod session;
mod session_binding;
mod handlers;
mod sanitize;
mod subprocess;
mod keystore;
mod webauthn;
mod audit;
mod remote;
mod localhost;

mod encrypted_inventory;


// Windows transport: named pipe listener (the Unix-socket equivalent).
#[cfg(windows)]
mod winpipe;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Initialize audit logger
    audit::init_audit_logger(None);
    audit::log_simple(audit::EventType::DaemonStart, audit::EventResult::Success);

    // Initialize shared session state
    let session = session::new_shared_session();
    handlers::init_session(session.clone());

    // Dev mode bootstrap (issue #59):
    //
    // When SCRT4_DEV_MODE=1, automatically establish an active session
    // with the fixed dev master key and any existing dev-vault contents.
    // No WebAuthn ceremony, no phone tap, no relay round-trip — the
    // daemon comes up with a usable session as soon as the socket is
    // bound. This is the entire point of the dev distribution.
    //
    // The dev vault lives at ~/.scrt4-dev/, separate from the hardened
    // vault, so cross-distribution open is impossible: there is no
    // shared state and no shared key.
    if keystore::is_dev_mode() {
        tracing::warn!("SCRT4_DEV_MODE=1 — bootstrapping dev session with fixed key");
        tracing::warn!("DO NOT use this distribution for real secrets");

        let master_key = keystore::DEV_MASTER_KEY_B64.to_string();

        // Load existing dev secrets if the vault file exists; otherwise
        // initialize the vault to empty so save_encrypted_env is happy.
        let secrets = if keystore::secrets_path().exists() {
            match keystore::decrypt_secrets(&master_key) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Dev vault decrypt failed (likely from a different SCRT4_DEV_MODE state): {}", e);
                    tracing::error!("Refusing to overwrite. Remove ~/.scrt4-dev manually if you want a fresh start.");
                    return Err(format!("dev vault decrypt failed: {}", e).into());
                }
            }
        } else {
            // First run — create empty vault so the rest of the daemon
            // can read/write it normally.
            if let Err(e) = keystore::save_encrypted_env(&std::collections::HashMap::new(), &master_key) {
                tracing::error!("Failed to initialize empty dev vault: {}", e);
                return Err(format!("dev vault init failed: {}", e).into());
            }
            std::collections::HashMap::new()
        };

        let token: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let mut sess = session.write().await;
        // 0 = no expiry. Dev sessions never time out — convenience over
        // security is the whole point.
        if let Err(e) = sess.store(token, secrets, 0) {
            tracing::error!("Failed to bootstrap dev session: {}", e);
            return Err(format!("dev session bootstrap failed: {}", e).into());
        }
        sess.set_master_key(master_key);
        tracing::info!("Dev session bootstrapped successfully");
    }

    // Start remote listener if configured
    let remote_config = remote::load_config();
    if remote_config.enabled {
        let remote_listener = remote::RemoteListener::new(remote_config);
        tokio::spawn(async move {
            if let Err(e) = remote_listener.start().await {
                tracing::error!("Remote listener error: {}", e);
            }
        });
    }

    // Set up graceful shutdown
    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        audit::log_simple(audit::EventType::DaemonStop, audit::EventResult::Success);
    };

    #[cfg(unix)]
    {
        let socket_path = get_socket_path();

        // Remove stale socket
        let _ = std::fs::remove_file(&socket_path);

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&socket_path)?;

        // Set socket permissions (owner only)
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        tracing::info!("Daemon listening on {:?}", socket_path);

        tokio::select! {
            _ = async {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            audit::log_simple(audit::EventType::ClientConnect, audit::EventResult::Success);
                            tokio::spawn(handlers::handle_connection(stream));
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
            } => {}
            _ = shutdown => {
                tracing::info!("Shutting down daemon");
            }
        }
    }

    #[cfg(windows)]
    {
        tokio::select! {
            res = winpipe::serve() => {
                if let Err(e) = res {
                    tracing::error!("Pipe listener error: {}", e);
                }
            }
            _ = shutdown => {
                tracing::info!("Shutting down daemon");
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
fn get_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("scrt4.sock")
    } else {
        // Fallback for systems without XDG_RUNTIME_DIR
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/scrt4-{}.sock", uid))
    }
}
