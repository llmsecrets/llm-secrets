// wsl2-helper/src/main.rs
use std::path::PathBuf;
use tokio::net::UnixListener;

mod protocol;
mod session;
mod handlers;
mod sanitize;
mod subprocess;
mod dpapi;
mod audit;
mod remote;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Initialize audit logger
    audit::init_audit_logger(None);
    audit::log_simple(audit::EventType::DaemonStart, audit::EventResult::Success);

    // Initialize shared session state
    let session = session::new_shared_session();
    handlers::init_session(session);

    let socket_path = get_socket_path();

    // Remove stale socket
    let _ = std::fs::remove_file(&socket_path);

    // Create parent directory if needed
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    // Set socket permissions (owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!("Daemon listening on {:?}", socket_path);

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

    Ok(())
}

fn get_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("scrt.sock")
    } else {
        // Fallback for systems without XDG_RUNTIME_DIR
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/scrt-{}.sock", uid))
    }
}
