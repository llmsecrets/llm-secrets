// wsl2-daemon/src/remote.rs
//! Remote session support for the WSL2 daemon
//!
//! Enables the daemon to accept connections from remote Claude Code sessions
//! with token-based authentication. This is useful for:
//! - SSH sessions into the WSL environment
//! - Remote development scenarios
//! - Multi-machine setups
//!
//! Security measures:
//! - Disabled by default (must be explicitly enabled)
//! - Token-based authentication required for all remote connections
//! - Limited methods available over remote connections (no unlock/reveal)
//! - Configurable bind address (default: localhost only)
//! - Connection rate limiting

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::audit::{self, AuditEvent, EventType, EventResult};
use crate::handlers;

/// Remote listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// Whether remote connections are enabled
    pub enabled: bool,
    /// Bind address (default: 127.0.0.1:9473)
    pub bind_addr: String,
    /// Authentication token (must be set if enabled)
    pub token: Option<String>,
    /// Maximum connections per minute (rate limiting)
    pub max_connections_per_minute: u32,
    /// Allowed methods over remote connections
    pub allowed_methods: Vec<String>,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: "127.0.0.1:9473".to_string(),
            token: None,
            max_connections_per_minute: 10,
            allowed_methods: vec![
                "status".to_string(),
                "list".to_string(),
                "run".to_string(),
            ],
        }
    }
}

/// Remote request wrapper with authentication
#[derive(Debug, Deserialize)]
pub struct RemoteRequest {
    /// Authentication token
    pub token: String,
    /// The actual request (same format as local requests)
    pub request: serde_json::Value,
}

/// Remote response
#[derive(Debug, Serialize)]
pub struct RemoteResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl RemoteResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            success: true,
            error: None,
            data: Some(data),
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

/// Rate limiter for remote connections
struct RateLimiter {
    connections: RwLock<HashMap<String, Vec<Instant>>>,
    max_per_minute: u32,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            max_per_minute,
        }
    }

    async fn check(&self, addr: &str) -> bool {
        let now = Instant::now();
        let minute_ago = now - Duration::from_secs(60);

        let mut connections = self.connections.write().await;
        let times = connections.entry(addr.to_string()).or_insert_with(Vec::new);

        // Remove old entries
        times.retain(|t| *t > minute_ago);

        // Check limit
        if times.len() >= self.max_per_minute as usize {
            return false;
        }

        // Record this connection
        times.push(now);
        true
    }
}

/// Remote listener handle
pub struct RemoteListener {
    config: RemoteConfig,
    rate_limiter: Arc<RateLimiter>,
}

impl RemoteListener {
    /// Create a new remote listener
    pub fn new(config: RemoteConfig) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(config.max_connections_per_minute));
        Self { config, rate_limiter }
    }

    /// Start the remote listener
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.enabled {
            tracing::info!("Remote listener disabled");
            return Ok(());
        }

        if self.config.token.is_none() {
            return Err("Remote listener enabled but no token configured".into());
        }

        let addr: SocketAddr = self.config.bind_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;

        tracing::info!("Remote listener started on {}", addr);
        audit::log_event(
            AuditEvent::new(EventType::DaemonStart, EventResult::Success)
                .with_client(&format!("remote:{}", addr))
        );

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let peer_str = peer_addr.to_string();

                    // Rate limiting
                    if !self.rate_limiter.check(&peer_str).await {
                        tracing::warn!("Rate limit exceeded for {}", peer_str);
                        audit::log_event(
                            AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                                .with_client(&peer_str)
                                .with_error("Rate limit exceeded")
                        );
                        continue;
                    }

                    let config = self.config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_remote_connection(stream, &peer_str, &config).await {
                            tracing::error!("Remote connection error from {}: {}", peer_str, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Remote accept error: {}", e);
                }
            }
        }
    }
}

/// Handle a single remote connection
async fn handle_remote_connection(
    stream: TcpStream,
    peer: &str,
    config: &RemoteConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    audit::log_event(
        AuditEvent::new(EventType::ClientConnect, EventResult::Success)
            .with_client(peer)
    );

    loop {
        line.clear();

        match reader.read_line(&mut line).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                let response = handle_remote_request(&line, peer, config).await;
                let json = serde_json::to_string(&response)?;

                writer.write_all(format!("{}\n", json).as_bytes()).await?;
            }
            Err(e) => {
                tracing::error!("Remote read error from {}: {}", peer, e);
                break;
            }
        }
    }

    audit::log_event(
        AuditEvent::new(EventType::ClientDisconnect, EventResult::Success)
            .with_client(peer)
    );

    Ok(())
}

/// Handle a single remote request
async fn handle_remote_request(
    line: &str,
    peer: &str,
    config: &RemoteConfig,
) -> RemoteResponse {
    // Parse the remote request wrapper
    let remote_req: RemoteRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            audit::log_event(
                AuditEvent::new(EventType::InvalidRequest, EventResult::Failure)
                    .with_client(peer)
                    .with_error(&e.to_string())
            );
            return RemoteResponse::error(format!("Invalid request format: {}", e));
        }
    };

    // Verify token
    let expected_token = config.token.as_ref().unwrap();
    if remote_req.token != *expected_token {
        audit::log_event(
            AuditEvent::new(EventType::AuthFailure, EventResult::Failure)
                .with_client(peer)
                .with_error("Invalid token")
        );
        return RemoteResponse::error("Authentication failed");
    }

    // Extract method from request
    let method = remote_req.request.get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Check if method is allowed over remote connections
    if !config.allowed_methods.iter().any(|m| m == method) {
        audit::log_event(
            AuditEvent::new(EventType::InvalidRequest, EventResult::Failure)
                .with_client(peer)
                .with_error(&format!("Method '{}' not allowed over remote", method))
        );
        return RemoteResponse::error(format!(
            "Method '{}' not allowed over remote connections. Allowed: {:?}",
            method, config.allowed_methods
        ));
    }

    audit::log_event(
        AuditEvent::new(EventType::AuthSuccess, EventResult::Success)
            .with_client(peer)
    );

    // Forward to local handler
    let request_json = serde_json::to_string(&remote_req.request).unwrap_or_default();
    let local_response = handlers::handle_request_string(&request_json).await;

    // Parse local response and wrap
    match serde_json::from_str::<serde_json::Value>(&local_response) {
        Ok(value) => {
            let success = value.get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if success {
                RemoteResponse::ok(value)
            } else {
                let error = value.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                RemoteResponse::error(error)
            }
        }
        Err(e) => RemoteResponse::error(format!("Internal error: {}", e)),
    }
}

/// Load remote config from file
pub fn load_config() -> RemoteConfig {
    let config_path = get_config_path();

    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => {
                match serde_json::from_str(&content) {
                    Ok(config) => return config,
                    Err(e) => {
                        tracing::warn!("Failed to parse remote config: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read remote config: {}", e);
            }
        }
    }

    RemoteConfig::default()
}

/// Save remote config to file
pub fn save_config(config: &RemoteConfig) -> Result<(), std::io::Error> {
    let config_path = get_config_path();

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(config_path, json)
}

/// Get the config file path
fn get_config_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home)
        .join(".scrt")
        .join("remote-config.json")
}

/// Generate a secure random token
pub fn generate_token() -> String {
    use rand::Rng;
    let token: [u8; 32] = rand::thread_rng().gen();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RemoteConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.bind_addr, "127.0.0.1:9473");
        assert!(config.token.is_none());
        assert!(config.allowed_methods.contains(&"run".to_string()));
        assert!(!config.allowed_methods.contains(&"unlock".to_string()));
        assert!(!config.allowed_methods.contains(&"reveal".to_string()));
    }

    #[test]
    fn test_generate_token() {
        let token = generate_token();
        assert!(!token.is_empty());
        assert!(token.len() >= 40); // Base64 of 32 bytes
    }

    #[test]
    fn test_remote_response_ok() {
        let response = RemoteResponse::ok(serde_json::json!({"test": "value"}));
        assert!(response.success);
        assert!(response.error.is_none());
        assert!(response.data.is_some());
    }

    #[test]
    fn test_remote_response_error() {
        let response = RemoteResponse::error("test error");
        assert!(!response.success);
        assert_eq!(response.error, Some("test error".to_string()));
        assert!(response.data.is_none());
    }
}
