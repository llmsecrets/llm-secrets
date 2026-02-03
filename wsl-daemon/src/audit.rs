// wsl2-daemon/src/audit.rs
//! Security audit logging for the WSL2 daemon
//!
//! Provides structured logging of all security-relevant events:
//! - Session lifecycle (start, end, timeout)
//! - Authentication attempts (success, failure)
//! - Secret access (list, reveal)
//! - Command execution (with sanitized command strings)
//!
//! Logs are written to a JSON Lines file for easy parsing and analysis.

use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Event types for audit logging
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Session started (after successful unlock)
    SessionStart,
    /// Session ended (logout or clear)
    SessionEnd,
    /// Session expired due to TTL
    SessionTimeout,
    /// Windows Hello authentication attempted
    AuthAttempt,
    /// Authentication succeeded
    AuthSuccess,
    /// Authentication failed
    AuthFailure,
    /// Secret names listed
    SecretList,
    /// Reveal challenge issued (Phase 1)
    RevealChallengeIssued,
    /// Reveal challenge completed successfully (Phase 2)
    RevealChallengeCompleted,
    /// Reveal challenge failed (wrong code, expired, etc.)
    RevealChallengeFailed,
    /// Bulk reveal challenge issued
    BulkRevealChallengeIssued,
    /// Bulk reveal challenge completed
    BulkRevealChallengeCompleted,
    /// Secrets added to active session
    SecretsAdded,
    /// Command executed with secrets
    CommandRun,
    /// Command execution failed
    CommandError,
    /// Session extended (timer reset)
    SessionExtend,
    /// Master key backup requested
    BackupKeyRequested,
    /// Key migration (old key -> new key)
    KeyMigration,
    /// Daemon started
    DaemonStart,
    /// Daemon stopped
    DaemonStop,
    /// Connection from client
    ClientConnect,
    /// Client disconnected
    ClientDisconnect,
    /// Invalid request received
    InvalidRequest,
}

/// Result of an audited operation
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventResult {
    Success,
    Failure,
    Pending,
}

/// A single audit event
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// ISO 8601 formatted timestamp
    pub timestamp_iso: String,
    /// Type of event
    pub event_type: EventType,
    /// Result of the operation
    pub result: EventResult,
    /// Optional command (sanitized - no secret values)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Optional error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Number of secrets involved (for list/run operations)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_count: Option<usize>,
    /// Name of secret (for reveal operations)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// Session TTL in seconds (for session start)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// Client identifier (socket peer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Exit code (for command execution)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl AuditEvent {
    /// Create a new audit event with current timestamp
    pub fn new(event_type: EventType, result: EventResult) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp = now.as_millis() as u64;

        // Format ISO 8601 timestamp
        let secs = now.as_secs();
        let timestamp_iso = format_timestamp(secs);

        Self {
            timestamp,
            timestamp_iso,
            event_type,
            result,
            command: None,
            error: None,
            secret_count: None,
            secret_name: None,
            ttl: None,
            client_id: None,
            exit_code: None,
        }
    }

    /// Set the command (will be sanitized)
    pub fn with_command(mut self, cmd: &str) -> Self {
        // Sanitize command - remove potential secret values
        // Keep only the structure, not any inline values
        let sanitized = sanitize_command(cmd);
        self.command = Some(sanitized);
        self
    }

    /// Set error message
    pub fn with_error(mut self, err: &str) -> Self {
        self.error = Some(err.to_string());
        self
    }

    /// Set secret count
    pub fn with_secret_count(mut self, count: usize) -> Self {
        self.secret_count = Some(count);
        self
    }

    /// Set secret name (for reveal operations)
    pub fn with_secret_name(mut self, name: &str) -> Self {
        self.secret_name = Some(name.to_string());
        self
    }

    /// Set TTL
    pub fn with_ttl(mut self, ttl: u64) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set client ID
    pub fn with_client(mut self, client: &str) -> Self {
        self.client_id = Some(client.to_string());
        self
    }

    /// Set exit code
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }
}

/// Sanitize command string to remove potential secret values
fn sanitize_command(cmd: &str) -> String {
    // Replace anything that looks like a value after common patterns
    let mut result = cmd.to_string();

    // Don't log long strings that might be secrets
    if result.len() > 500 {
        result = format!("{}...[truncated]", &result[..200]);
    }

    // Replace quoted strings longer than 20 chars (might be secrets)
    let re = regex::Regex::new(r#"["'][^"']{20,}["']"#).unwrap();
    result = re.replace_all(&result, "\"[REDACTED]\"").to_string();

    // Replace base64-looking strings (44+ chars, common for keys)
    let re = regex::Regex::new(r"[A-Za-z0-9+/=]{44,}").unwrap();
    result = re.replace_all(&result, "[REDACTED_B64]").to_string();

    // Replace hex strings (40+ chars without 0x prefix, or any with 0x prefix over 20 chars)
    let re = regex::Regex::new(r"0x[a-fA-F0-9]{20,}").unwrap();
    result = re.replace_all(&result, "[REDACTED_HEX]").to_string();

    // Also catch hex strings without 0x prefix (64+ chars)
    let re = regex::Regex::new(r"[a-fA-F0-9]{64,}").unwrap();
    result = re.replace_all(&result, "[REDACTED_HEX]").to_string();

    result
}

/// Format Unix timestamp as ISO 8601
fn format_timestamp(secs: u64) -> String {
    // Simple ISO 8601 formatting without external crate
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate date calculation (doesn't account for leap seconds, but close enough for logging)
    let mut year = 1970;
    let mut remaining_days = days_since_epoch;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days in days_in_months.iter() {
        if remaining_days < *days {
            break;
        }
        remaining_days -= *days;
        month += 1;
    }

    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Global audit logger
static AUDIT_LOGGER: std::sync::OnceLock<AuditLogger> = std::sync::OnceLock::new();

/// Initialize the audit logger
pub fn init_audit_logger(log_dir: Option<PathBuf>) {
    let logger = AuditLogger::new(log_dir);
    AUDIT_LOGGER.set(logger).ok();
}

/// Log an audit event
pub fn log_event(event: AuditEvent) {
    if let Some(logger) = AUDIT_LOGGER.get() {
        logger.log(event);
    } else {
        // Fallback to tracing if logger not initialized
        tracing::info!(
            event_type = ?event.event_type,
            result = ?event.result,
            "Audit event (logger not initialized)"
        );
    }
}

/// Convenience function to log a simple event
pub fn log_simple(event_type: EventType, result: EventResult) {
    log_event(AuditEvent::new(event_type, result));
}

/// The audit logger
pub struct AuditLogger {
    writer: Mutex<Option<BufWriter<File>>>,
    log_path: PathBuf,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_dir: Option<PathBuf>) -> Self {
        let log_dir = log_dir.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".scrt").join("audit")
        });

        // Ensure directory exists
        std::fs::create_dir_all(&log_dir).ok();

        // Create log file with date in name
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let date_str = format_timestamp(now.as_secs()).split('T').next().unwrap_or("unknown").to_string();
        let log_path = log_dir.join(format!("audit-{}.jsonl", date_str));

        let writer = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok()
            .map(|f| BufWriter::new(f));

        Self {
            writer: Mutex::new(writer),
            log_path,
        }
    }

    /// Log an event
    pub fn log(&self, event: AuditEvent) {
        // Also log to tracing for real-time visibility
        tracing::info!(
            event_type = ?event.event_type,
            result = ?event.result,
            "Audit: {:?}", event.event_type
        );

        // Write to file
        if let Ok(mut guard) = self.writer.lock() {
            if let Some(ref mut writer) = *guard {
                if let Ok(json) = serde_json::to_string(&event) {
                    writeln!(writer, "{}", json).ok();
                    writer.flush().ok();
                }
            }
        }
    }

    /// Get the log file path
    pub fn log_path(&self) -> &PathBuf {
        &self.log_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(EventType::SessionStart, EventResult::Success)
            .with_ttl(7200)
            .with_secret_count(5);

        assert!(event.timestamp > 0);
        assert!(matches!(event.event_type, EventType::SessionStart));
        assert!(matches!(event.result, EventResult::Success));
        assert_eq!(event.ttl, Some(7200));
        assert_eq!(event.secret_count, Some(5));
    }

    #[test]
    fn test_sanitize_command() {
        // Test long string redaction - base64 JWT
        let cmd = "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIn0'";
        let sanitized = sanitize_command(cmd);
        assert!(
            sanitized.contains("[REDACTED_B64]") || sanitized.contains("[REDACTED]"),
            "Expected redaction for base64, got: {}", sanitized
        );

        // Test hex string redaction (Ethereum private key format)
        let cmd = "send --key 0x1234567890abcdef1234567890abcdef12345678";
        let sanitized = sanitize_command(cmd);
        assert!(
            sanitized.contains("[REDACTED_HEX]"),
            "Expected [REDACTED_HEX], got: {}", sanitized
        );
    }

    #[test]
    fn test_format_timestamp() {
        // Unix epoch
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");

        // Known date: 2024-01-15 12:30:45 UTC
        // (approximate, not accounting for leap seconds)
        let ts = format_timestamp(1705321845);
        assert!(ts.starts_with("2024-01-15"));
    }

    #[test]
    fn test_event_serialization() {
        let event = AuditEvent::new(EventType::CommandRun, EventResult::Success)
            .with_command("scrt run env")
            .with_exit_code(0);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("command_run"));
        assert!(json.contains("success"));
        assert!(json.contains("\"exit_code\":0"));
    }
}
