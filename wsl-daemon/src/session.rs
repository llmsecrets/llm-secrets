// wsl2-helper/src/session.rs
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use rand::Rng;

/// Maximum TTL: 24 hours
const MAX_TTL: u64 = 86400;

/// Challenge expires after 60 seconds
const CHALLENGE_TTL_SECS: u64 = 60;

/// Maximum number of pending challenges to prevent memory exhaustion
const MAX_PENDING_CHALLENGES: usize = 10;

/// A pending challenge awaiting user confirmation via GUI
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    pub secret_name: String,
    pub display_code: String,
    pub created_at: Instant,
}

/// A pending bulk reveal challenge (one challenge for all secrets)
#[derive(Debug, Clone)]
pub struct PendingBulkChallenge {
    pub display_code: String,
    pub created_at: Instant,
}

/// Session state - holds secrets in memory
#[derive(Debug)]
pub struct Session {
    token: Option<Vec<u8>>,
    secrets: Option<HashMap<String, String>>,
    master_key: Option<String>,  // Retained for re-encryption on save
    started_at: Option<Instant>,
    ttl: Duration,
    pending_challenges: HashMap<String, PendingChallenge>,
    pending_bulk_challenge: Option<(String, PendingBulkChallenge)>,  // (nonce, data)
}

impl Session {
    pub fn new() -> Self {
        Session {
            token: None,
            secrets: None,
            master_key: None,
            started_at: None,
            ttl: Duration::ZERO,
            pending_challenges: HashMap::new(),
            pending_bulk_challenge: None,
        }
    }

    /// Set the master key (called after unlock for re-encryption on save)
    pub fn set_master_key(&mut self, key: String) {
        self.master_key = Some(key);
    }

    /// Get the master key (for re-encryption)
    pub fn master_key(&self) -> Option<&str> {
        self.master_key.as_deref()
    }

    /// Store a new session with secrets
    pub fn store(
        &mut self,
        token: Vec<u8>,
        secrets: HashMap<String, String>,
        ttl_secs: u64,
    ) -> Result<(), String> {
        // Validate token size
        if token.len() != 32 {
            return Err("Invalid token size (must be 32 bytes)".into());
        }

        // Validate TTL
        if ttl_secs > MAX_TTL {
            return Err(format!("TTL too large (max {})", MAX_TTL));
        }

        // Clear existing session first
        self.clear();

        self.token = Some(token);
        self.secrets = Some(secrets);
        self.started_at = Some(Instant::now());
        self.ttl = if ttl_secs == 0 {
            Duration::MAX  // No expiry
        } else {
            Duration::from_secs(ttl_secs)
        };

        tracing::info!("Session stored with {} secrets, TTL: {}s",
            self.secrets.as_ref().map(|s| s.len()).unwrap_or(0),
            ttl_secs
        );

        Ok(())
    }

    /// Add secrets to an active session (merges with existing)
    pub fn add_secrets(&mut self, secrets: HashMap<String, String>) -> Result<usize, String> {
        if !self.is_active() {
            return Err("No active session".into());
        }

        let count = secrets.len();
        if let Some(ref mut existing) = self.secrets {
            existing.extend(secrets);
        }

        tracing::info!("Added {} secret(s) to session (total: {})",
            count,
            self.secrets.as_ref().map(|s| s.len()).unwrap_or(0)
        );

        Ok(count)
    }

    /// Clear the session
    pub fn clear(&mut self) {
        // Zero out token before dropping
        if let Some(ref mut token) = self.token {
            token.iter_mut().for_each(|b| *b = 0);
        }
        self.token = None;
        self.secrets = None;
        self.master_key = None;
        self.started_at = None;
        self.ttl = Duration::ZERO;
        self.pending_challenges.clear();
        self.pending_bulk_challenge = None;
        tracing::info!("Session cleared");
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        if self.token.is_none() || self.secrets.is_none() {
            return false;
        }

        if let Some(started) = self.started_at {
            if self.ttl != Duration::MAX && started.elapsed() > self.ttl {
                return false;
            }
        }

        true
    }

    /// Extend the session: reset the timer, optionally update TTL.
    /// Returns the new remaining seconds on success.
    pub fn extend(&mut self, ttl_secs: Option<u64>) -> Result<i64, String> {
        if !self.is_active() {
            return Err("No active session".into());
        }

        // Update TTL if provided
        if let Some(new_ttl) = ttl_secs {
            if new_ttl > MAX_TTL {
                return Err(format!("TTL too large (max {})", MAX_TTL));
            }
            self.ttl = if new_ttl == 0 {
                Duration::MAX
            } else {
                Duration::from_secs(new_ttl)
            };
        }

        // Reset the timer
        self.started_at = Some(Instant::now());

        let remaining = self.remaining_secs();
        tracing::info!("Session extended, remaining: {}s", remaining);

        Ok(remaining)
    }

    /// Get remaining seconds (-1 = no expiry, 0 = expired)
    pub fn remaining_secs(&self) -> i64 {
        if !self.is_active() {
            return 0;
        }

        if self.ttl == Duration::MAX {
            return -1;
        }

        if let Some(started) = self.started_at {
            let elapsed = started.elapsed();
            if elapsed >= self.ttl {
                return 0;
            }
            return (self.ttl - elapsed).as_secs() as i64;
        }

        0
    }

    /// Get secret names (not values)
    pub fn secret_names(&self) -> Option<Vec<String>> {
        self.secrets.as_ref().map(|s| {
            let mut names: Vec<_> = s.keys().cloned().collect();
            names.sort();
            names
        })
    }

    /// Get all secrets (for command substitution)
    pub fn secrets(&self) -> Option<&HashMap<String, String>> {
        if self.is_active() {
            self.secrets.as_ref()
        } else {
            None
        }
    }

    /// Get a single secret by name
    pub fn get_secret(&self, name: &str) -> Option<&String> {
        if self.is_active() {
            self.secrets.as_ref().and_then(|s| s.get(name))
        } else {
            None
        }
    }

    /// Create a challenge for revealing a secret.
    ///
    /// Returns (nonce, display_code) on success. The nonce is 64 hex chars
    /// (32 random bytes). The display_code is a 6-digit numeric string that
    /// the user must confirm via the GUI before the secret is released.
    pub fn create_challenge(&mut self, secret_name: &str) -> Result<(String, String), String> {
        if !self.is_active() {
            return Err("No active session".into());
        }

        // Check the secret actually exists
        let has_secret = self.secrets.as_ref()
            .map(|s| s.contains_key(secret_name))
            .unwrap_or(false);
        if !has_secret {
            return Err(format!("Secret '{}' not found", secret_name));
        }

        // Evict expired challenges first to free space
        self.evict_expired_challenges();

        // Enforce max pending limit
        if self.pending_challenges.len() >= MAX_PENDING_CHALLENGES {
            return Err("Too many pending challenges; try again later".into());
        }

        let mut rng = rand::thread_rng();

        // Generate 32 random bytes -> 64 hex chars
        let mut nonce_bytes = [0u8; 32];
        rng.fill(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Generate 6-digit display code (000000-999999)
        let code_num: u32 = rng.gen_range(0..1_000_000);
        let display_code = format!("{:06}", code_num);

        let challenge = PendingChallenge {
            secret_name: secret_name.to_string(),
            display_code: display_code.clone(),
            created_at: Instant::now(),
        };

        self.pending_challenges.insert(nonce.clone(), challenge);

        tracing::info!("Challenge created for secret '{}'", secret_name);

        Ok((nonce, display_code))
    }

    /// Validate a challenge and return the secret value if the code matches.
    ///
    /// The challenge is always consumed (single-use) regardless of whether
    /// validation succeeds or fails.
    pub fn validate_challenge(&mut self, nonce: &str, user_code: &str) -> Result<String, String> {
        if !self.is_active() {
            return Err("No active session".into());
        }

        // Evict expired challenges
        self.evict_expired_challenges();

        // Remove the challenge (single-use: consumed on any attempt)
        let challenge = self.pending_challenges.remove(nonce)
            .ok_or_else(|| "Challenge not found or expired".to_string())?;

        // Check expiry (belt-and-suspenders; eviction already ran, but the
        // challenge could have been created just at the boundary)
        if challenge.created_at.elapsed() > Duration::from_secs(CHALLENGE_TTL_SECS) {
            return Err("Challenge expired".into());
        }

        // Check the user-provided code matches the display code
        if user_code != challenge.display_code {
            return Err("Invalid confirmation code".into());
        }

        // Return the secret value
        self.get_secret(&challenge.secret_name)
            .cloned()
            .ok_or_else(|| "Secret no longer available".into())
    }

    /// Remove all pending challenges that have exceeded CHALLENGE_TTL_SECS.
    pub fn evict_expired_challenges(&mut self) {
        let ttl = Duration::from_secs(CHALLENGE_TTL_SECS);
        self.pending_challenges.retain(|_, c| c.created_at.elapsed() <= ttl);
    }

    /// Create a bulk challenge for revealing all secrets at once.
    ///
    /// Returns (nonce, display_code) on success. Only one bulk challenge can
    /// be pending at a time (creating a new one replaces any previous one).
    pub fn create_bulk_challenge(&mut self) -> Result<(String, String), String> {
        if !self.is_active() {
            return Err("No active session".into());
        }

        let mut rng = rand::thread_rng();

        // Generate 32 random bytes -> 64 hex chars
        let mut nonce_bytes = [0u8; 32];
        rng.fill(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Generate 6-digit display code (000000-999999)
        let code_num: u32 = rng.gen_range(0..1_000_000);
        let display_code = format!("{:06}", code_num);

        self.pending_bulk_challenge = Some((nonce.clone(), PendingBulkChallenge {
            display_code: display_code.clone(),
            created_at: Instant::now(),
        }));

        tracing::info!("Bulk reveal challenge created");

        Ok((nonce, display_code))
    }

    /// Validate a bulk challenge and return all secrets if the code matches.
    ///
    /// The challenge is always consumed (single-use) regardless of whether
    /// validation succeeds or fails.
    pub fn validate_bulk_challenge(&mut self, nonce: &str, user_code: &str) -> Result<HashMap<String, String>, String> {
        if !self.is_active() {
            return Err("No active session".into());
        }

        let (stored_nonce, challenge) = match self.pending_bulk_challenge.take() {
            Some(c) => c,
            None => return Err("No pending bulk challenge".into()),
        };

        if stored_nonce != nonce {
            return Err("Invalid challenge nonce".into());
        }

        if challenge.created_at.elapsed() > Duration::from_secs(CHALLENGE_TTL_SECS) {
            return Err("Challenge expired".into());
        }

        if user_code != challenge.display_code {
            return Err("Invalid confirmation code".into());
        }

        match &self.secrets {
            Some(secrets) => Ok(secrets.clone()),
            None => Err("No secrets available".into()),
        }
    }
}

/// Thread-safe session state
pub type SharedSession = Arc<RwLock<Session>>;

pub fn new_shared_session() -> SharedSession {
    Arc::new(RwLock::new(Session::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a session with one secret stored
    fn setup_active_session() -> Session {
        let mut session = Session::new();
        let token = vec![0xABu8; 32];
        let mut secrets = HashMap::new();
        secrets.insert("MY_SECRET".to_string(), "super_secret_value".to_string());
        secrets.insert("OTHER_SECRET".to_string(), "other_value".to_string());
        session.store(token, secrets, 3600).unwrap();
        session
    }

    #[test]
    fn test_create_challenge_returns_nonce_and_code() {
        let mut session = setup_active_session();
        let (nonce, code) = session.create_challenge("MY_SECRET").unwrap();

        // Nonce should be 64 hex characters (32 bytes hex-encoded)
        assert_eq!(nonce.len(), 64, "nonce must be 64 hex chars");
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()), "nonce must be hex");

        // Display code should be 6 digits
        assert_eq!(code.len(), 6, "display code must be 6 chars");
        assert!(code.chars().all(|c| c.is_ascii_digit()), "display code must be digits");
    }

    #[test]
    fn test_create_challenge_fails_for_missing_secret() {
        let mut session = setup_active_session();
        let result = session.create_challenge("NONEXISTENT");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_create_challenge_fails_when_inactive() {
        let mut session = Session::new();
        let result = session.create_challenge("MY_SECRET");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No active session"));
    }

    #[test]
    fn test_validate_challenge_success() {
        let mut session = setup_active_session();
        let (nonce, code) = session.create_challenge("MY_SECRET").unwrap();

        let value = session.validate_challenge(&nonce, &code).unwrap();
        assert_eq!(value, "super_secret_value");
    }

    #[test]
    fn test_validate_challenge_wrong_code() {
        let mut session = setup_active_session();
        let (nonce, code) = session.create_challenge("MY_SECRET").unwrap();

        // Construct a code guaranteed to differ from the real one
        let wrong_code = if code == "999999" { "000000" } else { "999999" };
        let err = session.validate_challenge(&nonce, wrong_code);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Invalid confirmation code"));
    }

    #[test]
    fn test_validate_challenge_reuse_fails() {
        let mut session = setup_active_session();
        let (nonce, code) = session.create_challenge("MY_SECRET").unwrap();

        // First use succeeds
        let value = session.validate_challenge(&nonce, &code).unwrap();
        assert_eq!(value, "super_secret_value");

        // Second use of same nonce fails (challenge was consumed)
        let result = session.validate_challenge(&nonce, &code);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_clear_removes_challenges() {
        let mut session = setup_active_session();
        let (_nonce, _code) = session.create_challenge("MY_SECRET").unwrap();
        assert!(!session.pending_challenges.is_empty());

        session.clear();
        assert!(session.pending_challenges.is_empty());
    }

    #[test]
    fn test_max_pending_challenges() {
        let mut session = setup_active_session();

        // Fill up to MAX_PENDING_CHALLENGES
        for _ in 0..MAX_PENDING_CHALLENGES {
            session.create_challenge("MY_SECRET").unwrap();
        }

        // The next one should fail
        let result = session.create_challenge("MY_SECRET");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Too many pending challenges"));
    }

    #[test]
    fn test_create_bulk_challenge_returns_nonce_and_code() {
        let mut session = setup_active_session();
        let (nonce, code) = session.create_bulk_challenge().unwrap();

        assert_eq!(nonce.len(), 64, "nonce must be 64 hex chars");
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()), "nonce must be hex");
        assert_eq!(code.len(), 6, "display code must be 6 chars");
        assert!(code.chars().all(|c| c.is_ascii_digit()), "display code must be digits");
    }

    #[test]
    fn test_create_bulk_challenge_fails_when_inactive() {
        let mut session = Session::new();
        let result = session.create_bulk_challenge();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No active session"));
    }

    #[test]
    fn test_validate_bulk_challenge_success() {
        let mut session = setup_active_session();
        let (nonce, code) = session.create_bulk_challenge().unwrap();

        let secrets = session.validate_bulk_challenge(&nonce, &code).unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets.get("MY_SECRET").unwrap(), "super_secret_value");
        assert_eq!(secrets.get("OTHER_SECRET").unwrap(), "other_value");
    }

    #[test]
    fn test_validate_bulk_challenge_wrong_code() {
        let mut session = setup_active_session();
        let (nonce, code) = session.create_bulk_challenge().unwrap();

        let wrong_code = if code == "999999" { "000000" } else { "999999" };
        let err = session.validate_bulk_challenge(&nonce, wrong_code);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Invalid confirmation code"));
    }

    #[test]
    fn test_validate_bulk_challenge_reuse_fails() {
        let mut session = setup_active_session();
        let (nonce, code) = session.create_bulk_challenge().unwrap();

        // First use succeeds
        let secrets = session.validate_bulk_challenge(&nonce, &code).unwrap();
        assert_eq!(secrets.len(), 2);

        // Second use fails (challenge was consumed)
        let result = session.validate_bulk_challenge(&nonce, &code);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No pending bulk challenge"));
    }

    #[test]
    fn test_validate_bulk_challenge_wrong_nonce() {
        let mut session = setup_active_session();
        let (_nonce, code) = session.create_bulk_challenge().unwrap();

        let result = session.validate_bulk_challenge("wrong_nonce", &code);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid challenge nonce"));
    }

    #[test]
    fn test_clear_removes_bulk_challenge() {
        let mut session = setup_active_session();
        let (_nonce, _code) = session.create_bulk_challenge().unwrap();
        assert!(session.pending_bulk_challenge.is_some());

        session.clear();
        assert!(session.pending_bulk_challenge.is_none());
    }
}
