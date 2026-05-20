//! SessionStore — in-memory store for authenticated sessions.
//!
//! Sessions have a 1-hour TTL. A background tokio task sweeps expired
//! sessions every 60 seconds.

use crate::auth_error::AuthError;
use crate::challenge::ChallengeStore;
use crate::types::{Session, SessionInfo};
use chrono::Utc;
use dashmap::DashMap;
use rand::Rng;
use std::sync::Arc;

/// Default session TTL in seconds.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour

/// Default cleanup interval in seconds.
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 60;

/// In-memory store for authenticated sessions.
pub struct SessionStore {
    /// Sessions keyed by token.
    sessions: DashMap<String, Session>,
    /// Session time-to-live in seconds.
    ttl_secs: u64,
}

impl SessionStore {
    /// Create a new session store.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            sessions: DashMap::new(),
            ttl_secs,
        }
    }

    /// Create a new session for an authenticated DID.
    ///
    /// Generates a random 32-byte session token.
    pub fn create(&self, did: &str) -> Session {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut token_bytes);
        let token = hex::encode(token_bytes);

        let now = Utc::now().timestamp() as u64;
        let session = Session {
            did: did.to_string(),
            token: token.clone(),
            valid_until: now + self.ttl_secs,
            created_at: now,
        };

        self.sessions.insert(token, session.clone());
        session
    }

    /// Validate a session token. Returns the associated DID if valid.
    pub fn validate(&self, token: &str) -> Result<String, AuthError> {
        let session = self.sessions.get(token).ok_or(AuthError::SessionNotFound)?;

        let now = Utc::now().timestamp() as u64;
        if now >= session.valid_until {
            // Remove expired session
            drop(session);
            self.sessions.remove(token);
            return Err(AuthError::SessionExpired);
        }

        Ok(session.did.clone())
    }

    /// List all active (non-expired) sessions.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let now = Utc::now().timestamp() as u64;
        self.sessions
            .iter()
            .filter(|entry| entry.value().valid_until > now)
            .map(|entry| {
                let s = entry.value();
                SessionInfo {
                    did: s.did.clone(),
                    created_at: s.created_at,
                    valid_until: s.valid_until,
                }
            })
            .collect()
    }

    /// Number of active sessions (including possibly expired ones not yet cleaned up).
    pub fn active_count(&self) -> u32 {
        self.sessions.len() as u32
    }

    /// Remove all expired sessions.
    pub fn cleanup_expired(&self) {
        let now = Utc::now().timestamp() as u64;
        self.sessions.retain(|_, s| s.valid_until > now);
    }

    /// Start a background task that periodically cleans up expired sessions
    /// and challenges.
    ///
    /// The task runs every `interval_secs` seconds and stops when the
    /// `SessionStore` Arc is dropped (checked via `Arc::strong_count`).
    pub fn start_cleanup(
        self: &Arc<Self>,
        challenge_store: Arc<ChallengeStore>,
        interval_secs: u64,
    ) {
        let session_store = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                session_store.cleanup_expired();
                challenge_store.cleanup_expired();
                // Stop if we're the only reference left
                if Arc::strong_count(&session_store) <= 1 {
                    break;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_session() {
        let store = SessionStore::new(3600);
        let session = store.create("did:pkh:eip155:1:0xabc");
        assert_eq!(session.did, "did:pkh:eip155:1:0xabc");
        assert_eq!(session.token.len(), 64); // 32 bytes hex

        let did = store.validate(&session.token).unwrap();
        assert_eq!(did, "did:pkh:eip155:1:0xabc");
    }

    #[test]
    fn unknown_token_fails() {
        let store = SessionStore::new(3600);
        assert!(store.validate("nonexistent").is_err());
    }

    #[test]
    fn expired_session_fails() {
        let store = SessionStore::new(0); // 0-second TTL
        let session = store.create("did:pkh:eip155:1:0xabc");
        // Already expired
        assert!(store.validate(&session.token).is_err());
    }

    #[test]
    fn list_sessions_returns_active() {
        let store = SessionStore::new(3600);
        store.create("did:pkh:eip155:1:0xaaa");
        store.create("did:pkh:eip155:1:0xbbb");

        let sessions = store.list_sessions();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn cleanup_removes_expired() {
        let store = SessionStore::new(0);
        store.create("did:pkh:eip155:1:0xaaa");
        assert_eq!(store.active_count(), 1);

        store.cleanup_expired();
        assert_eq!(store.active_count(), 0);
    }
}
