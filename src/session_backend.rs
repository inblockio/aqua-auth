//! `SessionBackend` — pluggable storage seam for [`crate::session::SessionStore`].
//!
//! This module is purely additive: it does not change `SessionStore`'s
//! behavior or public API. It defines a storage trait that a future task
//! will wire `SessionStore` to use internally, so a Redis (or other)
//! backend can be layered in later without another semver break.
//!
//! Token generation, TTL math, and capacity enforcement are policy that
//! stays in `SessionStore`. A `SessionBackend` is pure storage: insert,
//! get, remove, and enumerate sessions keyed by token.

use crate::auth_error::AuthError;
use crate::types::Session;
use dashmap::DashMap;

/// Pluggable storage seam for authenticated sessions.
///
/// Implementations are pure key-value storage keyed by session token; they
/// do not generate tokens, enforce TTLs, or enforce capacity limits — that
/// policy lives in [`crate::session::SessionStore`], which will drive an
/// implementation of this trait.
pub trait SessionBackend: Send + Sync {
    /// Insert (or overwrite) a session, keyed by its `token`.
    fn insert(&self, session: Session) -> Result<(), AuthError>;

    /// Look up a session by token.
    fn get(&self, token: &str) -> Option<Session>;

    /// Remove a session by token. Returns `true` if a session was removed.
    fn remove(&self, token: &str) -> bool;

    /// Remove all sessions belonging to `did`. Returns the number removed.
    fn remove_all_for_did(&self, did: &str) -> usize;

    /// All currently stored sessions.
    fn all(&self) -> Vec<Session>;

    /// The number of currently stored sessions.
    fn len(&self) -> usize;

    /// Whether the backend currently holds no sessions.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// In-memory [`SessionBackend`] backed by a [`DashMap`].
///
/// This is the default backend used by [`crate::session::SessionStore`]
/// today. It is not persistent: sessions are lost on process restart.
pub struct InMemoryBackend {
    sessions: DashMap<String, Session>,
}

impl InMemoryBackend {
    /// Create an empty in-memory backend.
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionBackend for InMemoryBackend {
    fn insert(&self, session: Session) -> Result<(), AuthError> {
        self.sessions.insert(session.token.clone(), session);
        Ok(())
    }

    fn get(&self, token: &str) -> Option<Session> {
        self.sessions.get(token).map(|entry| entry.value().clone())
    }

    fn remove(&self, token: &str) -> bool {
        self.sessions.remove(token).is_some()
    }

    fn remove_all_for_did(&self, did: &str) -> usize {
        let tokens: Vec<String> = self
            .sessions
            .iter()
            .filter(|entry| entry.value().did == did)
            .map(|entry| entry.key().clone())
            .collect();
        let count = tokens.len();
        for token in tokens {
            self.sessions.remove(&token);
        }
        count
    }

    fn all(&self) -> Vec<Session> {
        self.sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    fn len(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Session;

    #[test]
    fn in_memory_backend_insert_get_remove() {
        let b = InMemoryBackend::new();
        let s = Session {
            did: "did:key:zDnX".into(),
            token: "tok1".into(),
            valid_until: 9_999_999_999,
            created_at: 1,
        };
        b.insert(s.clone()).unwrap();
        assert_eq!(b.get("tok1").unwrap().did, "did:key:zDnX");
        assert_eq!(b.len(), 1);
        assert!(b.remove("tok1"));
        assert!(b.get("tok1").is_none());
    }
}
