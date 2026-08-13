//! SessionStore — in-memory store for authenticated sessions.
//!
//! Sessions have a 1-hour TTL. A background tokio task sweeps expired
//! sessions every 60 seconds.
//!
//! ## H2 hardening: bounded capacity, revocation
//!
//! Two independent bounds protect this store:
//!
//! - A global hard cap ([`MAX_SESSIONS`], overridable via
//!   [`SessionStore::with_capacity`]). At capacity, `create` purges expired
//!   sessions first; if that doesn't free a slot, the new session is
//!   **rejected** with [`AuthError::SessionStoreFull`] rather than evicting
//!   an active, authenticated session. The rejection is logged loudly via
//!   `tracing::error!`.
//! - A per-DID cap ([`MAX_SESSIONS_PER_DID`], overridable via the same
//!   constructor). Unlike the global cap, this one evicts: creating beyond a
//!   single DID's quota evicts that DID's own oldest session. This bounds
//!   sybil-session farming (one identity minting unbounded sessions) without
//!   ever touching another identity's sessions, and without needing to
//!   reject legitimate re-logins from an active user.
//!
//! Sessions can also be revoked directly ([`SessionStore::revoke`],
//! [`SessionStore::revoke_all_for_did`]) — e.g. for `POST /auth/logout`.
//! Revocation removes the session outright, so `validate` fails immediately
//! afterward (same code path as an unknown token).

use crate::auth_error::AuthError;
use crate::challenge::ChallengeStore;
use crate::session_backend::{InMemoryBackend, SessionBackend};
use crate::types::{Session, SessionInfo};
use chrono::Utc;
use rand::Rng;
use std::sync::Arc;

/// Default session TTL in seconds.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour

/// Default cleanup interval in seconds.
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 60;

/// Default hard cap on total concurrently active sessions across all DIDs.
/// Override via [`SessionStore::with_capacity`].
pub const MAX_SESSIONS: usize = 8192;

/// Default hard cap on concurrently active sessions for a single DID.
/// Override via [`SessionStore::with_capacity`].
pub const MAX_SESSIONS_PER_DID: usize = 32;

/// In-memory store for authenticated sessions.
pub struct SessionStore {
    /// Pluggable storage backend (see [`crate::session_backend::SessionBackend`]).
    backend: Arc<dyn SessionBackend>,
    /// Session time-to-live in seconds.
    ttl_secs: u64,
    /// Global hard cap (see [`MAX_SESSIONS`]).
    max_sessions: usize,
    /// Per-DID hard cap (see [`MAX_SESSIONS_PER_DID`]).
    max_sessions_per_did: usize,
}

impl SessionStore {
    /// Create a new session store.
    ///
    /// Capped at [`MAX_SESSIONS`] total sessions and [`MAX_SESSIONS_PER_DID`]
    /// sessions per DID. Use [`Self::with_capacity`] to override either cap.
    pub fn new(ttl_secs: u64) -> Self {
        Self::with_capacity(ttl_secs, MAX_SESSIONS, MAX_SESSIONS_PER_DID)
    }

    /// Same as [`Self::new`], but with explicit hard caps overriding
    /// [`MAX_SESSIONS`] and [`MAX_SESSIONS_PER_DID`].
    pub fn with_capacity(ttl_secs: u64, max_sessions: usize, max_sessions_per_did: usize) -> Self {
        Self::with_backend(
            ttl_secs,
            max_sessions,
            max_sessions_per_did,
            Arc::new(InMemoryBackend::new()),
        )
    }

    /// Same as [`Self::with_capacity`], but with an explicit
    /// [`SessionBackend`] implementation for storage (e.g. Redis) instead of
    /// the default in-memory one.
    pub fn with_backend(
        ttl_secs: u64,
        max_sessions: usize,
        max_sessions_per_did: usize,
        backend: Arc<dyn SessionBackend>,
    ) -> Self {
        Self {
            backend,
            ttl_secs,
            max_sessions,
            max_sessions_per_did,
        }
    }

    /// Create a new session for an authenticated DID.
    ///
    /// Generates a random 32-byte session token.
    ///
    /// At the global capacity, expired sessions are purged first; if the
    /// store is still full the new session is rejected with
    /// [`AuthError::SessionStoreFull`] — active authenticated sessions are
    /// never evicted to make room. Independently, if `did` already holds
    /// `max_sessions_per_did` sessions, its own oldest session is evicted to
    /// make room for the new one (bounds per-identity session farming).
    pub fn create(&self, did: &str) -> Result<Session, AuthError> {
        if self.backend.len() >= self.max_sessions {
            self.cleanup_expired();
            if self.backend.len() >= self.max_sessions {
                tracing::error!(
                    max = self.max_sessions,
                    did,
                    "SessionStore at capacity; rejecting new session"
                );
                return Err(AuthError::SessionStoreFull {
                    max: self.max_sessions,
                });
            }
        }

        self.enforce_per_did_cap(did);

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

        self.backend.insert(session.clone())?;
        Ok(session)
    }

    /// If `did` is already at (or over) `max_sessions_per_did`, evict its
    /// single oldest session (by `created_at`, ties broken by token) to make
    /// room. A no-op when `did` is under quota. Never touches another DID's
    /// sessions — only bounds a single identity's own session count.
    fn enforce_per_did_cap(&self, did: &str) {
        let mut this_did: Vec<(String, u64)> = self
            .backend
            .all()
            .into_iter()
            .filter(|s| s.did == did)
            .map(|s| (s.token, s.created_at))
            .collect();
        if this_did.len() < self.max_sessions_per_did {
            return;
        }
        this_did.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        if let Some((oldest_token, _)) = this_did.first() {
            tracing::warn!(
                did,
                max_per_did = self.max_sessions_per_did,
                "per-DID session cap reached; evicting oldest session for this DID"
            );
            self.backend.remove(oldest_token);
        }
    }

    /// Revoke a session by token. Returns `true` if a session was removed,
    /// `false` if the token was already invalid/unknown. A revoked session
    /// fails `validate` immediately afterward (same path as an unknown
    /// token, since revocation removes the entry outright).
    pub fn revoke(&self, token: &str) -> bool {
        self.backend.remove(token)
    }

    /// Revoke every active session belonging to `did`. Returns the number of
    /// sessions removed. Best-effort under concurrency: a session created by
    /// `did` concurrently with this call may or may not be included, same as
    /// the rest of this store's other bulk operations (`cleanup_expired`).
    pub fn revoke_all_for_did(&self, did: &str) -> usize {
        self.backend.remove_all_for_did(did)
    }

    /// Validate a session token. Returns the associated DID if valid.
    pub fn validate(&self, token: &str) -> Result<String, AuthError> {
        let session = self.backend.get(token).ok_or(AuthError::SessionNotFound)?;

        let now = Utc::now().timestamp() as u64;
        if now >= session.valid_until {
            // Remove expired session
            self.backend.remove(token);
            return Err(AuthError::SessionExpired);
        }

        Ok(session.did.clone())
    }

    /// List all active (non-expired) sessions.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let now = Utc::now().timestamp() as u64;
        self.backend
            .all()
            .into_iter()
            .filter(|s| s.valid_until > now)
            .map(|s| SessionInfo {
                did: s.did,
                created_at: s.created_at,
                valid_until: s.valid_until,
            })
            .collect()
    }

    /// Number of active sessions (including possibly expired ones not yet cleaned up).
    pub fn active_count(&self) -> u32 {
        self.backend.len() as u32
    }

    /// Remove all expired sessions. Best-effort under concurrency: a session
    /// created between this call's snapshot and its removal pass is simply
    /// swept on the next cycle.
    pub fn cleanup_expired(&self) {
        let now = Utc::now().timestamp() as u64;
        for s in self.backend.all() {
            if s.valid_until <= now {
                self.backend.remove(&s.token);
            }
        }
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
        let session = store.create("did:pkh:eip155:1:0xabc").unwrap();
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
        let session = store.create("did:pkh:eip155:1:0xabc").unwrap();
        // Already expired
        assert!(store.validate(&session.token).is_err());
    }

    #[test]
    fn list_sessions_returns_active() {
        let store = SessionStore::new(3600);
        store.create("did:pkh:eip155:1:0xaaa").unwrap();
        store.create("did:pkh:eip155:1:0xbbb").unwrap();

        let sessions = store.list_sessions();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn cleanup_removes_expired() {
        let store = SessionStore::new(0);
        store.create("did:pkh:eip155:1:0xaaa").unwrap();
        assert_eq!(store.active_count(), 1);

        store.cleanup_expired();
        assert_eq!(store.active_count(), 0);
    }

    // ── H2 hardening: bounded capacity ──────────────────────────────────

    #[test]
    fn default_caps_match_consts() {
        let store = SessionStore::new(3600);
        assert_eq!(store.max_sessions, MAX_SESSIONS);
        assert_eq!(store.max_sessions_per_did, MAX_SESSIONS_PER_DID);
    }

    #[test]
    fn with_capacity_overrides_both_caps() {
        let store = SessionStore::with_capacity(3600, 3, 2);
        assert_eq!(store.max_sessions, 3);
        assert_eq!(store.max_sessions_per_did, 2);
    }

    #[test]
    fn global_cap_purges_expired_before_rejecting() {
        // 0-second TTL: every prior session is immediately expired, so
        // hitting the global cap must be resolved by purging (freeing all
        // slots), not by rejecting.
        let store = SessionStore::with_capacity(0, 2, 2);
        store.create("did:pkh:eip155:1:0xaaa").unwrap();
        store.create("did:pkh:eip155:1:0xbbb").unwrap();
        assert_eq!(store.active_count(), 2);

        // Both prior sessions are already expired: create() purges them
        // first, so this succeeds instead of being rejected.
        let s = store.create("did:pkh:eip155:1:0xccc");
        assert!(
            s.is_ok(),
            "purge must reclaim expired slots before any rejection"
        );
        assert_eq!(store.active_count(), 1);
    }

    #[test]
    fn global_cap_rejects_when_still_full_after_purge() {
        // Long TTL so nothing is purgeable; every DID distinct so the
        // per-DID cap never kicks in first.
        let store = SessionStore::with_capacity(3600, 2, 100);
        store.create("did:pkh:eip155:1:0xaaa").unwrap();
        store.create("did:pkh:eip155:1:0xbbb").unwrap();
        assert_eq!(store.active_count(), 2);

        // Third create must be REJECTED, not evict either active session.
        let err = store.create("did:pkh:eip155:1:0xccc").unwrap_err();
        assert!(matches!(err, AuthError::SessionStoreFull { max: 2 }));
        assert_eq!(
            store.active_count(),
            2,
            "an active authenticated session must never be evicted for a rejected create"
        );
    }

    #[test]
    fn per_did_cap_evicts_that_dids_oldest_session_only() {
        // High global cap so only the per-DID cap is in play.
        let store = SessionStore::with_capacity(3600, 100, 2);
        let did_a = "did:pkh:eip155:1:0xaaa";
        let other = "did:pkh:eip155:1:0xbbb";

        let a1 = store.create(did_a).unwrap();
        // created_at has 1-second resolution; force a real gap so ordering
        // is unambiguous.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let a2 = store.create(did_a).unwrap();
        let b1 = store.create(other).unwrap();
        assert_eq!(store.active_count(), 3);

        // A third session for did_a exceeds its per-DID quota (2): a1 (the
        // oldest for did_a) must be evicted. `other`'s session is untouched.
        let a3 = store.create(did_a).unwrap();
        assert!(store.validate(&a1.token).is_err(), "a1 must be evicted");
        assert!(store.validate(&a2.token).is_ok());
        assert!(store.validate(&a3.token).is_ok());
        assert!(
            store.validate(&b1.token).is_ok(),
            "another DID's session must never be touched by this DID's cap"
        );
    }

    #[test]
    fn revoke_removes_session_and_fails_validation_immediately() {
        let store = SessionStore::new(3600);
        let session = store.create("did:pkh:eip155:1:0xabc").unwrap();
        assert!(store.validate(&session.token).is_ok());

        assert!(store.revoke(&session.token));
        assert!(matches!(
            store.validate(&session.token),
            Err(AuthError::SessionNotFound)
        ));
        // Revoking again is a no-op that reports no session was found.
        assert!(!store.revoke(&session.token));
    }

    #[test]
    fn revoke_unknown_token_returns_false() {
        let store = SessionStore::new(3600);
        assert!(!store.revoke("nonexistent"));
    }

    #[test]
    fn store_with_explicit_backend_roundtrips() {
        let store = SessionStore::with_backend(
            3600,
            8192,
            32,
            Arc::new(crate::session_backend::InMemoryBackend::new()),
        );
        let s = store.create("did:pkh:eip155:1:0xabc").unwrap();
        assert_eq!(store.validate(&s.token).unwrap(), "did:pkh:eip155:1:0xabc");
    }

    #[test]
    fn revoke_all_for_did_removes_only_that_dids_sessions() {
        let store = SessionStore::new(3600);
        let did_a = "did:pkh:eip155:1:0xaaa";
        let did_b = "did:pkh:eip155:1:0xbbb";
        store.create(did_a).unwrap();
        store.create(did_a).unwrap();
        let b = store.create(did_b).unwrap();

        let revoked = store.revoke_all_for_did(did_a);
        assert_eq!(revoked, 2);
        assert_eq!(store.active_count(), 1);
        assert!(store.validate(&b.token).is_ok());
    }
}
