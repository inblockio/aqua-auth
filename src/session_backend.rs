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

use std::sync::Arc;

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

    /// Every session belonging to `did`.
    ///
    /// **Hot path.** [`crate::session::SessionStore::create`] calls this on
    /// every login to enforce the per-DID cap, so a remote backend must serve
    /// it from a `did -> tokens` index rather than by scanning the keyspace.
    /// The result is bounded by the store's `max_sessions_per_did` (default
    /// 32), so this stays cheap where [`Self::all`] would not.
    fn sessions_for_did(&self, did: &str) -> Vec<Session>;

    /// Remove all sessions belonging to `did`. Returns the number removed.
    fn remove_all_for_did(&self, did: &str) -> usize;

    /// Drop every session whose `valid_until` is at or before `now_secs`.
    /// Returns the number removed.
    ///
    /// Defaulted over [`Self::all`] for backends with no native expiry. A
    /// backend whose store expires entries itself (Redis `EXAT`, a SQL job)
    /// should override this with a no-op returning `0`: the sweep would
    /// otherwise walk the whole keyspace to delete rows the store has already
    /// dropped.
    fn purge_expired(&self, now_secs: u64) -> usize {
        let expired: Vec<String> = self
            .all()
            .into_iter()
            .filter(|s| s.valid_until <= now_secs)
            .map(|s| s.token)
            .collect();
        expired.iter().filter(|t| self.remove(t)).count()
    }

    /// All currently stored sessions.
    ///
    /// **Cold path only.** This is administrative introspection
    /// ([`crate::session::SessionStore::list_sessions`]); on a remote backend
    /// it is a full keyspace walk. Nothing on the login path may call it: use
    /// [`Self::sessions_for_did`] or [`Self::len`] instead.
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

    fn sessions_for_did(&self, did: &str) -> Vec<Session> {
        // A scan of an in-process `DashMap`, not a network round trip. A
        // second `did -> tokens` index would have to be kept consistent with
        // this map on every insert/remove, and the failure mode of a stale
        // index (sessions invisible to the per-DID cap) is worse than the
        // cost of the scan. Remote backends, where the scan *is* the
        // expensive part, are the ones that must carry a real index.
        self.sessions
            .iter()
            .filter(|entry| entry.value().did == did)
            .map(|entry| entry.value().clone())
            .collect()
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

    fn purge_expired(&self, now_secs: u64) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, s| s.valid_until > now_secs);
        before - self.sessions.len()
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

/// Selects which [`SessionBackend`] implementation [`build_backend`] should
/// construct, so a consumer can pick a backend from config (e.g. a string
/// read from a TOML/env value) without branching on cargo features itself.
#[non_exhaustive]
pub enum SessionBackendKind {
    /// [`InMemoryBackend`]. Always available, in every feature configuration.
    Memory,
    /// [`crate::redis_backend::RedisBackend`] at the given connection URL
    /// (e.g. `redis://127.0.0.1:6379`). This variant always exists so
    /// `SessionBackendKind` itself compiles the same way regardless of the
    /// `redis` feature; only its *connect path* in [`build_backend`] is
    /// feature-gated. Without the `redis` feature, [`build_backend`] returns
    /// `Err(AuthError::BackendUnavailable(_))` instead of failing to compile.
    Redis(String),
}

/// Construct a [`SessionBackend`] from a [`SessionBackendKind`].
///
/// This is the seam consumers (aqua-node, aquafier) use to select a session
/// backend from config without `#[cfg(feature = "redis")]` at the call site:
/// they hold a `SessionBackendKind` (built from a config string) and call
/// this function, which does the feature branching internally.
///
/// `SessionBackendKind::Redis(_)` without the `redis` cargo feature enabled
/// returns a descriptive `Err(AuthError::BackendUnavailable(_))` rather than
/// failing to compile.
pub fn build_backend(kind: SessionBackendKind) -> Result<Arc<dyn SessionBackend>, AuthError> {
    match kind {
        SessionBackendKind::Memory => Ok(Arc::new(InMemoryBackend::new())),

        #[cfg(feature = "redis")]
        SessionBackendKind::Redis(url) => {
            let backend = crate::redis_backend::RedisBackend::connect(&url)?;
            Ok(Arc::new(backend))
        }

        #[cfg(not(feature = "redis"))]
        SessionBackendKind::Redis(_url) => Err(AuthError::BackendUnavailable(
            "redis session backend requested but this build of aqua-auth was compiled without \
             the `redis` cargo feature"
                .to_string(),
        )),
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

    fn session(did: &str, token: &str, valid_until: u64) -> Session {
        Session {
            did: did.into(),
            token: token.into(),
            valid_until,
            created_at: 1,
        }
    }

    #[test]
    fn sessions_for_did_returns_only_that_dids_sessions() {
        let b = InMemoryBackend::new();
        b.insert(session("did:key:zA", "a1", 9_999_999_999)).unwrap();
        b.insert(session("did:key:zA", "a2", 9_999_999_999)).unwrap();
        b.insert(session("did:key:zB", "b1", 9_999_999_999)).unwrap();

        let mut a: Vec<String> = b
            .sessions_for_did("did:key:zA")
            .into_iter()
            .map(|s| s.token)
            .collect();
        a.sort();
        assert_eq!(a, vec!["a1".to_string(), "a2".to_string()]);

        assert_eq!(b.sessions_for_did("did:key:zB").len(), 1);
        assert!(b.sessions_for_did("did:key:zAbsent").is_empty());
        // Reading the index must not mutate the store.
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn purge_expired_removes_only_expired_sessions() {
        let b = InMemoryBackend::new();
        b.insert(session("did:key:zA", "live", 2_000)).unwrap();
        b.insert(session("did:key:zA", "dead", 1_000)).unwrap();
        // `valid_until == now` counts as expired: `SessionStore::validate`
        // rejects with `now >= valid_until`, so the sweep must agree.
        b.insert(session("did:key:zB", "boundary", 1_500)).unwrap();

        assert_eq!(b.purge_expired(1_500), 2);
        assert_eq!(b.len(), 1);
        assert!(b.get("live").is_some());
        assert!(b.get("dead").is_none());
        assert!(b.get("boundary").is_none());

        // Idempotent: a second sweep at the same instant removes nothing.
        assert_eq!(b.purge_expired(1_500), 0);
    }
}

#[cfg(test)]
mod build_backend_tests {
    use super::*;
    use crate::types::Session;

    #[test]
    fn build_backend_memory_round_trips_a_session() {
        let backend = build_backend(SessionBackendKind::Memory).unwrap();
        let s = Session {
            did: "did:key:zBuild".into(),
            token: "build-tok".into(),
            valid_until: 9_999_999_999,
            created_at: 1,
        };
        backend.insert(s.clone()).unwrap();
        assert_eq!(backend.get("build-tok").unwrap().did, "did:key:zBuild");
        assert_eq!(backend.len(), 1);
        assert!(backend.remove("build-tok"));
        assert!(backend.get("build-tok").is_none());
    }

    #[cfg(not(feature = "redis"))]
    #[test]
    fn build_backend_redis_without_feature_returns_descriptive_err() {
        let result = build_backend(SessionBackendKind::Redis("redis://127.0.0.1:6379".into()));
        let err = match result {
            Ok(_) => panic!("expected an Err without the `redis` feature enabled"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("redis"),
            "expected the error message to mention redis, got: {msg}"
        );
    }

    #[cfg(feature = "redis")]
    #[test]
    fn build_backend_redis_with_feature_connects_when_available() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skip: TEST_REDIS_URL unset");
            return;
        };
        let backend = build_backend(SessionBackendKind::Redis(url)).unwrap();
        let s = Session {
            did: "did:key:zBuildRedis".into(),
            token: "build-redis-tok".into(),
            valid_until: 9_999_999_999,
            created_at: 1,
        };
        backend.insert(s.clone()).unwrap();
        assert_eq!(
            backend.get("build-redis-tok").unwrap().did,
            "did:key:zBuildRedis"
        );
        assert!(backend.remove("build-redis-tok"));
    }
}
