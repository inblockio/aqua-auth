//! Redis-backed [`crate::session_backend::SessionBackend`] (feature `redis`).
//!
//! Persists sessions in Redis so they survive process restarts and can be
//! shared across multiple server instances. This is purely additive: the
//! default (in-memory) backend is unchanged, and this module only compiles
//! when the `redis` cargo feature is enabled.
//!
//! `SessionBackend` is a **sync** trait, so this uses the `redis` crate's
//! synchronous API (`redis::Client` + `get_connection()`), not the async
//! client. A `Mutex<redis::Connection>` serializes access to the single
//! blocking connection.
//!
//! Key layout:
//! - `aqua:session:{token}` -> JSON-serialized [`Session`], with a Redis
//!   expiry set to the session's `valid_until` (Unix seconds) atomically via
//!   `SET key value EXAT valid_until`.
//! - `aqua:did:{did}` -> a Redis SET of tokens belonging to `did`, used to
//!   implement `remove_all_for_did` without a full scan. Its own expiry is
//!   refreshed to the newest member's `valid_until` on every `insert`, so it
//!   self-expires instead of accumulating stale tokens forever when sessions
//!   are left to expire naturally (Redis deletes `aqua:session:{token}` via
//!   its own EXAT before anyone calls `remove()`, so `remove()` alone cannot
//!   keep the DID set bounded — see the "DID-set leak" fix note below).

use std::sync::{Mutex, MutexGuard};

use redis::{Commands, SetExpiry, SetOptions};

use crate::auth_error::AuthError;
use crate::session_backend::SessionBackend;
use crate::types::Session;

const SESSION_PREFIX: &str = "aqua:session:";
const DID_PREFIX: &str = "aqua:did:";

fn session_key(token: &str) -> String {
    format!("{SESSION_PREFIX}{token}")
}

fn did_key(did: &str) -> String {
    format!("{DID_PREFIX}{did}")
}

/// Redis-backed [`SessionBackend`].
///
/// Holds a single blocking `redis::Connection` behind a `Mutex`, since
/// `SessionBackend`'s methods are sync and `redis::Connection` is `!Sync`.
pub struct RedisBackend {
    conn: Mutex<redis::Connection>,
}

impl RedisBackend {
    /// Connect to Redis at `url` (e.g. `redis://127.0.0.1:6379`).
    pub fn connect(url: &str) -> Result<Self, AuthError> {
        let client = redis::Client::open(url).map_err(AuthError::Redis)?;
        let conn = client.get_connection().map_err(AuthError::Redis)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Acquire the connection lock, recovering to `None` instead of
    /// panicking if a prior panic poisoned it. Every trait method below
    /// degrades gracefully on `None` (its safe default for reads, or
    /// `AuthError::LockPoisoned` for the one fallible method, `insert`) —
    /// there is no `.expect()`/panic path anywhere in this backend.
    fn lock(&self) -> Option<MutexGuard<'_, redis::Connection>> {
        self.conn.lock().ok()
    }
}

impl SessionBackend for RedisBackend {
    fn insert(&self, session: Session) -> Result<(), AuthError> {
        let payload = serde_json::to_string(&session).map_err(AuthError::Serde)?;
        let mut conn = self.lock().ok_or(AuthError::LockPoisoned)?;
        let skey = session_key(&session.token);
        let dkey = did_key(&session.did);

        // Atomic SET + EXAT: unlike a separate SET followed by EXPIREAT,
        // there is no window where aqua:session:{token} exists without an
        // expiry already attached.
        let opts = SetOptions::default().with_expiration(SetExpiry::EXAT(session.valid_until));
        let _: () = conn
            .set_options(&skey, payload, opts)
            .map_err(AuthError::Redis)?;

        let _: () = conn.sadd(&dkey, &session.token).map_err(AuthError::Redis)?;
        // Bound the DID-set's own lifetime to this (newest) session's
        // expiry. Without this, natural session expiry never shrinks
        // aqua:did:{did}: Redis deletes aqua:session:{token} itself via its
        // EXAT *before* anyone calls remove()/remove_all_for_did(), so
        // those methods never observe the expiry and never SREM the stale
        // token — the set would otherwise grow without bound for any DID
        // whose sessions are left to expire rather than explicitly logged
        // out. A stale token left behind in the set by an earlier,
        // shorter-lived session is harmless: remove_all_for_did() issues a
        // no-op DEL for its already-gone session key.
        let _: () = conn
            .expire_at(&dkey, session.valid_until as i64)
            .map_err(AuthError::Redis)?;

        Ok(())
    }

    fn get(&self, token: &str) -> Option<Session> {
        let mut conn = self.lock()?;
        let raw: Option<String> = conn.get(session_key(token)).ok()?;
        let raw = raw?;
        serde_json::from_str(&raw).ok()
    }

    fn remove(&self, token: &str) -> bool {
        let Some(mut conn) = self.lock() else {
            return false;
        };

        // Look the session up first so we know which DID-set to clean up.
        let raw: Option<String> = conn.get(session_key(token)).unwrap_or(None);
        let did = raw
            .as_deref()
            .and_then(|s| serde_json::from_str::<Session>(s).ok())
            .map(|s| s.did);

        let removed: i64 = conn.del(session_key(token)).unwrap_or(0);
        if let Some(did) = did {
            let _: Result<i64, _> = conn.srem(did_key(&did), token);
        }
        removed > 0
    }

    fn sessions_for_did(&self, did: &str) -> Vec<Session> {
        let Some(mut conn) = self.lock() else {
            return Vec::new();
        };

        // Served from the `aqua:did:{did}` SET this backend already
        // maintains, so this is SMEMBERS + one GET per live token (bounded by
        // `max_sessions_per_did`), never a keyspace scan. Tokens whose
        // session key Redis has already expired via EXAT simply miss.
        let tokens: Vec<String> = conn.smembers(did_key(did)).unwrap_or_default();
        tokens
            .into_iter()
            .filter_map(|token| {
                let raw: Option<String> = conn.get(session_key(&token)).ok()?;
                raw.and_then(|s| serde_json::from_str::<Session>(&s).ok())
            })
            .collect()
    }

    fn purge_expired(&self, _now_secs: u64) -> usize {
        // No-op by design. `insert` attaches `SET ... EXAT valid_until`, so
        // Redis drops each session key at its own expiry without help. The
        // default implementation would SCAN the whole keyspace and GET every
        // session only to find that the expired ones are already gone.
        0
    }

    fn remove_all_for_did(&self, did: &str) -> usize {
        let Some(mut conn) = self.lock() else {
            return 0;
        };

        let dkey = did_key(did);
        let tokens: Vec<String> = conn.smembers(&dkey).unwrap_or_default();
        let mut count = 0;
        for token in &tokens {
            let removed: i64 = conn.del(session_key(token)).unwrap_or(0);
            if removed > 0 {
                count += 1;
            }
        }
        let _: Result<i64, _> = conn.del(&dkey);
        count
    }

    fn all(&self) -> Vec<Session> {
        let Some(mut conn) = self.lock() else {
            return Vec::new();
        };

        let keys: Vec<String> = conn
            .scan_match(format!("{SESSION_PREFIX}*"))
            .map(|iter| iter.collect())
            .unwrap_or_default();

        keys.into_iter()
            .filter_map(|key| {
                let raw: Option<String> = conn.get(&key).ok()?;
                raw.and_then(|s| serde_json::from_str::<Session>(&s).ok())
            })
            .collect()
    }

    fn len(&self) -> usize {
        let Some(mut conn) = self.lock() else {
            return 0;
        };

        conn.scan_match::<_, String>(format!("{SESSION_PREFIX}*"))
            .map(|iter| iter.count())
            .unwrap_or(0)
    }
}

// Serializes the redis-gated tests below (across all three `mod`s in this
// file). They exercise a single real Redis instance (`TEST_REDIS_URL`), and
// several of them assert on whole-keyspace state (`len()`/`all()`); without
// this lock, Rust's default parallel test execution can interleave them
// against the same live Redis and produce racy counts (observed while
// fixing the DID-set-leak review comment: a 4th, unrelated key from a
// concurrently-running test showed up in `extra_manual_check`'s `len()`
// assertion). Each test still independently skips if `TEST_REDIS_URL` is
// unset, so this has no effect on the no-Redis default path.
#[cfg(test)]
static REDIS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Session;

    #[test]
    fn redis_backend_roundtrips_when_available() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skip: TEST_REDIS_URL unset");
            return;
        };
        let _guard = REDIS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let b = RedisBackend::connect(&url).unwrap();
        let s = Session {
            did: "did:pkh:p256:0xAA".into(),
            token: "rtok".into(),
            valid_until: 9_999_999_999,
            created_at: 1,
        };
        b.insert(s.clone()).unwrap();
        assert_eq!(b.get("rtok").unwrap().did, "did:pkh:p256:0xAA");
        assert!(b.remove("rtok"));
    }
}

#[cfg(test)]
mod extra_manual_check {
    // Manual extra coverage beyond the brief's required test — exercises
    // remove_all_for_did/all/len, which the brief's roundtrip test doesn't
    // touch. Same skip-if-no-redis gating.
    use super::*;
    use crate::types::Session;

    #[test]
    fn redis_backend_extra_did_set_and_enumeration() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else { eprintln!("skip: TEST_REDIS_URL unset"); return; };
        let _guard = REDIS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let b = RedisBackend::connect(&url).unwrap();
        let s1 = Session { did: "did:key:zX".into(), token: "t1".into(), valid_until: 9_999_999_999, created_at: 1 };
        let s2 = Session { did: "did:key:zX".into(), token: "t2".into(), valid_until: 9_999_999_999, created_at: 1 };
        let s3 = Session { did: "did:key:zY".into(), token: "t3".into(), valid_until: 9_999_999_999, created_at: 1 };
        b.insert(s1).unwrap();
        b.insert(s2).unwrap();
        b.insert(s3).unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!(b.remove_all_for_did("did:key:zX"), 2);
        assert_eq!(b.len(), 1);
        assert!(b.get("t1").is_none());
        assert!(b.get("t3").is_some());
        let all = b.all();
        assert_eq!(all.len(), 1);
        b.remove("t3");
        assert_eq!(b.len(), 0);
    }
}

#[cfg(test)]
mod did_set_ttl {
    // Review fix (Task 3): aqua:did:{did} must carry its own TTL after
    // insert, or it leaks unboundedly for any DID whose sessions are left
    // to expire naturally (Redis deletes aqua:session:{token} itself before
    // remove()/remove_all_for_did() ever run, so those methods alone can't
    // shrink the set). Same skip-if-no-redis gating as the other tests.
    use super::*;
    use crate::types::Session;

    #[test]
    fn did_set_carries_a_ttl_after_insert() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skip: TEST_REDIS_URL unset");
            return;
        };
        let _guard = REDIS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let b = RedisBackend::connect(&url).unwrap();
        let did = "did:key:zTtlCheck";
        let s = Session {
            did: did.into(),
            token: "ttl-tok".into(),
            valid_until: 9_999_999_999,
            created_at: 1,
        };
        b.insert(s).unwrap();

        // Check directly against Redis (bypassing RedisBackend's own API,
        // which doesn't expose TTLs) that aqua:did:{did} has a real expiry
        // set, not -1 ("no TTL") or -2 ("key doesn't exist").
        let client = redis::Client::open(url).unwrap();
        let mut conn = client.get_connection().unwrap();
        let ttl: i64 = redis::cmd("TTL")
            .arg(did_key(did))
            .query(&mut conn)
            .unwrap();
        assert!(ttl > 0, "expected aqua:did:{{did}} to carry a TTL, got {ttl}");

        b.remove("ttl-tok");
    }
}
