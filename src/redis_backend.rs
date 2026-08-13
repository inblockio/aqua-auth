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
//!   expiry set to the session's `valid_until` (Unix seconds) via `EXPIREAT`.
//! - `aqua:did:{did}` -> a Redis SET of tokens belonging to `did`, used to
//!   implement `remove_all_for_did` without a full scan.

use std::sync::Mutex;

use redis::Commands;

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
}

impl SessionBackend for RedisBackend {
    fn insert(&self, session: Session) -> Result<(), AuthError> {
        let payload = serde_json::to_string(&session).map_err(AuthError::Serde)?;
        let mut conn = self.conn.lock().expect("redis connection mutex poisoned");
        let skey = session_key(&session.token);
        let dkey = did_key(&session.did);

        let _: () = conn.set(&skey, payload).map_err(AuthError::Redis)?;
        // Best-effort expiry: an expiry in the past (already-expired session)
        // is still accepted by Redis and simply deletes the key immediately.
        let _: () = conn
            .expire_at(&skey, session.valid_until as i64)
            .map_err(AuthError::Redis)?;
        let _: () = conn.sadd(&dkey, &session.token).map_err(AuthError::Redis)?;

        Ok(())
    }

    fn get(&self, token: &str) -> Option<Session> {
        let mut conn = self.conn.lock().expect("redis connection mutex poisoned");
        let raw: Option<String> = conn.get(session_key(token)).ok()?;
        let raw = raw?;
        serde_json::from_str(&raw).ok()
    }

    fn remove(&self, token: &str) -> bool {
        let mut conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return false,
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

    fn remove_all_for_did(&self, did: &str) -> usize {
        let mut conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return 0,
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
        let mut conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
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
        let mut conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return 0,
        };

        conn.scan_match::<_, String>(format!("{SESSION_PREFIX}*"))
            .map(|iter| iter.count())
            .unwrap_or(0)
    }
}

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
