//! Redis-backed [`crate::webauthn_store::WebauthnCredentialBackend`]
//! (features `webauthn` + `redis`).
//!
//! Passkey credentials live in Redis so they survive restarts and are shared
//! across instances: the single production store all consumers (aqua-node, and
//! aquafier via aqua-node) read and write. Only compiles with both features on.
//!
//! Uses the `redis` crate's SYNC API behind a `Mutex<redis::Connection>` (the
//! credential-store trait is sync, and `redis::Connection` is `!Sync`).
//!
//! Key layout (credentials are persistent, NO TTL, unlike sessions):
//! - `aqua:webauthn:cred:{b64url(credential_id)}` -> JSON [`StoredCredential`]
//! - `aqua:webauthn:did:{did}` -> a Redis SET of the b64url credential ids that
//!   belong to `did`, so `list_for_did` is a set-read + MGET, not a keyspace scan.

use std::sync::{Mutex, MutexGuard};

use base64::Engine;
use redis::Commands;

use crate::webauthn_store::{
    CredentialId, NewCredential, StoredCredential, WebauthnCredentialBackend, WebauthnStoreError,
};

const CRED_PREFIX: &str = "aqua:webauthn:cred:";
const DID_PREFIX: &str = "aqua:webauthn:did:";

fn b64(id: &CredentialId) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&id.0)
}

fn cred_key(id: &CredentialId) -> String {
    format!("{CRED_PREFIX}{}", b64(id))
}

fn did_key(did: &str) -> String {
    format!("{DID_PREFIX}{did}")
}

fn backend<E: std::fmt::Display>(e: E) -> WebauthnStoreError {
    WebauthnStoreError::Backend(e.to_string())
}

/// Redis-backed credential store. One blocking connection behind a `Mutex`.
pub struct RedisWebauthnStore {
    conn: Mutex<redis::Connection>,
}

impl RedisWebauthnStore {
    /// Connect to Redis at `url` (e.g. `redis://127.0.0.1:6379`).
    ///
    /// Errors are reported as [`WebauthnStoreError::Backend`] carrying the
    /// stringified `redis` error, so no `redis` type appears in this crate's
    /// public API.
    pub fn connect(url: &str) -> Result<Self, WebauthnStoreError> {
        let client = redis::Client::open(url).map_err(backend)?;
        let conn = client.get_connection().map_err(backend)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, redis::Connection>, WebauthnStoreError> {
        self.conn
            .lock()
            .map_err(|_| WebauthnStoreError::Backend("redis connection mutex poisoned".into()))
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl WebauthnCredentialBackend for RedisWebauthnStore {
    fn insert(&self, cred: NewCredential) -> Result<(), WebauthnStoreError> {
        let stored = StoredCredential {
            did: cred.did,
            credential_id: cred.credential_id,
            public_key: cred.public_key,
            sign_count: cred.sign_count,
            transports: cred.transports,
            label: cred.label,
            created_at: Self::now_secs(),
        };
        let payload = serde_json::to_string(&stored).map_err(backend)?;
        let mut conn = self.lock()?;
        // Idempotent by id: SET overwrites, SADD is a no-op if already present.
        let _: () = conn
            .set(cred_key(&stored.credential_id), payload)
            .map_err(backend)?;
        let _: () = conn
            .sadd(did_key(&stored.did), b64(&stored.credential_id))
            .map_err(backend)?;
        Ok(())
    }

    fn list_for_did(&self, did: &str) -> Vec<StoredCredential> {
        let Ok(mut conn) = self.lock() else {
            return Vec::new();
        };
        let ids: Vec<String> = conn.smembers(did_key(did)).unwrap_or_default();
        ids.into_iter()
            .filter_map(|b64id| {
                let raw: Option<String> = conn.get(format!("{CRED_PREFIX}{b64id}")).ok()?;
                raw.and_then(|s| serde_json::from_str::<StoredCredential>(&s).ok())
            })
            // A stale id in the DID set (its cred key already deleted) filters
            // out above rather than surfacing as a phantom credential.
            .filter(|c| c.did == did)
            .collect()
    }

    fn get_by_id(&self, cred_id: &CredentialId) -> Option<StoredCredential> {
        let mut conn = self.lock().ok()?;
        let raw: Option<String> = conn.get(cred_key(cred_id)).ok()?;
        raw.and_then(|s| serde_json::from_str(&s).ok())
    }

    fn update_sign_count(
        &self,
        cred_id: &CredentialId,
        new_count: u32,
    ) -> Result<(), WebauthnStoreError> {
        let mut conn = self.lock()?;
        let raw: Option<String> = conn.get(cred_key(cred_id)).map_err(backend)?;
        let raw = raw.ok_or(WebauthnStoreError::NotFound)?;
        let mut cred: StoredCredential = serde_json::from_str(&raw).map_err(backend)?;
        // Monotonic: never let a replayed lower count regress the stored value.
        if new_count <= cred.sign_count {
            return Ok(());
        }
        cred.sign_count = new_count;
        let payload = serde_json::to_string(&cred).map_err(backend)?;
        let _: () = conn.set(cred_key(cred_id), payload).map_err(backend)?;
        Ok(())
    }

    fn delete(&self, did: &str, cred_id: &CredentialId) -> Result<bool, WebauthnStoreError> {
        let mut conn = self.lock()?;
        // Ownership check: only the DID that owns the credential may delete it.
        let raw: Option<String> = conn.get(cred_key(cred_id)).map_err(backend)?;
        let owner_matches = raw
            .as_deref()
            .and_then(|s| serde_json::from_str::<StoredCredential>(s).ok())
            .map(|c| c.did == did)
            .unwrap_or(false);
        if !owner_matches {
            return Ok(false);
        }
        let removed: i64 = conn.del(cred_key(cred_id)).map_err(backend)?;
        let _: Result<i64, _> = conn.srem(did_key(did), b64(cred_id));
        Ok(removed > 0)
    }
}

// Serializes the redis-gated tests. Each skips unless TEST_REDIS_URL is set,
// so this has no effect on the no-Redis default path.
#[cfg(test)]
static REDIS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn newcred(did: &str, id: &[u8]) -> NewCredential {
        NewCredential {
            did: did.into(),
            credential_id: CredentialId(id.to_vec()),
            public_key: vec![9, 9, 9],
            sign_count: 0,
            transports: vec!["hybrid".into()],
            label: Some("test".into()),
        }
    }

    #[test]
    fn redis_credential_roundtrips_when_available() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skip: TEST_REDIS_URL unset");
            return;
        };
        let _guard = REDIS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let s = RedisWebauthnStore::connect(&url).unwrap();
        let did = "did:key:zRedisCredTest";
        let id = CredentialId(b"rediscredid".to_vec());
        // clean any prior run
        let _ = s.delete(did, &id);

        s.insert(newcred(did, b"rediscredid")).unwrap();
        assert_eq!(s.get_by_id(&id).unwrap().did, did);
        assert_eq!(s.list_for_did(did).len(), 1);

        s.update_sign_count(&id, 7).unwrap();
        s.update_sign_count(&id, 4).unwrap(); // lower ignored
        assert_eq!(s.get_by_id(&id).unwrap().sign_count, 7);

        assert!(!s.delete("did:key:zWRONG", &id).unwrap());
        assert!(s.delete(did, &id).unwrap());
        assert!(s.get_by_id(&id).is_none());
        assert!(s.list_for_did(did).is_empty());
    }
}
