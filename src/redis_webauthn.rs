//! Redis-backed [`crate::webauthn_store::WebauthnCredentialBackend`]
//! (features `webauthn` + `redis`).
//!
//! Passkey credentials live in Redis so they survive restarts and are shared
//! across instances: the single production store all consumers (aqua-node, and
//! aquafier via aqua-node) read and write. Only compiles with both features on.
//!
//! Uses the `redis` crate's ASYNC API over a
//! [`redis::aio::MultiplexedConnection`]. Until 0.7.0 this was the sync API
//! behind a `Mutex<redis::Connection>`, which serialised every credential
//! operation process-wide and ran blocking I/O on tokio worker threads (no
//! consumer wrapped it in `spawn_blocking`). A multiplexed connection pipelines
//! concurrent commands over one socket and is cheap to clone, so the mutex is
//! gone rather than merely relocated.
//!
//! Key layout (credentials are persistent, NO TTL, unlike sessions):
//! - `aqua:webauthn:cred:{b64url(credential_id)}` -> JSON [`StoredCredential`]
//! - `aqua:webauthn:did:{did}` -> a Redis SET of the b64url credential ids that
//!   belong to `did`, so `list_for_did` is a set-read + MGET, not a keyspace scan.

use async_trait::async_trait;
use base64::Engine;
use redis::AsyncCommands;

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

/// Redis-backed credential store over a multiplexed async connection.
///
/// Cloning the handle per call is the documented `redis` pattern: the
/// multiplexer is shared, and commands from concurrent tasks are pipelined
/// onto the one socket instead of queueing behind a lock.
pub struct RedisWebauthnStore {
    conn: redis::aio::MultiplexedConnection,
}

impl RedisWebauthnStore {
    /// Connect to Redis at `url` (e.g. `redis://127.0.0.1:6379`).
    ///
    /// Async as of 0.7.0, and still eager: the connection is established here,
    /// so an unreachable Redis fails at boot rather than at first login.
    ///
    /// Errors are reported as [`WebauthnStoreError::Backend`] carrying the
    /// stringified `redis` error, so no `redis` type appears in this crate's
    /// public API.
    pub async fn connect(url: &str) -> Result<Self, WebauthnStoreError> {
        let client = redis::Client::open(url).map_err(backend)?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(backend)?;
        Ok(Self { conn })
    }

    fn conn(&self) -> redis::aio::MultiplexedConnection {
        self.conn.clone()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[async_trait]
impl WebauthnCredentialBackend for RedisWebauthnStore {
    async fn insert(&self, cred: NewCredential) -> Result<(), WebauthnStoreError> {
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
        let mut conn = self.conn();
        // Idempotent by id: SET overwrites, SADD is a no-op if already present.
        let _: () = conn
            .set(cred_key(&stored.credential_id), payload)
            .await
            .map_err(backend)?;
        let _: () = conn
            .sadd(did_key(&stored.did), b64(&stored.credential_id))
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn list_for_did(&self, did: &str) -> Result<Vec<StoredCredential>, WebauthnStoreError> {
        let mut conn = self.conn();
        let ids: Vec<String> = conn.smembers(did_key(did)).await.map_err(backend)?;
        let mut out = Vec::with_capacity(ids.len());
        for b64id in ids {
            let raw: Option<String> = conn
                .get(format!("{CRED_PREFIX}{b64id}"))
                .await
                .map_err(backend)?;
            // A stale id in the DID set (its cred key already deleted, or a row
            // that no longer claims this DID) filters out here rather than
            // surfacing as a phantom credential. An undecodable row is skipped
            // for the same reason: one bad row must not fail the whole list.
            if let Some(c) = raw.and_then(|s| serde_json::from_str::<StoredCredential>(&s).ok()) {
                if c.did == did {
                    out.push(c);
                }
            }
        }
        Ok(out)
    }

    async fn get_by_id(
        &self,
        cred_id: &CredentialId,
    ) -> Result<Option<StoredCredential>, WebauthnStoreError> {
        let mut conn = self.conn();
        let raw: Option<String> = conn.get(cred_key(cred_id)).await.map_err(backend)?;
        match raw {
            None => Ok(None),
            Some(s) => serde_json::from_str(&s).map(Some).map_err(backend),
        }
    }

    async fn update_sign_count(
        &self,
        cred_id: &CredentialId,
        new_count: u32,
    ) -> Result<(), WebauthnStoreError> {
        let mut conn = self.conn();
        let raw: Option<String> = conn.get(cred_key(cred_id)).await.map_err(backend)?;
        let raw = raw.ok_or(WebauthnStoreError::NotFound)?;
        let mut cred: StoredCredential = serde_json::from_str(&raw).map_err(backend)?;
        // Monotonic: never let a replayed lower count regress the stored value.
        if new_count <= cred.sign_count {
            return Ok(());
        }
        cred.sign_count = new_count;
        let payload = serde_json::to_string(&cred).map_err(backend)?;
        let _: () = conn
            .set(cred_key(cred_id), payload)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn delete(&self, did: &str, cred_id: &CredentialId) -> Result<bool, WebauthnStoreError> {
        let mut conn = self.conn();
        // Ownership check: only the DID that owns the credential may delete it.
        let raw: Option<String> = conn.get(cred_key(cred_id)).await.map_err(backend)?;
        let owner_matches = raw
            .as_deref()
            .and_then(|s| serde_json::from_str::<StoredCredential>(s).ok())
            .map(|c| c.did == did)
            .unwrap_or(false);
        if !owner_matches {
            return Ok(false);
        }
        let removed: i64 = conn.del(cred_key(cred_id)).await.map_err(backend)?;
        let _: Result<i64, _> = conn.srem(did_key(did), b64(cred_id)).await;
        Ok(removed > 0)
    }
}

// Serializes the redis-gated tests. Each skips unless TEST_REDIS_URL is set,
// so this has no effect on the no-Redis default path. `tokio::sync::Mutex`
// because the guard is now held across awaits.
#[cfg(test)]
static REDIS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

    #[tokio::test]
    async fn redis_credential_roundtrips_when_available() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skip: TEST_REDIS_URL unset");
            return;
        };
        let _guard = REDIS_TEST_LOCK.lock().await;
        let s = RedisWebauthnStore::connect(&url).await.unwrap();
        let did = "did:key:zRedisCredTest";
        let id = CredentialId(b"rediscredid".to_vec());
        // clean any prior run
        let _ = s.delete(did, &id).await;

        s.insert(newcred(did, b"rediscredid")).await.unwrap();
        assert_eq!(s.get_by_id(&id).await.unwrap().unwrap().did, did);
        assert_eq!(s.list_for_did(did).await.unwrap().len(), 1);

        s.update_sign_count(&id, 7).await.unwrap();
        s.update_sign_count(&id, 4).await.unwrap(); // lower ignored
        assert_eq!(s.get_by_id(&id).await.unwrap().unwrap().sign_count, 7);

        assert!(!s.delete("did:key:zWRONG", &id).await.unwrap());
        assert!(s.delete(did, &id).await.unwrap());
        assert!(s.get_by_id(&id).await.unwrap().is_none());
        assert!(s.list_for_did(did).await.unwrap().is_empty());
    }

    /// Concurrency was the point of dropping the `Mutex<Connection>`: many
    /// tasks must be able to hold `&RedisWebauthnStore` and issue overlapping
    /// commands. This would still pass under the old mutex (serialised), but it
    /// pins the shape: no `&mut self`, no external locking, `Arc`-shareable.
    #[tokio::test]
    async fn concurrent_inserts_share_one_connection() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skip: TEST_REDIS_URL unset");
            return;
        };
        let _guard = REDIS_TEST_LOCK.lock().await;
        let s = std::sync::Arc::new(RedisWebauthnStore::connect(&url).await.unwrap());
        let did = "did:key:zRedisConcurrent";
        for i in 0..8u8 {
            let _ = s.delete(did, &CredentialId(vec![b'c', i])).await;
        }

        let mut handles = Vec::new();
        for i in 0..8u8 {
            let s = s.clone();
            handles.push(tokio::spawn(async move {
                s.insert(newcred(did, &[b'c', i])).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(s.list_for_did(did).await.unwrap().len(), 8);

        for i in 0..8u8 {
            assert!(s.delete(did, &CredentialId(vec![b'c', i])).await.unwrap());
        }
        assert!(s.list_for_did(did).await.unwrap().is_empty());
    }
}
