//! Pluggable WebAuthn credential store (feature `webauthn`).
//!
//! The credential-persistence half of passkey support, split exactly like
//! [`crate::session_backend`]: a **sync** trait ([`WebauthnCredentialBackend`])
//! with an in-memory default ([`InMemoryWebauthnStore`]) and — behind the
//! `redis` feature — a Redis backend ([`crate::redis_webauthn::RedisWebauthnStore`]).
//!
//! Why here, and why one store: passkey credentials were persisted separately by
//! each consumer (aqua-node in fjall, aquafier in Postgres), duplicating the
//! ceremony around two divergent stores. Lifting the store into `aqua-auth` lets
//! every consumer share ONE backend — in production, aqua-node's Redis — so a
//! passkey registered once is usable everywhere the same Redis is reachable.
//!
//! The stored `public_key` is the opaque credential blob (a serialized
//! `webauthn_rs::Passkey` in practice); this layer never parses it, so the store
//! carries no `webauthn-rs` dependency — only the ceremony that mints/verifies
//! does.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// A WebAuthn credential identifier — raw bytes, NOT base64-encoded.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CredentialId(pub Vec<u8>);

/// A persisted passkey credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// The identity this credential authenticates (a `did:key:zDn…` for a
    /// passkey-as-identity registration, or the wallet DID for a second factor).
    pub did: String,
    pub credential_id: CredentialId,
    /// Opaque credential blob (a serialized `webauthn_rs::Passkey`). Never
    /// parsed here — the ceremony/verify layer owns that.
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub transports: Vec<String>,
    pub label: Option<String>,
    /// Unix timestamp (seconds).
    pub created_at: u64,
}

/// A credential to insert. `created_at` is stamped by the backend.
#[derive(Debug, Clone)]
pub struct NewCredential {
    pub did: String,
    pub credential_id: CredentialId,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub transports: Vec<String>,
    pub label: Option<String>,
}

/// Errors from a credential backend. Kept independent of [`crate::AuthError`]
/// (which is `http`-gated) so the store trait compiles under `webauthn` alone.
#[derive(Debug, thiserror::Error)]
pub enum WebauthnStoreError {
    #[error("credential not found")]
    NotFound,
    #[error("credential store backend error: {0}")]
    Backend(String),
}

/// Sync credential store — the WebAuthn analogue of
/// [`crate::session_backend::SessionBackend`]. Sync (not async) to match this
/// crate's blocking-Redis pattern; auth is low-frequency, so a blocking call
/// from an async handler is acceptable (or wrap in `spawn_blocking`).
pub trait WebauthnCredentialBackend: Send + Sync {
    /// Insert or replace a credential. MUST be idempotent by `credential_id`:
    /// re-inserting the same id updates the row rather than duplicating it.
    fn insert(&self, cred: NewCredential) -> Result<(), WebauthnStoreError>;

    /// All credentials registered to `did` (for the browser's
    /// `allowCredentials`). Empty vec if none.
    fn list_for_did(&self, did: &str) -> Vec<StoredCredential>;

    /// Look up by raw credential id (the one the authenticator returns).
    fn get_by_id(&self, cred_id: &CredentialId) -> Option<StoredCredential>;

    /// Monotonic sign-count bump. Backends MUST NOT let the count go backwards
    /// (the spec requires it to increase, to detect cloned authenticators);
    /// a lower `new_count` is ignored, not an error.
    fn update_sign_count(
        &self,
        cred_id: &CredentialId,
        new_count: u32,
    ) -> Result<(), WebauthnStoreError>;

    /// Delete `(did, cred_id)`. `Ok(true)` if a row was removed, `Ok(false)`
    /// if it didn't exist (the DELETE endpoint maps `false` to a 404 for
    /// existence-hiding). A wrong `did` for an existing id is `Ok(false)`.
    fn delete(&self, did: &str, cred_id: &CredentialId) -> Result<bool, WebauthnStoreError>;
}

/// In-memory default backend (the `DashMap`-free analogue of
/// [`crate::session_backend::InMemoryBackend`]). Non-persistent: fine for tests
/// and single-process dev, but production wants the Redis backend so a passkey
/// survives restarts and is shared across instances.
#[derive(Default)]
pub struct InMemoryWebauthnStore {
    // credential_id -> StoredCredential. Keyed by id because `get_by_id`
    // (verify path) is the hot lookup; `list_for_did` scans, which is fine at
    // the handful-of-credentials-per-user scale.
    creds: Mutex<HashMap<Vec<u8>, StoredCredential>>,
}

impl InMemoryWebauthnStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl WebauthnCredentialBackend for InMemoryWebauthnStore {
    fn insert(&self, cred: NewCredential) -> Result<(), WebauthnStoreError> {
        let mut map = self.creds.lock().map_err(|_| {
            WebauthnStoreError::Backend("in-memory credential store lock poisoned".into())
        })?;
        map.insert(
            cred.credential_id.0.clone(),
            StoredCredential {
                did: cred.did,
                credential_id: cred.credential_id,
                public_key: cred.public_key,
                sign_count: cred.sign_count,
                transports: cred.transports,
                label: cred.label,
                created_at: Self::now_secs(),
            },
        );
        Ok(())
    }

    fn list_for_did(&self, did: &str) -> Vec<StoredCredential> {
        let Ok(map) = self.creds.lock() else {
            return Vec::new();
        };
        map.values().filter(|c| c.did == did).cloned().collect()
    }

    fn get_by_id(&self, cred_id: &CredentialId) -> Option<StoredCredential> {
        let map = self.creds.lock().ok()?;
        map.get(&cred_id.0).cloned()
    }

    fn update_sign_count(
        &self,
        cred_id: &CredentialId,
        new_count: u32,
    ) -> Result<(), WebauthnStoreError> {
        let mut map = self.creds.lock().map_err(|_| {
            WebauthnStoreError::Backend("in-memory credential store lock poisoned".into())
        })?;
        let cred = map.get_mut(&cred_id.0).ok_or(WebauthnStoreError::NotFound)?;
        if new_count > cred.sign_count {
            cred.sign_count = new_count;
        }
        Ok(())
    }

    fn delete(&self, did: &str, cred_id: &CredentialId) -> Result<bool, WebauthnStoreError> {
        let mut map = self.creds.lock().map_err(|_| {
            WebauthnStoreError::Backend("in-memory credential store lock poisoned".into())
        })?;
        // Only remove when the DID matches, so one user cannot delete another's
        // credential by guessing an id.
        match map.get(&cred_id.0) {
            Some(c) if c.did == did => {
                map.remove(&cred_id.0);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(did: &str, id: &[u8]) -> NewCredential {
        NewCredential {
            did: did.into(),
            credential_id: CredentialId(id.to_vec()),
            public_key: vec![1, 2, 3],
            sign_count: 0,
            transports: vec!["internal".into()],
            label: None,
        }
    }

    #[test]
    fn insert_get_list_roundtrip() {
        let s = InMemoryWebauthnStore::new();
        s.insert(cred("did:key:zA", b"id1")).unwrap();
        s.insert(cred("did:key:zA", b"id2")).unwrap();
        s.insert(cred("did:key:zB", b"id3")).unwrap();
        assert_eq!(s.list_for_did("did:key:zA").len(), 2);
        assert_eq!(s.list_for_did("did:key:zB").len(), 1);
        assert_eq!(
            s.get_by_id(&CredentialId(b"id1".to_vec())).unwrap().did,
            "did:key:zA"
        );
    }

    #[test]
    fn insert_is_idempotent_by_id() {
        let s = InMemoryWebauthnStore::new();
        s.insert(cred("did:key:zA", b"id1")).unwrap();
        s.insert(cred("did:key:zA", b"id1")).unwrap();
        assert_eq!(s.list_for_did("did:key:zA").len(), 1);
    }

    #[test]
    fn sign_count_is_monotonic() {
        let s = InMemoryWebauthnStore::new();
        s.insert(cred("did:key:zA", b"id1")).unwrap();
        let id = CredentialId(b"id1".to_vec());
        s.update_sign_count(&id, 5).unwrap();
        s.update_sign_count(&id, 3).unwrap(); // lower — ignored
        assert_eq!(s.get_by_id(&id).unwrap().sign_count, 5);
    }

    #[test]
    fn delete_requires_matching_did() {
        let s = InMemoryWebauthnStore::new();
        s.insert(cred("did:key:zA", b"id1")).unwrap();
        let id = CredentialId(b"id1".to_vec());
        assert!(!s.delete("did:key:zWRONG", &id).unwrap()); // wrong owner: no-op
        assert!(s.get_by_id(&id).is_some());
        assert!(s.delete("did:key:zA", &id).unwrap());
        assert!(s.get_by_id(&id).is_none());
    }
}
