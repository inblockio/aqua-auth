//! ChallengeStore — in-memory store for CAIP-122 authentication challenges.
//!
//! Challenges have a 5-minute TTL. Expired challenges are cleaned up lazily
//! on access and via the session store's background sweep.

use crate::auth_error::AuthError;
use crate::message::{build_message, MessageParams};
use crate::types::Challenge;
use chrono::{Duration, Utc};
use dashmap::DashMap;
use rand::Rng;

/// Default challenge TTL in seconds.
pub const DEFAULT_CHALLENGE_TTL_SECS: u64 = 300; // 5 minutes

/// In-memory store for pending authentication challenges.
pub struct ChallengeStore {
    /// Challenges keyed by nonce.
    challenges: DashMap<String, Challenge>,
    /// Challenge time-to-live in seconds.
    ttl_secs: u64,
    /// Domain used in CAIP-122 messages.
    domain: String,
    /// URI used in CAIP-122 messages.
    uri: String,
}

impl ChallengeStore {
    /// Create a new challenge store with the given configuration.
    pub fn new(ttl_secs: u64, domain: String, uri: String) -> Self {
        Self {
            challenges: DashMap::new(),
            ttl_secs,
            domain,
            uri,
        }
    }

    /// Generate a new challenge for the given DID.
    ///
    /// Returns the challenge including the canonical CAIP-122 message to sign.
    pub fn create(&self, did: &str) -> Result<Challenge, AuthError> {
        // Generate 32-byte random nonce
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = format!("0x{}", hex::encode(nonce_bytes));

        let now = Utc::now();
        let expires = now + Duration::seconds(self.ttl_secs as i64);

        let message = build_message(&MessageParams {
            did,
            domain: &self.domain,
            uri: &self.uri,
            nonce: &nonce,
            issued_at: now,
            expiration_time: expires,
        })?;

        let challenge = Challenge {
            did: did.to_string(),
            nonce: nonce.clone(),
            message,
            expires_at: expires.timestamp() as u64,
        };

        self.challenges.insert(nonce, challenge.clone());
        Ok(challenge)
    }

    /// Validate and consume a challenge by nonce.
    ///
    /// Returns the challenge if valid and not expired. The challenge is removed
    /// from the store (single-use).
    pub fn validate(&self, nonce: &str) -> Result<Challenge, AuthError> {
        let (_, challenge) = self
            .challenges
            .remove(nonce)
            .ok_or(AuthError::ChallengeNotFound)?;

        let now = Utc::now().timestamp() as u64;
        if now >= challenge.expires_at {
            return Err(AuthError::ChallengeExpired);
        }

        Ok(challenge)
    }

    /// Remove all expired challenges. Called by the session store's background sweep.
    pub fn cleanup_expired(&self) {
        let now = Utc::now().timestamp() as u64;
        self.challenges.retain(|_, c| c.expires_at > now);
    }

    /// Number of active (non-expired) challenges.
    pub fn len(&self) -> usize {
        self.challenges.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> ChallengeStore {
        ChallengeStore::new(300, "aqua-node".into(), "http://127.0.0.1:3000".into())
    }

    #[test]
    fn create_and_validate_challenge() {
        let store = test_store();
        let addr_hex = hex::encode([0x42; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");

        let challenge = store.create(&did).unwrap();
        assert_eq!(challenge.did, did);
        assert!(challenge.nonce.starts_with("0x"));
        assert!(challenge.message.contains("Sign in to Aqua Node"));

        // Validate consumes the challenge
        let validated = store.validate(&challenge.nonce).unwrap();
        assert_eq!(validated.did, did);

        // Second validate fails (consumed)
        assert!(store.validate(&challenge.nonce).is_err());
    }

    #[test]
    fn unknown_nonce_fails() {
        let store = test_store();
        assert!(store.validate("0xnonexistent").is_err());
    }

    #[test]
    fn expired_challenge_fails() {
        // Create store with 0-second TTL
        let store = ChallengeStore::new(0, "aqua-node".into(), "http://127.0.0.1:3000".into());
        let addr_hex = hex::encode([0x42; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");

        let challenge = store.create(&did).unwrap();
        // Already expired since TTL is 0
        assert!(store.validate(&challenge.nonce).is_err());
    }

    #[test]
    fn cleanup_removes_expired() {
        let store = ChallengeStore::new(0, "aqua-node".into(), "http://127.0.0.1:3000".into());
        let addr_hex = hex::encode([0x42; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");

        let _ = store.create(&did).unwrap();
        assert_eq!(store.len(), 1);

        store.cleanup_expired();
        assert_eq!(store.len(), 0);
    }
}
