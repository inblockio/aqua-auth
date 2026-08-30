//! ChallengeStore: in-memory store for CAIP-122 authentication challenges.
//!
//! Challenges have a 5-minute TTL. Expired challenges are cleaned up lazily
//! on access and via the session store's background sweep.
//!
//! ## H2 hardening: bounded capacity
//!
//! The store is hard-capped at [`MAX_CHALLENGES`] entries (overridable via
//! [`ChallengeStore::with_capacity`]) so an attacker flooding
//! `GET /auth/challenge` cannot grow this map without bound. At capacity,
//! `create` first purges expired entries; if that doesn't free a slot, the
//! single oldest-issued challenge is evicted to make room. Challenges are
//! pre-auth, single-use, and short-TTL by design, so evicting the oldest one
//! only inconveniences whoever is flooding the endpoint (their oldest
//! in-flight challenge stops working); it never touches an established,
//! authenticated session. The store is never unbounded.

use crate::auth_error::AuthError;
use crate::message::{build_message, MessageParams};
use crate::types::Challenge;
use chrono::{Duration, Utc};
use dashmap::DashMap;
use rand::Rng;

/// Default challenge TTL in seconds.
pub const DEFAULT_CHALLENGE_TTL_SECS: u64 = 300; // 5 minutes

/// Default hard cap on concurrently pending challenges. Override via
/// [`ChallengeStore::with_capacity`].
pub const MAX_CHALLENGES: usize = 8192;

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
    /// Hard cap on concurrently pending challenges (see [`MAX_CHALLENGES`]).
    max_challenges: usize,
}

impl ChallengeStore {
    /// Create a new challenge store with the given configuration.
    ///
    /// Capped at [`MAX_CHALLENGES`] pending challenges. Use
    /// [`Self::with_capacity`] to override the cap.
    pub fn new(ttl_secs: u64, domain: String, uri: String) -> Self {
        Self::with_capacity(ttl_secs, domain, uri, MAX_CHALLENGES)
    }

    /// Same as [`Self::new`], but with an explicit hard cap on the number of
    /// concurrently pending challenges, overriding [`MAX_CHALLENGES`].
    pub fn with_capacity(
        ttl_secs: u64,
        domain: String,
        uri: String,
        max_challenges: usize,
    ) -> Self {
        Self {
            challenges: DashMap::new(),
            ttl_secs,
            domain,
            uri,
            max_challenges,
        }
    }

    /// Generate a new challenge for the given DID.
    ///
    /// Returns the challenge including the canonical CAIP-122 message to sign.
    ///
    /// At capacity, expired entries are purged first; if the store is still
    /// full, the single oldest-issued challenge is evicted to make room (see
    /// the module docs). This method never grows the store past
    /// `max_challenges`.
    pub fn create(&self, did: &str) -> Result<Challenge, AuthError> {
        if self.challenges.len() >= self.max_challenges {
            self.cleanup_expired();
            if self.challenges.len() >= self.max_challenges {
                self.evict_oldest();
            }
        }

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

    /// Evict the single oldest-issued pending challenge to free a slot.
    ///
    /// `Challenge` doesn't carry an `issued_at` field, but every challenge in
    /// a given store shares the same `ttl_secs`, so `expires_at` (which does
    /// exist) sorts identically to issuance order: the smallest `expires_at`
    /// is the oldest-issued challenge. Ties (identical `expires_at`) are
    /// broken by nonce so eviction never depends on `DashMap` iteration
    /// order.
    ///
    /// Best-effort under concurrency (as is the rest of this `DashMap`-backed
    /// store): a race between the capacity check and this eviction can let
    /// the store briefly exceed `max_challenges` by a small amount, which the
    /// next `create` call self-corrects.
    fn evict_oldest(&self) {
        let victim = self
            .challenges
            .iter()
            .min_by(|a, b| {
                a.value()
                    .expires_at
                    .cmp(&b.value().expires_at)
                    .then_with(|| a.key().cmp(b.key()))
            })
            .map(|e| e.key().clone());
        if let Some(nonce) = victim {
            self.challenges.remove(&nonce);
        }
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
    fn create_challenge_for_did_key_ed25519() {
        let store = test_store();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut bytes = crate::key::ED25519_PREFIX.to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());

        let challenge = store.create(&did).unwrap();
        assert_eq!(challenge.did, did);
        assert!(challenge.message.contains("Ed25519 account"));
        assert!(challenge.message.contains("z6Mk"));
        assert!(!challenge.message.contains("Chain ID"));

        // Verify the signature round-trips
        use ed25519_dalek::Signer;
        let sig = key.sign(challenge.message.as_bytes());
        assert!(crate::verify_caip122(&did, &challenge.message, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn create_challenge_for_did_key_p256() {
        let store = test_store();
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let compressed = key.verifying_key().to_encoded_point(true);
        let mut bytes = crate::key::P256_PREFIX.to_vec();
        bytes.extend_from_slice(compressed.as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());

        let challenge = store.create(&did).unwrap();
        assert_eq!(challenge.did, did);
        assert!(challenge.message.contains("P-256 account"));
        assert!(!challenge.message.contains("Chain ID"));

        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = key.sign(challenge.message.as_bytes());
        assert!(crate::verify_caip122(&did, &challenge.message, &sig.to_bytes()).unwrap());
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

    // ── H2 hardening: bounded capacity ──────────────────────────────────

    fn addr_did(byte: u8) -> String {
        format!("did:pkh:eip155:1:0x{}", hex::encode([byte; 20]))
    }

    #[test]
    fn default_cap_matches_max_challenges_const() {
        let store = test_store();
        assert_eq!(store.max_challenges, MAX_CHALLENGES);
    }

    #[test]
    fn with_capacity_overrides_the_default_cap() {
        // Long TTL so nothing expires mid-test.
        let store = ChallengeStore::with_capacity(300, "aqua-node".into(), "http://x".into(), 3);
        for i in 0..3u8 {
            store.create(&addr_did(i)).unwrap();
        }
        assert_eq!(store.len(), 3);

        // A 4th create must not grow the store past the cap.
        store.create(&addr_did(9)).unwrap();
        assert!(
            store.len() <= 3,
            "store must never exceed its configured capacity"
        );
    }

    #[test]
    fn cap_never_exceeded_across_many_creates() {
        let store = ChallengeStore::with_capacity(300, "aqua-node".into(), "http://x".into(), 5);
        for i in 0..50u8 {
            store.create(&addr_did(i)).unwrap();
            assert!(store.len() <= 5, "hard cap violated at iteration {i}");
        }
    }

    #[test]
    fn purge_expired_before_evicting_oldest() {
        // 0-second TTL: every challenge is immediately expired, so hitting
        // the cap must be resolved by purging (freeing all slots) rather
        // than evicting a still-pending challenge; there are none left
        // pending once real time has moved past their 1-second TTL.
        let store = ChallengeStore::with_capacity(1, "aqua-node".into(), "http://x".into(), 2);
        let a = store.create(&addr_did(1)).unwrap();
        let _b = store.create(&addr_did(2)).unwrap();
        assert_eq!(store.len(), 2);

        // Let both prior challenges actually expire.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Both prior challenges are now expired: create() must purge them
        // first, so a fresh 2-slot store ends up with just the new one
        // (which is not yet expired: its own TTL starts now).
        let c = store.create(&addr_did(3)).unwrap();
        assert_eq!(
            store.len(),
            1,
            "purge must reclaim expired slots before any eviction"
        );
        // The purge removed the expired entries outright; neither survives.
        assert!(store.validate(&a.nonce).is_err());
        assert!(store.validate(&c.nonce).is_ok());
    }

    #[test]
    fn evicts_oldest_issued_when_still_full_after_purge() {
        // Long TTL so purge finds nothing to reclaim; the only way to make
        // room is evicting the oldest still-pending challenge.
        let store = ChallengeStore::with_capacity(300, "aqua-node".into(), "http://x".into(), 2);
        let first = store.create(&addr_did(1)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = store.create(&addr_did(2)).unwrap();
        assert_eq!(store.len(), 2);

        // Third create must evict the oldest (`first`), not `second`.
        let third = store.create(&addr_did(3)).unwrap();
        assert_eq!(store.len(), 2);
        assert!(
            store.validate(&first.nonce).is_err(),
            "the oldest-issued challenge must be evicted"
        );
        assert!(store.validate(&second.nonce).is_ok());
        assert!(store.validate(&third.nonce).is_ok());
    }
}
